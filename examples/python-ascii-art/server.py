"""
ASCII Art Generator Server - Pay 1 sat per character

Demonstrates the Spilman payment channel bridge in Python.

Endpoints:
    GET  /channel/params  - Get server pubkey and pricing info
    POST /ascii           - Generate ASCII art (requires X-Cashu-Channel header)

Usage:
    python server.py

Environment variables:
    SERVER_SECRET_KEY - Server's secret key (64 hex chars, default: random)
    MINT_URL - Mint URL (default: http://localhost:3338)
    PORT - Server port (default: 5000)
"""

from flask import Flask, request, jsonify
from cdk_spilman import SpilmanBridge, secret_key_to_pubkey, unblind_and_verify_dleq
import pyfiglet
import json
import time
import os
import signal
import threading
import sys
import requests as http_requests
import secrets

app = Flask(__name__)

# Configuration
SECRET_KEY = os.environ.get("SERVER_SECRET_KEY") or secrets.token_hex(32)
MINT_URL = os.environ.get("MINT_URL", "http://localhost:3338")
PORT = int(os.environ.get("PORT", "5000"))
PRICE_PER_CHAR = 1  # 1 sat per character

# In-memory stores
channel_funding = {}   # channel_id -> {params, proofs, shared_secret, keyset_info}
channel_usage = {}     # channel_id -> {chars_served: int}
channel_largest_payment = {}  # channel_id -> {balance: int, signature: str}
channel_closed = {}    # channel_id -> {balance, receiver_proofs, sender_proofs}

# Keyset cache: (mint, keyset_id) -> keyset_info_json
keyset_cache = {}


def print_stats_table(sig=None, frame=None):
    """Print ASCII table of all channel stats. Can be called via Ctrl+\\ (SIGQUIT)."""
    print()
    print("=" * 70)
    print("  Channel Statistics (Press Ctrl+\\ to refresh)")
    print("=" * 70)
    
    if not channel_funding:
        print("  No channels registered yet.")
        print("=" * 70)
        print()
        return
    
    # Table header
    print(f"  {'ID':<10} {'Status':<8} {'Capacity':>10} {'Balance':>10} {'Usage':>10}")
    print(f"  {'-'*10} {'-'*8} {'-'*10} {'-'*10} {'-'*10}")
    
    total_balance = 0
    total_usage = 0
    
    for cid, funding in channel_funding.items():
        try:
            params = json.loads(funding["params"])
            capacity = params.get("capacity", 0)
            unit = params.get("unit", "sat")
        except:
            capacity = 0
            unit = "?"
        
        usage = channel_usage.get(cid, {}).get("chars_served", 0)
        payment = channel_largest_payment.get(cid, {})
        balance = payment.get("balance", 0)
        status = "CLOSED" if cid in channel_closed else "OPEN"
        
        short_id = cid[:8]
        print(f"  {short_id:<10} {status:<8} {capacity:>7} {unit:<3} {balance:>7} {unit:<3} {usage:>7} ch")
        
        total_balance += balance
        total_usage += usage
    
    print(f"  {'-'*10} {'-'*8} {'-'*10} {'-'*10} {'-'*10}")
    print(f"  {'TOTAL':<10} {'':<8} {'':<10} {total_balance:>7} sat {total_usage:>7} ch")
    print("=" * 70)
    print()


def fetch_keyset_info(mint_url: str, keyset_id: str, unit: str, input_fee_ppk: int = 0) -> str:
    """Fetch keyset info from mint and cache it."""
    cache_key = (mint_url, keyset_id)
    if cache_key in keyset_cache:
        return keyset_cache[cache_key]
    
    print(f"  [Keyset] Fetching keyset {keyset_id} from {mint_url}...")
    
    try:
        # Get keys for this keyset
        resp = http_requests.get(f"{mint_url}/v1/keys/{keyset_id}")
        resp.raise_for_status()
        keys_data = resp.json()["keysets"][0]["keys"]
        
        keyset_info = {
            "keysetId": keyset_id,
            "unit": unit,
            "keys": keys_data,
            "inputFeePpk": input_fee_ppk,
            "amounts": sorted([int(k) for k in keys_data.keys()], reverse=True)
        }
        
        keyset_info_json = json.dumps(keyset_info)
        keyset_cache[cache_key] = keyset_info_json
        print(f"  [Keyset] Cached keyset {keyset_id}")
        return keyset_info_json
    except Exception as e:
        print(f"  [Keyset] Failed to fetch keyset: {e}")
        return None


def initialize_keysets():
    """Fetch and cache keysets from approved mints at startup."""
    print(f"Fetching keysets from {MINT_URL}...")
    try:
        resp = http_requests.get(f"{MINT_URL}/v1/keysets")
        resp.raise_for_status()
        keysets = resp.json()["keysets"]
        
        for k in keysets:
            if k["active"] and k["unit"] == "sat":
                fetch_keyset_info(
                    MINT_URL, 
                    k["id"], 
                    k["unit"], 
                    k.get("input_fee_ppk", 0)
                )
        
        print(f"Cached {len(keyset_cache)} keysets")
    except Exception as e:
        print(f"WARNING: Failed to fetch keysets: {e}")
        print("Payment validation may fail for new channels")


class AsciiArtHost:
    """SpilmanHost implementation for ASCII art service.
    
    This class provides the callbacks that the SpilmanBridge uses to:
    - Validate channel parameters
    - Store and retrieve channel funding data
    - Calculate pricing based on usage
    - Record successful payments
    """
    
    def __init__(self, secret_key_hex: str, mint_url: str):
        self.secret_key = secret_key_hex
        self.mint_url = mint_url
        self.pubkey = secret_key_to_pubkey(secret_key_hex)
    
    def receiver_key_is_acceptable(self, pubkey: str) -> bool:
        """Check if the receiver pubkey matches our server."""
        result = pubkey == self.pubkey
        print(f"  [Bridge] receiver_key_is_acceptable:")
        print(f"           received: '{pubkey[:32]}...'")
        print(f"           expected: '{self.pubkey[:32]}...'")
        print(f"           result: {result}")
        return result
    
    def mint_and_keyset_is_acceptable(self, mint: str, keyset_id: str) -> bool:
        """Check if the mint is our approved mint."""
        result = mint == self.mint_url
        print(f"  [Bridge] mint_and_keyset_is_acceptable:")
        print(f"           mint received: '{mint}'")
        print(f"           mint expected: '{self.mint_url}'")
        print(f"           keyset_id: '{keyset_id}'")
        print(f"           result: {result}")
        return result
    
    def get_funding_and_params(self, channel_id: str):
        """Get cached funding data for a channel."""
        data = channel_funding.get(channel_id)
        if not data:
            return None
        return (
            data["params"],
            data["proofs"],
            data["shared_secret"],
            data["keyset_info"]
        )
    
    def save_funding(
        self,
        channel_id: str,
        params: str,
        proofs: str,
        shared_secret: str,
        keyset_info: str
    ):
        """Save funding data for a new channel."""
        channel_funding[channel_id] = {
            "params": params,
            "proofs": proofs,
            "shared_secret": shared_secret,
            "keyset_info": keyset_info
        }
        print(f"  [Bridge] Saved funding for channel {channel_id[:16]}...")
    
    def get_amount_due(self, channel_id: str, context_json: str) -> int:
        """Calculate total amount due based on usage + current request."""
        ctx = json.loads(context_json)
        usage = channel_usage.get(channel_id, {"chars_served": 0})
        new_chars = ctx.get("message_length", 0)
        return (usage["chars_served"] + new_chars) * PRICE_PER_CHAR
    
    def record_payment(
        self,
        channel_id: str,
        balance: int,
        signature: str,
        context_json: str
    ):
        """Record a successful payment and update usage."""
        ctx = json.loads(context_json)
        new_chars = ctx.get("message_length", 0)
        
        if channel_id not in channel_usage:
            channel_usage[channel_id] = {"chars_served": 0}
        
        channel_usage[channel_id]["chars_served"] += new_chars
        
        # Only update if this is a larger balance (prevents replay attacks)
        current = channel_largest_payment.get(channel_id, {})
        if balance > current.get("balance", 0):
            channel_largest_payment[channel_id] = {
                "balance": balance,
                "signature": signature
            }
        
        print(f"  [Bridge] Payment recorded: channel={channel_id[:16]}... "
              f"balance={balance} chars_served={channel_usage[channel_id]['chars_served']}")
    
    def is_closed(self, channel_id: str) -> bool:
        """Check if a channel has been closed."""
        return channel_id in channel_closed  # Works with dict too
    
    def get_server_config(self) -> str:
        """Return server configuration for validation."""
        return json.dumps({
            "min_expiry_in_seconds": 3600,
            "pricing": {
                "sat": {"minCapacity": 10}
            }
        })
    
    def now_seconds(self) -> int:
        """Return current Unix timestamp."""
        return int(time.time())
    
    def get_largest_balance_with_signature(self, channel_id: str):
        """Get the largest balance and its signature for unilateral closing."""
        payment = channel_largest_payment.get(channel_id)
        if not payment:
            return None
        return (payment["balance"], payment["signature"])


# Initialize host and bridge
host = AsciiArtHost(SECRET_KEY, MINT_URL)
bridge = SpilmanBridge(host, SECRET_KEY)


@app.route("/channel/params")
def get_params():
    """Return server pubkey and pricing info for channel setup."""
    return jsonify({
        "receiver_pubkey": host.pubkey,
        "pricing": {
            "sat": {
                "per_char": PRICE_PER_CHAR,
                "minCapacity": 10
            }
        },
        "mint": MINT_URL,
        "min_expiry_in_seconds": 3600,
    })


@app.route("/ascii", methods=["POST"])
def ascii_art():
    """Generate ASCII art - requires payment via X-Cashu-Channel header."""
    
    # Check for payment header
    payment_header = request.headers.get("X-Cashu-Channel")
    if not payment_header:
        return jsonify({
            "error": "Payment required",
            "reason": "Missing X-Cashu-Channel header"
        }), 402
    
    # Get message from request body
    data = request.get_json() or {}
    message = data.get("message", "")
    if not message:
        return jsonify({"error": "Missing 'message' in request body"}), 400
    
    print(f"\n[Request] ASCII art for '{message}' ({len(message)} chars)")
    
    # Create context with message length for pricing
    context = json.dumps({"message_length": len(message)})
    
    # Look up keyset info if params are provided
    keyset_info_json = None
    try:
        payment = json.loads(payment_header)
        if "params" in payment:
            params = payment["params"]
            keyset_info_json = fetch_keyset_info(
                params["mint"],
                params["keyset_id"],
                params["unit"],
                params.get("input_fee_ppk", 0)
            )
    except Exception as e:
        print(f"  [Warning] Failed to parse payment header: {e}")
    
    # Process payment through bridge
    result_json = bridge.process_payment(payment_header, context, keyset_info_json)
    result = json.loads(result_json)
    
    if not result["success"]:
        print(f"  [Payment] REJECTED: {result.get('error', 'unknown')}")
        response = jsonify(result.get("body", {"error": result.get("error")}))
        if result.get("header"):
            response.headers["X-Cashu-Channel"] = json.dumps(result["header"])
        return response, 402
    
    # Payment accepted - generate ASCII art
    cost = len(message) * PRICE_PER_CHAR
    payment_info = result.get("header", {})
    print(f"  [Payment] ACCEPTED: cost={cost} balance={payment_info.get('balance')}/{payment_info.get('capacity')}")
    
    art = pyfiglet.figlet_format(message)
    
    return jsonify({
        "art": art,
        "message": message,
        "cost": cost,
        "payment": payment_info
    })


def close_channel(channel_id: str) -> dict:
    """Close a single channel unilaterally using the largest stored payment."""
    print(f"\n[Close] Attempting to close channel {channel_id[:16]}...")
    
    # Check if already closed
    if channel_id in channel_closed:
        return {"success": False, "error": "channel already closed"}
    
    # Check if we have a payment for this channel
    if channel_id not in channel_largest_payment:
        return {"success": False, "error": "no payment recorded for channel"}
    
    # Get the close data from the bridge
    close_result_json = bridge.create_unilateral_close_data(channel_id)
    close_result = json.loads(close_result_json)
    
    if not close_result["success"]:
        print(f"  [Close] Bridge error: {close_result.get('error')}")
        return close_result
    
    swap_request = close_result["swap_request"]
    expected_total = close_result["expected_total"]
    secrets_with_blinding = close_result["secrets_with_blinding"]
    balance = channel_largest_payment[channel_id]["balance"]
    
    print(f"  [Close] Swap request created, expected_total={expected_total}")
    
    # Get channel params for mint URL
    funding = channel_funding.get(channel_id)
    if not funding:
        return {"success": False, "error": "no funding data for channel"}
    
    params = json.loads(funding["params"])
    mint_url = params["mint"]
    
    # Submit swap to mint
    print(f"  [Close] Submitting swap to mint: {mint_url}")
    try:
        response = http_requests.post(
            f"{mint_url}/v1/swap",
            json=swap_request,
            headers={"Content-Type": "application/json"}
        )
        if not response.ok:
            error_text = response.text
            print(f"  [Close] Mint rejected swap: {error_text}")
            return {"success": False, "error": f"mint rejected swap: {error_text}"}
        
        swap_response = response.json()
        print(f"  [Close] Got {len(swap_response.get('signatures', []))} blind signatures")
    except Exception as e:
        print(f"  [Close] Failed to contact mint: {e}")
        return {"success": False, "error": f"failed to contact mint: {e}"}
    
    # Unblind and verify DLEQ
    try:
        unblind_result_json = unblind_and_verify_dleq(
            json.dumps(swap_response.get("signatures", [])),
            json.dumps(secrets_with_blinding),
            funding["params"],
            funding["keyset_info"],
            funding["shared_secret"],
            balance
        )
        unblind_result = json.loads(unblind_result_json)
        print(f"  [Close] Unblinded: receiver={len(unblind_result['receiver_proofs'])} proofs "
              f"({unblind_result['receiver_sum_after_stage1']} sat), "
              f"sender={len(unblind_result['sender_proofs'])} proofs "
              f"({unblind_result['sender_sum_after_stage1']} sat)")
    except Exception as e:
        print(f"  [Close] Unblind/DLEQ verification failed: {e}")
        return {"success": False, "error": f"unblind verification failed: {e}"}
    
    # Mark channel as closed
    channel_closed[channel_id] = {
        "balance": balance,
        "receiver_proofs": unblind_result["receiver_proofs"],
        "sender_proofs": unblind_result["sender_proofs"],
        "receiver_sum": unblind_result["receiver_sum_after_stage1"],
        "sender_sum": unblind_result["sender_sum_after_stage1"]
    }
    
    print(f"  [Close] SUCCESS! Channel {channel_id[:16]} closed. "
          f"Earned {unblind_result['receiver_sum_after_stage1']} sat")
    
    return {
        "success": True,
        "channel_id": channel_id,
        "balance": balance,
        "receiver_sum": unblind_result["receiver_sum_after_stage1"],
        "sender_sum": unblind_result["sender_sum_after_stage1"]
    }


def close_all_channels():
    """Close all open channels that have payments."""
    print("\n" + "=" * 70)
    print("  Closing all channels...")
    print("=" * 70)
    
    open_channels = [cid for cid in channel_funding if cid not in channel_closed]
    
    if not open_channels:
        print("  No open channels to close.")
        print("=" * 70)
        return
    
    total_earned = 0
    closed_count = 0
    
    for cid in open_channels:
        if cid in channel_largest_payment:
            result = close_channel(cid)
            if result["success"]:
                total_earned += result["receiver_sum"]
                closed_count += 1
        else:
            print(f"  [Close] Skipping {cid[:16]}: no payment recorded")
    
    print()
    print(f"  Closed {closed_count}/{len(open_channels)} channels")
    print(f"  Total earned: {total_earned} sat")
    print("=" * 70)
    print()


def cli_listener():
    """Background thread that listens for CLI commands."""
    print("CLI ready. Commands: 's' = stats, 'c' = close all, 'q' = quit")
    
    while True:
        try:
            cmd = input().strip().lower()
            
            if cmd == 's':
                print_stats_table()
            elif cmd == 'c':
                close_all_channels()
            elif cmd == 'q':
                print("\n[Shutdown] Closing all channels before exit...")
                close_all_channels()
                print("[Shutdown] Exiting...")
                os._exit(0)
            elif cmd:
                print(f"  Unknown command: '{cmd}'. Use 's' (stats), 'c' (close), 'q' (quit)")
        except EOFError:
            # stdin closed, exit gracefully
            break
        except Exception as e:
            print(f"  CLI error: {e}")


if __name__ == "__main__":
    print("=" * 60)
    print("ASCII Art Server - Spilman Payment Channel Demo")
    print("=" * 60)
    print()
    
    # Fetch keysets at startup
    initialize_keysets()
    print()
    
    print(f"Server pubkey: {host.pubkey}")
    print(f"Mint URL:      {MINT_URL}")
    print(f"Pricing:       {PRICE_PER_CHAR} sat per character")
    print(f"Listening on:  http://0.0.0.0:{PORT}")
    print()
    print("Endpoints:")
    print(f"  GET  http://localhost:{PORT}/channel/params")
    print(f"  POST http://localhost:{PORT}/ascii")
    print()
    print("Commands (type and press Enter):")
    print("  s = show channel statistics")
    print("  c = close all channels (settle with mint)")
    print("  q = close all and quit")
    print()
    print("Press Ctrl+\\ for quick stats (no Enter needed)")
    print()
    print("=" * 60)
    print()
    
    # Register SIGQUIT handler (Ctrl+\) to print stats table
    signal.signal(signal.SIGQUIT, print_stats_table)
    
    # Start CLI listener thread
    cli_thread = threading.Thread(target=cli_listener, daemon=True)
    cli_thread.start()
    
    app.run(host="0.0.0.0", port=PORT, debug=False)
