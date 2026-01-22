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
from typing import Optional
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

# Keyset cache: (mint, keyset_id) -> {info_json: str, active: bool}
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


def fetch_details_for_one_keyset(mint_url: str, keyset_id: str, unit: str, input_fee_ppk: int = 0, set_the_active_flag: Optional[bool] = None) -> str:
    """Fetch keyset info from mint and cache it.

    Optionally, set the value of the 'active' flag
    """
    cache_key = (mint_url, keyset_id)
    if cache_key in keyset_cache:
        # Update active status if provided
        if set_the_active_flag is not None:
            keyset_cache[cache_key]["active"] = set_the_active_flag
        return keyset_cache[cache_key]["info_json"]
    
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
        
        # If set_the_active_flag is None, we default to False for new discoveries
        active_status = set_the_active_flag if set_the_active_flag is not None else False
        
        keyset_cache[cache_key] = {
            "info_json": keyset_info_json,
            "active": active_status,
            "unit": unit
        }
        print(f"  [Keyset] Cached keyset {keyset_id} (active={active_status})")
        return keyset_info_json
    except Exception as e:
        print(f"  [Keyset] Failed to fetch keyset: {e}")
        return None


def initialize_keysets():
    """Fetch and cache keysets (active and inactive) from approved mints at startup."""
    print(f"Fetching keysets from {MINT_URL}...")
    try:
        resp = http_requests.get(f"{MINT_URL}/v1/keysets")
        resp.raise_for_status()
        keysets = resp.json()["keysets"]
        
        for k in keysets:
            if k["unit"] == "sat":
                fetch_details_for_one_keyset(
                    MINT_URL, 
                    k["id"], 
                    k["unit"], 
                    k.get("input_fee_ppk", 0),
                    set_the_active_flag=k.get("active", False)
                )
        
        print(f"Cached {len(keyset_cache)} keysets")
    except Exception as e:
        print(f"WARNING: Failed to fetch keysets: {e}")
        print("Payment validation may fail for new channels")


class AsciiArtHost:
    """
    SpilmanHost implementation for the ASCII Art service.
    
    This class provides the necessary callbacks for the SpilmanBridge to 
    manage channel lifecycle, validate parameters, calculate pricing, 
    and persist payment state.
    """
    
    def __init__(self, secret_key_hex: str, mint_url: str):
        self.secret_key = secret_key_hex
        self.mint_url = mint_url
        self.pubkey = secret_key_to_pubkey(secret_key_hex)
    
    def receiver_key_is_acceptable(self, pubkey: str) -> bool:
        """
        Validates if the provided receiver public key is acceptable to this server.

        Args:
            pubkey: The receiver's public key as a hex string.

        Returns:
            True if the key matches this server's public key, False otherwise.
        """
        result = pubkey == self.pubkey
        print(f"  [Bridge] receiver_key_is_acceptable:")
        print(f"           received: '{pubkey[:32]}...'")
        print(f"           expected: '{self.pubkey[:32]}...'")
        print(f"           result: {result}")
        return result
    
    def mint_and_keyset_is_acceptable(self, mint: str, keyset_id: str) -> bool:
        """
        Validates if the provided mint URL and keyset ID are acceptable.

        Args:
            mint: The mint's URL.
            keyset_id: The ID of the keyset being used.

        Returns:
            True if the mint matches the configured URL and the keyset is cached.
        """
        # 1. Verify the mint matches our configured one
        if mint != self.mint_url:
            print(f"  [Bridge] mint REJECTED: expected '{self.mint_url}', got '{mint}'")
            return False
            
        # 2. Verify we have the keyset in our cache (active or inactive)
        is_cached = (mint, keyset_id) in keyset_cache
        
        print(f"  [Bridge] mint_and_keyset_is_acceptable:")
        print(f"           mint: '{mint}'")
        print(f"           keyset_id: '{keyset_id}'")
        print(f"           is_cached: {is_cached}")
        
        return is_cached
    
    def get_funding_and_params(self, channel_id: str):
        """
        Retrieves cached funding proofs and parameters for a specific channel.

        Args:
            channel_id: The unique ID of the payment channel.

        Returns:
            A tuple of (params_json, funding_proofs_json, shared_secret_hex, 
            keyset_info_json) if found, otherwise None.
        """
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
        """
        Persists funding data for a newly discovered channel.

        Args:
            channel_id: The unique ID of the payment channel.
            params: The full channel parameters as a JSON string.
            proofs: The funding proofs as a JSON string.
            shared_secret: The ECDH shared secret as a hex string.
            keyset_info: The keyset information as a JSON string.
        """
        channel_funding[channel_id] = {
            "params": params,
            "proofs": proofs,
            "shared_secret": shared_secret,
            "keyset_info": keyset_info
        }
        print(f"  [Bridge] Saved funding for channel {channel_id[:16]}...")
    
    def get_amount_due(self, channel_id: str, context_json: str) -> int:
        """
        Calculates the cumulative amount due for a channel based on total usage.

        Args:
            channel_id: The unique ID of the payment channel.
            context_json: Request-specific data used for pricing.

        Returns:
            The total nominal value (in sats) that Charlie should have received 
            to cover all service rendered to this channel so far.
        """
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
        """
        Atomically records a verified payment and updates the channel's cumulative usage.

        This method performs two critical state updates:
        1. Increments service-specific usage metrics (e.g., characters served) 
           based on metadata provided in the request context.
        2. Persists the highest balance and its corresponding signature. This 
           record serves as the server's proof-of-claim when settling the 
           channel with the mint.

        Args:
            channel_id: The unique ID of the payment channel.
            balance: The new total balance authorized by the client.
            signature: Alice's Schnorr signature proving her authorization 
                      of the new balance.
            context_json: A JSON string containing request-specific data used 
                         to track usage.
        """
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
        """
        Checks if a channel has already been closed and settled.

        Args:
            channel_id: The unique ID of the payment channel.

        Returns:
            True if the channel is closed, False otherwise.
        """
        return channel_id in channel_closed  # Works with dict too
    
    def get_server_config(self) -> str:
        """
        Returns the server's validation policy configuration.

        Returns:
            A JSON string defining minimum expiry and per-unit pricing minimums.
        """
        return json.dumps({
            "min_expiry_in_seconds": 3600,
            "pricing": {
                "sat": {"minCapacity": 10}
            }
        })
    
    def now_seconds(self) -> int:
        """
        Returns the current system time in seconds.

        Returns:
            Unix timestamp.
        """
        return int(time.time())
    
    def get_largest_balance_with_signature(self, channel_id: str):
        """
        Retrieves the highest recorded balance and signature for a channel.

        Used during unilateral channel closure to recover the latest off-chain 
        payment state.

        Args:
            channel_id: The unique ID of the payment channel.

        Returns:
            A tuple of (balance, signature) if a payment exists, otherwise None.
        """
        payment = channel_largest_payment.get(channel_id)
        if not payment:
            return None
        return (payment["balance"], payment["signature"])

    def get_active_keyset_ids(self, mint: str, unit: str):
        """
        Lists the keyset IDs currently considered active for new channels.

        Args:
            mint: The mint URL.
            unit: The currency unit (e.g., 'sat').

        Returns:
            A list of active keyset ID strings.
        """
        return [kid for (m, kid), data in keyset_cache.items() if m == mint and data.get("unit") == unit and data.get("active")]

    def get_keyset_info(self, mint: str, keyset_id: str):
        """
        Retrieves the full KeysetInfo JSON for a specific keyset.

        Args:
            mint: The mint URL.
            keyset_id: The unique ID of the keyset.

        Returns:
            The KeysetInfo JSON string if found, otherwise None.
        """
        data = keyset_cache.get((mint, keyset_id))
        return data["info_json"] if data else None


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
            keyset_info_json = fetch_details_for_one_keyset(
                params["mint"],
                params["keyset_id"],
                params["unit"],
                params.get("input_fee_ppk", 0),
                set_the_active_flag=None
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
    output_keyset_info = json.dumps(close_result["output_keyset_info"])
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
            balance,
            output_keyset_info
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
