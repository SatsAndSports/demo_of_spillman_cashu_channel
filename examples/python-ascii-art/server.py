"""
ASCII Art Generator Server - Pay 1 sat per character

Demonstrates the Spilman payment channel bridge in Python.

Endpoints:
    GET  /channel/params    - Get server pubkey and pricing info
    POST /channel/register  - Pre-register a channel (balance=0, no usage)
    POST /ascii             - Generate ASCII art (requires X-Cashu-Channel header)

Usage:
    python server.py

Environment variables:
    SERVER_SECRET_KEY - Server's secret key (64 hex chars, default: random)
    MINT_URL - Mint URL (default: http://localhost:3338)
    PORT - Server port (default: 5000)
"""

from flask import Flask, request, jsonify
from typing import Optional
from cdk_spilman import SpilmanBridge, secret_key_to_pubkey
import pyfiglet
import json
import base64
import time
import os
import requests as http_requests
import secrets

app = Flask(__name__)

# Configuration
SECRET_KEY = os.environ.get("SERVER_SECRET_KEY") or secrets.token_hex(32)
MINT_URL = os.environ.get("MINT_URL", "http://localhost:3338")
PORT = int(os.environ.get("PORT", "5000"))
# Pricing per character for each unit (superset — filtered dynamically by active mint keysets)
ALL_PRICING = {
    "sat":  {"per_char": 1,    "minCapacity": 10},
    "msat": {"per_char": 1000, "minCapacity": 10000},  # 1 sat = 1000 msat
    "usd":  {"per_char": 1,    "minCapacity": 10},     # 1 cent per char
}


def get_active_pricing():
    """Returns pricing filtered to only units that have active keysets in the mint."""
    active_units = {data["unit"] for data in keyset_cache.values() if data.get("active")}
    return {u: p for u, p in ALL_PRICING.items() if u in active_units}


def get_mints_units_keysets():
    """Returns {mint_url: {unit: [keyset_id, ...]}} for all active keysets."""
    result = {}
    for (mint, kid), data in keyset_cache.items():
        if not data.get("active"):
            continue
        if mint not in result:
            result[mint] = {}
        unit = data["unit"]
        if unit not in result[mint]:
            result[mint][unit] = []
        result[mint][unit].append(kid)
    return result

# In-memory stores
channel_funding = {}   # channel_id -> {params, proofs, shared_secret, keyset_info}
channel_usage = {}     # channel_id -> {chars_served: int}
channel_largest_payment = {}  # channel_id -> {balance: int, signature: str}
channel_closing = {}   # channel_id -> {locktime, balance, signature}  (pre-swap state)
channel_closed = {}    # channel_id -> {balance, receiver_proofs, sender_proofs}

# Keyset cache: (mint, keyset_id) -> {info_json: str, active: bool}
keyset_cache = {}


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


def get_mint_version(mint_url: str) -> str:
    """Fetch mint version from /v1/info endpoint."""
    try:
        resp = http_requests.get(f"{mint_url}/v1/info", timeout=2)
        if resp.ok:
            return resp.json().get("version", "unknown")
    except Exception:
        pass
    return "unknown"


def initialize_keysets():
    """Fetch and cache keysets (active and inactive) from approved mints at startup."""
    print(f"Fetching keysets from {MINT_URL}...")
    try:
        resp = http_requests.get(f"{MINT_URL}/v1/keysets")
        resp.raise_for_status()
        keysets = resp.json()["keysets"]
        
        for k in keysets:
            if k["unit"] in ALL_PRICING:
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


def refresh_active_keysets(mint_url: str):
    """Re-fetch keysets from mint to update active status in cache.
    
    Called when a swap fails (e.g., "Inactive Keyset" error) to refresh
    the keyset cache before retrying.
    """
    print(f"  [Keyset] Refreshing keysets from {mint_url}...")
    try:
        resp = http_requests.get(f"{mint_url}/v1/keysets")
        resp.raise_for_status()
        keysets = resp.json()["keysets"]
        
        for k in keysets:
            if k.get("unit") in ALL_PRICING:
                fetch_details_for_one_keyset(
                    mint_url,
                    k["id"],
                    k["unit"],
                    k.get("input_fee_ppk", 0),
                    set_the_active_flag=k.get("active", False)
                )
        print(f"  [Keyset] Refresh complete, {len(keyset_cache)} keysets cached")
    except Exception as e:
        print(f"  [Keyset] Refresh failed: {e}")


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
    
    def get_amount_due(self, channel_id: str, context_json: Optional[str]) -> int:
        """
        Calculates the cumulative amount due for a channel based on total usage.

        Args:
            channel_id: The unique ID of the payment channel.
            context_json: Request-specific data used for pricing. 
                         If None, calculates based on existing usage only.

        Returns:
            The total nominal value (in sats) that Charlie should have received 
            to cover all service rendered to this channel so far.
        """
        usage = channel_usage.get(channel_id, {"chars_served": 0})
        total_chars = usage["chars_served"]

        if context_json:
            try:
                ctx = json.loads(context_json)
                new_chars = ctx.get("message_length", 0)
                total_chars += new_chars
            except Exception as e:
                print(f"  [Bridge] Error parsing context: {e}")

        # Look up unit from stored channel params
        funding = channel_funding.get(channel_id)
        if funding:
            params = json.loads(funding["params"])
            unit_pricing = ALL_PRICING.get(params.get("unit", "sat"), ALL_PRICING["sat"])
            return total_chars * unit_pricing["per_char"]
        return total_chars * ALL_PRICING["sat"]["per_char"]
    
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
    
    def get_channel_state(self, channel_id: str) -> str:
        """
        Get the current state of a channel.

        Args:
            channel_id: The unique ID of the payment channel.

        Returns:
            "open", "closing", or "closed"
        """
        if channel_id in channel_closed:
            return "closed"
        elif channel_id in channel_closing:
            return "closing"
        else:
            return "open"

    def mark_channel_closing(
        self,
        channel_id: str,
        locktime: int,
        balance: int,
        signature: str
    ):
        """
        Mark a channel as closing (pre-swap state).

        Called before attempting the mint swap. The host should store the closing
        parameters (enough to reconstruct swap request later).

        Args:
            channel_id: The unique ID of the payment channel.
            locktime: The channel's locktime.
            balance: The balance at close.
            signature: The client's Schnorr signature authorizing this balance.
        """
        channel_closing[channel_id] = {
            "locktime": locktime,
            "balance": balance,
            "signature": signature
        }
        print(f"  [Bridge] Channel {channel_id[:16]}... marked CLOSING balance={balance}")

    def get_closing_data(self, channel_id: str):
        """
        Get the stored closing data for a channel in CLOSING state.

        Args:
            channel_id: The unique ID of the payment channel.

        Returns:
            A dict with {locktime, balance, signature} if channel is closing, None otherwise.
        """
        return channel_closing.get(channel_id)
    
    def get_channel_policy(self) -> str:
        """
        Returns the server's validation policy configuration.

        Returns:
            A JSON string defining minimum expiry and per-unit pricing minimums.
        """
        return json.dumps({
            "min_expiry_in_seconds": 3600,
            "pricing": get_active_pricing(),
        })
    
    def now_seconds(self) -> int:
        """
        Returns the current system time in seconds.

        Returns:
            Unix timestamp.
        """
        return int(time.time())
    
    def get_balance_and_signature_for_unilateral_exit(self, channel_id: str):
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

    def call_mint_swap(self, mint_url: str, swap_request_json: str) -> str:
        """
        Call the mint's /v1/swap endpoint.

        The host is responsible for HTTP communication with the mint.
        Returns the full JSON response body on success.
        Raises an exception on HTTP error.

        Args:
            mint_url: The mint's base URL.
            swap_request_json: The swap request as a JSON string.

        Returns:
            The mint's response body as a JSON string.
        """
        print(f"  [Host] call_mint_swap to {mint_url}")
        swap_request = json.loads(swap_request_json)
        response = http_requests.post(
            f"{mint_url}/v1/swap",
            json=swap_request,
            headers={"Content-Type": "application/json"}
        )
        if not response.ok:
            raise Exception(f"Mint rejected swap: {response.text}")
        print(f"  [Host] Got {len(response.json().get('signatures', []))} blind signatures")
        return response.text

    def mark_channel_closed(
        self,
        channel_id: str,
        locktime: int,
        balance: int,
        receiver_proofs_json: str,
        sender_proofs_json: str,
        receiver_sum: int,
        sender_sum: int
    ):
        """
        Mark a channel as closed and persist the final state.

        Called after successful unblinding and DLEQ verification.
        The host should store the proofs and mark the channel as closed.

        Args:
            channel_id: The unique ID of the payment channel.
            locktime: The channel's locktime.
            balance: The balance at which the channel was closed.
            receiver_proofs_json: JSON array of receiver's P2PK proofs.
            sender_proofs_json: JSON array of sender's P2PK proofs (change).
            receiver_sum: Sum of receiver proof amounts.
            sender_sum: Sum of sender proof amounts.
        """
        channel_closed[channel_id] = {
            "locktime": locktime,
            "balance": balance,
            "receiver_proofs": json.loads(receiver_proofs_json),
            "sender_proofs": json.loads(sender_proofs_json),
            "receiver_sum": receiver_sum,
            "sender_sum": sender_sum
        }
        print(f"  [Host] Channel {channel_id[:16]} marked closed. "
              f"Receiver: {receiver_sum} sat, Sender: {sender_sum} sat")


# Initialize host and bridge
host = AsciiArtHost(SECRET_KEY, MINT_URL)
bridge = SpilmanBridge(host, SECRET_KEY)


@app.route("/channel/params")
def get_params():
    """Return server pubkey and pricing info for channel setup."""
    return jsonify({
        "receiver_pubkey": host.pubkey,
        "pricing": get_active_pricing(),
        "mints_units_keysets": get_mints_units_keysets(),
        "min_expiry_in_seconds": 3600,
    })


@app.route("/channel/register", methods=["POST"])
def register_channel():
    """Pre-register a channel with balance=0 signature (no usage recorded)."""
    data = request.get_json() or {}
    
    channel_id = data.get("channel_id")
    balance = data.get("balance")
    signature = data.get("signature")
    params = data.get("params")
    funding_proofs = data.get("funding_proofs")
    
    # Validate required fields
    if not channel_id or signature is None or not params or not funding_proofs:
        return jsonify({
            "error": "Bad request",
            "reason": "missing required fields: channel_id, signature, params, funding_proofs",
        }), 400
    
    # balance must be 0 for registration
    if balance != 0:
        return jsonify({
            "error": "Bad request",
            "reason": f"funding requires balance=0, got {balance}",
        }), 400
    
    print(f"\n[Register] Channel {channel_id[:16]}...")
    
    # Build request body in the same format as payment
    register_body = {
        "channel_id": channel_id,
        "balance": 0,
        "signature": signature,
        "params": params,
        "funding_proofs": funding_proofs,
    }
    
    # Use fund_channel to validate and store the channel
    # fund_channel now returns FundChannelResult object and raises RuntimeError on error
    try:
        result = bridge.fund_channel(json.dumps(register_body))
    except RuntimeError as e:
        error_msg = str(e)
        print(f"  [Register] REJECTED: {error_msg}")
        
        # Determine HTTP status from error type
        status = 402  # Payment Required (default)
        lower_msg = error_msg.lower()
        if ("invalid base64" in lower_msg or
            "invalid utf8" in lower_msg or
            "invalid json" in lower_msg or
            "missing field" in lower_msg or
            "missing channel_id" in lower_msg or
            "missing signature" in lower_msg or
            ("expected" in lower_msg and ("string" in lower_msg or "integer" in lower_msg or "u64" in lower_msg))):
            status = 400
        elif "internal" in lower_msg or "misconfigured" in lower_msg:
            status = 500
        
        return jsonify({
            "success": False,
            "error": "Registration failed",
            "reason": error_msg,
            "status": status,
        }), status
    
    print(f"  [Register] SUCCESS! channel={result.channel_id[:16]} capacity={result.capacity} already_known={result.already_known}")
    return jsonify({
        "success": True,
        "channel_id": result.channel_id,
        "capacity": result.capacity,
        "already_known": result.already_known,
    })


@app.route("/ascii", methods=["POST"])
def ascii_art():
    """Generate ASCII art - requires payment via X-Cashu-Channel header."""
    
    # Check for payment header
    payment_header_b64 = request.headers.get("X-Cashu-Channel")
    if not payment_header_b64:
        return jsonify({
            "error": "Payment required",
            "reason": "Missing X-Cashu-Channel header"
        }), 402
    
    # Decode base64-encoded payment header
    try:
        payment_header = base64.b64decode(payment_header_b64).decode()
    except Exception as e:
        return jsonify({
            "error": "Invalid payment header",
            "reason": "invalid base64 encoding"
        }), 400
    
    # Get message from request body
    data = request.get_json() or {}
    message = data.get("message", "")
    if not message:
        return jsonify({"error": "Missing 'message' in request body"}), 400
    
    print(f"\n[Request] ASCII art for '{message}' ({len(message)} chars)")
    
    # Create context with message length for pricing
    context = json.dumps({"message_length": len(message)})
    
    # Process payment through bridge
    # process_payment now returns PaymentSuccess object and raises RuntimeError on error
    try:
        result = bridge.process_payment(payment_header, context)
    except RuntimeError as e:
        error_msg = str(e)
        print(f"  [Payment] REJECTED: {error_msg}")
        
        # Determine HTTP status from error type
        status = 402  # Payment Required (default)
        lower_msg = error_msg.lower()
        if ("invalid base64" in lower_msg or
            "invalid utf8" in lower_msg or
            "invalid json" in lower_msg or
            "missing field" in lower_msg or
            "missing channel_id" in lower_msg or
            "missing signature" in lower_msg or
            ("expected" in lower_msg and ("string" in lower_msg or "integer" in lower_msg or "u64" in lower_msg))):
            status = 400
        elif "internal" in lower_msg or "misconfigured" in lower_msg:
            status = 500
        
        response = jsonify({"error": "Payment failed", "reason": error_msg})
        response.headers["X-Cashu-Channel"] = json.dumps({"error": error_msg})
        return response, status
    
    # Payment accepted - generate ASCII art
    payment_info = {
        "channel_id": result.channel_id,
        "balance": result.balance,
        "amount_due": result.amount_due,
        "capacity": result.capacity,
    }
    # Look up unit-specific pricing from channel params
    funding = channel_funding.get(payment_info.get("channel_id", ""))
    unit_pricing = ALL_PRICING["sat"]  # default
    if funding:
        params = json.loads(funding["params"])
        unit_pricing = ALL_PRICING.get(params.get("unit", "sat"), ALL_PRICING["sat"])
    cost = len(message) * unit_pricing["per_char"]
    print(f"  [Payment] ACCEPTED: cost={cost} balance={payment_info.get('balance')}/{payment_info.get('capacity')}")
    
    art = pyfiglet.figlet_format(message)
    
    return jsonify({
        "art": art,
        "message": message,
        "cost": cost,
        "payment": payment_info
    })


@app.route("/channel/<channel_id>/status")
def channel_status(channel_id: str):
    """Get channel status including balance and closed state."""
    funding = channel_funding.get(channel_id)
    if not funding:
        return jsonify({"error": "unknown channel"}), 404
    
    params = json.loads(funding["params"])
    payment = channel_largest_payment.get(channel_id, {})
    closed_info = channel_closed.get(channel_id)
    
    return jsonify({
        "channel_id": channel_id,
        "capacity": params.get("capacity", 0),
        "balance": payment.get("balance", 0),
        "amount_due": host.get_amount_due(channel_id, None),
        "closed": closed_info is not None,
        "closed_amount": closed_info.get("balance") if closed_info else None,
    })


@app.route("/channel/<channel_id>/close", methods=["POST"])
def cooperative_close(channel_id: str):
    """Cooperative channel close - client provides balance and signature."""
    data = request.get_json() or {}
    
    balance = data.get("balance")
    signature = data.get("signature")
    params = data.get("params")
    funding_proofs = data.get("funding_proofs")
    
    if balance is None or not signature:
        return jsonify({"error": "missing balance or signature"}), 400
    
    print(f"\n[CooperativeClose] Channel {channel_id[:16]}... balance={balance}")
    
    # Check if already closed - return idempotent response
    if channel_id in channel_closed:
        closed_info = channel_closed[channel_id]
        if closed_info.get("balance") == balance:
            print(f"  [CooperativeClose] Already closed at same balance, returning cached result")
            return jsonify({
                "success": True,
                "channel_id": channel_id,
                "already_closed": True,
                "total_value": closed_info.get("receiver_sum", 0) + closed_info.get("sender_sum", 0),
                "receiver_sum": closed_info.get("receiver_sum", 0),
                "sender_sum": closed_info.get("sender_sum", 0),
                "sender_proofs": closed_info.get("sender_proofs", []),
            })
        else:
            return jsonify({
                "error": "channel already closed at different balance",
                "closed_amount": closed_info.get("balance"),
                "requested_amount": balance,
            }), 400
    
    # Build payment request for the bridge
    payment_request = {
        "channel_id": channel_id,
        "balance": balance,
        "signature": signature,
    }
    if params:
        payment_request["params"] = params
    if funding_proofs:
        payment_request["funding_proofs"] = funding_proofs
    
    # Execute cooperative close via bridge (handles swap, retry, unblind, mark closed)
    # Returns CloseSuccess on success, raises RuntimeError with JSON-encoded CloseError on failure
    try:
        result = bridge.execute_cooperative_close(json.dumps(payment_request))
    except RuntimeError as e:
        error_msg = str(e)
        # Try to parse CloseError JSON from error message
        try:
            close_error = json.loads(error_msg)
            reason = close_error.get("reason", error_msg)
            status = close_error.get("status", 500)
        except json.JSONDecodeError:
            reason = error_msg
            status = 500
        print(f"  [CooperativeClose] Failed: {reason}")
        return jsonify({"success": False, "error": reason, "reason": reason}), status
    
    print(f"  [CooperativeClose] SUCCESS! total_value={result.total_value}")
    return jsonify({
        "success": True,
        "channel_id": result.channel_id,
        "total_value": result.total_value,
        "receiver_sum": result.receiver_sum,
        "sender_sum": result.sender_sum,
        "sender_proofs": json.loads(result.sender_proofs),
        "already_closed": result.already_closed,
    })


@app.route("/channel/<channel_id>/unilateral-close", methods=["POST"])
def unilateral_close_endpoint(channel_id: str):
    """Server-initiated channel close using stored payment proof."""
    print(f"\n[UnilateralClose] Channel {channel_id[:16]}...")
    
    # Check if already closed - return idempotent response
    if channel_id in channel_closed:
        closed_info = channel_closed[channel_id]
        print(f"  [UnilateralClose] Already closed, returning cached result")
        return jsonify({
            "success": True,
            "channel_id": channel_id,
            "already_closed": True,
            "earnedBeforeStage2Fees": closed_info.get("receiver_sum", 0),
        })
    
    # Check if channel exists
    if channel_id not in channel_funding:
        return jsonify({"error": "unknown channel"}), 404
    
    # Execute unilateral close via bridge (handles swap, retry, unblind, mark closed)
    # Returns CloseSuccess on success, raises RuntimeError with JSON-encoded CloseError on failure
    try:
        result = bridge.execute_unilateral_close(channel_id)
    except RuntimeError as e:
        error_msg = str(e)
        # Try to parse CloseError JSON from error message
        try:
            close_error = json.loads(error_msg)
            reason = close_error.get("reason", error_msg)
            status = close_error.get("status", 500)
        except json.JSONDecodeError:
            reason = error_msg
            status = 500
        print(f"  [UnilateralClose] Failed: {reason}")
        return jsonify({"success": False, "error": reason}), status
    
    print(f"  [UnilateralClose] SUCCESS! Earned {result.receiver_sum} sat")
    return jsonify({
        "success": True,
        "channel_id": channel_id,
        "already_closed": False,
        "earnedBeforeStage2Fees": result.receiver_sum,
    })


if __name__ == "__main__":
    # Fetch keysets at startup
    initialize_keysets()
    
    print(f"Server pubkey: {host.pubkey}")
    print(f"Mint URL:      {MINT_URL}")
    print(f"Mint version:  {get_mint_version(MINT_URL)}")
    active = get_active_pricing()
    pricing_str = ", ".join(f"{u}={p['per_char']}/char" for u, p in active.items())
    print(f"Pricing:       {pricing_str or '(no active units)'}")
    print(f"Listening on:  http://0.0.0.0:{PORT}")
    
    app.run(host="0.0.0.0", port=PORT, debug=False)
