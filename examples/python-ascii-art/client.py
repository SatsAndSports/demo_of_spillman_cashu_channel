"""
ASCII Art Client - Creates channel and makes paid requests

Demonstrates the Spilman payment channel client in Python.

Usage:
    python client.py [messages...]
    
Examples:
    python client.py Hello World Cashu
    python client.py "Hello World"

Environment variables:
    MINT_URL - Mint URL (default: http://localhost:3338)
    SERVER_URL - ASCII art server URL (default: http://localhost:5000)
"""

import sys
import json
import time
import requests
import os

# Optional QR code support
try:
    import qrcode
except ImportError:
    qrcode = None

from cdk_spilman import (
    generate_keypair,
    compute_shared_secret,
    channel_parameters_get_channel_id,
    create_funding_outputs,
    construct_proofs,
    create_signed_balance_update,
)

MINT_URL = os.environ.get("MINT_URL", "http://localhost:3338")
SERVER_URL = os.environ.get("SERVER_URL", "http://localhost:5000")


def fetch_keyset_info(mint_url: str) -> dict:
    """Fetch active keyset info from mint."""
    print(f"  Fetching keysets from {mint_url}...")
    
    # Get keysets
    keysets_resp = requests.get(f"{mint_url}/v1/keysets")
    keysets_resp.raise_for_status()
    keysets = keysets_resp.json()["keysets"]
    
    # Find active sat keyset
    active = None
    for k in keysets:
        if k["unit"] == "sat" and k["active"]:
            active = k
            break
    
    if not active:
        raise Exception("No active sat keyset found")
    
    keyset_id = active["id"]
    print(f"  Found keyset: {keyset_id}")
    
    # Get keys for this keyset
    keys_resp = requests.get(f"{mint_url}/v1/keys/{keyset_id}")
    keys_resp.raise_for_status()
    keys_data = keys_resp.json()["keysets"][0]
    
    return {
        "keysetId": keyset_id,
        "unit": "sat",
        "inputFeePpk": active.get("input_fee_ppk", 0),
        "keys": keys_data["keys"]
    }


def mint_funding_token(mint_url: str, amount: int, blinded_messages: list) -> list:
    """Mint tokens by requesting a Lightning invoice and waiting for payment."""
    print(f"  Requesting mint quote for {amount} sat...")
    
    # 1. Request quote
    quote_resp = requests.post(
        f"{mint_url}/v1/mint/quote/bolt11",
        json={"amount": amount, "unit": "sat"}
    )
    quote_resp.raise_for_status()
    quote = quote_resp.json()
    quote_id = quote["quote"]
    invoice = quote.get("request", "").strip()
    
    print(f"  Quote ID: {quote_id[:24]}...")
    
    # 2. Display invoice and QR code
    if invoice:
        print()
        print("  " + "=" * 56)
        print("  PAY THIS INVOICE TO FUND THE CHANNEL")
        print("  " + "=" * 56)
        print()
        print(f"  {invoice}")
        print()
        
        # Display QR code if qrcode library is available
        if qrcode:
            print("  Scan this QR code with your Lightning wallet:")
            print()
            qr = qrcode.QRCode(
                error_correction=qrcode.constants.ERROR_CORRECT_M,  # Medium error correction for better scanning
                box_size=1,
                border=4,  # Larger quiet zone for reliable scanning
            )
            qr.add_data(invoice.upper())  # BOLT11 invoices are case-insensitive, uppercase is more compact
            qr.make(fit=True)
            qr.print_ascii(invert=True)
            print()
        else:
            print("  (Install 'qrcode' package to see QR code: pip install qrcode)")
            print()
        
        print("  " + "=" * 56)
        print()
    
    # 3. Wait for quote to be paid (60 seconds timeout for manual payment)
    print("  Waiting for payment (Nutshell test mint may auto-pay)...")
    for attempt in range(120):  # 60 seconds total
        check_resp = requests.get(f"{mint_url}/v1/mint/quote/bolt11/{quote_id}")
        check_resp.raise_for_status()
        status = check_resp.json()
        
        state = status.get("state", status.get("paid"))
        if state == "PAID" or state is True:
            print("  Payment received!")
            break
        
        # Show progress every 5 seconds
        if attempt > 0 and attempt % 10 == 0:
            print(f"  Still waiting... ({attempt // 2}s)")
        
        time.sleep(0.5)
    else:
        raise Exception("Quote was not paid in time (60s timeout)")
    
    # 4. Mint tokens
    print("  Minting tokens...")
    mint_resp = requests.post(
        f"{mint_url}/v1/mint/bolt11",
        json={"quote": quote_id, "outputs": blinded_messages}
    )
    mint_resp.raise_for_status()
    
    signatures = mint_resp.json()["signatures"]
    print(f"  Got {len(signatures)} blind signatures")
    
    return signatures


def main():
    # Get messages from command line or use defaults
    messages = sys.argv[1:] if len(sys.argv) > 1 else ["Hello", "Cashu", "World"]
    
    print()
    print("=" * 60)
    print("ASCII Art Client - Spilman Payment Channel Demo")
    print("=" * 60)
    print()
    print(f"Mint URL:   {MINT_URL}")
    print(f"Server URL: {SERVER_URL}")
    print(f"Messages:   {messages}")
    print()
    
    # 1. Get server params
    print("[1/8] Fetching server params...")
    try:
        server_params = requests.get(f"{SERVER_URL}/channel/params").json()
    except requests.exceptions.ConnectionError:
        print(f"\nERROR: Cannot connect to server at {SERVER_URL}")
        print("Make sure the server is running: python server.py")
        sys.exit(1)
    
    charlie_pubkey = server_params["receiver_pubkey"]
    print(f"  Server pubkey: {charlie_pubkey[:24]}...")
    print()
    
    # 2. Generate Alice keypair
    print("[2/8] Generating keypair...")
    alice_secret, alice_pubkey = generate_keypair()
    print(f"  Alice pubkey: {alice_pubkey[:24]}...")
    print()
    
    # 3. Fetch keyset info
    print("[3/8] Fetching keyset info from mint...")
    try:
        keyset_info = fetch_keyset_info(MINT_URL)
    except requests.exceptions.ConnectionError:
        print(f"\nERROR: Cannot connect to mint at {MINT_URL}")
        print("Make sure Nutshell mint is running at localhost:3338")
        sys.exit(1)
    print()
    
    # 4. Compute shared secret
    print("[4/8] Computing shared secret...")
    shared_secret = compute_shared_secret(alice_secret, charlie_pubkey)
    print(f"  Shared secret: {shared_secret[:24]}...")
    print()
    
    # 5. Calculate capacity and build channel params
    print("[5/8] Building channel parameters...")
    total_chars = sum(len(m) for m in messages)
    capacity = max(total_chars + 20, 50)  # Some headroom
    
    channel_params = {
        "alice_pubkey": alice_pubkey,
        "charlie_pubkey": charlie_pubkey,
        "mint": MINT_URL,
        "unit": "sat",
        "capacity": capacity,
        "maximum_amount": 64,
        "locktime": int(time.time()) + 7200,  # 2 hours
        "setup_timestamp": int(time.time()),
        "sender_nonce": f"demo-{int(time.time())}",
        "keyset_id": keyset_info["keysetId"],
        "input_fee_ppk": keyset_info["inputFeePpk"],
    }
    
    # Get channel ID
    channel_id = channel_parameters_get_channel_id(
        json.dumps(channel_params),
        shared_secret,
        json.dumps(keyset_info)
    )
    print(f"  Channel ID: {channel_id[:24]}...")
    print(f"  Capacity:   {capacity} sat")
    print()
    
    # 6. Create funding outputs
    print("[6/8] Creating funding outputs...")
    funding = json.loads(create_funding_outputs(
        json.dumps(channel_params),
        alice_secret,
        json.dumps(keyset_info)
    ))
    print(f"  Funding amount: {funding['funding_token_nominal']} sat")
    print(f"  Blinded messages: {len(funding['blinded_messages'])}")
    print()
    
    # 7. Mint the funding token
    print("[7/8] Minting funding token...")
    signatures = mint_funding_token(
        MINT_URL,
        funding["funding_token_nominal"],
        funding["blinded_messages"]
    )
    print()
    
    # 8. Construct proofs
    print("[8/8] Constructing proofs...")
    proofs = json.loads(construct_proofs(
        json.dumps(signatures),
        json.dumps(funding["secrets_with_blinding"]),
        json.dumps(keyset_info)
    ))
    print(f"  Got {len(proofs)} proofs")
    print()
    
    print("=" * 60)
    print("Channel funded! Making requests...")
    print("=" * 60)
    print()
    
    # Make paid requests
    balance = 0
    first_request = True
    total_cost = 0
    
    for i, msg in enumerate(messages, 1):
        cost = len(msg)
        balance += cost
        total_cost += cost
        
        print(f"[Request {i}/{len(messages)}] '{msg}' ({cost} sat)")
        
        # Create signed balance update
        update = json.loads(create_signed_balance_update(
            json.dumps(channel_params),
            json.dumps(keyset_info),
            alice_secret,
            json.dumps(proofs),
            balance
        ))
        
        # Build payment header
        payment = {
            "channel_id": channel_id,
            "balance": balance,
            "signature": update["signature"],
        }
        
        # Include params and proofs on first request
        if first_request:
            payment["params"] = channel_params
            payment["funding_proofs"] = proofs
            first_request = False
        
        # Make request
        response = requests.post(
            f"{SERVER_URL}/ascii",
            json={"message": msg},
            headers={"X-Cashu-Channel": json.dumps(payment)}
        )
        
        if response.status_code == 200:
            result = response.json()
            payment_info = result.get("payment", {})
            print(f"  Payment accepted! Balance: {balance}/{capacity} sat")
            print("-" * 40)
            print(result["art"])
        else:
            print(f"  FAILED! Status: {response.status_code}")
            try:
                error = response.json()
                print(f"  Error: {error}")
            except:
                print(f"  Response: {response.text}")
            break
    
    print("=" * 60)
    print(f"Done! Total spent: {total_cost} sat")
    print(f"Channel balance: {balance}/{capacity} sat")
    print(f"Remaining: {capacity - balance} sat")
    print("=" * 60)


if __name__ == "__main__":
    main()
