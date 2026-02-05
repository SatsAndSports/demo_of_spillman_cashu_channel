"""
Integration tests for CDK Spilman Python bindings.

These tests require a Cashu mint running at MINT_URL (default: http://localhost:3338).

Run with: MINT_URL=http://localhost:3338 pytest tests/ -v
"""

import json
import os
import time

import pytest
import requests

import cdk_spilman


def get_mint_url():
    return os.environ.get("MINT_URL", "http://localhost:3338")


def fetch_active_keyset(mint_url: str, unit: str) -> dict | None:
    """Fetch the active keyset for a unit from the mint."""
    try:
        # Get keysets
        resp = requests.get(f"{mint_url}/v1/keysets")
        resp.raise_for_status()
        keysets = resp.json()["keysets"]

        # Find active keyset for unit
        active_keyset = None
        for k in keysets:
            if k["unit"] == unit and k["active"]:
                active_keyset = k
                break

        if not active_keyset:
            return None

        keyset_id = active_keyset["id"]
        input_fee_ppk = active_keyset.get("input_fee_ppk", 0)

        # Get keys for this keyset
        resp = requests.get(f"{mint_url}/v1/keys/{keyset_id}")
        resp.raise_for_status()
        keys = resp.json()["keysets"][0]["keys"]

        return {
            "keysetId": keyset_id,
            "unit": unit,
            "keys": keys,
            "inputFeePpk": input_fee_ppk,
        }
    except Exception as e:
        print(f"Failed to fetch keyset: {e}")
        return None


class TestMintConnectivity:
    """Test that we can connect to the mint."""

    def test_mint_connectivity(self):
        """Verify mint is reachable and returns info."""
        mint_url = get_mint_url()
        resp = requests.get(f"{mint_url}/v1/info")
        assert resp.status_code == 200, f"Mint returned status {resp.status_code}"

        info = resp.json()
        print(f"Connected to mint: {info.get('name', 'unknown')} (version {info.get('version', 'unknown')})")


class TestChannelSetup:
    """Test the client-side channel setup flow."""

    def test_generate_keypair(self):
        """Test keypair generation."""
        secret, pubkey = cdk_spilman.generate_keypair()

        assert len(secret) == 64, f"Secret should be 64 hex chars, got {len(secret)}"
        assert len(pubkey) == 66, f"Pubkey should be 66 hex chars (compressed), got {len(pubkey)}"
        assert pubkey.startswith("02") or pubkey.startswith("03"), "Pubkey should be compressed format"

        print(f"Generated keypair: pubkey={pubkey[:16]}...")

    def test_secret_key_to_pubkey(self):
        """Test deriving pubkey from secret."""
        secret, expected_pubkey = cdk_spilman.generate_keypair()
        derived_pubkey = cdk_spilman.secret_key_to_pubkey(secret)

        assert derived_pubkey == expected_pubkey, "Derived pubkey should match"

    def test_compute_shared_secret(self):
        """Test ECDH shared secret computation."""
        alice_secret, alice_pubkey = cdk_spilman.generate_keypair()
        bob_secret, bob_pubkey = cdk_spilman.generate_keypair()

        # Both parties should compute the same shared secret
        shared_alice = cdk_spilman.compute_shared_secret(alice_secret, bob_pubkey)
        shared_bob = cdk_spilman.compute_shared_secret(bob_secret, alice_pubkey)

        assert shared_alice == shared_bob, "Shared secrets should match"
        assert len(shared_alice) == 64, f"Shared secret should be 64 hex chars, got {len(shared_alice)}"

        print(f"Computed shared secret: {shared_alice[:16]}...")

    def test_funding_outputs_and_channel_id(self):
        """Test the full channel setup flow with keyset from mint."""
        mint_url = get_mint_url()

        # Generate keypairs
        alice_secret, alice_pubkey = cdk_spilman.generate_keypair()
        _, receiver_pubkey = cdk_spilman.generate_keypair()

        print(f"Generated sender pubkey: {alice_pubkey[:16]}...")
        print(f"Generated receiver pubkey: {receiver_pubkey[:16]}...")

        # Fetch active keyset from mint
        keyset_info = fetch_active_keyset(mint_url, "sat")
        assert keyset_info is not None, "Failed to fetch keyset from mint"
        keyset_json = json.dumps(keyset_info)
        print(f"Fetched keyset: {keyset_info['keysetId']}")

        # Compute shared secret
        shared_secret = cdk_spilman.compute_shared_secret(alice_secret, receiver_pubkey)
        print(f"Computed shared secret: {shared_secret[:16]}...")

        # Build channel parameters
        now = int(time.time())
        params = {
            "alice_pubkey": alice_pubkey,
            "charlie_pubkey": receiver_pubkey,
            "mint": mint_url,
            "unit": "sat",
            "capacity": 100,
            "maximum_amount": 64,
            "locktime": now + 7200,
            "setup_timestamp": now,
            "sender_nonce": f"test-python-{now}",
            "keyset_id": keyset_info["keysetId"],
            "input_fee_ppk": keyset_info["inputFeePpk"],
        }
        params_json = json.dumps(params)

        # Get channel ID
        channel_id = cdk_spilman.channel_parameters_get_channel_id(params_json, shared_secret, keyset_json)
        assert len(channel_id) == 64, f"Channel ID should be 64 hex chars, got {len(channel_id)}"
        print(f"Channel ID: {channel_id}")

        # Create funding outputs
        funding_json = cdk_spilman.create_funding_outputs(params_json, alice_secret, keyset_json)
        funding = json.loads(funding_json)

        funding_nominal = funding["funding_token_nominal"]
        blinded_messages = funding["blinded_messages"]

        print(f"Funding nominal: {funding_nominal} sat, outputs: {len(blinded_messages)}")

        # Verify we got reasonable outputs
        assert funding_nominal >= 100, f"Expected funding >= 100, got {funding_nominal}"
        assert len(blinded_messages) > 0, "Expected at least one blinded message"

    def test_channel_id_deterministic(self):
        """Test that channel ID computation is deterministic."""
        mint_url = get_mint_url()

        alice_secret, alice_pubkey = cdk_spilman.generate_keypair()
        _, receiver_pubkey = cdk_spilman.generate_keypair()

        keyset_info = fetch_active_keyset(mint_url, "sat")
        assert keyset_info is not None, "Failed to fetch keyset from mint"
        keyset_json = json.dumps(keyset_info)

        shared_secret = cdk_spilman.compute_shared_secret(alice_secret, receiver_pubkey)

        now = int(time.time())
        params = {
            "alice_pubkey": alice_pubkey,
            "charlie_pubkey": receiver_pubkey,
            "mint": mint_url,
            "unit": "sat",
            "capacity": 100,
            "maximum_amount": 64,
            "locktime": now + 7200,
            "setup_timestamp": now,
            "sender_nonce": "deterministic-test",
            "keyset_id": keyset_info["keysetId"],
            "input_fee_ppk": keyset_info["inputFeePpk"],
        }
        params_json = json.dumps(params)

        # Compute channel ID twice
        channel_id_1 = cdk_spilman.channel_parameters_get_channel_id(params_json, shared_secret, keyset_json)
        channel_id_2 = cdk_spilman.channel_parameters_get_channel_id(params_json, shared_secret, keyset_json)

        assert channel_id_1 == channel_id_2, "Channel ID should be deterministic"
        print(f"Channel ID is deterministic: {channel_id_1}")
