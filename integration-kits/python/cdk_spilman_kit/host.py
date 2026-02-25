import json
import time
import requests
from typing import Optional, Tuple, List, Dict, Any
from .stores import SpilmanStores, ChannelClosedData
from .keysets import refresh_keyset_cache

DEFAULT_TIMEOUT = 10

# We import these from cdk_spilman which should be installed
try:
    from cdk_spilman import secret_key_to_pubkey, compute_channel_secret, sign_with_tweaked_key_util
except ImportError:
    # Fallback for development/testing if not installed in environment
    secret_key_to_pubkey = None
    compute_channel_secret = None
    sign_with_tweaked_key_util = None

class BaseSpilmanHost:
    def __init__(self, secret_key: str, mint_url: str, pricing: Dict[str, Any], stores: SpilmanStores):
        if secret_key_to_pubkey is None:
            raise RuntimeError("cdk_spilman is required to use cdk_spilman_kit")
        self.secret_key = secret_key
        self.mint_url = mint_url
        self.pricing = pricing
        self.stores = stores
        self.pubkey = secret_key_to_pubkey(secret_key)

    def receiver_key_is_acceptable(self, pubkey_hex: str) -> bool:
        return pubkey_hex == self.pubkey

    def mint_and_keyset_is_acceptable(self, mint: str, keyset_id: str) -> bool:
        if mint != self.mint_url:
            return False
        return (mint, keyset_id) in self.stores.keyset_cache

    def get_funding_and_params(self, channel_id: str) -> Optional[Tuple[str, str, str, str]]:
        data = self.stores.channel_funding.get(channel_id)
        if not data:
            return None
        return (
            data["params"],
            data["proofs"],
            data["channel_secret"],
            data["keyset_info"]
        )

    def save_funding(self, channel_id, params, proofs, secret, keyset, initial_balance, initial_signature):
        self.stores.channel_funding[channel_id] = {
            "params": params,
            "proofs": proofs,
            "channel_secret": secret,
            "keyset_info": keyset
        }
        current = self.stores.channel_largest_payment.get(channel_id)
        if not current or initial_balance > current.get("balance", 0):
            self.stores.channel_largest_payment[channel_id] = {
                "balance": initial_balance,
                "signature": initial_signature
            }

    def get_amount_due(self, channel_id: str, context_json: Optional[str]) -> int:
        # Default implementation assumes pricing based on the channel's unit
        # Users should override this or provide a custom context handler
        funding = self.stores.channel_funding.get(channel_id)
        unit = "sat"
        if funding:
            params = json.loads(funding["params"])
            unit = params.get("unit", "sat")
        
        # This is service-specific. By default, we might just return 0 
        # unless the user overrides this.
        return 0 

    def record_payment(self, channel_id: str, balance: int, signature: str, context_json: str):
        current = self.stores.channel_largest_payment.get(channel_id, {})
        if balance > current.get("balance", 0):
            self.stores.channel_largest_payment[channel_id] = {
                "balance": balance,
                "signature": signature
            }

    def get_channel_state(self, channel_id: str) -> str:
        if channel_id in self.stores.channel_closed:
            return "closed"
        if channel_id in self.stores.channel_closing:
            return "closing"
        return "open"

    def mark_channel_closing(self, channel_id, locktime, balance, signature):
        if channel_id in self.stores.channel_closed:
            raise ValueError("channel already closed")
        self.stores.channel_closing[channel_id] = {
            "locktime": locktime,
            "balance": balance,
            "signature": signature
        }

    def get_closing_data(self, channel_id: str) -> Optional[Dict[str, Any]]:
        return self.stores.channel_closing.get(channel_id)

    def get_channel_policy(self, unit: str) -> Optional[Tuple[int, int, Optional[int]]]:
        p = self.pricing.get(unit)
        if not p:
            return None
        return (3600, p.get("minCapacity", 10), p.get("maxAmountPerOutput"))

    def now_seconds(self) -> int:
        return int(time.time())

    def get_balance_and_signature_for_unilateral_exit(self, channel_id: str) -> Optional[Tuple[int, str]]:
        payment = self.stores.channel_largest_payment.get(channel_id)
        if not payment:
            return None
        return (payment["balance"], payment["signature"])

    def get_active_keyset_ids(self, mint: str, unit: str) -> List[str]:
        return [kid for (m, kid), entry in self.stores.keyset_cache.items() 
                if m == mint and entry.unit == unit and entry.active]

    def get_keyset_info(self, mint: str, keyset_id: str) -> Optional[str]:
        entry = self.stores.keyset_cache.get((mint, keyset_id))
        return entry.info_json if entry else None

    def call_mint_swap(self, mint_url: str, swap_request_json: str) -> str:
        resp = requests.post(
            f"{mint_url}/v1/swap",
            json=json.loads(swap_request_json),
            timeout=DEFAULT_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.text

    def refresh_all_keysets(self, mint: str):
        refresh_keyset_cache(self.stores, mint, list(self.pricing.keys()))

    def mark_channel_closed(self, channel_id, locktime, balance, receiver_proofs_json, sender_proofs_json, receiver_sum, sender_sum):
        if channel_id in self.stores.channel_closed:
            raise ValueError("channel already closed")
        self.stores.channel_closed[channel_id] = ChannelClosedData(
            locktime=locktime,
            balance=balance,
            receiver_proofs=json.loads(receiver_proofs_json),
            sender_proofs=json.loads(sender_proofs_json),
            receiver_sum=receiver_sum,
            sender_sum=sender_sum
        )

    def compute_channel_secret(self, charlie_pubkey_hex: str, alice_pubkey_hex: str) -> str:
        if compute_channel_secret is None:
             raise RuntimeError("cdk_spilman.compute_channel_secret is not available")
        return compute_channel_secret(self.secret_key, alice_pubkey_hex)

    def sign_with_tweaked_key(self, signer_pubkey_hex: str, message_hex: str, tweak_scalar_hex: str) -> str:
        if sign_with_tweaked_key_util is None:
            raise RuntimeError("cdk_spilman.sign_with_tweaked_key_util is not available")
        return sign_with_tweaked_key_util(self.secret_key, message_hex, tweak_scalar_hex)
