import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

@dataclass
class ChannelClosedData:
    locktime: int
    balance: int
    receiver_proofs: List[Dict[str, Any]]
    sender_proofs: List[Dict[str, Any]]
    receiver_sum: int
    sender_sum: int

@dataclass
class KeysetCacheEntry:
    info_json: str
    active: bool
    unit: str

class SpilmanStores:
    def __init__(self):
        # channel_id -> {params, proofs, channel_secret, keyset_info}
        self.channel_funding: Dict[str, Dict[str, str]] = {}
        # channel_id -> {balance: int, signature: str}
        self.channel_largest_payment: Dict[str, Dict[str, Any]] = {}
        # channel_id -> {locktime, balance, signature}
        self.channel_closing: Dict[str, Dict[str, Any]] = {}
        # channel_id -> ChannelClosedData
        self.channel_closed: Dict[str, ChannelClosedData] = {}
        # (mint, keyset_id) -> KeysetCacheEntry
        self.keyset_cache: Dict[Tuple[str, str], KeysetCacheEntry] = {}
        # channel_id -> Dict[str, Any] (Custom usage tracking)
        self.channel_usage: Dict[str, Dict[str, Any]] = {}

    def get_active_pricing(self, all_pricing: Dict[str, Any]) -> Dict[str, Any]:
        active_units = {entry.unit for entry in self.keyset_cache.values() if entry.active}
        return {u: p for u, p in all_pricing.items() if u in active_units}

    def get_mints_units_keysets(self) -> Dict[str, Dict[str, List[str]]]:
        result = {}
        for (mint, kid), entry in self.keyset_cache.items():
            if not entry.active:
                continue
            if mint not in result:
                result[mint] = {}
            if entry.unit not in result[mint]:
                result[mint][entry.unit] = []
            result[mint][entry.unit].append(kid)
        return result
