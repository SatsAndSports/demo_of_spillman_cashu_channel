//! In-memory stores for Spilman channel state.
//!
//! These stores track channel funding, usage, balances, and closed status.
//! In production, you'd persist these to a database.

use std::collections::HashMap;
use std::sync::RwLock;

// ============================================================================
// Type Definitions
// ============================================================================

#[derive(Clone)]
pub struct ChannelFundingData {
    pub params_json: String,
    pub funding_proofs_json: String,
    pub shared_secret: String,
    pub keyset_info_json: String,
}

#[derive(Clone)]
pub struct ChannelBalance {
    pub balance: u64,
    pub signature: String,
}

#[derive(Clone, Default)]
pub struct ChannelUsage {
    pub chars_served: u64,
}

/// Data stored when a channel enters CLOSING state (pre-swap).
#[derive(Clone)]
pub struct ClosingChannelData {
    pub locktime: u64,
    pub balance: u64,
    pub signature: String,
}

/// Data stored when a channel is fully CLOSED (post-swap).
#[derive(Clone)]
#[allow(dead_code)]
pub struct ClosedChannelData {
    pub locktime: u64,
    pub closed_amount: u64,
    pub value_after_stage1: u64,
    pub receiver_sum: u64,
    pub sender_sum: u64,
    pub receiver_proofs_json: String,
    pub sender_proofs_json: String,
}

#[derive(Clone)]
pub struct KeysetCacheEntry {
    pub info_json: String,
    pub active: bool,
    pub unit: String,
}

// ============================================================================
// Stores Container
// ============================================================================

/// Thread-safe container for all channel state stores.
pub struct Stores {
    funding: RwLock<HashMap<String, ChannelFundingData>>,
    balance: RwLock<HashMap<String, ChannelBalance>>,
    usage: RwLock<HashMap<String, ChannelUsage>>,
    closing: RwLock<HashMap<String, ClosingChannelData>>,
    closed: RwLock<HashMap<String, ClosedChannelData>>,
    keysets: RwLock<HashMap<String, KeysetCacheEntry>>,
}

impl Default for Stores {
    fn default() -> Self {
        Self::new()
    }
}

impl Stores {
    pub fn new() -> Self {
        Self {
            funding: RwLock::new(HashMap::new()),
            balance: RwLock::new(HashMap::new()),
            usage: RwLock::new(HashMap::new()),
            closing: RwLock::new(HashMap::new()),
            closed: RwLock::new(HashMap::new()),
            keysets: RwLock::new(HashMap::new()),
        }
    }

    // ========================================================================
    // Channel Funding
    // ========================================================================

    pub fn get_funding(&self, channel_id: &str) -> Option<ChannelFundingData> {
        self.funding
            .read()
            .expect("funding lock poisoned")
            .get(channel_id)
            .cloned()
    }

    pub fn insert_funding(&self, channel_id: &str, data: ChannelFundingData) {
        let mut store = self.funding.write().expect("funding lock poisoned");
        if !store.contains_key(channel_id) {
            tracing::info!(
                "  [Store] Saved funding for channel {}...",
                &channel_id[..8.min(channel_id.len())]
            );
            store.insert(channel_id.to_string(), data);
        }
    }

    #[allow(dead_code)]
    pub fn all_funding(&self) -> HashMap<String, ChannelFundingData> {
        self.funding.read().expect("funding lock poisoned").clone()
    }

    // ========================================================================
    // Channel Balance
    // ========================================================================

    pub fn get_balance(&self, channel_id: &str) -> Option<ChannelBalance> {
        self.balance
            .read()
            .expect("balance lock poisoned")
            .get(channel_id)
            .cloned()
    }

    pub fn update_balance(&self, channel_id: &str, balance: u64, signature: &str) {
        let mut store = self.balance.write().expect("balance lock poisoned");
        let should_update = store
            .get(channel_id)
            .map(|b| balance > b.balance)
            .unwrap_or(true);
        if should_update {
            let old_balance = store.get(channel_id).map(|b| b.balance).unwrap_or(0);
            tracing::info!(
                "  [Store] Balance updated: channel={} {} -> {}",
                &channel_id[..8.min(channel_id.len())],
                old_balance,
                balance
            );
            store.insert(
                channel_id.to_string(),
                ChannelBalance {
                    balance,
                    signature: signature.to_string(),
                },
            );
        }
    }

    // ========================================================================
    // Channel Usage
    // ========================================================================

    pub fn get_usage(&self, channel_id: &str) -> Option<ChannelUsage> {
        self.usage
            .read()
            .expect("usage lock poisoned")
            .get(channel_id)
            .cloned()
    }

    pub fn record_chars_served(&self, channel_id: &str, chars: u64) {
        let mut store = self.usage.write().expect("usage lock poisoned");
        let usage = store.entry(channel_id.to_string()).or_default();
        usage.chars_served += chars;
        tracing::info!(
            "  [Store] Usage: channel={} chars={}",
            &channel_id[..8.min(channel_id.len())],
            usage.chars_served
        );
    }

    // ========================================================================
    // Channel Closing (pre-swap state)
    // ========================================================================

    pub fn is_closing(&self, channel_id: &str) -> bool {
        self.closing
            .read()
            .expect("closing lock poisoned")
            .contains_key(channel_id)
    }

    pub fn get_closing(&self, channel_id: &str) -> Option<ClosingChannelData> {
        self.closing
            .read()
            .expect("closing lock poisoned")
            .get(channel_id)
            .cloned()
    }

    pub fn mark_closing(&self, channel_id: &str, locktime: u64, balance: u64, signature: &str) {
        let mut store = self.closing.write().expect("closing lock poisoned");
        store.insert(
            channel_id.to_string(),
            ClosingChannelData {
                locktime,
                balance,
                signature: signature.to_string(),
            },
        );
        tracing::info!(
            "  [Store] Channel marked CLOSING: {} balance={}",
            &channel_id[..8.min(channel_id.len())],
            balance
        );
    }

    /// Remove from closing when transitioning to closed.
    fn remove_closing(&self, channel_id: &str) {
        self.closing
            .write()
            .expect("closing lock poisoned")
            .remove(channel_id);
    }

    // ========================================================================
    // Channel Closed (post-swap state)
    // ========================================================================

    pub fn is_closed(&self, channel_id: &str) -> bool {
        self.closed
            .read()
            .expect("closed lock poisoned")
            .contains_key(channel_id)
    }

    pub fn get_closed(&self, channel_id: &str) -> Option<ClosedChannelData> {
        self.closed
            .read()
            .expect("closed lock poisoned")
            .get(channel_id)
            .cloned()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mark_closed(
        &self,
        channel_id: &str,
        locktime: u64,
        closed_amount: u64,
        value_after_stage1: u64,
        receiver_sum: u64,
        sender_sum: u64,
        receiver_proofs_json: &str,
        sender_proofs_json: &str,
    ) {
        // Remove from closing state (if present)
        self.remove_closing(channel_id);

        let mut store = self.closed.write().expect("closed lock poisoned");
        store.insert(
            channel_id.to_string(),
            ClosedChannelData {
                locktime,
                closed_amount,
                value_after_stage1,
                receiver_sum,
                sender_sum,
                receiver_proofs_json: receiver_proofs_json.to_string(),
                sender_proofs_json: sender_proofs_json.to_string(),
            },
        );
        tracing::info!(
            "  [Store] Channel closed: {} amount={} value={}",
            &channel_id[..8.min(channel_id.len())],
            closed_amount,
            value_after_stage1
        );
    }

    // ========================================================================
    // Keyset Cache
    // ========================================================================

    fn keyset_key(mint: &str, keyset_id: &str) -> String {
        format!("{}|{}", mint, keyset_id)
    }

    pub fn get_keyset(&self, mint: &str, keyset_id: &str) -> Option<KeysetCacheEntry> {
        let key = Self::keyset_key(mint, keyset_id);
        self.keysets
            .read()
            .expect("keysets lock poisoned")
            .get(&key)
            .cloned()
    }

    pub fn set_keyset(&self, mint: &str, keyset_id: &str, entry: KeysetCacheEntry) {
        let key = Self::keyset_key(mint, keyset_id);
        tracing::info!(
            "  [Store] Cached keyset: {} (active={})",
            keyset_id,
            entry.active
        );
        self.keysets
            .write()
            .expect("keysets lock poisoned")
            .insert(key, entry);
    }

    pub fn has_keyset(&self, mint: &str, keyset_id: &str) -> bool {
        let key = Self::keyset_key(mint, keyset_id);
        self.keysets
            .read()
            .expect("keysets lock poisoned")
            .contains_key(&key)
    }

    pub fn get_active_keyset_ids(&self, mint: &str, unit: &str) -> Vec<String> {
        let prefix = format!("{}|", mint);
        self.keysets
            .read()
            .expect("keysets lock poisoned")
            .iter()
            .filter(|(key, entry)| key.starts_with(&prefix) && entry.unit == unit && entry.active)
            .filter_map(|(key, _)| key.split('|').nth(1).map(String::from))
            .collect()
    }

    #[allow(dead_code)]
    pub fn clear_keysets_for_mint(&self, mint: &str) {
        let prefix = format!("{}|", mint);
        let mut store = self.keysets.write().expect("keysets lock poisoned");
        store.retain(|key, _| !key.starts_with(&prefix));
        tracing::info!("  [Store] Cleared cached keysets for mint: {}", mint);
    }

    /// Returns { mintUrl: { unit: [keysetId, ...] } } for all active keysets.
    pub fn get_mints_units_keysets(&self) -> HashMap<String, HashMap<String, Vec<String>>> {
        let mut result: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
        let store = self.keysets.read().expect("keysets lock poisoned");
        for (key, entry) in store.iter() {
            if !entry.active {
                continue;
            }
            let parts: Vec<&str> = key.splitn(2, '|').collect();
            if parts.len() != 2 {
                continue;
            }
            let mint = parts[0].to_string();
            let keyset_id = parts[1].to_string();
            result
                .entry(mint)
                .or_default()
                .entry(entry.unit.clone())
                .or_default()
                .push(keyset_id);
        }
        result
    }

    /// Returns the set of units that have at least one active keyset across all mints.
    pub fn get_active_units(&self) -> std::collections::HashSet<String> {
        let store = self.keysets.read().expect("keysets lock poisoned");
        store
            .values()
            .filter(|entry| entry.active)
            .map(|entry| entry.unit.clone())
            .collect()
    }
}

// ============================================================================
// Channel Status (for status endpoint)
// ============================================================================

#[derive(serde::Serialize)]
pub struct ChannelStatus {
    pub channel_id: String,
    pub capacity: u64,
    pub balance: u64,
    pub chars_served: u64,
    pub amount_due: u64,
    pub closed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_amount: Option<u64>,
}

#[derive(Clone)]
pub struct UnitPricing {
    pub per_char: u64,
    pub min_capacity: u64,
}

pub fn get_channel_status(
    stores: &Stores,
    channel_id: &str,
    pricing: &HashMap<String, UnitPricing>,
) -> Result<ChannelStatus, &'static str> {
    let funding = stores.get_funding(channel_id).ok_or("unknown channel")?;

    let params: serde_json::Value =
        serde_json::from_str(&funding.params_json).map_err(|_| "invalid params")?;

    let capacity = params.get("capacity").and_then(|v| v.as_u64()).unwrap_or(0);
    let unit = params.get("unit").and_then(|v| v.as_str()).unwrap_or("sat");

    let balance_data = stores.get_balance(channel_id);
    let usage = stores.get_usage(channel_id);
    let closed_data = stores.get_closed(channel_id);

    let chars_served = usage.map(|u| u.chars_served).unwrap_or(0);
    let price_per_char = pricing.get(unit).map(|p| p.per_char).unwrap_or(0);
    let amount_due = chars_served * price_per_char;

    Ok(ChannelStatus {
        channel_id: channel_id.to_string(),
        capacity,
        balance: balance_data.map(|b| b.balance).unwrap_or(0),
        chars_served,
        amount_due,
        closed: closed_data.is_some(),
        closed_amount: closed_data.map(|c| c.closed_amount),
    })
}
