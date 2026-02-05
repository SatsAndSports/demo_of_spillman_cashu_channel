//! SpilmanHost implementation for ASCII art server.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use cdk::nuts::{CurrencyUnit, Id, PublicKey};
use cdk::spilman::{ChannelState, ClosingData, SpilmanHost};

use crate::stores::{ChannelFundingData, KeysetCacheEntry, Stores, UnitPricing};

/// SpilmanHost implementation for the ASCII art server.
#[derive(Clone)]
pub struct AsciiArtHost {
    pub stores: Arc<Stores>,
    pub server_pubkey: PublicKey,
    pub mint_url: String,
    pub pricing: HashMap<String, UnitPricing>,
    pub min_expiry_seconds: u64,
}

impl AsciiArtHost {
    /// Create a new AsciiArtHost instance.
    pub fn new(
        stores: Arc<Stores>,
        mint_url: &str,
        server_pubkey: PublicKey,
        pricing: HashMap<String, UnitPricing>,
        min_expiry_seconds: u64,
    ) -> Self {
        Self {
            stores,
            server_pubkey,
            mint_url: mint_url.to_string(),
            pricing,
            min_expiry_seconds,
        }
    }

    /// Get the unit for a channel from its funding params.
    fn get_channel_unit(&self, channel_id: &str) -> Option<String> {
        let funding = self.stores.get_funding(channel_id)?;
        let params: serde_json::Value = serde_json::from_str(&funding.params_json).ok()?;
        params.get("unit")?.as_str().map(String::from)
    }

    /// Fetch keysets from the mint and populate the cache (async version for startup).
    pub async fn fetch_keysets_async(&self) -> Result<(), String> {
        let client = reqwest::Client::new();

        // Fetch /v1/keysets
        let keysets_url = format!("{}/v1/keysets", self.mint_url);
        let keysets_resp: serde_json::Value = client
            .get(&keysets_url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch keysets: {}", e))?
            .json()
            .await
            .map_err(|e| format!("Failed to parse keysets response: {}", e))?;

        let keysets = keysets_resp
            .get("keysets")
            .and_then(|k| k.as_array())
            .ok_or("Invalid keysets response")?;

        tracing::info!("Fetched {} keysets from {}", keysets.len(), self.mint_url);

        for keyset in keysets {
            let keyset_id = keyset
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or("Keyset missing id")?;
            let unit = keyset
                .get("unit")
                .and_then(|v| v.as_str())
                .ok_or("Keyset missing unit")?;
            let active = keyset.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
            let input_fee_ppk = keyset
                .get("input_fee_ppk")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            // Fetch keys for this keyset
            let keys_url = format!("{}/v1/keys/{}", self.mint_url, keyset_id);
            let keys_resp: serde_json::Value = client
                .get(&keys_url)
                .send()
                .await
                .map_err(|e| format!("Failed to fetch keys for {}: {}", keyset_id, e))?
                .json()
                .await
                .map_err(|e| format!("Failed to parse keys response for {}: {}", keyset_id, e))?;

            // Build KeysetInfo JSON (matching the format expected by the bridge)
            let keys = keys_resp
                .get("keysets")
                .and_then(|k| k.as_array())
                .and_then(|arr| arr.first())
                .and_then(|k| k.get("keys"))
                .cloned()
                .unwrap_or(serde_json::json!({}));

            let keyset_info = serde_json::json!({
                "keysetId": keyset_id,
                "unit": unit,
                "keys": keys,
                "inputFeePpk": input_fee_ppk,
            });

            self.stores.set_keyset(
                &self.mint_url,
                keyset_id,
                KeysetCacheEntry {
                    info_json: keyset_info.to_string(),
                    active,
                    unit: unit.to_string(),
                },
            );
        }

        Ok(())
    }

    /// Call mint swap endpoint (async version for route handlers).
    pub async fn call_mint_swap_async(
        &self,
        mint_url: &str,
        swap_request_json: &str,
    ) -> Result<String, String> {
        let client = reqwest::Client::new();
        let url = format!("{}/v1/swap", mint_url);

        let resp = client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(swap_request_json.to_string())
            .send()
            .await
            .map_err(|e| format!("Swap request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Swap failed: {} - {}", status, body));
        }

        resp.text()
            .await
            .map_err(|e| format!("Failed to read swap response: {}", e))
    }
}

impl SpilmanHost for AsciiArtHost {
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool {
        receiver_pubkey == &self.server_pubkey
    }

    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool {
        // Check mint matches and keyset is in cache
        mint == self.mint_url && self.stores.has_keyset(mint, &keyset_id.to_string())
    }

    fn get_funding_and_params(&self, channel_id: &str) -> Option<(String, String, String, String)> {
        self.stores.get_funding(channel_id).map(|f| {
            (
                f.params_json,
                f.funding_proofs_json,
                f.shared_secret,
                f.keyset_info_json,
            )
        })
    }

    fn save_funding(
        &self,
        channel_id: &str,
        params_json: &str,
        funding_proofs_json: &str,
        shared_secret_hex: &str,
        keyset_info_json: &str,
        initial_balance: u64,
        initial_signature: &str,
    ) {
        self.stores.insert_funding(
            channel_id,
            ChannelFundingData {
                params_json: params_json.to_string(),
                funding_proofs_json: funding_proofs_json.to_string(),
                shared_secret: shared_secret_hex.to_string(),
                keyset_info_json: keyset_info_json.to_string(),
            },
        );
        // Store the initial balance/signature for closing
        self.stores.update_balance(channel_id, initial_balance, initial_signature);
    }

    fn get_amount_due(&self, channel_id: &str, context_json: Option<&str>) -> u64 {
        // Get existing usage
        let existing_chars = self
            .stores
            .get_usage(channel_id)
            .map(|u| u.chars_served)
            .unwrap_or(0);

        // Parse context to get pending chars
        let pending_chars = context_json
            .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
            .and_then(|v| v.get("chars")?.as_u64())
            .unwrap_or(0);

        // Get unit from funding params
        let unit = self
            .get_channel_unit(channel_id)
            .unwrap_or_else(|| "sat".to_string());
        let per_char = self.pricing.get(&unit).map(|p| p.per_char).unwrap_or(1);

        (existing_chars + pending_chars) * per_char
    }

    fn record_payment(&self, channel_id: &str, balance: u64, signature: &str, context_json: &str) {
        // Update balance
        self.stores.update_balance(channel_id, balance, signature);

        // Update usage
        if let Some(chars) = serde_json::from_str::<serde_json::Value>(context_json)
            .ok()
            .and_then(|v| v.get("chars")?.as_u64())
        {
            self.stores.record_chars_served(channel_id, chars);
        }
    }

    fn get_channel_state(&self, channel_id: &str) -> ChannelState {
        if self.stores.is_closed(channel_id) {
            ChannelState::Closed
        } else if self.stores.is_closing(channel_id) {
            ChannelState::Closing
        } else {
            ChannelState::Open
        }
    }

    fn mark_channel_closing(
        &self,
        channel_id: &str,
        locktime: u64,
        balance: u64,
        signature: &str,
    ) -> Result<(), String> {
        // Check if channel is already closed
        if self.stores.is_closed(channel_id) {
            return Err("channel already closed".to_string());
        }
        self.stores.mark_closing(channel_id, locktime, balance, signature);
        Ok(())
    }

    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        self.stores.get_closing(channel_id).map(|data| ClosingData {
            locktime: data.locktime,
            balance: data.balance,
            signature: data.signature,
        })
    }

    fn get_channel_policy(&self) -> String {
        // Build pricing with minCapacity and optional maxAmountPerOutput (matching TS server format)
        let pricing_json: serde_json::Value = self
            .pricing
            .iter()
            .map(|(unit, p)| {
                let mut pricing_obj = serde_json::json!({
                    "per_char": p.per_char,
                    "minCapacity": p.min_capacity,
                });
                if let Some(max_amount) = p.max_amount_per_output {
                    pricing_obj["maxAmountPerOutput"] = serde_json::json!(max_amount);
                }
                (unit.clone(), pricing_obj)
            })
            .collect();

        serde_json::json!({
            "min_expiry_in_seconds": self.min_expiry_seconds,
            "pricing": pricing_json
        })
        .to_string()
    }

    fn now_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
    }

    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        channel_id: &str,
    ) -> Option<(u64, String)> {
        self.stores
            .get_balance(channel_id)
            .map(|b| (b.balance, b.signature))
    }

    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id> {
        self.stores
            .get_active_keyset_ids(mint, &unit.to_string())
            .into_iter()
            .filter_map(|id_str| id_str.parse().ok())
            .collect()
    }

    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String> {
        self.stores
            .get_keyset(mint, &keyset_id.to_string())
            .map(|e| e.info_json)
    }

    fn refresh_active_keysets(&self, _mint: &str) -> Result<(), String> {
        // In the Rust server, we handle keyset refresh at startup only.
        // The async refresh_active_keysets_async method should be used instead.
        Err("Use refresh_active_keysets_async for async context".to_string())
    }

    fn call_mint_swap(&self, _mint_url: &str, _swap_request_json: &str) -> Result<String, String> {
        // In the Rust server, we call the mint swap directly in async route handlers
        // using call_mint_swap_async instead of this sync method.
        Err("Use call_mint_swap_async for async context".to_string())
    }

    fn mark_channel_closed(
        &self,
        channel_id: &str,
        locktime: u64,
        balance: u64,
        receiver_proofs_json: &str,
        sender_proofs_json: &str,
        receiver_sum: u64,
        sender_sum: u64,
    ) -> Result<(), String> {
        // Check if channel is already closed
        if self.stores.is_closed(channel_id) {
            return Err("channel already closed".to_string());
        }
        let value_after_stage1 = receiver_sum + sender_sum;
        self.stores.mark_closed(
            channel_id,
            locktime,
            balance,
            value_after_stage1,
            receiver_sum,
            sender_sum,
            receiver_proofs_json,
            sender_proofs_json,
        );
        Ok(())
    }
}
