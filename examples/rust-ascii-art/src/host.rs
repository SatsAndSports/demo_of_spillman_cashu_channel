//! SpilmanHost implementation for ASCII art server.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use async_trait::async_trait;

use cdk::nuts::{CurrencyUnit, Id, PublicKey};
use cdk::spilman::{ChannelState, ClosingData, SpilmanHost, SpilmanAsyncNetworking, ChannelFunding, PaymentProof};

use crate::stores::{ChannelFundingData, KeysetCacheEntry, Stores, UnitPricing};

/// Represents keyset info and keys fetched from a mint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MintKeysetWithKeys {
    pub id: String,
    pub unit: String,
    pub active: bool,
    pub input_fee_ppk: u64,
    pub keys: serde_json::Value,
}

/// Standalone helper to fetch all keyset info (including keys) from a mint.
pub async fn fetch_all_keysets_from_mint(mint_url: &str) -> Result<Vec<MintKeysetWithKeys>, String> {
    let client = reqwest::Client::new();

    // 1. Fetch /v1/keysets
    let keysets_url = format!("{}/v1/keysets", mint_url);
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

    let mut result = Vec::new();

    for keyset in keysets {
        let id = keyset
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("Keyset missing id")?
            .to_string();
        let unit = keyset
            .get("unit")
            .and_then(|v| v.as_str())
            .ok_or("Keyset missing unit")?
            .to_string();
        let active = keyset.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
        let input_fee_ppk = keyset
            .get("input_fee_ppk")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // 2. Fetch keys for this keyset
        let keys_url = format!("{}/v1/keys/{}", mint_url, id);
        let keys_resp: serde_json::Value = client
            .get(&keys_url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch keys for {}: {}", id, e))?
            .json()
            .await
            .map_err(|e| format!("Failed to parse keys response for {}: {}", id, e))?;

        let keys = keys_resp
            .get("keysets")
            .and_then(|k| k.as_array())
            .and_then(|arr| arr.first())
            .and_then(|k| k.get("keys"))
            .cloned()
            .unwrap_or(serde_json::json!({}));

        result.push(MintKeysetWithKeys {
            id,
            unit,
            active,
            input_fee_ppk,
            keys,
        });
    }

    Ok(result)
}

/// SpilmanHost implementation for the ASCII art server.
#[derive(Clone)]
pub struct AsciiArtHost {
    pub stores: Arc<Stores>,
    pub server_pubkey: PublicKey,
    pub server_secret_hex: String,
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
        server_secret_hex: String,
        pricing: HashMap<String, UnitPricing>,
        min_expiry_seconds: u64,
    ) -> Self {
        Self {
            stores,
            server_pubkey,
            server_secret_hex,
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

    /// Refresh the keyset cache for a mint (async version).
    pub async fn refresh_all_keysets_async(&self, mint_url: &str) -> Result<(), String> {
        tracing::info!("  [Keyset] Refreshing keysets from {}...", mint_url);
        let keysets = fetch_all_keysets_from_mint(mint_url).await?;

        for ks in keysets {
            let info_json = Self::build_keyset_info_json(&ks.id, &ks.unit, &ks.keys, ks.input_fee_ppk);

            self.stores.set_keyset(
                mint_url,
                &ks.id,
                KeysetCacheEntry {
                    info_json,
                    active: ks.active,
                    unit: ks.unit,
                },
            );
        }
        tracing::info!("  [Keyset] Refresh complete");
        Ok(())
    }

    /// Build KeysetInfo JSON (matching the format expected by the bridge).
    fn build_keyset_info_json(
        keyset_id: &str,
        unit: &str,
        keys: &serde_json::Value,
        input_fee_ppk: u64,
    ) -> String {
        serde_json::json!({
            "keysetId": keyset_id,
            "unit": unit,
            "keys": keys,
            "inputFeePpk": input_fee_ppk,
        })
        .to_string()
    }

    /// Fetch keysets from the mint and populate the cache (async version for startup).
    pub async fn fetch_keysets_async(&self) -> Result<(), String> {
        let keysets = fetch_all_keysets_from_mint(&self.mint_url).await?;

        tracing::info!(
            "Fetched {} keysets from {}",
            keysets.len(),
            self.mint_url
        );

        for ks in keysets {
            let info_json = Self::build_keyset_info_json(&ks.id, &ks.unit, &ks.keys, ks.input_fee_ppk);

            self.stores.set_keyset(
                &self.mint_url,
                &ks.id,
                KeysetCacheEntry {
                    info_json,
                    active: ks.active,
                    unit: ks.unit,
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

    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        self.stores.get_funding(channel_id).map(|f| ChannelFunding {
            params_json: f.params_json,
            funding_proofs_json: f.funding_proofs_json,
            channel_secret_hex: f.channel_secret,
            keyset_info_json: f.keyset_info_json,
        })
    }

    fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
    ) {
        self.stores.insert_funding(
            channel_id,
            ChannelFundingData {
                params_json: funding.params_json,
                funding_proofs_json: funding.funding_proofs_json,
                channel_secret: funding.channel_secret_hex,
                keyset_info_json: funding.keyset_info_json,
            },
        );
        // Store the initial balance/signature for closing
        self.stores.update_balance(channel_id, initial_payment.balance, &initial_payment.signature);
    }

    fn get_amount_due(&self, channel_id: &str, context_json: Option<&String>) -> u64 {
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

    fn record_payment(&self, channel_id: &str, payment: PaymentProof, context_json: &String) {
        // Update balance
        self.stores.update_balance(channel_id, payment.balance, &payment.signature);

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
        payment: PaymentProof,
    ) -> Result<(), String> {
        // Check if channel is already closed
        if self.stores.is_closed(channel_id) {
            return Err("channel already closed".to_string());
        }
        self.stores.mark_closing(channel_id, locktime, payment.balance, &payment.signature);
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
    ) -> Option<PaymentProof> {
        self.stores
            .get_balance(channel_id)
            .map(|b| PaymentProof {
                balance: b.balance,
                signature: b.signature,
            })
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

    fn compute_channel_secret(&self, _charlie_pubkey_hex: &str, alice_pubkey_hex: &str) -> Result<String, String> {
        cdk::spilman::compute_channel_secret_from_hex(&self.server_secret_hex, alice_pubkey_hex)
    }

    fn sign_with_tweaked_key(&self, _signer_pubkey_hex: &str, message_hex: &str, tweak_scalar_hex: &str) -> Result<String, String> {
        cdk::spilman::sign_with_tweaked_key_util(&self.server_secret_hex, message_hex, tweak_scalar_hex)
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

#[async_trait]
impl SpilmanAsyncNetworking for AsciiArtHost {
    async fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String> {
        self.call_mint_swap_async(mint_url, swap_request_json).await
    }

    async fn refresh_all_keysets(&self, mint: &str) -> Result<(), String> {
        self.refresh_all_keysets_async(mint).await
    }
}
