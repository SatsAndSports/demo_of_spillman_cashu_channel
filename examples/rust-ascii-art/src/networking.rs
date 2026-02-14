//! Async networking for the ASCII art server.
//!
//! Implements [`SpilmanAsyncNetworking`] for the [`ConfigurableHost`],
//! providing HTTP communication with the mint (swap and keyset refresh).

use async_trait::async_trait;
use std::sync::Arc;

use cdk::spilman::configurable_host::{ConfigurableHost, KeysetCacheEntry};
use cdk::spilman::SpilmanAsyncNetworking;

/// Keyset with full key data, as fetched from a mint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MintKeysetWithKeys {
    pub id: String,
    pub unit: String,
    pub active: bool,
    pub input_fee_ppk: u64,
    pub keys: serde_json::Value,
}

/// Fetch all keysets (with full keys) from a mint.
pub async fn fetch_all_keysets_from_mint(
    mint_url: &str,
) -> Result<Vec<MintKeysetWithKeys>, String> {
    let client = reqwest::Client::new();

    let keysets_url = format!("{mint_url}/v1/keysets");
    let keysets_resp: serde_json::Value = client
        .get(&keysets_url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch keysets: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse keysets response: {e}"))?;

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

        let keys_url = format!("{mint_url}/v1/keys/{id}");
        let keys_resp: serde_json::Value = client
            .get(&keys_url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch keys for {id}: {e}"))?
            .json()
            .await
            .map_err(|e| format!("Failed to parse keys response for {id}: {e}"))?;

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

/// Populate the keyset cache for a [`ConfigurableHost`].
pub async fn fetch_and_cache_keysets(
    host: &ConfigurableHost,
    mint_url: &str,
) -> Result<(), String> {
    let keysets = fetch_all_keysets_from_mint(mint_url).await?;
    for ks in keysets {
        let info_json = build_keyset_info_json(&ks.id, &ks.unit, &ks.keys, ks.input_fee_ppk);
        host.set_keyset(
            mint_url,
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

/// Thin wrapper providing async networking for a shared [`ConfigurableHost`].
pub struct HostNetworking {
    pub host: Arc<ConfigurableHost>,
}

#[async_trait]
impl SpilmanAsyncNetworking for HostNetworking {
    async fn call_mint_swap(
        &self,
        mint_url: &str,
        swap_request_json: &str,
    ) -> Result<String, String> {
        let client = reqwest::Client::new();
        let url = format!("{mint_url}/v1/swap");

        let resp = client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(swap_request_json.to_string())
            .send()
            .await
            .map_err(|e| format!("Swap request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Swap failed: {status} - {body}"));
        }

        resp.text()
            .await
            .map_err(|e| format!("Failed to read swap response: {e}"))
    }

    async fn refresh_all_keysets(&self, mint: &str) -> Result<(), String> {
        tracing::info!("  [Keyset] Refreshing keysets from {mint}...");
        fetch_and_cache_keysets(&self.host, mint).await?;
        tracing::info!("  [Keyset] Refresh complete");
        Ok(())
    }
}
