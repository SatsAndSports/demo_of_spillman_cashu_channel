//! WASM bindings for Cashu payment channels

use wasm_bindgen::prelude::*;

/// Initialize panic hook for better error messages in browser console
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Create channel parameters and return the channel ID
///
/// For now this is a simplified version that just demonstrates
/// the WASM <-> JS bridge is working.
#[wasm_bindgen]
pub fn create_channel_id(
    alice_pubkey_hex: &str,
    charlie_pubkey_hex: &str,
    capacity: u64,
) -> Result<String, JsValue> {
    use cdk::nuts::{CurrencyUnit, PublicKey, SecretKey};
    use cdk::spilman::{ChannelParameters, KeysetInfo};
    use cdk::util::unix_time;

    // Parse public keys
    let alice_pubkey: PublicKey = alice_pubkey_hex
        .parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid alice pubkey: {}", e)))?;

    let charlie_pubkey: PublicKey = charlie_pubkey_hex
        .parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid charlie pubkey: {}", e)))?;

    // In real usage, Alice would provide her secret for ECDH
    let _temp_secret = SecretKey::generate();

    // Create mock keyset info (in real usage, this comes from the mint)
    let mock_keyset_info = KeysetInfo::mock_with_id_and_fee("00deadbeef123456", 0)
        .map_err(|e| JsValue::from_str(&format!("Failed to create mock keyset: {}", e)))?;

    let setup_timestamp = unix_time();
    let locktime = setup_timestamp + 3600; // 1 hour from now
    let sender_nonce = format!("nonce-{}", setup_timestamp);

    // Create channel parameters
    let params = ChannelParameters::new(
        alice_pubkey,
        charlie_pubkey,
        "http://localhost:8080".to_string(),
        CurrencyUnit::Sat,
        capacity,
        locktime,
        setup_timestamp,
        sender_nonce,
        mock_keyset_info,
        100_000, // max amount per output
        [0u8; 32], // placeholder shared secret
    ).map_err(|e| JsValue::from_str(&format!("Failed to create params: {}", e)))?;

    Ok(params.get_channel_id())
}

/// Generate a new keypair and return the public key as hex
#[wasm_bindgen]
pub fn generate_keypair() -> Result<JsValue, JsValue> {
    use cdk::nuts::SecretKey;

    let secret = SecretKey::generate();
    let pubkey = secret.public_key();

    let result = serde_json::json!({
        "secret_hex": secret.to_secret_hex(),
        "pubkey_hex": pubkey.to_hex(),
    });

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Simple test function to verify WASM is loaded
#[wasm_bindgen]
pub fn hello() -> String {
    "Hello from cdk-wasm!".to_string()
}

/// Compute channel_id from params JSON and Alice's secret key
///
/// Takes the JSON produced by `ChannelParameters::get_channel_id_params_json()`
/// and Alice's secret key (hex), computes the shared secret via ECDH,
/// and returns the channel_id.
#[wasm_bindgen]
pub fn compute_channel_id_from_json(params_json: &str, alice_secret_hex: &str) -> Result<String, JsValue> {
    use cdk::nuts::SecretKey;
    use cdk::spilman::{ChannelParameters, KeysetInfo};

    // Parse Alice's secret key
    let alice_secret = SecretKey::from_hex(alice_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {}", e)))?;

    // Parse JSON to extract keyset_id and input_fee_ppk for the mock
    let json: serde_json::Value = serde_json::from_str(params_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid JSON: {}", e)))?;

    let keyset_id_str = json["keyset_id"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("Missing 'keyset_id' field"))?;
    let input_fee_ppk = json["input_fee_ppk"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing 'input_fee_ppk' field"))?;

    // Create mock KeysetInfo with matching keyset_id and input_fee_ppk
    let keyset_info = KeysetInfo::mock_with_id_and_fee(keyset_id_str, input_fee_ppk)
        .map_err(|e| JsValue::from_str(&format!("Failed to create mock keyset: {}", e)))?;

    // Use from_json to construct params (computes shared_secret via ECDH)
    let params = ChannelParameters::from_json(params_json, keyset_info, &alice_secret)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse params: {}", e)))?;

    Ok(params.get_channel_id())
}
