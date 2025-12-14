//! WASM bindings for Cashu payment channels

use wasm_bindgen::prelude::*;

/// Initialize panic hook for better error messages in browser console
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Compute ECDH shared secret from Alice's secret key and Charlie's public key
///
/// Returns the x-coordinate of the shared point as a hex string (32 bytes).
#[wasm_bindgen]
pub fn compute_shared_secret(alice_secret_hex: &str, charlie_pubkey_hex: &str) -> Result<String, JsValue> {
    use cdk::nuts::{PublicKey, SecretKey};
    use cdk::spilman::compute_shared_secret as ecdh;
    use cdk::util::hex;

    let alice_secret = SecretKey::from_hex(alice_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {}", e)))?;

    let charlie_pubkey: PublicKey = charlie_pubkey_hex
        .parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid pubkey: {}", e)))?;

    let shared_secret = ecdh(&alice_secret, &charlie_pubkey);
    Ok(hex::encode(shared_secret))
}

/// Compute channel_id from params JSON and a secret key
///
/// Takes the JSON produced by `ChannelParameters::get_channel_id_params_json()`
/// and either Alice's or Charlie's secret key (hex). The function auto-detects
/// which party the secret belongs to by matching the derived pubkey against
/// alice_pubkey and charlie_pubkey in the JSON.
#[wasm_bindgen]
pub fn compute_channel_id_from_json(params_json: &str, my_secret_hex: &str) -> Result<String, JsValue> {
    use cdk::nuts::SecretKey;
    use cdk::spilman::{ChannelParameters, KeysetInfo};

    // Parse the secret key (can be either Alice's or Charlie's)
    let my_secret = SecretKey::from_hex(my_secret_hex)
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

    // Use from_json to construct params (auto-detects Alice vs Charlie, computes shared_secret via ECDH)
    let params = ChannelParameters::from_json(params_json, keyset_info, &my_secret)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse params: {}", e)))?;

    Ok(params.get_channel_id())
}
