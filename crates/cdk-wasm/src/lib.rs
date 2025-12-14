//! WASM bindings for Cashu payment channels

use wasm_bindgen::prelude::*;

/// Initialize panic hook for better error messages in browser console
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Compute ECDH shared secret from a secret key and counterparty's public key
///
/// Returns the x-coordinate of the shared point as a hex string (32 bytes).
#[wasm_bindgen]
pub fn compute_shared_secret(my_secret_hex: &str, their_pubkey_hex: &str) -> Result<String, JsValue> {
    cdk::spilman::compute_shared_secret_from_hex(my_secret_hex, their_pubkey_hex)
        .map_err(|e| JsValue::from_str(&e))
}

/// Compute channel_id from params JSON and a secret key
///
/// Takes the JSON produced by `ChannelParameters::get_channel_id_params_json()`
/// and either Alice's or Charlie's secret key (hex). The function auto-detects
/// which party the secret belongs to by matching the derived pubkey against
/// alice_pubkey and charlie_pubkey in the JSON.
#[wasm_bindgen]
pub fn compute_channel_id_from_json(params_json: &str, my_secret_hex: &str) -> Result<String, JsValue> {
    cdk::spilman::compute_channel_id_from_json_str(params_json, my_secret_hex)
        .map_err(|e| JsValue::from_str(&e))
}
