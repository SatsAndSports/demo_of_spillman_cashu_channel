//! Core functions for FFI bindings (WASM, PyO3, etc.)
//!
//! These functions take string inputs and return string outputs,
//! making them easy to wrap with any FFI system.

use crate::nuts::{PublicKey, SecretKey};
use crate::util::hex;
use super::{compute_shared_secret as ecdh, ChannelParameters, KeysetInfo};

/// Get channel_id from params JSON and shared secret (hex strings)
///
/// This is effectively a method on ChannelParameters, but takes JSON input
/// for FFI compatibility. Takes the params JSON and shared secret hex.
pub fn channel_parameters_get_channel_id(
    params_json: &str,
    shared_secret_hex: &str,
) -> Result<String, String> {
    // Parse the shared secret
    let shared_secret_bytes = hex::decode(shared_secret_hex)
        .map_err(|e| format!("Invalid shared secret hex: {}", e))?;

    if shared_secret_bytes.len() != 32 {
        return Err(format!("Shared secret must be 32 bytes, got {}", shared_secret_bytes.len()));
    }

    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&shared_secret_bytes);

    // Parse JSON to extract keyset_id and input_fee_ppk for the mock
    let json: serde_json::Value = serde_json::from_str(params_json)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let keyset_id_str = json["keyset_id"]
        .as_str()
        .ok_or_else(|| "Missing 'keyset_id' field".to_string())?;

    let input_fee_ppk = json["input_fee_ppk"]
        .as_u64()
        .ok_or_else(|| "Missing 'input_fee_ppk' field".to_string())?;

    // Create mock KeysetInfo with matching keyset_id and input_fee_ppk
    let keyset_info = KeysetInfo::mock_with_id_and_fee(keyset_id_str, input_fee_ppk)
        .map_err(|e| format!("Failed to create mock keyset: {}", e))?;

    // Use from_json_with_shared_secret to construct params
    let params = ChannelParameters::from_json_with_shared_secret(params_json, keyset_info, shared_secret)
        .map_err(|e| format!("Failed to parse params: {}", e))?;

    Ok(params.get_channel_id())
}

/// Compute ECDH shared secret from hex strings
///
/// Returns the x-coordinate of the shared point as a hex string (32 bytes).
pub fn compute_shared_secret_from_hex(
    my_secret_hex: &str,
    their_pubkey_hex: &str,
) -> Result<String, String> {
    let my_secret = SecretKey::from_hex(my_secret_hex)
        .map_err(|e| format!("Invalid secret key: {}", e))?;

    let their_pubkey: PublicKey = their_pubkey_hex
        .parse()
        .map_err(|e| format!("Invalid pubkey: {}", e))?;

    let shared_secret = ecdh(&my_secret, &their_pubkey);
    Ok(hex::encode(shared_secret))
}
