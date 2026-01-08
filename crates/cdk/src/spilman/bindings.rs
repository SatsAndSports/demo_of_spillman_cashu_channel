//! Core functions for FFI bindings (WASM, PyO3, etc.)
//!
//! These functions take string inputs and return string outputs,
//! making them easy to wrap with any FFI system.

use super::{compute_shared_secret as ecdh, ChannelParameters, KeysetInfo};
use crate::nuts::{Id, Keys, PublicKey, SecretKey};
use crate::util::hex;
use crate::Amount;
use std::collections::BTreeMap;
use std::str::FromStr;

/// Parse KeysetInfo from JSON
///
/// Expected format:
/// {
///   "keysetId": "00...",
///   "unit": "sat",
///   "keys": { "1": "02...", "2": "02...", ... },
///   "inputFeePpk": 100,
///   "amounts": [1048576, 524288, ...]  // optional, computed from keys if missing
/// }
pub fn parse_keyset_info_from_json(json_str: &str) -> Result<KeysetInfo, String> {
    let json: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid keyset JSON: {}", e))?;

    // Parse keyset_id
    let keyset_id_str = json["keysetId"]
        .as_str()
        .ok_or("Missing or invalid 'keysetId' field")?;
    let keyset_id: Id = keyset_id_str
        .parse()
        .map_err(|e| format!("Invalid keyset_id: {}", e))?;

    // Parse input_fee_ppk
    let input_fee_ppk = json["inputFeePpk"]
        .as_u64()
        .ok_or("Missing or invalid 'inputFeePpk' field")?;

    // Parse keys map: { "1": "02...", "2": "02...", ... }
    let keys_obj = json["keys"]
        .as_object()
        .ok_or("Missing or invalid 'keys' field")?;

    let mut keys_map: BTreeMap<Amount, PublicKey> = BTreeMap::new();
    for (amount_str, pubkey_val) in keys_obj {
        let amount: u64 = amount_str
            .parse()
            .map_err(|e| format!("Invalid amount '{}': {}", amount_str, e))?;
        let pubkey_hex = pubkey_val
            .as_str()
            .ok_or_else(|| format!("Invalid pubkey for amount {}", amount))?;
        let pubkey = PublicKey::from_str(pubkey_hex)
            .map_err(|e| format!("Invalid pubkey hex for amount {}: {}", amount, e))?;
        keys_map.insert(Amount::from(amount), pubkey);
    }

    let active_keys = Keys::new(keys_map);

    Ok(KeysetInfo::new(keyset_id, active_keys, input_fee_ppk))
}

/// Get channel_id from params JSON, shared secret, and keyset info (all as strings)
///
/// This is effectively a method on ChannelParameters, but takes JSON input
/// for FFI compatibility.
pub fn channel_parameters_get_channel_id(
    params_json: &str,
    shared_secret_hex: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    // Parse the shared secret
    let shared_secret_bytes =
        hex::decode(shared_secret_hex).map_err(|e| format!("Invalid shared secret hex: {}", e))?;

    if shared_secret_bytes.len() != 32 {
        return Err(format!(
            "Shared secret must be 32 bytes, got {}",
            shared_secret_bytes.len()
        ));
    }

    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&shared_secret_bytes);

    // Parse real KeysetInfo from JSON
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Use from_json_with_shared_secret to construct params
    let params =
        ChannelParameters::from_json_with_shared_secret(params_json, keyset_info, shared_secret)
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
    let my_secret =
        SecretKey::from_hex(my_secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;

    let their_pubkey: PublicKey = their_pubkey_hex
        .parse()
        .map_err(|e| format!("Invalid pubkey: {}", e))?;

    let shared_secret = ecdh(&my_secret, &their_pubkey);
    Ok(hex::encode(shared_secret))
}
