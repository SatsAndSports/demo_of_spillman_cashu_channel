//! WASM bindings for Cashu payment channels

use std::collections::BTreeMap;
use std::str::FromStr;

use wasm_bindgen::prelude::*;

use cdk::nuts::{Id, Keys, Proof, PublicKey, SecretKey};
use cdk::spilman::{
    ChannelParameters, DeterministicOutputsForOneContext, EstablishedChannel, KeysetInfo,
    SpilmanChannelSender,
};
use cdk::Amount;

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

/// Get channel_id from params JSON and shared secret
///
/// This is effectively a method on ChannelParameters for FFI.
/// Takes the params JSON and the pre-computed shared secret (hex).
#[wasm_bindgen]
pub fn channel_parameters_get_channel_id(params_json: &str, shared_secret_hex: &str) -> Result<String, JsValue> {
    cdk::spilman::channel_parameters_get_channel_id(params_json, shared_secret_hex)
        .map_err(|e| JsValue::from_str(&e))
}

/// Parse KeysetInfo from JavaScript object
///
/// Expected format (from fetchKeysetInfo in player.html):
/// {
///   "keysetId": "00...",
///   "unit": "sat",
///   "keys": { "1": "02...", "2": "02...", ... },
///   "inputFeePpk": 100,
///   "amounts": [1048576, 524288, ...]
/// }
fn parse_keyset_info_from_json(json_str: &str) -> Result<KeysetInfo, String> {
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

/// Create funding outputs for a Spilman channel
///
/// Takes:
/// - `params_json`: Channel parameters JSON (from get_channel_id_params_json or stored in DB)
/// - `my_secret_hex`: Alice's secret key (hex)
/// - `keyset_info_json`: KeysetInfo JSON (from fetchKeysetInfo)
///
/// Returns JSON with:
/// - `funding_token_nominal`: The nominal amount to request when minting the funding token
/// - `blinded_messages`: Array of blinded messages (ready for mint request)
/// - `secrets_with_blinding`: Array of {secret, blinding_factor, amount} for unblinding later
#[wasm_bindgen]
pub fn create_funding_outputs(
    params_json: &str,
    my_secret_hex: &str,
    keyset_info_json: &str,
) -> Result<String, JsValue> {
    create_funding_outputs_inner(params_json, my_secret_hex, keyset_info_json)
        .map_err(|e| JsValue::from_str(&e))
}

fn create_funding_outputs_inner(
    params_json: &str,
    my_secret_hex: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    // Parse the keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Parse the secret key
    let my_secret = SecretKey::from_hex(my_secret_hex)
        .map_err(|e| format!("Invalid secret key: {}", e))?;

    // Create ChannelParameters from JSON
    let params = ChannelParameters::from_json_with_secret_key(params_json, keyset_info, &my_secret)
        .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    // Get the funding token nominal amount
    let funding_token_nominal = params
        .get_total_funding_token_amount()
        .map_err(|e| format!("Failed to compute funding token amount: {}", e))?;

    // Create deterministic outputs for "funding" context
    let funding_outputs =
        DeterministicOutputsForOneContext::new("funding".to_string(), funding_token_nominal, params)
            .map_err(|e| format!("Failed to create funding outputs: {}", e))?;

    // Get blinded messages
    let blinded_messages = funding_outputs
        .get_blinded_messages()
        .map_err(|e| format!("Failed to get blinded messages: {}", e))?;

    // Get secrets with blinding factors
    let secrets_with_blinding = funding_outputs
        .get_secrets_with_blinding()
        .map_err(|e| format!("Failed to get secrets with blinding: {}", e))?;

    // Serialize blinded messages to JSON
    let blinded_messages_json: Vec<serde_json::Value> = blinded_messages
        .iter()
        .map(|bm| {
            serde_json::json!({
                "amount": u64::from(bm.amount),
                "id": bm.keyset_id.to_string(),
                "B_": bm.blinded_secret.to_hex()
            })
        })
        .collect();

    // Serialize secrets with blinding to JSON
    let secrets_json: Vec<serde_json::Value> = secrets_with_blinding
        .iter()
        .map(|swb| {
            serde_json::json!({
                "secret": swb.secret.to_string(),
                "blinding_factor": swb.blinding_factor.to_secret_hex(),
                "amount": swb.amount
            })
        })
        .collect();

    // Build result JSON
    let result = serde_json::json!({
        "funding_token_nominal": funding_token_nominal,
        "blinded_messages": blinded_messages_json,
        "secrets_with_blinding": secrets_json
    });

    Ok(result.to_string())
}

/// Create a signed balance update message
///
/// This is equivalent to calling `SpilmanChannelSender::create_signed_balance_update()` in Rust.
///
/// Takes:
/// - `params_json`: Channel parameters JSON
/// - `keyset_info_json`: KeysetInfo JSON
/// - `alice_secret_hex`: Alice's secret key (hex)
/// - `funding_proofs_json`: JSON array of funding proofs
/// - `charlie_balance`: The new balance for Charlie
///
/// Returns JSON with:
/// - `channel_id`: The channel ID
/// - `amount`: The balance amount
/// - `signature`: Alice's Schnorr signature (hex)
#[wasm_bindgen]
pub fn spilman_channel_sender_create_signed_balance_update(
    params_json: &str,
    keyset_info_json: &str,
    alice_secret_hex: &str,
    funding_proofs_json: &str,
    charlie_balance: u64,
) -> Result<String, JsValue> {
    spilman_channel_sender_create_signed_balance_update_inner(
        params_json,
        keyset_info_json,
        alice_secret_hex,
        funding_proofs_json,
        charlie_balance,
    )
    .map_err(|e| JsValue::from_str(&e))
}

fn spilman_channel_sender_create_signed_balance_update_inner(
    params_json: &str,
    keyset_info_json: &str,
    alice_secret_hex: &str,
    funding_proofs_json: &str,
    charlie_balance: u64,
) -> Result<String, String> {
    // Parse keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Parse Alice's secret key
    let alice_secret = SecretKey::from_hex(alice_secret_hex)
        .map_err(|e| format!("Invalid secret key: {}", e))?;

    // Create ChannelParameters
    let params = ChannelParameters::from_json_with_secret_key(params_json, keyset_info, &alice_secret)
        .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    // Parse funding proofs
    let funding_proofs: Vec<Proof> = serde_json::from_str(funding_proofs_json)
        .map_err(|e| format!("Failed to parse funding proofs: {}", e))?;

    // Create EstablishedChannel
    let channel = EstablishedChannel::new(params, funding_proofs)
        .map_err(|e| format!("Failed to create EstablishedChannel: {}", e))?;

    // Create SpilmanChannelSender
    let sender = SpilmanChannelSender::new(alice_secret, channel);

    // Create signed balance update
    let (balance_update, _swap_request) = sender
        .create_signed_balance_update(charlie_balance)
        .map_err(|e| format!("Failed to create signed balance update: {}", e))?;

    // Serialize the balance update message
    let result = serde_json::json!({
        "channel_id": balance_update.channel_id,
        "amount": balance_update.amount,
        "signature": balance_update.signature.to_string()
    });

    Ok(result.to_string())
}
