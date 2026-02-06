//! Core functions for FFI bindings (WASM, PyO3, etc.)
//!
//! These functions take string inputs and return string outputs,
//! making them easy to wrap with any FFI system.

use super::{
    compute_shared_secret as ecdh, ChannelParameters, DeterministicOutputsForOneContext,
    EstablishedChannel, KeysetInfo, SpilmanChannelSender,
};
use crate::amount::{FeeAndAmounts, SplitTarget};
use crate::dhke::{blind_message, construct_proofs as dhke_construct_proofs};
use crate::nuts::{
    BlindSignature, BlindSignatureDleq, BlindedMessage, CurrencyUnit, Id, Keys, Proof, PublicKey,
    SecretKey, SwapRequest, Token,
};
use crate::secret::Secret;
use crate::util::{hex, unix_time};
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

    // Parse keyset_id (handle both camelCase and snake_case)
    let keyset_id_str = json["keysetId"]
        .as_str()
        .or_else(|| json["keyset_id"].as_str())
        .ok_or("Missing or invalid 'keysetId' field")?;
    let keyset_id: Id = keyset_id_str
        .parse()
        .map_err(|e| format!("Invalid keyset_id: {}", e))?;

    // Parse input_fee_ppk (handle both camelCase and snake_case)
    let input_fee_ppk = json["inputFeePpk"]
        .as_u64()
        .or_else(|| json["input_fee_ppk"].as_u64())
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

/// Create funding outputs from params and keyset info
///
/// Returns JSON with:
/// - `funding_token_nominal`: Total nominal value needed
/// - `blinded_messages`: Array of blinded messages (ready for mint request)
/// - `secrets_with_blinding`: Array of {secret, blinding_factor, amount} for unblinding later
pub fn create_funding_outputs(
    params_json: &str,
    alice_secret_hex: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    // Parse the keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Parse Alice's secret key
    let alice_secret =
        SecretKey::from_hex(alice_secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;

    // Create ChannelParameters from JSON
    let params =
        ChannelParameters::from_json_with_secret_key(params_json, keyset_info, &alice_secret)
            .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    // Get the funding token nominal amount
    let funding_token_nominal = params
        .get_total_funding_token_amount()
        .map_err(|e| format!("Failed to compute funding token amount: {}", e))?;

    // Create deterministic outputs for "funding" context
    let funding_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        funding_token_nominal,
        params,
    )
    .map_err(|e| format!("Failed to create funding outputs: {}", e))?;

    // Get blinded messages
    let blinded_messages = funding_outputs
        .get_blinded_messages(None)
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

/// Construct proofs from blind signatures and secrets with blinding
///
/// Returns JSON array of proofs ready for use
pub fn construct_proofs(
    blind_signatures_json: &str,
    secrets_with_blinding_json: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    // Parse keyset info to get the keys
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;
    let keys = keyset_info.active_keys.clone();

    // Parse blind signatures from mint
    let blind_sigs_raw: Vec<serde_json::Value> = serde_json::from_str(blind_signatures_json)
        .map_err(|e| format!("Failed to parse blind signatures: {}", e))?;

    let mut blind_signatures: Vec<BlindSignature> = Vec::new();
    for sig in blind_sigs_raw {
        let amount = sig["amount"]
            .as_u64()
            .ok_or("Missing 'amount' in blind signature")?;
        let id_str = sig["id"]
            .as_str()
            .ok_or("Missing 'id' in blind signature")?;
        let c_str = sig["C_"]
            .as_str()
            .ok_or("Missing 'C_' in blind signature")?;

        let keyset_id: Id = id_str
            .parse()
            .map_err(|e| format!("Invalid keyset id: {}", e))?;
        let c = PublicKey::from_str(c_str).map_err(|e| format!("Invalid C_ pubkey: {}", e))?;

        // Parse DLEQ - required for Spilman channels
        let dleq_obj = sig["dleq"]
            .as_object()
            .ok_or("Missing 'dleq' in blind signature - DLEQ proofs are required")?;
        let e_str = dleq_obj
            .get("e")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'e' in dleq")?;
        let s_str = dleq_obj
            .get("s")
            .and_then(|v| v.as_str())
            .ok_or("Missing 's' in dleq")?;
        let e = SecretKey::from_hex(e_str).map_err(|e| format!("Invalid dleq.e: {}", e))?;
        let s = SecretKey::from_hex(s_str).map_err(|e| format!("Invalid dleq.s: {}", e))?;
        let dleq = BlindSignatureDleq { e, s };

        blind_signatures.push(BlindSignature {
            amount: Amount::from(amount),
            keyset_id,
            c,
            dleq: Some(dleq),
        });
    }

    // Parse secrets with blinding factors
    let secrets_raw: Vec<serde_json::Value> = serde_json::from_str(secrets_with_blinding_json)
        .map_err(|e| format!("Failed to parse secrets with blinding: {}", e))?;

    let mut secrets: Vec<Secret> = Vec::new();
    let mut rs: Vec<SecretKey> = Vec::new();

    for swb in secrets_raw {
        let secret_str = swb["secret"]
            .as_str()
            .ok_or("Missing 'secret' in secrets_with_blinding")?;
        let blinding_factor_hex = swb["blinding_factor"]
            .as_str()
            .ok_or("Missing 'blinding_factor' in secrets_with_blinding")?;

        let secret: Secret = secret_str
            .parse()
            .map_err(|e| format!("Invalid secret: {}", e))?;
        let r = SecretKey::from_hex(blinding_factor_hex)
            .map_err(|e| format!("Invalid blinding factor: {}", e))?;

        secrets.push(secret);
        rs.push(r);
    }

    // Construct the proofs
    let proofs = dhke_construct_proofs(blind_signatures, rs, secrets, &keys)
        .map_err(|e| format!("Failed to construct proofs: {}", e))?;

    // Serialize proofs to JSON
    let proofs_json =
        serde_json::to_string(&proofs).map_err(|e| format!("Failed to serialize proofs: {}", e))?;

    Ok(proofs_json)
}

/// Create a signed balance update for a channel
pub fn create_signed_balance_update(
    params_json: &str,
    keyset_info_json: &str,
    alice_secret_hex: &str,
    proofs_json: &str,
    balance: u64,
) -> Result<String, String> {
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;
    let alice_secret =
        SecretKey::from_hex(alice_secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;
    let params =
        ChannelParameters::from_json_with_secret_key(params_json, keyset_info, &alice_secret)
            .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;
    let funding_proofs: Vec<Proof> =
        serde_json::from_str(proofs_json).map_err(|e| format!("Failed to parse proofs: {}", e))?;
    let channel = EstablishedChannel::new(params, funding_proofs)
        .map_err(|e| format!("EstablishedChannel::new failed: {}", e))?;
    let sender = SpilmanChannelSender::new(alice_secret, channel);

    let (balance_update, _) = sender
        .create_signed_balance_update(balance)
        .map_err(|e| format!("create_signed_balance_update failed: {}", e))?;

    let result = serde_json::json!({
        "channel_id": balance_update.channel_id,
        "amount": balance_update.amount,
        "signature": balance_update.signature.to_string()
    });

    Ok(result.to_string())
}

// ============================================================================
// SWAP-TO-FUNDING FUNCTIONS
// ============================================================================
// These functions allow creating channel funding from existing wallet tokens
// (via swap) instead of minting fresh tokens.

/// Compute channel parameters from a Cashu token
///
/// Given a token string (cashuA.../cashuB...), computes the channel capacity,
/// funding token nominal amount, and change amount. Also builds the channel
/// parameters ready for use.
///
/// # Arguments
/// * `token_string` - The Cashu token (cashuA... or cashuB...)
/// * `charlie_pubkey_hex` - Receiver's public key (hex)
/// * `alice_secret_hex` - Sender's secret key (hex)
/// * `locktime` - Unix timestamp for refund locktime
/// * `keyset_info_json` - Keyset info from mint (JSON)
/// * `maximum_amount_for_one_output` - Max amount per output from server policy
///
/// # Returns
/// JSON with:
/// - `capacity`: Channel capacity (final value after all fees)
/// - `funding_token_nominal`: Nominal value needed for funding outputs
/// - `change_amount`: Amount left over for change outputs
/// - `input_value`: Total value of input proofs
/// - `mint_url`: Mint URL from the token
/// - `params_json`: Serialized channel params for use in later functions
/// - `proofs_json`: The parsed proofs from the token (for create_funding_swap)
pub fn compute_channel_from_token(
    token_string: &str,
    charlie_pubkey_hex: &str,
    alice_secret_hex: &str,
    locktime: u64,
    keyset_info_json: &str,
    maximum_amount_for_one_output: u64,
) -> Result<String, String> {
    // Parse the token
    let token: Token = token_string
        .parse()
        .map_err(|e| format!("Failed to parse token: {}", e))?;

    // Get total value from token (doesn't need keyset info)
    let input_value: u64 = token
        .value()
        .map_err(|e| format!("Failed to get token value: {}", e))?
        .into();

    // Get mint URL
    let mint_url = token
        .mint_url()
        .map_err(|e| format!("Failed to get mint URL: {}", e))?;

    // Get unit from token
    let unit = token.unit().unwrap_or(CurrencyUnit::Sat);

    // Parse keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Parse proofs using keyset info
    // We need to create a KeySetInfo (nut02) for the token's proofs() method
    let nut02_keyset_info = crate::nuts::KeySetInfo {
        id: keyset_info.keyset_id,
        unit: unit.clone(),
        active: true,
        input_fee_ppk: keyset_info.input_fee_ppk,
        final_expiry: None,
    };
    let proofs = token
        .proofs(&[nut02_keyset_info])
        .map_err(|e| format!("Failed to parse proofs: {}", e))?;

    // Assert all proofs are from the same keyset
    for proof in &proofs {
        if proof.keyset_id != keyset_info.keyset_id {
            return Err(format!(
                "All proofs must be from the same keyset. Expected {}, got {}",
                keyset_info.keyset_id, proof.keyset_id
            ));
        }
    }

    let max_amt = maximum_amount_for_one_output;

    // Step 1: v1 = forward_fees(input_value) - value after swap's input fees
    let v1 = keyset_info
        .deterministic_value_after_fees(input_value, max_amt)
        .map_err(|e| format!("Failed to compute v1: {}", e))?;

    // Step 2: v2 = forward_fees(v1) - value after stage 1 close fees
    let v2 = keyset_info
        .deterministic_value_after_fees(v1, max_amt)
        .map_err(|e| format!("Failed to compute v2: {}", e))?;

    // Step 3: capacity = forward_fees(v2) - value after stage 2 swap fees
    let capacity = keyset_info
        .deterministic_value_after_fees(v2, max_amt)
        .map_err(|e| format!("Failed to compute capacity: {}", e))?;

    // Parse Alice's secret key
    let alice_secret =
        SecretKey::from_hex(alice_secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;
    let alice_pubkey = alice_secret.public_key();

    // Parse Charlie's pubkey
    let charlie_pubkey: PublicKey = charlie_pubkey_hex
        .parse()
        .map_err(|e| format!("Invalid charlie pubkey: {}", e))?;

    // Generate sender nonce
    let sender_nonce = format!(
        "swap-{}-{}",
        unix_time(),
        hex::encode(&alice_pubkey.to_bytes()[..8])
    );

    // Create channel parameters with the computed capacity
    let params = ChannelParameters::new_with_secret_key(
        alice_pubkey,
        charlie_pubkey,
        mint_url.to_string(),
        unit,
        capacity,
        locktime,
        unix_time(),
        sender_nonce,
        keyset_info.clone(),
        max_amt,
        &alice_secret,
    )
    .map_err(|e| format!("Failed to create channel params: {}", e))?;

    // Get funding token nominal via inverse²
    let funding_token_nominal = params
        .get_total_funding_token_amount()
        .map_err(|e| format!("Failed to get funding token amount: {}", e))?;

    // Calculate change: v1 - funding_token_nominal
    let change_amount = v1.saturating_sub(funding_token_nominal);

    // Serialize proofs
    let proofs_json =
        serde_json::to_string(&proofs).map_err(|e| format!("Failed to serialize proofs: {}", e))?;

    // Serialize params
    let params_json = params.get_channel_id_params_json();

    // Build result
    let result = serde_json::json!({
        "capacity": capacity,
        "funding_token_nominal": funding_token_nominal,
        "change_amount": change_amount,
        "input_value": input_value,
        "mint_url": mint_url.to_string(),
        "params_json": params_json,
        "proofs_json": proofs_json
    });

    Ok(result.to_string())
}

/// Create a swap request for funding a channel from existing proofs
///
/// Takes input proofs and creates a swap request with:
/// - Deterministic funding outputs (2-of-2 locked)
/// - Random change outputs (anyone-can-spend)
///
/// # Arguments
/// * `params_json` - Channel params JSON (from compute_channel_from_token)
/// * `alice_secret_hex` - Sender's secret key (hex)
/// * `keyset_info_json` - Keyset info (JSON)
/// * `input_proofs_json` - Input proofs from the token (JSON array)
/// * `change_amount` - Amount for change outputs (from compute_channel_from_token)
///
/// # Returns
/// JSON with:
/// - `swap_request_json`: The swap request to send to mint (JSON)
/// - `funding_secrets_json`: Secrets for unblinding funding outputs (JSON array)
/// - `change_secrets_json`: Secrets for unblinding change outputs (JSON array)
/// - `funding_count`: Number of funding outputs
/// - `change_count`: Number of change outputs
pub fn create_funding_swap(
    params_json: &str,
    alice_secret_hex: &str,
    keyset_info_json: &str,
    input_proofs_json: &str,
    change_amount: u64,
) -> Result<String, String> {
    // Parse keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Parse Alice's secret key
    let alice_secret =
        SecretKey::from_hex(alice_secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;

    // Create ChannelParameters from JSON
    let params = ChannelParameters::from_json_with_secret_key(
        params_json,
        keyset_info.clone(),
        &alice_secret,
    )
    .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    // Parse input proofs
    let input_proofs: Vec<Proof> = serde_json::from_str(input_proofs_json)
        .map_err(|e| format!("Failed to parse input proofs: {}", e))?;

    // Get the funding token nominal amount
    let funding_token_nominal = params
        .get_total_funding_token_amount()
        .map_err(|e| format!("Failed to compute funding token amount: {}", e))?;

    // Create deterministic funding outputs
    let funding_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        funding_token_nominal,
        params,
    )
    .map_err(|e| format!("Failed to create funding outputs: {}", e))?;

    // Get funding blinded messages
    let funding_blinded_messages = funding_outputs
        .get_blinded_messages(None)
        .map_err(|e| format!("Failed to get funding blinded messages: {}", e))?;

    // Get funding secrets with blinding
    let funding_secrets = funding_outputs
        .get_secrets_with_blinding()
        .map_err(|e| format!("Failed to get funding secrets: {}", e))?;

    // Create change outputs (random, anyone-can-spend)
    let mut change_blinded_messages: Vec<BlindedMessage> = Vec::new();
    let mut change_secrets_list: Vec<serde_json::Value> = Vec::new();

    if change_amount > 0 {
        // Build FeeAndAmounts for splitting
        let amounts: Vec<u64> = keyset_info.amounts_largest_first.clone();
        let fee_and_amounts: FeeAndAmounts = (0u64, amounts).into(); // No fee on output side

        // Create random secrets for change
        let change_amounts = Amount::from(change_amount)
            .split_targeted(&SplitTarget::None, &fee_and_amounts)
            .map_err(|e| format!("Failed to split change amount: {}", e))?;

        for amount in change_amounts {
            // Generate random secret
            let secret = Secret::generate();

            // Create blinded message
            let (blinded, r) = blind_message(&secret.to_bytes(), None)
                .map_err(|e| format!("Failed to blind change message: {}", e))?;

            let blinded_message = BlindedMessage::new(amount, keyset_info.keyset_id, blinded);
            change_blinded_messages.push(blinded_message);

            // Store secret with blinding for later unblinding
            change_secrets_list.push(serde_json::json!({
                "secret": secret.to_string(),
                "blinding_factor": r.to_secret_hex(),
                "amount": u64::from(amount)
            }));
        }
    }

    // Combine all outputs: funding first, then change
    let mut all_outputs = funding_blinded_messages;
    all_outputs.extend(change_blinded_messages);

    // Create swap request
    let swap_request = SwapRequest::new(input_proofs, all_outputs);

    // Serialize swap request
    let swap_request_json = serde_json::to_string(&swap_request)
        .map_err(|e| format!("Failed to serialize swap request: {}", e))?;

    // Serialize funding secrets
    let funding_secrets_json: Vec<serde_json::Value> = funding_secrets
        .iter()
        .map(|swb| {
            serde_json::json!({
                "secret": swb.secret.to_string(),
                "blinding_factor": swb.blinding_factor.to_secret_hex(),
                "amount": swb.amount
            })
        })
        .collect();

    // Serialize secrets to JSON strings
    let funding_secrets_str = serde_json::to_string(&funding_secrets_json)
        .map_err(|e| format!("Failed to serialize funding secrets: {}", e))?;
    let change_secrets_str = serde_json::to_string(&change_secrets_list)
        .map_err(|e| format!("Failed to serialize change secrets: {}", e))?;

    // Build result
    let result = serde_json::json!({
        "swap_request_json": swap_request_json,
        "funding_secrets_json": funding_secrets_str,
        "change_secrets_json": change_secrets_str,
        "funding_count": funding_secrets.len(),
        "change_count": change_secrets_list.len()
    });

    Ok(result.to_string())
}

/// Complete a funding swap by unblinding the mint's response
///
/// Takes the mint's swap response and unblinds both funding and change proofs.
/// Also verifies DLEQ proofs on all signatures.
///
/// # Arguments
/// * `swap_response_json` - Mint's swap response (JSON with "signatures" array)
/// * `funding_secrets_json` - Funding secrets from create_funding_swap (JSON array)
/// * `change_secrets_json` - Change secrets from create_funding_swap (JSON array)
/// * `keyset_info_json` - Keyset info (JSON)
///
/// # Returns
/// JSON with:
/// - `funding_proofs_json`: Funding proofs for channel (JSON array)
/// - `change_proofs_json`: Change proofs for user's wallet (JSON array)
pub fn complete_funding_swap(
    swap_response_json: &str,
    funding_secrets_json: &str,
    change_secrets_json: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    // Parse keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;
    let keys = keyset_info.active_keys.clone();

    // Parse swap response to get signatures
    let response: serde_json::Value = serde_json::from_str(swap_response_json)
        .map_err(|e| format!("Failed to parse swap response: {}", e))?;

    let signatures_raw = response["signatures"]
        .as_array()
        .ok_or("Missing 'signatures' in swap response")?;

    // Parse funding secrets
    let funding_secrets_raw: Vec<serde_json::Value> = serde_json::from_str(funding_secrets_json)
        .map_err(|e| format!("Failed to parse funding secrets: {}", e))?;

    // Parse change secrets
    let change_secrets_raw: Vec<serde_json::Value> = serde_json::from_str(change_secrets_json)
        .map_err(|e| format!("Failed to parse change secrets: {}", e))?;

    let funding_count = funding_secrets_raw.len();
    let change_count = change_secrets_raw.len();
    let total_expected = funding_count + change_count;

    // Verify signature count matches
    if signatures_raw.len() != total_expected {
        return Err(format!(
            "Signature count mismatch: expected {} ({}+{}), got {}",
            total_expected,
            funding_count,
            change_count,
            signatures_raw.len()
        ));
    }

    // Split signatures into funding and change
    let funding_sigs = &signatures_raw[..funding_count];
    let change_sigs = &signatures_raw[funding_count..];

    // Helper to parse and verify signatures
    let parse_signatures = |sigs: &[serde_json::Value]| -> Result<Vec<BlindSignature>, String> {
        let mut result = Vec::new();
        for (i, sig) in sigs.iter().enumerate() {
            let amount = sig["amount"]
                .as_u64()
                .ok_or_else(|| format!("Missing 'amount' in signature {}", i))?;
            let id_str = sig["id"]
                .as_str()
                .ok_or_else(|| format!("Missing 'id' in signature {}", i))?;
            let c_str = sig["C_"]
                .as_str()
                .ok_or_else(|| format!("Missing 'C_' in signature {}", i))?;

            let keyset_id: Id = id_str
                .parse()
                .map_err(|e| format!("Invalid keyset id in signature {}: {}", i, e))?;
            let c = PublicKey::from_str(c_str)
                .map_err(|e| format!("Invalid C_ in signature {}: {}", i, e))?;

            // Parse DLEQ - required for Spilman channels
            let dleq_obj = sig["dleq"].as_object().ok_or_else(|| {
                format!(
                    "Missing 'dleq' in signature {} - DLEQ proofs are required",
                    i
                )
            })?;
            let e_str = dleq_obj
                .get("e")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("Missing 'e' in dleq for signature {}", i))?;
            let s_str = dleq_obj
                .get("s")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("Missing 's' in dleq for signature {}", i))?;
            let e = SecretKey::from_hex(e_str)
                .map_err(|e| format!("Invalid dleq.e in signature {}: {}", i, e))?;
            let s = SecretKey::from_hex(s_str)
                .map_err(|e| format!("Invalid dleq.s in signature {}: {}", i, e))?;
            let dleq = BlindSignatureDleq { e, s };

            result.push(BlindSignature {
                amount: Amount::from(amount),
                keyset_id,
                c,
                dleq: Some(dleq),
            });
        }
        Ok(result)
    };

    // Helper to parse secrets
    let parse_secrets =
        |secrets: &[serde_json::Value]| -> Result<(Vec<Secret>, Vec<SecretKey>), String> {
            let mut result_secrets = Vec::new();
            let mut result_rs = Vec::new();
            for (i, swb) in secrets.iter().enumerate() {
                let secret_str = swb["secret"]
                    .as_str()
                    .ok_or_else(|| format!("Missing 'secret' in secrets {}", i))?;
                let blinding_factor_hex = swb["blinding_factor"]
                    .as_str()
                    .ok_or_else(|| format!("Missing 'blinding_factor' in secrets {}", i))?;

                let secret: Secret = secret_str
                    .parse()
                    .map_err(|e| format!("Invalid secret {}: {}", i, e))?;
                let r = SecretKey::from_hex(blinding_factor_hex)
                    .map_err(|e| format!("Invalid blinding factor {}: {}", i, e))?;

                result_secrets.push(secret);
                result_rs.push(r);
            }
            Ok((result_secrets, result_rs))
        };

    // Parse funding signatures and secrets
    let funding_blind_sigs = parse_signatures(funding_sigs)?;
    let (funding_secrets, funding_rs) = parse_secrets(&funding_secrets_raw)?;

    // Construct funding proofs (includes DLEQ verification)
    let funding_proofs =
        dhke_construct_proofs(funding_blind_sigs, funding_rs, funding_secrets, &keys).map_err(
            |e| {
                format!(
                    "Failed to construct funding proofs (DLEQ verification failed?): {}",
                    e
                )
            },
        )?;

    // Parse change signatures and secrets (if any)
    let change_proofs = if change_count > 0 {
        let change_blind_sigs = parse_signatures(change_sigs)?;
        let (change_secrets, change_rs) = parse_secrets(&change_secrets_raw)?;

        dhke_construct_proofs(change_blind_sigs, change_rs, change_secrets, &keys).map_err(|e| {
            format!(
                "Failed to construct change proofs (DLEQ verification failed?): {}",
                e
            )
        })?
    } else {
        Vec::new()
    };

    // Serialize results
    let funding_proofs_json = serde_json::to_string(&funding_proofs)
        .map_err(|e| format!("Failed to serialize funding proofs: {}", e))?;
    let change_proofs_json = serde_json::to_string(&change_proofs)
        .map_err(|e| format!("Failed to serialize change proofs: {}", e))?;

    let result = serde_json::json!({
        "funding_proofs_json": funding_proofs_json,
        "change_proofs_json": change_proofs_json
    });

    Ok(result.to_string())
}
