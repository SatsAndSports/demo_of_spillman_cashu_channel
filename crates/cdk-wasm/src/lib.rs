//! WASM bindings for Cashu payment channels

use std::str::FromStr;

use wasm_bindgen::prelude::*;

use bitcoin::secp256k1::schnorr::Signature;
use cdk::dhke::construct_proofs as dhke_construct_proofs;
use cdk::nuts::{BlindSignature, BlindSignatureDleq, Id, Proof, PublicKey, SecretKey};
use cdk::secret::Secret;
use cdk::spilman::{
    parse_keyset_info_from_json, verify_valid_channel, BalanceUpdateMessage, ChannelParameters,
    DeterministicOutputsForOneContext, EstablishedChannel, SpilmanChannelSender,
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
pub fn compute_shared_secret(
    my_secret_hex: &str,
    their_pubkey_hex: &str,
) -> Result<String, JsValue> {
    cdk::spilman::compute_shared_secret_from_hex(my_secret_hex, their_pubkey_hex)
        .map_err(|e| JsValue::from_str(&e))
}

/// Get channel_id from params JSON, shared secret, and keyset info
///
/// This is effectively a method on ChannelParameters for FFI.
/// Takes the params JSON, the pre-computed shared secret (hex), and keyset info JSON.
#[wasm_bindgen]
pub fn channel_parameters_get_channel_id(
    params_json: &str,
    shared_secret_hex: &str,
    keyset_info_json: &str,
) -> Result<String, JsValue> {
    cdk::spilman::channel_parameters_get_channel_id(
        params_json,
        shared_secret_hex,
        keyset_info_json,
    )
    .map_err(|e| JsValue::from_str(&e))
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
    let my_secret =
        SecretKey::from_hex(my_secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;

    // Create ChannelParameters from JSON
    let params = ChannelParameters::from_json_with_secret_key(params_json, keyset_info, &my_secret)
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

/// Unblind blind signatures and verify DLEQ proofs
///
/// Takes blind signatures from a mint swap response, unblinds them using the
/// secrets and blinding factors from create_close_swap_request, verifies DLEQ
/// proofs, and returns the separated receiver/sender proofs.
///
/// # Arguments
/// * `blind_signatures_json` - JSON array of blind signatures from mint's swap response
/// * `secrets_with_blinding_json` - JSON array from create_close_swap_request's secrets_with_blinding
/// * `params_json` - Full channel parameters JSON (for keyset_info and maximum_amount)
/// * `keyset_info_json` - KeysetInfo JSON (from fetchKeysetInfo)
/// * `shared_secret_hex` - Pre-computed shared secret (hex) for blinded pubkey derivation
/// * `balance` - The receiver's (Charlie's) intended balance (for verification)
///
/// # Returns
/// JSON object with:
/// - `receiver_proofs`: Array of Charlie's P2PK proofs (DLEQ verified)
/// - `sender_proofs`: Array of Alice's P2PK proofs (DLEQ verified)
/// - `receiver_sum_after_stage1`: Sum of receiver proof amounts
/// - `sender_sum_after_stage1`: Sum of sender proof amounts
#[wasm_bindgen]
pub fn unblind_and_verify_dleq(
    blind_signatures_json: &str,
    secrets_with_blinding_json: &str,
    params_json: &str,
    keyset_info_json: &str,
    shared_secret_hex: &str,
    balance: u64,
) -> Result<String, JsValue> {
    unblind_and_verify_dleq_inner(
        blind_signatures_json,
        secrets_with_blinding_json,
        params_json,
        keyset_info_json,
        shared_secret_hex,
        balance,
    )
    .map_err(|e| JsValue::from_str(&e))
}

fn unblind_and_verify_dleq_inner(
    blind_signatures_json: &str,
    secrets_with_blinding_json: &str,
    params_json: &str,
    keyset_info_json: &str,
    shared_secret_hex: &str,
    balance: u64,
) -> Result<String, String> {
    use cdk::nuts::BlindSignature;

    // Parse keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Parse shared secret
    let shared_secret_bytes =
        hex::decode(shared_secret_hex).map_err(|e| format!("Invalid shared secret hex: {}", e))?;
    let shared_secret: [u8; 32] = shared_secret_bytes
        .try_into()
        .map_err(|_| "Shared secret must be 32 bytes".to_string())?;

    // Create ChannelParameters to compute blinded pubkey
    let params = ChannelParameters::from_json_with_shared_secret(
        params_json,
        keyset_info.clone(),
        shared_secret,
    )
    .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    // Get maximum_amount from params
    let maximum_amount = params.maximum_amount_for_one_output;

    // Parse blind signatures
    let blind_signatures: Vec<BlindSignature> = serde_json::from_str(blind_signatures_json)
        .map_err(|e| format!("Invalid blind signatures JSON: {}", e))?;

    // Parse secrets with blinding
    let secrets_with_blinding: Vec<serde_json::Value> =
        serde_json::from_str(secrets_with_blinding_json)
            .map_err(|e| format!("Invalid secrets_with_blinding JSON: {}", e))?;

    // Validate lengths match
    if blind_signatures.len() != secrets_with_blinding.len() {
        return Err(format!(
            "Length mismatch: {} blind signatures but {} secrets",
            blind_signatures.len(),
            secrets_with_blinding.len()
        ));
    }

    // Metadata for each proof: (is_receiver, amount, index)
    struct ProofMeta {
        is_receiver: bool,
        amount: u64,
        index: usize,
    }

    // Extract secrets, blinding factors, and metadata
    let mut secrets = Vec::new();
    let mut blinding_factors = Vec::new();
    let mut proof_metas = Vec::new();

    for (i, swb) in secrets_with_blinding.iter().enumerate() {
        let secret_str = swb["secret"]
            .as_str()
            .ok_or_else(|| format!("Missing 'secret' at index {}", i))?;
        let blinding_hex = swb["blinding_factor"]
            .as_str()
            .ok_or_else(|| format!("Missing 'blinding_factor' at index {}", i))?;
        let is_receiver = swb["is_receiver"]
            .as_bool()
            .ok_or_else(|| format!("Missing 'is_receiver' at index {}", i))?;
        let amount = swb["amount"]
            .as_u64()
            .ok_or_else(|| format!("Missing 'amount' at index {}", i))?;
        let index = swb["index"]
            .as_u64()
            .ok_or_else(|| format!("Missing 'index' at index {}", i))? as usize;

        let secret = Secret::new(secret_str.to_string());
        let blinding_bytes = hex::decode(blinding_hex)
            .map_err(|e| format!("Invalid blinding_factor hex at index {}: {}", i, e))?;
        let blinding_factor = SecretKey::from_slice(&blinding_bytes)
            .map_err(|e| format!("Invalid blinding_factor at index {}: {}", i, e))?;

        secrets.push(secret);
        blinding_factors.push(blinding_factor);
        proof_metas.push(ProofMeta {
            is_receiver,
            amount,
            index,
        });
    }

    // Unblind the signatures to get proofs
    let proofs = cdk::dhke::construct_proofs(
        blind_signatures,
        blinding_factors,
        secrets,
        &keyset_info.active_keys,
    )
    .map_err(|e| format!("Failed to construct proofs: {}", e))?;

    // Verify DLEQ for each proof
    let mut dleq_failures = 0;
    for (i, proof) in proofs.iter().enumerate() {
        // Get mint pubkey for this amount
        let mint_pubkey = keyset_info
            .active_keys
            .amount_key(proof.amount)
            .ok_or_else(|| format!("No mint key for amount {} at index {}", proof.amount, i))?;

        // Verify DLEQ
        if let Err(e) = proof.verify_dleq(mint_pubkey) {
            dleq_failures += 1;
            // Log but continue to count all failures
            eprintln!("DLEQ verification failed for proof {}: {}", i, e);
        }
    }

    if dleq_failures > 0 {
        return Err(format!(
            "DLEQ verification failed: {} of {} proofs failed",
            dleq_failures,
            proofs.len()
        ));
    }

    // Separate proofs by is_receiver flag and compute sums
    // Also keep track of (amount, index) for per-proof pubkey verification
    let mut receiver_proofs = Vec::new();
    let mut receiver_metas = Vec::new(); // (amount, index) for each receiver proof
    let mut sender_proofs = Vec::new();
    let mut receiver_sum: u64 = 0;
    let mut sender_sum: u64 = 0;

    for (proof, meta) in proofs.into_iter().zip(proof_metas.iter()) {
        let amount = u64::from(proof.amount);
        if meta.is_receiver {
            receiver_sum += amount;
            receiver_metas.push((meta.amount, meta.index));
            receiver_proofs.push(proof);
        } else {
            sender_sum += amount;
            sender_proofs.push(proof);
        }
    }

    // Verify each receiver proof is P2PK locked to Charlie's per-proof blinded pubkey
    for (i, (proof, (amount, index))) in receiver_proofs
        .iter()
        .zip(receiver_metas.iter())
        .enumerate()
    {
        // Compute the expected per-proof blinded pubkey for this (amount, index)
        let expected_pubkey = params
            .get_receiver_blinded_pubkey_for_stage2_output(*amount, *index)
            .map_err(|e| {
                format!(
                    "Failed to get receiver blinded pubkey for ({}, {}): {}",
                    amount, index, e
                )
            })?;
        let expected_pubkey_hex = expected_pubkey.to_hex();

        let secret_str = proof.secret.to_string();
        let secret_json: serde_json::Value = serde_json::from_str(&secret_str)
            .map_err(|e| format!("Failed to parse receiver proof {} secret: {}", i, e))?;

        // Check it's P2PK
        let kind = secret_json.get(0).and_then(|v| v.as_str());
        if kind != Some("P2PK") {
            return Err(format!(
                "Receiver proof {} is not P2PK (kind={:?})",
                i, kind
            ));
        }

        // Check pubkey matches Charlie's per-proof blinded pubkey
        let data = secret_json
            .get(1)
            .and_then(|v| v.get("data"))
            .and_then(|v| v.as_str());
        if data != Some(expected_pubkey_hex.as_str()) {
            return Err(format!(
                "Receiver proof {} locked to wrong pubkey: expected {} (charlie blinded stage2 for amount={} index={}), got {:?}",
                i, expected_pubkey_hex, amount, index, data
            ));
        }
    }

    // Verify receiver sum matches expected nominal for this balance
    let inverse_result = keyset_info
        .inverse_deterministic_value_after_fees(balance, maximum_amount)
        .map_err(|e| format!("Failed to compute inverse for balance {}: {}", balance, e))?;

    if receiver_sum != inverse_result.nominal_value {
        return Err(format!(
            "Receiver nominal mismatch: expected {} for balance {}, got {}",
            inverse_result.nominal_value, balance, receiver_sum
        ));
    }

    // Serialize proofs for JSON output
    let receiver_proofs_json: Vec<serde_json::Value> = receiver_proofs
        .iter()
        .map(|p| serde_json::to_value(p).unwrap())
        .collect();
    let sender_proofs_json: Vec<serde_json::Value> = sender_proofs
        .iter()
        .map(|p| serde_json::to_value(p).unwrap())
        .collect();

    // Build result
    let result = serde_json::json!({
        "receiver_proofs": receiver_proofs_json,
        "sender_proofs": sender_proofs_json,
        "receiver_sum_after_stage1": receiver_sum,
        "sender_sum_after_stage1": sender_sum
    });

    Ok(result.to_string())
}

/// Create a signed balance update from Alice (sender) to Charlie (receiver)
///
/// This function creates a balance update message signed by Alice, which authorizes
/// Charlie to claim the specified balance when closing the channel.
///
/// # Arguments
/// * `params_json` - Channel parameters JSON
/// * `keyset_info_json` - Keyset info JSON with keys and fee info
/// * `alice_secret_hex` - Alice's secret key in hex
/// * `funding_proofs_json` - JSON array of funding proofs
/// * `charlie_balance` - The balance to authorize for Charlie
///
/// # Returns
/// JSON object with:
/// - `channel_id`: The channel ID
/// - `amount`: The authorized balance
/// - `signature`: Alice's signature over the balance update
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
    let alice_secret =
        SecretKey::from_hex(alice_secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;

    // Create ChannelParameters
    let params =
        ChannelParameters::from_json_with_secret_key(params_json, keyset_info, &alice_secret)
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

/// Verify a balance update signature from the sender (Alice)
///
/// Takes:
/// - `params_json`: Channel parameters JSON
/// - `shared_secret_hex`: Pre-computed shared secret (hex)
/// - `funding_proofs_json`: JSON array of funding proofs
/// - `keyset_info_json`: KeysetInfo JSON (from fetchKeysetInfo)
/// - `channel_id`: The channel ID from the balance update
/// - `balance`: The balance amount from the balance update
/// - `signature`: Alice's Schnorr signature (hex)
///
/// Returns `true` if the signature is valid, or an error if invalid
#[wasm_bindgen]
pub fn verify_balance_update_signature(
    params_json: &str,
    shared_secret_hex: &str,
    funding_proofs_json: &str,
    keyset_info_json: &str,
    channel_id: &str,
    balance: u64,
    signature: &str,
) -> Result<bool, JsValue> {
    verify_balance_update_signature_inner(
        params_json,
        shared_secret_hex,
        funding_proofs_json,
        keyset_info_json,
        channel_id,
        balance,
        signature,
    )
    .map_err(|e| JsValue::from_str(&e))
}

fn verify_balance_update_signature_inner(
    params_json: &str,
    shared_secret_hex: &str,
    funding_proofs_json: &str,
    keyset_info_json: &str,
    channel_id: &str,
    balance: u64,
    signature: &str,
) -> Result<bool, String> {
    // Parse shared secret from hex
    let shared_secret_bytes =
        hex::decode(shared_secret_hex).map_err(|e| format!("Invalid shared secret hex: {}", e))?;
    let shared_secret: [u8; 32] = shared_secret_bytes
        .try_into()
        .map_err(|_| "Shared secret must be 32 bytes")?;

    // Parse real KeysetInfo from JSON
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Create ChannelParameters with shared secret
    let params =
        ChannelParameters::from_json_with_shared_secret(params_json, keyset_info, shared_secret)
            .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    // Parse funding proofs
    let funding_proofs: Vec<Proof> = serde_json::from_str(funding_proofs_json)
        .map_err(|e| format!("Failed to parse funding proofs: {}", e))?;

    // Create EstablishedChannel
    let channel = EstablishedChannel::new(params, funding_proofs)
        .map_err(|e| format!("Failed to create EstablishedChannel: {}", e))?;

    // Parse signature
    let sig = Signature::from_str(signature).map_err(|e| format!("Invalid signature: {}", e))?;

    // Create BalanceUpdateMessage
    let balance_update = BalanceUpdateMessage {
        channel_id: channel_id.to_string(),
        amount: balance,
        signature: sig,
    };

    // Verify the signature
    balance_update
        .verify_sender_signature(&channel)
        .map_err(|e| format!("Signature verification failed: {}", e))?;

    Ok(true)
}

/// Verify DLEQ proof on a Proof (offline signature verification)
///
/// This allows anyone to verify that the mint really signed this token,
/// without needing to contact the mint. The proof must include the DLEQ
/// data (e, s, r) from construct_proofs.
///
/// Takes:
/// - `proof_json`: A single proof with DLEQ data
///   Format: {"amount": 1, "id": "00...", "secret": "...", "C": "02...", "dleq": {"e": "...", "s": "...", "r": "..."}}
/// - `mint_pubkey_hex`: The mint's public key for this amount (from keyset keys)
///
/// Returns `true` if the DLEQ is valid, throws error otherwise
#[wasm_bindgen]
pub fn verify_proof_dleq(proof_json: &str, mint_pubkey_hex: &str) -> Result<bool, JsValue> {
    verify_proof_dleq_inner(proof_json, mint_pubkey_hex).map_err(|e| JsValue::from_str(&e))
}

fn verify_proof_dleq_inner(proof_json: &str, mint_pubkey_hex: &str) -> Result<bool, String> {
    // Parse the proof
    let proof: Proof =
        serde_json::from_str(proof_json).map_err(|e| format!("Failed to parse proof: {}", e))?;

    // Parse the mint pubkey
    let mint_pubkey =
        PublicKey::from_str(mint_pubkey_hex).map_err(|e| format!("Invalid mint pubkey: {}", e))?;

    // Verify the DLEQ
    proof
        .verify_dleq(mint_pubkey)
        .map_err(|e| format!("DLEQ verification failed: {}", e))?;

    Ok(true)
}

/// Get Alice's blinded secret key for a specific stage 2 output
///
/// Alice uses this to sign when spending a specific stage 1 proof in stage 2.
/// Each stage 1 output is P2PK locked to a UNIQUE blinded pubkey derived from (amount, index),
/// so she needs the corresponding blinded secret key to spend each one.
///
/// # Arguments
/// * `params_json` - Channel parameters JSON
/// * `keyset_info_json` - Keyset info JSON with keys and fee info
/// * `alice_secret_hex` - Alice's raw secret key in hex
/// * `amount` - The proof amount
/// * `index` - The proof index within proofs of the same amount
///
/// # Returns
/// Hex string of Alice's blinded secret key for this specific output
#[wasm_bindgen]
pub fn get_sender_blinded_secret_key_for_stage2_output(
    params_json: &str,
    keyset_info_json: &str,
    alice_secret_hex: &str,
    amount: u64,
    index: u32,
) -> Result<String, JsValue> {
    get_sender_blinded_secret_key_for_stage2_output_inner(
        params_json,
        keyset_info_json,
        alice_secret_hex,
        amount,
        index as usize,
    )
    .map_err(|e| JsValue::from_str(&e))
}

fn get_sender_blinded_secret_key_for_stage2_output_inner(
    params_json: &str,
    keyset_info_json: &str,
    alice_secret_hex: &str,
    amount: u64,
    index: usize,
) -> Result<String, String> {
    // Parse keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Parse Alice's secret key
    let alice_secret =
        SecretKey::from_hex(alice_secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;

    // Create ChannelParameters
    let params =
        ChannelParameters::from_json_with_secret_key(params_json, keyset_info, &alice_secret)
            .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    // Get blinded secret key for this specific stage 2 output
    let blinded_secret = params
        .get_sender_blinded_secret_key_for_stage2_output(&alice_secret, amount, index)
        .map_err(|e| format!("Failed to get blinded secret key: {}", e))?;

    Ok(blinded_secret.to_secret_hex())
}

/// Get Charlie's blinded secret key for a specific stage 2 output
///
/// Charlie uses this to sign when spending a specific stage 1 proof in stage 2.
/// Each stage 1 output is P2PK locked to a UNIQUE blinded pubkey derived from (amount, index),
/// so he needs the corresponding blinded secret key to spend each one.
///
/// # Arguments
/// * `params_json` - Channel parameters JSON
/// * `keyset_info_json` - Keyset info JSON with keys and fee info
/// * `charlie_secret_hex` - Charlie's raw secret key in hex
/// * `shared_secret_hex` - Pre-computed shared secret (hex)
/// * `amount` - The proof amount
/// * `index` - The proof index within proofs of the same amount
///
/// # Returns
/// Hex string of Charlie's blinded secret key for this specific output
#[wasm_bindgen]
pub fn get_receiver_blinded_secret_key_for_stage2_output(
    params_json: &str,
    keyset_info_json: &str,
    charlie_secret_hex: &str,
    shared_secret_hex: &str,
    amount: u64,
    index: u32,
) -> Result<String, JsValue> {
    get_receiver_blinded_secret_key_for_stage2_output_inner(
        params_json,
        keyset_info_json,
        charlie_secret_hex,
        shared_secret_hex,
        amount,
        index as usize,
    )
    .map_err(|e| JsValue::from_str(&e))
}

fn get_receiver_blinded_secret_key_for_stage2_output_inner(
    params_json: &str,
    keyset_info_json: &str,
    charlie_secret_hex: &str,
    shared_secret_hex: &str,
    amount: u64,
    index: usize,
) -> Result<String, String> {
    // Parse keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Parse Charlie's secret key
    let charlie_secret = SecretKey::from_hex(charlie_secret_hex)
        .map_err(|e| format!("Invalid secret key: {}", e))?;

    // Parse shared secret
    let shared_secret_bytes =
        hex::decode(shared_secret_hex).map_err(|e| format!("Invalid shared secret hex: {}", e))?;
    let shared_secret: [u8; 32] = shared_secret_bytes
        .try_into()
        .map_err(|_| "Shared secret must be 32 bytes")?;

    // Create ChannelParameters with shared secret
    let params =
        ChannelParameters::from_json_with_shared_secret(params_json, keyset_info, shared_secret)
            .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    // Get blinded secret key for this specific stage 2 output
    let blinded_secret = params
        .get_receiver_blinded_secret_key_for_stage2_output(&charlie_secret, amount, index)
        .map_err(|e| format!("Failed to get blinded secret key: {}", e))?;

    Ok(blinded_secret.to_secret_hex())
}

/// Verify that a channel is valid
///
/// This verifies everything about a channel that the receiver (Charlie)
/// needs to check before accepting it:
///
/// 1. DLEQ proofs - the mint actually signed each funding proof
///
/// Takes:
/// - `params_json`: Channel parameters JSON
/// - `shared_secret_hex`: Pre-computed shared secret (hex)
/// - `funding_proofs_json`: JSON array of funding proofs
/// - `keyset_info_json`: KeysetInfo JSON (from fetchKeysetInfo)
///
/// Returns JSON: {"valid": true, "errors": []} or {"valid": false, "errors": [...]}
#[wasm_bindgen]
pub fn verify_channel(
    params_json: &str,
    shared_secret_hex: &str,
    funding_proofs_json: &str,
    keyset_info_json: &str,
) -> Result<String, JsValue> {
    verify_channel_inner(
        params_json,
        shared_secret_hex,
        funding_proofs_json,
        keyset_info_json,
    )
    .map_err(|e| JsValue::from_str(&e))
}

fn verify_channel_inner(
    params_json: &str,
    shared_secret_hex: &str,
    funding_proofs_json: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    // Parse shared secret from hex
    let shared_secret_bytes =
        hex::decode(shared_secret_hex).map_err(|e| format!("Invalid shared secret hex: {}", e))?;
    let shared_secret: [u8; 32] = shared_secret_bytes
        .try_into()
        .map_err(|_| "Shared secret must be 32 bytes")?;

    // Parse keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Create ChannelParameters with shared secret
    let params =
        ChannelParameters::from_json_with_shared_secret(params_json, keyset_info, shared_secret)
            .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    // Parse funding proofs
    let funding_proofs: Vec<Proof> = serde_json::from_str(funding_proofs_json)
        .map_err(|e| format!("Failed to parse funding proofs: {}", e))?;

    // Verify the channel
    let result = verify_valid_channel(&funding_proofs, &params);

    // Serialize result to JSON
    serde_json::to_string(&result).map_err(|e| format!("Failed to serialize result: {}", e))
}

/// Construct proofs from blind signatures
///
/// Takes the blind signatures from the mint and unblinds them using the
/// secrets and blinding factors from `create_funding_outputs`.
///
/// Takes:
/// - `blind_signatures_json`: JSON array of blind signatures from mint response
///   Format: [{"amount": 1, "id": "00...", "C_": "02..."}, ...]
/// - `secrets_with_blinding_json`: JSON array from `create_funding_outputs`
///   Format: [{"secret": "...", "blinding_factor": "...", "amount": 1}, ...]
/// - `keyset_info_json`: KeysetInfo JSON (from fetchKeysetInfo)
///
/// Returns JSON array of proofs ready for use
#[wasm_bindgen]
pub fn construct_proofs(
    blind_signatures_json: &str,
    secrets_with_blinding_json: &str,
    keyset_info_json: &str,
) -> Result<String, JsValue> {
    construct_proofs_inner(
        blind_signatures_json,
        secrets_with_blinding_json,
        keyset_info_json,
    )
    .map_err(|e| JsValue::from_str(&e))
}

fn construct_proofs_inner(
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

/// Create a fully-signed swap request for channel closing (Charlie's side)
///
/// Charlie (the receiver/server) uses this to:
/// 1. Verify Alice's signature on the balance update
/// 2. Add his own signature to complete the 2-of-2 multisig
/// 3. Get the swap request ready to submit to the mint
///
/// Takes:
/// - `params_json`: Channel parameters JSON
/// - `keyset_info_json`: KeysetInfo JSON (with full keys for output computation)
/// - `charlie_secret_hex`: Charlie's secret key (hex)
/// - `funding_proofs_json`: JSON array of funding proofs
/// - `channel_id`: The channel ID
/// - `balance`: Charlie's balance (the amount_due)
/// - `alice_signature`: Alice's Schnorr signature (hex) from the close request
///
/// Returns JSON with:
/// - `swap_request`: The fully-signed swap request ready for mint
/// - `expected_total`: Expected total output amount (value after stage 1 fees)
#[wasm_bindgen]
pub fn create_close_swap_request(
    params_json: &str,
    keyset_info_json: &str,
    charlie_secret_hex: &str,
    funding_proofs_json: &str,
    channel_id: &str,
    balance: u64,
    alice_signature: &str,
) -> Result<String, JsValue> {
    create_close_swap_request_inner(
        params_json,
        keyset_info_json,
        charlie_secret_hex,
        funding_proofs_json,
        channel_id,
        balance,
        alice_signature,
    )
    .map_err(|e| JsValue::from_str(&e))
}

fn create_close_swap_request_inner(
    params_json: &str,
    keyset_info_json: &str,
    charlie_secret_hex: &str,
    funding_proofs_json: &str,
    channel_id: &str,
    balance: u64,
    alice_signature: &str,
) -> Result<String, String> {
    use cdk::spilman::{CommitmentOutputs, SpilmanChannelReceiver};

    // Parse keyset info (need full keys for output computation)
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Parse Charlie's secret key
    let charlie_secret = SecretKey::from_hex(charlie_secret_hex)
        .map_err(|e| format!("Invalid Charlie secret key: {}", e))?;

    // Compute shared secret from Charlie's perspective
    // We need Alice's pubkey from the params to do this
    let json: serde_json::Value =
        serde_json::from_str(params_json).map_err(|e| format!("Invalid params JSON: {}", e))?;
    let alice_pubkey_hex = json["alice_pubkey"]
        .as_str()
        .ok_or_else(|| "Missing 'alice_pubkey' field in params".to_string())?;

    let shared_secret_hex =
        cdk::spilman::compute_shared_secret_from_hex(charlie_secret_hex, alice_pubkey_hex)?;
    let shared_secret_bytes =
        hex::decode(&shared_secret_hex).map_err(|e| format!("Invalid shared secret hex: {}", e))?;
    let shared_secret: [u8; 32] = shared_secret_bytes
        .try_into()
        .map_err(|_| "Shared secret must be 32 bytes")?;

    // Create ChannelParameters with shared secret
    let params =
        ChannelParameters::from_json_with_shared_secret(params_json, keyset_info, shared_secret)
            .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    // Parse funding proofs
    let funding_proofs: Vec<Proof> = serde_json::from_str(funding_proofs_json)
        .map_err(|e| format!("Failed to parse funding proofs: {}", e))?;

    // Create EstablishedChannel
    let channel = EstablishedChannel::new(params.clone(), funding_proofs.clone())
        .map_err(|e| format!("Failed to create EstablishedChannel: {}", e))?;

    // Create SpilmanChannelReceiver (Charlie's view)
    let receiver = SpilmanChannelReceiver::new(charlie_secret, channel);

    // Create CommitmentOutputs for this balance
    let commitment_outputs = CommitmentOutputs::for_balance(balance, &params)
        .map_err(|e| format!("Failed to create commitment outputs: {}", e))?;

    // Create unsigned swap request
    let mut swap_request = commitment_outputs
        .create_swap_request(funding_proofs)
        .map_err(|e| format!("Failed to create swap request: {}", e))?;

    // Parse Alice's signature
    let alice_sig = Signature::from_str(alice_signature)
        .map_err(|e| format!("Invalid Alice signature: {}", e))?;

    // Create BalanceUpdateMessage from the close request
    let balance_update = BalanceUpdateMessage {
        channel_id: channel_id.to_string(),
        amount: balance,
        signature: alice_sig.clone(),
    };

    // Add Alice's signature to the swap request witness
    // (This is what Alice would have done before sending the balance update)
    {
        use cdk::nuts::{nut00::Witness, nut11::P2PKWitness};
        let first_input = swap_request
            .inputs_mut()
            .first_mut()
            .ok_or_else(|| "Swap request has no inputs".to_string())?;

        match first_input.witness.as_mut() {
            Some(witness) => {
                witness.add_signatures(vec![alice_sig.to_string()]);
            }
            None => {
                let mut p2pk_witness = Witness::P2PKWitness(P2PKWitness::default());
                p2pk_witness.add_signatures(vec![alice_sig.to_string()]);
                first_input.witness = Some(p2pk_witness);
            }
        }
    }

    // Verify Alice's signature and add Charlie's signature
    let signed_swap_request = receiver
        .add_second_signature(&balance_update, swap_request)
        .map_err(|e| format!("Failed to add second signature: {}", e))?;

    // Get expected total (value after stage 1 fees)
    let expected_total = params
        .get_value_after_stage1()
        .map_err(|e| format!("Failed to get value after stage 1: {}", e))?;

    // Get secrets with blinding factors for unblinding later
    // Must be in same order as swap_request.outputs (sorted by amount, stable)
    let receiver_secrets = commitment_outputs
        .receiver_outputs
        .get_secrets_with_blinding()
        .map_err(|e| format!("Failed to get receiver secrets: {}", e))?;
    let sender_secrets = commitment_outputs
        .sender_outputs
        .get_secrets_with_blinding()
        .map_err(|e| format!("Failed to get sender secrets: {}", e))?;

    // Combine and tag with is_receiver, then sort by amount (stable) to match output order
    let mut secrets_with_tags: Vec<(cdk::spilman::DeterministicSecretWithBlinding, bool)> =
        receiver_secrets
            .into_iter()
            .map(|s| (s, true))
            .chain(sender_secrets.into_iter().map(|s| (s, false)))
            .collect();
    secrets_with_tags.sort_by_key(|(s, _)| s.amount);

    // Serialize secrets for JSON output (includes index for per-proof blinding)
    let secrets_with_blinding: Vec<serde_json::Value> = secrets_with_tags
        .into_iter()
        .map(|(s, is_receiver)| {
            serde_json::json!({
                "secret": s.secret.to_string(),
                "blinding_factor": hex::encode(s.blinding_factor.secret_bytes()),
                "amount": s.amount,
                "index": s.index,
                "is_receiver": is_receiver
            })
        })
        .collect();

    // Serialize the swap request
    let swap_request_json = serde_json::to_value(&signed_swap_request)
        .map_err(|e| format!("Failed to serialize swap request: {}", e))?;

    // Build result
    let result = serde_json::json!({
        "swap_request": swap_request_json,
        "expected_total": expected_total,
        "secrets_with_blinding": secrets_with_blinding
    });

    Ok(result.to_string())
}
