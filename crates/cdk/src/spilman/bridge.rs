//! Spilman Protocol Bridge
//!
//! This module provides a high-level bridge for implementing Spilman payment channels
//! in any service provider. It handles the core protocol logic, validation, and
//! signature verification, while delegating storage and pricing to a host hook.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::{
    verify_valid_channel, BalanceUpdateMessage, ChannelParameters, CommitmentOutputs,
    DeterministicSecretWithBlinding, EstablishedChannel, KeysetInfo, SpilmanChannelReceiver,
};
use crate::nuts::{BlindSignature, CurrencyUnit, Id, Proof, PublicKey, SecretKey, SwapRequest};
use crate::util::hex;
use std::str::FromStr;

/// Host hooks for the Spilman bridge
///
/// Implement this trait to provide storage and pricing logic for your service.
pub trait SpilmanHost {
    /// Check if the receiver pubkey in the channel params is acceptable
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool;

    /// Check if the mint and keyset are acceptable
    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &crate::nuts::Id) -> bool;

    /// Get cached funding data for a channel
    /// Returns (params_json, funding_proofs_json, shared_secret_hex, keyset_info_json)
    fn get_funding_and_params(&self, channel_id: &str) -> Option<(String, String, String, String)>;

    /// Save funding data for a channel
    fn save_funding(
        &self,
        channel_id: &str,
        params_json: &str,
        funding_proofs_json: &str,
        shared_secret_hex: &str,
        keyset_info_json: &str,
    );

    /// Get the current amount due for a channel
    ///
    /// The host should compute this based on the service provided so far,
    /// plus the current request described in `context_json`.
    /// If `context_json` is None, return the amount due based on existing usage.
    fn get_amount_due(&self, channel_id: &str, context_json: Option<&str>) -> u64;

    /// Record a successful payment and update usage
    fn record_payment(&self, channel_id: &str, balance: u64, signature: &str, context_json: &str);

    /// Check if a channel has been closed
    fn is_closed(&self, channel_id: &str) -> bool;

    /// Get channel policy (pricing, limits, etc.)
    fn get_channel_policy(&self) -> String;

    /// Get the current time in seconds
    fn now_seconds(&self) -> u64;

    /// Get the balance and signature for a unilateral exit
    ///
    /// This is used for unilateral closing - the server retrieves the best
    /// payment proof it has stored to close the channel.
    /// Returns (balance, signature_hex) if available.
    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        channel_id: &str,
    ) -> Option<(u64, String)>;

    /// Get currently active keyset IDs for a mint and unit
    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id>;

    /// Get full KeysetInfo JSON for a specific keyset
    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String>;
}

/// Bridge for processing Spilman payments
pub struct SpilmanBridge<H: SpilmanHost> {
    host: H,
    server_secret_key: Option<SecretKey>,
}

#[derive(Debug, Deserialize)]
pub struct PaymentRequest {
    pub channel_id: String,
    pub balance: u64,
    pub signature: String,
    pub params: Option<serde_json::Value>,
    pub funding_proofs: Option<Vec<Proof>>,
}

#[derive(Debug, Serialize, Copy, Clone)]
pub enum BridgeStatus {
    OK,
    PaymentRequired,
    BadRequest,
    ServerError,
}

#[derive(Debug, Serialize)]
pub struct PaymentResponse {
    pub success: bool,
    pub error: Option<String>,
    pub status: BridgeStatus,
    pub header: Option<serde_json::Value>,
    pub body: Option<serde_json::Value>,
}

/// Data needed to close a channel
///
/// Contains the fully-signed swap request ready to submit to the mint,
/// plus the secrets and blinding factors needed to unblind the response.
#[derive(Debug)]
pub struct CloseData {
    /// The fully-signed swap request (2-of-2 multisig complete)
    pub swap_request: SwapRequest,
    /// Expected total output value after stage 1 fees
    pub expected_total: u64,
    /// Secrets with blinding factors for unblinding, tagged with is_receiver
    /// Sorted by amount (stable) to match swap_request output order
    pub secrets_with_blinding: Vec<(DeterministicSecretWithBlinding, bool)>,
    /// The keyset info for the outputs of the swap (may differ from funding keyset)
    pub output_keyset_info: KeysetInfo,
}

/// Result of unblinding and verifying stage 1 swap response
#[derive(Debug)]
pub struct UnblindResult {
    /// Receiver's proofs (P2PK locked to Charlie's blinded pubkey)
    pub receiver_proofs: Vec<Proof>,
    /// Sender's proofs (P2PK locked to Alice's blinded pubkey)
    pub sender_proofs: Vec<Proof>,
    /// Sum of receiver proof amounts
    pub receiver_sum: u64,
    /// Sum of sender proof amounts
    pub sender_sum: u64,
}

#[derive(Debug, Deserialize)]
pub struct BridgeServerConfig {
    pub min_expiry_in_seconds: u64,
    pub pricing: BTreeMap<String, UnitPricing>,
}

#[derive(Debug, Deserialize)]
pub struct UnitPricing {
    #[serde(default)]
    #[serde(rename = "minCapacity")]
    pub min_capacity: u64,
    #[serde(rename = "maxAmountPerOutput")]
    pub max_amount_per_output: Option<u64>,
}

#[derive(Debug)]
pub enum BridgeError {
    InvalidRequest(String),
    ChannelClosed,
    ServerMisconfigured(String),
    CapacityTooSmall {
        capacity: u64,
        min_capacity: u64,
    },
    LocktimeTooSoon {
        locktime: u64,
        min_locktime: u64,
        now: u64,
    },
    MaxAmountExceeded {
        amount: u64,
        max_allowed: u64,
    },
    BalanceExceedsCapacity {
        balance: u64,
        capacity: u64,
    },
    UnsupportedUnit(String),
    ChannelIdMismatch,
    ValidationFailed(String),
    UnknownChannel,
    InvalidSignature(String),
    InsufficientBalance {
        balance: u64,
        amount_due: u64,
    },
    BalanceMismatch {
        expected: u64,
        actual: u64,
    },
    Internal(String),
    ReceiverKeyNotAcceptable,
    MintOrKeysetNotAcceptable,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(s) => write!(f, "{}", s),
            Self::ChannelClosed => write!(f, "channel closed"),
            Self::ServerMisconfigured(s) => write!(f, "server misconfigured: {}", s),
            Self::CapacityTooSmall {
                capacity,
                min_capacity,
            } => write!(f, "capacity too small: {} < {}", capacity, min_capacity),
            Self::LocktimeTooSoon {
                locktime,
                min_locktime,
                now,
            } => write!(
                f,
                "locktime too soon: {} < {} ({}s remaining)",
                locktime,
                min_locktime,
                locktime.saturating_sub(*now)
            ),
            Self::MaxAmountExceeded {
                amount,
                max_allowed,
            } => write!(
                f,
                "max_amount_per_output exceeded: {} > {}",
                amount, max_allowed
            ),
            Self::BalanceExceedsCapacity { balance, capacity } => {
                write!(f, "balance exceeds capacity: {} > {}", balance, capacity)
            }
            Self::UnsupportedUnit(u) => write!(f, "unsupported unit: {}", u),
            Self::ChannelIdMismatch => write!(f, "channel_id mismatch"),
            Self::ValidationFailed(s) => write!(f, "channel validation failed: {}", s),
            Self::UnknownChannel => write!(f, "unknown channel"),
            Self::InvalidSignature(s) => write!(f, "invalid signature: {}", s),
            Self::InsufficientBalance {
                balance,
                amount_due,
            } => write!(f, "insufficient balance: {} < {}", balance, amount_due),
            Self::BalanceMismatch { expected, actual } => {
                write!(f, "balance mismatch: expected {}, got {}", expected, actual)
            }
            Self::Internal(s) => write!(f, "internal error: {}", s),
            Self::ReceiverKeyNotAcceptable => write!(f, "receiver key not acceptable"),
            Self::MintOrKeysetNotAcceptable => write!(f, "mint or keyset not acceptable"),
        }
    }
}

/// Unblind and verify stage 1 swap response from the mint
///
/// This function processes the mint's response to a channel close swap request:
/// 1. Unblinds the signatures to construct proofs
/// 2. Verifies DLEQ proofs on all outputs
/// 3. Separates receiver and sender proofs
/// 4. Verifies receiver proofs are P2PK locked to Charlie's blinded pubkey (stage2 context)
/// 5. Verifies receiver sum matches expected nominal value for the balance
///
/// # Arguments
/// * `blind_signatures` - The mint's blind signatures from the swap response
/// * `secrets_with_blinding` - Secrets and blinding factors tagged with is_receiver, from CloseData
/// * `params` - Channel parameters (with shared secret already set)
/// * `keyset_info` - Keyset info for the channel's keyset
/// * `balance` - The balance at which the channel was closed
///
/// # Returns
/// * `UnblindResult` with separated proofs and sums
pub fn unblind_and_verify_stage1_response(
    blind_signatures: Vec<BlindSignature>,
    secrets_with_blinding: Vec<(DeterministicSecretWithBlinding, bool)>,
    params: &ChannelParameters,
    output_keyset_info: &KeysetInfo,
    balance: u64,
) -> Result<UnblindResult, BridgeError> {
    // Validate lengths match
    if blind_signatures.len() != secrets_with_blinding.len() {
        return Err(BridgeError::Internal(format!(
            "Length mismatch: {} blind signatures but {} secrets",
            blind_signatures.len(),
            secrets_with_blinding.len()
        )));
    }

    // Extract secrets, blinding factors for construct_proofs
    let mut secrets = Vec::with_capacity(secrets_with_blinding.len());
    let mut blinding_factors = Vec::with_capacity(secrets_with_blinding.len());
    let mut is_receiver_flags = Vec::with_capacity(secrets_with_blinding.len());
    let mut amount_index_pairs = Vec::with_capacity(secrets_with_blinding.len());

    for (swb, is_receiver) in secrets_with_blinding {
        secrets.push(swb.secret);
        blinding_factors.push(swb.blinding_factor);
        is_receiver_flags.push(is_receiver);
        amount_index_pairs.push((swb.amount, swb.index));
    }

    // Unblind the signatures to get proofs
    let proofs = crate::dhke::construct_proofs(
        blind_signatures,
        blinding_factors,
        secrets,
        &output_keyset_info.active_keys,
    )
    .map_err(|e| BridgeError::Internal(format!("Failed to construct proofs: {}", e)))?;

    // Verify DLEQ for each proof
    let mut dleq_failures = 0;
    for (i, proof) in proofs.iter().enumerate() {
        let mint_pubkey = output_keyset_info
            .active_keys
            .amount_key(proof.amount)
            .ok_or_else(|| {
                BridgeError::Internal(format!(
                    "No mint key for amount {} at index {}",
                    proof.amount, i
                ))
            })?;

        if let Err(e) = proof.verify_dleq(mint_pubkey) {
            dleq_failures += 1;
            eprintln!("DLEQ verification failed for proof {}: {}", i, e);
        }
    }

    if dleq_failures > 0 {
        return Err(BridgeError::ValidationFailed(format!(
            "DLEQ verification failed: {} of {} proofs failed",
            dleq_failures,
            proofs.len()
        )));
    }

    // Separate proofs by is_receiver flag and compute sums
    let mut receiver_proofs = Vec::new();
    let mut receiver_metas = Vec::new(); // (amount, index) for each receiver proof
    let mut sender_proofs = Vec::new();
    let mut receiver_sum: u64 = 0;
    let mut sender_sum: u64 = 0;

    for ((proof, &is_receiver), (amount, index)) in proofs
        .into_iter()
        .zip(is_receiver_flags.iter())
        .zip(amount_index_pairs.iter())
    {
        let proof_amount = u64::from(proof.amount);
        if is_receiver {
            receiver_sum += proof_amount;
            receiver_metas.push((*amount, *index));
            receiver_proofs.push(proof);
        } else {
            sender_sum += proof_amount;
            sender_proofs.push(proof);
        }
    }

    // Verify each receiver proof is P2PK locked to Charlie's per-proof blinded pubkey
    for (i, (proof, (amount, index))) in receiver_proofs
        .iter()
        .zip(receiver_metas.iter())
        .enumerate()
    {
        let expected_pubkey = params
            .get_receiver_blinded_pubkey_for_stage2_output(*amount, *index)
            .map_err(|e| {
                BridgeError::Internal(format!(
                    "Failed to get receiver blinded pubkey for ({}, {}): {}",
                    amount, index, e
                ))
            })?;
        let expected_pubkey_hex = expected_pubkey.to_hex();

        let secret_str = proof.secret.to_string();
        let secret_json: serde_json::Value = serde_json::from_str(&secret_str).map_err(|e| {
            BridgeError::Internal(format!(
                "Failed to parse receiver proof {} secret: {}",
                i, e
            ))
        })?;

        // Check it's P2PK
        let kind = secret_json.get(0).and_then(|v| v.as_str());
        if kind != Some("P2PK") {
            return Err(BridgeError::ValidationFailed(format!(
                "Receiver proof {} is not P2PK (kind={:?})",
                i, kind
            )));
        }

        // Check pubkey matches Charlie's per-proof blinded pubkey
        let data = secret_json
            .get(1)
            .and_then(|v| v.get("data"))
            .and_then(|v| v.as_str());
        if data != Some(expected_pubkey_hex.as_str()) {
            return Err(BridgeError::ValidationFailed(format!(
                "Receiver proof {} locked to wrong pubkey: expected {} (charlie blinded stage2 for amount={} index={}), got {:?}",
                i, expected_pubkey_hex, amount, index, data
            )));
        }
    }

    // Verify receiver sum matches expected nominal for this balance
    let maximum_amount = params.maximum_amount_for_one_output;
    let inverse_result = output_keyset_info
        .inverse_deterministic_value_after_fees(balance, maximum_amount)
        .map_err(|e| {
            BridgeError::Internal(format!(
                "Failed to compute inverse for balance {}: {}",
                balance, e
            ))
        })?;

    if receiver_sum != inverse_result.nominal_value {
        return Err(BridgeError::ValidationFailed(format!(
            "Receiver nominal mismatch: expected {} for balance {}, got {}",
            inverse_result.nominal_value, balance, receiver_sum
        )));
    }

    Ok(UnblindResult {
        receiver_proofs,
        sender_proofs,
        receiver_sum,
        sender_sum,
    })
}

/// Unblind signatures from a swap response and verify DLEQ proofs
pub fn unblind_and_verify_dleq(
    blind_signatures_json: &str,
    secrets_with_blinding_json: &str,
    params_json: &str,
    keyset_info_json: &str,
    shared_secret_hex: &str,
    balance: u64,
    output_keyset_info_json: Option<&str>,
) -> Result<String, String> {
    use super::{parse_keyset_info_from_json, unblind_and_verify_stage1_response};
    use crate::nuts::SecretKey;
    use crate::secret::Secret;

    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;
    let output_keyset_info = match output_keyset_info_json {
        Some(json) => parse_keyset_info_from_json(json)?,
        None => keyset_info.clone(),
    };

    let shared_secret_bytes =
        hex::decode(shared_secret_hex).map_err(|e| format!("Invalid shared secret hex: {}", e))?;
    let shared_secret: [u8; 32] = shared_secret_bytes
        .try_into()
        .map_err(|_| "Shared secret must be 32 bytes".to_string())?;

    let params =
        ChannelParameters::from_json_with_shared_secret(params_json, keyset_info, shared_secret)
            .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    let blind_signatures: Vec<BlindSignature> = serde_json::from_str(blind_signatures_json)
        .map_err(|e| format!("Invalid blind signatures JSON: {}", e))?;

    let swb_raw: Vec<serde_json::Value> = serde_json::from_str(secrets_with_blinding_json)
        .map_err(|e| format!("Invalid secrets_with_blinding JSON: {}", e))?;

    let mut secrets_with_blinding: Vec<(DeterministicSecretWithBlinding, bool)> = Vec::new();
    for swb in swb_raw {
        let secret_str = swb["secret"].as_str().ok_or("Missing secret")?;
        let blinding_hex = swb["blinding_factor"].as_str().ok_or("Missing blinding")?;
        let is_receiver = swb["is_receiver"].as_bool().ok_or("Missing is_receiver")?;
        let amount = swb["amount"].as_u64().ok_or("Missing amount")?;
        let index = swb["index"].as_u64().ok_or("Missing index")? as usize;

        let secret = Secret::new(secret_str.to_string());
        let blinding_bytes = hex::decode(blinding_hex).map_err(|e| e.to_string())?;
        let blinding_factor = SecretKey::from_slice(&blinding_bytes).map_err(|e| e.to_string())?;

        secrets_with_blinding.push((
            DeterministicSecretWithBlinding {
                secret,
                blinding_factor,
                amount,
                index,
            },
            is_receiver,
        ));
    }

    let result = unblind_and_verify_stage1_response(
        blind_signatures,
        secrets_with_blinding,
        &params,
        &output_keyset_info,
        balance,
    )
    .map_err(|e| e.to_string())?;

    let json = serde_json::json!({
        "receiver_proofs": result.receiver_proofs,
        "sender_proofs": result.sender_proofs,
        "receiver_sum_after_stage1": result.receiver_sum,
        "sender_sum_after_stage1": result.sender_sum
    });

    Ok(json.to_string())
}

impl<H: SpilmanHost> SpilmanBridge<H> {
    pub fn new(host: H, server_secret_key: Option<SecretKey>) -> Self {
        Self {
            host,
            server_secret_key,
        }
    }

    /// Process an incoming payment
    pub fn process_payment(
        &self,
        payment_json: &str,
        context_json: &str,
        keyset_info_json: Option<&str>,
    ) -> PaymentResponse {
        match self.process_payment_inner(payment_json, context_json, keyset_info_json) {
            Ok(resp) => resp,
            Err(e) => {
                let mut extra = BTreeMap::new();
                let msg = e.to_string();
                let status = match e {
                    BridgeError::InvalidRequest(_) => BridgeStatus::PaymentRequired,
                    BridgeError::ServerMisconfigured(_) => BridgeStatus::ServerError,
                    BridgeError::Internal(_) => BridgeStatus::ServerError,
                    _ => BridgeStatus::PaymentRequired,
                };

                match e {
                    BridgeError::CapacityTooSmall {
                        capacity,
                        min_capacity,
                    } => {
                        extra.insert("capacity".into(), serde_json::json!(capacity));
                        extra.insert("min_capacity".into(), serde_json::json!(min_capacity));
                    }
                    BridgeError::LocktimeTooSoon {
                        locktime,
                        min_locktime,
                        now,
                    } => {
                        extra.insert("locktime".into(), serde_json::json!(locktime));
                        extra.insert(
                            "min_expiry_in_seconds".into(),
                            serde_json::json!(min_locktime - now),
                        );
                        extra.insert(
                            "seconds_remaining".into(),
                            serde_json::json!(locktime.saturating_sub(now)),
                        );
                    }
                    BridgeError::MaxAmountExceeded {
                        amount,
                        max_allowed,
                    } => {
                        extra.insert("maximum_amount".into(), serde_json::json!(amount));
                        extra.insert("max_allowed".into(), serde_json::json!(max_allowed));
                    }
                    BridgeError::BalanceExceedsCapacity { balance, capacity } => {
                        extra.insert("balance".into(), serde_json::json!(balance));
                        extra.insert("capacity".into(), serde_json::json!(capacity));
                    }
                    BridgeError::InsufficientBalance {
                        balance,
                        amount_due,
                    } => {
                        extra.insert("balance".into(), serde_json::json!(balance));
                        extra.insert("amount_due".into(), serde_json::json!(amount_due));
                    }
                    BridgeError::BalanceMismatch { expected, actual } => {
                        extra.insert("expected".into(), serde_json::json!(expected));
                        extra.insert("actual".into(), serde_json::json!(actual));
                    }
                    BridgeError::ValidationFailed(ref s) => {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(s) {
                            extra.insert("validation_errors".into(), val);
                        }
                    }
                    _ => {}
                }
                self.error_with_extra(&msg, status, None, extra)
            }
        }
    }

    fn process_payment_inner(
        &self,
        payment_json: &str,
        context_json: &str,
        keyset_info_json: Option<&str>,
    ) -> Result<PaymentResponse, BridgeError> {
        // 1. Parse payment request
        let payment: PaymentRequest = serde_json::from_str::<PaymentRequest>(payment_json)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;

        if payment.channel_id.is_empty() {
            return Err(BridgeError::InvalidRequest("missing channel_id".into()));
        }

        if payment.signature.is_empty() {
            return Err(BridgeError::InvalidRequest("missing signature".into()));
        }

        let channel_id = &payment.channel_id;

        // 2. Check if channel is closed
        if self.host.is_closed(channel_id) {
            return Err(BridgeError::ChannelClosed);
        }

        // 3. Resolve or verify funding
        let funding_and_params = match self.host.get_funding_and_params(channel_id) {
            Some(f) => f,
            None => {
                // Unknown channel - must provide params and funding_proofs
                let params_val = payment.params.as_ref().ok_or(BridgeError::UnknownChannel)?;
                let funding_proofs = payment
                    .funding_proofs
                    .as_ref()
                    .ok_or(BridgeError::UnknownChannel)?;
                let keyset_info_json =
                    keyset_info_json.ok_or(BridgeError::MintOrKeysetNotAcceptable)?;

                // Perform full validation
                self.validate_and_save_new_channel(
                    channel_id,
                    params_val,
                    funding_proofs,
                    keyset_info_json,
                )?
            }
        };

        let (params_json, funding_proofs_json, shared_secret_hex, keyset_info_json) =
            funding_and_params;

        // 4. Parse params for capacity and unit checks
        let params: serde_json::Value = serde_json::from_str(&params_json)
            .map_err(|e| BridgeError::Internal(format!("failed to parse cached params: {}", e)))?;

        let capacity = params["capacity"].as_u64().unwrap_or(0);

        // 5. Check balance doesn't exceed capacity
        if payment.balance > capacity {
            return Err(BridgeError::BalanceExceedsCapacity {
                balance: payment.balance,
                capacity,
            });
        }

        // 6. Check balance against amount_due
        let amount_due = self.host.get_amount_due(channel_id, Some(context_json));
        if payment.balance < amount_due {
            return Err(BridgeError::InsufficientBalance {
                balance: payment.balance,
                amount_due,
            });
        }

        // 7. Verify signature
        self.verify_signature(
            &params_json,
            &funding_proofs_json,
            &shared_secret_hex,
            &keyset_info_json,
            channel_id,
            payment.balance,
            &payment.signature,
        )
        .map_err(BridgeError::InvalidSignature)?;

        // 8. Record successful payment
        self.host.record_payment(
            channel_id,
            payment.balance,
            &payment.signature,
            context_json,
        );

        // 9. Return success with confirmation header
        let header = serde_json::json!({
            "channel_id": channel_id,
            "balance": payment.balance,
            "amount_due": amount_due,
            "capacity": capacity,
        });

        Ok(PaymentResponse {
            success: true,
            error: None,
            status: BridgeStatus::OK,
            header: Some(header),
            body: None,
        })
    }

    fn validate_and_save_new_channel(
        &self,
        channel_id: &str,
        params_val: &serde_json::Value,
        funding_proofs: &[Proof],
        keyset_info_json: &str,
    ) -> Result<(String, String, String, String), BridgeError> {
        let server_secret_key = self
            .server_secret_key
            .as_ref()
            .ok_or(BridgeError::ServerMisconfigured("no secret key".into()))?;

        let params_json = params_val.to_string();
        let unit = params_val["unit"]
            .as_str()
            .ok_or(BridgeError::InvalidRequest("missing unit".into()))?;
        let capacity = params_val["capacity"]
            .as_u64()
            .ok_or(BridgeError::InvalidRequest("missing capacity".into()))?;
        let locktime = params_val["locktime"]
            .as_u64()
            .ok_or(BridgeError::InvalidRequest("missing locktime".into()))?;
        let maximum_amount = params_val["maximum_amount"]
            .as_u64()
            .ok_or(BridgeError::InvalidRequest("missing maximum_amount".into()))?;

        // 0. Host-specific acceptability checks
        let charlie_pubkey_hex = params_val["charlie_pubkey"]
            .as_str()
            .ok_or(BridgeError::InvalidRequest("missing charlie_pubkey".into()))?;
        let charlie_pubkey = PublicKey::from_hex(charlie_pubkey_hex)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;

        if !self.host.receiver_key_is_acceptable(&charlie_pubkey) {
            return Err(BridgeError::ReceiverKeyNotAcceptable);
        }

        let keyset_id_str = params_val["keyset_id"]
            .as_str()
            .ok_or(BridgeError::InvalidRequest("missing keyset_id".into()))?;
        let keyset_id = crate::nuts::Id::from_str(keyset_id_str)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        let mint = params_val["mint"]
            .as_str()
            .ok_or(BridgeError::InvalidRequest("missing mint".into()))?;

        if !self.host.mint_and_keyset_is_acceptable(mint, &keyset_id) {
            return Err(BridgeError::MintOrKeysetNotAcceptable);
        }

        // Parse channel policy for validations
        let config_json = self.host.get_channel_policy();
        let config: BridgeServerConfig =
            serde_json::from_str(&config_json).map_err(|e| BridgeError::Internal(e.to_string()))?;

        // 1. Check capacity
        if let Some(pricing) = config.pricing.get(unit) {
            if capacity < pricing.min_capacity {
                return Err(BridgeError::CapacityTooSmall {
                    capacity,
                    min_capacity: pricing.min_capacity,
                });
            }
            // 2. Check maximum_amount
            if let Some(max_allowed) = pricing.max_amount_per_output {
                if max_allowed > 0 && maximum_amount > max_allowed {
                    return Err(BridgeError::MaxAmountExceeded {
                        amount: maximum_amount,
                        max_allowed,
                    });
                }
            }
        } else {
            return Err(BridgeError::UnsupportedUnit(unit.to_string()));
        }

        // 3. Check locktime
        let now = self.host.now_seconds();
        let min_locktime = now + config.min_expiry_in_seconds;
        if locktime < min_locktime {
            return Err(BridgeError::LocktimeTooSoon {
                locktime,
                min_locktime,
                now,
            });
        }

        let alice_pubkey_hex = params_val["alice_pubkey"]
            .as_str()
            .ok_or(BridgeError::InvalidRequest("missing alice_pubkey".into()))?;
        let alice_pubkey = PublicKey::from_hex(alice_pubkey_hex)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;

        // Compute shared secret
        let shared_secret = super::compute_shared_secret(server_secret_key, &alice_pubkey);
        let shared_secret_hex = hex::encode(shared_secret);

        // Parse keyset info
        let keyset_info = super::parse_keyset_info_from_json(keyset_info_json)
            .map_err(BridgeError::InvalidRequest)?;

        // Verify channel_id matches
        let params = ChannelParameters::from_json_with_shared_secret(
            &params_json,
            keyset_info,
            shared_secret,
        )
        .map_err(|e| BridgeError::Internal(e.to_string()))?;

        if params.get_channel_id() != channel_id {
            return Err(BridgeError::ChannelIdMismatch);
        }

        // Verify DLEQ proofs
        let verification = verify_valid_channel(funding_proofs, &params);
        if !verification.valid {
            return Err(BridgeError::ValidationFailed(
                serde_json::to_string(&verification.errors).unwrap(),
            ));
        }

        // Save to host
        let funding_proofs_json = serde_json::to_string(funding_proofs).unwrap();
        self.host.save_funding(
            channel_id,
            &params_json,
            &funding_proofs_json,
            &shared_secret_hex,
            keyset_info_json,
        );

        Ok((
            params_json,
            funding_proofs_json,
            shared_secret_hex,
            keyset_info_json.to_string(),
        ))
    }

    fn verify_signature(
        &self,
        params_json: &str,
        funding_proofs_json: &str,
        shared_secret_hex: &str,
        keyset_info_json: &str,
        channel_id: &str,
        balance: u64,
        signature: &str,
    ) -> Result<(), String> {
        let shared_secret_bytes = hex::decode(shared_secret_hex).map_err(|e| e.to_string())?;
        let shared_secret: [u8; 32] = shared_secret_bytes
            .try_into()
            .map_err(|_| "invalid shared secret length")?;

        let keyset_info =
            super::parse_keyset_info_from_json(keyset_info_json).map_err(|e| e.to_string())?;

        let params = ChannelParameters::from_json_with_shared_secret(
            params_json,
            keyset_info,
            shared_secret,
        )
        .map_err(|e| e.to_string())?;

        let funding_proofs: Vec<Proof> =
            serde_json::from_str(funding_proofs_json).map_err(|e| e.to_string())?;

        let channel = EstablishedChannel::new(params, funding_proofs).map_err(|e| e.to_string())?;

        let sig: bitcoin::secp256k1::schnorr::Signature = signature
            .parse()
            .map_err(|e: <bitcoin::secp256k1::schnorr::Signature as FromStr>::Err| e.to_string())?;

        let balance_update = BalanceUpdateMessage {
            channel_id: channel_id.to_string(),
            amount: balance,
            signature: sig,
        };

        balance_update
            .verify_sender_signature(&channel)
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    fn error_with_extra(
        &self,
        msg: &str,
        status: BridgeStatus,
        reason: Option<String>,
        extra: BTreeMap<String, serde_json::Value>,
    ) -> PaymentResponse {
        let mut header = extra.clone();
        header.insert("error".into(), serde_json::json!(msg));

        let mut body = extra;
        body.insert("error".into(), serde_json::json!("Payment required"));
        body.insert(
            "reason".into(),
            serde_json::json!(match reason {
                Some(r) => format!("{} - {}", msg, r),
                None => msg.to_string(),
            }),
        );

        PaymentResponse {
            success: false,
            error: Some(msg.to_string()),
            status,
            header: Some(serde_json::json!(header)),
            body: Some(serde_json::json!(body)),
        }
    }

    /// Create the data needed to close a channel
    ///
    /// This validates the payment (signature, balance, etc.) and if valid,
    /// constructs the fully-signed swap request ready to submit to the mint.
    ///
    /// The host should:
    /// 1. Call this method to get the CloseData
    /// 2. Submit swap_request to the mint's /v1/swap endpoint
    /// 3. Use secrets_with_blinding to unblind the response
    ///
    /// Returns Err if validation fails (same errors as process_payment).
    pub fn create_close_data(
        &self,
        payment_json: &str,
        keyset_info_json: Option<&str>,
    ) -> Result<CloseData, BridgeError> {
        // 1. Parse payment request
        let payment: PaymentRequest = serde_json::from_str(payment_json)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;

        if payment.channel_id.is_empty() {
            return Err(BridgeError::InvalidRequest("missing channel_id".into()));
        }

        if payment.signature.is_empty() {
            return Err(BridgeError::InvalidRequest("missing signature".into()));
        }

        let channel_id = &payment.channel_id;

        // 2. Check if channel is closed
        if self.host.is_closed(channel_id) {
            return Err(BridgeError::ChannelClosed);
        }

        // 3. Get or validate funding
        let funding_and_params = match self.host.get_funding_and_params(channel_id) {
            Some(f) => f,
            None => {
                // Unknown channel - must provide params and funding_proofs
                let params_val = payment.params.as_ref().ok_or(BridgeError::UnknownChannel)?;
                let funding_proofs = payment
                    .funding_proofs
                    .as_ref()
                    .ok_or(BridgeError::UnknownChannel)?;
                let keyset_info_json =
                    keyset_info_json.ok_or(BridgeError::MintOrKeysetNotAcceptable)?;

                self.validate_and_save_new_channel(
                    channel_id,
                    params_val,
                    funding_proofs,
                    keyset_info_json,
                )?
            }
        };

        let (params_json, funding_proofs_json, shared_secret_hex, keyset_info_json) =
            funding_and_params;

        // 4. Parse everything we need
        let shared_secret_bytes =
            hex::decode(&shared_secret_hex).map_err(|e| BridgeError::Internal(e.to_string()))?;
        let shared_secret: [u8; 32] = shared_secret_bytes
            .try_into()
            .map_err(|_| BridgeError::Internal("invalid shared secret length".into()))?;

        let keyset_info = super::parse_keyset_info_from_json(&keyset_info_json)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        let params = ChannelParameters::from_json_with_shared_secret(
            &params_json,
            keyset_info,
            shared_secret,
        )
        .map_err(|e| BridgeError::Internal(e.to_string()))?;

        let funding_proofs: Vec<Proof> = serde_json::from_str(&funding_proofs_json)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        // 5. Check if the keyset is still active, if not switch to a new one
        let active_keyset_ids = self.host.get_active_keyset_ids(&params.mint, &params.unit);
        let output_keyset_info = if active_keyset_ids.contains(&params.keyset_info.keyset_id) {
            params.keyset_info.clone()
        } else {
            // Pick the first active keyset ID
            let new_keyset_id = active_keyset_ids.first().ok_or_else(|| {
                BridgeError::Internal(format!(
                    "No active keysets found for mint {} and unit {:?}",
                    params.mint, params.unit
                ))
            })?;

            let keyset_info_json = self
                .host
                .get_keyset_info(&params.mint, new_keyset_id)
                .ok_or_else(|| {
                    BridgeError::Internal(format!(
                        "Failed to get keyset info for {}",
                        new_keyset_id
                    ))
                })?;

            super::parse_keyset_info_from_json(&keyset_info_json)
                .map_err(|e| BridgeError::Internal(e.to_string()))?
        };

        let output_keyset_id = output_keyset_info.keyset_id;

        // 6. Check balance doesn't exceed capacity
        if payment.balance > params.capacity {
            return Err(BridgeError::BalanceExceedsCapacity {
                balance: payment.balance,
                capacity: params.capacity,
            });
        }

        // 7. Check balance equals amount_due
        let amount_due = self.host.get_amount_due(channel_id, None);
        if payment.balance != amount_due {
            return Err(BridgeError::BalanceMismatch {
                expected: amount_due,
                actual: payment.balance,
            });
        }

        // 8. Parse signature
        let sig: bitcoin::secp256k1::schnorr::Signature = payment.signature.parse().map_err(
            |e: <bitcoin::secp256k1::schnorr::Signature as FromStr>::Err| {
                BridgeError::InvalidSignature(e.to_string())
            },
        )?;

        // 8. Create commitment outputs and swap request
        let commitment_outputs = CommitmentOutputs::for_balance(payment.balance, &params)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        let mut swap_request = commitment_outputs
            .create_swap_request(funding_proofs.clone(), Some(output_keyset_id))
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        // 9. Create balance update message
        let balance_update = BalanceUpdateMessage {
            channel_id: channel_id.to_string(),
            amount: payment.balance,
            signature: sig.clone(),
        };

        // 10. Add Alice's signature to the swap request witness
        {
            use crate::nuts::{nut00::Witness, nut11::P2PKWitness};
            let first_input = swap_request
                .inputs_mut()
                .first_mut()
                .ok_or_else(|| BridgeError::Internal("swap request has no inputs".into()))?;

            match first_input.witness.as_mut() {
                Some(witness) => {
                    witness.add_signatures(vec![sig.to_string()]);
                }
                None => {
                    let mut p2pk_witness = Witness::P2PKWitness(P2PKWitness::default());
                    p2pk_witness.add_signatures(vec![sig.to_string()]);
                    first_input.witness = Some(p2pk_witness);
                }
            }
        }

        // 11. Create channel and receiver, verify + add Charlie's signature
        let channel = EstablishedChannel::new(params.clone(), funding_proofs)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        let server_secret_key = self
            .server_secret_key
            .as_ref()
            .ok_or(BridgeError::ServerMisconfigured("no secret key".into()))?;

        let receiver = SpilmanChannelReceiver::new(server_secret_key.clone(), channel);

        let signed_swap_request = receiver
            .add_second_signature(&balance_update, swap_request)
            .map_err(|e| BridgeError::InvalidSignature(e.to_string()))?;

        // 12. Get expected total (value after stage 1 fees) using the OUTPUT keyset
        let expected_total = params
            .get_value_after_stage1_with_keyset(&output_keyset_info)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        // 13. Collect secrets with blinding factors for unblinding
        let receiver_secrets = commitment_outputs
            .receiver_outputs
            .get_secrets_with_blinding()
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let sender_secrets = commitment_outputs
            .sender_outputs
            .get_secrets_with_blinding()
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        // Combine and tag with is_receiver, then sort by amount to match output order
        let mut secrets_with_blinding: Vec<(DeterministicSecretWithBlinding, bool)> =
            receiver_secrets
                .into_iter()
                .map(|s| (s, true))
                .chain(sender_secrets.into_iter().map(|s| (s, false)))
                .collect();
        secrets_with_blinding.sort_by_key(|(s, _)| s.amount);

        Ok(CloseData {
            swap_request: signed_swap_request,
            expected_total,
            secrets_with_blinding,
            output_keyset_info,
        })
    }

    /// Create close data for a unilateral (server-initiated) channel close
    ///
    /// This retrieves the largest balance and signature from the host and
    /// constructs a fully-signed swap request. Use this when the server
    /// wants to close a channel without waiting for the client.
    ///
    /// The host must have stored at least one valid payment (via record_payment)
    /// for this to succeed.
    ///
    /// Returns:
    /// - CloseData with fully-signed swap request ready for the mint
    /// - Err if no payment proof is stored, channel is closed, or validation fails
    pub fn create_unilateral_close_data(&self, channel_id: &str) -> Result<CloseData, BridgeError> {
        // 1. Check if channel is closed
        if self.host.is_closed(channel_id) {
            return Err(BridgeError::ChannelClosed);
        }

        // 2. Get the balance and signature from host
        let (balance, signature) = self
            .host
            .get_balance_and_signature_for_unilateral_exit(channel_id)
            .ok_or_else(|| {
                BridgeError::InvalidRequest("no payment proof stored for channel".into())
            })?;

        // 3. Get funding data
        let (params_json, funding_proofs_json, shared_secret_hex, keyset_info_json) = self
            .host
            .get_funding_and_params(channel_id)
            .ok_or(BridgeError::UnknownChannel)?;

        // 4. Parse everything we need
        let shared_secret_bytes =
            hex::decode(&shared_secret_hex).map_err(|e| BridgeError::Internal(e.to_string()))?;
        let shared_secret: [u8; 32] = shared_secret_bytes
            .try_into()
            .map_err(|_| BridgeError::Internal("invalid shared secret length".into()))?;

        let keyset_info = super::parse_keyset_info_from_json(&keyset_info_json)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        let params = ChannelParameters::from_json_with_shared_secret(
            &params_json,
            keyset_info,
            shared_secret,
        )
        .map_err(|e| BridgeError::Internal(e.to_string()))?;

        let funding_proofs: Vec<Proof> = serde_json::from_str(&funding_proofs_json)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        // 5. Check if the keyset is still active, if not switch to a new one
        let active_keyset_ids = self.host.get_active_keyset_ids(&params.mint, &params.unit);
        let output_keyset_info = if active_keyset_ids.contains(&params.keyset_info.keyset_id) {
            params.keyset_info.clone()
        } else {
            // Pick the first active keyset ID
            let new_keyset_id = active_keyset_ids.first().ok_or_else(|| {
                BridgeError::Internal(format!(
                    "No active keysets found for mint {} and unit {:?}",
                    params.mint, params.unit
                ))
            })?;

            let keyset_info_json = self
                .host
                .get_keyset_info(&params.mint, new_keyset_id)
                .ok_or_else(|| {
                    BridgeError::Internal(format!(
                        "Failed to get keyset info for {}",
                        new_keyset_id
                    ))
                })?;

            super::parse_keyset_info_from_json(&keyset_info_json)
                .map_err(|e| BridgeError::Internal(e.to_string()))?
        };

        let output_keyset_id = output_keyset_info.keyset_id;

        // 6. Check balance doesn't exceed capacity
        if balance > params.capacity {
            return Err(BridgeError::BalanceExceedsCapacity {
                balance,
                capacity: params.capacity,
            });
        }

        // 7. Parse signature
        let sig: bitcoin::secp256k1::schnorr::Signature = signature.parse().map_err(
            |e: <bitcoin::secp256k1::schnorr::Signature as FromStr>::Err| {
                BridgeError::InvalidSignature(e.to_string())
            },
        )?;

        // 8. Create commitment outputs and swap request
        let commitment_outputs = CommitmentOutputs::for_balance(balance, &params)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        let mut swap_request = commitment_outputs
            .create_swap_request(funding_proofs.clone(), Some(output_keyset_id))
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        // 9. Create balance update message
        let balance_update = BalanceUpdateMessage {
            channel_id: channel_id.to_string(),
            amount: balance,
            signature: sig.clone(),
        };

        // 10. Add Alice's signature to the swap request witness
        {
            use crate::nuts::{nut00::Witness, nut11::P2PKWitness};
            let first_input = swap_request
                .inputs_mut()
                .first_mut()
                .ok_or_else(|| BridgeError::Internal("swap request has no inputs".into()))?;

            match first_input.witness.as_mut() {
                Some(witness) => {
                    witness.add_signatures(vec![sig.to_string()]);
                }
                None => {
                    let mut p2pk_witness = Witness::P2PKWitness(P2PKWitness::default());
                    p2pk_witness.add_signatures(vec![sig.to_string()]);
                    first_input.witness = Some(p2pk_witness);
                }
            }
        }

        // 11. Create channel and receiver, verify + add Charlie's signature
        let channel = EstablishedChannel::new(params.clone(), funding_proofs)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        let server_secret_key = self
            .server_secret_key
            .as_ref()
            .ok_or(BridgeError::ServerMisconfigured("no secret key".into()))?;

        let receiver = SpilmanChannelReceiver::new(server_secret_key.clone(), channel);

        let signed_swap_request = receiver
            .add_second_signature(&balance_update, swap_request)
            .map_err(|e| BridgeError::InvalidSignature(e.to_string()))?;

        // 12. Get expected total (value after stage 1 fees) using the OUTPUT keyset
        let expected_total = params
            .get_value_after_stage1_with_keyset(&output_keyset_info)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        // 13. Collect secrets with blinding factors for unblinding
        let receiver_secrets = commitment_outputs
            .receiver_outputs
            .get_secrets_with_blinding()
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let sender_secrets = commitment_outputs
            .sender_outputs
            .get_secrets_with_blinding()
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        // Combine and tag with is_receiver, then sort by amount to match output order
        let mut secrets_with_blinding: Vec<(DeterministicSecretWithBlinding, bool)> =
            receiver_secrets
                .into_iter()
                .map(|s| (s, true))
                .chain(sender_secrets.into_iter().map(|s| (s, false)))
                .collect();
        secrets_with_blinding.sort_by_key(|(s, _)| s.amount);

        Ok(CloseData {
            swap_request: signed_swap_request,
            expected_total,
            secrets_with_blinding,
            output_keyset_info,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nuts::{Id, PublicKey};

    struct MockHost {
        receiver_acceptable: bool,
        mint_acceptable: bool,
    }

    impl SpilmanHost for MockHost {
        fn receiver_key_is_acceptable(&self, _receiver_pubkey: &PublicKey) -> bool {
            self.receiver_acceptable
        }

        fn mint_and_keyset_is_acceptable(&self, _mint: &str, _keyset_id: &Id) -> bool {
            self.mint_acceptable
        }

        fn get_funding_and_params(
            &self,
            _channel_id: &str,
        ) -> Option<(String, String, String, String)> {
            None
        }

        fn save_funding(
            &self,
            _channel_id: &str,
            _params_json: &str,
            _funding_proofs_json: &str,
            _shared_secret_hex: &str,
            _keyset_info_json: &str,
        ) {
        }

        fn get_amount_due(&self, _channel_id: &str, _context_json: Option<&str>) -> u64 {
            0
        }

        fn record_payment(
            &self,
            _channel_id: &str,
            _balance: u64,
            _signature: &str,
            _context_json: &str,
        ) {
        }

        fn is_closed(&self, _channel_id: &str) -> bool {
            false
        }

        fn get_channel_policy(&self) -> String {
            serde_json::json!({
                "min_expiry_in_seconds": 3600,
                "pricing": {
                    "sat": {
                        "minCapacity": 100
                    }
                }
            })
            .to_string()
        }

        fn now_seconds(&self) -> u64 {
            1700000000
        }

        fn get_balance_and_signature_for_unilateral_exit(
            &self,
            _channel_id: &str,
        ) -> Option<(u64, String)> {
            None
        }

        fn get_active_keyset_ids(&self, _mint: &str, _unit: &CurrencyUnit) -> Vec<Id> {
            Vec::new()
        }

        fn get_keyset_info(&self, _mint: &str, _keyset_id: &Id) -> Option<String> {
            None
        }
    }

    #[test]
    fn test_bridge_rejects_unacceptable_receiver() {
        let host = MockHost {
            receiver_acceptable: false,
            mint_acceptable: true,
        };
        let bridge = SpilmanBridge::new(host, Some(SecretKey::generate()));

        let params = serde_json::json!({
            "alice_pubkey": SecretKey::generate().public_key().to_hex(),
            "charlie_pubkey": SecretKey::generate().public_key().to_hex(),
            "mint": "https://mint.host",
            "unit": "sat",
            "capacity": 1000,
            "maximum_amount": 64,
            "locktime": 1700000000 + 7200,
            "setup_timestamp": 1700000000,
            "sender_nonce": "nonce",
            "keyset_id": "00aabbccddeeff00",
            "input_fee_ppk": 0
        });

        let payment = serde_json::json!({
            "channel_id": "id",
            "balance": 100,
            "signature": "sig",
            "params": params,
            "funding_proofs": []
        });

        let keyset_info = serde_json::json!({
            "keysetId": "00aabbccddeeff00",
            "unit": "sat",
            "inputFeePpk": 0,
            "keys": {}
        });

        let response =
            bridge.process_payment(&payment.to_string(), "{}", Some(&keyset_info.to_string()));

        assert!(!response.success);
        assert!(response
            .error
            .unwrap()
            .contains("receiver key not acceptable"));
    }

    #[test]
    fn test_bridge_rejects_unacceptable_mint() {
        let host = MockHost {
            receiver_acceptable: true,
            mint_acceptable: false,
        };
        let bridge = SpilmanBridge::new(host, Some(SecretKey::generate()));

        let params = serde_json::json!({
            "alice_pubkey": SecretKey::generate().public_key().to_hex(),
            "charlie_pubkey": SecretKey::generate().public_key().to_hex(),
            "mint": "https://mint.host",
            "unit": "sat",
            "capacity": 1000,
            "maximum_amount": 64,
            "locktime": 1700000000 + 7200,
            "setup_timestamp": 1700000000,
            "sender_nonce": "nonce",
            "keyset_id": "00aabbccddeeff00",
            "input_fee_ppk": 0
        });

        let payment = serde_json::json!({
            "channel_id": "id",
            "balance": 100,
            "signature": "sig",
            "params": params,
            "funding_proofs": []
        });

        let keyset_info = serde_json::json!({
            "keysetId": "00aabbccddeeff00",
            "unit": "sat",
            "inputFeePpk": 0,
            "keys": {}
        });

        let response =
            bridge.process_payment(&payment.to_string(), "{}", Some(&keyset_info.to_string()));

        assert!(!response.success);
        assert!(response
            .error
            .unwrap()
            .contains("mint or keyset not acceptable"));
    }

    struct FlexibleMockHost {
        pub active_keyset_ids: Vec<Id>,
        pub keyset_infos: std::collections::HashMap<Id, String>,
        pub funding_data: std::collections::HashMap<String, (String, String, String, String)>,
        pub amount_due: u64,
    }

    impl SpilmanHost for FlexibleMockHost {
        fn receiver_key_is_acceptable(&self, _receiver_pubkey: &PublicKey) -> bool {
            true
        }
        fn mint_and_keyset_is_acceptable(&self, _mint: &str, _keyset_id: &Id) -> bool {
            true
        }
        fn get_funding_and_params(
            &self,
            channel_id: &str,
        ) -> Option<(String, String, String, String)> {
            self.funding_data.get(channel_id).cloned()
        }
        fn save_funding(
            &self,
            _channel_id: &str,
            _params_json: &str,
            _funding_proofs_json: &str,
            _shared_secret_hex: &str,
            _keyset_info_json: &str,
        ) {
        }
        fn get_amount_due(&self, _channel_id: &str, _context_json: Option<&str>) -> u64 {
            self.amount_due
        }
        fn record_payment(
            &self,
            _channel_id: &str,
            _balance: u64,
            _signature: &str,
            _context_json: &str,
        ) {
        }
        fn is_closed(&self, _channel_id: &str) -> bool {
            false
        }
        fn get_channel_policy(&self) -> String {
            serde_json::json!({
                "min_expiry_in_seconds": 3600,
                "pricing": {
                    "sat": {
                        "minCapacity": 100
                    }
                }
            })
            .to_string()
        }
        fn now_seconds(&self) -> u64 {
            1700000000
        }
        fn get_balance_and_signature_for_unilateral_exit(
            &self,
            _channel_id: &str,
        ) -> Option<(u64, String)> {
            None
        }
        fn get_active_keyset_ids(&self, _mint: &str, _unit: &CurrencyUnit) -> Vec<Id> {
            self.active_keyset_ids.clone()
        }
        fn get_keyset_info(&self, _mint: &str, keyset_id: &Id) -> Option<String> {
            self.keyset_infos.get(keyset_id).cloned()
        }
    }

    #[test]
    fn test_create_close_data_with_keyset_rotation() {
        use crate::nuts::Proof;
        use crate::secret::Secret;
        use crate::spilman::params::mock_keyset_info;
        use crate::spilman::{
            compute_shared_secret, ChannelParameters, EstablishedChannel, SpilmanChannelSender,
        };

        let alice_sk = SecretKey::generate();
        let charlie_sk = SecretKey::generate();
        let shared_secret = compute_shared_secret(&alice_sk, &charlie_sk.public_key());

        // Create Keyset A (the one the channel is funded with)
        let keyset_a = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 0);
        let keyset_a_id = keyset_a.keyset_id;

        // Create Keyset B (the new active one with different fees)
        let mut keyset_b = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 500); // 0.5 sat per output fee
        let keyset_b_id = Id::from_str("000000000000000b").unwrap();
        keyset_b.keyset_id = keyset_b_id;

        // Setup channel params with Keyset A
        let params_struct = ChannelParameters {
            alice_pubkey: alice_sk.public_key(),
            charlie_pubkey: charlie_sk.public_key(),
            mint: "https://mint.host".to_string(),
            unit: CurrencyUnit::Sat,
            capacity: 1000,
            maximum_amount_for_one_output: 64,
            setup_timestamp: 1700000000,
            locktime: 1700003600,
            sender_nonce: "nonce".to_string(),
            keyset_info: keyset_a.clone(),
            shared_secret,
        };
        let channel_id = params_struct.get_channel_id();
        let balance = 100;

        // Dummy funding proofs (all for Keyset A)
        let proofs = vec![Proof {
            amount: 1000.into(),
            secret: Secret::new("funding".to_string()),
            c: PublicKey::from_str(
                "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
            )
            .unwrap(),
            keyset_id: keyset_a_id,
            dleq: None,
            witness: None,
        }];

        let host = FlexibleMockHost {
            active_keyset_ids: vec![keyset_b_id], // ONLY Keyset B is active
            keyset_infos: vec![
                (keyset_a_id, serde_json::to_string(&keyset_a).unwrap()),
                (keyset_b_id, serde_json::to_string(&keyset_b).unwrap()),
            ]
            .into_iter()
            .collect(),
            funding_data: vec![(
                channel_id.clone(),
                (
                    params_struct.get_channel_id_params_json(),
                    serde_json::to_string(&proofs).unwrap(),
                    hex::encode(shared_secret),
                    serde_json::to_string(&keyset_a).unwrap(),
                ),
            )]
            .into_iter()
            .collect(),
            amount_due: balance,
        };

        let bridge = SpilmanBridge::new(host, Some(charlie_sk.clone()));

        // Create a signature for balance update (100 sats to Charlie)
        let channel = EstablishedChannel::new(params_struct.clone(), proofs.clone()).unwrap();
        let sender = SpilmanChannelSender::new(alice_sk, channel);
        let (balance_update, _) = sender.create_signed_balance_update(balance).unwrap();

        let payment_json = serde_json::json!({
            "channel_id": channel_id,
            "balance": balance,
            "signature": balance_update.signature.to_string(),
        })
        .to_string();

        // EXECUTE: Create close data
        // Bridge should see Keyset A is inactive and switch to Keyset B
        let close_data = bridge.create_close_data(&payment_json, None).unwrap();

        // VERIFY: Output keyset is Keyset B
        assert_eq!(close_data.output_keyset_info.keyset_id, keyset_b_id);

        // VERIFY: Swap request outputs use Keyset B ID
        for output in close_data.swap_request.outputs() {
            assert_eq!(output.keyset_id, keyset_b_id);
        }

        // VERIFY: Expected total uses Keyset B fees
        let expected_total_b = params_struct
            .get_value_after_stage1_with_keyset(&keyset_b)
            .unwrap();
        assert_eq!(close_data.expected_total, expected_total_b);
        assert!(close_data.expected_total < 1000);
    }
}
