//! Spilman Protocol Bridge
//!
//! This module provides a high-level bridge for implementing Spilman payment channels
//! in any service provider. It handles the core protocol logic, validation, and
//! signature verification, while delegating storage and pricing to a host hook.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};

use super::{
    verify_valid_channel, BalanceUpdateMessage, ChannelParameters, CommitmentOutputs,
    DeterministicSecretWithBlinding, EstablishedChannel, KeysetInfo,
};
use crate::nuts::nut10::SpendingConditionVerification;
use crate::nuts::{BlindSignature, CurrencyUnit, Id, Proof, PublicKey, SwapRequest};
use crate::util::hex;
use async_trait::async_trait;
use std::str::FromStr;

/// Funding data for a channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelFunding {
    pub params_json: String,
    pub funding_proofs_json: String,
    pub channel_secret_hex: String,
    pub keyset_info_json: String,
}

/// A payment proof (signed balance update)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentProof {
    pub balance: u64,
    pub signature: String,
}

/// Channel lifecycle states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelState {
    /// Channel is open and accepting payments
    Open,
    /// Channel is closing (swap pending, no more payments accepted)
    Closing,
    /// Channel is closed (swap completed, proofs stored)
    Closed,
}

/// Data stored when a channel enters CLOSING state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosingData {
    /// The channel's locktime
    pub locktime: u64,
    /// The balance at close
    pub balance: u64,
    /// The client's Schnorr signature authorizing this balance
    pub signature: String,
}

/// Host hooks for the Spilman bridge
///
/// Implement this trait to provide storage and pricing logic for your service.
/// The generic type `C` allows for a custom request context used in pricing.
pub trait SpilmanHost<C = String> {
    /// Check if the receiver pubkey in the channel params is acceptable
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool;

    /// Check if the mint and keyset are acceptable
    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &crate::nuts::Id) -> bool;

    /// Get cached funding data for a channel
    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding>;

    /// Save funding data for a channel, including the initial payment proof
    fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
    );

    /// Get the current amount due for a channel
    fn get_amount_due(&self, channel_id: &str, context: Option<&C>) -> u64;

    /// Record a successful payment and update usage
    fn record_payment(&self, channel_id: &str, payment: PaymentProof, context: &C);

    /// Get the current state of a channel.
    fn get_channel_state(&self, channel_id: &str) -> ChannelState;

    /// Mark a channel as closing (pre-swap state).
    fn mark_channel_closing(
        &self,
        channel_id: &str,
        locktime: u64,
        payment: PaymentProof,
    ) -> Result<(), String>;

    /// Get the stored closing data for a channel in CLOSING state.
    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData>;

    /// Get channel policy for a given unit: funding-time validation thresholds.
    /// Returns `None` if the unit is not supported.
    fn get_channel_policy(&self, unit: &str) -> Option<ChannelPolicy>;

    /// Get the current time in seconds
    fn now_seconds(&self) -> u64;

    /// Get the balance and signature for a unilateral exit
    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        channel_id: &str,
    ) -> Option<PaymentProof>;

    /// Get active keyset IDs for a mint and unit
    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id>;

    /// Get full KeysetInfo JSON for a specific keyset
    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String>;

    /// Mark a channel as closed and persist the final state
    #[allow(clippy::too_many_arguments)]
    fn mark_channel_closed(
        &self,
        channel_id: &str,
        locktime: u64,
        balance: u64,
        receiver_proofs_json: &str,
        sender_proofs_json: &str,
        receiver_sum: u64,
        sender_sum: u64,
    ) -> Result<(), String>;

    /// Compute the ECDH-derived channel secret.
    fn compute_channel_secret(
        &self,
        charlie_pubkey_hex: &str,
        alice_pubkey_hex: &str,
    ) -> Result<String, String>;

    /// Sign a message with the tweaked (P2BK-blinded) server key.
    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String>;
}

/// Sync networking hooks for the Spilman bridge
pub trait SpilmanNetworking {
    /// Call the mint's /v1/swap endpoint
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String>;

    /// Refresh the keyset cache for a mint
    fn refresh_all_keysets(&self, mint: &str) -> Result<(), String>;
}

/// Async networking hooks for the Spilman bridge
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait SpilmanAsyncNetworking {
    /// Call the mint's /v1/swap endpoint
    async fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String>;

    /// Refresh the keyset cache for a mint
    async fn refresh_all_keysets(&self, mint: &str) -> Result<(), String>;
}

/// Bridge for processing Spilman payments
pub struct SpilmanBridge<H: SpilmanHost<C>, C = String> {
    host: H,
    _phantom: std::marker::PhantomData<C>,
}

#[derive(Debug, Deserialize)]
pub struct PaymentRequest {
    pub channel_id: String,
    pub balance: u64,
    pub signature: String,
    pub params: Option<serde_json::Value>,
    pub funding_proofs: Option<Vec<Proof>>,
}

/// Result of a successful payment
#[derive(Debug, Clone, Serialize)]
pub struct PaymentSuccess {
    pub channel_id: String,
    pub balance: u64,
    pub amount_due: u64,
    pub capacity: u64,
}

/// Data needed to close a channel
#[derive(Debug)]
pub struct CloseData {
    pub swap_request: SwapRequest,
    pub expected_total: u64,
    pub secrets_with_blinding: Vec<(DeterministicSecretWithBlinding, bool)>,
    pub output_keyset_info: KeysetInfo,
}

impl CloseData {
    pub fn to_json_value(self) -> serde_json::Value {
        let swap_request_json =
            serde_json::to_value(&self.swap_request).unwrap_or(serde_json::Value::Null);

        let secrets_with_blinding: Vec<serde_json::Value> = self
            .secrets_with_blinding
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

        serde_json::json!({
            "success": true,
            "swap_request": swap_request_json,
            "expected_total": self.expected_total,
            "secrets_with_blinding": secrets_with_blinding,
            "output_keyset_info": serde_json::to_value(&self.output_keyset_info).unwrap_or(serde_json::Value::Null)
        })
    }
}

/// Result of unblinding and verifying stage 1 swap response
#[derive(Debug)]
pub struct UnblindResult {
    pub receiver_proofs: Vec<Proof>,
    pub sender_proofs: Vec<Proof>,
    pub receiver_sum: u64,
    pub sender_sum: u64,
}

/// Everything needed to execute a close operation after sync validation.
#[derive(Debug)]
pub struct PreparedClose {
    pub channel_id: String,
    pub balance: u64,
    pub mint_url: String,
    pub swap_request: serde_json::Value,
    pub secrets_with_blinding: serde_json::Value,
    pub output_keyset_info: serde_json::Value,
    pub params_json: String,
    pub keyset_info_json: String,
    pub channel_secret: String,
}

/// HTTP-friendly error for close preparation.
#[derive(Debug, Clone, Serialize)]
pub struct ClosePreparationError {
    pub error: String,
    pub reason: String,
    pub status: u16,
    #[serde(flatten)]
    pub extra: Option<serde_json::Map<String, serde_json::Value>>,
}

impl ClosePreparationError {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn bad_request(reason: impl Into<String>) -> Self {
        Self { error: "Bad request".into(), reason: reason.into(), status: 400, extra: None }
    }

    pub fn payment_required(reason: impl Into<String>) -> Self {
        Self { error: "Payment required".into(), reason: reason.into(), status: 402, extra: None }
    }

    pub fn not_found(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self { error: reason.clone(), reason, status: 404, extra: None }
    }

    pub fn internal(reason: impl Into<String>) -> Self {
        Self { error: "Internal error".into(), reason: reason.into(), status: 500, extra: None }
    }

    pub fn conflict(reason: impl Into<String>) -> Self {
        Self { error: "Channel closing".into(), reason: reason.into(), status: 409, extra: None }
    }

    pub fn gone(reason: impl Into<String>) -> Self {
        Self { error: "Channel closed".into(), reason: reason.into(), status: 410, extra: None }
    }

    pub fn with_extra(mut self, extra: serde_json::Map<String, serde_json::Value>) -> Self {
        self.extra = Some(extra);
        self
    }

    pub fn from_bridge_error(err: BridgeError) -> Self {
        let reason = err.to_string();
        match &err {
            BridgeError::ChannelClosed => Self::gone(reason),
            BridgeError::ChannelClosing => Self::conflict(reason),
            BridgeError::UnknownChannel => Self::not_found(reason),
            BridgeError::InvalidRequest(msg) if msg.contains("no payment proof") => Self::bad_request(reason),
            BridgeError::Internal(_) | BridgeError::ServerMisconfigured(_) => Self::internal(reason),
            BridgeError::BalanceMismatch { expected, actual } => {
                let mut extra = serde_json::Map::new();
                extra.insert("expected".into(), serde_json::json!(expected));
                extra.insert("actual".into(), serde_json::json!(actual));
                Self::payment_required(reason).with_extra(extra)
            }
            _ => Self::payment_required(reason),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymentValidationResult {
    pub channel_id: String,
    pub balance: u64,
    pub amount_due: u64,
    pub capacity: u64,
    pub sender_signature: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FundChannelResult {
    pub channel_id: String,
    pub capacity: u64,
    pub already_known: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloseSuccess {
    pub channel_id: String,
    pub total_value: u64,
    pub receiver_sum: u64,
    pub sender_sum: u64,
    pub sender_proofs: String,
    pub already_closed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum CloseError {
    #[serde(rename = "validation_failed")]
    ValidationFailed { reason: String, status: u16, #[serde(skip_serializing_if = "Option::is_none")] expected_balance: Option<u64>, #[serde(skip_serializing_if = "Option::is_none")] actual_balance: Option<u64> },
    #[serde(rename = "unknown_channel")]
    UnknownChannel { status: u16 },
    #[serde(rename = "already_closed")]
    AlreadyClosed { closed_balance: u64, requested_balance: u64, status: u16 },
    #[serde(rename = "mint_rejected")]
    MintRejected { mint_error: serde_json::Value, status: u16 },
    #[serde(rename = "mint_rejected_after_retry")]
    MintRejectedAfterRetry { original_error: serde_json::Value, retry_error: serde_json::Value, status: u16 },
    #[serde(rename = "unblind_failed")]
    UnblindFailed { reason: String, status: u16 },
    #[serde(rename = "storage_failed")]
    StorageFailed { reason: String, status: u16 },
}

impl CloseError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::ValidationFailed { status, .. } | Self::UnknownChannel { status } | Self::AlreadyClosed { status, .. } | Self::MintRejected { status, .. } | Self::MintRejectedAfterRetry { status, .. } | Self::UnblindFailed { status, .. } | Self::StorageFailed { status, .. } => *status,
        }
    }

    pub fn from_preparation_error(err: ClosePreparationError) -> Self {
        let (expected_balance, actual_balance) = if let Some(extra) = &err.extra {
            (extra.get("expected").and_then(|v| v.as_u64()), extra.get("actual").and_then(|v| v.as_u64()))
        } else { (None, None) };
        Self::ValidationFailed { reason: err.reason, status: err.status, expected_balance, actual_balance }
    }

    pub fn unknown_channel() -> Self { Self::UnknownChannel { status: 404 } }
    pub fn mint_rejected(mint_error: serde_json::Value) -> Self { Self::MintRejected { mint_error, status: 502 } }
    pub fn mint_rejected_after_retry(original_error: serde_json::Value, retry_error: serde_json::Value) -> Self {
        Self::MintRejectedAfterRetry { original_error, retry_error, status: 502 }
    }
    pub fn unblind_failed(reason: impl Into<String>) -> Self { Self::UnblindFailed { reason: reason.into(), status: 500 } }
    pub fn storage_failed(reason: impl Into<String>) -> Self { Self::StorageFailed { reason: reason.into(), status: 500 } }
}

impl std::fmt::Display for CloseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ValidationFailed { reason, .. } => write!(f, "validation failed: {}", reason),
            Self::UnknownChannel { .. } => write!(f, "unknown channel"),
            Self::AlreadyClosed { closed_balance, requested_balance, .. } => write!(f, "channel already closed with balance {} (requested {})", closed_balance, requested_balance),
            Self::MintRejected { mint_error, .. } => write!(f, "mint rejected swap: {}", mint_error),
            Self::MintRejectedAfterRetry { original_error, retry_error, .. } => write!(f, "mint rejected swap after retry: original={}, retry={}", original_error, retry_error),
            Self::UnblindFailed { reason, .. } => write!(f, "unblind failed: {}", reason),
            Self::StorageFailed { reason, .. } => write!(f, "storage failed: {}", reason),
        }
    }
}

impl std::error::Error for CloseError {}

/// Funding-time validation thresholds for a given unit, returned by
/// [`SpilmanHost::get_channel_policy`].
#[derive(Debug, Clone)]
pub struct ChannelPolicy {
    /// Minimum seconds between now and the channel locktime.
    pub min_expiry_in_seconds: u64,
    /// Minimum channel capacity (in the unit's base denomination).
    pub min_capacity: u64,
    /// Optional cap on the largest single proof denomination.
    pub max_amount_per_output: Option<u64>,
}

#[derive(Debug)]
pub enum BridgeError {
    InvalidRequest(String), ChannelClosed, ChannelClosing, ServerMisconfigured(String),
    CapacityTooSmall { capacity: u64, min_capacity: u64 },
    LocktimeTooSoon { locktime: u64, min_locktime: u64, now: u64 },
    MaxAmountExceeded { amount: u64, max_allowed: u64 },
    BalanceExceedsCapacity { balance: u64, capacity: u64 },
    UnsupportedUnit(String), ChannelIdMismatch, ValidationFailed(String), UnknownChannel,
    InvalidSignature(String), InsufficientBalance { balance: u64, amount_due: u64 },
    BalanceMismatch { expected: u64, actual: u64 }, Internal(String),
    ReceiverKeyNotAcceptable, MintOrKeysetNotAcceptable,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(s) => write!(f, "{}", s),
            Self::ChannelClosed => write!(f, "channel closed"),
            Self::ChannelClosing => write!(f, "channel closing, swap pending"),
            Self::ServerMisconfigured(s) => write!(f, "server misconfigured: {}", s),
            Self::CapacityTooSmall { capacity, min_capacity } => write!(f, "capacity too small: {} < {}", capacity, min_capacity),
            Self::LocktimeTooSoon { locktime, min_locktime, now } => write!(f, "locktime too soon: {} < {} ({}s remaining)", locktime, min_locktime, locktime.saturating_sub(*now)),
            Self::MaxAmountExceeded { amount, max_allowed } => write!(f, "max_amount_per_output exceeded: {} > {}", amount, max_allowed),
            Self::BalanceExceedsCapacity { balance, capacity } => { write!(f, "balance exceeds capacity: {} > {}", balance, capacity) }
            Self::UnsupportedUnit(u) => write!(f, "unsupported unit: {}", u),
            Self::ChannelIdMismatch => write!(f, "channel_id mismatch"),
            Self::ValidationFailed(s) => write!(f, "channel validation failed: {}", s),
            Self::UnknownChannel => write!(f, "unknown channel"),
            Self::InvalidSignature(s) => write!(f, "invalid signature: {}", s),
            Self::InsufficientBalance { balance, amount_due } => write!(f, "insufficient balance: {} < {}", balance, amount_due),
            Self::BalanceMismatch { expected, actual } => { write!(f, "balance mismatch: expected {}, got {}", expected, actual) }
            Self::Internal(s) => write!(f, "internal error: {}", s),
            Self::ReceiverKeyNotAcceptable => write!(f, "receiver key not acceptable"),
            Self::MintOrKeysetNotAcceptable => write!(f, "mint or keyset not acceptable"),
        }
    }
}

pub fn unblind_and_verify_stage1_response(
    blind_signatures: Vec<BlindSignature>,
    secrets_with_blinding: Vec<(DeterministicSecretWithBlinding, bool)>,
    params: &ChannelParameters,
    output_keyset_info: &KeysetInfo,
    balance: u64,
) -> Result<UnblindResult, BridgeError> {
    if blind_signatures.len() != secrets_with_blinding.len() {
        return Err(BridgeError::Internal("Length mismatch between signatures and secrets".into()));
    }
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

    let proofs = crate::dhke::construct_proofs(blind_signatures, blinding_factors, secrets, &output_keyset_info.active_keys)
        .map_err(|e| BridgeError::Internal(format!("Failed to construct proofs: {}", e)))?;

    for (i, proof) in proofs.iter().enumerate() {
        let mint_pubkey = output_keyset_info.active_keys.amount_key(proof.amount).ok_or_else(|| BridgeError::Internal("Missing mint key".into()))?;
        proof.verify_dleq(mint_pubkey).map_err(|e| BridgeError::ValidationFailed(format!("DLEQ failed for proof {}: {}", i, e)))?;
    }

    let mut receiver_proofs = Vec::new();
    let mut sender_proofs = Vec::new();
    let mut receiver_sum = 0;
    let mut sender_sum = 0;

    for ((proof, is_receiver), (amount, index)) in proofs.into_iter().zip(is_receiver_flags).zip(amount_index_pairs) {
        if is_receiver {
            let expected_pubkey = params.get_receiver_blinded_pubkey_for_stage2_output(amount, index).map_err(|e| BridgeError::Internal(e.to_string()))?;
            let secret_json: serde_json::Value = serde_json::from_str(&proof.secret.to_string()).map_err(|e| BridgeError::Internal(e.to_string()))?;
            if secret_json.get(0).and_then(|v| v.as_str()) != Some("P2PK") || secret_json.get(1).and_then(|v| v.get("data")).and_then(|v| v.as_str()) != Some(&expected_pubkey.to_hex()) {
                return Err(BridgeError::ValidationFailed("Receiver proof locked to wrong pubkey".into()));
            }
            receiver_sum += u64::from(proof.amount);
            receiver_proofs.push(proof);
        } else {
            sender_sum += u64::from(proof.amount);
            sender_proofs.push(proof);
        }
    }

    let expected_nominal = output_keyset_info.inverse_deterministic_value_after_fees(balance, params.maximum_amount_for_one_output).map_err(|e| BridgeError::Internal(e.to_string()))?.nominal_value;
    if receiver_sum != expected_nominal {
        return Err(BridgeError::ValidationFailed(format!("Receiver nominal mismatch: expected {}, got {}", expected_nominal, receiver_sum)));
    }

    Ok(UnblindResult { receiver_proofs, sender_proofs, receiver_sum, sender_sum })
}

pub fn unblind_and_verify_dleq(
    blind_signatures_json: &str,
    secrets_with_blinding_json: &str,
    params_json: &str,
    keyset_info_json: &str,
    channel_secret_hex: &str,
    balance: u64,
    output_keyset_info_json: Option<&str>,
) -> Result<String, String> {
    use super::parse_keyset_info_from_json;
    use crate::nuts::SecretKey;
    use crate::secret::Secret;

    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;
    let output_keyset_info = match output_keyset_info_json {
        Some(json) => parse_keyset_info_from_json(json)?,
        None => keyset_info.clone(),
    };

    let channel_secret_bytes = hex::decode(channel_secret_hex).map_err(|e| e.to_string())?;
    let channel_secret: [u8; 32] = channel_secret_bytes.try_into().map_err(|_| "Invalid shared secret length".to_string())?;

    let params = ChannelParameters::from_json_with_channel_secret(params_json, keyset_info, channel_secret).map_err(|e| e.to_string())?;
    let blind_signatures: Vec<BlindSignature> = serde_json::from_str(blind_signatures_json).map_err(|e| e.to_string())?;
    let swb_raw: Vec<serde_json::Value> = serde_json::from_str(secrets_with_blinding_json).map_err(|e| e.to_string())?;

    let mut secrets_with_blinding = Vec::new();
    for swb in swb_raw {
        let secret = Secret::new(swb["secret"].as_str().ok_or("Missing secret")?.to_string());
        let blinding_factor = SecretKey::from_slice(&hex::decode(swb["blinding_factor"].as_str().ok_or("Missing blinding")?).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        secrets_with_blinding.push((DeterministicSecretWithBlinding { secret, blinding_factor, amount: swb["amount"].as_u64().ok_or("Missing amount")?, index: swb["index"].as_u64().ok_or("Missing index")? as usize }, swb["is_receiver"].as_bool().ok_or("Missing is_receiver")?));
    }

    let result = unblind_and_verify_stage1_response(blind_signatures, secrets_with_blinding, &params, &output_keyset_info, balance).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "receiver_proofs": result.receiver_proofs, "sender_proofs": result.sender_proofs, "receiver_sum_after_stage1": result.receiver_sum, "sender_sum_after_stage1": result.sender_sum }).to_string())
}

impl<H: SpilmanHost<C>, C> SpilmanBridge<H, C> {
    pub fn new(host: H) -> Self { Self { host, _phantom: std::marker::PhantomData } }
    pub fn host(&self) -> &H { &self.host }

    fn decode_payment_header(base64_header: &str) -> Result<PaymentRequest, BridgeError> {
        let decoded = BASE64.decode(base64_header).map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        let json = String::from_utf8(decoded).map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        serde_json::from_str(&json).map_err(|e| BridgeError::InvalidRequest(e.to_string()))
    }

    pub fn process_payment(&self, channel_id: &str, balance: u64, signature: &str, params: Option<&serde_json::Value>, funding_proofs: Option<&[Proof]>, context: &C) -> Result<PaymentSuccess, BridgeError> {
        let val = self.validate_payment(channel_id, balance, signature, params, funding_proofs, context)?;
        self.host.record_payment(&val.channel_id, PaymentProof { balance: val.balance, signature: val.sender_signature.clone() }, context);
        Ok(PaymentSuccess { channel_id: val.channel_id, balance: val.balance, amount_due: val.amount_due, capacity: val.capacity })
    }

    pub fn process_payment_via_json(&self, payment_json: &str, context: &C) -> Result<PaymentSuccess, BridgeError> {
        let p: PaymentRequest = serde_json::from_str(payment_json).map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        self.process_payment(&p.channel_id, p.balance, &p.signature, p.params.as_ref(), p.funding_proofs.as_deref(), context)
    }

    pub fn process_payment_via_base64_header(&self, base64_header: &str, context: &C) -> Result<PaymentSuccess, BridgeError> {
        let p = Self::decode_payment_header(base64_header)?;
        self.process_payment(&p.channel_id, p.balance, &p.signature, p.params.as_ref(), p.funding_proofs.as_deref(), context)
    }

    pub fn validate_payment(&self, channel_id: &str, balance: u64, signature: &str, params: Option<&serde_json::Value>, funding_proofs: Option<&[Proof]>, context: &C) -> Result<PaymentValidationResult, BridgeError> {
        if channel_id.is_empty() {
            return Err(BridgeError::InvalidRequest("missing channel_id".into()));
        }
        if signature.is_empty() {
            return Err(BridgeError::InvalidRequest("missing signature".into()));
        }
        match self.host.get_channel_state(channel_id) { ChannelState::Closed => return Err(BridgeError::ChannelClosed), ChannelState::Closing => return Err(BridgeError::ChannelClosing), ChannelState::Open => {} }
        let (funding, is_new) = match self.host.get_funding(channel_id) { Some(f) => (f, false), None => (self.validate_and_save_new_channel(channel_id, params.ok_or(BridgeError::UnknownChannel)?, funding_proofs.ok_or(BridgeError::UnknownChannel)?, balance, signature)?, true) };
        let params_val: serde_json::Value = serde_json::from_str(&funding.params_json).map_err(|e| BridgeError::Internal(e.to_string()))?;
        let capacity = params_val["capacity"].as_u64().unwrap_or(0);
        if !is_new {
            if balance > capacity { return Err(BridgeError::BalanceExceedsCapacity { balance, capacity }); }
            self.verify_signature(&funding.params_json, &funding.funding_proofs_json, &funding.channel_secret_hex, &funding.keyset_info_json, channel_id, balance, signature).map_err(BridgeError::InvalidSignature)?;
        }
        let amount_due = self.host.get_amount_due(channel_id, Some(context));
        if balance < amount_due { return Err(BridgeError::InsufficientBalance { balance, amount_due }); }
        Ok(PaymentValidationResult { channel_id: channel_id.to_string(), balance, amount_due, capacity, sender_signature: signature.to_string() })
    }

    pub fn validate_payment_via_json(&self, payment_json: &str, context: &C) -> Result<PaymentValidationResult, BridgeError> {
        let p: PaymentRequest = serde_json::from_str(payment_json).map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        self.validate_payment(&p.channel_id, p.balance, &p.signature, p.params.as_ref(), p.funding_proofs.as_deref(), context)
    }

    pub fn validate_payment_via_base64_header(&self, base64_header: &str, context: &C) -> Result<PaymentValidationResult, BridgeError> {
        let p = Self::decode_payment_header(base64_header)?;
        self.validate_payment(&p.channel_id, p.balance, &p.signature, p.params.as_ref(), p.funding_proofs.as_deref(), context)
    }

    pub fn fund_channel(&self, channel_id: &str, balance: u64, signature: &str, params: Option<&serde_json::Value>, funding_proofs: Option<&[Proof]>) -> Result<FundChannelResult, BridgeError> {
        if channel_id.is_empty() {
            return Err(BridgeError::InvalidRequest("missing channel_id".into()));
        }
        if signature.is_empty() {
            return Err(BridgeError::InvalidRequest("missing signature".into()));
        }
        match self.host.get_channel_state(channel_id) { ChannelState::Closed => return Err(BridgeError::ChannelClosed), ChannelState::Closing => return Err(BridgeError::ChannelClosing), ChannelState::Open => {} }
        let (funding, already_known) = match self.host.get_funding(channel_id) { Some(f) => (f, true), None => (self.validate_and_save_new_channel(channel_id, params.ok_or(BridgeError::InvalidRequest("Missing params".into()))?, funding_proofs.ok_or(BridgeError::InvalidRequest("Missing proofs".into()))?, balance, signature)?, false) };
        let params_val: serde_json::Value = serde_json::from_str(&funding.params_json).map_err(|e| BridgeError::Internal(e.to_string()))?;
        let capacity = params_val["capacity"].as_u64().unwrap_or(0);
        if already_known { self.verify_signature(&funding.params_json, &funding.funding_proofs_json, &funding.channel_secret_hex, &funding.keyset_info_json, channel_id, balance, signature).map_err(BridgeError::InvalidSignature)?; }
        Ok(FundChannelResult { channel_id: channel_id.to_string(), capacity, already_known })
    }

    pub fn fund_channel_via_json(&self, json: &str) -> Result<FundChannelResult, BridgeError> {
        let p: PaymentRequest = serde_json::from_str(json).map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        self.fund_channel(&p.channel_id, p.balance, &p.signature, p.params.as_ref(), p.funding_proofs.as_deref())
    }

    pub fn fund_channel_via_base64_header(&self, base64_header: &str) -> Result<FundChannelResult, BridgeError> {
        let p = Self::decode_payment_header(base64_header)?;
        self.fund_channel(&p.channel_id, p.balance, &p.signature, p.params.as_ref(), p.funding_proofs.as_deref())
    }

    fn validate_and_save_new_channel(&self, channel_id: &str, params_val: &serde_json::Value, proofs: &[Proof], balance: u64, signature: &str) -> Result<ChannelFunding, BridgeError> {
        let unit = params_val["unit"].as_str().ok_or(BridgeError::InvalidRequest("Missing unit".into()))?;
        let capacity = params_val["capacity"].as_u64().ok_or(BridgeError::InvalidRequest("Missing capacity".into()))?;
        let locktime = params_val["locktime"].as_u64().ok_or(BridgeError::InvalidRequest("Missing locktime".into()))?;
        let maximum_amount = params_val["maximum_amount"].as_u64().ok_or(BridgeError::InvalidRequest("Missing maximum_amount".into()))?;
        let charlie_pubkey = PublicKey::from_hex(params_val["charlie_pubkey"].as_str().ok_or(BridgeError::InvalidRequest("Missing charlie_pubkey".into()))?).map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        if !self.host.receiver_key_is_acceptable(&charlie_pubkey) { return Err(BridgeError::ReceiverKeyNotAcceptable); }
        let keyset_id = Id::from_str(params_val["keyset_id"].as_str().ok_or(BridgeError::InvalidRequest("Missing keyset_id".into()))?).map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        let mint = params_val["mint"].as_str().ok_or(BridgeError::InvalidRequest("Missing mint".into()))?;
        if !self.host.mint_and_keyset_is_acceptable(mint, &keyset_id) { return Err(BridgeError::MintOrKeysetNotAcceptable); }
        let keyset_info_json = self.host.get_keyset_info(mint, &keyset_id).ok_or(BridgeError::MintOrKeysetNotAcceptable)?;
        let policy = self.host.get_channel_policy(unit).ok_or(BridgeError::UnsupportedUnit(unit.to_string()))?;
        if capacity < policy.min_capacity { return Err(BridgeError::CapacityTooSmall { capacity, min_capacity: policy.min_capacity }); }
        if let Some(max) = policy.max_amount_per_output { if max > 0 && maximum_amount > max { return Err(BridgeError::MaxAmountExceeded { amount: maximum_amount, max_allowed: max }); } }
        let now = self.host.now_seconds();
        if locktime < now + policy.min_expiry_in_seconds { return Err(BridgeError::LocktimeTooSoon { locktime, min_locktime: now + policy.min_expiry_in_seconds, now }); }
        if balance > capacity { return Err(BridgeError::BalanceExceedsCapacity { balance, capacity }); }
        let channel_secret_hex = self.host.compute_channel_secret(params_val["charlie_pubkey"].as_str().unwrap(), params_val["alice_pubkey"].as_str().ok_or(BridgeError::InvalidRequest("Missing alice_pubkey".into()))?).map_err(BridgeError::ServerMisconfigured)?;
        let channel_secret: [u8; 32] = hex::decode(&channel_secret_hex).map_err(|e| BridgeError::Internal(e.to_string()))?.try_into().map_err(|_| BridgeError::Internal("Invalid secret length".into()))?;
        let params = ChannelParameters::from_json_with_channel_secret(&params_val.to_string(), super::parse_keyset_info_from_json(&keyset_info_json).map_err(BridgeError::InvalidRequest)?, channel_secret).map_err(|e| BridgeError::Internal(e.to_string()))?;
        if params.get_channel_id() != channel_id { return Err(BridgeError::ChannelIdMismatch); }
        let verif = verify_valid_channel(proofs, &params);
        if !verif.valid { return Err(BridgeError::ValidationFailed(serde_json::to_string(&verif.errors).unwrap())); }
        self.verify_signature(&params_val.to_string(), &serde_json::to_string(proofs).unwrap(), &channel_secret_hex, &keyset_info_json, channel_id, balance, signature).map_err(BridgeError::InvalidSignature)?;
        let funding = ChannelFunding { params_json: params_val.to_string(), funding_proofs_json: serde_json::to_string(proofs).unwrap(), channel_secret_hex, keyset_info_json };
        self.host.save_funding(channel_id, funding.clone(), PaymentProof { balance, signature: signature.to_string() });
        Ok(funding)
    }

    fn verify_signature(&self, params_json: &str, proofs_json: &str, secret_hex: &str, keyset_json: &str, channel_id: &str, balance: u64, signature: &str) -> Result<(), String> {
        let secret: [u8; 32] = hex::decode(secret_hex).map_err(|e| e.to_string())?.try_into().map_err(|_| "Invalid secret length")?;
        let params = ChannelParameters::from_json_with_channel_secret(params_json, super::parse_keyset_info_from_json(keyset_json).map_err(|e| e.to_string())?, secret).map_err(|e| e.to_string())?;
        let channel = EstablishedChannel::new(params, serde_json::from_str(proofs_json).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let sig: bitcoin::secp256k1::schnorr::Signature = signature.parse().map_err(|e: <bitcoin::secp256k1::schnorr::Signature as FromStr>::Err| e.to_string())?;
        BalanceUpdateMessage { channel_id: channel_id.to_string(), amount: balance, signature: sig }.verify_sender_signature(&channel).map_err(|e| e.to_string())
    }

    fn prepare_close_data_impl(&self, channel_id: &str, balance: u64, signature: &str, funding: ChannelFunding, validate_due: bool) -> Result<CloseData, BridgeError> {
        let secret: [u8; 32] = hex::decode(&funding.channel_secret_hex).map_err(|e| BridgeError::Internal(e.to_string()))?.try_into().map_err(|_| BridgeError::Internal("Invalid secret length".into()))?;
        let params = ChannelParameters::from_json_with_channel_secret(&funding.params_json, super::parse_keyset_info_from_json(&funding.keyset_info_json).map_err(|e| BridgeError::Internal(e.to_string()))?, secret).map_err(|e| BridgeError::Internal(e.to_string()))?;
        let proofs: Vec<Proof> = serde_json::from_str(&funding.funding_proofs_json).map_err(|e| BridgeError::Internal(e.to_string()))?;
        let active = self.host.get_active_keyset_ids(&params.mint, &params.unit);
        let out_keyset = if active.contains(&params.keyset_info.keyset_id) { params.keyset_info.clone() } else {
            let nid = active.first().ok_or_else(|| BridgeError::Internal("No active keysets".into()))?;
            super::parse_keyset_info_from_json(&self.host.get_keyset_info(&params.mint, nid).ok_or_else(|| BridgeError::Internal("Missing keyset info".into()))?).map_err(|e| BridgeError::Internal(e.to_string()))?
        };
        if balance > params.capacity { return Err(BridgeError::BalanceExceedsCapacity { balance, capacity: params.capacity }); }
        if validate_due && balance != self.host.get_amount_due(channel_id, None) { return Err(BridgeError::BalanceMismatch { expected: self.host.get_amount_due(channel_id, None), actual: balance }); }
        let sig: bitcoin::secp256k1::schnorr::Signature = signature.parse().map_err(|e: <bitcoin::secp256k1::schnorr::Signature as FromStr>::Err| BridgeError::InvalidSignature(e.to_string()))?;
        let commitment = CommitmentOutputs::for_balance(balance, &params).map_err(|e| BridgeError::Internal(e.to_string()))?;
        let mut swap = commitment.create_swap_request(proofs.clone(), Some(out_keyset.keyset_id)).map_err(|e| BridgeError::Internal(e.to_string()))?;
        swap.attach_signature_to_first_input(&sig.to_string()).map_err(|e| BridgeError::Internal(e.to_string()))?;
        let channel = EstablishedChannel::new(params.clone(), proofs).map_err(|e| BridgeError::Internal(e.to_string()))?;
        BalanceUpdateMessage { channel_id: channel_id.to_string(), amount: balance, signature: sig }.verify_sender_signature(&channel).map_err(|e| BridgeError::InvalidSignature(e.to_string()))?;
        let tweak = hex::encode(params.derive_receiver_blinding_scalar_for_stage1().map_err(|e| BridgeError::Internal(e.to_string()))?.to_be_bytes());
        let server_sig = self.host.sign_with_tweaked_key(&params.charlie_pubkey.to_hex(), &swap.sig_all_message_hash_hex(), &tweak).map_err(BridgeError::ServerMisconfigured)?;
        swap.attach_signature_to_first_input(&server_sig).map_err(|e| BridgeError::Internal(e.to_string()))?;
        let expected_total = params.get_value_after_stage1_with_keyset(&out_keyset).map_err(|e| BridgeError::Internal(e.to_string()))?;
        let mut swb: Vec<_> = commitment.receiver_outputs.get_secrets_with_blinding().map_err(|e| BridgeError::Internal(e.to_string()))?.into_iter().map(|s| (s, true)).chain(commitment.sender_outputs.get_secrets_with_blinding().map_err(|e| BridgeError::Internal(e.to_string()))?.into_iter().map(|s| (s, false))).collect();
        swb.sort_by_key(|(s, _)| s.amount);
        Ok(CloseData { swap_request: swap, expected_total, secrets_with_blinding: swb, output_keyset_info: out_keyset })
    }

    fn prepare_close_data(&self, channel_id: &str, balance: u64, signature: &str, params: Option<&serde_json::Value>, funding_proofs: Option<&[Proof]>, validate_due: bool) -> Result<CloseData, BridgeError> {
        if self.host.get_channel_state(channel_id) == ChannelState::Closed { return Err(BridgeError::ChannelClosed); }
        let funding = match self.host.get_funding(channel_id) { Some(f) => f, None => self.validate_and_save_new_channel(channel_id, params.ok_or(BridgeError::UnknownChannel)?, funding_proofs.ok_or(BridgeError::UnknownChannel)?, balance, signature)? };
        self.prepare_close_data_impl(channel_id, balance, signature, funding, validate_due)
    }

    pub fn validate_and_prepare_cooperative_close(&self, json: &str) -> Result<CloseData, BridgeError> {
        let p: PaymentRequest = serde_json::from_str(json).map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        if p.channel_id.is_empty() {
            return Err(BridgeError::InvalidRequest("missing channel_id".into()));
        }
        if p.signature.is_empty() {
            return Err(BridgeError::InvalidRequest("missing signature".into()));
        }
        self.prepare_close_data(&p.channel_id, p.balance, &p.signature, p.params.as_ref(), p.funding_proofs.as_deref(), true)
    }

    pub fn create_unilateral_close_data(&self, channel_id: &str) -> Result<CloseData, BridgeError> {
        if self.host.get_funding(channel_id).is_none() { return Err(BridgeError::UnknownChannel); }
        let p = self.host.get_balance_and_signature_for_unilateral_exit(channel_id).ok_or_else(|| BridgeError::InvalidRequest("No payment proof".into()))?;
        self.prepare_close_data(channel_id, p.balance, &p.signature, None, None, false)
    }

    pub fn prepare_cooperative_close_for_execution(&self, json: &str) -> Result<PreparedClose, ClosePreparationError> {
        let p: serde_json::Value = serde_json::from_str(json).map_err(|e| ClosePreparationError::bad_request(e.to_string()))?;
        let channel_id = p["channel_id"].as_str().ok_or_else(|| ClosePreparationError::bad_request("Missing ID"))?.to_string();
        let close_data = self.validate_and_prepare_cooperative_close(json).map_err(ClosePreparationError::from_bridge_error)?;
        let funding = self.host.get_funding(&channel_id).ok_or_else(|| ClosePreparationError::internal("Missing funding"))?;
        let mint_url = serde_json::from_str::<serde_json::Value>(&funding.params_json).map_err(|e| ClosePreparationError::internal(e.to_string()))?["mint"].as_str().ok_or_else(|| ClosePreparationError::internal("Missing mint"))?.to_string();
        Ok(PreparedClose { channel_id, balance: p["balance"].as_u64().unwrap_or(0), mint_url, swap_request: serde_json::to_value(&close_data.swap_request).unwrap_or(serde_json::Value::Null), secrets_with_blinding: close_data.secrets_with_blinding.iter().map(|(s, is_r)| serde_json::json!({ "secret": s.secret.to_string(), "blinding_factor": hex::encode(s.blinding_factor.secret_bytes()), "amount": s.amount, "index": s.index, "is_receiver": is_r })).collect(), output_keyset_info: serde_json::to_value(&close_data.output_keyset_info).unwrap_or(serde_json::Value::Null), params_json: funding.params_json, keyset_info_json: funding.keyset_info_json, channel_secret: funding.channel_secret_hex })
    }

    pub fn prepare_unilateral_close_for_execution(&self, channel_id: &str) -> Result<PreparedClose, ClosePreparationError> {
        let close_data = self.create_unilateral_close_data(channel_id).map_err(ClosePreparationError::from_bridge_error)?;
        let funding = self.host.get_funding(channel_id).ok_or_else(|| ClosePreparationError::internal("Missing funding"))?;
        let p = self.host.get_balance_and_signature_for_unilateral_exit(channel_id).ok_or_else(|| ClosePreparationError::internal("Missing payment"))?;
        let mint_url = serde_json::from_str::<serde_json::Value>(&funding.params_json).map_err(|e| ClosePreparationError::internal(e.to_string()))?["mint"].as_str().ok_or_else(|| ClosePreparationError::internal("Missing mint"))?.to_string();
        Ok(PreparedClose { channel_id: channel_id.to_string(), balance: p.balance, mint_url, swap_request: serde_json::to_value(&close_data.swap_request).unwrap_or(serde_json::Value::Null), secrets_with_blinding: close_data.secrets_with_blinding.iter().map(|(s, is_r)| serde_json::json!({ "secret": s.secret.to_string(), "blinding_factor": hex::encode(s.blinding_factor.secret_bytes()), "amount": s.amount, "index": s.index, "is_receiver": is_r })).collect(), output_keyset_info: serde_json::to_value(&close_data.output_keyset_info).unwrap_or(serde_json::Value::Null), params_json: funding.params_json, keyset_info_json: funding.keyset_info_json, channel_secret: funding.channel_secret_hex })
    }

    fn finalize_close(&self, channel_id: &str, locktime: u64, payment: PaymentProof, resp_json: &str, prep: &PreparedClose) -> Result<CloseSuccess, CloseError> {
        let resp: serde_json::Value = serde_json::from_str(resp_json).map_err(|e| CloseError::UnblindFailed { reason: e.to_string(), status: 500 })?;
        let sigs = resp.get("signatures").ok_or_else(|| CloseError::UnblindFailed { reason: "Missing signatures".into(), status: 500 })?;
        let unblind_json = unblind_and_verify_dleq(&sigs.to_string(), &prep.secrets_with_blinding.to_string(), &prep.params_json, &prep.keyset_info_json, &prep.channel_secret, payment.balance, Some(&prep.output_keyset_info.to_string())).map_err(CloseError::unblind_failed)?;
        let res: serde_json::Value = serde_json::from_str(&unblind_json).map_err(|e| CloseError::UnblindFailed { reason: e.to_string(), status: 500 })?;
        let r_sum = res["receiver_sum_after_stage1"].as_u64().unwrap_or(0);
        let s_sum = res["sender_sum_after_stage1"].as_u64().unwrap_or(0);
        self.host.mark_channel_closed(channel_id, locktime, payment.balance, &res["receiver_proofs"].to_string(), &res["sender_proofs"].to_string(), r_sum, s_sum).map_err(CloseError::storage_failed)?;
        Ok(CloseSuccess { channel_id: channel_id.to_string(), total_value: r_sum + s_sum, receiver_sum: r_sum, sender_sum: s_sum, sender_proofs: res["sender_proofs"].to_string(), already_closed: false })
    }

    pub fn execute_close_for_closing_channel<N: SpilmanNetworking>(&self, channel_id: &str, net: &N) -> Result<CloseSuccess, CloseError> {
        if self.host.get_channel_state(channel_id) != ChannelState::Closing { return Err(CloseError::ValidationFailed { reason: "Not closing".into(), status: 400, expected_balance: None, actual_balance: None }); }
        let cd = self.host.get_closing_data(channel_id).ok_or_else(|| CloseError::ValidationFailed { reason: "Missing closing data".into(), status: 500, expected_balance: None, actual_balance: None })?;
        let prep = self.prepare_unilateral_close_for_execution(channel_id).map_err(CloseError::from_preparation_error)?;
        let (prep, resp) = match net.call_mint_swap(&prep.mint_url, &prep.swap_request.to_string()) {
            Ok(r) => (prep, r),
            Err(e) => {
                let _ = net.refresh_all_keysets(&prep.mint_url);
                let retry = self.prepare_unilateral_close_for_execution(channel_id).map_err(CloseError::from_preparation_error)?;
                let resp = net
                    .call_mint_swap(&retry.mint_url, &retry.swap_request.to_string())
                    .map_err(|re| CloseError::mint_rejected_after_retry(serde_json::json!(e), serde_json::json!(re)))?;
                (retry, resp)
            }
        };
        self.finalize_close(channel_id, cd.locktime, PaymentProof { balance: cd.balance, signature: cd.signature }, &resp, &prep)
    }

    pub async fn execute_close_for_closing_channel_async<N: SpilmanAsyncNetworking>(&self, channel_id: &str, net: &N) -> Result<CloseSuccess, CloseError> {
        if self.host.get_channel_state(channel_id) != ChannelState::Closing { return Err(CloseError::ValidationFailed { reason: "Not closing".into(), status: 400, expected_balance: None, actual_balance: None }); }
        let cd = self.host.get_closing_data(channel_id).ok_or_else(|| CloseError::ValidationFailed { reason: "Missing closing data".into(), status: 500, expected_balance: None, actual_balance: None })?;
        let prep = self.prepare_unilateral_close_for_execution(channel_id).map_err(CloseError::from_preparation_error)?;
        let (prep, resp) = match net.call_mint_swap(&prep.mint_url, &prep.swap_request.to_string()).await {
            Ok(r) => (prep, r),
            Err(e) => {
                let _ = net.refresh_all_keysets(&prep.mint_url).await;
                let retry = self.prepare_unilateral_close_for_execution(channel_id).map_err(CloseError::from_preparation_error)?;
                let resp = net
                    .call_mint_swap(&retry.mint_url, &retry.swap_request.to_string())
                    .await
                    .map_err(|re| CloseError::mint_rejected_after_retry(serde_json::json!(e), serde_json::json!(re)))?;
                (retry, resp)
            }
        };
        self.finalize_close(channel_id, cd.locktime, PaymentProof { balance: cd.balance, signature: cd.signature }, &resp, &prep)
    }

    pub fn execute_cooperative_close<N: SpilmanNetworking>(&self, json: &str, net: &N) -> Result<CloseSuccess, CloseError> {
        let prep = self.prepare_cooperative_close_for_execution(json).map_err(CloseError::from_preparation_error)?;
        let locktime = serde_json::from_str::<serde_json::Value>(&prep.params_json).unwrap_or_default()["locktime"].as_u64().unwrap_or(0);
        let sig = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default()["signature"].as_str().unwrap_or_default().to_string();
        self.host.mark_channel_closing(&prep.channel_id, locktime, PaymentProof { balance: prep.balance, signature: sig }).map_err(CloseError::storage_failed)?;
        self.execute_close_for_closing_channel(&prep.channel_id, net)
    }

    pub async fn execute_cooperative_close_async<N: SpilmanAsyncNetworking>(&self, json: &str, net: &N) -> Result<CloseSuccess, CloseError> {
        let prep = self.prepare_cooperative_close_for_execution(json).map_err(CloseError::from_preparation_error)?;
        let locktime = serde_json::from_str::<serde_json::Value>(&prep.params_json).unwrap_or_default()["locktime"].as_u64().unwrap_or(0);
        let sig = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default()["signature"].as_str().unwrap_or_default().to_string();
        self.host.mark_channel_closing(&prep.channel_id, locktime, PaymentProof { balance: prep.balance, signature: sig }).map_err(CloseError::storage_failed)?;
        self.execute_close_for_closing_channel_async(&prep.channel_id, net).await
    }

    pub fn execute_unilateral_close<N: SpilmanNetworking>(&self, channel_id: &str, net: &N) -> Result<CloseSuccess, CloseError> {
        let prep = self.prepare_unilateral_close_for_execution(channel_id).map_err(CloseError::from_preparation_error)?;
        let locktime = serde_json::from_str::<serde_json::Value>(&prep.params_json).unwrap_or_default()["locktime"].as_u64().unwrap_or(0);
        let p = self.host.get_balance_and_signature_for_unilateral_exit(channel_id).ok_or_else(|| CloseError::ValidationFailed { reason: "No payment".into(), status: 400, expected_balance: None, actual_balance: None })?;
        self.host.mark_channel_closing(channel_id, locktime, p).map_err(CloseError::storage_failed)?;
        self.execute_close_for_closing_channel(channel_id, net)
    }

    pub async fn execute_unilateral_close_async<N: SpilmanAsyncNetworking>(&self, channel_id: &str, net: &N) -> Result<CloseSuccess, CloseError> {
        let prep = self.prepare_unilateral_close_for_execution(channel_id).map_err(CloseError::from_preparation_error)?;
        let locktime = serde_json::from_str::<serde_json::Value>(&prep.params_json).unwrap_or_default()["locktime"].as_u64().unwrap_or(0);
        let p = self.host.get_balance_and_signature_for_unilateral_exit(channel_id).ok_or_else(|| CloseError::ValidationFailed { reason: "No payment".into(), status: 400, expected_balance: None, actual_balance: None })?;
        self.host.mark_channel_closing(channel_id, locktime, p).map_err(CloseError::storage_failed)?;
        self.execute_close_for_closing_channel_async(channel_id, net).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nuts::{Id, PublicKey, SecretKey};
    struct MockHost { ra: bool, ma: bool }
    impl SpilmanHost<String> for MockHost {
        fn receiver_key_is_acceptable(&self, _: &PublicKey) -> bool { self.ra }
        fn mint_and_keyset_is_acceptable(&self, _: &str, _: &Id) -> bool { self.ma }
        fn get_funding(&self, _: &str) -> Option<ChannelFunding> { None }
        fn save_funding(&self, _: &str, _: ChannelFunding, _: PaymentProof) {}
        fn get_amount_due(&self, _: &str, _: Option<&String>) -> u64 { 0 }
        fn record_payment(&self, _: &str, _: PaymentProof, _: &String) {}
        fn get_channel_state(&self, _: &str) -> ChannelState { ChannelState::Open }
        fn mark_channel_closing(&self, _: &str, _: u64, _: PaymentProof) -> Result<(), String> { Ok(()) }
        fn get_closing_data(&self, _: &str) -> Option<ClosingData> { None }
        fn get_channel_policy(&self, _unit: &str) -> Option<ChannelPolicy> { Some(ChannelPolicy { min_expiry_in_seconds: 3600, min_capacity: 100, max_amount_per_output: None }) }
        fn now_seconds(&self) -> u64 { 1700000000 }
        fn get_balance_and_signature_for_unilateral_exit(&self, _: &str) -> Option<PaymentProof> { None }
        fn get_active_keyset_ids(&self, _: &str, _: &CurrencyUnit) -> Vec<Id> { Vec::new() }
        fn get_keyset_info(&self, _: &str, _: &Id) -> Option<String> { None }
        fn mark_channel_closed(&self, _: &str, _: u64, _: u64, _: &str, _: &str, _: u64, _: u64) -> Result<(), String> { Ok(()) }
        fn compute_channel_secret(&self, _: &str, _: &str) -> Result<String, String> { Err("N/A".into()) }
        fn sign_with_tweaked_key(&self, _: &str, _: &str, _: &str) -> Result<String, String> { Err("N/A".into()) }
    }
    impl SpilmanNetworking for MockHost {
        fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, String> { Err("N/A".into()) }
        fn refresh_all_keysets(&self, _: &str) -> Result<(), String> { Err("N/A".into()) }
    }
    #[test]
    fn test_bridge_rejects_unacceptable_receiver() {
        let b = SpilmanBridge::new(MockHost { ra: false, ma: true });
        let p = serde_json::json!({ "alice_pubkey": SecretKey::generate().public_key().to_hex(), "charlie_pubkey": SecretKey::generate().public_key().to_hex(), "mint": "https://m", "unit": "sat", "capacity": 1000, "funding_token_amount": 1000, "maximum_amount": 64, "locktime": 1700007200, "setup_timestamp": 1700000000, "sender_nonce": "n", "keyset_id": "00" });
        let pay = serde_json::json!({ "channel_id": "i", "balance": 100, "signature": "s", "params": p, "funding_proofs": [] });
        assert!(b.process_payment_via_json(&pay.to_string(), &"{}".to_string()).unwrap_err().to_string().contains("receiver key not acceptable"));
    }
}
