//! Spilman Protocol Bridge
//!
//! This module provides a high-level bridge for implementing Spilman payment channels
//! in any service provider. It handles the core protocol logic, validation, and
//! signature verification, while delegating storage and pricing to a host hook.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::{
    verify_valid_channel, BalanceUpdateMessage, ChannelParameters, CommitmentOutputs,
    DeterministicSecretWithBlinding, EstablishedChannel, KeysetInfo, SpilmanChannelReceiver,
};
use crate::nuts::{BlindSignature, CurrencyUnit, Id, Proof, PublicKey, SecretKey, SwapRequest};
use crate::util::hex;
use std::str::FromStr;

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
pub trait SpilmanHost {
    /// Check if the receiver pubkey in the channel params is acceptable
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool;

    /// Check if the mint and keyset are acceptable
    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &crate::nuts::Id) -> bool;

    /// Get cached funding data for a channel
    /// Returns (params_json, funding_proofs_json, shared_secret_hex, keyset_info_json)
    fn get_funding_and_params(&self, channel_id: &str) -> Option<(String, String, String, String)>;

    /// Save funding data for a channel, including the initial payment proof
    ///
    /// The initial_balance and initial_signature represent the first valid payment
    /// for this channel. Even if balance is 0, the signature is valid and can be
    /// used for closing. The host should store these alongside the funding data.
    #[allow(clippy::too_many_arguments)]
    fn save_funding(
        &self,
        channel_id: &str,
        params_json: &str,
        funding_proofs_json: &str,
        shared_secret_hex: &str,
        keyset_info_json: &str,
        initial_balance: u64,
        initial_signature: &str,
    );

    /// Get the current amount due for a channel
    ///
    /// The host should compute this based on the service provided so far,
    /// plus the current request described in `context_json`.
    /// If `context_json` is None, return the amount due based on existing usage.
    fn get_amount_due(&self, channel_id: &str, context_json: Option<&str>) -> u64;

    /// Record a successful payment and update usage
    fn record_payment(&self, channel_id: &str, balance: u64, signature: &str, context_json: &str);

    /// Get the current state of a channel.
    ///
    /// Returns `Open` for unknown channels (they're implicitly open until funded).
    fn get_channel_state(&self, channel_id: &str) -> ChannelState;

    /// Mark a channel as closing (pre-swap state).
    ///
    /// Called before attempting the mint swap. The host should:
    /// - Store the closing parameters (enough to reconstruct swap request later)
    /// - Return `ChannelState::Closing` from `get_channel_state()` for this channel
    /// - Reject further payments to this channel
    ///
    /// Can be called multiple times to update the closing parameters (server policy decision).
    ///
    /// # Arguments
    /// * `channel_id` - The channel ID
    /// * `locktime` - The channel's locktime
    /// * `balance` - The balance at close
    /// * `signature` - The client's Schnorr signature authorizing this balance
    fn mark_channel_closing(
        &self,
        channel_id: &str,
        locktime: u64,
        balance: u64,
        signature: &str,
    ) -> Result<(), String>;

    /// Get the stored closing data for a channel in CLOSING state.
    ///
    /// Returns the data needed to reconstruct a swap request for retry.
    /// Returns None if channel is not in CLOSING state.
    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData>;

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

    /// Get active keyset IDs for a mint and unit
    /// There is no requirement that this be up-to-date
    /// If the bridge concludes that the ids might be
    /// out of date, it may call 'refresh_active_keysets'
    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id>;

    /// Get full KeysetInfo JSON for a specific keyset
    /// There is no requirement that this be complete
    /// If the bridge concludes that the data maybe be
    /// out of date, it may call 'refresh_active_keysets'
    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String>;

    /// Refresh the active keyset cache for a mint
    ///
    /// Called when a swap fails (possibly due to stale keyset data).
    /// The host should re-fetch keysets from the mint and update its cache.
    /// Returns Ok(()) on success, or an error string on failure.
    ///
    /// Note: This is primarily used by async WASM bindings which implement
    /// retry logic. The sync Rust implementation returns an error by default.
    fn refresh_active_keysets(&self, mint: &str) -> Result<(), String> {
        let _ = mint;
        Err("refresh_active_keysets not implemented (sync)".to_string())
    }

    /// Call the mint's /v1/swap endpoint
    ///
    /// The host is responsible for HTTP communication with the mint.
    /// Returns the full JSON response body on success (e.g., `{"signatures": [...]}`),
    /// or an error string on failure.
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String>;

    /// Mark a channel as closed and persist the final state
    ///
    /// Called after successful unblinding and DLEQ verification.
    /// The host should store the proofs and mark the channel as closed.
    ///
    /// # Arguments
    /// * `channel_id` - The channel ID
    /// * `locktime` - The channel's locktime
    /// * `balance` - The balance at which the channel was closed
    /// * `receiver_proofs_json` - JSON array of receiver's P2PK proofs
    /// * `sender_proofs_json` - JSON array of sender's P2PK proofs (change)
    /// * `receiver_sum` - Sum of receiver proof amounts
    /// * `sender_sum` - Sum of sender proof amounts
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

/// Result of a successful payment
///
/// Returned by `process_payment` after validation and recording.
#[derive(Debug, Clone, Serialize)]
pub struct PaymentSuccess {
    pub channel_id: String,
    pub balance: u64,
    pub amount_due: u64,
    pub capacity: u64,
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

impl CloseData {
    /// Serialize CloseData to a JSON value for FFI responses
    ///
    /// Returns a JSON object with:
    /// - `success`: true
    /// - `swap_request`: The fully-signed swap request
    /// - `expected_total`: Expected total output value
    /// - `secrets_with_blinding`: Array of {secret, blinding_factor, amount, index, is_receiver}
    /// - `output_keyset_info`: The keyset info for outputs
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
    /// Receiver's proofs (P2PK locked to Charlie's blinded pubkey)
    pub receiver_proofs: Vec<Proof>,
    /// Sender's proofs (P2PK locked to Alice's blinded pubkey)
    pub sender_proofs: Vec<Proof>,
    /// Sum of receiver proof amounts
    pub receiver_sum: u64,
    /// Sum of sender proof amounts
    pub sender_sum: u64,
}

/// Everything needed to execute a close operation after sync validation.
///
/// Contains all data for the HTTP phase (swap request) and subsequent
/// finalization (unblinding and marking closed).
#[derive(Debug)]
pub struct PreparedClose {
    /// The channel being closed
    pub channel_id: String,
    /// The balance at which the channel is being closed
    pub balance: u64,
    /// The mint URL to submit the swap to
    pub mint_url: String,
    /// The fully-signed swap request, ready to POST to /v1/swap
    pub swap_request: serde_json::Value,
    /// Secrets with blinding factors for unblinding the response
    pub secrets_with_blinding: serde_json::Value,
    /// Keyset info for the output proofs
    pub output_keyset_info: serde_json::Value,
    /// Channel parameters (for unblinding phase)
    pub params_json: String,
    /// Keyset info JSON (for unblinding phase)
    pub keyset_info_json: String,
    /// Shared secret hex (for unblinding phase)
    pub shared_secret: String,
}

/// HTTP-friendly error for close preparation.
///
/// Not a Rust Error type - just a struct that serializes to JSON with status code.
/// Used by bindings to return errors with appropriate HTTP status codes.
#[derive(Debug)]
pub struct ClosePreparationError {
    /// Short error message (e.g., "Payment required")
    pub error: String,
    /// Detailed reason (e.g., "invalid signature: Alice did not authorize...")
    pub reason: String,
    /// HTTP status code (400, 402, 404, 500)
    pub status: u16,
    /// Additional fields for specific errors (e.g., expected/actual for mismatch)
    pub extra: Option<serde_json::Map<String, serde_json::Value>>,
}

impl ClosePreparationError {
    /// Serialize to JSON string for FFI responses
    pub fn to_json(&self) -> String {
        let mut obj = serde_json::json!({
            "success": false,
            "error": self.error,
            "reason": self.reason,
            "status": self.status
        });

        // Merge extra fields into the response
        if let Some(extra) = &self.extra {
            if let Some(obj_map) = obj.as_object_mut() {
                for (k, v) in extra {
                    obj_map.insert(k.clone(), v.clone());
                }
            }
        }

        obj.to_string()
    }

    /// Create a 400 Bad Request error
    pub fn bad_request(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            error: "Bad request".into(),
            reason,
            status: 400,
            extra: None,
        }
    }

    /// Create a 402 Payment Required error
    pub fn payment_required(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            error: "Payment required".into(),
            reason,
            status: 402,
            extra: None,
        }
    }

    /// Create a 404 Not Found error
    /// Uses the reason as both error and reason since specific error messages
    /// (like "unknown channel") are more useful than generic "Not found"
    pub fn not_found(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            error: reason.clone(),
            reason,
            status: 404,
            extra: None,
        }
    }

    /// Create a 500 Internal Server Error
    pub fn internal(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            error: "Internal error".into(),
            reason,
            status: 500,
            extra: None,
        }
    }

    /// Add extra fields to the error
    pub fn with_extra(mut self, extra: serde_json::Map<String, serde_json::Value>) -> Self {
        self.extra = Some(extra);
        self
    }

    /// Create from a BridgeError with appropriate status code
    pub fn from_bridge_error(err: BridgeError) -> Self {
        let reason = err.to_string();

        match &err {
            BridgeError::ChannelClosed => Self::payment_required(reason),
            BridgeError::UnknownChannel => Self::not_found(reason),
            BridgeError::InvalidRequest(msg) if msg.contains("no payment proof") => {
                Self::bad_request(reason)
            }
            BridgeError::Internal(_) | BridgeError::ServerMisconfigured(_) => {
                Self::internal(reason)
            }
            BridgeError::BalanceMismatch { expected, actual } => {
                let mut extra = serde_json::Map::new();
                extra.insert("expected".into(), serde_json::json!(expected));
                extra.insert("actual".into(), serde_json::json!(actual));
                Self::payment_required(reason).with_extra(extra)
            }
            // All validation errors are 402 Payment Required
            _ => Self::payment_required(reason),
        }
    }
}

/// Result of validating a payment without recording it
///
/// This struct contains all validation results without any side effects.
/// For new channels, the channel funding is saved, but no usage is recorded.
#[derive(Debug, Clone, Serialize)]
pub struct PaymentValidationResult {
    pub channel_id: String,
    pub balance: u64,
    pub amount_due: u64,
    pub capacity: u64,
    pub sender_signature: String,
}

/// Result of registering/funding a channel
///
/// Returned by `fund_channel` which validates and saves a channel
/// without recording any usage.
#[derive(Debug, Clone, Serialize)]
pub struct FundChannelResult {
    pub channel_id: String,
    pub capacity: u64,
    /// True if the channel was already known (idempotent call)
    pub already_known: bool,
}

/// Result of successfully closing a channel
///
/// Returned by `execute_cooperative_close` and `execute_unilateral_close`
/// after the swap is submitted to the mint and proofs are unblinded.
#[derive(Debug, Clone, Serialize)]
pub struct CloseSuccess {
    /// The channel that was closed
    pub channel_id: String,
    /// Total value of all output proofs (receiver + sender)
    pub total_value: u64,
    /// Sum of receiver proof amounts (server's earnings before stage 2 fees)
    pub receiver_sum: u64,
    /// Sum of sender proof amounts (change returned to sender)
    pub sender_sum: u64,
    /// JSON string of sender's P2PK proofs (to return to client)
    pub sender_proofs: String,
    /// True if this was an idempotent call (channel was already closed)
    pub already_closed: bool,
}

/// Error that occurred during channel close execution
///
/// This enum captures all the ways a close operation can fail,
/// with structured data for each error type.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum CloseError {
    /// Validation failed before mint interaction (signature, balance, etc.)
    #[serde(rename = "validation_failed")]
    ValidationFailed {
        reason: String,
        status: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        expected_balance: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        actual_balance: Option<u64>,
    },

    /// Channel not found
    #[serde(rename = "unknown_channel")]
    UnknownChannel { status: u16 },

    /// Channel is already closed (only used if bridge handles idempotency)
    #[serde(rename = "already_closed")]
    AlreadyClosed {
        closed_balance: u64,
        requested_balance: u64,
        status: u16,
    },

    /// Mint rejected the swap request
    #[serde(rename = "mint_rejected")]
    MintRejected {
        mint_error: serde_json::Value,
        status: u16,
    },

    /// Mint rejected swap, retry also failed
    #[serde(rename = "mint_rejected_after_retry")]
    MintRejectedAfterRetry {
        original_error: serde_json::Value,
        retry_error: serde_json::Value,
        status: u16,
    },

    /// DLEQ verification failed after swap
    #[serde(rename = "unblind_failed")]
    UnblindFailed { reason: String, status: u16 },

    /// Failed to mark channel as closed in storage
    #[serde(rename = "storage_failed")]
    StorageFailed { reason: String, status: u16 },
}

impl CloseError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            Self::ValidationFailed { status, .. } => *status,
            Self::UnknownChannel { status } => *status,
            Self::AlreadyClosed { status, .. } => *status,
            Self::MintRejected { status, .. } => *status,
            Self::MintRejectedAfterRetry { status, .. } => *status,
            Self::UnblindFailed { status, .. } => *status,
            Self::StorageFailed { status, .. } => *status,
        }
    }

    /// Create a validation failed error from a ClosePreparationError
    pub fn from_preparation_error(err: ClosePreparationError) -> Self {
        let (expected_balance, actual_balance) = if let Some(extra) = &err.extra {
            (
                extra.get("expected").and_then(|v| v.as_u64()),
                extra.get("actual").and_then(|v| v.as_u64()),
            )
        } else {
            (None, None)
        };

        Self::ValidationFailed {
            reason: err.reason,
            status: err.status,
            expected_balance,
            actual_balance,
        }
    }

    /// Create an unknown channel error
    pub fn unknown_channel() -> Self {
        Self::UnknownChannel { status: 404 }
    }

    /// Create a mint rejected error
    pub fn mint_rejected(mint_error: serde_json::Value) -> Self {
        Self::MintRejected {
            mint_error,
            status: 502,
        }
    }

    /// Create a mint rejected after retry error
    pub fn mint_rejected_after_retry(
        original_error: serde_json::Value,
        retry_error: serde_json::Value,
    ) -> Self {
        Self::MintRejectedAfterRetry {
            original_error,
            retry_error,
            status: 502,
        }
    }

    /// Create an unblind failed error
    pub fn unblind_failed(reason: impl Into<String>) -> Self {
        Self::UnblindFailed {
            reason: reason.into(),
            status: 500,
        }
    }

    /// Create a storage failed error
    pub fn storage_failed(reason: impl Into<String>) -> Self {
        Self::StorageFailed {
            reason: reason.into(),
            status: 500,
        }
    }
}

impl std::fmt::Display for CloseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ValidationFailed { reason, .. } => write!(f, "validation failed: {}", reason),
            Self::UnknownChannel { .. } => write!(f, "unknown channel"),
            Self::AlreadyClosed {
                closed_balance,
                requested_balance,
                ..
            } => write!(
                f,
                "channel already closed with balance {} (requested {})",
                closed_balance, requested_balance
            ),
            Self::MintRejected { mint_error, .. } => {
                write!(f, "mint rejected swap: {}", mint_error)
            }
            Self::MintRejectedAfterRetry {
                original_error,
                retry_error,
                ..
            } => write!(
                f,
                "mint rejected swap after retry: original={}, retry={}",
                original_error, retry_error
            ),
            Self::UnblindFailed { reason, .. } => write!(f, "unblind failed: {}", reason),
            Self::StorageFailed { reason, .. } => write!(f, "storage failed: {}", reason),
        }
    }
}

impl std::error::Error for CloseError {}

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
    ChannelClosing,
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
            Self::ChannelClosing => write!(f, "channel closing, swap pending"),
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

    // 1. Unblind the signatures to get proofs
    let proofs = crate::dhke::construct_proofs(
        blind_signatures,
        blinding_factors,
        secrets,
        &output_keyset_info.active_keys,
    )
    .map_err(|e| BridgeError::Internal(format!("Failed to construct proofs: {}", e)))?;

    // 2. Verify DLEQ for each proof
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

    // 3. Separate proofs by is_receiver flag and compute sums
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

    // 4. Verify each receiver proof is P2PK locked to Charlie's per-proof blinded pubkey
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

    // 5. Verify receiver sum matches expected nominal for this balance
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

    /// Get a reference to the host
    pub fn host(&self) -> &H {
        &self.host
    }

    /// Decode a base64-encoded payment header into a PaymentRequest
    fn decode_payment_header(base64_header: &str) -> Result<PaymentRequest, BridgeError> {
        let decoded = BASE64
            .decode(base64_header)
            .map_err(|e| BridgeError::InvalidRequest(format!("invalid base64: {}", e)))?;
        let json = String::from_utf8(decoded)
            .map_err(|e| BridgeError::InvalidRequest(format!("invalid utf8: {}", e)))?;
        serde_json::from_str(&json).map_err(|e| BridgeError::InvalidRequest(e.to_string()))
    }

    /// Process an incoming payment (typed parameters)
    ///
    /// This is the core implementation that takes typed parameters.
    /// For JSON or base64 input, use the `*_via_json` or `*_via_base64_header` variants.
    ///
    /// Returns `PaymentSuccess` on success, `BridgeError` on failure.
    pub fn process_payment(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        funding_proofs: Option<&[Proof]>,
        context_json: &str,
    ) -> Result<PaymentSuccess, BridgeError> {
        // 1. Validate the payment (no side effects except saving funding for new channels)
        let validation = self.validate_payment(
            channel_id,
            balance,
            signature,
            params,
            funding_proofs,
            context_json,
        )?;

        // 2. Record successful payment (the side effect we're separating out)
        self.host.record_payment(
            &validation.channel_id,
            validation.balance,
            &validation.sender_signature,
            context_json,
        );

        // 3. Return success
        Ok(PaymentSuccess {
            channel_id: validation.channel_id,
            balance: validation.balance,
            amount_due: validation.amount_due,
            capacity: validation.capacity,
        })
    }

    /// Process an incoming payment from a JSON string
    ///
    /// This is a convenience wrapper that parses the JSON and calls `process_payment`.
    pub fn process_payment_via_json(
        &self,
        payment_json: &str,
        context_json: &str,
    ) -> Result<PaymentSuccess, BridgeError> {
        let payment: PaymentRequest = serde_json::from_str(payment_json)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        self.process_payment(
            &payment.channel_id,
            payment.balance,
            &payment.signature,
            payment.params.as_ref(),
            payment.funding_proofs.as_deref(),
            context_json,
        )
    }

    /// Process an incoming payment from a base64-encoded header
    ///
    /// This is a convenience wrapper that decodes the base64 header and calls `process_payment`.
    pub fn process_payment_via_base64_header(
        &self,
        base64_header: &str,
        context_json: &str,
    ) -> Result<PaymentSuccess, BridgeError> {
        let payment = Self::decode_payment_header(base64_header)?;
        self.process_payment(
            &payment.channel_id,
            payment.balance,
            &payment.signature,
            payment.params.as_ref(),
            payment.funding_proofs.as_deref(),
            context_json,
        )
    }

    /// Validate a payment without recording it (typed parameters)
    ///
    /// Performs all validation (channel verification, balance checks,
    /// signature verification) but does NOT call `record_payment`.
    ///
    /// For new channels, funding data IS saved via `save_funding` (idempotent).
    /// This is necessary because signature verification requires the shared secret
    /// which is computed and stored during channel setup.
    ///
    /// This is the core implementation that takes typed parameters.
    /// For JSON or base64 input, use the `*_via_json` or `*_via_base64_header` variants.
    ///
    /// Returns `PaymentValidationResult` with validation outcome on success.
    pub fn validate_payment(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        funding_proofs: Option<&[Proof]>,
        context_json: &str,
    ) -> Result<PaymentValidationResult, BridgeError> {
        // 1. Validate required fields
        if channel_id.is_empty() {
            return Err(BridgeError::InvalidRequest("missing channel_id".into()));
        }

        if signature.is_empty() {
            return Err(BridgeError::InvalidRequest("missing signature".into()));
        }

        // 2. Check channel state
        match self.host.get_channel_state(channel_id) {
            ChannelState::Closed => return Err(BridgeError::ChannelClosed),
            ChannelState::Closing => return Err(BridgeError::ChannelClosing),
            ChannelState::Open => {}
        }

        // 3. Resolve or verify funding (saves funding for new channels - idempotent)
        let (funding_and_params, is_new_channel) =
            match self.host.get_funding_and_params(channel_id) {
                Some(f) => (f, false),
                None => {
                    // Unknown channel - must provide params and funding_proofs
                    let params_val = params.ok_or(BridgeError::UnknownChannel)?;
                    let proofs = funding_proofs.ok_or(BridgeError::UnknownChannel)?;

                    // Perform full validation, signature verification, and save funding
                    let f = self.validate_and_save_new_channel(
                        channel_id, params_val, proofs, balance, signature,
                    )?;
                    (f, true)
                }
            };

        let (params_json, funding_proofs_json, shared_secret_hex, keyset_info_json) =
            funding_and_params;

        // 4. Parse params for capacity and unit checks
        let params_value: serde_json::Value = serde_json::from_str(&params_json)
            .map_err(|e| BridgeError::Internal(format!("failed to parse cached params: {}", e)))?;

        let capacity = params_value["capacity"].as_u64().unwrap_or(0);

        // For known channels, we still need to check balance and verify signature
        // (for new channels, validate_and_save_new_channel already did this)
        if !is_new_channel {
            // 5. Check balance doesn't exceed capacity
            if balance > capacity {
                return Err(BridgeError::BalanceExceedsCapacity { balance, capacity });
            }

            // 6. Verify signature
            self.verify_signature(
                &params_json,
                &funding_proofs_json,
                &shared_secret_hex,
                &keyset_info_json,
                channel_id,
                balance,
                signature,
            )
            .map_err(BridgeError::InvalidSignature)?;
        }

        // 7. Check balance against amount_due (always, for both new and known channels)
        let amount_due = self.host.get_amount_due(channel_id, Some(context_json));
        if balance < amount_due {
            return Err(BridgeError::InsufficientBalance {
                balance,
                amount_due,
            });
        }

        // 8. Return validation result (no record_payment call here)
        Ok(PaymentValidationResult {
            channel_id: channel_id.to_string(),
            balance,
            amount_due,
            capacity,
            sender_signature: signature.to_string(),
        })
    }

    /// Validate a payment from a JSON string
    ///
    /// This is a convenience wrapper that parses the JSON and calls `validate_payment`.
    pub fn validate_payment_via_json(
        &self,
        payment_json: &str,
        context_json: &str,
    ) -> Result<PaymentValidationResult, BridgeError> {
        let payment: PaymentRequest = serde_json::from_str(payment_json)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        self.validate_payment(
            &payment.channel_id,
            payment.balance,
            &payment.signature,
            payment.params.as_ref(),
            payment.funding_proofs.as_deref(),
            context_json,
        )
    }

    /// Validate a payment from a base64-encoded header
    ///
    /// This is a convenience wrapper that decodes the base64 header and calls `validate_payment`.
    pub fn validate_payment_via_base64_header(
        &self,
        base64_header: &str,
        context_json: &str,
    ) -> Result<PaymentValidationResult, BridgeError> {
        let payment = Self::decode_payment_header(base64_header)?;
        self.validate_payment(
            &payment.channel_id,
            payment.balance,
            &payment.signature,
            payment.params.as_ref(),
            payment.funding_proofs.as_deref(),
            context_json,
        )
    }

    /// Register/fund a channel without recording any usage (typed parameters)
    ///
    /// This validates the channel (params, funding proofs, signature) and saves it
    /// to the funding store, but does NOT record any payment/usage.
    ///
    /// The bridge accepts any balance value. Servers that want to enforce balance=0
    /// for registration should check this at the application layer before calling.
    ///
    /// This is the core implementation that takes typed parameters.
    /// For JSON or base64 input, use the `*_via_json` or `*_via_base64_header` variants.
    ///
    /// Returns `FundChannelResult` with channel info. Idempotent - calling multiple
    /// times with the same data succeeds with `already_known: true`.
    pub fn fund_channel(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        funding_proofs: Option<&[Proof]>,
    ) -> Result<FundChannelResult, BridgeError> {
        if channel_id.is_empty() {
            return Err(BridgeError::InvalidRequest("missing channel_id".into()));
        }

        if signature.is_empty() {
            return Err(BridgeError::InvalidRequest("missing signature".into()));
        }

        // 2. Check channel state
        match self.host.get_channel_state(channel_id) {
            ChannelState::Closed => return Err(BridgeError::ChannelClosed),
            ChannelState::Closing => return Err(BridgeError::ChannelClosing),
            ChannelState::Open => {}
        }

        // 3. Resolve or verify funding (saves funding for new channels - idempotent)
        let (funding_and_params, already_known) = match self.host.get_funding_and_params(channel_id)
        {
            Some(f) => (f, true),
            None => {
                // Unknown channel - must provide params and funding_proofs
                let params_val = params.ok_or(BridgeError::InvalidRequest(
                    "missing params for new channel".into(),
                ))?;
                let proofs = funding_proofs.ok_or(BridgeError::InvalidRequest(
                    "missing funding_proofs for new channel".into(),
                ))?;

                // Perform full validation, signature verification, and save funding
                let f = self.validate_and_save_new_channel(
                    channel_id, params_val, proofs, balance, signature,
                )?;
                (f, false)
            }
        };

        let (params_json, funding_proofs_json, shared_secret_hex, keyset_info_json) =
            funding_and_params;

        // 4. Parse params for capacity
        let params_value: serde_json::Value = serde_json::from_str(&params_json)
            .map_err(|e| BridgeError::Internal(format!("failed to parse cached params: {}", e)))?;

        let capacity = params_value["capacity"].as_u64().unwrap_or(0);

        // 5. For already-known channels, verify signature
        // (for new channels, validate_and_save_new_channel already did this)
        if already_known {
            self.verify_signature(
                &params_json,
                &funding_proofs_json,
                &shared_secret_hex,
                &keyset_info_json,
                channel_id,
                balance,
                signature,
            )
            .map_err(BridgeError::InvalidSignature)?;
        }

        // 6. Return success (no record_payment call)
        Ok(FundChannelResult {
            channel_id: channel_id.to_string(),
            capacity,
            already_known,
        })
    }

    /// Register/fund a channel from a JSON string
    ///
    /// This is a convenience wrapper that parses the JSON and calls `fund_channel`.
    pub fn fund_channel_via_json(
        &self,
        payment_json: &str,
    ) -> Result<FundChannelResult, BridgeError> {
        let payment: PaymentRequest = serde_json::from_str(payment_json)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        self.fund_channel(
            &payment.channel_id,
            payment.balance,
            &payment.signature,
            payment.params.as_ref(),
            payment.funding_proofs.as_deref(),
        )
    }

    /// Register/fund a channel from a base64-encoded header
    ///
    /// This is a convenience wrapper that decodes the base64 header and calls `fund_channel`.
    pub fn fund_channel_via_base64_header(
        &self,
        base64_header: &str,
    ) -> Result<FundChannelResult, BridgeError> {
        let payment = Self::decode_payment_header(base64_header)?;
        self.fund_channel(
            &payment.channel_id,
            payment.balance,
            &payment.signature,
            payment.params.as_ref(),
            payment.funding_proofs.as_deref(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_and_save_new_channel(
        &self,
        channel_id: &str,
        params_val: &serde_json::Value,
        funding_proofs: &[Proof],
        balance: u64,
        signature: &str,
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
        let _funding_token_amount =
            params_val["funding_token_amount"]
                .as_u64()
                .ok_or(BridgeError::InvalidRequest(
                    "missing funding_token_amount".into(),
                ))?;
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

        // Get keyset info from host
        let keyset_info_json = self
            .host
            .get_keyset_info(mint, &keyset_id)
            .ok_or(BridgeError::MintOrKeysetNotAcceptable)?;

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

        // 4. Check balance doesn't exceed capacity
        if balance > capacity {
            return Err(BridgeError::BalanceExceedsCapacity { balance, capacity });
        }

        let alice_pubkey_hex = params_val["alice_pubkey"]
            .as_str()
            .ok_or(BridgeError::InvalidRequest("missing alice_pubkey".into()))?;
        let alice_pubkey = PublicKey::from_hex(alice_pubkey_hex)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;

        // 5. Compute shared secret
        let shared_secret = super::compute_shared_secret(server_secret_key, &alice_pubkey);
        let shared_secret_hex = hex::encode(shared_secret);

        // 6. Parse keyset info
        let keyset_info = super::parse_keyset_info_from_json(&keyset_info_json)
            .map_err(BridgeError::InvalidRequest)?;

        // 7. Verify channel_id matches
        let params = ChannelParameters::from_json_with_shared_secret(
            &params_json,
            keyset_info.clone(),
            shared_secret,
        )
        .map_err(|e| BridgeError::Internal(e.to_string()))?;

        if params.get_channel_id() != channel_id {
            return Err(BridgeError::ChannelIdMismatch);
        }

        // 8. Verify DLEQ proofs
        let verification = verify_valid_channel(funding_proofs, &params);
        if !verification.valid {
            return Err(BridgeError::ValidationFailed(
                serde_json::to_string(&verification.errors)
                    .expect("ChannelVerificationError should always serialize"),
            ));
        }

        // 9. Verify signature for the initial balance
        let funding_proofs_json =
            serde_json::to_string(funding_proofs).expect("Vec<Proof> should always serialize");
        self.verify_signature(
            &params_json,
            &funding_proofs_json,
            &shared_secret_hex,
            &keyset_info_json,
            channel_id,
            balance,
            signature,
        )
        .map_err(BridgeError::InvalidSignature)?;

        // 10. Save to host (including initial balance and signature)
        self.host.save_funding(
            channel_id,
            &params_json,
            &funding_proofs_json,
            &shared_secret_hex,
            &keyset_info_json,
            balance,
            signature,
        );

        Ok((
            params_json,
            funding_proofs_json,
            shared_secret_hex,
            keyset_info_json,
        ))
    }

    #[allow(clippy::too_many_arguments)]
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
    /// Implementation helper for prepare_close_data.
    ///
    /// This contains the shared logic between cooperative and unilateral close:
    /// - Parse funding data
    /// - Find active output keyset
    /// - Create commitment outputs and swap request
    /// - Add both signatures (Alice's from the balance update, Charlie's from the server)
    /// - Collect secrets with blinding factors
    ///
    /// # Arguments
    /// * `channel_id` - The channel ID
    /// * `balance` - The balance to close at
    /// * `signature` - Alice's signature authorizing this balance
    /// * `funding_data` - Tuple of (params_json, funding_proofs_json, shared_secret_hex, keyset_info_json)
    /// * `validate_balance_equals_amount_due` - If true, verify balance == amount_due (for cooperative close)
    fn prepare_close_data_impl(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        funding_data: (String, String, String, String),
        validate_balance_equals_amount_due: bool,
    ) -> Result<CloseData, BridgeError> {
        let (params_json, funding_proofs_json, shared_secret_hex, keyset_info_json) = funding_data;

        // 1. Parse everything we need
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

        // 2. Check if the keyset is still active, if not switch to a new one
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

        // 3. Check balance doesn't exceed capacity
        if balance > params.capacity {
            return Err(BridgeError::BalanceExceedsCapacity {
                balance,
                capacity: params.capacity,
            });
        }

        // 4. Optionally check balance equals amount_due (for cooperative close)
        if validate_balance_equals_amount_due {
            let amount_due = self.host.get_amount_due(channel_id, None);
            if balance != amount_due {
                return Err(BridgeError::BalanceMismatch {
                    expected: amount_due,
                    actual: balance,
                });
            }
        }

        // 5. Parse signature
        let sig: bitcoin::secp256k1::schnorr::Signature = signature.parse().map_err(
            |e: <bitcoin::secp256k1::schnorr::Signature as FromStr>::Err| {
                BridgeError::InvalidSignature(e.to_string())
            },
        )?;

        // 6. Create commitment outputs and swap request
        let commitment_outputs = CommitmentOutputs::for_balance(balance, &params)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        let mut swap_request = commitment_outputs
            .create_swap_request(funding_proofs.clone(), Some(output_keyset_id))
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        // 7. Create balance update message
        let balance_update = BalanceUpdateMessage {
            channel_id: channel_id.to_string(),
            amount: balance,
            signature: sig,
        };

        // 8. Add Alice's signature to the swap request witness
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

        // 9. Create channel and receiver, verify + add Charlie's signature
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

        // 10. Get expected total (value after stage 1 fees) using the OUTPUT keyset
        let expected_total = params
            .get_value_after_stage1_with_keyset(&output_keyset_info)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        // 11. Collect secrets with blinding factors for unblinding
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

    /// Prepare close data for a channel given balance and signature.
    ///
    /// Handles both known channels (funding already stored) and unknown channels
    /// (params/funding_proofs provided for validation).
    ///
    /// This is the shared helper used by both cooperative and unilateral close.
    fn prepare_close_data(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        funding_proofs: Option<&[Proof]>,
        validate_balance_equals_amount_due: bool,
    ) -> Result<CloseData, BridgeError> {
        // 1. Check channel state - only reject if already fully closed
        // Note: We allow preparing close for channels in Closing state (for retry)
        if self.host.get_channel_state(channel_id) == ChannelState::Closed {
            return Err(BridgeError::ChannelClosed);
        }

        // 2. Get or validate funding
        let funding_data = match self.host.get_funding_and_params(channel_id) {
            Some(f) => f,
            None => {
                // Unknown channel - must provide params and funding_proofs
                let p = params.ok_or(BridgeError::UnknownChannel)?;
                let fp = funding_proofs.ok_or(BridgeError::UnknownChannel)?;
                self.validate_and_save_new_channel(channel_id, p, fp, balance, signature)?
            }
        };

        // 3. Build close data
        self.prepare_close_data_impl(
            channel_id,
            balance,
            signature,
            funding_data,
            validate_balance_equals_amount_due,
        )
    }

    /// Create the data needed to close a channel (cooperative close)
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
    pub fn validate_and_prepare_cooperative_close(
        &self,
        payment_json: &str,
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

        // 2. Delegate to helper
        self.prepare_close_data(
            &payment.channel_id,
            payment.balance,
            &payment.signature,
            payment.params.as_ref(),
            payment.funding_proofs.as_deref(),
            true, // validate_balance_equals_amount_due
        )
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
        // 1. Check channel exists first (so we return "unknown channel" not "no payment proof")
        if self.host.get_funding_and_params(channel_id).is_none() {
            return Err(BridgeError::UnknownChannel);
        }

        // 2. Get the balance and signature from host
        let (balance, signature) = self
            .host
            .get_balance_and_signature_for_unilateral_exit(channel_id)
            .ok_or_else(|| {
                BridgeError::InvalidRequest("no payment proof stored for channel".into())
            })?;

        // 3. Delegate to prepare_close_data (no params/proofs for unilateral, no balance validation)
        self.prepare_close_data(
            channel_id, balance, &signature, None,  // no params - channel must already exist
            None,  // no funding_proofs - channel must already exist
            false, // don't validate_balance_equals_amount_due
        )
    }

    /// Validate payment and prepare everything needed for cooperative close execution.
    ///
    /// This is the sync phase before any HTTP calls to the mint. It validates the
    /// payment request and prepares all data needed for the HTTP swap and subsequent
    /// finalization (unblinding).
    ///
    /// Returns either:
    /// - `Ok(PreparedClose)` - ready to POST `swap_request` to `mint_url/v1/swap`
    /// - `Err(ClosePreparationError)` - with HTTP-friendly status code
    ///
    /// After this succeeds, the caller should:
    /// 1. POST `swap_request` to `{mint_url}/v1/swap`
    /// 2. On mint error: call `refresh_active_keysets()`, re-call this method, retry step 1
    /// 3. Call `unblind_and_verify_dleq()` with the mint response
    /// 4. Call `host.mark_channel_closed()` with the unblinded proofs
    ///
    /// # Arguments
    /// * `payment_json` - JSON string with `channel_id`, `balance`, `signature`, and
    ///   optionally `params` and `funding_proofs` for new channels
    pub fn prepare_cooperative_close_for_execution(
        &self,
        payment_json: &str,
    ) -> Result<PreparedClose, ClosePreparationError> {
        // 1. Parse payment_json to extract channel_id and balance for later
        let payment: serde_json::Value = serde_json::from_str(payment_json).map_err(|e| {
            ClosePreparationError::bad_request(format!("Invalid payment JSON: {}", e))
        })?;

        let channel_id = payment["channel_id"]
            .as_str()
            .ok_or_else(|| ClosePreparationError::bad_request("missing channel_id"))?
            .to_string();

        let balance = payment["balance"]
            .as_u64()
            .ok_or_else(|| ClosePreparationError::bad_request("missing balance"))?;

        // 2. Validate and prepare (this does signature verification, balance checks, etc.)
        let close_data = self
            .validate_and_prepare_cooperative_close(payment_json)
            .map_err(ClosePreparationError::from_bridge_error)?;

        // 3. Get funding data for unblinding phase
        let (params_json, _funding_proofs_json, shared_secret, keyset_info_json) = self
            .host
            .get_funding_and_params(&channel_id)
            .ok_or_else(|| ClosePreparationError::internal("channel not found after validation"))?;

        // 4. Extract mint_url from params
        let params: serde_json::Value = serde_json::from_str(&params_json)
            .map_err(|e| ClosePreparationError::internal(format!("Invalid params JSON: {}", e)))?;

        let mint_url = params["mint"]
            .as_str()
            .ok_or_else(|| ClosePreparationError::internal("missing mint in params"))?
            .to_string();

        // 5. Convert CloseData to PreparedClose (JSON values for FFI)
        Ok(PreparedClose {
            channel_id,
            balance,
            mint_url,
            swap_request: serde_json::to_value(&close_data.swap_request)
                .unwrap_or(serde_json::Value::Null),
            secrets_with_blinding: close_data
                .secrets_with_blinding
                .iter()
                .map(|(s, is_receiver)| {
                    serde_json::json!({
                        "secret": s.secret.to_string(),
                        "blinding_factor": hex::encode(s.blinding_factor.secret_bytes()),
                        "amount": s.amount,
                        "index": s.index,
                        "is_receiver": is_receiver
                    })
                })
                .collect(),
            output_keyset_info: serde_json::to_value(&close_data.output_keyset_info)
                .unwrap_or(serde_json::Value::Null),
            params_json,
            keyset_info_json,
            shared_secret,
        })
    }

    /// Prepare everything needed for unilateral (server-initiated) close execution.
    ///
    /// Same as `prepare_cooperative_close_for_execution` but uses the stored payment
    /// proof instead of requiring a client-provided signature.
    ///
    /// Returns either:
    /// - `Ok(PreparedClose)` - ready to POST `swap_request` to `mint_url/v1/swap`
    /// - `Err(ClosePreparationError)` - with HTTP-friendly status code:
    ///   - 400: channel already closed, or no payment recorded
    ///   - 404: unknown channel
    ///   - 500: internal error
    ///
    /// # Arguments
    /// * `channel_id` - The channel ID to close
    pub fn prepare_unilateral_close_for_execution(
        &self,
        channel_id: &str,
    ) -> Result<PreparedClose, ClosePreparationError> {
        // 1. Create close data (this checks channel exists, gets stored payment, validates)
        let close_data = self
            .create_unilateral_close_data(channel_id)
            .map_err(ClosePreparationError::from_bridge_error)?;

        // 2. Get funding data for unblinding phase
        let (params_json, _funding_proofs_json, shared_secret, keyset_info_json) = self
            .host
            .get_funding_and_params(channel_id)
            .ok_or_else(|| ClosePreparationError::internal("channel not found after validation"))?;

        // 3. Get balance from host (we need it for PreparedClose)
        let (balance, _signature) = self
            .host
            .get_balance_and_signature_for_unilateral_exit(channel_id)
            .ok_or_else(|| ClosePreparationError::internal("balance not found after validation"))?;

        // 4. Extract mint_url from params
        let params: serde_json::Value = serde_json::from_str(&params_json)
            .map_err(|e| ClosePreparationError::internal(format!("Invalid params JSON: {}", e)))?;

        let mint_url = params["mint"]
            .as_str()
            .ok_or_else(|| ClosePreparationError::internal("missing mint in params"))?
            .to_string();

        // 5. Convert CloseData to PreparedClose (JSON values for FFI)
        Ok(PreparedClose {
            channel_id: channel_id.to_string(),
            balance,
            mint_url,
            swap_request: serde_json::to_value(&close_data.swap_request)
                .unwrap_or(serde_json::Value::Null),
            secrets_with_blinding: close_data
                .secrets_with_blinding
                .iter()
                .map(|(s, is_receiver)| {
                    serde_json::json!({
                        "secret": s.secret.to_string(),
                        "blinding_factor": hex::encode(s.blinding_factor.secret_bytes()),
                        "amount": s.amount,
                        "index": s.index,
                        "is_receiver": is_receiver
                    })
                })
                .collect(),
            output_keyset_info: serde_json::to_value(&close_data.output_keyset_info)
                .unwrap_or(serde_json::Value::Null),
            params_json,
            keyset_info_json,
            shared_secret,
        })
    }

    /// Execute close for a channel that is already in CLOSING state.
    ///
    /// This is the unified method for completing a close operation. It can be called:
    /// 1. Immediately after `mark_channel_closing()` (initial attempt)
    /// 2. Later as a retry if the initial swap failed
    ///
    /// The method:
    /// 1. Retrieves closing data from the host (locktime, balance, signature)
    /// 2. Rebuilds the swap request from closing data + funding data
    /// 3. Submits swap to the mint
    /// 4. On mint error: refreshes keysets, rebuilds swap, retries once
    /// 5. Unblinds and verifies DLEQ proofs
    /// 6. Calls `mark_channel_closed()` with the final proofs
    ///
    /// # Arguments
    /// * `channel_id` - The channel ID (must be in CLOSING state)
    ///
    /// # Returns
    /// * `Ok(CloseSuccess)` - Channel successfully closed, contains proofs
    /// * `Err(CloseError)` - Close failed (validation, mint rejection, etc.)
    pub fn execute_close_for_closing_channel(
        &self,
        channel_id: &str,
    ) -> Result<CloseSuccess, CloseError> {
        // 1. Verify channel is in CLOSING state
        match self.host.get_channel_state(channel_id) {
            ChannelState::Open => {
                return Err(CloseError::ValidationFailed {
                    reason: "channel is OPEN, not CLOSING".to_string(),
                    status: 400,
                    expected_balance: None,
                    actual_balance: None,
                });
            }
            ChannelState::Closed => {
                // Already closed - this is idempotent
                // We need to return the stored proofs if we have them
                // For now, return an error indicating it's already closed
                return Err(CloseError::ValidationFailed {
                    reason: "channel is already CLOSED".to_string(),
                    status: 400,
                    expected_balance: None,
                    actual_balance: None,
                });
            }
            ChannelState::Closing => {
                // Expected state, continue
            }
        }

        // 2. Get closing data from host
        let closing_data =
            self.host
                .get_closing_data(channel_id)
                .ok_or_else(|| CloseError::ValidationFailed {
                    reason: "channel in CLOSING state but no closing data found".to_string(),
                    status: 500,
                    expected_balance: None,
                    actual_balance: None,
                })?;

        // 3. Get funding data
        let (params_json, _funding_proofs_json, shared_secret_hex, keyset_info_json) = self
            .host
            .get_funding_and_params(channel_id)
            .ok_or_else(|| CloseError::ValidationFailed {
                reason: "channel in CLOSING state but no funding data found".to_string(),
                status: 500,
                expected_balance: None,
                actual_balance: None,
            })?;

        // 4. Extract mint URL from params
        let params: serde_json::Value =
            serde_json::from_str(&params_json).map_err(|e| CloseError::ValidationFailed {
                reason: format!("invalid params JSON: {}", e),
                status: 500,
                expected_balance: None,
                actual_balance: None,
            })?;

        let mint_url = params["mint"]
            .as_str()
            .ok_or_else(|| CloseError::ValidationFailed {
                reason: "missing mint in params".to_string(),
                status: 500,
                expected_balance: None,
                actual_balance: None,
            })?
            .to_string();

        // 5. Prepare the close data (same as cooperative close, but with stored signature)
        let prepared = self
            .prepare_close_data(
                channel_id,
                closing_data.balance,
                &closing_data.signature,
                None,  // no params - channel already exists
                None,  // no funding_proofs - channel already exists
                false, // don't validate balance == amount_due (that was done when marking CLOSING)
            )
            .map_err(|e| {
                CloseError::from_preparation_error(ClosePreparationError::from_bridge_error(e))
            })?;

        // 6. Helper function to execute swap and unblind
        let execute_swap = |close_data: &CloseData,
                            output_keyset_info_json: &str|
         -> Result<CloseSuccess, CloseError> {
            // Submit swap to mint
            let swap_request_json =
                serde_json::to_string(&close_data.swap_request).map_err(|e| {
                    CloseError::ValidationFailed {
                        reason: format!("failed to serialize swap request: {}", e),
                        status: 500,
                        expected_balance: None,
                        actual_balance: None,
                    }
                })?;

            let swap_response_json = self
                .host
                .call_mint_swap(&mint_url, &swap_request_json)
                .map_err(|e| {
                    // Try to parse as JSON for structured error
                    let mint_error = serde_json::from_str(&e)
                        .unwrap_or_else(|_| serde_json::json!({"error": e}));
                    CloseError::mint_rejected(mint_error)
                })?;

            // Parse response to get blind signatures
            let swap_response: serde_json::Value = serde_json::from_str(&swap_response_json)
                .map_err(|e| CloseError::UnblindFailed {
                    reason: format!("invalid swap response JSON: {}", e),
                    status: 500,
                })?;

            let blind_signatures_json = swap_response["signatures"].to_string();

            // Prepare secrets_with_blinding for unblind function
            let secrets_with_blinding_json: String = serde_json::to_string(
                &close_data
                    .secrets_with_blinding
                    .iter()
                    .map(|(s, is_receiver)| {
                        serde_json::json!({
                            "secret": s.secret.to_string(),
                            "blinding_factor": hex::encode(s.blinding_factor.secret_bytes()),
                            "amount": s.amount,
                            "index": s.index,
                            "is_receiver": is_receiver
                        })
                    })
                    .collect::<Vec<_>>(),
            )
            .map_err(|e| CloseError::UnblindFailed {
                reason: format!("failed to serialize secrets: {}", e),
                status: 500,
            })?;

            // Unblind and verify
            let unblind_result_json = unblind_and_verify_dleq(
                &blind_signatures_json,
                &secrets_with_blinding_json,
                &params_json,
                &keyset_info_json,
                &shared_secret_hex,
                closing_data.balance,
                Some(output_keyset_info_json),
            )
            .map_err(CloseError::unblind_failed)?;

            let unblind_result: serde_json::Value = serde_json::from_str(&unblind_result_json)
                .map_err(|e| CloseError::UnblindFailed {
                    reason: format!("invalid unblind result JSON: {}", e),
                    status: 500,
                })?;

            let receiver_proofs_json = unblind_result["receiver_proofs"].to_string();
            let sender_proofs_json = unblind_result["sender_proofs"].to_string();
            let receiver_sum = unblind_result["receiver_sum_after_stage1"]
                .as_u64()
                .unwrap_or(0);
            let sender_sum = unblind_result["sender_sum_after_stage1"]
                .as_u64()
                .unwrap_or(0);

            // Mark channel as closed
            self.host
                .mark_channel_closed(
                    channel_id,
                    closing_data.locktime,
                    closing_data.balance,
                    &receiver_proofs_json,
                    &sender_proofs_json,
                    receiver_sum,
                    sender_sum,
                )
                .map_err(CloseError::storage_failed)?;

            Ok(CloseSuccess {
                channel_id: channel_id.to_string(),
                total_value: receiver_sum + sender_sum,
                receiver_sum,
                sender_sum,
                sender_proofs: sender_proofs_json,
                already_closed: false,
            })
        };

        // Serialize output keyset info for unblinding
        let output_keyset_info_json =
            serde_json::to_string(&prepared.output_keyset_info).map_err(|e| {
                CloseError::ValidationFailed {
                    reason: format!("failed to serialize output keyset info: {}", e),
                    status: 500,
                    expected_balance: None,
                    actual_balance: None,
                }
            })?;

        // 7. First attempt
        match execute_swap(&prepared, &output_keyset_info_json) {
            Ok(success) => Ok(success),
            Err(CloseError::MintRejected { mint_error, .. }) => {
                // 8. Refresh keysets and retry
                if self.host.refresh_active_keysets(&mint_url).is_err() {
                    // Refresh failed, return original error
                    return Err(CloseError::mint_rejected(mint_error));
                }

                // Re-prepare with potentially new keyset
                let prepared_retry = self
                    .prepare_close_data(
                        channel_id,
                        closing_data.balance,
                        &closing_data.signature,
                        None,
                        None,
                        false,
                    )
                    .map_err(|e| {
                        CloseError::from_preparation_error(
                            ClosePreparationError::from_bridge_error(e),
                        )
                    })?;

                let output_keyset_info_json_retry =
                    serde_json::to_string(&prepared_retry.output_keyset_info).map_err(|e| {
                        CloseError::ValidationFailed {
                            reason: format!("failed to serialize output keyset info: {}", e),
                            status: 500,
                            expected_balance: None,
                            actual_balance: None,
                        }
                    })?;

                // Retry
                match execute_swap(&prepared_retry, &output_keyset_info_json_retry) {
                    Ok(success) => Ok(success),
                    Err(CloseError::MintRejected {
                        mint_error: retry_error,
                        ..
                    }) => Err(CloseError::mint_rejected_after_retry(
                        mint_error,
                        retry_error,
                    )),
                    Err(other) => Err(other),
                }
            }
            Err(other) => Err(other),
        }
    }

    /// Execute a cooperative close: mark as CLOSING then execute the swap.
    ///
    /// This is the high-level method that combines:
    /// 1. Validating the close request
    /// 2. Marking the channel as CLOSING
    /// 3. Executing the swap via `execute_close_for_closing_channel`
    ///
    /// If the swap fails, the channel remains in CLOSING state and can be
    /// retried by calling `execute_close_for_closing_channel` directly.
    ///
    /// # Arguments
    /// * `payment_json` - JSON with channel_id, balance, signature
    ///
    /// # Returns
    /// * `Ok(CloseSuccess)` - Channel successfully closed
    /// * `Err(CloseError)` - Close failed
    pub fn execute_cooperative_close(
        &self,
        payment_json: &str,
    ) -> Result<CloseSuccess, CloseError> {
        // 1. Parse and validate the close request
        let prepared = self
            .prepare_cooperative_close_for_execution(payment_json)
            .map_err(CloseError::from_preparation_error)?;

        // 2. Get locktime from params
        let params: serde_json::Value =
            serde_json::from_str(&prepared.params_json).map_err(|e| {
                CloseError::ValidationFailed {
                    reason: format!("invalid params JSON: {}", e),
                    status: 500,
                    expected_balance: None,
                    actual_balance: None,
                }
            })?;
        let locktime = params["locktime"].as_u64().unwrap_or(0);

        // 3. Extract signature from payment_json
        let payment: serde_json::Value =
            serde_json::from_str(payment_json).map_err(|e| CloseError::ValidationFailed {
                reason: format!("invalid payment JSON: {}", e),
                status: 400,
                expected_balance: None,
                actual_balance: None,
            })?;
        let signature =
            payment["signature"]
                .as_str()
                .ok_or_else(|| CloseError::ValidationFailed {
                    reason: "missing signature".to_string(),
                    status: 400,
                    expected_balance: None,
                    actual_balance: None,
                })?;

        // 4. Mark channel as CLOSING
        self.host
            .mark_channel_closing(&prepared.channel_id, locktime, prepared.balance, signature)
            .map_err(CloseError::storage_failed)?;

        // 5. Execute the close
        self.execute_close_for_closing_channel(&prepared.channel_id)
    }

    /// Execute a unilateral close: mark as CLOSING then execute the swap.
    ///
    /// This is the high-level method for server-initiated close that combines:
    /// 1. Getting the stored payment proof
    /// 2. Marking the channel as CLOSING
    /// 3. Executing the swap via `execute_close_for_closing_channel`
    ///
    /// # Arguments
    /// * `channel_id` - The channel ID to close
    ///
    /// # Returns
    /// * `Ok(CloseSuccess)` - Channel successfully closed
    /// * `Err(CloseError)` - Close failed
    pub fn execute_unilateral_close(&self, channel_id: &str) -> Result<CloseSuccess, CloseError> {
        // 1. Prepare the close to validate and get balance/signature
        let prepared = self
            .prepare_unilateral_close_for_execution(channel_id)
            .map_err(CloseError::from_preparation_error)?;

        // 2. Get locktime and signature from stored data
        let params: serde_json::Value =
            serde_json::from_str(&prepared.params_json).map_err(|e| {
                CloseError::ValidationFailed {
                    reason: format!("invalid params JSON: {}", e),
                    status: 500,
                    expected_balance: None,
                    actual_balance: None,
                }
            })?;
        let locktime = params["locktime"].as_u64().unwrap_or(0);

        let (_, signature) = self
            .host
            .get_balance_and_signature_for_unilateral_exit(channel_id)
            .ok_or_else(|| CloseError::ValidationFailed {
                reason: "no payment proof stored".to_string(),
                status: 400,
                expected_balance: None,
                actual_balance: None,
            })?;

        // 3. Mark channel as CLOSING
        self.host
            .mark_channel_closing(channel_id, locktime, prepared.balance, &signature)
            .map_err(CloseError::storage_failed)?;

        // 4. Execute the close
        self.execute_close_for_closing_channel(channel_id)
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
            _initial_balance: u64,
            _initial_signature: &str,
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

        fn get_channel_state(&self, _channel_id: &str) -> ChannelState {
            ChannelState::Open
        }

        fn mark_channel_closing(
            &self,
            _channel_id: &str,
            _locktime: u64,
            _balance: u64,
            _signature: &str,
        ) -> Result<(), String> {
            Ok(())
        }

        fn get_closing_data(&self, _channel_id: &str) -> Option<ClosingData> {
            None
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

        fn call_mint_swap(
            &self,
            _mint_url: &str,
            _swap_request_json: &str,
        ) -> Result<String, String> {
            Err("not implemented".to_string())
        }

        fn mark_channel_closed(
            &self,
            _channel_id: &str,
            _locktime: u64,
            _balance: u64,
            _receiver_proofs_json: &str,
            _sender_proofs_json: &str,
            _receiver_sum: u64,
            _sender_sum: u64,
        ) -> Result<(), String> {
            Ok(())
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
            "funding_token_amount": 1000,
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

        let _keyset_info = serde_json::json!({
            "keysetId": "00aabbccddeeff00",
            "unit": "sat",
            "inputFeePpk": 0,
            "keys": {}
        });

        let result = bridge.process_payment_via_json(&payment.to_string(), "{}");

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("receiver key not acceptable"));
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
            "funding_token_amount": 1000,
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

        let _keyset_info = serde_json::json!({
            "keysetId": "00aabbccddeeff00",
            "unit": "sat",
            "inputFeePpk": 0,
            "keys": {}
        });

        let result = bridge.process_payment_via_json(&payment.to_string(), "{}");

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("mint or keyset not acceptable"));
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
            _initial_balance: u64,
            _initial_signature: &str,
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
        fn get_channel_state(&self, _channel_id: &str) -> ChannelState {
            ChannelState::Open
        }
        fn mark_channel_closing(
            &self,
            _channel_id: &str,
            _locktime: u64,
            _balance: u64,
            _signature: &str,
        ) -> Result<(), String> {
            Ok(())
        }
        fn get_closing_data(&self, _channel_id: &str) -> Option<ClosingData> {
            None
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

        fn call_mint_swap(
            &self,
            _mint_url: &str,
            _swap_request_json: &str,
        ) -> Result<String, String> {
            Err("not implemented".to_string())
        }

        fn mark_channel_closed(
            &self,
            _channel_id: &str,
            _locktime: u64,
            _balance: u64,
            _receiver_proofs_json: &str,
            _sender_proofs_json: &str,
            _receiver_sum: u64,
            _sender_sum: u64,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn test_validate_and_prepare_cooperative_close_with_keyset_rotation() {
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
            funding_token_amount: 1000,
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
        let close_data = bridge
            .validate_and_prepare_cooperative_close(&payment_json)
            .unwrap();

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

    /// Mock host that simulates keyset refresh behavior
    ///
    /// Initially returns `stale_keyset_id` as the active keyset.
    /// After `refresh_active_keysets()` is called, returns `fresh_keyset_id`.
    /// This simulates the real-world scenario where a mint deactivates a keyset
    /// and the server needs to refresh its cache to discover the new active keyset.
    struct RefreshableMockHost {
        /// Active keyset IDs (mutable via RefCell to simulate refresh)
        active_keyset_ids: std::cell::RefCell<Vec<Id>>,
        /// Count of refresh calls (for verification)
        refresh_count: std::cell::Cell<u32>,
        /// The keyset ID to switch to after refresh
        fresh_keyset_id: Id,
        /// All known keyset infos (both stale and fresh)
        keyset_infos: std::collections::HashMap<Id, String>,
        /// Channel funding data
        funding_data: std::collections::HashMap<String, (String, String, String, String)>,
        /// Amount due for closing
        amount_due: u64,
        /// Stored payment for unilateral close (balance, signature)
        stored_payment: Option<(u64, String)>,
    }

    impl SpilmanHost for RefreshableMockHost {
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
            _initial_balance: u64,
            _initial_signature: &str,
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

        fn get_channel_state(&self, _channel_id: &str) -> ChannelState {
            ChannelState::Open
        }

        fn mark_channel_closing(
            &self,
            _channel_id: &str,
            _locktime: u64,
            _balance: u64,
            _signature: &str,
        ) -> Result<(), String> {
            Ok(())
        }

        fn get_closing_data(&self, _channel_id: &str) -> Option<ClosingData> {
            None
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
            self.stored_payment.clone()
        }

        fn get_active_keyset_ids(&self, _mint: &str, _unit: &CurrencyUnit) -> Vec<Id> {
            self.active_keyset_ids.borrow().clone()
        }

        fn get_keyset_info(&self, _mint: &str, keyset_id: &Id) -> Option<String> {
            self.keyset_infos.get(keyset_id).cloned()
        }

        fn refresh_active_keysets(&self, _mint: &str) -> Result<(), String> {
            // Simulate fetching from mint and discovering new active keyset
            *self.active_keyset_ids.borrow_mut() = vec![self.fresh_keyset_id];
            self.refresh_count.set(self.refresh_count.get() + 1);
            Ok(())
        }

        fn call_mint_swap(
            &self,
            _mint_url: &str,
            _swap_request_json: &str,
        ) -> Result<String, String> {
            // Not used in these tests - we're testing prepare, not execute
            Err("not implemented".to_string())
        }

        fn mark_channel_closed(
            &self,
            _channel_id: &str,
            _locktime: u64,
            _balance: u64,
            _receiver_proofs_json: &str,
            _sender_proofs_json: &str,
            _receiver_sum: u64,
            _sender_sum: u64,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    /// Test: Cooperative close uses refreshed keysets after refresh_active_keysets()
    ///
    /// Simulates the retry scenario where:
    /// 1. First prepare uses stale keyset (which would fail at mint)
    /// 2. After refresh_active_keysets(), second prepare uses fresh keyset
    ///
    /// This verifies the retry logic works correctly - when a swap fails due to
    /// stale keyset, refreshing and re-preparing will use the new keyset.
    ///
    /// Migrated from planned TypeScript test:
    /// "retries cooperative close with refreshed keysets when first swap fails"
    #[test]
    fn test_cooperative_close_retries_with_refreshed_keysets() {
        use crate::nuts::Proof;
        use crate::secret::Secret;
        use crate::spilman::params::mock_keyset_info;
        use crate::spilman::{
            compute_shared_secret, ChannelParameters, EstablishedChannel, SpilmanChannelSender,
        };

        let alice_sk = SecretKey::generate();
        let charlie_sk = SecretKey::generate();
        let shared_secret = compute_shared_secret(&alice_sk, &charlie_sk.public_key());

        // Create "stale" keyset (the one initially cached, but deactivated at mint)
        let keyset_stale = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 0);
        let keyset_stale_id = keyset_stale.keyset_id;

        // Create "fresh" keyset (the new active one after refresh)
        let mut keyset_fresh = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100); // Different fee
        let keyset_fresh_id = Id::from_str("00000000000000ff").unwrap();
        keyset_fresh.keyset_id = keyset_fresh_id;

        // Setup channel params (funded with stale keyset)
        let params_struct = ChannelParameters {
            alice_pubkey: alice_sk.public_key(),
            charlie_pubkey: charlie_sk.public_key(),
            mint: "https://mint.host".to_string(),
            unit: CurrencyUnit::Sat,
            capacity: 1000,
            funding_token_amount: 1000,
            maximum_amount_for_one_output: 64,
            setup_timestamp: 1700000000,
            locktime: 1700003600,
            sender_nonce: "test-refresh-coop".to_string(),
            keyset_info: keyset_stale.clone(),
            shared_secret,
        };
        let channel_id = params_struct.get_channel_id();
        let balance = 100;

        // Funding proofs (keyset doesn't matter for this test)
        let proofs = vec![Proof {
            amount: 1000.into(),
            secret: Secret::new("funding".to_string()),
            c: PublicKey::from_str(
                "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
            )
            .unwrap(),
            keyset_id: keyset_stale_id,
            dleq: None,
            witness: None,
        }];

        // Create refreshable mock host
        // Initially returns stale keyset as active, switches to fresh after refresh
        let host = RefreshableMockHost {
            active_keyset_ids: std::cell::RefCell::new(vec![keyset_stale_id]), // Initially stale
            refresh_count: std::cell::Cell::new(0),
            fresh_keyset_id: keyset_fresh_id,
            keyset_infos: vec![
                (
                    keyset_stale_id,
                    serde_json::to_string(&keyset_stale).unwrap(),
                ),
                (
                    keyset_fresh_id,
                    serde_json::to_string(&keyset_fresh).unwrap(),
                ),
            ]
            .into_iter()
            .collect(),
            funding_data: vec![(
                channel_id.clone(),
                (
                    params_struct.get_channel_id_params_json(),
                    serde_json::to_string(&proofs).unwrap(),
                    hex::encode(shared_secret),
                    serde_json::to_string(&keyset_stale).unwrap(),
                ),
            )]
            .into_iter()
            .collect(),
            amount_due: balance,
            stored_payment: None,
        };

        let bridge = SpilmanBridge::new(host, Some(charlie_sk.clone()));

        // Create signed balance update
        let channel = EstablishedChannel::new(params_struct.clone(), proofs.clone()).unwrap();
        let sender = SpilmanChannelSender::new(alice_sk, channel);
        let (balance_update, _) = sender.create_signed_balance_update(balance).unwrap();

        let payment_json = serde_json::json!({
            "channel_id": channel_id,
            "balance": balance,
            "signature": balance_update.signature.to_string(),
        })
        .to_string();

        // STEP 1: First prepare - should use stale keyset (would fail at mint)
        let prepared_first = bridge
            .prepare_cooperative_close_for_execution(&payment_json)
            .expect("First prepare should succeed");

        // Verify first prepare uses stale keyset for outputs
        let first_swap: serde_json::Value =
            serde_json::from_value(prepared_first.swap_request.clone()).unwrap();
        let first_outputs = first_swap["outputs"].as_array().unwrap();
        for output in first_outputs {
            let output_keyset = output["id"].as_str().unwrap();
            assert_eq!(
                output_keyset,
                keyset_stale_id.to_string(),
                "First prepare should use stale keyset"
            );
        }
        println!("✓ First prepare uses stale keyset: {}", keyset_stale_id);

        // Verify refresh hasn't been called yet
        assert_eq!(
            bridge.host().refresh_count.get(),
            0,
            "Refresh should not have been called yet"
        );

        // STEP 2: Simulate mint error - call refresh_active_keysets
        bridge
            .host()
            .refresh_active_keysets("https://mint.host")
            .expect("Refresh should succeed");

        assert_eq!(
            bridge.host().refresh_count.get(),
            1,
            "Refresh should have been called once"
        );
        println!("✓ refresh_active_keysets() called");

        // STEP 3: Second prepare - should now use fresh keyset
        let prepared_second = bridge
            .prepare_cooperative_close_for_execution(&payment_json)
            .expect("Second prepare should succeed");

        // Verify second prepare uses fresh keyset for outputs
        let second_swap: serde_json::Value =
            serde_json::from_value(prepared_second.swap_request.clone()).unwrap();
        let second_outputs = second_swap["outputs"].as_array().unwrap();
        for output in second_outputs {
            let output_keyset = output["id"].as_str().unwrap();
            assert_eq!(
                output_keyset,
                keyset_fresh_id.to_string(),
                "Second prepare should use fresh keyset"
            );
        }
        println!("✓ Second prepare uses fresh keyset: {}", keyset_fresh_id);

        // Verify the swap requests are different (different keyset IDs)
        assert_ne!(
            first_outputs[0]["id"], second_outputs[0]["id"],
            "Swap requests should use different keysets"
        );
        println!("✓ Retry would use different keyset after refresh");
    }

    /// Test: Unilateral close uses refreshed keysets after refresh_active_keysets()
    ///
    /// Same pattern as cooperative close test, but for server-initiated close.
    ///
    /// Migrated from planned TypeScript test:
    /// "retries unilateral close with refreshed keysets when first swap fails"
    #[test]
    fn test_unilateral_close_retries_with_refreshed_keysets() {
        use crate::nuts::Proof;
        use crate::secret::Secret;
        use crate::spilman::params::mock_keyset_info;
        use crate::spilman::{
            compute_shared_secret, ChannelParameters, EstablishedChannel, SpilmanChannelSender,
        };

        let alice_sk = SecretKey::generate();
        let charlie_sk = SecretKey::generate();
        let shared_secret = compute_shared_secret(&alice_sk, &charlie_sk.public_key());

        // Create "stale" keyset
        let keyset_stale = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 0);
        let keyset_stale_id = keyset_stale.keyset_id;

        // Create "fresh" keyset
        let mut keyset_fresh = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);
        let keyset_fresh_id = Id::from_str("00000000000000fe").unwrap();
        keyset_fresh.keyset_id = keyset_fresh_id;

        // Setup channel params
        let params_struct = ChannelParameters {
            alice_pubkey: alice_sk.public_key(),
            charlie_pubkey: charlie_sk.public_key(),
            mint: "https://mint.host".to_string(),
            unit: CurrencyUnit::Sat,
            capacity: 1000,
            funding_token_amount: 1000,
            maximum_amount_for_one_output: 64,
            setup_timestamp: 1700000000,
            locktime: 1700003600,
            sender_nonce: "test-refresh-unilateral".to_string(),
            keyset_info: keyset_stale.clone(),
            shared_secret,
        };
        let channel_id = params_struct.get_channel_id();
        let balance = 200;

        // Funding proofs
        let proofs = vec![Proof {
            amount: 1000.into(),
            secret: Secret::new("funding".to_string()),
            c: PublicKey::from_str(
                "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
            )
            .unwrap(),
            keyset_id: keyset_stale_id,
            dleq: None,
            witness: None,
        }];

        // Create signed balance update (for stored payment)
        let channel = EstablishedChannel::new(params_struct.clone(), proofs.clone()).unwrap();
        let sender = SpilmanChannelSender::new(alice_sk, channel);
        let (balance_update, _) = sender.create_signed_balance_update(balance).unwrap();

        // Create refreshable mock host with stored payment for unilateral close
        let host = RefreshableMockHost {
            active_keyset_ids: std::cell::RefCell::new(vec![keyset_stale_id]),
            refresh_count: std::cell::Cell::new(0),
            fresh_keyset_id: keyset_fresh_id,
            keyset_infos: vec![
                (
                    keyset_stale_id,
                    serde_json::to_string(&keyset_stale).unwrap(),
                ),
                (
                    keyset_fresh_id,
                    serde_json::to_string(&keyset_fresh).unwrap(),
                ),
            ]
            .into_iter()
            .collect(),
            funding_data: vec![(
                channel_id.clone(),
                (
                    params_struct.get_channel_id_params_json(),
                    serde_json::to_string(&proofs).unwrap(),
                    hex::encode(shared_secret),
                    serde_json::to_string(&keyset_stale).unwrap(),
                ),
            )]
            .into_iter()
            .collect(),
            amount_due: balance,
            // Stored payment for unilateral close
            stored_payment: Some((balance, balance_update.signature.to_string())),
        };

        let bridge = SpilmanBridge::new(host, Some(charlie_sk.clone()));

        // STEP 1: First prepare - should use stale keyset
        let prepared_first = bridge
            .prepare_unilateral_close_for_execution(&channel_id)
            .expect("First prepare should succeed");

        // Verify first prepare uses stale keyset
        let first_swap: serde_json::Value =
            serde_json::from_value(prepared_first.swap_request.clone()).unwrap();
        let first_outputs = first_swap["outputs"].as_array().unwrap();
        for output in first_outputs {
            let output_keyset = output["id"].as_str().unwrap();
            assert_eq!(
                output_keyset,
                keyset_stale_id.to_string(),
                "First prepare should use stale keyset"
            );
        }
        println!(
            "✓ First unilateral prepare uses stale keyset: {}",
            keyset_stale_id
        );

        // STEP 2: Simulate mint error - call refresh
        bridge
            .host()
            .refresh_active_keysets("https://mint.host")
            .expect("Refresh should succeed");

        assert_eq!(bridge.host().refresh_count.get(), 1);
        println!("✓ refresh_active_keysets() called");

        // STEP 3: Second prepare - should use fresh keyset
        let prepared_second = bridge
            .prepare_unilateral_close_for_execution(&channel_id)
            .expect("Second prepare should succeed");

        // Verify second prepare uses fresh keyset
        let second_swap: serde_json::Value =
            serde_json::from_value(prepared_second.swap_request.clone()).unwrap();
        let second_outputs = second_swap["outputs"].as_array().unwrap();
        for output in second_outputs {
            let output_keyset = output["id"].as_str().unwrap();
            assert_eq!(
                output_keyset,
                keyset_fresh_id.to_string(),
                "Second prepare should use fresh keyset"
            );
        }
        println!(
            "✓ Second unilateral prepare uses fresh keyset: {}",
            keyset_fresh_id
        );

        // Verify different keysets
        assert_ne!(
            first_outputs[0]["id"], second_outputs[0]["id"],
            "Swap requests should use different keysets"
        );
        println!("✓ Unilateral retry would use different keyset after refresh");
    }

    /// Test: fund_channel accepts non-zero initial balance
    ///
    /// The bridge should accept any balance value for fund_channel.
    /// Servers that want to enforce balance=0 should do so at the application layer.
    #[test]
    fn test_fund_channel_accepts_nonzero_balance() {
        use crate::nuts::Proof;
        use crate::secret::Secret;
        use crate::spilman::params::mock_keyset_info;
        use crate::spilman::{
            compute_shared_secret, ChannelParameters, EstablishedChannel, SpilmanChannelSender,
        };

        let alice_sk = SecretKey::generate();
        let charlie_sk = SecretKey::generate();
        let shared_secret = compute_shared_secret(&alice_sk, &charlie_sk.public_key());

        let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 0);
        let keyset_id = keyset_info.keyset_id;

        // Setup channel params
        let params_struct = ChannelParameters {
            alice_pubkey: alice_sk.public_key(),
            charlie_pubkey: charlie_sk.public_key(),
            mint: "https://mint.host".to_string(),
            unit: CurrencyUnit::Sat,
            capacity: 1000,
            funding_token_amount: 1000,
            maximum_amount_for_one_output: 64,
            setup_timestamp: 1700000000,
            locktime: 1700003600,
            sender_nonce: "test-nonzero-funding".to_string(),
            keyset_info: keyset_info.clone(),
            shared_secret,
        };
        let channel_id = params_struct.get_channel_id();

        // Non-zero balance for initial funding
        let initial_balance = 50u64;

        // Funding proofs
        let proofs = vec![Proof {
            amount: 1000.into(),
            secret: Secret::new("funding".to_string()),
            c: PublicKey::from_str(
                "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
            )
            .unwrap(),
            keyset_id,
            dleq: None,
            witness: None,
        }];

        // Pre-populate funding data (simulates a channel that was just validated)
        let host = FlexibleMockHost {
            active_keyset_ids: vec![keyset_id],
            keyset_infos: vec![(keyset_id, serde_json::to_string(&keyset_info).unwrap())]
                .into_iter()
                .collect(),
            funding_data: vec![(
                channel_id.clone(),
                (
                    params_struct.get_channel_id_params_json(),
                    serde_json::to_string(&proofs).unwrap(),
                    hex::encode(shared_secret),
                    serde_json::to_string(&keyset_info).unwrap(),
                ),
            )]
            .into_iter()
            .collect(),
            amount_due: 0, // Not relevant for fund_channel
        };

        let bridge = SpilmanBridge::new(host, Some(charlie_sk.clone()));

        // Create a valid signature for the non-zero balance
        let channel = EstablishedChannel::new(params_struct.clone(), proofs.clone()).unwrap();
        let sender = SpilmanChannelSender::new(alice_sk, channel);
        let (balance_update, _) = sender
            .create_signed_balance_update(initial_balance)
            .unwrap();

        // EXECUTE: fund_channel with non-zero balance
        let result = bridge.fund_channel(
            &channel_id,
            initial_balance,
            &balance_update.signature.to_string(),
            None, // params not needed - channel already known
            None, // funding_proofs not needed - channel already known
        );

        // VERIFY: Should succeed
        assert!(
            result.is_ok(),
            "fund_channel should accept non-zero balance"
        );
        let fund_result = result.unwrap();
        assert_eq!(fund_result.channel_id, channel_id);
        assert_eq!(fund_result.capacity, 1000);
        assert!(
            fund_result.already_known,
            "Channel should be marked as already known"
        );

        println!(
            "✓ fund_channel accepts non-zero initial balance ({})",
            initial_balance
        );
    }

    /// Test: fund_channel rejects invalid signature for non-zero balance
    ///
    /// Ensures the signature verification uses the actual balance value, not hardcoded 0.
    #[test]
    fn test_fund_channel_rejects_wrong_signature_for_nonzero_balance() {
        use crate::nuts::Proof;
        use crate::secret::Secret;
        use crate::spilman::params::mock_keyset_info;
        use crate::spilman::{
            compute_shared_secret, ChannelParameters, EstablishedChannel, SpilmanChannelSender,
        };

        let alice_sk = SecretKey::generate();
        let charlie_sk = SecretKey::generate();
        let shared_secret = compute_shared_secret(&alice_sk, &charlie_sk.public_key());

        let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 0);
        let keyset_id = keyset_info.keyset_id;

        let params_struct = ChannelParameters {
            alice_pubkey: alice_sk.public_key(),
            charlie_pubkey: charlie_sk.public_key(),
            mint: "https://mint.host".to_string(),
            unit: CurrencyUnit::Sat,
            capacity: 1000,
            funding_token_amount: 1000,
            maximum_amount_for_one_output: 64,
            setup_timestamp: 1700000000,
            locktime: 1700003600,
            sender_nonce: "test-wrong-sig".to_string(),
            keyset_info: keyset_info.clone(),
            shared_secret,
        };
        let channel_id = params_struct.get_channel_id();

        let proofs = vec![Proof {
            amount: 1000.into(),
            secret: Secret::new("funding".to_string()),
            c: PublicKey::from_str(
                "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
            )
            .unwrap(),
            keyset_id,
            dleq: None,
            witness: None,
        }];

        let host = FlexibleMockHost {
            active_keyset_ids: vec![keyset_id],
            keyset_infos: vec![(keyset_id, serde_json::to_string(&keyset_info).unwrap())]
                .into_iter()
                .collect(),
            funding_data: vec![(
                channel_id.clone(),
                (
                    params_struct.get_channel_id_params_json(),
                    serde_json::to_string(&proofs).unwrap(),
                    hex::encode(shared_secret),
                    serde_json::to_string(&keyset_info).unwrap(),
                ),
            )]
            .into_iter()
            .collect(),
            amount_due: 0,
        };

        let bridge = SpilmanBridge::new(host, Some(charlie_sk.clone()));

        // Create signature for balance=0
        let channel = EstablishedChannel::new(params_struct.clone(), proofs.clone()).unwrap();
        let sender = SpilmanChannelSender::new(alice_sk, channel);
        let (balance_update_zero, _) = sender.create_signed_balance_update(0).unwrap();

        // EXECUTE: Try to fund with balance=50 but signature for balance=0
        let result = bridge.fund_channel(
            &channel_id,
            50,                                         // Claiming balance=50
            &balance_update_zero.signature.to_string(), // But signature is for balance=0
            None,
            None,
        );

        // VERIFY: Should fail with invalid signature
        assert!(
            result.is_err(),
            "Should reject mismatched balance/signature"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, BridgeError::InvalidSignature(_)),
            "Error should be InvalidSignature, got: {:?}",
            err
        );

        println!("✓ fund_channel rejects signature mismatch (sig for 0, claimed 50)");
    }
}
