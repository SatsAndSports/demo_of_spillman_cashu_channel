//! Spilman Protocol Bridge
//!
//! This module provides a high-level bridge for implementing Spilman payment channels
//! in any service provider. It handles the core protocol logic, validation, and
//! signature verification, while delegating storage and pricing to a host hook.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::{
    verify_valid_channel, BalanceUpdateMessage, ChannelParameters, CommitmentOutputs,
    DeterministicSecretWithBlinding, EstablishedChannel, SpilmanChannelReceiver,
};
use crate::nuts::{Proof, PublicKey, SecretKey, SwapRequest};
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
    fn get_amount_due(&self, channel_id: &str, context_json: &str) -> u64;

    /// Record a successful payment and update usage
    fn record_payment(&self, channel_id: &str, balance: u64, signature: &str, context_json: &str);

    /// Check if a channel has been closed
    fn is_closed(&self, channel_id: &str) -> bool;

    /// Get server configuration (pricing, limits, etc.)
    fn get_server_config(&self) -> String;

    /// Get the current time in seconds
    fn now_seconds(&self) -> u64;
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
            Self::Internal(s) => write!(f, "internal error: {}", s),
            Self::ReceiverKeyNotAcceptable => write!(f, "receiver key not acceptable"),
            Self::MintOrKeysetNotAcceptable => write!(f, "mint or keyset not acceptable"),
        }
    }
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
        let amount_due = self.host.get_amount_due(channel_id, context_json);
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

        // Parse server config for validations
        let config_json = self.host.get_server_config();
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

        // 5. Check balance doesn't exceed capacity
        if payment.balance > params.capacity {
            return Err(BridgeError::BalanceExceedsCapacity {
                balance: payment.balance,
                capacity: params.capacity,
            });
        }

        // 6. Parse signature
        let sig: bitcoin::secp256k1::schnorr::Signature = payment.signature.parse().map_err(
            |e: <bitcoin::secp256k1::schnorr::Signature as FromStr>::Err| {
                BridgeError::InvalidSignature(e.to_string())
            },
        )?;

        // 7. Create commitment outputs and swap request
        let commitment_outputs = CommitmentOutputs::for_balance(payment.balance, &params)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        let mut swap_request = commitment_outputs
            .create_swap_request(funding_proofs.clone())
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        // 8. Create balance update message
        let balance_update = BalanceUpdateMessage {
            channel_id: channel_id.to_string(),
            amount: payment.balance,
            signature: sig.clone(),
        };

        // 9. Add Alice's signature to the swap request witness
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

        // 10. Create channel and receiver, verify + add Charlie's signature
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

        // 11. Get expected total (value after stage 1 fees)
        let expected_total = params
            .get_value_after_stage1()
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        // 12. Collect secrets with blinding factors for unblinding
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

        fn get_amount_due(&self, _channel_id: &str, _context_json: &str) -> u64 {
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

        fn get_server_config(&self) -> String {
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
}
