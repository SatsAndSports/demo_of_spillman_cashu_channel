//! Python bindings for CDK Spilman payment channels
//!
//! This module provides PyO3 bindings for both server-side (SpilmanBridge)
//! and client-side (standalone functions) Spilman channel operations.

use pyo3::prelude::*;
use pyo3::types::PyTuple;

use cdk::nuts::{Id, PublicKey, SecretKey};
use cdk::spilman::{self, SpilmanBridge as RustSpilmanBridge, SpilmanHost};

// ============================================================================
// Server-side: SpilmanBridge with Python host callbacks
// ============================================================================

/// Wrapper that delegates SpilmanHost trait calls to a Python object.
///
/// The Python object must implement these methods:
/// - receiver_key_is_acceptable(pubkey_hex: str) -> bool
/// - mint_and_keyset_is_acceptable(mint: str, keyset_id: str) -> bool
/// - get_funding_and_params(channel_id: str) -> Optional[Tuple[str, str, str, str]]
/// - save_funding(channel_id: str, params: str, proofs: str, secret: str, keyset: str)
/// - get_amount_due(channel_id: str, context_json: str) -> int
/// - record_payment(channel_id: str, balance: int, signature: str, context_json: str)
/// - is_closed(channel_id: str) -> bool
/// - get_server_config() -> str
/// - now_seconds() -> int
/// - get_largest_balance_with_signature(channel_id: str) -> Optional[Tuple[int, str]]
/// - get_active_keyset_ids(mint: str, unit: str) -> List[str]
/// - get_keyset_info(mint: str, keyset_id: str) -> Optional[str]
struct PySpilmanHost {
    py_host: PyObject,
}

impl SpilmanHost for PySpilmanHost {
    fn get_active_keyset_ids(&self, mint: &str, unit: &cdk::nuts::CurrencyUnit) -> Vec<Id> {
        let unit_str = match unit {
            cdk::nuts::CurrencyUnit::Sat => "sat",
            cdk::nuts::CurrencyUnit::Msat => "msat",
            cdk::nuts::CurrencyUnit::Usd => "usd",
            cdk::nuts::CurrencyUnit::Eur => "eur",
            _ => "units",
        };

        Python::with_gil(|py| {
            match self
                .py_host
                .call_method1(py, "get_active_keyset_ids", (mint, unit_str))
            {
                Ok(result) => {
                    if let Ok(list) = result.extract::<Vec<String>>(py) {
                        list.into_iter()
                            .filter_map(|s| Id::from_str(&s).ok())
                            .collect()
                    } else {
                        Vec::new()
                    }
                }
                Err(e) => {
                    eprintln!("[PySpilmanHost] get_active_keyset_ids call error: {}", e);
                    Vec::new()
                }
            }
        })
    }

    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String> {
        Python::with_gil(|py| {
            match self
                .py_host
                .call_method1(py, "get_keyset_info", (mint, keyset_id.to_string()))
            {
                Ok(result) => {
                    if result.is_none(py) {
                        None
                    } else {
                        result.extract::<String>(py).ok()
                    }
                }
                Err(e) => {
                    eprintln!("[PySpilmanHost] get_keyset_info call error: {}", e);
                    None
                }
            }
        })
    }

    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool {
        Python::with_gil(|py| {
            match self.py_host.call_method1(
                py,
                "receiver_key_is_acceptable",
                (receiver_pubkey.to_hex(),),
            ) {
                Ok(result) => match result.extract::<bool>(py) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!(
                            "[PySpilmanHost] receiver_key_is_acceptable extract error: {}",
                            e
                        );
                        false
                    }
                },
                Err(e) => {
                    eprintln!(
                        "[PySpilmanHost] receiver_key_is_acceptable call error: {}",
                        e
                    );
                    false
                }
            }
        })
    }

    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool {
        Python::with_gil(|py| {
            match self.py_host.call_method1(
                py,
                "mint_and_keyset_is_acceptable",
                (mint, keyset_id.to_string()),
            ) {
                Ok(result) => match result.extract::<bool>(py) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!(
                            "[PySpilmanHost] mint_and_keyset_is_acceptable extract error: {}",
                            e
                        );
                        false
                    }
                },
                Err(e) => {
                    eprintln!(
                        "[PySpilmanHost] mint_and_keyset_is_acceptable call error: {}",
                        e
                    );
                    false
                }
            }
        })
    }

    fn get_funding_and_params(&self, channel_id: &str) -> Option<(String, String, String, String)> {
        Python::with_gil(|py| {
            let result = self
                .py_host
                .call_method1(py, "get_funding_and_params", (channel_id,))
                .ok()?;

            if result.is_none(py) {
                return None;
            }

            let tuple = result.downcast_bound::<PyTuple>(py).ok()?;
            if tuple.len() != 4 {
                return None;
            }

            Some((
                tuple.get_item(0).ok()?.extract::<String>().ok()?,
                tuple.get_item(1).ok()?.extract::<String>().ok()?,
                tuple.get_item(2).ok()?.extract::<String>().ok()?,
                tuple.get_item(3).ok()?.extract::<String>().ok()?,
            ))
        })
    }

    fn save_funding(
        &self,
        channel_id: &str,
        params_json: &str,
        funding_proofs_json: &str,
        shared_secret_hex: &str,
        keyset_info_json: &str,
    ) {
        Python::with_gil(|py| {
            let _ = self.py_host.call_method1(
                py,
                "save_funding",
                (
                    channel_id,
                    params_json,
                    funding_proofs_json,
                    shared_secret_hex,
                    keyset_info_json,
                ),
            );
        });
    }

    fn get_amount_due(&self, channel_id: &str, context_json: &str) -> u64 {
        Python::with_gil(|py| {
            self.py_host
                .call_method1(py, "get_amount_due", (channel_id, context_json))
                .and_then(|r| r.extract::<u64>(py))
                .unwrap_or(0)
        })
    }

    fn record_payment(&self, channel_id: &str, balance: u64, signature: &str, context_json: &str) {
        Python::with_gil(|py| {
            let _ = self.py_host.call_method1(
                py,
                "record_payment",
                (channel_id, balance, signature, context_json),
            );
        });
    }

    fn is_closed(&self, channel_id: &str) -> bool {
        Python::with_gil(|py| {
            self.py_host
                .call_method1(py, "is_closed", (channel_id,))
                .and_then(|r| r.extract::<bool>(py))
                .unwrap_or(false)
        })
    }

    fn get_server_config(&self) -> String {
        Python::with_gil(|py| {
            self.py_host
                .call_method0(py, "get_server_config")
                .and_then(|r| r.extract::<String>(py))
                .unwrap_or_else(|_| "{}".to_string())
        })
    }

    fn now_seconds(&self) -> u64 {
        Python::with_gil(|py| {
            self.py_host
                .call_method0(py, "now_seconds")
                .and_then(|r| r.extract::<u64>(py))
                .unwrap_or(0)
        })
    }

    fn get_largest_balance_with_signature(&self, channel_id: &str) -> Option<(u64, String)> {
        Python::with_gil(|py| {
            let result = self
                .py_host
                .call_method1(py, "get_largest_balance_with_signature", (channel_id,))
                .ok()?;

            if result.is_none(py) {
                return None;
            }

            let tuple = result.downcast_bound::<PyTuple>(py).ok()?;
            if tuple.len() != 2 {
                return None;
            }

            Some((
                tuple.get_item(0).ok()?.extract::<u64>().ok()?,
                tuple.get_item(1).ok()?.extract::<String>().ok()?,
            ))
        })
    }
}

/// Spilman payment channel bridge for servers (receivers).
///
/// This validates incoming payments and manages channel state through
/// the provided host object which implements storage and pricing logic.
#[pyclass]
struct SpilmanBridge {
    inner: RustSpilmanBridge<PySpilmanHost>,
}

#[pymethods]
impl SpilmanBridge {
    /// Create a new SpilmanBridge.
    ///
    /// Args:
    ///     host: Python object implementing SpilmanHost methods
    ///     secret_key_hex: Server's secret key (hex string, 64 chars)
    #[new]
    #[pyo3(signature = (host, secret_key_hex=None))]
    fn new(host: PyObject, secret_key_hex: Option<String>) -> PyResult<Self> {
        let secret_key = match secret_key_hex {
            Some(hex) => Some(
                SecretKey::from_hex(&hex)
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?,
            ),
            None => None,
        };

        let py_host = PySpilmanHost { py_host: host };
        let inner = RustSpilmanBridge::new(py_host, secret_key);

        Ok(SpilmanBridge { inner })
    }

    /// Process an incoming payment request.
    ///
    /// Args:
    ///     payment_json: JSON string with channel_id, balance, signature, and optionally params/funding_proofs
    ///     context_json: JSON string with request context (for pricing)
    ///     keyset_info_json: Optional keyset info JSON (required for unknown channels)
    ///
    /// Returns:
    ///     JSON string with success/error and header/body
    #[pyo3(signature = (payment_json, context_json, keyset_info_json=None))]
    fn process_payment(
        &self,
        payment_json: &str,
        context_json: &str,
        keyset_info_json: Option<String>,
    ) -> PyResult<String> {
        let response =
            self.inner
                .process_payment(payment_json, context_json, keyset_info_json.as_deref());

        serde_json::to_string(&response)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    /// Create data needed to close a channel.
    ///
    /// Args:
    ///     payment_json: JSON string with channel_id, balance, signature
    ///     keyset_info_json: Optional keyset info JSON
    ///
    /// Returns:
    ///     JSON string with swap_request, expected_total, and secrets_with_blinding
    #[pyo3(signature = (payment_json, keyset_info_json=None))]
    fn create_close_data(
        &self,
        payment_json: &str,
        keyset_info_json: Option<String>,
    ) -> PyResult<String> {
        match self
            .inner
            .create_close_data(payment_json, keyset_info_json.as_deref())
        {
            Ok(close_data) => {
                let swap_request_json = serde_json::to_value(&close_data.swap_request)
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

                let secrets_with_blinding: Vec<serde_json::Value> = close_data
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

                let result = serde_json::json!({
                    "success": true,
                    "swap_request": swap_request_json,
                    "expected_total": close_data.expected_total,
                    "secrets_with_blinding": secrets_with_blinding,
                    "output_keyset_info": serde_json::to_value(&close_data.output_keyset_info).unwrap()
                });

                Ok(result.to_string())
            }
            Err(e) => {
                let result = serde_json::json!({
                    "success": false,
                    "error": e.to_string()
                });
                Ok(result.to_string())
            }
        }
    }

    /// Create data for a unilateral (server-initiated) channel close.
    ///
    /// This retrieves the largest balance and signature from the host
    /// and constructs a fully-signed swap request ready for the mint.
    ///
    /// Args:
    ///     channel_id: The channel ID to close
    ///
    /// Returns:
    ///     JSON string with swap_request, expected_total, and secrets_with_blinding
    fn create_unilateral_close_data(&self, channel_id: &str) -> PyResult<String> {
        match self.inner.create_unilateral_close_data(channel_id) {
            Ok(close_data) => {
                let swap_request_json = serde_json::to_value(&close_data.swap_request)
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

                let secrets_with_blinding: Vec<serde_json::Value> = close_data
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

                let result = serde_json::json!({
                    "success": true,
                    "swap_request": swap_request_json,
                    "expected_total": close_data.expected_total,
                    "secrets_with_blinding": secrets_with_blinding,
                    "output_keyset_info": serde_json::to_value(&close_data.output_keyset_info).unwrap()
                });

                Ok(result.to_string())
            }
            Err(e) => {
                let result = serde_json::json!({
                    "success": false,
                    "error": e.to_string()
                });
                Ok(result.to_string())
            }
        }
    }
}

// ============================================================================
// Client-side: Standalone functions for Alice (sender)
// ============================================================================

/// Generate a new keypair for use as Alice (sender).
///
/// Returns:
///     Tuple of (secret_key_hex, pubkey_hex)
#[pyfunction]
fn generate_keypair() -> PyResult<(String, String)> {
    let secret = SecretKey::generate();
    let pubkey = secret.public_key();
    Ok((secret.to_secret_hex(), pubkey.to_hex()))
}

/// Derive public key from a secret key.
///
/// Args:
///     secret_hex: Secret key as hex string (64 chars)
///
/// Returns:
///     Public key as hex string (66 chars, compressed)
#[pyfunction]
fn secret_key_to_pubkey(secret_hex: &str) -> PyResult<String> {
    let secret = SecretKey::from_hex(secret_hex)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok(secret.public_key().to_hex())
}

/// Compute ECDH shared secret between two parties.
///
/// Args:
///     my_secret_hex: Your secret key (hex)
///     their_pubkey_hex: Counterparty's public key (hex)
///
/// Returns:
///     Shared secret as hex string (64 chars)
#[pyfunction]
fn compute_shared_secret(my_secret_hex: &str, their_pubkey_hex: &str) -> PyResult<String> {
    spilman::compute_shared_secret_from_hex(my_secret_hex, their_pubkey_hex)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))
}

/// Get channel ID from parameters.
///
/// Args:
///     params_json: Channel parameters JSON
///     shared_secret_hex: Pre-computed shared secret (hex)
///     keyset_info_json: Keyset info JSON
///
/// Returns:
///     Channel ID as hex string
#[pyfunction]
fn channel_parameters_get_channel_id(
    params_json: &str,
    shared_secret_hex: &str,
    keyset_info_json: &str,
) -> PyResult<String> {
    spilman::channel_parameters_get_channel_id(params_json, shared_secret_hex, keyset_info_json)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))
}

/// Create funding outputs (blinded messages) for minting.
///
/// Args:
///     params_json: Channel parameters JSON
///     my_secret_hex: Alice's secret key (hex)
///     keyset_info_json: Keyset info JSON
///
/// Returns:
///     JSON with funding_token_nominal, blinded_messages, and secrets_with_blinding
#[pyfunction]
fn create_funding_outputs(
    params_json: &str,
    my_secret_hex: &str,
    keyset_info_json: &str,
) -> PyResult<String> {
    create_funding_outputs_inner(params_json, my_secret_hex, keyset_info_json)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))
}

fn create_funding_outputs_inner(
    params_json: &str,
    my_secret_hex: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    use cdk::spilman::{ChannelParameters, DeterministicOutputsForOneContext};

    // Parse keyset info
    let keyset_info = spilman::parse_keyset_info_from_json(keyset_info_json)?;

    // Parse secret key
    let my_secret =
        SecretKey::from_hex(my_secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;

    // Create channel parameters
    let params = ChannelParameters::from_json_with_secret_key(params_json, keyset_info, &my_secret)
        .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    // Get funding token nominal amount
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

    // Serialize for JSON output
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

    // Get secrets with blinding factors
    let secrets_with_blinding = funding_outputs
        .get_secrets_with_blinding()
        .map_err(|e| format!("Failed to get secrets with blinding: {}", e))?;

    let secrets_json: Vec<serde_json::Value> = secrets_with_blinding
        .into_iter()
        .map(|s| {
            serde_json::json!({
                "secret": s.secret.to_string(),
                "blinding_factor": hex::encode(s.blinding_factor.secret_bytes()),
                "amount": s.amount,
                "index": s.index
            })
        })
        .collect();

    let result = serde_json::json!({
        "funding_token_nominal": funding_token_nominal,
        "blinded_messages": blinded_messages_json,
        "secrets_with_blinding": secrets_json
    });

    Ok(result.to_string())
}

/// Construct proofs from blind signatures.
///
/// Args:
///     signatures_json: JSON array of blind signatures from mint
///     secrets_with_blinding_json: JSON array from create_funding_outputs
///     keyset_info_json: Keyset info JSON
///
/// Returns:
///     JSON array of proofs
#[pyfunction]
fn construct_proofs(
    signatures_json: &str,
    secrets_with_blinding_json: &str,
    keyset_info_json: &str,
) -> PyResult<String> {
    construct_proofs_inner(
        signatures_json,
        secrets_with_blinding_json,
        keyset_info_json,
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))
}

fn construct_proofs_inner(
    signatures_json: &str,
    secrets_with_blinding_json: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    use cdk::dhke::construct_proofs as dhke_construct_proofs;
    use cdk::nuts::{BlindSignature, BlindSignatureDleq};
    use cdk::secret::Secret;
    use cdk::Amount;

    // Parse keyset info
    let keyset_info = spilman::parse_keyset_info_from_json(keyset_info_json)?;
    let keys = keyset_info.active_keys;

    // Parse blind signatures
    let sigs_raw: Vec<serde_json::Value> = serde_json::from_str(signatures_json)
        .map_err(|e| format!("Failed to parse signatures: {}", e))?;

    let mut blind_signatures = Vec::new();
    for sig in sigs_raw {
        let amount = sig["amount"]
            .as_u64()
            .ok_or("Missing 'amount' in signature")?;
        let id_str = sig["id"].as_str().ok_or("Missing 'id' in signature")?;
        let c_str = sig["C_"].as_str().ok_or("Missing 'C_' in signature")?;

        let keyset_id: Id = id_str
            .parse()
            .map_err(|e| format!("Invalid keyset id: {}", e))?;
        let c = PublicKey::from_hex(c_str).map_err(|e| format!("Invalid C_ pubkey: {}", e))?;

        // Parse DLEQ if present
        let dleq = if let Some(dleq_obj) = sig["dleq"].as_object() {
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
            Some(BlindSignatureDleq { e, s })
        } else {
            None
        };

        blind_signatures.push(BlindSignature {
            amount: Amount::from(amount),
            keyset_id,
            c,
            dleq,
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

    // Construct proofs
    let proofs = dhke_construct_proofs(blind_signatures, rs, secrets, &keys)
        .map_err(|e| format!("Failed to construct proofs: {}", e))?;

    // Serialize proofs
    let proofs_json =
        serde_json::to_string(&proofs).map_err(|e| format!("Failed to serialize proofs: {}", e))?;

    Ok(proofs_json)
}

/// Create a signed balance update for a payment.
///
/// Args:
///     params_json: Channel parameters JSON
///     keyset_info_json: Keyset info JSON
///     secret_hex: Alice's secret key (hex)
///     proofs_json: Funding proofs JSON array
///     balance: New balance (Charlie's amount)
///
/// Returns:
///     JSON with channel_id, amount, and signature
#[pyfunction]
fn create_signed_balance_update(
    params_json: &str,
    keyset_info_json: &str,
    secret_hex: &str,
    proofs_json: &str,
    balance: u64,
) -> PyResult<String> {
    create_signed_balance_update_inner(
        params_json,
        keyset_info_json,
        secret_hex,
        proofs_json,
        balance,
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))
}

fn create_signed_balance_update_inner(
    params_json: &str,
    keyset_info_json: &str,
    secret_hex: &str,
    proofs_json: &str,
    balance: u64,
) -> Result<String, String> {
    use cdk::nuts::Proof;
    use cdk::spilman::{ChannelParameters, EstablishedChannel, SpilmanChannelSender};

    // Parse keyset info
    let keyset_info = spilman::parse_keyset_info_from_json(keyset_info_json)?;

    // Parse secret key
    let alice_secret =
        SecretKey::from_hex(secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;

    // Create channel parameters
    let params =
        ChannelParameters::from_json_with_secret_key(params_json, keyset_info, &alice_secret)
            .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    // Parse funding proofs
    let funding_proofs: Vec<Proof> =
        serde_json::from_str(proofs_json).map_err(|e| format!("Failed to parse proofs: {}", e))?;

    // Create channel and sender
    let channel = EstablishedChannel::new(params, funding_proofs)
        .map_err(|e| format!("Failed to create EstablishedChannel: {}", e))?;

    let sender = SpilmanChannelSender::new(alice_secret, channel);

    // Create signed balance update
    let (balance_update, _swap_request) = sender
        .create_signed_balance_update(balance)
        .map_err(|e| format!("Failed to create balance update: {}", e))?;

    let result = serde_json::json!({
        "channel_id": balance_update.channel_id,
        "amount": balance_update.amount,
        "signature": balance_update.signature.to_string()
    });

    Ok(result.to_string())
}

/// Unblind mint signatures and verify DLEQ proofs.
///
/// This processes the mint's response to a swap request, unblinding the signatures
/// and verifying that they are valid. It also separates receiver and sender proofs.
///
/// Args:
///     blind_signatures_json: JSON array of blind signatures from mint
///     secrets_with_blinding_json: JSON array from create_close_data
///     params_json: Channel parameters JSON
///     keyset_info_json: Keyset info JSON (funding keyset)
///     shared_secret_hex: Shared secret (hex)
///     balance: The balance used to close the channel
///     output_keyset_info_json: Optional Keyset info JSON for outputs
///
/// Returns:
///     JSON with receiver_proofs, sender_proofs, receiver_sum_after_stage1, sender_sum_after_stage1
#[pyfunction]
#[pyo3(signature = (blind_signatures_json, secrets_with_blinding_json, params_json, keyset_info_json, shared_secret_hex, balance, output_keyset_info_json=None))]
fn unblind_and_verify_dleq(
    blind_signatures_json: &str,
    secrets_with_blinding_json: &str,
    params_json: &str,
    keyset_info_json: &str,
    shared_secret_hex: &str,
    balance: u64,
    output_keyset_info_json: Option<String>,
) -> PyResult<String> {
    unblind_and_verify_dleq_inner(
        blind_signatures_json,
        secrets_with_blinding_json,
        params_json,
        keyset_info_json,
        shared_secret_hex,
        balance,
        output_keyset_info_json,
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))
}

fn unblind_and_verify_dleq_inner(
    blind_signatures_json: &str,
    secrets_with_blinding_json: &str,
    params_json: &str,
    keyset_info_json: &str,
    shared_secret_hex: &str,
    balance: u64,
    output_keyset_info_json: Option<String>,
) -> Result<String, String> {
    use cdk::nuts::BlindSignature;
    use cdk::secret::Secret;
    use cdk::spilman::{
        unblind_and_verify_stage1_response, ChannelParameters, DeterministicSecretWithBlinding,
    };

    // Parse keyset info
    let keyset_info = spilman::parse_keyset_info_from_json(keyset_info_json)?;

    // Parse output keyset info if provided, otherwise use funding keyset
    let output_keyset_info = match output_keyset_info_json {
        Some(json) => spilman::parse_keyset_info_from_json(&json)?,
        None => keyset_info.clone(),
    };

    // Parse shared secret
    let shared_secret_bytes =
        hex::decode(shared_secret_hex).map_err(|e| format!("Invalid shared secret hex: {}", e))?;
    let shared_secret: [u8; 32] = shared_secret_bytes
        .try_into()
        .map_err(|_| "Shared secret must be 32 bytes".to_string())?;

    // Create ChannelParameters to compute blinded pubkey
    let params =
        ChannelParameters::from_json_with_shared_secret(params_json, keyset_info, shared_secret)
            .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    // Parse blind signatures
    let blind_signatures: Vec<BlindSignature> = serde_json::from_str(blind_signatures_json)
        .map_err(|e| format!("Invalid blind signatures JSON: {}", e))?;

    // Parse secrets with blinding from JSON into typed data
    let secrets_with_blinding_json: Vec<serde_json::Value> =
        serde_json::from_str(secrets_with_blinding_json)
            .map_err(|e| format!("Invalid secrets_with_blinding JSON: {}", e))?;

    let mut secrets_with_blinding: Vec<(DeterministicSecretWithBlinding, bool)> = Vec::new();
    for (i, swb) in secrets_with_blinding_json.iter().enumerate() {
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

    // Call the core function
    let result = unblind_and_verify_stage1_response(
        blind_signatures,
        secrets_with_blinding,
        &params,
        &output_keyset_info,
        balance,
    )
    .map_err(|e| e.to_string())?;

    // Serialize proofs for JSON output
    let receiver_proofs_json: Vec<serde_json::Value> = result
        .receiver_proofs
        .iter()
        .map(|p| serde_json::to_value(p).unwrap())
        .collect();
    let sender_proofs_json: Vec<serde_json::Value> = result
        .sender_proofs
        .iter()
        .map(|p| serde_json::to_value(p).unwrap())
        .collect();

    // Build result
    let json_result = serde_json::json!({
        "receiver_proofs": receiver_proofs_json,
        "sender_proofs": sender_proofs_json,
        "receiver_sum_after_stage1": result.receiver_sum,
        "sender_sum_after_stage1": result.sender_sum
    });

    Ok(json_result.to_string())
}

// ============================================================================
// Module registration
// ============================================================================

/// Python module for CDK Spilman payment channels.
#[pymodule]
fn cdk_spilman(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Server-side
    m.add_class::<SpilmanBridge>()?;

    // Client-side functions
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(secret_key_to_pubkey, m)?)?;
    m.add_function(wrap_pyfunction!(compute_shared_secret, m)?)?;
    m.add_function(wrap_pyfunction!(channel_parameters_get_channel_id, m)?)?;
    m.add_function(wrap_pyfunction!(create_funding_outputs, m)?)?;
    m.add_function(wrap_pyfunction!(construct_proofs, m)?)?;
    m.add_function(wrap_pyfunction!(create_signed_balance_update, m)?)?;

    // Server-side functions (for closing)
    m.add_function(wrap_pyfunction!(unblind_and_verify_dleq, m)?)?;

    Ok(())
}
