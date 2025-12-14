//! Python bindings for Cashu payment channels

use pyo3::prelude::*;

/// Compute channel_id from params JSON and a secret key
///
/// Takes the JSON produced by `ChannelParameters::get_channel_id_params_json()`
/// and either Alice's or Charlie's secret key (hex). The function auto-detects
/// which party the secret belongs to by matching the derived pubkey against
/// alice_pubkey and charlie_pubkey in the JSON.
#[pyfunction]
fn compute_channel_id_from_json(params_json: &str, my_secret_hex: &str) -> PyResult<String> {
    cdk::spilman::compute_channel_id_from_json_str(params_json, my_secret_hex)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))
}

/// Compute ECDH shared secret from a secret key and counterparty's public key
///
/// Returns the x-coordinate of the shared point as a hex string (32 bytes).
#[pyfunction]
fn compute_shared_secret(my_secret_hex: &str, their_pubkey_hex: &str) -> PyResult<String> {
    cdk::spilman::compute_shared_secret_from_hex(my_secret_hex, their_pubkey_hex)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))
}

/// Python module definition
#[pymodule]
fn cdk_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(compute_channel_id_from_json, m)?)?;
    m.add_function(wrap_pyfunction!(compute_shared_secret, m)?)?;
    Ok(())
}
