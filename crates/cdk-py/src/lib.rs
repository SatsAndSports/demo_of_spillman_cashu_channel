//! Python bindings for Cashu payment channels

use pyo3::prelude::*;

/// Get channel_id from params JSON and shared secret
///
/// This is effectively a method on ChannelParameters for FFI.
/// Takes the params JSON and the pre-computed shared secret (hex).
#[pyfunction]
fn channel_parameters_get_channel_id(params_json: &str, shared_secret_hex: &str) -> PyResult<String> {
    cdk::spilman::channel_parameters_get_channel_id(params_json, shared_secret_hex)
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
    m.add_function(wrap_pyfunction!(channel_parameters_get_channel_id, m)?)?;
    m.add_function(wrap_pyfunction!(compute_shared_secret, m)?)?;
    Ok(())
}
