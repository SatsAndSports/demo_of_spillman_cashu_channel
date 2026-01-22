//! WASM bindings for Cashu payment channels

use std::str::FromStr;

use wasm_bindgen::prelude::*;

use cdk::nuts::{Id, PublicKey, SecretKey};
use cdk::spilman::{self, ChannelParameters, SpilmanBridge, SpilmanHost};
use cdk::util::hex;

/// Initialize panic hook for better error messages in browser console
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
extern "C" {
    pub type JsSpilmanHost;

    #[wasm_bindgen(method, js_name = getFundingAndParams)]
    fn get_funding_and_params(this: &JsSpilmanHost, channel_id: &str) -> JsValue;

    #[wasm_bindgen(method, js_name = receiverKeyIsAcceptable)]
    fn receiver_key_is_acceptable(this: &JsSpilmanHost, receiver_pubkey_hex: &str) -> bool;

    #[wasm_bindgen(method, js_name = mintAndKeysetIsAcceptable)]
    fn mint_and_keyset_is_acceptable(this: &JsSpilmanHost, mint: &str, keyset_id: &str) -> bool;

    #[wasm_bindgen(method, js_name = saveFunding)]
    fn save_funding(
        this: &JsSpilmanHost,
        channel_id: &str,
        params_json: &str,
        funding_proofs_json: &str,
        shared_secret_hex: &str,
        keyset_info_json: &str,
    );

    #[wasm_bindgen(method, js_name = getAmountDue)]
    fn get_amount_due(this: &JsSpilmanHost, channel_id: &str, context_json: &str) -> u64;

    #[wasm_bindgen(method, js_name = recordPayment)]
    fn record_payment(
        this: &JsSpilmanHost,
        channel_id: &str,
        balance: u64,
        signature: &str,
        context_json: &str,
    );

    #[wasm_bindgen(method, js_name = isClosed)]
    fn is_closed(this: &JsSpilmanHost, channel_id: &str) -> bool;

    #[wasm_bindgen(method, js_name = getServerConfig)]
    fn get_server_config(this: &JsSpilmanHost) -> String;

    #[wasm_bindgen(method, js_name = nowSeconds)]
    fn now_seconds(this: &JsSpilmanHost) -> u64;

    #[wasm_bindgen(method, js_name = getLargestBalanceWithSignature)]
    fn get_largest_balance_with_signature(this: &JsSpilmanHost, channel_id: &str) -> JsValue;

    #[wasm_bindgen(method, js_name = getActiveKeysetIds)]
    fn get_active_keyset_ids(this: &JsSpilmanHost, mint: &str, unit: &str) -> JsValue;

    #[wasm_bindgen(method, js_name = getKeysetInfo)]
    fn get_keyset_info(this: &JsSpilmanHost, mint: &str, keyset_id: &str) -> JsValue;
}

struct WasmSpilmanHostProxy {
    js_host: JsSpilmanHost,
}

impl SpilmanHost for WasmSpilmanHostProxy {
    fn get_funding_and_params(&self, channel_id: &str) -> Option<(String, String, String, String)> {
        let val = self.js_host.get_funding_and_params(channel_id);
        if val.is_null() || val.is_undefined() {
            return None;
        }

        // Expecting an array [params, funding_proofs, shared_secret, keyset_info]
        let arr = js_sys::Array::from(&val);
        if arr.length() != 4 {
            return None;
        }

        Some((
            arr.get(0).as_string()?,
            arr.get(1).as_string()?,
            arr.get(2).as_string()?,
            arr.get(3).as_string()?,
        ))
    }

    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool {
        self.js_host
            .receiver_key_is_acceptable(&receiver_pubkey.to_hex())
    }

    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool {
        self.js_host
            .mint_and_keyset_is_acceptable(mint, &keyset_id.to_string())
    }

    fn save_funding(
        &self,
        channel_id: &str,
        params_json: &str,
        funding_proofs_json: &str,
        shared_secret_hex: &str,
        keyset_info_json: &str,
    ) {
        self.js_host.save_funding(
            channel_id,
            params_json,
            funding_proofs_json,
            shared_secret_hex,
            keyset_info_json,
        );
    }

    fn get_amount_due(&self, channel_id: &str, context_json: &str) -> u64 {
        self.js_host.get_amount_due(channel_id, context_json)
    }

    fn record_payment(&self, channel_id: &str, balance: u64, signature: &str, context_json: &str) {
        self.js_host
            .record_payment(channel_id, balance, signature, context_json);
    }

    fn is_closed(&self, channel_id: &str) -> bool {
        self.js_host.is_closed(channel_id)
    }

    fn get_server_config(&self) -> String {
        self.js_host.get_server_config()
    }

    fn now_seconds(&self) -> u64 {
        self.js_host.now_seconds()
    }

    fn get_largest_balance_with_signature(&self, channel_id: &str) -> Option<(u64, String)> {
        let val = self.js_host.get_largest_balance_with_signature(channel_id);
        if val.is_null() || val.is_undefined() {
            return None;
        }

        // Expecting an array [balance, signature] from JS
        let arr = js_sys::Array::from(&val);
        if arr.length() != 2 {
            return None;
        }

        let balance = arr.get(0).as_f64()? as u64;
        let signature = arr.get(1).as_string()?;
        Some((balance, signature))
    }

    fn get_active_keyset_ids(&self, mint: &str, unit: &cdk::nuts::CurrencyUnit) -> Vec<Id> {
        let unit_str = unit.to_string();

        let val = self.js_host.get_active_keyset_ids(mint, &unit_str);
        if val.is_null() || val.is_undefined() {
            return Vec::new();
        }

        let arr = js_sys::Array::from(&val);
        arr.iter()
            .filter_map(|v| v.as_string())
            .filter_map(|s| Id::from_str(&s).ok())
            .collect()
    }

    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String> {
        let val = self.js_host.get_keyset_info(mint, &keyset_id.to_string());
        if val.is_null() || val.is_undefined() {
            return None;
        }
        val.as_string()
    }
}

#[wasm_bindgen]
pub struct WasmSpilmanBridge {
    bridge: SpilmanBridge<WasmSpilmanHostProxy>,
}

#[wasm_bindgen]
impl WasmSpilmanBridge {
    #[wasm_bindgen(constructor)]
    pub fn new(
        js_host: JsSpilmanHost,
        server_secret_key_hex: Option<String>,
    ) -> Result<WasmSpilmanBridge, JsValue> {
        let secret_key = match server_secret_key_hex {
            Some(hex) => {
                Some(SecretKey::from_hex(&hex).map_err(|e| JsValue::from_str(&e.to_string()))?)
            }
            None => None,
        };

        Ok(WasmSpilmanBridge {
            bridge: SpilmanBridge::new(WasmSpilmanHostProxy { js_host }, secret_key),
        })
    }

    #[wasm_bindgen(js_name = processPayment)]
    pub fn process_payment(
        &self,
        payment_json: &str,
        context_json: &str,
        keyset_info_json: Option<String>,
    ) -> Result<String, JsValue> {
        let response =
            self.bridge
                .process_payment(payment_json, context_json, keyset_info_json.as_deref());

        serde_json::to_string(&response).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Create data needed to close a channel
    ///
    /// Validates the payment signature and creates the fully-signed swap request
    /// ready to submit to the mint, plus secrets for unblinding the response.
    #[wasm_bindgen(js_name = createCloseData)]
    pub fn create_close_data(
        &self,
        payment_json: &str,
        keyset_info_json: Option<String>,
    ) -> Result<String, JsValue> {
        match self
            .bridge
            .create_close_data(payment_json, keyset_info_json.as_deref())
        {
            Ok(close_data) => {
                // Serialize swap_request
                let swap_request_json =
                    serde_json::to_value(&close_data.swap_request).map_err(|e| {
                        JsValue::from_str(&format!("Failed to serialize swap request: {}", e))
                    })?;

                // Serialize secrets_with_blinding
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
                // Return error in same format as processPayment for consistency
                let error_msg = e.to_string();
                let result = serde_json::json!({
                    "success": false,
                    "error": error_msg
                });
                Ok(result.to_string())
            }
        }
    }

    /// Create data for a unilateral (server-initiated) channel close
    #[wasm_bindgen(js_name = createUnilateralCloseData)]
    pub fn create_unilateral_close_data(&self, channel_id: &str) -> Result<String, JsValue> {
        match self.bridge.create_unilateral_close_data(channel_id) {
            Ok(close_data) => {
                // Serialize swap_request
                let swap_request_json =
                    serde_json::to_value(&close_data.swap_request).map_err(|e| {
                        JsValue::from_str(&format!("Failed to serialize swap request: {}", e))
                    })?;

                // Serialize secrets_with_blinding
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
                let error_msg = e.to_string();
                let result = serde_json::json!({
                    "success": false,
                    "error": error_msg
                });
                Ok(result.to_string())
            }
        }
    }
}

/// Compute ECDH shared secret from a secret key and counterparty's public key
#[wasm_bindgen]
pub fn compute_shared_secret(
    my_secret_hex: &str,
    their_pubkey_hex: &str,
) -> Result<String, JsValue> {
    cdk::spilman::compute_shared_secret_from_hex(my_secret_hex, their_pubkey_hex)
        .map_err(|e| JsValue::from_str(&e))
}

/// Get channel_id from params JSON, shared secret, and keyset info
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
#[wasm_bindgen]
pub fn create_funding_outputs(
    params_json: &str,
    my_secret_hex: &str,
    keyset_info_json: &str,
) -> Result<String, JsValue> {
    cdk::spilman::create_funding_outputs(params_json, my_secret_hex, keyset_info_json)
        .map_err(|e| JsValue::from_str(&e))
}

/// Unblind blind signatures and verify DLEQ proofs
#[wasm_bindgen]
pub fn unblind_and_verify_dleq(
    blind_signatures_json: &str,
    secrets_with_blinding_json: &str,
    params_json: &str,
    keyset_info_json: &str,
    shared_secret_hex: &str,
    balance: u64,
    output_keyset_info_json: Option<String>,
) -> Result<String, JsValue> {
    cdk::spilman::unblind_and_verify_dleq(
        blind_signatures_json,
        secrets_with_blinding_json,
        params_json,
        keyset_info_json,
        shared_secret_hex,
        balance,
        output_keyset_info_json.as_deref(),
    )
    .map_err(|e| JsValue::from_str(&e))
}

/// Create a signed balance update from Alice (sender) to Charlie (receiver)
#[wasm_bindgen]
pub fn spilman_channel_sender_create_signed_balance_update(
    params_json: &str,
    keyset_info_json: &str,
    alice_secret_hex: &str,
    funding_proofs_json: &str,
    charlie_balance: u64,
) -> Result<String, JsValue> {
    cdk::spilman::create_signed_balance_update(
        params_json,
        keyset_info_json,
        alice_secret_hex,
        funding_proofs_json,
        charlie_balance,
    )
    .map_err(|e| JsValue::from_str(&e))
}

/// Verify a balance update signature from the sender (Alice)
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
    // This one doesn't have a direct string binding yet, let's see if we should add it or just leave this as is.
    // Given the goal is thin wrappers, maybe we should add it to bindings.rs too.
    // For now, I'll keep the logic here but call the core structures.
    use bitcoin::secp256k1::schnorr::Signature;
    use cdk::nuts::Proof;
    use cdk::spilman::{parse_keyset_info_from_json, BalanceUpdateMessage, EstablishedChannel};

    let shared_secret_bytes = hex::decode(shared_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid shared secret hex: {}", e)))?;
    let shared_secret: [u8; 32] = shared_secret_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Shared secret must be 32 bytes"))?;

    let keyset_info =
        parse_keyset_info_from_json(keyset_info_json).map_err(|e| JsValue::from_str(&e))?;

    let params =
        ChannelParameters::from_json_with_shared_secret(params_json, keyset_info, shared_secret)
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to create ChannelParameters: {}", e))
            })?;

    let funding_proofs: Vec<Proof> = serde_json::from_str(funding_proofs_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse funding proofs: {}", e)))?;

    let channel = EstablishedChannel::new(params, funding_proofs)
        .map_err(|e| JsValue::from_str(&format!("Failed to create EstablishedChannel: {}", e)))?;

    let sig = Signature::from_str(signature)
        .map_err(|e| JsValue::from_str(&format!("Invalid signature: {}", e)))?;

    let balance_update = BalanceUpdateMessage {
        channel_id: channel_id.to_string(),
        amount: balance,
        signature: sig,
    };

    balance_update
        .verify_sender_signature(&channel)
        .map_err(|e| JsValue::from_str(&format!("Signature verification failed: {}", e)))?;

    Ok(true)
}

/// Verify DLEQ proof on a Proof (offline signature verification)
#[wasm_bindgen]
pub fn verify_proof_dleq(proof_json: &str, mint_pubkey_hex: &str) -> Result<bool, JsValue> {
    use cdk::nuts::Proof;
    let proof: Proof = serde_json::from_str(proof_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse proof: {}", e)))?;

    let mint_pubkey = PublicKey::from_str(mint_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid mint pubkey: {}", e)))?;

    proof
        .verify_dleq(mint_pubkey)
        .map_err(|e| JsValue::from_str(&format!("DLEQ verification failed: {}", e)))?;

    Ok(true)
}

/// Verify that a channel is valid
#[wasm_bindgen]
pub fn verify_channel(
    params_json: &str,
    shared_secret_hex: &str,
    funding_proofs_json: &str,
    keyset_info_json: &str,
) -> Result<String, JsValue> {
    use cdk::nuts::Proof;
    use cdk::spilman::{parse_keyset_info_from_json, verify_valid_channel};

    let shared_secret_bytes = hex::decode(shared_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid shared secret hex: {}", e)))?;
    let shared_secret: [u8; 32] = shared_secret_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Shared secret must be 32 bytes"))?;

    let keyset_info =
        parse_keyset_info_from_json(keyset_info_json).map_err(|e| JsValue::from_str(&e))?;

    let params =
        ChannelParameters::from_json_with_shared_secret(params_json, keyset_info, shared_secret)
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to create ChannelParameters: {}", e))
            })?;

    let funding_proofs: Vec<Proof> = serde_json::from_str(funding_proofs_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse funding proofs: {}", e)))?;

    let result = verify_valid_channel(&funding_proofs, &params);

    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Construct proofs from blind signatures
#[wasm_bindgen]
pub fn construct_proofs(
    blind_signatures_json: &str,
    secrets_with_blinding_json: &str,
    keyset_info_json: &str,
) -> Result<String, JsValue> {
    cdk::spilman::construct_proofs(
        blind_signatures_json,
        secrets_with_blinding_json,
        keyset_info_json,
    )
    .map_err(|e| JsValue::from_str(&e))
}

/// Get Alice's blinded secret key for a specific stage 2 output
#[wasm_bindgen]
pub fn get_sender_blinded_secret_key_for_stage2_output(
    params_json: &str,
    keyset_info_json: &str,
    alice_secret_hex: &str,
    amount: u64,
    index: u32,
) -> Result<String, JsValue> {
    use cdk::spilman::parse_keyset_info_from_json;
    let keyset_info =
        parse_keyset_info_from_json(keyset_info_json).map_err(|e| JsValue::from_str(&e))?;
    let alice_secret = SecretKey::from_hex(alice_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {}", e)))?;

    let params =
        ChannelParameters::from_json_with_secret_key(params_json, keyset_info, &alice_secret)
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to create ChannelParameters: {}", e))
            })?;

    let blinded_secret = params
        .get_sender_blinded_secret_key_for_stage2_output(&alice_secret, amount, index as usize)
        .map_err(|e| JsValue::from_str(&format!("Failed to get blinded secret key: {}", e)))?;

    Ok(blinded_secret.to_secret_hex())
}

/// Get Charlie's blinded secret key for a specific stage 2 output
#[wasm_bindgen]
pub fn get_receiver_blinded_secret_key_for_stage2_output(
    params_json: &str,
    keyset_info_json: &str,
    charlie_secret_hex: &str,
    shared_secret_hex: &str,
    amount: u64,
    index: u32,
) -> Result<String, JsValue> {
    use cdk::spilman::parse_keyset_info_from_json;
    let keyset_info =
        parse_keyset_info_from_json(keyset_info_json).map_err(|e| JsValue::from_str(&e))?;
    let charlie_secret = SecretKey::from_hex(charlie_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {}", e)))?;

    let shared_secret_bytes = hex::decode(shared_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid shared secret hex: {}", e)))?;
    let shared_secret: [u8; 32] = shared_secret_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Shared secret must be 32 bytes"))?;

    let params =
        ChannelParameters::from_json_with_shared_secret(params_json, keyset_info, shared_secret)
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to create ChannelParameters: {}", e))
            })?;

    let blinded_secret = params
        .get_receiver_blinded_secret_key_for_stage2_output(&charlie_secret, amount, index as usize)
        .map_err(|e| JsValue::from_str(&format!("Failed to get blinded secret key: {}", e)))?;

    Ok(blinded_secret.to_secret_hex())
}
