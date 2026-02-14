//! WASM bindings for Cashu payment channels

use std::str::FromStr;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use async_trait::async_trait;

use cdk::nuts::{Id, PublicKey, SecretKey, Proof};
use cdk::spilman::{ChannelParameters, ChannelState, ClosingData, SpilmanBridge, SpilmanHost, SpilmanAsyncNetworking, PaymentProof, ChannelFunding, BalanceUpdateMessage, EstablishedChannel};
use cdk::util::hex;

#[wasm_bindgen(start)]
pub fn init() { console_error_panic_hook::set_once(); }

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
    fn save_funding(this: &JsSpilmanHost, channel_id: &str, params_json: &str, funding_proofs_json: &str, channel_secret_hex: &str, keyset_info_json: &str, initial_balance: u64, initial_signature: &str);
    #[wasm_bindgen(method, js_name = getAmountDue)]
    fn get_amount_due(this: &JsSpilmanHost, channel_id: &str, context_json: JsValue) -> u64;
    #[wasm_bindgen(method, js_name = recordPayment)]
    fn record_payment(this: &JsSpilmanHost, channel_id: &str, balance: u64, signature: &str, context_json: &str);
    #[wasm_bindgen(method, js_name = getChannelState)]
    fn get_channel_state(this: &JsSpilmanHost, channel_id: &str) -> String;
    #[wasm_bindgen(method, catch, js_name = markChannelClosing)]
    fn mark_channel_closing(this: &JsSpilmanHost, channel_id: &str, locktime: u64, balance: u64, signature: &str) -> Result<(), JsValue>;
    #[wasm_bindgen(method, js_name = getClosingData)]
    fn get_closing_data(this: &JsSpilmanHost, channel_id: &str) -> JsValue;
    #[wasm_bindgen(method, js_name = getChannelPolicy)]
    fn get_channel_policy(this: &JsSpilmanHost) -> String;
    #[wasm_bindgen(method, js_name = nowSeconds)]
    fn now_seconds(this: &JsSpilmanHost) -> u64;
    #[wasm_bindgen(method, js_name = getBalanceAndSignatureForUnilateralExit)]
    fn get_balance_and_signature_for_unilateral_exit(this: &JsSpilmanHost, channel_id: &str) -> JsValue;
    #[wasm_bindgen(method, js_name = getActiveKeysetIds)]
    fn get_active_keyset_ids(this: &JsSpilmanHost, mint: &str, unit: &str) -> JsValue;
    #[wasm_bindgen(method, js_name = getKeysetInfo)]
    fn get_keyset_info(this: &JsSpilmanHost, mint: &str, keyset_id: &str) -> JsValue;
    #[wasm_bindgen(method, js_name = callMintSwap)]
    fn call_mint_swap(this: &JsSpilmanHost, mint_url: &str, swap_request_json: &str) -> js_sys::Promise;
    #[wasm_bindgen(method, catch, js_name = markChannelClosed)]
    fn mark_channel_closed(this: &JsSpilmanHost, channel_id: &str, locktime: u64, balance: u64, receiver_proofs_json: &str, sender_proofs_json: &str, receiver_sum: u64, sender_sum: u64) -> Result<(), JsValue>;
    #[wasm_bindgen(method, js_name = refreshAllKeysets)]
    fn refresh_all_keysets(this: &JsSpilmanHost, mint: &str) -> js_sys::Promise;
    #[wasm_bindgen(method, catch, js_name = computeChannelSecret)]
    fn compute_channel_secret(this: &JsSpilmanHost, charlie_pubkey_hex: &str, alice_pubkey_hex: &str) -> Result<String, JsValue>;
    #[wasm_bindgen(method, catch, js_name = signWithTweakedKey)]
    fn sign_with_tweaked_key(this: &JsSpilmanHost, signer_pubkey_hex: &str, message_hex: &str, tweak_scalar_hex: &str) -> Result<String, JsValue>;
}

struct WasmSpilmanHostProxy { js_host: JsSpilmanHost }

unsafe impl Send for WasmSpilmanHostProxy {}
unsafe impl Sync for WasmSpilmanHostProxy {}

impl SpilmanHost<String> for WasmSpilmanHostProxy {
    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        let val = self.js_host.get_funding_and_params(channel_id);
        if val.is_null() || val.is_undefined() { return None; }
        let arr = js_sys::Array::from(&val);
        if arr.length() != 4 { return None; }
        Some(ChannelFunding { params_json: arr.get(0).as_string()?, funding_proofs_json: arr.get(1).as_string()?, channel_secret_hex: arr.get(2).as_string()?, keyset_info_json: arr.get(3).as_string()? })
    }
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool { self.js_host.receiver_key_is_acceptable(&receiver_pubkey.to_hex()) }
    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool { self.js_host.mint_and_keyset_is_acceptable(mint, &keyset_id.to_string()) }
    fn save_funding(&self, channel_id: &str, funding: ChannelFunding, initial_payment: PaymentProof) {
        self.js_host.save_funding(channel_id, &funding.params_json, &funding.funding_proofs_json, &funding.channel_secret_hex, &funding.keyset_info_json, initial_payment.balance, &initial_payment.signature);
    }
    fn get_amount_due(&self, channel_id: &str, context_json: Option<&String>) -> u64 {
        let ctx_val = match context_json { Some(s) => JsValue::from_str(s), None => JsValue::NULL };
        self.js_host.get_amount_due(channel_id, ctx_val)
    }
    fn record_payment(&self, channel_id: &str, payment: PaymentProof, context_json: &String) {
        self.js_host.record_payment(channel_id, payment.balance, &payment.signature, context_json);
    }
    fn get_channel_state(&self, channel_id: &str) -> ChannelState {
        match self.js_host.get_channel_state(channel_id).as_str() { "closed" => ChannelState::Closed, "closing" => ChannelState::Closing, _ => ChannelState::Open }
    }
    fn mark_channel_closing(&self, channel_id: &str, locktime: u64, payment: PaymentProof) -> Result<(), String> {
        self.js_host.mark_channel_closing(channel_id, locktime, payment.balance, &payment.signature).map_err(|e| format!("{:?}", e))
    }
    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        let val = self.js_host.get_closing_data(channel_id);
        if val.is_null() || val.is_undefined() { return None; }
        let obj = js_sys::Object::try_from(&val)?;
        let locktime = js_sys::Reflect::get(obj, &JsValue::from_str("locktime")).ok()?.as_f64()? as u64;
        let balance = js_sys::Reflect::get(obj, &JsValue::from_str("balance")).ok()?.as_f64()? as u64;
        let signature = js_sys::Reflect::get(obj, &JsValue::from_str("signature")).ok()?.as_string()?;
        Some(ClosingData { locktime, balance, signature })
    }
    fn get_channel_policy(&self) -> String { self.js_host.get_channel_policy() }
    fn now_seconds(&self) -> u64 { self.js_host.now_seconds() }
    fn get_balance_and_signature_for_unilateral_exit(&self, channel_id: &str) -> Option<PaymentProof> {
        let val = self.js_host.get_balance_and_signature_for_unilateral_exit(channel_id);
        if val.is_null() || val.is_undefined() { return None; }
        let arr = js_sys::Array::from(&val);
        if arr.length() != 2 { return None; }
        Some(PaymentProof { balance: arr.get(0).as_f64()? as u64, signature: arr.get(1).as_string()? })
    }
    fn get_active_keyset_ids(&self, mint: &str, unit: &cdk::nuts::CurrencyUnit) -> Vec<Id> {
        let val = self.js_host.get_active_keyset_ids(mint, &unit.to_string());
        if val.is_null() || val.is_undefined() { return Vec::new(); }
        js_sys::Array::from(&val).iter().filter_map(|v| v.as_string()).filter_map(|s| Id::from_str(&s).ok()).collect()
    }
    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String> { self.js_host.get_keyset_info(mint, &keyset_id.to_string()).as_string() }
    fn mark_channel_closed(&self, channel_id: &str, locktime: u64, balance: u64, receiver_proofs_json: &str, sender_proofs_json: &str, receiver_sum: u64, sender_sum: u64) -> Result<(), String> {
        self.js_host.mark_channel_closed(channel_id, locktime, balance, receiver_proofs_json, sender_proofs_json, receiver_sum, sender_sum).map_err(|e| format!("{:?}", e))
    }
    fn compute_channel_secret(&self, charlie_pubkey_hex: &str, alice_pubkey_hex: &str) -> Result<String, String> { self.js_host.compute_channel_secret(charlie_pubkey_hex, alice_pubkey_hex).map_err(|e| format!("{:?}", e)) }
    fn sign_with_tweaked_key(&self, signer_pubkey_hex: &str, message_hex: &str, tweak_scalar_hex: &str) -> Result<String, String> { self.js_host.sign_with_tweaked_key(signer_pubkey_hex, message_hex, tweak_scalar_hex).map_err(|e| format!("{:?}", e)) }
}

#[async_trait(?Send)]
impl SpilmanAsyncNetworking for WasmSpilmanHostProxy {
    async fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String> {
        let promise = self.js_host.call_mint_swap(mint_url, swap_request_json);
        let result = JsFuture::from(promise).await.map_err(|e| format!("{:?}", e))?;
        result.as_string().ok_or_else(|| "Not string".into())
    }
    async fn refresh_all_keysets(&self, mint: &str) -> Result<(), String> {
        let promise = self.js_host.refresh_all_keysets(mint);
        JsFuture::from(promise).await.map_err(|e| format!("{:?}", e))?;
        Ok(())
    }
}

#[wasm_bindgen]
pub struct WasmSpilmanBridge {
    bridge: SpilmanBridge<WasmSpilmanHostProxy>,
}

#[wasm_bindgen]
impl WasmSpilmanBridge {
    #[wasm_bindgen(constructor)]
    pub fn new(js_host: JsSpilmanHost) -> WasmSpilmanBridge {
        WasmSpilmanBridge { bridge: SpilmanBridge::new(WasmSpilmanHostProxy { js_host }) }
    }

    #[wasm_bindgen(js_name = processPayment)]
    pub fn process_payment(&self, payment_json: &str, context_json: &str) -> Result<JsValue, JsValue> {
        let context_json = context_json.to_string();
        self.bridge.process_payment_via_json(payment_json, &context_json).map(|r| serde_wasm_bindgen::to_value(&r).unwrap()).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen(js_name = validatePayment)]
    pub fn validate_payment(&self, payment_json: &str, context_json: &str) -> Result<JsValue, JsValue> {
        let context_json = context_json.to_string();
        self.bridge.validate_payment_via_json(payment_json, &context_json).map(|r| serde_wasm_bindgen::to_value(&r).unwrap()).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen(js_name = fundChannel)]
    pub fn fund_channel(&self, payment_json: &str) -> Result<JsValue, JsValue> {
        self.bridge.fund_channel_via_json(payment_json).map(|r| serde_wasm_bindgen::to_value(&r).unwrap()).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen(js_name = validateAndPrepareCooperativeClose)]
    pub fn validate_and_prepare_cooperative_close(&self, payment_json: &str) -> Result<String, JsValue> {
        match self.bridge.validate_and_prepare_cooperative_close(payment_json) {
            Ok(close_data) => Ok(close_data.to_json_value().to_string()),
            Err(e) => {
                let mut result = serde_json::json!({ "success": false, "error": e.to_string() });
                if let cdk::spilman::BridgeError::BalanceMismatch { expected, actual } = e {
                    if let Some(obj) = result.as_object_mut() {
                        obj.insert("expected".into(), serde_json::json!(expected));
                        obj.insert("actual".into(), serde_json::json!(actual));
                    }
                }
                Ok(result.to_string())
            }
        }
    }

    #[wasm_bindgen(js_name = createUnilateralCloseData)]
    pub fn create_unilateral_close_data(&self, channel_id: &str) -> Result<String, JsValue> {
        match self.bridge.create_unilateral_close_data(channel_id) {
            Ok(close_data) => Ok(close_data.to_json_value().to_string()),
            Err(e) => Ok(serde_json::json!({ "success": false, "error": e.to_string() }).to_string())
        }
    }

    #[wasm_bindgen(js_name = executeCooperativeClose)]
    pub async fn execute_cooperative_close(&self, payment_json: &str) -> Result<JsValue, JsValue> {
        self.bridge.execute_cooperative_close_async(payment_json, self.bridge.host()).await
            .map(|r| serde_wasm_bindgen::to_value(&r).unwrap())
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap_or_else(|_| JsValue::from_str(&e.to_string())))
    }

    #[wasm_bindgen(js_name = executeUnilateralClose)]
    pub async fn execute_unilateral_close(&self, channel_id: &str) -> Result<JsValue, JsValue> {
        self.bridge.execute_unilateral_close_async(channel_id, self.bridge.host()).await
            .map(|r| serde_wasm_bindgen::to_value(&r).unwrap())
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap_or_else(|_| JsValue::from_str(&e.to_string())))
    }
}

#[wasm_bindgen]
pub fn compute_channel_secret(my_secret_hex: &str, their_pubkey_hex: &str) -> Result<String, JsValue> {
    cdk::spilman::compute_channel_secret_from_hex(my_secret_hex, their_pubkey_hex).map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn sign_with_tweaked_key(secret_key_hex: &str, message_hex: &str, tweak_scalar_hex: &str) -> Result<String, JsValue> {
    cdk::spilman::sign_with_tweaked_key_util(secret_key_hex, message_hex, tweak_scalar_hex).map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn channel_parameters_get_channel_id(params_json: &str, channel_secret_hex: &str, keyset_info_json: &str) -> Result<String, JsValue> {
    cdk::spilman::channel_parameters_get_channel_id(params_json, channel_secret_hex, keyset_info_json).map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn compute_funding_token_amount(capacity: u64, keyset_info_json: &str, maximum_amount: u64) -> Result<u64, JsValue> {
    cdk::spilman::compute_funding_token_amount(capacity, keyset_info_json, maximum_amount).map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn create_funding_outputs(params_json: &str, my_secret_hex: &str, keyset_info_json: &str) -> Result<String, JsValue> {
    cdk::spilman::create_funding_outputs(params_json, my_secret_hex, keyset_info_json).map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn unblind_and_verify_dleq(blind_signatures_json: &str, secrets_with_blinding_json: &str, params_json: &str, keyset_info_json: &str, channel_secret_hex: &str, balance: u64, output_keyset_info_json: Option<String>) -> Result<String, JsValue> {
    cdk::spilman::unblind_and_verify_dleq(blind_signatures_json, secrets_with_blinding_json, params_json, keyset_info_json, channel_secret_hex, balance, output_keyset_info_json.as_deref()).map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn spilman_channel_sender_create_signed_balance_update(params_json: &str, keyset_info_json: &str, alice_secret_hex: &str, funding_proofs_json: &str, charlie_balance: u64) -> Result<String, JsValue> {
    cdk::spilman::create_signed_balance_update(params_json, keyset_info_json, alice_secret_hex, funding_proofs_json, charlie_balance).map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn verify_balance_update_signature(params_json: &str, channel_secret_hex: &str, funding_proofs_json: &str, keyset_info_json: &str, channel_id: &str, balance: u64, signature: &str) -> Result<bool, JsValue> {
    let secret: [u8; 32] = hex::decode(channel_secret_hex).map_err(|e| JsValue::from_str(&e.to_string()))?.try_into().map_err(|_| JsValue::from_str("Invalid secret"))?;
    let params = cdk::spilman::ChannelParameters::from_json_with_channel_secret(params_json, cdk::spilman::parse_keyset_info_from_json(keyset_info_json).map_err(|e| JsValue::from_str(&e.to_string()))?, secret).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let channel = EstablishedChannel::new(params, serde_json::from_str::<Vec<Proof>>(funding_proofs_json).map_err(|e| JsValue::from_str(&e.to_string()))?).map_err(|e| JsValue::from_str(&e.to_string()))?;
    BalanceUpdateMessage { channel_id: channel_id.to_string(), amount: balance, signature: signature.parse().map_err(|e: <bitcoin::secp256k1::schnorr::Signature as FromStr>::Err| JsValue::from_str(&e.to_string()))? }.verify_sender_signature(&channel).map(|_| true).map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn verify_proof_dleq(proof_json: &str, mint_pubkey_hex: &str) -> Result<bool, JsValue> {
    let proof: Proof = serde_json::from_str(proof_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    proof.verify_dleq(PublicKey::from_str(mint_pubkey_hex).map_err(|e| JsValue::from_str(&e.to_string()))?).map(|_| true).map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn verify_channel(params_json: &str, channel_secret_hex: &str, funding_proofs_json: &str, keyset_info_json: &str) -> Result<String, JsValue> {
    let secret: [u8; 32] = hex::decode(channel_secret_hex).map_err(|e| JsValue::from_str(&e.to_string()))?.try_into().map_err(|_| JsValue::from_str("Invalid secret"))?;
    let params = ChannelParameters::from_json_with_channel_secret(params_json, cdk::spilman::parse_keyset_info_from_json(keyset_info_json).map_err(|e| JsValue::from_str(&e.to_string()))?, secret).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let result = cdk::spilman::verify_valid_channel(&serde_json::from_str::<Vec<Proof>>(funding_proofs_json).map_err(|e| JsValue::from_str(&e.to_string()))?, &params);
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn construct_proofs(sigs_json: &str, swb_json: &str, keyset_json: &str) -> Result<String, JsValue> {
    cdk::spilman::construct_proofs(sigs_json, swb_json, keyset_json).map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn get_sender_blinded_secret_key_for_stage2_output(params_json: &str, keyset_json: &str, secret_hex: &str, amount: u64, index: u32) -> Result<String, JsValue> {
    let s = SecretKey::from_hex(secret_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let p = ChannelParameters::from_json_with_secret_key(params_json, cdk::spilman::parse_keyset_info_from_json(keyset_json).map_err(|e| JsValue::from_str(&e.to_string()))?, &s).map_err(|e| JsValue::from_str(&e.to_string()))?;
    p.get_sender_blinded_secret_key_for_stage2_output(&s, amount, index as usize).map(|k| k.to_secret_hex()).map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn get_receiver_blinded_secret_key_for_stage2_output(params_json: &str, keyset_json: &str, secret_hex: &str, channel_secret_hex: &str, amount: u64, index: u32) -> Result<String, JsValue> {
    let s = SecretKey::from_hex(secret_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let cs: [u8; 32] = hex::decode(channel_secret_hex).map_err(|e| JsValue::from_str(&e.to_string()))?.try_into().map_err(|_| JsValue::from_str("Invalid secret"))?;
    let p = ChannelParameters::from_json_with_channel_secret(params_json, cdk::spilman::parse_keyset_info_from_json(keyset_json).map_err(|e| JsValue::from_str(&e.to_string()))?, cs).map_err(|e| JsValue::from_str(&e.to_string()))?;
    p.get_receiver_blinded_secret_key_for_stage2_output(&s, amount, index as usize).map(|k| k.to_secret_hex()).map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn compute_funding_token_nominal(capacity: u64, keyset_info_json: &str, maximum_amount: u64) -> Result<u64, JsValue> {
    cdk::spilman::compute_funding_token_amount(capacity, keyset_info_json, maximum_amount).map_err(|e| JsValue::from_str(&e.to_string()))
}
