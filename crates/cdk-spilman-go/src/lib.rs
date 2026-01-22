use cdk::nuts::SecretKey;
use cdk::spilman::{self, SpilmanBridge, SpilmanHost};
pub use libc::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::ptr;

// ============================================================================
// C-Compatible Types
// ============================================================================

#[repr(C)]
pub struct CResult {
    pub data: *mut c_char,
    pub error: *mut c_char,
}

impl CResult {
    fn success(data: String) -> Self {
        CResult {
            data: CString::new(data).unwrap().into_raw(),
            error: ptr::null_mut(),
        }
    }

    fn error(err: String) -> Self {
        CResult {
            data: ptr::null_mut(),
            error: CString::new(err).unwrap().into_raw(),
        }
    }
}

#[repr(C)]
pub struct SpilmanHostCallbacks {
    pub user_data: *mut libc::c_void,
    pub receiver_key_is_acceptable:
        extern "C" fn(user_data: *mut libc::c_void, pubkey_hex: *const c_char) -> c_int,
    pub mint_and_keyset_is_acceptable: extern "C" fn(
        user_data: *mut libc::c_void,
        mint: *const c_char,
        keyset_id: *const c_char,
    ) -> c_int,
    pub get_funding_and_params: extern "C" fn(
        user_data: *mut libc::c_void,
        channel_id: *const c_char,
        params_out: *mut *mut c_char,
        proofs_out: *mut *mut c_char,
        secret_out: *mut *mut c_char,
        keyset_out: *mut *mut c_char,
    ) -> c_int,
    pub save_funding: extern "C" fn(
        user_data: *mut libc::c_void,
        channel_id: *const c_char,
        params_json: *const c_char,
        funding_proofs_json: *const c_char,
        shared_secret_hex: *const c_char,
        keyset_info_json: *const c_char,
    ),
    pub get_amount_due: extern "C" fn(
        user_data: *mut libc::c_void,
        channel_id: *const c_char,
        context_json: *const c_char,
    ) -> u64,
    pub record_payment: extern "C" fn(
        user_data: *mut libc::c_void,
        channel_id: *const c_char,
        balance: u64,
        signature: *const c_char,
        context_json: *const c_char,
    ),
    pub is_closed: extern "C" fn(user_data: *mut libc::c_void, channel_id: *const c_char) -> c_int,
    pub get_channel_policy: extern "C" fn(user_data: *mut libc::c_void) -> *mut c_char,
    pub now_seconds: extern "C" fn(user_data: *mut libc::c_void) -> u64,
    pub get_balance_and_signature_for_unilateral_exit: extern "C" fn(
        user_data: *mut libc::c_void,
        channel_id: *const c_char,
        balance_out: *mut u64,
        signature_out: *mut *mut c_char,
    ) -> c_int,
    pub get_active_keyset_ids: extern "C" fn(
        user_data: *mut libc::c_void,
        mint: *const c_char,
        unit: *const c_char,
    ) -> *mut c_char, // Returns JSON array string
    pub get_keyset_info: extern "C" fn(
        user_data: *mut libc::c_void,
        mint: *const c_char,
        keyset_id: *const c_char,
    ) -> *mut c_char, // Returns KeysetInfo JSON
}

struct CGoSpilmanHost {
    callbacks: SpilmanHostCallbacks,
}

// Safety: We assume the Go side handles thread safety if it provides a shared user_data
unsafe impl Send for CGoSpilmanHost {}
unsafe impl Sync for CGoSpilmanHost {}

impl SpilmanHost for CGoSpilmanHost {
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &cdk::nuts::PublicKey) -> bool {
        let hex = CString::new(receiver_pubkey.to_hex()).unwrap();
        (self.callbacks.receiver_key_is_acceptable)(self.callbacks.user_data, hex.as_ptr()) != 0
    }

    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &cdk::nuts::Id) -> bool {
        let mint_c = CString::new(mint).unwrap();
        let kid_c = CString::new(keyset_id.to_string()).unwrap();
        (self.callbacks.mint_and_keyset_is_acceptable)(
            self.callbacks.user_data,
            mint_c.as_ptr(),
            kid_c.as_ptr(),
        ) != 0
    }

    fn get_funding_and_params(&self, channel_id: &str) -> Option<(String, String, String, String)> {
        let id_c = CString::new(channel_id).unwrap();
        let mut p_ptr: *mut c_char = ptr::null_mut();
        let mut pr_ptr: *mut c_char = ptr::null_mut();
        let mut s_ptr: *mut c_char = ptr::null_mut();
        let mut k_ptr: *mut c_char = ptr::null_mut();

        let ok = (self.callbacks.get_funding_and_params)(
            self.callbacks.user_data,
            id_c.as_ptr(),
            &mut p_ptr,
            &mut pr_ptr,
            &mut s_ptr,
            &mut k_ptr,
        );

        if ok != 0 {
            unsafe {
                let p = CString::from_raw(p_ptr).into_string().unwrap();
                let pr = CString::from_raw(pr_ptr).into_string().unwrap();
                let s = CString::from_raw(s_ptr).into_string().unwrap();
                let k = CString::from_raw(k_ptr).into_string().unwrap();
                Some((p, pr, s, k))
            }
        } else {
            None
        }
    }

    fn save_funding(
        &self,
        channel_id: &str,
        params_json: &str,
        funding_proofs_json: &str,
        shared_secret_hex: &str,
        keyset_info_json: &str,
    ) {
        let id_c = CString::new(channel_id).unwrap();
        let p_c = CString::new(params_json).unwrap();
        let pr_c = CString::new(funding_proofs_json).unwrap();
        let s_c = CString::new(shared_secret_hex).unwrap();
        let k_c = CString::new(keyset_info_json).unwrap();

        (self.callbacks.save_funding)(
            self.callbacks.user_data,
            id_c.as_ptr(),
            p_c.as_ptr(),
            pr_c.as_ptr(),
            s_c.as_ptr(),
            k_c.as_ptr(),
        );
    }

    fn get_amount_due(&self, channel_id: &str, context_json: Option<&str>) -> u64 {
        let id_c = CString::new(channel_id).unwrap();
        let ctx_c = context_json.map(|s| CString::new(s).unwrap());
        let ctx_ptr = ctx_c.as_ref().map(|c| c.as_ptr()).unwrap_or(ptr::null());
        (self.callbacks.get_amount_due)(self.callbacks.user_data, id_c.as_ptr(), ctx_ptr)
    }

    fn record_payment(&self, channel_id: &str, balance: u64, signature: &str, context_json: &str) {
        let id_c = CString::new(channel_id).unwrap();
        let sig_c = CString::new(signature).unwrap();
        let ctx_c = CString::new(context_json).unwrap();
        (self.callbacks.record_payment)(
            self.callbacks.user_data,
            id_c.as_ptr(),
            balance,
            sig_c.as_ptr(),
            ctx_c.as_ptr(),
        );
    }

    fn is_closed(&self, channel_id: &str) -> bool {
        let id_c = CString::new(channel_id).unwrap();
        (self.callbacks.is_closed)(self.callbacks.user_data, id_c.as_ptr()) != 0
    }

    fn get_channel_policy(&self) -> String {
        let ptr = (self.callbacks.get_channel_policy)(self.callbacks.user_data);
        if ptr.is_null() {
            return "{}".to_string();
        }
        unsafe { CString::from_raw(ptr).into_string().unwrap() }
    }

    fn now_seconds(&self) -> u64 {
        (self.callbacks.now_seconds)(self.callbacks.user_data)
    }

    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        channel_id: &str,
    ) -> Option<(u64, String)> {
        let id_c = CString::new(channel_id).unwrap();
        let mut balance: u64 = 0;
        let mut sig_ptr: *mut c_char = ptr::null_mut();

        let ok = (self.callbacks.get_balance_and_signature_for_unilateral_exit)(
            self.callbacks.user_data,
            id_c.as_ptr(),
            &mut balance,
            &mut sig_ptr,
        );

        if ok != 0 {
            unsafe {
                let sig = CString::from_raw(sig_ptr).into_string().unwrap();
                Some((balance, sig))
            }
        } else {
            None
        }
    }

    fn get_active_keyset_ids(
        &self,
        mint: &str,
        unit: &cdk::nuts::CurrencyUnit,
    ) -> Vec<cdk::nuts::Id> {
        let mint_c = CString::new(mint).unwrap();
        let unit_str = unit.to_string();
        let unit_c = CString::new(unit_str).unwrap();

        let json_ptr = (self.callbacks.get_active_keyset_ids)(
            self.callbacks.user_data,
            mint_c.as_ptr(),
            unit_c.as_ptr(),
        );
        if json_ptr.is_null() {
            return Vec::new();
        }

        unsafe {
            let json = CString::from_raw(json_ptr).into_string().unwrap();
            serde_json::from_str(&json).unwrap_or_default()
        }
    }

    fn get_keyset_info(&self, mint: &str, keyset_id: &cdk::nuts::Id) -> Option<String> {
        let mint_c = CString::new(mint).unwrap();
        let kid_c = CString::new(keyset_id.to_string()).unwrap();

        let json_ptr = (self.callbacks.get_keyset_info)(
            self.callbacks.user_data,
            mint_c.as_ptr(),
            kid_c.as_ptr(),
        );
        if json_ptr.is_null() {
            return None;
        }

        unsafe { Some(CString::from_raw(json_ptr).into_string().unwrap()) }
    }
}

// ============================================================================
// Bridge Instance
// ============================================================================

pub struct BridgeInstance {
    bridge: SpilmanBridge<CGoSpilmanHost>,
}

#[no_mangle]
pub unsafe extern "C" fn spilman_bridge_new(
    callbacks: SpilmanHostCallbacks,
    server_secret_key_hex: *const c_char,
) -> *mut BridgeInstance {
    let secret_key = if !server_secret_key_hex.is_null() {
        let hex = CStr::from_ptr(server_secret_key_hex).to_str().unwrap();
        SecretKey::from_hex(hex).ok()
    } else {
        None
    };

    let host = CGoSpilmanHost { callbacks };
    let bridge = SpilmanBridge::new(host, secret_key);

    Box::into_raw(Box::new(BridgeInstance { bridge }))
}

#[no_mangle]
pub unsafe extern "C" fn spilman_bridge_free(ptr: *mut BridgeInstance) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_bridge_process_payment(
    ptr: *mut BridgeInstance,
    payment_json: *const c_char,
    context_json: *const c_char,
    keyset_info_json: *const c_char,
) -> CResult {
    let instance = &*ptr;
    let payment = CStr::from_ptr(payment_json).to_str().unwrap();
    let context = CStr::from_ptr(context_json).to_str().unwrap();
    let keyset_info = if !keyset_info_json.is_null() {
        Some(CStr::from_ptr(keyset_info_json).to_str().unwrap())
    } else {
        None
    };

    let response = instance
        .bridge
        .process_payment(payment, context, keyset_info);
    let json = serde_json::to_string(&response).unwrap();
    CResult::success(json)
}

#[no_mangle]
pub unsafe extern "C" fn spilman_bridge_create_close_data(
    ptr: *mut BridgeInstance,
    payment_json: *const c_char,
    keyset_info_json: *const c_char,
) -> CResult {
    let instance = &*ptr;
    let payment = CStr::from_ptr(payment_json).to_str().unwrap();
    let keyset_info = if !keyset_info_json.is_null() {
        Some(CStr::from_ptr(keyset_info_json).to_str().unwrap())
    } else {
        None
    };

    match instance.bridge.create_close_data(payment, keyset_info) {
        Ok(close_data) => {
            let swap_request_json = serde_json::to_value(&close_data.swap_request).unwrap();
            let secrets_with_blinding: Vec<serde_json::Value> = close_data
                .secrets_with_blinding
                .into_iter()
                .map(|(s, is_receiver)| {
                    serde_json::json!({
                        "secret": s.secret.to_string(),
                        "blinding_factor": cdk::util::hex::encode(s.blinding_factor.secret_bytes()),
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
            CResult::success(result.to_string())
        }
        Err(e) => CResult::error(e.to_string()),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_bridge_create_unilateral_close_data(
    ptr: *mut BridgeInstance,
    channel_id: *const c_char,
) -> CResult {
    let instance = &*ptr;
    let id = CStr::from_ptr(channel_id).to_str().unwrap();

    match instance.bridge.create_unilateral_close_data(id) {
        Ok(close_data) => {
            let swap_request_json = serde_json::to_value(&close_data.swap_request).unwrap();
            let secrets_with_blinding: Vec<serde_json::Value> = close_data
                .secrets_with_blinding
                .into_iter()
                .map(|(s, is_receiver)| {
                    serde_json::json!({
                        "secret": s.secret.to_string(),
                        "blinding_factor": cdk::util::hex::encode(s.blinding_factor.secret_bytes()),
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
            CResult::success(result.to_string())
        }
        Err(e) => CResult::error(e.to_string()),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_unblind_and_verify_dleq(
    sigs_json: *const c_char,
    secrets_json: *const c_char,
    params_json: *const c_char,
    keyset_json: *const c_char,
    shared_secret_hex: *const c_char,
    balance: u64,
    output_keyset_json: *const c_char,
) -> CResult {
    let sigs = CStr::from_ptr(sigs_json).to_str().unwrap();
    let secrets = CStr::from_ptr(secrets_json).to_str().unwrap();
    let params = CStr::from_ptr(params_json).to_str().unwrap();
    let keyset = CStr::from_ptr(keyset_json).to_str().unwrap();
    let secret = CStr::from_ptr(shared_secret_hex).to_str().unwrap();
    let output_keyset = if !output_keyset_json.is_null() {
        Some(CStr::from_ptr(output_keyset_json).to_str().unwrap())
    } else {
        None
    };

    match spilman::unblind_and_verify_dleq(
        sigs,
        secrets,
        params,
        keyset,
        secret,
        balance,
        output_keyset,
    ) {
        Ok(res) => CResult::success(res),
        Err(e) => CResult::error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_create_signed_balance_update(
    params_json: *const c_char,
    keyset_json: *const c_char,
    secret_hex: *const c_char,
    proofs_json: *const c_char,
    balance: u64,
) -> CResult {
    let p = CStr::from_ptr(params_json).to_str().unwrap();
    let k = CStr::from_ptr(keyset_json).to_str().unwrap();
    let s = CStr::from_ptr(secret_hex).to_str().unwrap();
    let pr = CStr::from_ptr(proofs_json).to_str().unwrap();

    match spilman::create_signed_balance_update(p, k, s, pr, balance) {
        Ok(res) => CResult::success(res),
        Err(e) => CResult::error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_generate_keypair() -> CResult {
    let secret = SecretKey::generate();
    let pubkey = secret.public_key();
    let json = serde_json::json!({
        "secret": secret.to_secret_hex(),
        "pubkey": pubkey.to_hex()
    })
    .to_string();
    CResult::success(json)
}

#[no_mangle]
pub unsafe extern "C" fn spilman_secret_key_to_pubkey(secret_hex: *const c_char) -> CResult {
    let hex = CStr::from_ptr(secret_hex).to_str().unwrap();
    match SecretKey::from_hex(hex) {
        Ok(sk) => CResult::success(sk.public_key().to_hex()),
        Err(e) => CResult::error(e.to_string()),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_free_cresult(res: CResult) {
    spilman_free_string(res.data);
    spilman_free_string(res.error);
}

#[no_mangle]
pub unsafe extern "C" fn spilman_compute_shared_secret(
    my_secret_hex: *const c_char,
    their_pubkey_hex: *const c_char,
) -> CResult {
    let my_sk = CStr::from_ptr(my_secret_hex).to_str().unwrap();
    let their_pk = CStr::from_ptr(their_pubkey_hex).to_str().unwrap();

    match spilman::compute_shared_secret_from_hex(my_sk, their_pk) {
        Ok(s) => CResult::success(s),
        Err(e) => CResult::error(e.to_string()),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_channel_parameters_get_channel_id(
    params_json: *const c_char,
    shared_secret_hex: *const c_char,
    keyset_info_json: *const c_char,
) -> CResult {
    let p = CStr::from_ptr(params_json).to_str().unwrap();
    let s = CStr::from_ptr(shared_secret_hex).to_str().unwrap();
    let k = CStr::from_ptr(keyset_info_json).to_str().unwrap();

    match spilman::channel_parameters_get_channel_id(p, s, k) {
        Ok(id) => CResult::success(id),
        Err(e) => CResult::error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_create_funding_outputs(
    params_json: *const c_char,
    alice_secret_hex: *const c_char,
    keyset_info_json: *const c_char,
) -> CResult {
    let p = CStr::from_ptr(params_json).to_str().unwrap();
    let s = CStr::from_ptr(alice_secret_hex).to_str().unwrap();
    let k = CStr::from_ptr(keyset_info_json).to_str().unwrap();

    match spilman::create_funding_outputs(p, s, k) {
        Ok(json) => CResult::success(json),
        Err(e) => CResult::error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn spilman_construct_proofs(
    blind_signatures_json: *const c_char,
    secrets_with_blinding_json: *const c_char,
    keyset_info_json: *const c_char,
) -> CResult {
    let sigs = CStr::from_ptr(blind_signatures_json).to_str().unwrap();
    let secrets = CStr::from_ptr(secrets_with_blinding_json).to_str().unwrap();
    let k = CStr::from_ptr(keyset_info_json).to_str().unwrap();

    match spilman::construct_proofs(sigs, secrets, k) {
        Ok(json) => CResult::success(json),
        Err(e) => CResult::error(e),
    }
}
