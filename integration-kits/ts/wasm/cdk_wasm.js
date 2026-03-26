/* @ts-self-types="./cdk_wasm.d.ts" */

//#region exports

class WasmSpilmanBridge {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmSpilmanBridgeFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmspilmanbridge_free(ptr, 0);
    }
    /**
     * @param {string} payment_json
     * @returns {Promise<any>}
     */
    executeCooperativeClose(payment_json) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(payment_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmspilmanbridge_executeCooperativeClose(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {string} channel_id
     * @returns {Promise<any>}
     */
    executeUnilateralClose(channel_id) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(channel_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmspilmanbridge_executeUnilateralClose(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {string} payment_json
     * @returns {any}
     */
    fundChannel(payment_json) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(payment_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmspilmanbridge_fundChannel(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {any} js_host
     */
    constructor(js_host) {
        const ret = wasm.wasmspilmanbridge_new(js_host);
        this.__wbg_ptr = ret >>> 0;
        WasmSpilmanBridgeFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {string} payment_json
     * @param {string} context_json
     * @returns {boolean}
     */
    paymentCoversAmountDue(payment_json, context_json) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(payment_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(context_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmspilmanbridge_paymentCoversAmountDue(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * @param {string} payment_json
     * @param {string} context_json
     * @returns {any}
     */
    processPayment(payment_json, context_json) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(payment_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(context_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmspilmanbridge_processPayment(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} payment_json
     * @param {string} context_json
     * @returns {any}
     */
    validatePayment(payment_json, context_json) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(payment_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(context_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmspilmanbridge_validatePayment(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} payment_json
     * @param {string} context_json
     * @returns {bigint}
     */
    verifyPaymentCoversAmountDue(payment_json, context_json) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(payment_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(context_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmspilmanbridge_verifyPaymentCoversAmountDue(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return BigInt.asUintN(64, ret[0]);
    }
}
if (Symbol.dispose) WasmSpilmanBridge.prototype[Symbol.dispose] = WasmSpilmanBridge.prototype.free;
exports.WasmSpilmanBridge = WasmSpilmanBridge;

class WasmSpilmanClientBridge {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmSpilmanClientBridgeFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmspilmanclientbridge_free(ptr, 0);
    }
    /**
     * @param {string} channel_id
     * @param {bigint} balance
     * @param {boolean} include_funding
     * @returns {string}
     */
    buildPaymentHeader(channel_id, balance, include_funding) {
        let deferred3_0;
        let deferred3_1;
        try {
            if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
            _assertNum(this.__wbg_ptr);
            const ptr0 = passStringToWasm0(channel_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            _assertBigInt(balance);
            _assertBoolean(include_funding);
            const ret = wasm.wasmspilmanclientbridge_buildPaymentHeader(this.__wbg_ptr, ptr0, len0, balance, include_funding);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * @param {string} channel_id
     * @param {bigint} final_balance
     * @returns {string}
     */
    createCooperativeCloseRequest(channel_id, final_balance) {
        let deferred3_0;
        let deferred3_1;
        try {
            if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
            _assertNum(this.__wbg_ptr);
            const ptr0 = passStringToWasm0(channel_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            _assertBigInt(final_balance);
            const ret = wasm.wasmspilmanclientbridge_createCooperativeCloseRequest(this.__wbg_ptr, ptr0, len0, final_balance);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * @param {string} channel_id
     * @returns {any}
     */
    getChannelInfo(channel_id) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(channel_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmspilmanclientbridge_getChannelInfo(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @returns {any}
     */
    listChannels() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.wasmspilmanclientbridge_listChannels(this.__wbg_ptr);
        return ret;
    }
    /**
     * @param {any} js_host
     */
    constructor(js_host) {
        const ret = wasm.wasmspilmanclientbridge_new(js_host);
        this.__wbg_ptr = ret >>> 0;
        WasmSpilmanClientBridgeFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {string} token_string
     * @param {string} receiver_pubkey_hex
     * @param {string} sender_pubkey_hex
     * @param {bigint} expiry_timestamp
     * @param {string} keyset_info_json
     * @param {bigint} max_amount
     * @returns {any}
     */
    openChannelFromToken(token_string, receiver_pubkey_hex, sender_pubkey_hex, expiry_timestamp, keyset_info_json, max_amount) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(token_string, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(receiver_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(sender_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        _assertBigInt(expiry_timestamp);
        const ptr3 = passStringToWasm0(keyset_info_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        _assertBigInt(max_amount);
        const ret = wasm.wasmspilmanclientbridge_openChannelFromToken(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, expiry_timestamp, ptr3, len3, max_amount);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * @param {string} response_json
     */
    processCooperativeCloseResponse(response_json) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(response_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmspilmanclientbridge_processCooperativeCloseResponse(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {string} channel_id
     */
    removeChannel(channel_id) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(channel_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.wasmspilmanclientbridge_removeChannel(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) WasmSpilmanClientBridge.prototype[Symbol.dispose] = WasmSpilmanClientBridge.prototype.free;
exports.WasmSpilmanClientBridge = WasmSpilmanClientBridge;

/**
 * @param {string} mint_url
 * @param {string} unit
 * @param {string} proofs_json
 * @returns {string}
 */
function build_cashu_b_token(mint_url, unit, proofs_json) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(mint_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(unit, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(proofs_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.build_cashu_b_token(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}
exports.build_cashu_b_token = build_cashu_b_token;

/**
 * @param {string} params_json
 * @param {string} channel_secret_hex
 * @param {string} keyset_info_json
 * @returns {string}
 */
function channel_parameters_get_channel_id(params_json, channel_secret_hex, keyset_info_json) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(params_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(channel_secret_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(keyset_info_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.channel_parameters_get_channel_id(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}
exports.channel_parameters_get_channel_id = channel_parameters_get_channel_id;

/**
 * @param {string} my_secret_hex
 * @param {string} their_pubkey_hex
 * @returns {string}
 */
function compute_channel_secret(my_secret_hex, their_pubkey_hex) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(my_secret_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(their_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.compute_channel_secret(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}
exports.compute_channel_secret = compute_channel_secret;

/**
 * @param {bigint} capacity
 * @param {string} keyset_info_json
 * @param {bigint} maximum_amount
 * @returns {bigint}
 */
function compute_funding_token_amount(capacity, keyset_info_json, maximum_amount) {
    _assertBigInt(capacity);
    const ptr0 = passStringToWasm0(keyset_info_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    _assertBigInt(maximum_amount);
    const ret = wasm.compute_funding_token_amount(capacity, ptr0, len0, maximum_amount);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return BigInt.asUintN(64, ret[0]);
}
exports.compute_funding_token_amount = compute_funding_token_amount;

/**
 * @param {bigint} capacity
 * @param {string} keyset_info_json
 * @param {bigint} maximum_amount
 * @returns {bigint}
 */
function compute_funding_token_nominal(capacity, keyset_info_json, maximum_amount) {
    _assertBigInt(capacity);
    const ptr0 = passStringToWasm0(keyset_info_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    _assertBigInt(maximum_amount);
    const ret = wasm.compute_funding_token_nominal(capacity, ptr0, len0, maximum_amount);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return BigInt.asUintN(64, ret[0]);
}
exports.compute_funding_token_nominal = compute_funding_token_nominal;

/**
 * @param {string} sigs_json
 * @param {string} swb_json
 * @param {string} keyset_json
 * @returns {string}
 */
function construct_proofs(sigs_json, swb_json, keyset_json) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(sigs_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(swb_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(keyset_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.construct_proofs(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}
exports.construct_proofs = construct_proofs;

/**
 * @param {string} params_json
 * @param {string} my_secret_hex
 * @param {string} keyset_info_json
 * @returns {string}
 */
function create_funding_outputs(params_json, my_secret_hex, keyset_info_json) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(params_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(my_secret_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(keyset_info_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.create_funding_outputs(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}
exports.create_funding_outputs = create_funding_outputs;

/**
 * @param {string} params_json
 * @param {string} keyset_json
 * @param {string} secret_hex
 * @param {string} channel_secret_hex
 * @param {bigint} amount
 * @param {number} index
 * @returns {string}
 */
function get_receiver_blinded_secret_key_for_stage2_output(params_json, keyset_json, secret_hex, channel_secret_hex, amount, index) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(params_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(keyset_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(secret_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(channel_secret_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        _assertBigInt(amount);
        _assertNum(index);
        const ret = wasm.get_receiver_blinded_secret_key_for_stage2_output(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, amount, index);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}
exports.get_receiver_blinded_secret_key_for_stage2_output = get_receiver_blinded_secret_key_for_stage2_output;

/**
 * @param {string} params_json
 * @param {string} keyset_json
 * @param {string} secret_hex
 * @param {bigint} amount
 * @param {number} index
 * @returns {string}
 */
function get_sender_blinded_secret_key_for_stage2_output(params_json, keyset_json, secret_hex, amount, index) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(params_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(keyset_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(secret_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        _assertBigInt(amount);
        _assertNum(index);
        const ret = wasm.get_sender_blinded_secret_key_for_stage2_output(ptr0, len0, ptr1, len1, ptr2, len2, amount, index);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}
exports.get_sender_blinded_secret_key_for_stage2_output = get_sender_blinded_secret_key_for_stage2_output;

/**
 * @param {string} secret_key_hex
 * @param {string} message_hex
 * @param {string} tweak_scalar_hex
 * @returns {string}
 */
function sign_with_tweaked_key(secret_key_hex, message_hex, tweak_scalar_hex) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(secret_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(message_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(tweak_scalar_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.sign_with_tweaked_key(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}
exports.sign_with_tweaked_key = sign_with_tweaked_key;

/**
 * @param {string} params_json
 * @param {string} keyset_info_json
 * @param {string} alice_secret_hex
 * @param {string} funding_proofs_json
 * @param {bigint} charlie_balance
 * @returns {string}
 */
function spilman_channel_sender_create_signed_balance_update(params_json, keyset_info_json, alice_secret_hex, funding_proofs_json, charlie_balance) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(params_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(keyset_info_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(alice_secret_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(funding_proofs_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        _assertBigInt(charlie_balance);
        const ret = wasm.spilman_channel_sender_create_signed_balance_update(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, charlie_balance);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}
exports.spilman_channel_sender_create_signed_balance_update = spilman_channel_sender_create_signed_balance_update;

function start() {
    wasm.start();
}
exports.start = start;

/**
 * @param {string} params_json
 * @param {string} channel_secret_hex
 * @param {string} funding_proofs_json
 * @param {string} keyset_info_json
 * @param {string} channel_id
 * @param {bigint} balance
 * @param {string} signature
 * @returns {boolean}
 */
function verify_balance_update_signature(params_json, channel_secret_hex, funding_proofs_json, keyset_info_json, channel_id, balance, signature) {
    const ptr0 = passStringToWasm0(params_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(channel_secret_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(funding_proofs_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(keyset_info_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(channel_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    _assertBigInt(balance);
    const ptr5 = passStringToWasm0(signature, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.verify_balance_update_signature(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, balance, ptr5, len5);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}
exports.verify_balance_update_signature = verify_balance_update_signature;

/**
 * @param {string} params_json
 * @param {string} channel_secret_hex
 * @param {string} funding_proofs_json
 * @param {string} keyset_info_json
 * @returns {string}
 */
function verify_channel(params_json, channel_secret_hex, funding_proofs_json, keyset_info_json) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(params_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(channel_secret_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(funding_proofs_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(keyset_info_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.verify_channel(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}
exports.verify_channel = verify_channel;

/**
 * @param {string} proof_json
 * @param {string} mint_pubkey_hex
 * @returns {boolean}
 */
function verify_proof_dleq(proof_json, mint_pubkey_hex) {
    const ptr0 = passStringToWasm0(proof_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(mint_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.verify_proof_dleq(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}
exports.verify_proof_dleq = verify_proof_dleq;

//#endregion

//#region wasm imports

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_83742b46f01ce22d: function() { return logError(function (arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        }, arguments); },
        __wbg___wbindgen_debug_string_5398f5bb970e0daa: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_is_function_3c846841762788c1: function(arg0) {
            const ret = typeof(arg0) === 'function';
            _assertBoolean(ret);
            return ret;
        },
        __wbg___wbindgen_is_null_0b605fc6b167c56f: function(arg0) {
            const ret = arg0 === null;
            _assertBoolean(ret);
            return ret;
        },
        __wbg___wbindgen_is_object_781bc9f159099513: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            _assertBoolean(ret);
            return ret;
        },
        __wbg___wbindgen_is_string_7ef6b97b02428fae: function(arg0) {
            const ret = typeof(arg0) === 'string';
            _assertBoolean(ret);
            return ret;
        },
        __wbg___wbindgen_is_undefined_52709e72fb9f179c: function(arg0) {
            const ret = arg0 === undefined;
            _assertBoolean(ret);
            return ret;
        },
        __wbg___wbindgen_number_get_34bb9d9dcfa21373: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'number' ? obj : undefined;
            if (!isLikeNone(ret)) {
                _assertNum(ret);
            }
            getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_string_get_395e606bd0ee4427: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_6ddd609b62940d55: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_6b5b6b8576d35cb1: function() { return logError(function (arg0) {
            arg0._wbg_cb_unref();
        }, arguments); },
        __wbg_callMintSwap_070e36b598e2edf7: function() { return logError(function (arg0, arg1, arg2, arg3, arg4) {
            const ret = arg0.callMintSwap(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
            return ret;
        }, arguments); },
        __wbg_call_2d781c1f4d5c0ef8: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_computeChannelSecret_3f5398485cb654e2: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5) {
            const ret = arg1.computeChannelSecret(getStringFromWasm0(arg2, arg3), getStringFromWasm0(arg4, arg5));
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_computeChannelSecret_8b9b2bc6f9fc9152: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5) {
            const ret = arg1.computeChannelSecret(getStringFromWasm0(arg2, arg3), getStringFromWasm0(arg4, arg5));
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_createTask_6eb3a8b6dd2f87c9: function() { return handleError(function (arg0, arg1) {
            const ret = console.createTask(getStringFromWasm0(arg0, arg1));
            return ret;
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function() { return logError(function (arg0) {
            const ret = arg0.crypto;
            return ret;
        }, arguments); },
        __wbg_deleteChannel_462a0b8d8394e299: function() { return logError(function (arg0, arg1, arg2) {
            arg0.deleteChannel(getStringFromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_error_a6fa202b58aa1cd3: function() { return logError(function (arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
            }
        }, arguments); },
        __wbg_from_4bdf88943703fd48: function() { return logError(function (arg0) {
            const ret = Array.from(arg0);
            return ret;
        }, arguments); },
        __wbg_getActiveKeysetIds_8bc31e5dc03c7695: function() { return logError(function (arg0, arg1, arg2, arg3, arg4) {
            const ret = arg0.getActiveKeysetIds(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
            return ret;
        }, arguments); },
        __wbg_getAmountDue_1dcebbf1a0f7685d: function() { return logError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.getAmountDue(getStringFromWasm0(arg1, arg2), arg3);
            _assertBigInt(ret);
            return ret;
        }, arguments); },
        __wbg_getBalanceAndSignatureForUnilateralExit_9ffe3a9c97a3d420: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.getBalanceAndSignatureForUnilateralExit(getStringFromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_getChannelPolicy_3d1aec825b0c245e: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.getChannelPolicy(getStringFromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_getChannelState_5a9c280b99a6fdcb: function() { return logError(function (arg0, arg1, arg2, arg3) {
            const ret = arg1.getChannelState(getStringFromWasm0(arg2, arg3));
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_getChannel_38c3bac8102da1dd: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.getChannel(getStringFromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_getClosingData_05f4f219af3ea5ab: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.getClosingData(getStringFromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_getFundingAndParams_04b5a1147ffb122b: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.getFundingAndParams(getStringFromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_getKeysetInfo_5162e9a2628be3a7: function() { return logError(function (arg0, arg1, arg2, arg3, arg4) {
            const ret = arg0.getKeysetInfo(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
            return ret;
        }, arguments); },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_get_3ef1eba1850ade27: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_a8ee5c45dabc1b3b: function() { return logError(function (arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        }, arguments); },
        __wbg_get_unchecked_329cfe50afab7352: function() { return logError(function (arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        }, arguments); },
        __wbg_length_b3416cf66a5452c8: function() { return logError(function (arg0) {
            const ret = arg0.length;
            _assertNum(ret);
            return ret;
        }, arguments); },
        __wbg_length_ea16607d7b61445b: function() { return logError(function (arg0) {
            const ret = arg0.length;
            _assertNum(ret);
            return ret;
        }, arguments); },
        __wbg_listChannelIds_99c71b35dc02af16: function() { return logError(function (arg0) {
            const ret = arg0.listChannelIds();
            return ret;
        }, arguments); },
        __wbg_markChannelClosed_c7492eab90ae1ed7: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) {
            arg0.markChannelClosed(getStringFromWasm0(arg1, arg2), BigInt.asUintN(64, arg3), BigInt.asUintN(64, arg4), getStringFromWasm0(arg5, arg6), getStringFromWasm0(arg7, arg8), BigInt.asUintN(64, arg9), BigInt.asUintN(64, arg10));
        }, arguments); },
        __wbg_markChannelClosing_e55d734cfaf613ed: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5, arg6) {
            arg0.markChannelClosing(getStringFromWasm0(arg1, arg2), BigInt.asUintN(64, arg3), BigInt.asUintN(64, arg4), getStringFromWasm0(arg5, arg6));
        }, arguments); },
        __wbg_mintAndKeysetIsAcceptable_77b26f33c30b24e0: function() { return logError(function (arg0, arg1, arg2, arg3, arg4) {
            const ret = arg0.mintAndKeysetIsAcceptable(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
            _assertBoolean(ret);
            return ret;
        }, arguments); },
        __wbg_msCrypto_bd5a034af96bcba6: function() { return logError(function (arg0) {
            const ret = arg0.msCrypto;
            return ret;
        }, arguments); },
        __wbg_new_227d7c05414eb861: function() { return logError(function () {
            const ret = new Error();
            return ret;
        }, arguments); },
        __wbg_new_49d5571bd3f0c4d4: function() { return logError(function () {
            const ret = new Map();
            return ret;
        }, arguments); },
        __wbg_new_a70fbab9066b301f: function() { return logError(function () {
            const ret = new Array();
            return ret;
        }, arguments); },
        __wbg_new_ab79df5bd7c26067: function() { return logError(function () {
            const ret = new Object();
            return ret;
        }, arguments); },
        __wbg_new_typed_aaaeaf29cf802876: function() { return logError(function (arg0, arg1) {
            try {
                var state0 = {a: arg0, b: arg1};
                var cb0 = (arg0, arg1) => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen__convert__closures_____invoke__h9db16ebf99d37f0f(a, state0.b, arg0, arg1);
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = new Promise(cb0);
                return ret;
            } finally {
                state0.a = state0.b = 0;
            }
        }, arguments); },
        __wbg_new_with_length_825018a1616e9e55: function() { return logError(function (arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        }, arguments); },
        __wbg_node_84ea875411254db1: function() { return logError(function (arg0) {
            const ret = arg0.node;
            return ret;
        }, arguments); },
        __wbg_nowSeconds_7c2c7b2a71340e0c: function() { return logError(function (arg0) {
            const ret = arg0.nowSeconds();
            _assertBigInt(ret);
            return ret;
        }, arguments); },
        __wbg_now_16f0c993d5dd6c27: function() { return logError(function () {
            const ret = Date.now();
            return ret;
        }, arguments); },
        __wbg_process_44c7a14e11e9f69e: function() { return logError(function (arg0) {
            const ret = arg0.process;
            return ret;
        }, arguments); },
        __wbg_prototypesetcall_d62e5099504357e6: function() { return logError(function (arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        }, arguments); },
        __wbg_queueMicrotask_0c399741342fb10f: function() { return logError(function (arg0) {
            const ret = arg0.queueMicrotask;
            return ret;
        }, arguments); },
        __wbg_queueMicrotask_a082d78ce798393e: function() { return logError(function (arg0) {
            queueMicrotask(arg0);
        }, arguments); },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_receiverKeyIsAcceptable_77d1dfd42fffffff: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.receiverKeyIsAcceptable(getStringFromWasm0(arg1, arg2));
            _assertBoolean(ret);
            return ret;
        }, arguments); },
        __wbg_recordPayment_7582470163966791: function() { return logError(function (arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) {
            arg0.recordPayment(getStringFromWasm0(arg1, arg2), BigInt.asUintN(64, arg3), getStringFromWasm0(arg4, arg5), getStringFromWasm0(arg6, arg7));
        }, arguments); },
        __wbg_refreshAllKeysets_3f57ae2a197b33ab: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.refreshAllKeysets(getStringFromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_resolve_ae8d83246e5bcc12: function() { return logError(function (arg0) {
            const ret = Promise.resolve(arg0);
            return ret;
        }, arguments); },
        __wbg_run_78b7b601add6ed6b: function() { return logError(function (arg0, arg1, arg2) {
            try {
                var state0 = {a: arg1, b: arg2};
                var cb0 = () => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen__convert__closures_____invoke__h4764fc08042495b0(a, state0.b, );
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = arg0.run(cb0);
                _assertBoolean(ret);
                return ret;
            } finally {
                state0.a = state0.b = 0;
            }
        }, arguments); },
        __wbg_saveChannel_1774ac29c316386e: function() { return logError(function (arg0, arg1, arg2, arg3, arg4, arg5, arg6) {
            arg0.saveChannel(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4), getStringFromWasm0(arg5, arg6));
        }, arguments); },
        __wbg_saveFunding_faa55d242931d7f2: function() { return logError(function (arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13) {
            arg0.saveFunding(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4), getStringFromWasm0(arg5, arg6), getStringFromWasm0(arg7, arg8), getStringFromWasm0(arg9, arg10), BigInt.asUintN(64, arg11), getStringFromWasm0(arg12, arg13));
        }, arguments); },
        __wbg_set_282384002438957f: function() { return logError(function (arg0, arg1, arg2) {
            arg0[arg1 >>> 0] = arg2;
        }, arguments); },
        __wbg_set_6be42768c690e380: function() { return logError(function (arg0, arg1, arg2) {
            arg0[arg1] = arg2;
        }, arguments); },
        __wbg_set_bf7251625df30a02: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.set(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_signWithTweakedKey_44a3eaaea83c1ea2: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) {
            const ret = arg1.signWithTweakedKey(getStringFromWasm0(arg2, arg3), getStringFromWasm0(arg4, arg5), getStringFromWasm0(arg6, arg7));
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_signWithTweakedKey_ebc87258b5fc2d41: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) {
            const ret = arg1.signWithTweakedKey(getStringFromWasm0(arg2, arg3), getStringFromWasm0(arg4, arg5), getStringFromWasm0(arg6, arg7));
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_stack_3b0d974bbf31e44f: function() { return logError(function (arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_static_accessor_GLOBAL_8adb955bd33fac2f: function() { return logError(function () {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_static_accessor_GLOBAL_THIS_ad356e0db91c7913: function() { return logError(function () {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_static_accessor_SELF_f207c857566db248: function() { return logError(function () {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_static_accessor_WINDOW_bb9f1ba69d61b386: function() { return logError(function () {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_subarray_a068d24e39478a8a: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        }, arguments); },
        __wbg_then_098abe61755d12f6: function() { return logError(function (arg0, arg1) {
            const ret = arg0.then(arg1);
            return ret;
        }, arguments); },
        __wbg_then_9e335f6dd892bc11: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.then(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_versions_276b2795b1c6a219: function() { return logError(function (arg0) {
            const ret = arg0.versions;
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000001: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { dtor_idx: 474, function: Function { arguments: [Externref], shim_idx: 498, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm.wasm_bindgen__closure__destroy__h9d862f96957e8075, wasm_bindgen__convert__closures_____invoke__hd1dc654c3d1c0ab7);
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000002: function() { return logError(function (arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000003: function() { return logError(function (arg0) {
            // Cast intrinsic for `I64 -> Externref`.
            const ret = arg0;
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000004: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000005: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000006: function() { return logError(function (arg0) {
            // Cast intrinsic for `U64 -> Externref`.
            const ret = BigInt.asUintN(64, arg0);
            return ret;
        }, arguments); },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./cdk_wasm_bg.js": import0,
    };
}


//#endregion
function wasm_bindgen__convert__closures_____invoke__h4764fc08042495b0(arg0, arg1) {
    _assertNum(arg0);
    _assertNum(arg1);
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__h4764fc08042495b0(arg0, arg1);
    return ret !== 0;
}

function wasm_bindgen__convert__closures_____invoke__hd1dc654c3d1c0ab7(arg0, arg1, arg2) {
    _assertNum(arg0);
    _assertNum(arg1);
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__hd1dc654c3d1c0ab7(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__h9db16ebf99d37f0f(arg0, arg1, arg2, arg3) {
    _assertNum(arg0);
    _assertNum(arg1);
    wasm.wasm_bindgen__convert__closures_____invoke__h9db16ebf99d37f0f(arg0, arg1, arg2, arg3);
}

const WasmSpilmanBridgeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmspilmanbridge_free(ptr >>> 0, 1));
const WasmSpilmanClientBridgeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmspilmanclientbridge_free(ptr >>> 0, 1));


//#region intrinsics
function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function _assertBigInt(n) {
    if (typeof(n) !== 'bigint') throw new Error(`expected a bigint argument, found ${typeof(n)}`);
}

function _assertBoolean(n) {
    if (typeof(n) !== 'boolean') {
        throw new Error(`expected a boolean argument, found ${typeof(n)}`);
    }
}

function _assertNum(n) {
    if (typeof(n) !== 'number') throw new Error(`expected a number argument, found ${typeof(n)}`);
}

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(state => state.dtor(state.a, state.b));

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function logError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        let error = (function () {
            try {
                return e instanceof Error ? `${e.message}\n\nStack:\n${e.stack}` : e.toString();
            } catch(_) {
                return "<failed to stringify thrown value>";
            }
        }());
        console.error("wasm-bindgen: imported JS function that was not marked as `catch` threw an error:", error);
        throw e;
    }
}

function makeMutClosure(arg0, arg1, dtor, f) {
    const state = { a: arg0, b: arg1, cnt: 1, dtor };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            state.a = a;
            real._wbg_cb_unref();
        }
    };
    real._wbg_cb_unref = () => {
        if (--state.cnt === 0) {
            state.dtor(state.a, state.b);
            state.a = 0;
            CLOSURE_DTORS.unregister(state);
        }
    };
    CLOSURE_DTORS.register(real, state, state);
    return real;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (typeof(arg) !== 'string') throw new Error(`expected a string argument, found ${typeof(arg)}`);
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);
        if (ret.read !== arg.length) throw new Error('failed to pass whole string');
        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
function decodeText(ptr, len) {
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;


//#endregion

//#region wasm loading
const wasmPath = `${__dirname}/cdk_wasm_bg.wasm`;
const wasmBytes = require('fs').readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBytes);
let wasm = new WebAssembly.Instance(wasmModule, __wbg_get_imports()).exports;
wasm.__wbindgen_start();

//#endregion
exports.__wasm = wasm;
