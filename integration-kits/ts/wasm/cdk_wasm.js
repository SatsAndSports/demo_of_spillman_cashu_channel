
let imports = {};
imports['__wbindgen_placeholder__'] = module.exports;

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
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
    }
}

let WASM_VECTOR_LEN = 0;

function wasm_bindgen__convert__closures_____invoke__h57799704a46dd3be(arg0, arg1, arg2) {
    wasm.wasm_bindgen__convert__closures_____invoke__h57799704a46dd3be(arg0, arg1, arg2);
}

function wasm_bindgen__convert__closures_____invoke__h774e692e0dfc3d08(arg0, arg1, arg2, arg3) {
    wasm.wasm_bindgen__convert__closures_____invoke__h774e692e0dfc3d08(arg0, arg1, arg2, arg3);
}

const WasmSpilmanBridgeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmspilmanbridge_free(ptr >>> 0, 1));

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
     * @returns {any}
     */
    fundChannel(payment_json) {
        const ptr0 = passStringToWasm0(payment_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmspilmanbridge_fundChannel(this.__wbg_ptr, ptr0, len0);
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
    processPayment(payment_json, context_json) {
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
     * @param {string} channel_id
     * @returns {Promise<any>}
     */
    executeUnilateralClose(channel_id) {
        const ptr0 = passStringToWasm0(channel_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmspilmanbridge_executeUnilateralClose(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {string} payment_json
     * @returns {Promise<any>}
     */
    executeCooperativeClose(payment_json) {
        const ptr0 = passStringToWasm0(payment_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmspilmanbridge_executeCooperativeClose(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {string} channel_id
     * @returns {string}
     */
    createUnilateralCloseData(channel_id) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(channel_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmspilmanbridge_createUnilateralCloseData(this.__wbg_ptr, ptr0, len0);
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
     * @param {string} payment_json
     * @returns {string}
     */
    validateAndPrepareCooperativeClose(payment_json) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(payment_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmspilmanbridge_validateAndPrepareCooperativeClose(this.__wbg_ptr, ptr0, len0);
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
     * @param {any} js_host
     */
    constructor(js_host) {
        const ret = wasm.wasmspilmanbridge_new(js_host);
        this.__wbg_ptr = ret >>> 0;
        WasmSpilmanBridgeFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
}
if (Symbol.dispose) WasmSpilmanBridge.prototype[Symbol.dispose] = WasmSpilmanBridge.prototype.free;
exports.WasmSpilmanBridge = WasmSpilmanBridge;

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
    const ptr0 = passStringToWasm0(keyset_info_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
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
    const ptr0 = passStringToWasm0(keyset_info_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
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

function init() {
    wasm.init();
}
exports.init = init;

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

/**
 * @param {string} blind_signatures_json
 * @param {string} secrets_with_blinding_json
 * @param {string} params_json
 * @param {string} keyset_info_json
 * @param {string} channel_secret_hex
 * @param {bigint} balance
 * @param {string | null} [output_keyset_info_json]
 * @returns {string}
 */
function unblind_and_verify_dleq(blind_signatures_json, secrets_with_blinding_json, params_json, keyset_info_json, channel_secret_hex, balance, output_keyset_info_json) {
    let deferred8_0;
    let deferred8_1;
    try {
        const ptr0 = passStringToWasm0(blind_signatures_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(secrets_with_blinding_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(params_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(keyset_info_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(channel_secret_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        var ptr5 = isLikeNone(output_keyset_info_json) ? 0 : passStringToWasm0(output_keyset_info_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len5 = WASM_VECTOR_LEN;
        const ret = wasm.unblind_and_verify_dleq(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, balance, ptr5, len5);
        var ptr7 = ret[0];
        var len7 = ret[1];
        if (ret[3]) {
            ptr7 = 0; len7 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred8_0 = ptr7;
        deferred8_1 = len7;
        return getStringFromWasm0(ptr7, len7);
    } finally {
        wasm.__wbindgen_free(deferred8_0, deferred8_1, 1);
    }
}
exports.unblind_and_verify_dleq = unblind_and_verify_dleq;

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

exports.__wbg_Error_52673b7de5a0ca89 = function(arg0, arg1) {
    const ret = Error(getStringFromWasm0(arg0, arg1));
    return ret;
};

exports.__wbg___wbindgen_debug_string_adfb662ae34724b6 = function(arg0, arg1) {
    const ret = debugString(arg1);
    const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
    getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
};

exports.__wbg___wbindgen_is_function_8d400b8b1af978cd = function(arg0) {
    const ret = typeof(arg0) === 'function';
    return ret;
};

exports.__wbg___wbindgen_is_null_dfda7d66506c95b5 = function(arg0) {
    const ret = arg0 === null;
    return ret;
};

exports.__wbg___wbindgen_is_object_ce774f3490692386 = function(arg0) {
    const val = arg0;
    const ret = typeof(val) === 'object' && val !== null;
    return ret;
};

exports.__wbg___wbindgen_is_string_704ef9c8fc131030 = function(arg0) {
    const ret = typeof(arg0) === 'string';
    return ret;
};

exports.__wbg___wbindgen_is_undefined_f6b95eab589e0269 = function(arg0) {
    const ret = arg0 === undefined;
    return ret;
};

exports.__wbg___wbindgen_number_get_9619185a74197f95 = function(arg0, arg1) {
    const obj = arg1;
    const ret = typeof(obj) === 'number' ? obj : undefined;
    getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
    getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
};

exports.__wbg___wbindgen_string_get_a2a31e16edf96e42 = function(arg0, arg1) {
    const obj = arg1;
    const ret = typeof(obj) === 'string' ? obj : undefined;
    var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
    getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
};

exports.__wbg___wbindgen_throw_dd24417ed36fc46e = function(arg0, arg1) {
    throw new Error(getStringFromWasm0(arg0, arg1));
};

exports.__wbg__wbg_cb_unref_87dfb5aaa0cbcea7 = function(arg0) {
    arg0._wbg_cb_unref();
};

exports.__wbg_callMintSwap_9400b0ce300eefe6 = function(arg0, arg1, arg2, arg3, arg4) {
    const ret = arg0.callMintSwap(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
    return ret;
};

exports.__wbg_call_3020136f7a2d6e44 = function() { return handleError(function (arg0, arg1, arg2) {
    const ret = arg0.call(arg1, arg2);
    return ret;
}, arguments) };

exports.__wbg_call_abb4ff46ce38be40 = function() { return handleError(function (arg0, arg1) {
    const ret = arg0.call(arg1);
    return ret;
}, arguments) };

exports.__wbg_computeChannelSecret_46f312d860515a24 = function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5) {
    const ret = arg1.computeChannelSecret(getStringFromWasm0(arg2, arg3), getStringFromWasm0(arg4, arg5));
    const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
    getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
}, arguments) };

exports.__wbg_crypto_574e78ad8b13b65f = function(arg0) {
    const ret = arg0.crypto;
    return ret;
};

exports.__wbg_error_7534b8e9a36f1ab4 = function(arg0, arg1) {
    let deferred0_0;
    let deferred0_1;
    try {
        deferred0_0 = arg0;
        deferred0_1 = arg1;
        console.error(getStringFromWasm0(arg0, arg1));
    } finally {
        wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
    }
};

exports.__wbg_from_29a8414a7a7cd19d = function(arg0) {
    const ret = Array.from(arg0);
    return ret;
};

exports.__wbg_getActiveKeysetIds_89c0f59500efd972 = function(arg0, arg1, arg2, arg3, arg4) {
    const ret = arg0.getActiveKeysetIds(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
    return ret;
};

exports.__wbg_getAmountDue_59f1584ac2d17df3 = function(arg0, arg1, arg2, arg3) {
    const ret = arg0.getAmountDue(getStringFromWasm0(arg1, arg2), arg3);
    return ret;
};

exports.__wbg_getBalanceAndSignatureForUnilateralExit_8051a6ec7551e943 = function(arg0, arg1, arg2) {
    const ret = arg0.getBalanceAndSignatureForUnilateralExit(getStringFromWasm0(arg1, arg2));
    return ret;
};

exports.__wbg_getChannelPolicy_c3db502d323c9a64 = function(arg0, arg1, arg2) {
    const ret = arg0.getChannelPolicy(getStringFromWasm0(arg1, arg2));
    return ret;
};

exports.__wbg_getChannelState_b50cce1841b5b5f3 = function(arg0, arg1, arg2, arg3) {
    const ret = arg1.getChannelState(getStringFromWasm0(arg2, arg3));
    const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
    getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
};

exports.__wbg_getClosingData_bfff5996e4663086 = function(arg0, arg1, arg2) {
    const ret = arg0.getClosingData(getStringFromWasm0(arg1, arg2));
    return ret;
};

exports.__wbg_getFundingAndParams_c41a172dc138aeb5 = function(arg0, arg1, arg2) {
    const ret = arg0.getFundingAndParams(getStringFromWasm0(arg1, arg2));
    return ret;
};

exports.__wbg_getKeysetInfo_7359549655659127 = function(arg0, arg1, arg2, arg3, arg4) {
    const ret = arg0.getKeysetInfo(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
    return ret;
};

exports.__wbg_getRandomValues_b8f5dbd5f3995a9e = function() { return handleError(function (arg0, arg1) {
    arg0.getRandomValues(arg1);
}, arguments) };

exports.__wbg_get_6b7bd52aca3f9671 = function(arg0, arg1) {
    const ret = arg0[arg1 >>> 0];
    return ret;
};

exports.__wbg_get_af9dab7e9603ea93 = function() { return handleError(function (arg0, arg1) {
    const ret = Reflect.get(arg0, arg1);
    return ret;
}, arguments) };

exports.__wbg_length_22ac23eaec9d8053 = function(arg0) {
    const ret = arg0.length;
    return ret;
};

exports.__wbg_length_d45040a40c570362 = function(arg0) {
    const ret = arg0.length;
    return ret;
};

exports.__wbg_markChannelClosed_1a95945467314fb4 = function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) {
    arg0.markChannelClosed(getStringFromWasm0(arg1, arg2), BigInt.asUintN(64, arg3), BigInt.asUintN(64, arg4), getStringFromWasm0(arg5, arg6), getStringFromWasm0(arg7, arg8), BigInt.asUintN(64, arg9), BigInt.asUintN(64, arg10));
}, arguments) };

exports.__wbg_markChannelClosing_45e3d81e8e70eab3 = function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5, arg6) {
    arg0.markChannelClosing(getStringFromWasm0(arg1, arg2), BigInt.asUintN(64, arg3), BigInt.asUintN(64, arg4), getStringFromWasm0(arg5, arg6));
}, arguments) };

exports.__wbg_mintAndKeysetIsAcceptable_d66a32ec12bacfec = function(arg0, arg1, arg2, arg3, arg4) {
    const ret = arg0.mintAndKeysetIsAcceptable(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
    return ret;
};

exports.__wbg_msCrypto_a61aeb35a24c1329 = function(arg0) {
    const ret = arg0.msCrypto;
    return ret;
};

exports.__wbg_new_1ba21ce319a06297 = function() {
    const ret = new Object();
    return ret;
};

exports.__wbg_new_25f239778d6112b9 = function() {
    const ret = new Array();
    return ret;
};

exports.__wbg_new_8a6f238a6ece86ea = function() {
    const ret = new Error();
    return ret;
};

exports.__wbg_new_b546ae120718850e = function() {
    const ret = new Map();
    return ret;
};

exports.__wbg_new_ff12d2b041fb48f1 = function(arg0, arg1) {
    try {
        var state0 = {a: arg0, b: arg1};
        var cb0 = (arg0, arg1) => {
            const a = state0.a;
            state0.a = 0;
            try {
                return wasm_bindgen__convert__closures_____invoke__h774e692e0dfc3d08(a, state0.b, arg0, arg1);
            } finally {
                state0.a = a;
            }
        };
        const ret = new Promise(cb0);
        return ret;
    } finally {
        state0.a = state0.b = 0;
    }
};

exports.__wbg_new_no_args_cb138f77cf6151ee = function(arg0, arg1) {
    const ret = new Function(getStringFromWasm0(arg0, arg1));
    return ret;
};

exports.__wbg_new_with_length_aa5eaf41d35235e5 = function(arg0) {
    const ret = new Uint8Array(arg0 >>> 0);
    return ret;
};

exports.__wbg_node_905d3e251edff8a2 = function(arg0) {
    const ret = arg0.node;
    return ret;
};

exports.__wbg_nowSeconds_19e7721efab986c3 = function(arg0) {
    const ret = arg0.nowSeconds();
    return ret;
};

exports.__wbg_now_69d776cd24f5215b = function() {
    const ret = Date.now();
    return ret;
};

exports.__wbg_process_dc0fbacc7c1c06f7 = function(arg0) {
    const ret = arg0.process;
    return ret;
};

exports.__wbg_prototypesetcall_dfe9b766cdc1f1fd = function(arg0, arg1, arg2) {
    Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
};

exports.__wbg_queueMicrotask_9b549dfce8865860 = function(arg0) {
    const ret = arg0.queueMicrotask;
    return ret;
};

exports.__wbg_queueMicrotask_fca69f5bfad613a5 = function(arg0) {
    queueMicrotask(arg0);
};

exports.__wbg_randomFillSync_ac0988aba3254290 = function() { return handleError(function (arg0, arg1) {
    arg0.randomFillSync(arg1);
}, arguments) };

exports.__wbg_receiverKeyIsAcceptable_efc9b113ec9ca0f3 = function(arg0, arg1, arg2) {
    const ret = arg0.receiverKeyIsAcceptable(getStringFromWasm0(arg1, arg2));
    return ret;
};

exports.__wbg_recordPayment_3fedc0660308f212 = function(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) {
    arg0.recordPayment(getStringFromWasm0(arg1, arg2), BigInt.asUintN(64, arg3), getStringFromWasm0(arg4, arg5), getStringFromWasm0(arg6, arg7));
};

exports.__wbg_refreshAllKeysets_1526792e583a3307 = function(arg0, arg1, arg2) {
    const ret = arg0.refreshAllKeysets(getStringFromWasm0(arg1, arg2));
    return ret;
};

exports.__wbg_require_60cc747a6bc5215a = function() { return handleError(function () {
    const ret = module.require;
    return ret;
}, arguments) };

exports.__wbg_resolve_fd5bfbaa4ce36e1e = function(arg0) {
    const ret = Promise.resolve(arg0);
    return ret;
};

exports.__wbg_saveFunding_6c9857525f474788 = function(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13) {
    arg0.saveFunding(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4), getStringFromWasm0(arg5, arg6), getStringFromWasm0(arg7, arg8), getStringFromWasm0(arg9, arg10), BigInt.asUintN(64, arg11), getStringFromWasm0(arg12, arg13));
};

exports.__wbg_set_3f1d0b984ed272ed = function(arg0, arg1, arg2) {
    arg0[arg1] = arg2;
};

exports.__wbg_set_7df433eea03a5c14 = function(arg0, arg1, arg2) {
    arg0[arg1 >>> 0] = arg2;
};

exports.__wbg_set_efaaf145b9377369 = function(arg0, arg1, arg2) {
    const ret = arg0.set(arg1, arg2);
    return ret;
};

exports.__wbg_signWithTweakedKey_98683e33f437e916 = function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) {
    const ret = arg1.signWithTweakedKey(getStringFromWasm0(arg2, arg3), getStringFromWasm0(arg4, arg5), getStringFromWasm0(arg6, arg7));
    const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
    getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
}, arguments) };

exports.__wbg_stack_0ed75d68575b0f3c = function(arg0, arg1) {
    const ret = arg1.stack;
    const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
    getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
};

exports.__wbg_static_accessor_GLOBAL_769e6b65d6557335 = function() {
    const ret = typeof global === 'undefined' ? null : global;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
};

exports.__wbg_static_accessor_GLOBAL_THIS_60cf02db4de8e1c1 = function() {
    const ret = typeof globalThis === 'undefined' ? null : globalThis;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
};

exports.__wbg_static_accessor_SELF_08f5a74c69739274 = function() {
    const ret = typeof self === 'undefined' ? null : self;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
};

exports.__wbg_static_accessor_WINDOW_a8924b26aa92d024 = function() {
    const ret = typeof window === 'undefined' ? null : window;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
};

exports.__wbg_subarray_845f2f5bce7d061a = function(arg0, arg1, arg2) {
    const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
    return ret;
};

exports.__wbg_then_429f7caf1026411d = function(arg0, arg1, arg2) {
    const ret = arg0.then(arg1, arg2);
    return ret;
};

exports.__wbg_then_4f95312d68691235 = function(arg0, arg1) {
    const ret = arg0.then(arg1);
    return ret;
};

exports.__wbg_versions_c01dfd4722a88165 = function(arg0) {
    const ret = arg0.versions;
    return ret;
};

exports.__wbindgen_cast_2241b6af4c4b2941 = function(arg0, arg1) {
    // Cast intrinsic for `Ref(String) -> Externref`.
    const ret = getStringFromWasm0(arg0, arg1);
    return ret;
};

exports.__wbindgen_cast_4625c577ab2ec9ee = function(arg0) {
    // Cast intrinsic for `U64 -> Externref`.
    const ret = BigInt.asUintN(64, arg0);
    return ret;
};

exports.__wbindgen_cast_9ae0607507abb057 = function(arg0) {
    // Cast intrinsic for `I64 -> Externref`.
    const ret = arg0;
    return ret;
};

exports.__wbindgen_cast_cb9088102bce6b30 = function(arg0, arg1) {
    // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
    const ret = getArrayU8FromWasm0(arg0, arg1);
    return ret;
};

exports.__wbindgen_cast_d4ff28f80d43f797 = function(arg0, arg1) {
    // Cast intrinsic for `Closure(Closure { dtor_idx: 402, function: Function { arguments: [Externref], shim_idx: 403, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
    const ret = makeMutClosure(arg0, arg1, wasm.wasm_bindgen__closure__destroy__h4dc10dde27f91a71, wasm_bindgen__convert__closures_____invoke__h57799704a46dd3be);
    return ret;
};

exports.__wbindgen_cast_d6cd19b81560fd6e = function(arg0) {
    // Cast intrinsic for `F64 -> Externref`.
    const ret = arg0;
    return ret;
};

exports.__wbindgen_init_externref_table = function() {
    const table = wasm.__wbindgen_externrefs;
    const offset = table.grow(4);
    table.set(0, undefined);
    table.set(offset + 0, undefined);
    table.set(offset + 1, null);
    table.set(offset + 2, true);
    table.set(offset + 3, false);
};

const wasmPath = `${__dirname}/cdk_wasm_bg.wasm`;
const wasmBytes = require('fs').readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBytes);
const wasm = exports.__wasm = new WebAssembly.Instance(wasmModule, imports).exports;

wasm.__wbindgen_start();
