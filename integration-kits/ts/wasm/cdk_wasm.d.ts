/* tslint:disable */
/* eslint-disable */

export class WasmSpilmanBridge {
  free(): void;
  [Symbol.dispose](): void;
  fundChannel(payment_json: string): any;
  processPayment(payment_json: string, context_json: string): any;
  validatePayment(payment_json: string, context_json: string): any;
  executeUnilateralClose(channel_id: string): Promise<any>;
  executeCooperativeClose(payment_json: string): Promise<any>;
  createUnilateralCloseData(channel_id: string): string;
  validateAndPrepareCooperativeClose(payment_json: string): string;
  constructor(js_host: any);
}

export function channel_parameters_get_channel_id(params_json: string, channel_secret_hex: string, keyset_info_json: string): string;

export function compute_channel_secret(my_secret_hex: string, their_pubkey_hex: string): string;

export function compute_funding_token_amount(capacity: bigint, keyset_info_json: string, maximum_amount: bigint): bigint;

export function compute_funding_token_nominal(capacity: bigint, keyset_info_json: string, maximum_amount: bigint): bigint;

export function construct_proofs(sigs_json: string, swb_json: string, keyset_json: string): string;

export function create_funding_outputs(params_json: string, my_secret_hex: string, keyset_info_json: string): string;

export function get_receiver_blinded_secret_key_for_stage2_output(params_json: string, keyset_json: string, secret_hex: string, channel_secret_hex: string, amount: bigint, index: number): string;

export function get_sender_blinded_secret_key_for_stage2_output(params_json: string, keyset_json: string, secret_hex: string, amount: bigint, index: number): string;

export function sign_with_tweaked_key(secret_key_hex: string, message_hex: string, tweak_scalar_hex: string): string;

export function spilman_channel_sender_create_signed_balance_update(params_json: string, keyset_info_json: string, alice_secret_hex: string, funding_proofs_json: string, charlie_balance: bigint): string;

export function start(): void;

export function unblind_and_verify_dleq(blind_signatures_json: string, secrets_with_blinding_json: string, params_json: string, keyset_info_json: string, channel_secret_hex: string, balance: bigint, output_keyset_info_json?: string | null): string;

export function verify_balance_update_signature(params_json: string, channel_secret_hex: string, funding_proofs_json: string, keyset_info_json: string, channel_id: string, balance: bigint, signature: string): boolean;

export function verify_channel(params_json: string, channel_secret_hex: string, funding_proofs_json: string, keyset_info_json: string): string;

export function verify_proof_dleq(proof_json: string, mint_pubkey_hex: string): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_wasmspilmanbridge_free: (a: number, b: number) => void;
  readonly channel_parameters_get_channel_id: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly compute_channel_secret: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly compute_funding_token_amount: (a: bigint, b: number, c: number, d: bigint) => [bigint, number, number];
  readonly compute_funding_token_nominal: (a: bigint, b: number, c: number, d: bigint) => [bigint, number, number];
  readonly construct_proofs: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly create_funding_outputs: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly get_receiver_blinded_secret_key_for_stage2_output: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: number) => [number, number, number, number];
  readonly get_sender_blinded_secret_key_for_stage2_output: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number) => [number, number, number, number];
  readonly sign_with_tweaked_key: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly spilman_channel_sender_create_signed_balance_update: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint) => [number, number, number, number];
  readonly unblind_and_verify_dleq: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: bigint, l: number, m: number) => [number, number, number, number];
  readonly verify_balance_update_signature: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: bigint, l: number, m: number) => [number, number, number];
  readonly verify_channel: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
  readonly verify_proof_dleq: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly wasmspilmanbridge_createUnilateralCloseData: (a: number, b: number, c: number) => [number, number, number, number];
  readonly wasmspilmanbridge_executeCooperativeClose: (a: number, b: number, c: number) => any;
  readonly wasmspilmanbridge_executeUnilateralClose: (a: number, b: number, c: number) => any;
  readonly wasmspilmanbridge_fundChannel: (a: number, b: number, c: number) => [number, number, number];
  readonly wasmspilmanbridge_processPayment: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
  readonly wasmspilmanbridge_validateAndPrepareCooperativeClose: (a: number, b: number, c: number) => [number, number, number, number];
  readonly wasmspilmanbridge_validatePayment: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
  readonly wasmspilmanbridge_new: (a: any) => number;
  readonly start: () => void;
  readonly rustsecp256k1_v0_10_0_context_create: (a: number) => number;
  readonly rustsecp256k1_v0_10_0_context_destroy: (a: number) => void;
  readonly rustsecp256k1_v0_10_0_default_error_callback_fn: (a: number, b: number) => void;
  readonly rustsecp256k1_v0_10_0_default_illegal_callback_fn: (a: number, b: number) => void;
  readonly wasm_bindgen__convert__closures_____invoke__h57799704a46dd3be: (a: number, b: number, c: any) => void;
  readonly wasm_bindgen__closure__destroy__h4dc10dde27f91a71: (a: number, b: number) => void;
  readonly wasm_bindgen__convert__closures_____invoke__h774e692e0dfc3d08: (a: number, b: number, c: any, d: any) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
