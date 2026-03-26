/* tslint:disable */
/* eslint-disable */

export class WasmSpilmanBridge {
    free(): void;
    [Symbol.dispose](): void;
    executeCooperativeClose(payment_json: string): Promise<any>;
    executeUnilateralClose(channel_id: string): Promise<any>;
    fundChannel(payment_json: string): any;
    constructor(js_host: any);
    paymentCoversAmountDue(payment_json: string, context_json: string): boolean;
    processPayment(payment_json: string, context_json: string): any;
    validatePayment(payment_json: string, context_json: string): any;
    verifyPaymentCoversAmountDue(payment_json: string, context_json: string): bigint;
}

export class WasmSpilmanClientBridge {
    free(): void;
    [Symbol.dispose](): void;
    buildPaymentHeader(channel_id: string, balance: bigint, include_funding: boolean): string;
    createCooperativeCloseRequest(channel_id: string, final_balance: bigint): string;
    getChannelInfo(channel_id: string): any;
    listChannels(): any;
    constructor(js_host: any);
    openChannelFromToken(token_string: string, receiver_pubkey_hex: string, sender_pubkey_hex: string, expiry_timestamp: bigint, keyset_info_json: string, max_amount: bigint): any;
    processCooperativeCloseResponse(response_json: string): void;
    removeChannel(channel_id: string): void;
}

export function build_cashu_b_token(mint_url: string, unit: string, proofs_json: string): string;

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

export function verify_balance_update_signature(params_json: string, channel_secret_hex: string, funding_proofs_json: string, keyset_info_json: string, channel_id: string, balance: bigint, signature: string): boolean;

export function verify_channel(params_json: string, channel_secret_hex: string, funding_proofs_json: string, keyset_info_json: string): string;

export function verify_proof_dleq(proof_json: string, mint_pubkey_hex: string): boolean;
