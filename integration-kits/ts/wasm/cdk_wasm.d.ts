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

export function init(): void;

export function sign_with_tweaked_key(secret_key_hex: string, message_hex: string, tweak_scalar_hex: string): string;

export function spilman_channel_sender_create_signed_balance_update(params_json: string, keyset_info_json: string, alice_secret_hex: string, funding_proofs_json: string, charlie_balance: bigint): string;

export function unblind_and_verify_dleq(blind_signatures_json: string, secrets_with_blinding_json: string, params_json: string, keyset_info_json: string, channel_secret_hex: string, balance: bigint, output_keyset_info_json?: string | null): string;

export function verify_balance_update_signature(params_json: string, channel_secret_hex: string, funding_proofs_json: string, keyset_info_json: string, channel_id: string, balance: bigint, signature: string): boolean;

export function verify_channel(params_json: string, channel_secret_hex: string, funding_proofs_json: string, keyset_info_json: string): string;

export function verify_proof_dleq(proof_json: string, mint_pubkey_hex: string): boolean;
