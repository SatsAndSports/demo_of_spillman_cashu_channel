export {
  WasmSpilmanBridge,
  compute_channel_secret,
  compute_funding_token_amount,
  channel_parameters_get_channel_id,
  create_funding_outputs,
  construct_proofs,
  spilman_channel_sender_create_signed_balance_update,
  sign_with_tweaked_key,
  get_sender_blinded_secret_key_for_stage2_output,
  get_receiver_blinded_secret_key_for_stage2_output,
  compute_funding_token_nominal,
} from "../wasm/cdk_wasm.js";
import wasmInit from "../wasm/cdk_wasm.js";
import { readFileSync } from "fs";
import { join } from "path";
import { fileURLToPath } from "url";

export { createSpilmanManagementRouter } from "./router.js";
export { createSpilmanHost, getServerPubkey } from "./host.js";
export { createInMemoryStores } from "./stores.js";
export { createSqliteStores } from "./sqlite_stores.js";
export {
  getActivePricing,
  getChannelStatus,
  type PricingTable,
  type PricingEntry,
  type SpilmanStores,
  type UsageMap,
} from "./stores.js";
export { fetchAllKeysetsFromMint, fetchAndCacheKeysetsForMint } from "./keysets.js";
export { Spilman, mapErrorStatus, decodePaymentHeader } from "./express.js";
export { ConfigurableSpilman, type SpilmanConfig } from "./config.js";
export { demoFetchActiveKeysetInfo, demoMintFundingToken } from "./demo.js";
export { SpilmanClientBridge, type SpilmanClientHost } from "./client_bridge.js";

/**
 * Initializes the WASM module for Node.js environment.
 */
export async function init() {
  const __dirname = fileURLToPath(new URL(".", import.meta.url));
  const wasmPath = join(__dirname, "../wasm/cdk_wasm_bg.wasm");
  const wasmBytes = readFileSync(wasmPath);
  return await wasmInit({ module_or_path: wasmBytes });
}

