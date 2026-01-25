/**
 * ASCII Art Server - Pay 1 sat per character
 * 
 * Demonstrates Spilman payment channels in TypeScript using Express.
 * 
 * Endpoints:
 *   GET  /channel/params              - Get server pubkey and pricing info
 *   POST /ascii                       - Generate ASCII art (requires X-Cashu-Channel header)
 *   GET  /channel/:id/status          - Get channel status and amount_due
 *   POST /channel/:id/close           - Close channel cooperatively (client-initiated)
 *   POST /channel/:id/unilateral-close - Close channel unilaterally (server-initiated)
 */

import express from "express";
import figlet from "figlet";
import * as secp from "@noble/secp256k1";
import { randomBytes } from "crypto";
import {
  WasmSpilmanBridge,
  unblind_and_verify_dleq,
} from "./wasm/cdk_wasm.js";
import {
  channelFunding,
  channelBalance,
  channelUsage,
  channelClosed,
  keysetCache,
  getChannelStatus,
} from "./stores.js";

// ============================================================================
// Configuration
// ============================================================================

const SECRET_KEY = process.env.SERVER_SECRET_KEY || randomBytes(32).toString("hex");
const MINT_URL = process.env.MINT_URL || "http://localhost:3338";
const PORT = parseInt(process.env.PORT || "5002", 10);
// Pricing per character for each unit
// Note: msat has higher per_char to stay above mint's minimum denomination
const PRICING: Record<string, { per_char: number; minCapacity: number }> = {
  sat: { per_char: 1, minCapacity: 10 },
  msat: { per_char: 1000, minCapacity: 10000 },  // 1 sat = 1000 msat
  usd: { per_char: 1, minCapacity: 10 },         // 1 cent per char
};

// ============================================================================
// Server Pubkey
// ============================================================================

function getServerPubkey(): string {
  const secretBytes = Buffer.from(SECRET_KEY, "hex");
  const pubkeyBytes = secp.getPublicKey(secretBytes, true);
  return Buffer.from(pubkeyBytes).toString("hex");
}

const SERVER_PUBKEY = getServerPubkey();

// ============================================================================
// SpilmanHost Implementation
// ============================================================================

const spilmanHooks = {
  receiverKeyIsAcceptable: (pubkeyHex: string): boolean => {
    const result = pubkeyHex.toLowerCase() === SERVER_PUBKEY.toLowerCase();
    console.log(`  [Host] receiverKeyIsAcceptable: ${pubkeyHex.substring(0, 16)}... = ${result}`);
    return result;
  },

  mintAndKeysetIsAcceptable: (mint: string, keysetId: string): boolean => {
    const normMint = mint.replace(/\/$/, "");
    const normConfig = MINT_URL.replace(/\/$/, "");
    const result = normMint === normConfig && keysetCache.has(mint, keysetId);
    console.log(`  [Host] mintAndKeysetIsAcceptable: mint=${mint} keyset=${keysetId} = ${result}`);
    return result;
  },

  getFundingAndParams: (channelId: string): [string, string, string, string] | null => {
    const funding = channelFunding.get(channelId);
    if (!funding) return null;
    return [
      funding.paramsJson,
      funding.fundingProofsJson,
      funding.sharedSecret,
      funding.keysetInfoJson,
    ];
  },

  saveFunding: (
    channelId: string,
    paramsJson: string,
    fundingProofsJson: string,
    sharedSecret: string,
    keysetInfoJson: string
  ): void => {
    channelFunding.insert(channelId, {
      paramsJson,
      fundingProofsJson,
      sharedSecret,
      keysetInfoJson,
    });
  },

  getAmountDue: (channelId: string, contextJson: string | null): bigint => {
    const usage = channelUsage.get(channelId);
    let totalChars = usage?.charsServed ?? 0;

    if (contextJson) {
      const context = JSON.parse(contextJson);
      totalChars += context.message_length || 0;
    }

    // Look up unit from stored channel params
    const funding = channelFunding.get(channelId);
    if (!funding) return BigInt(0);

    const params = JSON.parse(funding.paramsJson);
    const pricing = PRICING[params.unit];
    if (!pricing) return BigInt(0);

    return BigInt(totalChars * pricing.per_char);
  },

  recordPayment: (
    channelId: string,
    balance: bigint,
    signature: string,
    contextJson: string
  ): void => {
    const context = JSON.parse(contextJson);
    const messageLength = context.message_length || 0;

    channelUsage.recordCharsServed(channelId, messageLength);
    channelBalance.update(channelId, Number(balance), signature);

    console.log(`  [Host] Payment recorded: channel=${channelId.substring(0, 8)} balance=${balance}`);
  },

  isClosed: (channelId: string): boolean => {
    return channelClosed.isClosed(channelId);
  },

  getChannelPolicy: (): string => {
    return JSON.stringify({
      min_expiry_in_seconds: 3600,
      pricing: PRICING,
    });
  },

  nowSeconds: (): bigint => {
    return BigInt(Math.floor(Date.now() / 1000));
  },

  getBalanceAndSignatureForUnilateralExit: (channelId: string): [number, string] | null => {
    const balanceData = channelBalance.get(channelId);
    if (!balanceData) return null;
    return [balanceData.balance, balanceData.signature];
  },

  getActiveKeysetIds: (mint: string, unit: string): string[] => {
    return keysetCache.getActiveIds(mint, unit);
  },

  getKeysetInfo: (mint: string, keysetId: string): string | null => {
    const entry = keysetCache.get(mint, keysetId);
    return entry?.infoJson ?? null;
  },

  callMintSwap: async (mintUrl: string, swapRequestJson: string): Promise<string> => {
    console.log(`  [Host] Calling mint swap: ${mintUrl}`);
    const response = await fetch(`${mintUrl}/v1/swap`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: swapRequestJson,
    });
    if (!response.ok) {
      const text = await response.text();
      return JSON.stringify({ error: `Mint rejected swap: ${text}` });
    }
    return await response.text();
  },

  markChannelClosed: (
    channelId: string,
    locktime: number,
    balance: number,
    receiverProofsJson: string,
    senderProofsJson: string,
    receiverSum: number,
    senderSum: number
  ): void => {
    channelClosed.markClosed(
      channelId,
      locktime,
      balance,
      receiverSum + senderSum,
      receiverSum,
      receiverProofsJson,
      senderProofsJson
    );
    console.log(`  [Host] Channel ${channelId.substring(0, 8)} closed. Earned: ${receiverSum} sat`);
  },
};

// ============================================================================
// Initialize Bridge
// ============================================================================

const bridge = new WasmSpilmanBridge(spilmanHooks, SECRET_KEY);

// ============================================================================
// Shared Channel Close Logic
// ============================================================================

interface CloseResultFromBridge {
  success: boolean;
  error?: string;
  swap_request: any;
  expected_total: number;
  secrets_with_blinding: any[];
  output_keyset_info: any;
}

type CloseOutcome = {
  success: true;
  unblindResult: {
    receiver_proofs: any[];
    sender_proofs: any[];
    receiver_sum_after_stage1: number;
    sender_sum_after_stage1: number;
  };
  actualTotal: number;
} | {
  success: false;
  error: string;
  status: number;
  details?: any;
};

/**
 * Execute the common channel close flow: submit swap, unblind, verify, mark closed.
 * 
 * Used by both cooperative and unilateral close endpoints after they've obtained
 * a closeResult from the bridge.
 */
async function executeChannelClose(
  channelId: string,
  balance: number,
  closeResult: CloseResultFromBridge,
  logPrefix: string
): Promise<CloseOutcome> {
  // Get funding data and mint URL
  const funding = channelFunding.get(channelId)!;
  const channelParams = JSON.parse(funding.paramsJson);
  const mintUrl = channelParams.mint;

  const swapRequestJson = JSON.stringify(closeResult.swap_request);
  const expectedTotal = closeResult.expected_total;
  const secretsWithBlinding = closeResult.secrets_with_blinding;
  const outputKeysetInfoJson = JSON.stringify(closeResult.output_keyset_info);

  console.log(`  ${logPrefix} Submitting swap to mint: ${mintUrl}`);

  // Submit swap to mint
  let swapResponse: any;
  try {
    const swapResponseText = await bridge.callMintSwapViaHost(mintUrl, swapRequestJson);
    swapResponse = JSON.parse(swapResponseText);

    if (swapResponse.error) {
      console.log(`  ${logPrefix} Mint error: ${swapResponse.error}`);
      return {
        success: false,
        error: "mint rejected swap",
        status: 502,
        details: { mint_error: swapResponse.error },
      };
    }
    console.log(`  ${logPrefix} Got ${swapResponse.signatures?.length ?? 0} signatures`);
  } catch (e) {
    console.log(`  ${logPrefix} Failed to contact mint: ${e}`);
    return {
      success: false,
      error: "failed to contact mint",
      status: 502,
      details: { reason: String(e) },
    };
  }

  // Unblind and verify DLEQ
  let unblindResult: {
    receiver_proofs: any[];
    sender_proofs: any[];
    receiver_sum_after_stage1: number;
    sender_sum_after_stage1: number;
  };
  try {
    unblindResult = JSON.parse(
      unblind_and_verify_dleq(
        JSON.stringify(swapResponse.signatures || []),
        JSON.stringify(secretsWithBlinding),
        funding.paramsJson,
        funding.keysetInfoJson,
        funding.sharedSecret,
        BigInt(balance),
        outputKeysetInfoJson
      )
    );
    console.log(`  ${logPrefix} Unblinded: receiver=${unblindResult.receiver_proofs.length} sender=${unblindResult.sender_proofs.length}`);
  } catch (e) {
    console.log(`  ${logPrefix} Unblind failed: ${e}`);
    return {
      success: false,
      error: "unblind verification failed",
      status: 500,
      details: { reason: String(e) },
    };
  }

  // Verify total
  const actualTotal = unblindResult.receiver_sum_after_stage1 + unblindResult.sender_sum_after_stage1;
  if (actualTotal !== expectedTotal) {
    console.log(`  ${logPrefix} Total mismatch: expected=${expectedTotal} actual=${actualTotal}`);
    return {
      success: false,
      error: "swap response total mismatch",
      status: 500,
      details: { expected: expectedTotal, actual: actualTotal },
    };
  }

  // Mark channel as closed
  spilmanHooks.markChannelClosed(
    channelId,
    channelParams.locktime,
    balance,
    JSON.stringify(unblindResult.receiver_proofs),
    JSON.stringify(unblindResult.sender_proofs),
    unblindResult.receiver_sum_after_stage1,
    unblindResult.sender_sum_after_stage1
  );

  console.log(`  ${logPrefix} SUCCESS! Earned ${unblindResult.receiver_sum_after_stage1} sat`);

  return {
    success: true,
    unblindResult,
    actualTotal,
  };
}

// ============================================================================
// Keyset Initialization
// ============================================================================

async function initializeKeysets(): Promise<void> {
  console.log(`Fetching keysets from ${MINT_URL}...`);
  try {
    const keysetsResp = await fetch(`${MINT_URL}/v1/keysets`);
    if (!keysetsResp.ok) throw new Error(`Failed to fetch keysets: ${keysetsResp.status}`);
    const keysetsData = await keysetsResp.json();

    for (const ks of keysetsData.keysets) {
      if (ks.unit in PRICING) {
        // Fetch full keys for this keyset
        const keysResp = await fetch(`${MINT_URL}/v1/keys/${ks.id}`);
        if (!keysResp.ok) continue;
        const keysData = await keysResp.json();
        const keys = keysData.keysets[0].keys;

        const keysetInfo = {
          keysetId: ks.id,
          unit: ks.unit,
          keys: keys,
          inputFeePpk: ks.input_fee_ppk || 0,
          amounts: Object.keys(keys).map(Number).sort((a, b) => b - a),
        };

        keysetCache.set(MINT_URL, ks.id, {
          infoJson: JSON.stringify(keysetInfo),
          active: ks.active,
          unit: ks.unit,
        });
      }
    }
    console.log(`Cached keysets for ${MINT_URL}`);
  } catch (e) {
    console.error(`WARNING: Failed to fetch keysets: ${e}`);
    console.error("Payment validation may fail for new channels");
  }
}

// ============================================================================
// Helper: Decode base64 payment header
// ============================================================================

function decodePaymentHeader(header: string): string {
  // Validate base64 format
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(header)) {
    throw new Error("invalid base64 encoding");
  }
  return Buffer.from(header, "base64").toString("utf-8");
}

// ============================================================================
// Express App
// ============================================================================

const app = express();
app.use(express.json());

// GET /channel/params - Return server pubkey and pricing info
app.get("/channel/params", (_req, res) => {
  res.json({
    receiver_pubkey: SERVER_PUBKEY,
    pricing: PRICING,
    mint: MINT_URL,
    min_expiry_in_seconds: 3600,
  });
});

// POST /ascii - Generate ASCII art (requires payment)
app.post("/ascii", (req, res) => {
  const paymentHeaderB64 = req.headers["x-cashu-channel"] as string | undefined;

  if (!paymentHeaderB64) {
    res.status(402).json({
      error: "Payment required",
      reason: "Missing X-Cashu-Channel header",
    });
    return;
  }

  // Decode base64 payment header
  let paymentJson: string;
  try {
    paymentJson = decodePaymentHeader(paymentHeaderB64);
  } catch {
    res.status(400).json({
      error: "Invalid payment header",
      reason: "invalid base64 encoding",
    });
    return;
  }

  // Get message from request body
  const message = req.body?.message;
  if (!message) {
    res.status(400).json({ error: "Missing 'message' in request body" });
    return;
  }

  console.log(`\n[Request] ASCII art for '${message}' (${message.length} chars)`);

  // Create context with message length for pricing
  const context = JSON.stringify({ message_length: message.length });

  // Process payment through bridge
  const resultJson = bridge.processPayment(paymentJson, context);
  const result = JSON.parse(resultJson);

  if (!result.success) {
    console.log(`  [Payment] REJECTED: ${result.error || "unknown"}`);
    if (result.header) {
      res.setHeader("X-Cashu-Channel", JSON.stringify(result.header));
    }
    res.status(402).json(result.body || { error: result.error });
    return;
  }

  // Payment accepted - generate ASCII art
  const paymentInfo = result.header || {};
  
  // Look up unit from stored channel params to calculate cost
  const funding = channelFunding.get(paymentInfo.channel_id);
  const channelParams = funding ? JSON.parse(funding.paramsJson) : null;
  const unitPricing = channelParams ? PRICING[channelParams.unit] : PRICING.sat;
  const cost = message.length * (unitPricing?.per_char ?? 1);
  
  console.log(`  [Payment] ACCEPTED: cost=${cost} balance=${paymentInfo.balance}/${paymentInfo.capacity}`);

  const art = figlet.textSync(message);

  res.json({
    art,
    message,
    cost,
    payment: paymentInfo,
  });
});

// GET /channel/:id/status - Get channel status
app.get("/channel/:id/status", (req, res) => {
  const channelId = req.params.id;

  try {
    const status = getChannelStatus(channelId, PRICING);
    res.json(status);
  } catch (e) {
    const message = (e as Error).message;
    if (message === "unknown channel") {
      res.status(404).json({ error: "unknown channel" });
    } else {
      res.status(500).json({ error: message });
    }
  }
});

// POST /channel/:id/close - Close channel cooperatively
app.post("/channel/:id/close", async (req, res) => {
  const channelId = req.params.id;
  const { balance, signature } = req.body;

  if (balance === undefined || !signature) {
    res.status(400).json({ error: "missing balance or signature" });
    return;
  }

  console.log(`\n[Close] Request for channel=${channelId.substring(0, 8)} balance=${balance}`);

  // Check if already closed (idempotent)
  const closedData = channelClosed.get(channelId);
  if (closedData !== null) {
    if (balance === closedData.closedAmount) {
      console.log(`  [Close] Already closed with same amount`);
      res.json({
        success: true,
        channel_id: channelId,
        total_value: closedData.valueAfterStage1,
        sender_proofs: JSON.parse(closedData.senderProofsJson),
        already_closed: true,
      });
      return;
    } else {
      console.log(`  [Close] Already closed with different amount`);
      res.status(400).json({
        error: "channel already closed with a different amount",
        closed_amount: closedData.closedAmount,
        requested_amount: balance,
      });
      return;
    }
  }

  // Use bridge.createCloseData() to validate and create swap request
  // Include params and funding_proofs if provided (for unknown channels)
  const { params, funding_proofs } = req.body;
  const closeBody: any = { channel_id: channelId, balance, signature };
  if (params) closeBody.params = params;
  if (funding_proofs) closeBody.funding_proofs = funding_proofs;
  
  const closeResultJson = bridge.createCloseData(JSON.stringify(closeBody));
  const closeResult = JSON.parse(closeResultJson);

  if (!closeResult.success) {
    console.log(`  [Close] Validation failed: ${closeResult.error}`);
    res.status(402).json({ error: "Payment required", reason: closeResult.error });
    return;
  }

  // Execute the close flow
  const outcome = await executeChannelClose(channelId, balance, closeResult, "[Close]");

  if (!outcome.success) {
    res.status(outcome.status).json({ error: outcome.error, ...outcome.details });
    return;
  }

  res.json({
    success: true,
    channel_id: channelId,
    total_value: outcome.actualTotal,
    sender_proofs: outcome.unblindResult.sender_proofs,
    already_closed: false,
  });
});

// POST /channel/:id/unilateral-close - Server-initiated close (uses stored payment)
app.post("/channel/:id/unilateral-close", async (req, res) => {
  const channelId = req.params.id;

  console.log(`\n[Unilateral Close] Request for channel=${channelId.substring(0, 8)}`);

  // Check if already closed (idempotent)
  const closedData = channelClosed.get(channelId);
  if (closedData !== null) {
    console.log(`  [Unilateral Close] Already closed, returning cached result`);
    res.json({
      success: true,
      channel_id: channelId,
      earnedBeforeStage2Fees: closedData.receiverSum,
      already_closed: true,
    });
    return;
  }

  // Check channel exists
  const funding = channelFunding.get(channelId);
  if (!funding) {
    console.log(`  [Unilateral Close] Unknown channel`);
    res.status(404).json({ error: "unknown channel" });
    return;
  }

  // Check channel has payments
  const balanceData = channelBalance.get(channelId);
  if (!balanceData) {
    console.log(`  [Unilateral Close] No payments recorded`);
    res.status(400).json({ error: "no payments recorded for channel" });
    return;
  }

  // Use bridge.createUnilateralCloseData() - uses stored balance/signature
  const closeResultJson = bridge.createUnilateralCloseData(channelId);
  const closeResult = JSON.parse(closeResultJson);

  if (!closeResult.success) {
    console.log(`  [Unilateral Close] Bridge error: ${closeResult.error}`);
    res.status(500).json({ error: closeResult.error });
    return;
  }

  // Execute the close flow
  const balance = balanceData.balance;
  const outcome = await executeChannelClose(channelId, balance, closeResult, "[Unilateral Close]");

  if (!outcome.success) {
    res.status(outcome.status).json({ error: outcome.error, ...outcome.details });
    return;
  }

  res.json({
    success: true,
    channel_id: channelId,
    earnedBeforeStage2Fees: outcome.unblindResult.receiver_sum_after_stage1,
    already_closed: false,
  });
});

// ============================================================================
// Stats Display
// ============================================================================

function printStats(): void {
  console.log("\n" + "=".repeat(70));
  console.log("  Channel Statistics");
  console.log("=".repeat(70));

  const allFunding = channelFunding.all();
  if (allFunding.size === 0) {
    console.log("  No channels registered yet.");
    console.log("=".repeat(70) + "\n");
    return;
  }

  console.log(`  ${"ID".padEnd(10)} ${"Status".padEnd(8)} ${"Capacity".padStart(10)} ${"Balance".padStart(10)} ${"Usage".padStart(10)}`);
  console.log(`  ${"-".repeat(10)} ${"-".repeat(8)} ${"-".repeat(10)} ${"-".repeat(10)} ${"-".repeat(10)}`);

  let totalBalance = 0;
  let totalUsage = 0;

  for (const [cid, funding] of allFunding) {
    const params = JSON.parse(funding.paramsJson);
    const balance = channelBalance.get(cid)?.balance ?? 0;
    const usage = channelUsage.get(cid)?.charsServed ?? 0;
    const closed = channelClosed.isClosed(cid);
    const status = closed ? "CLOSED" : "OPEN";

    console.log(
      `  ${cid.substring(0, 8).padEnd(10)} ${status.padEnd(8)} ${String(params.capacity).padStart(7)} sat ${String(balance).padStart(7)} sat ${String(usage).padStart(7)} ch`
    );

    totalBalance += balance;
    totalUsage += usage;
  }

  console.log(`  ${"-".repeat(10)} ${"-".repeat(8)} ${"-".repeat(10)} ${"-".repeat(10)} ${"-".repeat(10)}`);
  console.log(`  ${"TOTAL".padEnd(10)} ${"".padEnd(8)} ${"".padStart(10)} ${String(totalBalance).padStart(7)} sat ${String(totalUsage).padStart(7)} ch`);
  console.log("=".repeat(70) + "\n");
}

// ============================================================================
// Signal Handlers
// ============================================================================

function setupSignalHandlers(): void {
  const shutdown = () => {
    console.log("\n[Shutdown] Received signal, exiting...");
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

// ============================================================================
// Main Entry Point
// ============================================================================

export async function startServer(): Promise<void> {
  console.log("=".repeat(60));
  console.log("ASCII Art Server - Spilman Payment Channel Demo (TypeScript)");
  console.log("=".repeat(60));
  console.log();

  await initializeKeysets();
  console.log();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server pubkey: ${SERVER_PUBKEY}`);
    console.log(`Mint URL:      ${MINT_URL}`);
    console.log(`Pricing:       sat=${PRICING.sat.per_char}/char, msat=${PRICING.msat.per_char}/char, usd=${PRICING.usd.per_char}/char`);
    console.log(`Listening on:  http://0.0.0.0:${PORT}`);
    console.log();
    console.log("Endpoints:");
    console.log(`  GET  http://localhost:${PORT}/channel/params`);
    console.log(`  POST http://localhost:${PORT}/ascii`);
    console.log(`  GET  http://localhost:${PORT}/channel/:id/status`);
    console.log(`  POST http://localhost:${PORT}/channel/:id/close`);
    console.log(`  POST http://localhost:${PORT}/channel/:id/unilateral-close`);
    console.log();
    console.log("=".repeat(60));
    console.log();

    setupSignalHandlers();
  });
}
