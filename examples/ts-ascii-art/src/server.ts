/**
 * ASCII Art Server - Pay 1 sat per character
 * 
 * Demonstrates Spilman payment channels in TypeScript using Express.
 * 
 * Endpoints:
 *   GET  /channel/params              - Get server pubkey and pricing info
 *   POST /channel/register            - Pre-register a channel (balance=0, no usage)
 *   POST /ascii                       - Generate ASCII art (requires X-Cashu-Channel header)
 *   GET  /channel/:id/status          - Get channel status and amount_due
 *   POST /channel/:id/close           - Close channel cooperatively (client-initiated)
 *   POST /channel/:id/unilateral-close - Close channel unilaterally (server-initiated)
 */

import express from "express";
import figlet from "figlet";
import * as secp from "@noble/secp256k1";
import { randomBytes } from "crypto";
import { WasmSpilmanBridge } from "./wasm/cdk_wasm.js";
import {
  channelFunding,
  channelBalance,
  channelUsage,
  channelClosing,
  channelClosed,
  keysetCache,
  getChannelStatus,
} from "./stores.js";

// ============================================================================
// Configuration
// ============================================================================

export const SECRET_KEY = process.env.SERVER_SECRET_KEY || randomBytes(32).toString("hex");
export const MINT_URL = process.env.MINT_URL || "http://localhost:3338";
const PORT = parseInt(process.env.PORT || "5002", 10);
// Pricing per character for each unit (superset — filtered dynamically by active mint keysets)
// Note: msat has higher per_char to stay above mint's minimum denomination
const ALL_PRICING: Record<string, { per_char: number; minCapacity: number }> = {
  sat: { per_char: 1, minCapacity: 10 },
  msat: { per_char: 1000, minCapacity: 10000 },  // 1 sat = 1000 msat
  usd: { per_char: 1, minCapacity: 10 },         // 1 cent per char
};

/** Returns pricing filtered to only units that have active keysets in the mint. */
function getActivePricing(): Record<string, { per_char: number; minCapacity: number }> {
  const activeUnits = keysetCache.getActiveUnits();
  const result: Record<string, { per_char: number; minCapacity: number }> = {};
  for (const unit of activeUnits) {
    if (unit in ALL_PRICING) {
      result[unit] = ALL_PRICING[unit];
    }
  }
  return result;
}

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

export const spilmanHooks = {
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
    const pricing = ALL_PRICING[params.unit];
    if (!pricing) return BigInt(0);

    return BigInt(totalChars * pricing.per_char);
  },

  // Note: WASM passes u64 values as BigInt; we convert to number at this boundary
  // since all channel values fit safely in JS number (< 2^53).
  recordPayment: (
    channelId: string,
    balance: number,
    signature: string,
    contextJson: string
  ): void => {
    const context = JSON.parse(contextJson);
    const messageLength = context.message_length || 0;

    channelUsage.recordCharsServed(channelId, messageLength);
    channelBalance.update(channelId, Number(balance), signature);

    console.log(`  [Host] Payment recorded: channel=${channelId.substring(0, 8)} balance=${balance}`);
  },

  getChannelState: (channelId: string): string => {
    if (channelClosed.isClosed(channelId)) {
      return "closed";
    } else if (channelClosing.isClosing(channelId)) {
      return "closing";
    } else {
      return "open";
    }
  },

  markChannelClosing: (
    channelId: string,
    locktime: number,
    balance: number,
    signature: string
  ): void => {
    channelClosing.markClosing(channelId, Number(locktime), Number(balance), signature);
  },

  getClosingData: (channelId: string): { locktime: number; balance: number; signature: string } | null => {
    return channelClosing.get(channelId);
  },

  getChannelPolicy: (): string => {
    return JSON.stringify({
      min_expiry_in_seconds: 3600,
      pricing: getActivePricing(),
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
    const locktimeNum = Number(locktime);
    const balanceNum = Number(balance);
    const receiverSumNum = Number(receiverSum);
    const senderSumNum = Number(senderSum);
    
    channelClosed.markClosed(
      channelId,
      locktimeNum,
      balanceNum,
      receiverSumNum + senderSumNum,
      receiverSumNum,
      senderSumNum,
      receiverProofsJson,
      senderProofsJson
    );
    console.log(`  [Host] Channel ${channelId.substring(0, 8)} closed. Earned: ${receiverSumNum} sat`);
  },

  refreshActiveKeysets: async (mint: string): Promise<void> => {
    console.log(`  [Host] Refreshing keysets for mint: ${mint}`);
    keysetCache.clearForMint(mint);
    try {
      await fetchAndCacheKeysetsForMint(mint);
      console.log(`  [Host] Keyset refresh complete for: ${mint}`);
    } catch (e) {
      console.error(`  [Host] Failed to refresh keysets: ${e}`);
    }
  },
};

// ============================================================================
// Initialize Bridge
// ============================================================================

const bridge = new WasmSpilmanBridge(spilmanHooks, SECRET_KEY);

// ============================================================================
// Keyset Initialization
// ============================================================================

// Fetch and cache keysets for a specific mint
export async function fetchAndCacheKeysetsForMint(mintUrl: string): Promise<void> {
  const keysetsResp = await fetch(`${mintUrl}/v1/keysets`);
  if (!keysetsResp.ok) throw new Error(`Failed to fetch keysets: ${keysetsResp.status}`);
  const keysetsData = await keysetsResp.json();

  for (const ks of keysetsData.keysets) {
    if (ks.unit in ALL_PRICING) {
      // Fetch full keys for this keyset
      const keysResp = await fetch(`${mintUrl}/v1/keys/${ks.id}`);
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

      keysetCache.set(mintUrl, ks.id, {
        infoJson: JSON.stringify(keysetInfo),
        active: ks.active,
        unit: ks.unit,
      });
    }
  }
}

async function initializeKeysets(): Promise<void> {
  console.log(`Fetching keysets from ${MINT_URL}...`);
  try {
    await fetchAndCacheKeysetsForMint(MINT_URL);
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

// GET /channel/params - Return server pubkey, pricing, and trusted keysets
app.get("/channel/params", (_req, res) => {
  res.json({
    receiver_pubkey: SERVER_PUBKEY,
    pricing: getActivePricing(),
    mints_units_keysets: keysetCache.getMintsUnitsKeysets(),
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
  let paymentInfo: { channel_id: string; balance: number; amount_due: number; capacity: number };
  try {
    // processPayment now returns PaymentSuccess directly and throws on error
    paymentInfo = bridge.processPayment(paymentJson, context) as any;
  } catch (e) {
    const errorMsg = (e as Error).message || String(e);
    console.log(`  [Payment] REJECTED: ${errorMsg}`);
    
    // Determine HTTP status from error type
    let status = 402;
    const lowerMsg = errorMsg.toLowerCase();
    if (lowerMsg.includes("invalid base64") ||
        lowerMsg.includes("invalid utf8") ||
        lowerMsg.includes("invalid json") ||
        lowerMsg.includes("missing field") ||
        lowerMsg.includes("missing channel_id") ||
        lowerMsg.includes("missing signature") ||
        (lowerMsg.includes("expected") && (lowerMsg.includes("string") || lowerMsg.includes("integer") || lowerMsg.includes("u64")))) {
      status = 400;
    } else if (lowerMsg.includes("internal") || lowerMsg.includes("misconfigured")) {
      status = 500;
    }
    
    res.setHeader("X-Cashu-Channel", JSON.stringify({ error: errorMsg }));
    res.status(status).json({ error: "Payment failed", reason: errorMsg });
    return;
  }

  // Payment accepted - generate ASCII art
  
  // Look up unit from stored channel params to calculate cost
  const funding = channelFunding.get(paymentInfo.channel_id);
  const channelParams = funding ? JSON.parse(funding.paramsJson) : null;
  const unitPricing = channelParams ? ALL_PRICING[channelParams.unit] : ALL_PRICING.sat;
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
    const status = getChannelStatus(channelId, ALL_PRICING);
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
        receiver_sum: closedData.receiverSum,
        sender_sum: closedData.senderSum,
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

  // Build payment body (include params/funding_proofs for unknown channels)
  const { params, funding_proofs } = req.body;
  const closeBody: any = { channel_id: channelId, balance, signature };
  if (params) closeBody.params = params;
  if (funding_proofs) closeBody.funding_proofs = funding_proofs;

  // Execute cooperative close via bridge (validates, submits swap, unblinds, marks closed)
  // Returns CloseSuccess on success, throws CloseError on failure
  let result: { channel_id: string; total_value: number; receiver_sum: number; sender_sum: number; sender_proofs: string; already_closed: boolean };
  try {
    result = await bridge.executeCooperativeClose(JSON.stringify(closeBody)) as any;
  } catch (e: any) {
    // CloseError is thrown as a JS object (not a string), so access its properties directly
    // If it's a string or has a message property, try to parse it
    let closeError: any;
    if (typeof e === 'object' && e !== null && 'type' in e) {
      // Already a CloseError object from WASM
      closeError = e;
    } else {
      // Fallback: try to parse as JSON string
      const errorMsg = (e as Error).message || String(e);
      try {
        closeError = JSON.parse(errorMsg);
      } catch {
        closeError = { type: "MintRejected", reason: errorMsg, status: 502 };
      }
    }
    const status = closeError.status || 402;
    const reason = closeError.reason || closeError.mint_error || String(closeError);
    console.log(`  [Close] Failed: ${reason} (status=${status})`);
    res.status(status).json({ success: false, error: reason, ...closeError });
    return;
  }

  console.log(`  [Close] SUCCESS! total_value=${result.total_value}`);
  // Parse sender_proofs from JSON string to array
  const senderProofs = typeof result.sender_proofs === 'string' 
    ? JSON.parse(result.sender_proofs) 
    : result.sender_proofs;
  res.json({ 
    success: true, 
    channel_id: result.channel_id,
    total_value: result.total_value,
    receiver_sum: result.receiver_sum,
    sender_sum: result.sender_sum,
    sender_proofs: senderProofs,
    already_closed: result.already_closed,
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

  // Check if channel exists
  if (!channelFunding.get(channelId)) {
    res.status(404).json({ error: "unknown channel" });
    return;
  }

  // Execute unilateral close via bridge (gets stored balance/sig, submits swap with retry, unblinds, marks closed)
  // Returns CloseSuccess on success, throws CloseError on failure
  let result: { channel_id: string; total_value: number; receiver_sum: number; sender_sum: number; sender_proofs: string; already_closed: boolean };
  try {
    result = await bridge.executeUnilateralClose(channelId) as any;
  } catch (e: any) {
    // CloseError is thrown as a JS object (not a string), so access its properties directly
    // If it's a string or has a message property, try to parse it
    let closeError: any;
    if (typeof e === 'object' && e !== null && 'type' in e) {
      // Already a CloseError object from WASM
      closeError = e;
    } else {
      // Fallback: try to parse as JSON string
      const errorMsg = (e as Error).message || String(e);
      try {
        closeError = JSON.parse(errorMsg);
      } catch {
        closeError = { type: "MintRejected", reason: errorMsg, status: 502 };
      }
    }
    const status = closeError.status || 500;
    const reason = closeError.reason || closeError.mint_error || String(closeError);
    console.log(`  [Unilateral Close] Failed: ${reason} (status=${status})`);
    res.status(status).json({ success: false, error: reason, ...closeError });
    return;
  }

  console.log(`  [Unilateral Close] SUCCESS! Earned ${result.receiver_sum} sat`);
  res.json({
    success: true,
    channel_id: channelId,
    earnedBeforeStage2Fees: result.receiver_sum,
    already_closed: false,
  });
});

// POST /channel/register - Pre-register a channel (balance=0, no usage recorded)
app.post("/channel/register", (req, res) => {
  const { channel_id, balance, signature, params, funding_proofs } = req.body;

  if (!channel_id || signature === undefined || !params || !funding_proofs) {
    res.status(400).json({
      error: "Bad request",
      reason: "missing required fields: channel_id, signature, params, funding_proofs",
    });
    return;
  }

  // balance must be 0 for registration
  if (balance !== 0) {
    res.status(400).json({
      error: "Bad request",
      reason: `funding requires balance=0, got ${balance}`,
    });
    return;
  }

  console.log(`\n[Register] Request for channel=${channel_id.substring(0, 8)}`);

  // Build request body in the same format as payment
  const registerBody = { channel_id, balance: 0, signature, params, funding_proofs };

  // Use fundChannel to validate and store the channel
  let result: { channel_id: string; capacity: number; already_known: boolean };
  try {
    // fundChannel now returns FundChannelResult directly and throws on error
    result = bridge.fundChannel(JSON.stringify(registerBody)) as any;
  } catch (e) {
    const errorMsg = (e as Error).message || String(e);
    console.log(`  [Register] REJECTED: ${errorMsg}`);
    
    // Determine HTTP status from error type
    let status = 402;
    const lowerMsg = errorMsg.toLowerCase();
    if (lowerMsg.includes("invalid base64") ||
        lowerMsg.includes("invalid utf8") ||
        lowerMsg.includes("invalid json") ||
        lowerMsg.includes("missing field") ||
        lowerMsg.includes("missing channel_id") ||
        lowerMsg.includes("missing signature") ||
        (lowerMsg.includes("expected") && (lowerMsg.includes("string") || lowerMsg.includes("integer") || lowerMsg.includes("u64")))) {
      status = 400;
    } else if (lowerMsg.includes("internal") || lowerMsg.includes("misconfigured")) {
      status = 500;
    }
    
    res.status(status).json({ success: false, error: "Registration failed", reason: errorMsg, status });
    return;
  }

  console.log(`  [Register] SUCCESS! channel=${result.channel_id.substring(0, 8)} capacity=${result.capacity} already_known=${result.already_known}`);
  res.json({
    success: true,
    channel_id: result.channel_id,
    capacity: result.capacity,
    already_known: result.already_known,
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
    const activePricing = getActivePricing();
    const pricingStr = Object.entries(activePricing).map(([u, p]) => `${u}=${p.per_char}/char`).join(', ');
    console.log(`Pricing:       ${pricingStr || '(no active units)'}`);
    console.log(`Listening on:  http://0.0.0.0:${PORT}`);
    console.log();
    console.log("Endpoints:");
    console.log(`  GET  http://localhost:${PORT}/channel/params`);
    console.log(`  POST http://localhost:${PORT}/channel/register`);
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
