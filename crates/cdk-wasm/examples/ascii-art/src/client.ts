/**
 * ASCII Art Client - Creates channel and makes paid requests
 * 
 * Demonstrates Spilman payment channels in TypeScript.
 * 
 * Usage:
 *   tsx src/index.ts client [messages...]
 *   
 * Examples:
 *   tsx src/index.ts client Hello World Cashu
 *   tsx src/index.ts client "Hello World"
 */

import { randomBytes } from "crypto";
import * as secp from "@noble/secp256k1";
import qrcode from "qrcode-terminal";
import {
  compute_shared_secret,
  channel_parameters_get_channel_id,
  create_funding_outputs,
  construct_proofs,
  spilman_channel_sender_create_signed_balance_update,
} from "./wasm/cdk_wasm.js";

// ============================================================================
// Configuration
// ============================================================================

const MINT_URL = process.env.MINT_URL || "http://localhost:3338";
const SERVER_URL = process.env.SERVER_URL || "http://localhost:5002";

// ============================================================================
// Helper: Encode payment header as base64
// ============================================================================

function encodePaymentHeader(payment: object): string {
  return Buffer.from(JSON.stringify(payment)).toString("base64");
}

// ============================================================================
// Helper: Generate keypair
// ============================================================================

function generateKeypair(): { secret: string; pubkey: string } {
  const secretBytes = randomBytes(32);
  const pubkeyBytes = secp.getPublicKey(secretBytes, true);
  return {
    secret: secretBytes.toString("hex"),
    pubkey: Buffer.from(pubkeyBytes).toString("hex"),
  };
}

// ============================================================================
// Fetch active keyset info from mint
// ============================================================================

async function fetchActiveKeysetInfo(mintUrl: string): Promise<{
  keysetId: string;
  unit: string;
  inputFeePpk: number;
  keys: Record<string, string>;
}> {
  console.log(`  Fetching keysets from ${mintUrl}...`);

  // Get keysets
  const keysetsResp = await fetch(`${mintUrl}/v1/keysets`);
  if (!keysetsResp.ok) throw new Error(`Failed to fetch keysets: ${keysetsResp.status}`);
  const keysetsData = await keysetsResp.json();

  // Find active sat keyset
  const active = keysetsData.keysets.find(
    (k: any) => k.unit === "sat" && k.active
  );
  if (!active) throw new Error("No active sat keyset found");

  const keysetId = active.id;
  console.log(`  Found keyset: ${keysetId} (${active.unit})`);

  // Get keys for this keyset
  const keysResp = await fetch(`${mintUrl}/v1/keys/${keysetId}`);
  if (!keysResp.ok) throw new Error(`Failed to fetch keys: ${keysResp.status}`);
  const keysData = await keysResp.json();

  return {
    keysetId,
    unit: "sat",
    inputFeePpk: active.input_fee_ppk || 0,
    keys: keysData.keysets[0].keys,
  };
}

// ============================================================================
// Mint funding token
// ============================================================================

async function mintFundingToken(
  mintUrl: string,
  amount: number,
  blindedMessages: any[]
): Promise<any[]> {
  console.log(`  Requesting mint quote for ${amount} sat...`);

  // 1. Request quote
  const quoteResp = await fetch(`${mintUrl}/v1/mint/quote/bolt11`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ amount, unit: "sat" }),
  });
  if (!quoteResp.ok) throw new Error(`Failed to request quote: ${quoteResp.status}`);
  const quote = await quoteResp.json();
  const quoteId = quote.quote;
  const invoice = (quote.request || "").trim();

  console.log(`  Quote ID: ${quoteId.substring(0, 24)}...`);

  // 2. Display invoice and QR code
  if (invoice) {
    console.log();
    console.log("  " + "=".repeat(56));
    console.log("  PAY THIS INVOICE TO FUND THE CHANNEL");
    console.log("  " + "=".repeat(56));
    console.log();
    console.log(`  ${invoice}`);
    console.log();
    console.log("  Scan this QR code with your Lightning wallet:");
    console.log();
    qrcode.generate(invoice.toUpperCase(), { small: true });
    console.log();
    console.log("  " + "=".repeat(56));
    console.log();
  }

  // 3. Wait for quote to be paid
  console.log("  Waiting for payment (test mint may auto-pay)...");
  for (let attempt = 0; attempt < 120; attempt++) {
    const checkResp = await fetch(`${mintUrl}/v1/mint/quote/bolt11/${quoteId}`);
    if (!checkResp.ok) throw new Error(`Failed to check quote: ${checkResp.status}`);
    const status = await checkResp.json();

    const state = status.state ?? status.paid;
    if (state === "PAID" || state === true) {
      console.log("  Payment received!");
      break;
    }

    if (attempt > 0 && attempt % 10 === 0) {
      console.log(`  Still waiting... (${Math.floor(attempt / 2)}s)`);
    }

    await new Promise((r) => setTimeout(r, 500));

    if (attempt === 119) {
      throw new Error("Quote was not paid in time (60s timeout)");
    }
  }

  // 4. Mint tokens
  console.log("  Minting tokens...");
  const mintResp = await fetch(`${mintUrl}/v1/mint/bolt11`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ quote: quoteId, outputs: blindedMessages }),
  });
  if (!mintResp.ok) {
    const text = await mintResp.text();
    throw new Error(`Failed to mint: ${mintResp.status} - ${text}`);
  }
  const mintData = await mintResp.json();

  console.log(`  Got ${mintData.signatures.length} blind signatures`);
  return mintData.signatures;
}

// ============================================================================
// Main Client Function
// ============================================================================

export async function runClient(messages: string[]): Promise<void> {
  let mintUrl = MINT_URL;

  console.log();
  console.log("=".repeat(60));
  console.log("ASCII Art Client - Spilman Payment Channel Demo (TypeScript)");
  console.log("=".repeat(60));
  console.log();
  console.log(`Mint URL:   ${mintUrl}`);
  console.log(`Server URL: ${SERVER_URL}`);
  console.log(`Messages:   ${JSON.stringify(messages)}`);
  console.log();

  // 1. Get server params
  console.log("[1/9] Fetching server params...");
  let serverParams: any;
  try {
    const resp = await fetch(`${SERVER_URL}/channel/params`);
    if (!resp.ok) throw new Error(`${resp.status}`);
    serverParams = await resp.json();
  } catch (e) {
    console.error(`\nERROR: Cannot connect to server at ${SERVER_URL}`);
    console.error("Make sure the server is running: npm run server");
    process.exit(1);
  }

  if (serverParams.mint) {
    mintUrl = serverParams.mint;
    console.log(`  Using mint from server: ${mintUrl}`);
  }

  const charliePubkey = serverParams.receiver_pubkey;
  console.log(`  Server pubkey: ${charliePubkey.substring(0, 24)}...`);
  console.log();

  // 2. Generate Alice keypair
  console.log("[2/9] Generating keypair...");
  const alice = generateKeypair();
  console.log(`  Alice pubkey: ${alice.pubkey.substring(0, 24)}...`);
  console.log();

  // 3. Fetch keyset info
  console.log("[3/9] Fetching keyset info from mint...");
  let keysetInfo: any;
  try {
    keysetInfo = await fetchActiveKeysetInfo(mintUrl);
  } catch (e) {
    console.error(`\nERROR: Cannot connect to mint at ${mintUrl}`);
    console.error(`${e}`);
    process.exit(1);
  }
  console.log();

  // 4. Compute shared secret
  console.log("[4/9] Computing shared secret...");
  const sharedSecret = compute_shared_secret(alice.secret, charliePubkey);
  console.log(`  Shared secret: ${sharedSecret.substring(0, 24)}...`);
  console.log();

  // 5. Build channel params
  console.log("[5/9] Building channel parameters...");
  const totalChars = messages.reduce((sum, m) => sum + m.length, 0);
  const capacity = Math.max(totalChars + 20, 50); // Some headroom

  const channelParams = {
    alice_pubkey: alice.pubkey,
    charlie_pubkey: charliePubkey,
    mint: mintUrl,
    unit: "sat",
    capacity,
    maximum_amount: 64,
    locktime: Math.floor(Date.now() / 1000) + 7200, // 2 hours
    setup_timestamp: Math.floor(Date.now() / 1000),
    sender_nonce: `ts-demo-${Date.now()}`,
    keyset_id: keysetInfo.keysetId,
    input_fee_ppk: keysetInfo.inputFeePpk,
  };

  const keysetInfoJson = JSON.stringify({
    keysetId: keysetInfo.keysetId,
    unit: keysetInfo.unit,
    keys: keysetInfo.keys,
    inputFeePpk: keysetInfo.inputFeePpk,
    amounts: Object.keys(keysetInfo.keys).map(Number).sort((a, b) => b - a),
  });

  const channelId = channel_parameters_get_channel_id(
    JSON.stringify(channelParams),
    sharedSecret,
    keysetInfoJson
  );
  console.log(`  Channel ID: ${channelId.substring(0, 24)}...`);
  console.log(`  Capacity:   ${capacity} sat`);
  console.log();

  // 6. Create funding outputs
  console.log("[6/9] Creating funding outputs...");
  const funding = JSON.parse(
    create_funding_outputs(
      JSON.stringify(channelParams),
      alice.secret,
      keysetInfoJson
    )
  );
  console.log(`  Funding amount: ${funding.funding_token_nominal} sat`);
  console.log(`  Blinded messages: ${funding.blinded_messages.length}`);
  console.log();

  // 7. Mint the funding token
  console.log("[7/9] Minting funding token...");
  const signatures = await mintFundingToken(
    mintUrl,
    funding.funding_token_nominal,
    funding.blinded_messages
  );
  console.log();

  // 8. Construct proofs
  console.log("[8/9] Constructing proofs...");
  const proofs = JSON.parse(
    construct_proofs(
      JSON.stringify(signatures),
      JSON.stringify(funding.secrets_with_blinding),
      keysetInfoJson
    )
  );
  console.log(`  Got ${proofs.length} proofs`);
  console.log();

  console.log("=".repeat(60));
  console.log("Channel funded! Making requests...");
  console.log("=".repeat(60));
  console.log();

  // 9. Make paid requests
  let balance = 0;
  let firstRequest = true;

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    const cost = msg.length;
    balance += cost;

    console.log(`[Request ${i + 1}/${messages.length}] '${msg}' (${cost} sat)`);

    // Create signed balance update
    const update = JSON.parse(
      spilman_channel_sender_create_signed_balance_update(
        JSON.stringify(channelParams),
        keysetInfoJson,
        alice.secret,
        JSON.stringify(proofs),
        BigInt(balance)
      )
    );

    // Build payment header
    const payment: any = {
      channel_id: channelId,
      balance,
      signature: update.signature,
    };

    // Include params and proofs on first request
    if (firstRequest) {
      payment.params = channelParams;
      payment.funding_proofs = proofs;
      firstRequest = false;
    }

    // Make request
    const response = await fetch(`${SERVER_URL}/ascii`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Cashu-Channel": encodePaymentHeader(payment),
      },
      body: JSON.stringify({ message: msg }),
    });

    if (response.ok) {
      const result = await response.json();
      const paymentInfo = result.payment || {};
      console.log(`  Payment accepted! Balance: ${balance}/${capacity} sat`);
      console.log("-".repeat(40));
      console.log(result.art);
    } else {
      console.log(`  FAILED! Status: ${response.status}`);
      try {
        const error = await response.json();
        console.log(`  Error: ${JSON.stringify(error)}`);
      } catch {
        console.log(`  Response: ${await response.text()}`);
      }
      break;
    }
  }

  // Close the channel
  console.log("=".repeat(60));
  console.log("[9/9] Closing channel...");
  console.log("=".repeat(60));
  console.log();

  // Get status to confirm amount_due
  console.log("  Fetching channel status...");
  const statusResp = await fetch(`${SERVER_URL}/channel/${channelId}/status`);
  if (!statusResp.ok) {
    console.error(`  Failed to get status: ${statusResp.status}`);
    process.exit(1);
  }
  const status = await statusResp.json();
  console.log(`  Status: chars_served=${status.chars_served} amount_due=${status.amount_due}`);

  // Create close signature for exact amount_due
  const finalBalance = status.amount_due;
  const closeUpdate = JSON.parse(
    spilman_channel_sender_create_signed_balance_update(
      JSON.stringify(channelParams),
      keysetInfoJson,
      alice.secret,
      JSON.stringify(proofs),
      BigInt(finalBalance)
    )
  );

  console.log(`  Closing with balance=${finalBalance}...`);
  const closeResp = await fetch(`${SERVER_URL}/channel/${channelId}/close`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      balance: finalBalance,
      signature: closeUpdate.signature,
    }),
  });

  if (closeResp.ok) {
    const closeResult = await closeResp.json();
    console.log();
    console.log("=".repeat(60));
    console.log("Channel closed successfully!");
    console.log("=".repeat(60));
    console.log(`  Server earned:  ${finalBalance} sat`);
    console.log(`  Client refund:  ${closeResult.sender_proofs?.length || 0} proofs`);
    console.log(`  Total value:    ${closeResult.total_value} sat`);
    console.log(`  Remaining:      ${capacity - finalBalance} sat (returned to client)`);
    console.log("=".repeat(60));
  } else {
    console.log(`  Close FAILED! Status: ${closeResp.status}`);
    try {
      const error = await closeResp.json();
      console.log(`  Error: ${JSON.stringify(error)}`);
    } catch {
      console.log(`  Response: ${await closeResp.text()}`);
    }
  }
}
