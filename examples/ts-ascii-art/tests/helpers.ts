/**
 * Test helpers for Spilman payment channel tests.
 *
 * This module provides utilities for:
 * - Generating keypairs
 * - Creating and signing payment headers
 * - Minting funded channels
 * - Fetching ASCII art and channel status
 */

import { randomBytes } from 'crypto';
import * as secp from '@noble/secp256k1';
import type { Server } from './fixtures.js';

// Import WASM functions from the server's wasm directory
import {
  compute_shared_secret,
  channel_parameters_get_channel_id,
  create_funding_outputs,
  construct_proofs,
  spilman_channel_sender_create_signed_balance_update,
} from '../src/wasm/cdk_wasm.js';

// ============================================================================
// Types
// ============================================================================

/** Keypair with hex-encoded secret and public key */
export interface Keypair {
  secretHex: string;
  pubkeyHex: string;
}

/** Channel data returned by mintFundedChannel */
export interface Channel {
  alice: Keypair;
  channelParams: object;
  channelParamsJson: string;
  channelId: string;
  sharedSecret: string;
  proofs: any[];
  keysetInfo: any;
  capacity: number;
}

/** Response from fetchAsciiArt */
export interface AsciiArtResponse {
  status: number;
  body: any;
  channelHeader: any | null;
}

/** Response body from channel status endpoint */
export interface ChannelStatusBody {
  channel_id: string;
  chars_served: number;
  amount_due: number;
  balance: number;
  capacity: number;
  closed: boolean;
  closed_amount?: number;
}

/** Response from fetchChannelStatus */
export interface ChannelStatusResponse {
  httpStatus: number;
  body: ChannelStatusBody | null;
}

// ============================================================================
// Keypair Generation
// ============================================================================

/** Generate a random secp256k1 keypair */
export function generateKeypair(): Keypair {
  const secretBytes = randomBytes(32);
  const secretHex = secretBytes.toString('hex');
  const pubkeyBytes = secp.getPublicKey(secretBytes, true); // compressed
  const pubkeyHex = Buffer.from(pubkeyBytes).toString('hex');
  return { secretHex, pubkeyHex };
}

// ============================================================================
// Payment Header Helpers
// ============================================================================

/** Encode payment object to base64 for X-Cashu-Channel header */
export function encodePaymentHeader(payment: object): string {
  return Buffer.from(JSON.stringify(payment)).toString('base64');
}

/** Create a signed payment header for a channel (channel must be pre-registered) */
export function createPaymentHeader(
  channel: Channel,
  balance: number
): string {
  const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
    channel.channelParamsJson,
    JSON.stringify(channel.keysetInfo),
    channel.alice.secretHex,
    JSON.stringify(channel.proofs),
    BigInt(balance)
  );
  const balanceUpdate = JSON.parse(balanceUpdateJson);

  const payment = {
    channel_id: balanceUpdate.channel_id,
    balance: balanceUpdate.amount,
    signature: balanceUpdate.signature,
  };

  return encodePaymentHeader(payment);
}

// ============================================================================
// Server Request Helpers
// ============================================================================

/** Fetch ASCII art from the server with a payment header */
export async function fetchAsciiArt(
  server: Server,
  paymentHeader: string,
  message: string
): Promise<AsciiArtResponse> {
  const response = await fetch(`${server.baseUrl}/ascii`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Cashu-Channel': paymentHeader,
    },
    body: JSON.stringify({ message }),
  });

  const channelHeaderRaw = response.headers.get('X-Cashu-Channel');
  const channelHeader = channelHeaderRaw ? JSON.parse(channelHeaderRaw) : null;

  return {
    status: response.status,
    body: await response.json(),
    channelHeader,
  };
}

/** Fetch channel status from the server */
export async function fetchChannelStatus(
  server: Server,
  channelId: string
): Promise<ChannelStatusResponse> {
  const response = await fetch(`${server.baseUrl}/channel/${channelId}/status`);

  return {
    httpStatus: response.status,
    body: response.ok ? await response.json() : null,
  };
}

/** Response from closeChannel */
export interface CloseChannelResponse {
  httpStatus: number;
  body: any;
}

/** Register a channel with the server (balance=0). Must be called before making payments. */
export async function registerChannel(server: Server, channel: Channel): Promise<void> {
  const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
    channel.channelParamsJson,
    JSON.stringify(channel.keysetInfo),
    channel.alice.secretHex,
    JSON.stringify(channel.proofs),
    BigInt(0)
  );
  const balanceUpdate = JSON.parse(balanceUpdateJson);

  const response = await fetch(`${server.baseUrl}/channel/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      channel_id: channel.channelId,
      balance: 0,
      signature: balanceUpdate.signature,
      params: channel.channelParams,
      funding_proofs: channel.proofs,
    }),
  });

  if (!response.ok) {
    const body = await response.json();
    throw new Error(`Registration failed (${response.status}): ${body.reason || body.error || 'unknown error'}`);
  }
}

/** Close a channel cooperatively. Channel must be pre-registered. */
export async function closeChannel(
  server: Server,
  channel: Channel,
  balance: number
): Promise<CloseChannelResponse> {
  // Create signed balance update for the close
  const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
    channel.channelParamsJson,
    JSON.stringify(channel.keysetInfo),
    channel.alice.secretHex,
    JSON.stringify(channel.proofs),
    BigInt(balance)
  );
  const balanceUpdate = JSON.parse(balanceUpdateJson);

  const closeBody = {
    balance: balance,
    signature: balanceUpdate.signature,
  };

  const response = await fetch(`${server.baseUrl}/channel/${channel.channelId}/close`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(closeBody),
  });

  return {
    httpStatus: response.status,
    body: await response.json(),
  };
}

// ============================================================================
// Mint Interaction Helpers
// ============================================================================

/** Fetch keyset info from mint */
export async function fetchKeysetInfo(mintUrl: string, keysetId: string): Promise<any> {
  const keysRes = await fetch(`${mintUrl}/v1/keys/${keysetId}`);
  const keysData = await keysRes.json();

  const keysetsRes = await fetch(`${mintUrl}/v1/keysets`);
  const keysetsData = await keysetsRes.json();
  const keyset = keysetsData.keysets.find((k: any) => k.id === keysetId);
  if (!keyset) {
    throw new Error(`Keyset ${keysetId} not found at ${mintUrl}`);
  }

  const keys: Record<string, string> = {};
  if (keysData.keysets && keysData.keysets[0]?.keys) {
    for (const [amount, pubkey] of Object.entries(keysData.keysets[0].keys)) {
      keys[amount] = pubkey as string;
    }
  }

  return {
    keysetId,
    unit: keyset.unit,
    keys,
    inputFeePpk: keyset.input_fee_ppk ?? 0,
    amounts: Object.keys(keys).map(Number).sort((a, b) => b - a),
  };
}

/** Get the first active keyset for a given unit from the mint */
export async function getFirstKeysetId(mintUrl: string, unit: string): Promise<string> {
  const keysetsRes = await fetch(`${mintUrl}/v1/keysets`);
  const keysetsData = await keysetsRes.json();
  const keyset = keysetsData.keysets.find((k: any) => k.unit === unit && k.active);
  if (!keyset) {
    throw new Error(`No active ${unit} keyset found at ${mintUrl}`);
  }
  return keyset.id;
}

// ============================================================================
// Channel Funding
// ============================================================================

/** Options for customizing channel parameters */
export interface MintFundedChannelOptions {
  /** Custom locktime (Unix timestamp). Defaults to 1 week from now. */
  locktime?: number;
  /** Maximum amount per output. Defaults to 64. */
  maximumAmount?: number;
}

/** Mint a funded channel with the specified unit and capacity */
export async function mintFundedChannel(
  server: Server,
  unit: string,
  capacity: number,
  options?: MintFundedChannelOptions
): Promise<Channel> {
  const charliePubkey = server.channelParams.receiver_pubkey;
  const mintUrl = server.mintUrl;
  const keysetId = await getFirstKeysetId(mintUrl, unit);

  // Generate Alice's keypair
  const alice = generateKeypair();

  // Fetch keyset info from mint
  const keysetInfo = await fetchKeysetInfo(mintUrl, keysetId);

  // Build channel parameters
  const setupTimestamp = Math.floor(Date.now() / 1000);
  const locktime = options?.locktime ?? (setupTimestamp + 7 * 24 * 60 * 60); // Default: 1 week from now
  const maximumAmount = options?.maximumAmount ?? 64;
  const senderNonce = randomBytes(32).toString('hex');

  const channelParams = {
    mint: mintUrl,
    unit: unit,
    capacity: capacity,
    keyset_id: keysetId,
    input_fee_ppk: keysetInfo.inputFeePpk,
    maximum_amount: maximumAmount,
    setup_timestamp: setupTimestamp,
    alice_pubkey: alice.pubkeyHex,
    charlie_pubkey: charliePubkey,
    locktime: locktime,
    sender_nonce: senderNonce,
  };
  const channelParamsJson = JSON.stringify(channelParams);

  // Generate funding outputs
  const fundingOutputsJson = create_funding_outputs(
    channelParamsJson,
    alice.secretHex,
    JSON.stringify(keysetInfo)
  );
  const fundingOutputs = JSON.parse(fundingOutputsJson);

  // Create mint quote
  const quoteRes = await fetch(`${mintUrl}/v1/mint/quote/bolt11`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      amount: fundingOutputs.funding_token_nominal,
      unit: unit,
    }),
  });
  const quote = await quoteRes.json();

  // Wait for payment (FakeWallet auto-pays)
  for (let i = 0; i < 30; i++) {
    const statusRes = await fetch(`${mintUrl}/v1/mint/quote/bolt11/${quote.quote}`);
    const status = await statusRes.json();
    if (status.state === 'PAID') break;
    await new Promise(r => setTimeout(r, 100));
  }

  // Mint with our blinded messages
  const mintReq = {
    quote: quote.quote,
    outputs: fundingOutputs.blinded_messages.map((bm: any) => ({
      amount: bm.amount,
      id: bm.id,
      B_: bm.B_,
    })),
  };

  const mintRes = await fetch(`${mintUrl}/v1/mint/bolt11`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(mintReq),
  });
  const mintData = await mintRes.json();

  // Construct proofs (unblind signatures)
  const proofsJson = construct_proofs(
    JSON.stringify(mintData.signatures),
    JSON.stringify(fundingOutputs.secrets_with_blinding),
    JSON.stringify(keysetInfo)
  );
  const proofs = JSON.parse(proofsJson);

  // Compute shared secret and channel ID
  const sharedSecret = compute_shared_secret(alice.secretHex, charliePubkey);
  const keysetInfoJson = JSON.stringify(keysetInfo);
  const channelId = channel_parameters_get_channel_id(channelParamsJson, sharedSecret, keysetInfoJson);

  return {
    alice,
    channelParams,
    channelParamsJson,
    channelId,
    sharedSecret,
    proofs,
    keysetInfo,
    capacity,
  };
}
