import { test, describe, expect } from './fixtures.js';
import { randomBytes } from 'crypto';
import * as secp from '@noble/secp256k1';

// Import WASM functions from the server's wasm directory
import {
  compute_shared_secret,
  channel_parameters_get_channel_id,
  create_funding_outputs,
  construct_proofs,
  spilman_channel_sender_create_signed_balance_update,
} from '../src/wasm/cdk_wasm.js';

// Generate a random keypair for Alice
function generateKeypair(): { secretHex: string; pubkeyHex: string } {
  const secretBytes = randomBytes(32);
  const secretHex = secretBytes.toString('hex');
  const pubkeyBytes = secp.getPublicKey(secretBytes, true); // compressed
  const pubkeyHex = Buffer.from(pubkeyBytes).toString('hex');
  return { secretHex, pubkeyHex };
}

// Encode payment object to base64 for X-Cashu-Channel header
function encodePaymentHeader(payment: object): string {
  return Buffer.from(JSON.stringify(payment)).toString('base64');
}

// Fetch keyset info from mint
async function fetchKeysetInfo(mintUrl: string, keysetId: string): Promise<any> {
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

// Get the first active sat keyset from the mint
async function getFirstSatKeysetId(mintUrl: string): Promise<string> {
  const keysetsRes = await fetch(`${mintUrl}/v1/keysets`);
  const keysetsData = await keysetsRes.json();
  const satKeyset = keysetsData.keysets.find((k: any) => k.unit === 'sat' && k.active);
  if (!satKeyset) {
    throw new Error(`No active sat keyset found at ${mintUrl}`);
  }
  return satKeyset.id;
}

// Server type for fixture
interface Server {
  baseUrl: string;
  mintUrl: string;
  channelParams: {
    receiver_pubkey: string;
    pricing: { sat: { per_char: number; minCapacity: number } };
    mint: string;
    min_expiry_in_seconds: number;
  };
  pricePerChar: number;
  getAmountDue(charsServed: number): number;
  getMinCapacity(): number;
}

// Helper to mint a funded channel
async function mintFundedChannel(server: Server, capacity: number = 100) {
  const charliePubkey = server.channelParams.receiver_pubkey;
  const mintUrl = server.mintUrl;
  const keysetId = await getFirstSatKeysetId(mintUrl);

  // Generate Alice's keypair
  const alice = generateKeypair();

  // Fetch keyset info from mint
  const keysetInfo = await fetchKeysetInfo(mintUrl, keysetId);

  // Build channel parameters
  const setupTimestamp = Math.floor(Date.now() / 1000);
  const locktime = setupTimestamp + 7 * 24 * 60 * 60; // 1 week from now
  const senderNonce = randomBytes(32).toString('hex');

  const channelParams = {
    mint: mintUrl,
    unit: 'sat',
    capacity: capacity,
    keyset_id: keysetId,
    input_fee_ppk: keysetInfo.inputFeePpk,
    maximum_amount: 64,
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
      unit: 'sat',
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

describe('Payment flow', () => {
  test('makes payment and verifies channel status', async ({ server }) => {
    // 1. Mint a funded channel
    const channel = await mintFundedChannel(server, 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    console.log(`Channel capacity: ${channel.capacity} sats`);

    // 2. Create a message to convert to ASCII art
    const message = 'Hi';
    const expectedCost = message.length * server.pricePerChar;
    console.log(`Message: "${message}" (${message.length} chars, cost=${expectedCost} sats)`);

    // 3. Create a balance update for the expected cost
    const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
      channel.channelParamsJson,
      JSON.stringify(channel.keysetInfo),
      channel.alice.secretHex,
      JSON.stringify(channel.proofs),
      BigInt(expectedCost)
    );
    const balanceUpdate = JSON.parse(balanceUpdateJson);
    console.log(`Signed balance update: balance=${balanceUpdate.amount}`);

    // 4. POST /ascii with payment header (first request includes params and funding_proofs)
    const paymentHeader = encodePaymentHeader({
      channel_id: balanceUpdate.channel_id,
      balance: balanceUpdate.amount,
      signature: balanceUpdate.signature,
      params: channel.channelParams,
      funding_proofs: channel.proofs,
    });

    const response = await fetch(`${server.baseUrl}/ascii`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Cashu-Channel': paymentHeader,
      },
      body: JSON.stringify({ message }),
    });

    console.log(`Response status: ${response.status}`);
    expect(response.status).toBe(200);

    const result = await response.json();
    expect(result.art).toBeDefined();
    expect(result.message).toBe(message);
    expect(result.cost).toBe(expectedCost);
    console.log(`ASCII art generated, cost=${result.cost}`);

    // 5. GET /channel/:id/status and verify amount_due
    const statusResponse = await fetch(`${server.baseUrl}/channel/${channel.channelId}/status`);
    expect(statusResponse.status).toBe(200);

    const status = await statusResponse.json();
    console.log(`Channel status: chars_served=${status.chars_served} amount_due=${status.amount_due} balance=${status.balance}`);

    expect(status.channel_id).toBe(channel.channelId);
    expect(status.chars_served).toBe(message.length);
    expect(status.amount_due).toBe(expectedCost);
    expect(status.balance).toBe(expectedCost);
    expect(status.capacity).toBe(channel.capacity);
    expect(status.closed).toBe(false);
    console.log('Channel status verified!');
  });
});

describe('Channel policy', () => {
  test('rejects channel with capacity below minCapacity', async ({ server }) => {
    const minCapacity = server.getMinCapacity();
    const tooSmallCapacity = minCapacity - 1;
    console.log(`Server minCapacity=${minCapacity}, using capacity=${tooSmallCapacity}`);

    // 1. Mint a funded channel with capacity below minCapacity
    const channel = await mintFundedChannel(server, tooSmallCapacity);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

    // 2. Create a balance update
    const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
      channel.channelParamsJson,
      JSON.stringify(channel.keysetInfo),
      channel.alice.secretHex,
      JSON.stringify(channel.proofs),
      BigInt(1)
    );
    const balanceUpdate = JSON.parse(balanceUpdateJson);

    // 3. POST /ascii with payment header
    const paymentHeader = encodePaymentHeader({
      channel_id: balanceUpdate.channel_id,
      balance: balanceUpdate.amount,
      signature: balanceUpdate.signature,
      params: channel.channelParams,
      funding_proofs: channel.proofs,
    });

    const response = await fetch(`${server.baseUrl}/ascii`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Cashu-Channel': paymentHeader,
      },
      body: JSON.stringify({ message: 'X' }),
    });

    // 4. Expect 402 with "capacity too small" in the reason
    console.log(`Response status: ${response.status}`);
    expect(response.status).toBe(402);

    const result = await response.json();
    expect(result.reason).toContain('capacity too small');
    expect(result.capacity).toBe(tooSmallCapacity);
    expect(result.min_capacity).toBe(minCapacity);
    console.log(`Rejected with reason: ${result.reason}`);
  });
});
