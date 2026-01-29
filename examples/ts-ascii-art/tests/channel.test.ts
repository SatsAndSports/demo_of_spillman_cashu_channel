import { test, describe, expect } from './fixtures.js';
import {
  fetchChannelStatus,
  mintFundedChannel,
  fetchAsciiArt,
  createPaymentHeader,
} from './helpers.js';
import { spilman_channel_sender_create_signed_balance_update } from '../src/wasm/cdk_wasm.js';

describe.concurrent('Channel params endpoint', () => {
  test('returns receiver pubkey', async ({ server }) => {
    const response = await fetch(`${server.baseUrl}/channel/params`);
    expect(response.status).toBe(200);

    const params = await response.json();
    expect(params.receiver_pubkey).toBeDefined();
    expect(params.receiver_pubkey).toMatch(/^0[23][0-9a-f]{64}$/); // compressed pubkey format
    console.log(`Receiver pubkey: ${params.receiver_pubkey.substring(0, 16)}...`);
  });

  test('returns pricing for all active units', async ({ server }) => {
    const response = await fetch(`${server.baseUrl}/channel/params`);
    expect(response.status).toBe(200);

    const params = await response.json();
    expect(params.pricing).toBeDefined();

    // Check sat pricing (all servers must support sat)
    expect(params.pricing.sat).toBeDefined();
    expect(params.pricing.sat.per_char).toBeGreaterThan(0);
    expect(params.pricing.sat.minCapacity).toBeGreaterThan(0);

    // Check msat pricing (CDK dev mint has msat keysets)
    expect(params.pricing.msat).toBeDefined();
    expect(params.pricing.msat.per_char).toBeGreaterThan(0);
    expect(params.pricing.msat.minCapacity).toBeGreaterThan(0);

    // Check usd pricing (CDK dev mint has usd keysets)
    expect(params.pricing.usd).toBeDefined();
    expect(params.pricing.usd.per_char).toBeGreaterThan(0);
    expect(params.pricing.usd.minCapacity).toBeGreaterThan(0);

    const units = Object.keys(params.pricing);
    console.log(`Pricing units: ${units.join(', ')} (sat=${params.pricing.sat.per_char}/char)`);
  });

  test('returns mints_units_keysets with trusted keysets', async ({ server }) => {
    const response = await fetch(`${server.baseUrl}/channel/params`);
    expect(response.status).toBe(200);

    const params = await response.json();
    expect(params.mints_units_keysets).toBeDefined();

    // Should have at least one mint
    const mints = Object.keys(params.mints_units_keysets);
    expect(mints.length).toBeGreaterThan(0);

    // The mint should match the test mint URL
    expect(params.mints_units_keysets[server.mintUrl]).toBeDefined();

    // Should have sat keysets
    const mintKeysets = params.mints_units_keysets[server.mintUrl];
    expect(mintKeysets.sat).toBeDefined();
    expect(Array.isArray(mintKeysets.sat)).toBe(true);
    expect(mintKeysets.sat.length).toBeGreaterThan(0);

    // Should also have msat and usd keysets (CDK dev mint)
    expect(mintKeysets.msat).toBeDefined();
    expect(mintKeysets.usd).toBeDefined();

    console.log(`Mint URL: ${server.mintUrl}`);
    for (const [unit, ids] of Object.entries(mintKeysets)) {
      console.log(`  ${unit}: ${(ids as string[]).join(', ')}`);
    }
  });

  test('returns min_expiry_in_seconds', async ({ server }) => {
    const response = await fetch(`${server.baseUrl}/channel/params`);
    expect(response.status).toBe(200);

    const params = await response.json();
    expect(params.min_expiry_in_seconds).toBeDefined();
    expect(params.min_expiry_in_seconds).toBeGreaterThan(0);
    console.log(`Min expiry: ${params.min_expiry_in_seconds} seconds`);
  });
});

describe.concurrent('Channel status endpoint', () => {
  test('returns 404 for unknown channel', async ({ server }) => {
    const fakeChannelId = 'deadbeef'.repeat(8); // 64 char hex string
    const { httpStatus, body } = await fetchChannelStatus(server, fakeChannelId);

    expect(httpStatus).toBe(404);
    console.log(`GET /channel/${fakeChannelId.substring(0, 8)}... returned 404 as expected`);
  });
});

describe.concurrent('Channel register endpoint', () => {
  test('registers a channel with balance=0 signature', async ({ server }) => {
    // Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

    // Create a signature for balance=0
    const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
      channel.channelParamsJson,
      JSON.stringify(channel.keysetInfo),
      channel.alice.secretHex,
      JSON.stringify(channel.proofs),
      BigInt(0)
    );
    const balanceUpdate = JSON.parse(balanceUpdateJson);

    // Register the channel
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

    expect(response.status).toBe(200);
    const result = await response.json();
    expect(result.success).toBe(true);
    expect(result.channel_id).toBe(channel.channelId);
    expect(result.capacity).toBe(100);
    expect(result.already_known).toBe(false);
    console.log(`Registered channel: capacity=${result.capacity}, already_known=${result.already_known}`);
  });

  test('is idempotent (second register returns already_known=true)', async ({ server }) => {
    // Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

    // Create a signature for balance=0
    const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
      channel.channelParamsJson,
      JSON.stringify(channel.keysetInfo),
      channel.alice.secretHex,
      JSON.stringify(channel.proofs),
      BigInt(0)
    );
    const balanceUpdate = JSON.parse(balanceUpdateJson);

    const registerBody = {
      channel_id: channel.channelId,
      balance: 0,
      signature: balanceUpdate.signature,
      params: channel.channelParams,
      funding_proofs: channel.proofs,
    };

    // First registration
    const response1 = await fetch(`${server.baseUrl}/channel/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(registerBody),
    });
    expect(response1.status).toBe(200);
    const result1 = await response1.json();
    expect(result1.already_known).toBe(false);
    console.log(`First register: already_known=${result1.already_known}`);

    // Second registration (should be idempotent)
    const response2 = await fetch(`${server.baseUrl}/channel/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(registerBody),
    });
    expect(response2.status).toBe(200);
    const result2 = await response2.json();
    expect(result2.success).toBe(true);
    expect(result2.already_known).toBe(true);
    console.log(`Second register: already_known=${result2.already_known}`);
  });

  test('rejects registration with non-zero balance', async ({ server }) => {
    // Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);

    // Create a signature for balance=5 (not 0)
    const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
      channel.channelParamsJson,
      JSON.stringify(channel.keysetInfo),
      channel.alice.secretHex,
      JSON.stringify(channel.proofs),
      BigInt(5)
    );
    const balanceUpdate = JSON.parse(balanceUpdateJson);

    const response = await fetch(`${server.baseUrl}/channel/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        channel_id: channel.channelId,
        balance: 5,
        signature: balanceUpdate.signature,
        params: channel.channelParams,
        funding_proofs: channel.proofs,
      }),
    });

    expect(response.status).toBe(400);
    const result = await response.json();
    expect(result.error).toBe('Bad request');
    expect(result.reason).toContain('balance=0');
    console.log(`Rejected non-zero balance: ${result.reason}`);
  });

  test('rejects registration with invalid signature', async ({ server }) => {
    // Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);

    // Use a fake signature
    const fakeSignature = 'a'.repeat(128); // 64 bytes hex = 128 chars

    const response = await fetch(`${server.baseUrl}/channel/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        channel_id: channel.channelId,
        balance: 0,
        signature: fakeSignature,
        params: channel.channelParams,
        funding_proofs: channel.proofs,
      }),
    });

    expect(response.status).toBe(402);
    const result = await response.json();
    expect(result.success).toBe(false);
    expect(result.reason).toContain('signature');
    console.log(`Rejected invalid signature: ${result.reason}`);
  });

  test('allows subsequent payments on pre-registered channel', async ({ server }) => {
    // Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

    // Register with balance=0
    const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
      channel.channelParamsJson,
      JSON.stringify(channel.keysetInfo),
      channel.alice.secretHex,
      JSON.stringify(channel.proofs),
      BigInt(0)
    );
    const balanceUpdate = JSON.parse(balanceUpdateJson);

    const registerResponse = await fetch(`${server.baseUrl}/channel/register`, {
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
    expect(registerResponse.status).toBe(200);
    console.log(`Channel registered`);

    // Now make a payment (without params/funding_proofs since already registered)
    const paymentHeader = createPaymentHeader(channel, 5, false /* no params */);
    const artResponse = await fetchAsciiArt(server, paymentHeader, 'Hello');

    expect(artResponse.status).toBe(200);
    expect(artResponse.body.cost).toBe(5);
    console.log(`Payment succeeded on pre-registered channel: cost=${artResponse.body.cost}`);
  });

  test('rejects registration with missing fields', async ({ server }) => {
    const response = await fetch(`${server.baseUrl}/channel/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        channel_id: 'test',
        balance: 0,
        // missing signature, params, funding_proofs
      }),
    });

    expect(response.status).toBe(400);
    const result = await response.json();
    expect(result.error).toBe('Bad request');
    expect(result.reason).toContain('missing');
    console.log(`Rejected missing fields: ${result.reason}`);
  });
});
