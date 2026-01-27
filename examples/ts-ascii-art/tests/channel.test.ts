import { test, describe, expect } from './fixtures.js';
import { fetchChannelStatus } from './helpers.js';

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
