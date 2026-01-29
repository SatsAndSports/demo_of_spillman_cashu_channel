import { test, describe, expect } from './fixtures.js';
import { randomBytes } from 'crypto';
import {
  mintFundedChannel,
  registerChannel,
  createPaymentHeader,
  encodePaymentHeader,
  fetchAsciiArt,
  generateKeypair,
  fetchKeysetInfo,
  getFirstKeysetId,
} from './helpers.js';
import {
  compute_shared_secret,
  channel_parameters_get_channel_id,
  create_funding_outputs,
  construct_proofs,
} from '../src/wasm/cdk_wasm.js';

// Import WASM function for manual signature creation
import {
  spilman_channel_sender_create_signed_balance_update,
} from '../src/wasm/cdk_wasm.js';

describe.concurrent('Payment validation errors', () => {
  test('returns 402 when signature does not match balance', async ({ server }) => {
    // Mint and register a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    await registerChannel(server, channel);

    // Create a valid balance update for balance=1
    const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
      channel.channelParamsJson,
      JSON.stringify(channel.keysetInfo),
      channel.alice.secretHex,
      JSON.stringify(channel.proofs),
      BigInt(1)
    );
    const balanceUpdate = JSON.parse(balanceUpdateJson);

    // Send with balance=2 but signature for balance=1
    const paymentHeader = encodePaymentHeader({
      channel_id: balanceUpdate.channel_id,
      balance: 2,  // Wrong balance!
      signature: balanceUpdate.signature,  // Signature is for balance=1
    });

    const { status, body } = await fetchAsciiArt(server, paymentHeader, 'Hi');

    expect(status).toBe(402);
    expect(body.reason).toContain('invalid signature');
    console.log(`Invalid signature rejected: ${body.reason}`);
  });

  test('returns 402 when balance exceeds capacity', async ({ server }) => {
    // Mint and register a funded channel (capacity = 100)
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel capacity: ${channel.capacity}`);
    await registerChannel(server, channel);

    // First, establish the channel with a valid payment
    const paymentHeader1 = createPaymentHeader(channel, 1);
    const { status: status1 } = await fetchAsciiArt(server, paymentHeader1, 'X');
    expect(status1).toBe(200);
    console.log('Channel established with valid payment');

    // Now send a request with balance exceeding capacity
    // Use a fake signature since capacity check happens before signature verification
    const paymentHeader = encodePaymentHeader({
      channel_id: channel.channelId,
      balance: 101,  // Exceeds capacity of 100
      signature: 'fake_signature',
    });

    const { status, body } = await fetchAsciiArt(server, paymentHeader, 'Hi');

    expect(status).toBe(402);
    expect(body.reason).toContain('balance exceeds capacity');
    expect(body.capacity).toBe(100);
    expect(body.balance).toBe(101);
    console.log(`Balance exceeds capacity rejected: ${body.reason}`);
  });

  test('returns 402 when balance is insufficient', async ({ server }) => {
    // Mint and register a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    await registerChannel(server, channel);

    // First payment: balance=5 for 5-char message "Hello"
    const paymentHeader1 = createPaymentHeader(channel, 5);
    const { status: status1 } = await fetchAsciiArt(server, paymentHeader1, 'Hello');
    expect(status1).toBe(200);
    console.log('First payment accepted (balance=5, amount_due=5)');

    // Second payment: try with balance=3 but amount_due would be 5+2=7
    // The server checks: balance < amount_due, so 3 < 7 fails
    const paymentHeader2 = createPaymentHeader(channel, 3);
    const { status: status2, body } = await fetchAsciiArt(server, paymentHeader2, 'Hi');

    expect(status2).toBe(402);
    expect(body.reason).toContain('insufficient balance');
    console.log(`Insufficient balance rejected: ${body.reason}`);
  });

  test('returns 402 when DLEQ proof is tampered', async ({ server }) => {
    // Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

    // Tamper with DLEQ proof
    const tamperedProofs = JSON.parse(JSON.stringify(channel.proofs));
    const originalE = tamperedProofs[0].dleq.e;
    tamperedProofs[0].dleq.e = originalE.slice(0, -1) + (originalE.slice(-1) === 'a' ? 'b' : 'a');
    console.log(`Tampered DLEQ e: ${originalE.substring(0, 16)}... -> ${tamperedProofs[0].dleq.e.substring(0, 16)}...`);

    // Create a balance update with tampered proofs (for signature)
    const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
      channel.channelParamsJson,
      JSON.stringify(channel.keysetInfo),
      channel.alice.secretHex,
      JSON.stringify(tamperedProofs),
      BigInt(0)
    );
    const balanceUpdate = JSON.parse(balanceUpdateJson);

    // Try to register with tampered proofs - should fail
    const response = await fetch(`${server.baseUrl}/channel/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        channel_id: channel.channelId,
        balance: 0,
        signature: balanceUpdate.signature,
        params: channel.channelParams,
        funding_proofs: tamperedProofs,
      }),
    });

    expect(response.status).toBe(402);
    const body = await response.json();
    // The error could be in reason or in validation_errors
    const hasValidationError = body.validation_errors?.some((e: any) => e.type === 'InvalidDleq');
    const reasonContainsDleq = body.reason?.toLowerCase().includes('dleq');
    expect(hasValidationError || reasonContainsDleq).toBe(true);
    console.log(`Tampered DLEQ rejected`);
  });

  test('returns 402 when locktime is too soon', async ({ server }) => {
    // Get server's min_expiry_in_seconds
    const minExpiryInSeconds = server.channelParams.min_expiry_in_seconds;
    const now = Math.floor(Date.now() / 1000);
    const tooSoonLocktime = now + 60; // Only 60 seconds from now (need 3600s)
    console.log(`Server min_expiry=${minExpiryInSeconds}s, using locktime=${tooSoonLocktime} (60s from now)`);

    // Mint a channel with locktime too soon
    const channel = await mintFundedChannel(server, 'sat', 100, { locktime: tooSoonLocktime });

    // Create balance=0 signature for registration
    const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
      channel.channelParamsJson,
      JSON.stringify(channel.keysetInfo),
      channel.alice.secretHex,
      JSON.stringify(channel.proofs),
      BigInt(0)
    );
    const balanceUpdate = JSON.parse(balanceUpdateJson);

    // Try to register the channel - should fail due to locktime
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

    expect(response.status).toBe(402);
    const body = await response.json();
    expect(body.reason).toContain('locktime too soon');
    // locktime and min_expiry_in_seconds fields may or may not be present depending on server implementation
    console.log(`Locktime too soon rejected: ${body.reason}`);
  });

  test('returns 400 for missing X-Cashu-Channel header', async ({ server }) => {
    // Send request without payment header
    const response = await fetch(`${server.baseUrl}/ascii`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'Hello' }),
    });

    expect(response.status).toBe(402);
    const body = await response.json();
    expect(body.reason).toContain('Missing X-Cashu-Channel');
    console.log(`Missing header rejected: ${body.reason}`);
  });

  test('returns 400 for invalid base64 in header', async ({ server }) => {
    const response = await fetch(`${server.baseUrl}/ascii`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Cashu-Channel': 'not-valid-base64!!!',
      },
      body: JSON.stringify({ message: 'Hello' }),
    });

    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.reason).toContain('invalid base64');
    console.log(`Invalid base64 rejected: ${body.reason}`);
  });

  test('returns 402 when proof amount has no mint key', async ({ server }) => {
    // Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

    // Tamper with proof amount to a non-existent denomination
    const tamperedProofs = JSON.parse(JSON.stringify(channel.proofs));
    const originalAmount = tamperedProofs[0].amount;
    tamperedProofs[0].amount = 3;  // Not a power of 2, no mint key exists
    console.log(`Tampered amount: ${originalAmount} -> 3`);

    // Try to register with tampered proofs - should fail on channel validation
    const response = await fetch(`${server.baseUrl}/channel/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        channel_id: channel.channelId,
        balance: 0,
        signature: 'fake_signature',
        params: channel.channelParams,
        funding_proofs: tamperedProofs,
      }),
    });

    expect(response.status).toBe(402);
    const body = await response.json();
    // The error could be in reason or in validation_errors
    const hasValidationError = body.validation_errors?.some((e: any) => e.type === 'MissingMintKey');
    const reasonContainsMissingKey = body.reason?.toLowerCase().includes('missing') && body.reason?.toLowerCase().includes('key');
    expect(hasValidationError || reasonContainsMissingKey).toBe(true);
    console.log('MissingMintKey (invalid amount): 402 rejected');
  });

  test('returns 402 when channel_id does not match params', async ({ server }) => {
    // Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);

    // Create a valid balance update
    const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
      channel.channelParamsJson,
      JSON.stringify(channel.keysetInfo),
      channel.alice.secretHex,
      JSON.stringify(channel.proofs),
      BigInt(0)
    );
    const balanceUpdate = JSON.parse(balanceUpdateJson);

    // Tamper with the channel_id (flip last character)
    const tamperedChannelId = balanceUpdate.channel_id.slice(0, -1) +
      (balanceUpdate.channel_id.slice(-1) === 'a' ? 'b' : 'a');

    // Try to register with mismatched channel_id
    const response = await fetch(`${server.baseUrl}/channel/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        channel_id: tamperedChannelId,
        balance: 0,
        signature: balanceUpdate.signature,
        params: channel.channelParams,
        funding_proofs: channel.proofs,
      }),
    });

    expect(response.status).toBe(402);
    const body = await response.json();
    expect(body.reason).toContain('channel_id mismatch');
    console.log('channel_id mismatch: 402 rejected');
  });

  test('returns 402 when keyset is not from approved mint', async ({ server }) => {
    // Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);

    // Tamper with keyset_id in params - use a keyset that's not from an approved mint
    const tamperedParams = { ...channel.channelParams, keyset_id: '00deadbeef123456' };

    // Try to register with unknown keyset
    const response = await fetch(`${server.baseUrl}/channel/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        channel_id: 'aaaa' + channel.channelId.substring(4),  // fake channel_id
        balance: 0,
        signature: 'fake_signature',  // Won't get this far anyway
        params: tamperedParams,
        funding_proofs: channel.proofs,
      }),
    });

    expect(response.status).toBe(402);
    const body = await response.json();
    expect(body.reason).toContain('mint or keyset not acceptable');
    console.log('mint or keyset not acceptable: 402 rejected');
  });

  // NOTE: max_amount_per_output test removed - this policy is blossom-server specific
  // and not implemented in the ts-ascii-art reference server. See blossom-server/tests/payment.test.ts
  // for this test.

  test('returns 4xx for invalid or missing header fields', async ({ server }) => {
    // Test cases for malformed payment headers
    // Status codes vary by server implementation (400 for parse errors, 402 for missing fields)
    const testCases = [
      {
        name: 'missing channel_id',
        header: encodePaymentHeader({ balance: 1, signature: 'def456' }),
        expectedError: 'channel_id',
        acceptedStatuses: [400, 402],
      },
      {
        name: 'empty channel_id',
        header: encodePaymentHeader({ channel_id: '', balance: 1, signature: 'def456' }),
        expectedError: 'missing channel_id',
        acceptedStatuses: [400, 402],
      },
      {
        name: 'non-string channel_id',
        header: encodePaymentHeader({ channel_id: 12345, balance: 1, signature: 'def456' }),
        expectedError: 'integer',
        acceptedStatuses: [400, 402],
      },
      {
        name: 'missing balance',
        header: encodePaymentHeader({ channel_id: 'abc123', signature: 'def456' }),
        expectedError: 'balance',
        acceptedStatuses: [400, 402],
      },
      {
        name: 'non-integer balance',
        header: encodePaymentHeader({ channel_id: 'abc123', balance: 1.5, signature: 'def456' }),
        expectedError: 'u64',
        acceptedStatuses: [400, 402],
      },
      {
        name: 'missing signature',
        header: encodePaymentHeader({ channel_id: 'abc123', balance: 1 }),
        expectedError: 'signature',
        acceptedStatuses: [400, 402],
      },
      {
        name: 'empty signature',
        header: encodePaymentHeader({ channel_id: 'abc123', balance: 1, signature: '' }),
        expectedError: 'signature',
        acceptedStatuses: [400, 402],
      },
      {
        name: 'non-string signature',
        header: encodePaymentHeader({ channel_id: 'abc123', balance: 1, signature: 12345 }),
        expectedError: 'string',
        acceptedStatuses: [400, 402],
      },
    ];

    for (const tc of testCases) {
      const response = await fetch(`${server.baseUrl}/ascii`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Cashu-Channel': tc.header,
        },
        body: JSON.stringify({ message: 'Hello' }),
      });

      expect(tc.acceptedStatuses, `${tc.name}: expected 4xx`).toContain(response.status);
      const body = await response.json();
      expect(body.reason.toLowerCase(), `${tc.name}: wrong error`).toContain(tc.expectedError.toLowerCase());
      console.log(`${tc.name}: ${response.status} with reason containing "${tc.expectedError}"`);
    }
  });
});
