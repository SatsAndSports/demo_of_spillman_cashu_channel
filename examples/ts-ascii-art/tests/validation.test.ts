import { test, describe, expect } from './fixtures.js';
import {
  mintFundedChannel,
  createPaymentHeader,
  encodePaymentHeader,
  fetchAsciiArt,
} from './helpers.js';

// Import WASM function for manual signature creation
import {
  spilman_channel_sender_create_signed_balance_update,
} from '../src/wasm/cdk_wasm.js';

describe.concurrent('Payment validation errors', () => {
  test('returns 402 when signature does not match balance', async ({ server }) => {
    // Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

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
      params: channel.channelParams,
      funding_proofs: channel.proofs,
    });

    const { status, body } = await fetchAsciiArt(server, paymentHeader, 'Hi');

    expect(status).toBe(402);
    expect(body.reason).toContain('invalid signature');
    console.log(`Invalid signature rejected: ${body.reason}`);
  });

  test('returns 402 when balance exceeds capacity', async ({ server }) => {
    // Mint a funded channel (capacity = 100)
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel capacity: ${channel.capacity}`);

    // First, establish the channel with a valid payment
    const paymentHeader1 = createPaymentHeader(channel, 1, true);
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
    // Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

    // First payment: balance=5 for 5-char message "Hello"
    const paymentHeader1 = createPaymentHeader(channel, 5, true);
    const { status: status1 } = await fetchAsciiArt(server, paymentHeader1, 'Hello');
    expect(status1).toBe(200);
    console.log('First payment accepted (balance=5, amount_due=5)');

    // Second payment: try with balance=3 but amount_due would be 5+2=7
    // The server checks: balance < amount_due, so 3 < 7 fails
    const paymentHeader2 = createPaymentHeader(channel, 3, false);
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

    // Create a balance update with tampered proofs
    const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
      channel.channelParamsJson,
      JSON.stringify(channel.keysetInfo),
      channel.alice.secretHex,
      JSON.stringify(tamperedProofs),
      BigInt(1)
    );
    const balanceUpdate = JSON.parse(balanceUpdateJson);

    // Send payment with tampered proofs
    const paymentHeader = encodePaymentHeader({
      channel_id: balanceUpdate.channel_id,
      balance: balanceUpdate.amount,
      signature: balanceUpdate.signature,
      params: channel.channelParams,
      funding_proofs: tamperedProofs,
    });

    const { status, body } = await fetchAsciiArt(server, paymentHeader, 'Hi');

    expect(status).toBe(402);
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

    // Try to use the channel
    const paymentHeader = createPaymentHeader(channel, 1, true);
    const { status, body } = await fetchAsciiArt(server, paymentHeader, 'Hi');

    expect(status).toBe(402);
    expect(body.reason).toContain('locktime too soon');
    expect(body.locktime).toBe(tooSoonLocktime);
    expect(body.min_expiry_in_seconds).toBe(minExpiryInSeconds);
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
});
