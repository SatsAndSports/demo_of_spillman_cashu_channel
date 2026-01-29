import { test, describe, expect } from './fixtures.js';
import {
  type Channel,
  mintFundedChannel,
  registerChannel,
  createPaymentHeader,
  encodePaymentHeader,
  fetchAsciiArt,
  fetchChannelStatus,
} from './helpers.js';
import { spilman_channel_sender_create_signed_balance_update } from '../src/wasm/cdk_wasm.js';

describe.concurrent('Payment flow', () => {
  test('makes payment and verifies channel status', async ({ server }) => {
    // 1. Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    console.log(`Channel capacity: ${channel.capacity} sats`);

    // 2. Register the channel
    await registerChannel(server, channel);

    // 3. Create a message to convert to ASCII art
    const message = 'Hi';
    const expectedCost = message.length * server.getPricePerChar('sat');
    console.log(`Message: "${message}" (${message.length} chars, cost=${expectedCost} sats)`);

    // 4. Create payment header and fetch ASCII art
    const paymentHeader = createPaymentHeader(channel, expectedCost);
    const { status: httpStatus, body } = await fetchAsciiArt(server, paymentHeader, message);

    console.log(`Response status: ${httpStatus}`);
    expect(httpStatus).toBe(200);
    expect(body.art).toBeDefined();
    // message and cost fields are optional (not all servers return them)
    if (body.message !== undefined) expect(body.message).toBe(message);
    if (body.cost !== undefined) expect(body.cost).toBe(expectedCost);
    console.log(`ASCII art generated${body.cost !== undefined ? `, cost=${body.cost}` : ''}`);

    // 4. GET /channel/:id/status and verify amount_due
    const { httpStatus: statusCode, body: status } = await fetchChannelStatus(server, channel.channelId);
    expect(statusCode).toBe(200);
    console.log(`Channel status: amount_due=${status!.amount_due} balance=${status!.balance}${status!.chars_served !== undefined ? ` chars_served=${status!.chars_served}` : ''}`);

    expect(status!.channel_id).toBe(channel.channelId);
    // chars_served is optional (not all servers track character-level usage)
    if (status!.chars_served !== undefined) expect(status!.chars_served).toBe(message.length);
    expect(status!.amount_due).toBe(expectedCost);
    expect(status!.balance).toBe(expectedCost);
    expect(status!.capacity).toBe(channel.capacity);
    expect(status!.closed).toBe(false);
    console.log('Channel status verified!');
  });
});

describe.concurrent('Multi-unit payment', () => {
  test('makes payment with msat channel', async ({ server }) => {
    const capacity = server.getMinCapacity('msat');
    // Use larger maximum_amount to keep proof count small (10000 msat / 64 = 156 outputs overflows headers)
    const channel = await mintFundedChannel(server, 'msat', capacity, { maximumAmount: 8192 });
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    console.log(`Channel capacity: ${channel.capacity} msat`);

    await registerChannel(server, channel);

    const message = 'Hi';
    const expectedCost = message.length * server.getPricePerChar('msat');
    console.log(`Message: "${message}" (${message.length} chars, cost=${expectedCost} msat)`);

    const paymentHeader = createPaymentHeader(channel, expectedCost);
    const { status: httpStatus, body } = await fetchAsciiArt(server, paymentHeader, message);

    expect(httpStatus).toBe(200);
    expect(body.art).toBeDefined();
    if (body.cost !== undefined) expect(body.cost).toBe(expectedCost);
    console.log(`ASCII art generated, cost=${expectedCost} msat`);

    // Verify channel status
    const { httpStatus: statusCode, body: status } = await fetchChannelStatus(server, channel.channelId);
    expect(statusCode).toBe(200);
    expect(status!.amount_due).toBe(expectedCost);
    expect(status!.balance).toBe(expectedCost);
    expect(status!.capacity).toBe(capacity);
    expect(status!.closed).toBe(false);
    console.log(`Channel status verified: amount_due=${status!.amount_due} msat`);
  });
});

describe.concurrent('Channel policy', () => {
  test('rejects channel with capacity below minCapacity', async ({ server }) => {
    const minCapacity = server.getMinCapacity('sat');
    const tooSmallCapacity = minCapacity - 1;
    console.log(`Server minCapacity=${minCapacity}, using capacity=${tooSmallCapacity}`);

    // 1. Mint a funded channel with capacity below minCapacity
    const channel = await mintFundedChannel(server, 'sat', tooSmallCapacity);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

    // 2. Try to register the channel - should fail with capacity too small
    const response = await fetch(`${server.baseUrl}/channel/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        channel_id: channel.channelId,
        balance: 0,
        signature: 'any', // Won't be checked since capacity validation happens first
        params: channel.channelParams,
        funding_proofs: channel.proofs,
      }),
    });

    // 3. Expect 402 with "capacity too small" in the reason
    console.log(`Response status: ${response.status}`);
    expect(response.status).toBe(402);
    const body = await response.json();
    expect(body.reason).toContain('capacity too small');
    // capacity and min_capacity fields may or may not be present depending on server implementation
    console.log(`Rejected with reason: ${body.reason}`);
  });
});

describe.concurrent('Pre-payment and multi-currency', () => {
  test('response header shows balance higher than amount_due when pre-paying', async ({ server }) => {
    // Mint and register a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    await registerChannel(server, channel);

    // Create a balance update with pre-payment (10 sats, but message only costs 2)
    const message = 'Hi';  // 2 chars = 2 sats cost
    const balance = 10;    // Pre-pay 10 sats
    const expectedCost = message.length * server.getPricePerChar('sat');
    console.log(`Message: "${message}" (${message.length} chars, cost=${expectedCost}), pre-paying ${balance}`);

    const paymentHeader = createPaymentHeader(channel, balance);
    const { status, body, channelHeader } = await fetchAsciiArt(server, paymentHeader, message);

    expect(status).toBe(200);
    expect(body.art).toBeDefined();

    // ts-ascii-art server returns payment info in body.payment, not X-Cashu-Channel header
    // Check either the header (blossom-style) or body.payment (ts-ascii-art style)
    const paymentInfo = channelHeader || body.payment;
    expect(paymentInfo).toBeTruthy();
    expect(paymentInfo.balance).toBe(balance);  // 10 (what client sent)
    expect(paymentInfo.amount_due).toBe(expectedCost);  // 2 (what server charged)
    expect(paymentInfo.balance).toBeGreaterThan(paymentInfo.amount_due);

    console.log(`Pre-payment: balance=${paymentInfo.balance} amount_due=${paymentInfo.amount_due} (credit=${paymentInfo.balance - paymentInfo.amount_due})`);
  });

  test('accepts valid payment with usd channel', async ({ server }) => {
    // Mint a funded channel with USD
    const channel = await mintFundedChannel(server, 'usd', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    console.log(`Channel unit: ${channel.channelParams.unit}`);
    await registerChannel(server, channel);

    // Create a message and payment
    const message = 'Hi';  // 2 chars
    const expectedCost = message.length * server.getPricePerChar('usd');
    console.log(`Message: "${message}" (${message.length} chars, cost=${expectedCost} cents)`);

    const paymentHeader = createPaymentHeader(channel, expectedCost);
    const { status, body } = await fetchAsciiArt(server, paymentHeader, message);

    expect(status).toBe(200);
    expect(body.art).toBeDefined();
    if (body.cost !== undefined) expect(body.cost).toBe(expectedCost);
    console.log('USD channel payment accepted');
  });

  test('returns 402 without payment, then 200 with valid payment', async ({ server }) => {
    // Step 1: Request ASCII art WITHOUT payment - should get 402
    const noPaymentResponse = await fetch(`${server.baseUrl}/ascii`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'Hello' }),
    });
    expect(noPaymentResponse.status).toBe(402);
    const errorBody = await noPaymentResponse.json();
    expect(errorBody.reason).toContain('Missing X-Cashu-Channel');
    console.log(`Got 402 without payment: ${errorBody.reason}`);

    // Step 2: Mint and register a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    await registerChannel(server, channel);

    // Step 3: Retry WITH payment - should get 200
    const message = 'Hello';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader = createPaymentHeader(channel, cost);
    const { status, body } = await fetchAsciiArt(server, paymentHeader, message);

    expect(status).toBe(200);
    expect(body.art).toBeDefined();
    console.log('Got 200 with payment, ASCII art generated');
  });
});
