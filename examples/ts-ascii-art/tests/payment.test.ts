import { test, describe, expect } from './fixtures.js';
import {
  type Channel,
  mintFundedChannel,
  createPaymentHeader,
  fetchAsciiArt,
  fetchChannelStatus,
} from './helpers.js';

describe.concurrent('Payment flow', () => {
  test('makes payment and verifies channel status', async ({ server }) => {
    // 1. Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    console.log(`Channel capacity: ${channel.capacity} sats`);

    // 2. Create a message to convert to ASCII art
    const message = 'Hi';
    const expectedCost = message.length * server.getPricePerChar('sat');
    console.log(`Message: "${message}" (${message.length} chars, cost=${expectedCost} sats)`);

    // 3. Create payment header and fetch ASCII art
    const paymentHeader = createPaymentHeader(channel, expectedCost, true);
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

describe.concurrent('Channel policy', () => {
  test('rejects channel with capacity below minCapacity', async ({ server }) => {
    const minCapacity = server.getMinCapacity('sat');
    const tooSmallCapacity = minCapacity - 1;
    console.log(`Server minCapacity=${minCapacity}, using capacity=${tooSmallCapacity}`);

    // 1. Mint a funded channel with capacity below minCapacity
    const channel = await mintFundedChannel(server, 'sat', tooSmallCapacity);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

    // 2. Create payment header and fetch ASCII art
    const paymentHeader = createPaymentHeader(channel, 1, true);
    const { status, body } = await fetchAsciiArt(server, paymentHeader, 'X');

    // 3. Expect 402 with "capacity too small" in the reason
    console.log(`Response status: ${status}`);
    expect(status).toBe(402);
    expect(body.reason).toContain('capacity too small');
    expect(body.capacity).toBe(tooSmallCapacity);
    expect(body.min_capacity).toBe(minCapacity);
    console.log(`Rejected with reason: ${body.reason}`);
  });
});
