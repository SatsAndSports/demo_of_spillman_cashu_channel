import { test, describe, expect } from './fixtures.js';
import {
  mintFundedChannel,
  createPaymentHeader,
  fetchAsciiArt,
  fetchChannelStatus,
  closeChannel,
} from './helpers.js';

describe.concurrent('Channel closing', () => {
  test('closes unused channel directly with params (balance=0)', async ({ server }) => {
    // Mint a funded channel but make NO payments
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

    // Close directly with balance=0 and includeParams=true
    // The server doesn't know about this channel, so we must provide params/proofs
    const { httpStatus, body } = await closeChannel(server, channel, 0, true);

    console.log(`Close response: status=${httpStatus}`);
    expect(httpStatus).toBe(200);
    expect(body.success).toBe(true);
    expect(body.channel_id).toBe(channel.channelId);
    // total_value >= capacity (includes fee reserve when mint has input fees)
    expect(body.total_value).toBeGreaterThanOrEqual(channel.capacity);
    expect(body.sender_proofs).toBeDefined();
    expect(Array.isArray(body.sender_proofs)).toBe(true);
    expect(body.sender_proofs.length).toBeGreaterThan(0);
    expect(body.already_closed).toBe(false);

    // Sender should get back ALL the funds (receiver gets nothing)
    // With balance=0, sender_proofs sum equals total_value (full refund)
    const senderSum = body.sender_proofs.reduce((sum: number, p: any) => sum + p.amount, 0);
    expect(senderSum).toBe(body.total_value);
    console.log(`Sender recovered all ${senderSum} sats (channel was unused, total_value=${body.total_value})`);

    // Verify channel is now closed
    const { body: statusBody } = await fetchChannelStatus(server, channel.channelId);
    expect(statusBody!.closed).toBe(true);
    expect(statusBody!.closed_amount).toBe(0);
  });

  test('closes channel immediately after first payment (balance=cost)', async ({ server }) => {
    // Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

    // Make a minimal payment to establish the channel
    const message = 'X';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader = createPaymentHeader(channel, cost, true);
    const { status } = await fetchAsciiArt(server, paymentHeader, message);
    expect(status).toBe(200);
    console.log(`Made payment: cost=${cost}`);

    // Close with balance=cost (minimal usage)
    const { httpStatus, body } = await closeChannel(server, channel, cost, false);

    console.log(`Close response: status=${httpStatus}`);
    expect(httpStatus).toBe(200);
    expect(body.success).toBe(true);
    expect(body.channel_id).toBe(channel.channelId);
    expect(body.total_value).toBeGreaterThan(0);
    expect(body.sender_proofs).toBeDefined();
    expect(Array.isArray(body.sender_proofs)).toBe(true);
    expect(body.sender_proofs.length).toBeGreaterThan(0);
    expect(body.already_closed).toBe(false);

    // Verify sender proofs have required fields
    for (const proof of body.sender_proofs) {
      expect(proof.amount).toBeDefined();
      expect(proof.id).toBeDefined();
      expect(proof.secret).toBeDefined();
      expect(proof.C).toBeDefined();
    }

    const senderSum = body.sender_proofs.reduce((sum: number, p: any) => sum + p.amount, 0);
    console.log(`Closed with total_value=${body.total_value}, sender_proofs=${body.sender_proofs.length} (sum=${senderSum})`);
  });

  test('closes used channel with correct balance', async ({ server }) => {
    // Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

    // Make a payment
    const message = 'Hello';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader = createPaymentHeader(channel, cost, true);
    const { status } = await fetchAsciiArt(server, paymentHeader, message);
    expect(status).toBe(200);
    console.log(`Made payment: cost=${cost}`);

    // Get amount_due from status
    const { body: statusBody } = await fetchChannelStatus(server, channel.channelId);
    const amountDue = statusBody!.amount_due;
    console.log(`Amount due before close: ${amountDue}`);

    // Close with amount_due
    const { httpStatus, body } = await closeChannel(server, channel, amountDue, false);

    expect(httpStatus).toBe(200);
    expect(body.success).toBe(true);
    expect(body.total_value).toBeGreaterThan(0);
    expect(body.sender_proofs).toBeDefined();
    expect(body.already_closed).toBe(false);

    const senderSum = body.sender_proofs.reduce((sum: number, p: any) => sum + p.amount, 0);
    console.log(`Closed with total_value=${body.total_value}, sender got ${senderSum} back`);

    // Verify status shows closed
    const { body: statusAfter } = await fetchChannelStatus(server, channel.channelId);
    expect(statusAfter!.closed).toBe(true);
    expect(statusAfter!.closed_amount).toBe(amountDue);
    console.log(`Status after close: closed=true, closed_amount=${statusAfter!.closed_amount}`);
  });

  test('idempotent close with same amount succeeds', async ({ server }) => {
    // Mint a channel and make a payment to establish it
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

    // Make a payment to establish the channel
    const message = 'X';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader = createPaymentHeader(channel, cost, true);
    const { status } = await fetchAsciiArt(server, paymentHeader, message);
    expect(status).toBe(200);

    // First close
    const { httpStatus: status1, body: body1 } = await closeChannel(server, channel, cost, false);
    expect(status1).toBe(200);
    expect(body1.success).toBe(true);
    expect(body1.already_closed).toBe(false);
    console.log(`First close: total_value=${body1.total_value}, sender_proofs=${body1.sender_proofs.length}`);

    // Second close with same amount - should succeed with already_closed=true
    const { httpStatus: status2, body: body2 } = await closeChannel(server, channel, cost, false);
    expect(status2).toBe(200);
    expect(body2.success).toBe(true);
    expect(body2.already_closed).toBe(true);
    expect(body2.total_value).toBe(body1.total_value);
    expect(body2.sender_proofs.length).toBe(body1.sender_proofs.length);
    console.log(`Second close (idempotent): already_closed=true, sender_proofs=${body2.sender_proofs.length}`);
  });

  test('rejects close with different amount after already closed', async ({ server }) => {
    // Mint a channel and make a payment
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

    // Make a payment
    const message = 'Hi';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader = createPaymentHeader(channel, cost, true);
    const { status } = await fetchAsciiArt(server, paymentHeader, message);
    expect(status).toBe(200);

    // Close with the correct amount
    const { httpStatus: status1, body: body1 } = await closeChannel(server, channel, cost, false);
    expect(status1).toBe(200);
    expect(body1.success).toBe(true);
    console.log(`First close with balance=${cost} succeeded`);

    // Try to close again with different amount
    const differentAmount = cost + 1;
    const { httpStatus: status2, body: body2 } = await closeChannel(server, channel, differentAmount, false);
    expect(status2).toBe(400);
    expect(body2.error).toContain('already closed');
    expect(body2.closed_amount).toBe(cost);
    expect(body2.requested_amount).toBe(differentAmount);
    console.log(`Second close with different amount rejected: ${body2.error}`);
  });

  test('rejects payment on closed channel', async ({ server }) => {
    // Mint a channel and make a payment to establish it
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

    // Make a payment to establish the channel
    const message = 'Hi';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader1 = createPaymentHeader(channel, cost, true);
    const { status: paymentStatus } = await fetchAsciiArt(server, paymentHeader1, message);
    expect(paymentStatus).toBe(200);
    console.log(`Payment made: cost=${cost}`);

    // Close the channel
    const { httpStatus: closeStatus } = await closeChannel(server, channel, cost, false);
    expect(closeStatus).toBe(200);
    console.log('Channel closed');

    // Try to make another payment on the closed channel
    const newCost = cost + 1; // Try to pay more
    const paymentHeader2 = createPaymentHeader(channel, newCost, false);
    const { status, body } = await fetchAsciiArt(server, paymentHeader2, 'X');

    expect(status).toBe(402);
    expect(body.reason).toContain('channel closed');
    console.log(`Payment rejected on closed channel: ${body.reason}`);
  });

  test('rejects close with invalid signature', async ({ server }) => {
    // Mint a funded channel and establish it with a payment
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);

    // Make a payment to establish the channel
    const message = 'X';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader = createPaymentHeader(channel, cost, true);
    const { status } = await fetchAsciiArt(server, paymentHeader, message);
    expect(status).toBe(200);

    // Try to close with invalid signature
    const response = await fetch(`${server.baseUrl}/channel/${channel.channelId}/close`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        balance: cost,
        signature: 'invalid_signature_that_will_not_verify',
      }),
    });

    expect(response.status).toBe(402);
    const body = await response.json();
    expect(body.reason).toContain('invalid signature');
    console.log(`Close rejected with invalid signature: ${body.reason}`);
  });

  test('rejects close for unknown channel without params', async ({ server }) => {
    // Try to close a channel the server doesn't know about, without providing params
    const fakeChannelId = 'deadbeef'.repeat(8);

    const response = await fetch(`${server.baseUrl}/channel/${fakeChannelId}/close`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        balance: 0,
        signature: 'any_signature',
        // No params or funding_proofs
      }),
    });

    expect(response.status).toBe(402);
    const body = await response.json();
    expect(body.reason).toContain('unknown channel');
    console.log(`Close rejected for unknown channel: ${body.reason}`);
  });
});
