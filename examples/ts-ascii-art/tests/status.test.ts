import { test, describe, expect } from './fixtures.js';
import {
  mintFundedChannel,
  registerChannel,
  createPaymentHeader,
  encodePaymentHeader,
  fetchAsciiArt,
  fetchChannelStatus,
} from './helpers.js';
import { spilman_channel_sender_create_signed_balance_update } from '../src/wasm/cdk_wasm.js';

describe.concurrent('Channel status tracking', () => {
  test('returns status with zeroes before payment, then updated after payment', async ({ server }) => {
    // Mint and register a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    await registerChannel(server, channel);

    // Check status after registration (before any payments)
    const { httpStatus: statusCode0, body: status0 } = await fetchChannelStatus(server, channel.channelId);
    expect(statusCode0).toBe(200);
    expect(status0!.channel_id).toBe(channel.channelId);
    expect(status0!.capacity).toBe(channel.capacity);
    expect(status0!.balance).toBe(0);
    expect(status0!.amount_due).toBe(0);
    expect(status0!.closed).toBe(false);
    console.log(`Status before payment: balance=${status0!.balance} amount_due=${status0!.amount_due}`);

    // Make first payment
    const message1 = 'Hi';
    const cost1 = message1.length * server.getPricePerChar('sat');
    const paymentHeader1 = createPaymentHeader(channel, cost1);
    const { status: paymentStatus1 } = await fetchAsciiArt(server, paymentHeader1, message1);
    expect(paymentStatus1).toBe(200);

    // Check status after first payment
    const { httpStatus: statusCode1, body: status1 } = await fetchChannelStatus(server, channel.channelId);
    expect(statusCode1).toBe(200);
    expect(status1!.balance).toBe(cost1);
    expect(status1!.amount_due).toBe(cost1);
    // chars_served is optional (not all servers track character-level usage)
    if (status1!.chars_served !== undefined) expect(status1!.chars_served).toBe(message1.length);
    console.log(`Status after 1st payment: balance=${status1!.balance} amount_due=${status1!.amount_due}${status1!.chars_served !== undefined ? ` chars_served=${status1!.chars_served}` : ''}`);

    // Make second payment
    const message2 = 'Hey';
    const cost2 = cost1 + (message2.length * server.getPricePerChar('sat'));
    const paymentHeader2 = createPaymentHeader(channel, cost2);
    const { status: paymentStatus2 } = await fetchAsciiArt(server, paymentHeader2, message2);
    expect(paymentStatus2).toBe(200);

    // Check status after second payment
    const { httpStatus: statusCode2, body: status2 } = await fetchChannelStatus(server, channel.channelId);
    expect(statusCode2).toBe(200);
    expect(status2!.balance).toBe(cost2);
    expect(status2!.amount_due).toBe(cost2);
    // chars_served should have accumulated if tracked
    if (status2!.chars_served !== undefined) expect(status2!.chars_served).toBe(message1.length + message2.length);
    console.log(`Status after 2nd payment: balance=${status2!.balance} amount_due=${status2!.amount_due}${status2!.chars_served !== undefined ? ` chars_served=${status2!.chars_served}` : ''}`);
  });

  test('does not update status when payment fails', async ({ server }) => {
    // Mint and register a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    await registerChannel(server, channel);

    // Make a successful payment
    const message = 'Hi';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader = createPaymentHeader(channel, cost);
    const { status: paymentStatus } = await fetchAsciiArt(server, paymentHeader, message);
    expect(paymentStatus).toBe(200);

    // Check status after first payment
    const { body: status1 } = await fetchChannelStatus(server, channel.channelId);
    expect(status1!.balance).toBe(cost);
    expect(status1!.amount_due).toBe(cost);
    console.log(`Status after payment: balance=${status1!.balance} amount_due=${status1!.amount_due}`);

    // Attempt a second request with wrong balance (signature is for balance=cost, but we send balance=cost+1)
    // This uses the same signature but claims a higher balance
    const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
      channel.channelParamsJson,
      JSON.stringify(channel.keysetInfo),
      channel.alice.secretHex,
      JSON.stringify(channel.proofs),
      BigInt(cost)  // Signature for balance=cost
    );
    const balanceUpdate = JSON.parse(balanceUpdateJson);

    const badPaymentHeader = encodePaymentHeader({
      channel_id: balanceUpdate.channel_id,
      balance: cost + 1,  // Wrong! Signature is for balance=cost
      signature: balanceUpdate.signature,
    });

    const badResponse = await fetch(`${server.baseUrl}/ascii`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Cashu-Channel': badPaymentHeader,
      },
      body: JSON.stringify({ message: 'X' }),
    });
    expect(badResponse.status).toBe(402);
    const errorBody = await badResponse.json();
    expect(errorBody.reason).toContain('invalid signature');
    console.log(`Failed payment rejected: ${errorBody.reason}`);

    // Check status has NOT changed
    const { body: status2 } = await fetchChannelStatus(server, channel.channelId);
    expect(status2!.balance).toBe(cost);  // Still same as before failed payment
    expect(status2!.amount_due).toBe(cost);  // Still same
    console.log(`Status unchanged after failed payment: balance=${status2!.balance} amount_due=${status2!.amount_due}`);
  });
});
