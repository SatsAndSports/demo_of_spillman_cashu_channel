import { randomBytes } from 'crypto';
import { test, describe, expect } from './fixtures.js';
import {
  mintFundedChannel,
  registerChannel,
  createPaymentHeader,
  fetchAsciiArt,
  fetchChannelStatus,
  closeChannel,
  generateKeypair,
  fetchKeysetInfo,
  getFirstKeysetId,
  secretKeyToPubkey,
  get_sender_blinded_secret_key_for_stage2_output,
} from './helpers.js';
import {
  WasmSpilmanBridge,
  spilman_channel_sender_create_signed_balance_update,
  compute_shared_secret,
  channel_parameters_get_channel_id,
  create_funding_outputs,
  construct_proofs,
} from '../src/wasm/cdk_wasm.js';

describe.concurrent('Channel closing', () => {
  test('closes unused channel (balance=0)', async ({ server }) => {
    // Mint and register a funded channel but make NO payments
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    await registerChannel(server, channel);

    // Close with balance=0
    const { httpStatus, body } = await closeChannel(server, channel, 0);

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
    // Mint and register a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    await registerChannel(server, channel);

    // Make a minimal payment
    const message = 'X';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader = createPaymentHeader(channel, cost);
    const { status } = await fetchAsciiArt(server, paymentHeader, message);
    expect(status).toBe(200);
    console.log(`Made payment: cost=${cost}`);

    // Close with balance=cost (minimal usage)
    const { httpStatus, body } = await closeChannel(server, channel, cost);

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
    // Mint and register a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    await registerChannel(server, channel);

    // Make a payment
    const message = 'Hello';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader = createPaymentHeader(channel, cost);
    const { status } = await fetchAsciiArt(server, paymentHeader, message);
    expect(status).toBe(200);
    console.log(`Made payment: cost=${cost}`);

    // Get amount_due from status
    const { body: statusBody } = await fetchChannelStatus(server, channel.channelId);
    const amountDue = statusBody!.amount_due;
    console.log(`Amount due before close: ${amountDue}`);

    // Close with amount_due
    const { httpStatus, body } = await closeChannel(server, channel, amountDue);

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
    // Mint and register a channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    await registerChannel(server, channel);

    // Make a payment
    const message = 'X';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader = createPaymentHeader(channel, cost);
    const { status } = await fetchAsciiArt(server, paymentHeader, message);
    expect(status).toBe(200);

    // First close
    const { httpStatus: status1, body: body1 } = await closeChannel(server, channel, cost);
    expect(status1).toBe(200);
    expect(body1.success).toBe(true);
    expect(body1.already_closed).toBe(false);
    console.log(`First close: total_value=${body1.total_value}, sender_proofs=${body1.sender_proofs.length}`);

    // Second close with same amount - should succeed with already_closed=true
    const { httpStatus: status2, body: body2 } = await closeChannel(server, channel, cost);
    expect(status2).toBe(200);
    expect(body2.success).toBe(true);
    expect(body2.already_closed).toBe(true);
    expect(body2.total_value).toBe(body1.total_value);
    expect(body2.sender_proofs.length).toBe(body1.sender_proofs.length);
    console.log(`Second close (idempotent): already_closed=true, sender_proofs=${body2.sender_proofs.length}`);
  });

  test('rejects close with different amount after already closed', async ({ server }) => {
    // Mint and register a channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    await registerChannel(server, channel);

    // Make a payment
    const message = 'Hi';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader = createPaymentHeader(channel, cost);
    const { status } = await fetchAsciiArt(server, paymentHeader, message);
    expect(status).toBe(200);

    // Close with the correct amount
    const { httpStatus: status1, body: body1 } = await closeChannel(server, channel, cost);
    expect(status1).toBe(200);
    expect(body1.success).toBe(true);
    console.log(`First close with balance=${cost} succeeded`);

    // Try to close again with different amount
    const differentAmount = cost + 1;
    const { httpStatus: status2, body: body2 } = await closeChannel(server, channel, differentAmount);
    expect(status2).toBe(400);
    expect(body2.error).toContain('already closed');
    expect(body2.closed_amount).toBe(cost);
    expect(body2.requested_amount).toBe(differentAmount);
    console.log(`Second close with different amount rejected: ${body2.error}`);
  });

  test('rejects payment on closed channel', async ({ server }) => {
    // Mint and register a channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    await registerChannel(server, channel);

    // Make a payment
    const message = 'Hi';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader1 = createPaymentHeader(channel, cost);
    const { status: paymentStatus } = await fetchAsciiArt(server, paymentHeader1, message);
    expect(paymentStatus).toBe(200);
    console.log(`Payment made: cost=${cost}`);

    // Close the channel
    const { httpStatus: closeStatus } = await closeChannel(server, channel, cost);
    expect(closeStatus).toBe(200);
    console.log('Channel closed');

    // Try to make another payment on the closed channel
    const newCost = cost + 1; // Try to pay more
    const paymentHeader2 = createPaymentHeader(channel, newCost);
    const { status, body } = await fetchAsciiArt(server, paymentHeader2, 'X');

    expect(status).toBe(402);
    expect(body.reason).toContain('channel closed');
    console.log(`Payment rejected on closed channel: ${body.reason}`);
  });

  test('rejects close with invalid signature', async ({ server }) => {
    // Mint and register a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    await registerChannel(server, channel);

    // Make a payment
    const message = 'X';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader = createPaymentHeader(channel, cost);
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

    expect(response.status).toBe(404);
    const body = await response.json();
    expect(body.error).toContain('unknown channel');
    console.log(`Close rejected for unknown channel: ${body.error}`);
  });

  test('closes unused channel and verifies sender can derive secret keys for returned proofs', async ({ server }) => {
    // Alice mints a funded channel but never uses it
    // She can close immediately with balance=0
    // After close, she should be able to derive the secret key for each returned proof
    const channel = await mintFundedChannel(server, 'sat', 100);
    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    await registerChannel(server, channel);

    // Close the channel with balance=0 (unused)
    const { httpStatus, body: closeResult } = await closeChannel(server, channel, 0);

    expect(httpStatus).toBe(200);
    expect(closeResult.success).toBe(true);
    expect(closeResult.sender_proofs).toBeDefined();
    expect(Array.isArray(closeResult.sender_proofs)).toBe(true);
    expect(closeResult.sender_proofs.length).toBeGreaterThan(0);

    const senderSum = closeResult.sender_proofs.reduce((sum: number, p: any) => sum + p.amount, 0);
    console.log(`Channel closed with total_value=${closeResult.total_value}, sender_proofs=${closeResult.sender_proofs.length} (sum=${senderSum})`);

    // Verify Alice can derive the secret key for each sender_proof
    // The proofs are sorted smallest-amount-first, then by index within each amount
    const indexByAmount: Record<number, number> = {};
    for (const proof of closeResult.sender_proofs) {
      const amount = proof.amount;
      const index = indexByAmount[amount] ?? 0;
      indexByAmount[amount] = index + 1;

      // Get Alice's blinded secret key for this specific output
      const blindedSecretHex = get_sender_blinded_secret_key_for_stage2_output(
        channel.channelParamsJson,
        JSON.stringify(channel.keysetInfo),
        channel.alice.secretHex,
        BigInt(amount),
        index
      );

      // Derive pubkey from the secret key
      const derivedPubkey = secretKeyToPubkey(blindedSecretHex);

      // Parse the P2PK secret from the proof to get the locked pubkey
      // Secret format is: ["P2PK", {"nonce": "...", "data": "pubkey_hex", ...}]
      const secretArr = JSON.parse(proof.secret);
      expect(Array.isArray(secretArr)).toBe(true);
      expect(secretArr[0]).toBe('P2PK');
      const lockedPubkey = secretArr[1].data;

      // Verify they match
      expect(derivedPubkey).toBe(lockedPubkey);
    }
    console.log(`Alice can derive secret keys for all ${closeResult.sender_proofs.length} sender_proofs`);
  });

  test('rejects close with balance less than amount_due', async ({ server }) => {
    // Mint and register a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    await registerChannel(server, channel);

    // Make a payment to create usage
    const message = 'Hello';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader = createPaymentHeader(channel, cost);
    const { status } = await fetchAsciiArt(server, paymentHeader, message);
    expect(status).toBe(200);

    // Get amount_due
    const { body: statusBody } = await fetchChannelStatus(server, channel.channelId);
    const amountDue = statusBody!.amount_due;
    console.log(`amount_due=${amountDue}`);
    expect(amountDue).toBeGreaterThan(0);

    // Try to close with balance=0 (less than amount_due)
    const { httpStatus, body } = await closeChannel(server, channel, 0);

    expect(httpStatus).toBe(402);
    expect(body.error).toBe('Payment required');
    expect(body.reason).toContain('balance mismatch');
    // actual/expected fields are optional - not all servers return them
    if (body.actual !== undefined) expect(body.actual).toBe(0);
    if (body.expected !== undefined) expect(body.expected).toBe(amountDue);
    console.log('rejects close with insufficient balance');
  });

  test('rejects close with nonzero balance of an unused channel', async ({ server }) => {
    // Mint and register a funded channel (no usage, so amount_due = 0)
    const channel = await mintFundedChannel(server, 'sat', 100);
    await registerChannel(server, channel);

    // Try to close with balance=10 (but amount_due is 0 since channel was never used)
    const { httpStatus, body } = await closeChannel(server, channel, 10);

    expect(httpStatus).toBe(402);
    expect(body.error).toBe('Payment required');
    expect(body.reason).toContain('balance mismatch');
    // actual/expected fields are optional - not all servers return them
    if (body.actual !== undefined) expect(body.actual).toBe(10);
    if (body.expected !== undefined) expect(body.expected).toBe(0);
    console.log('Close rejected with nonzero balance on unused channel');
  });

  test('rejects close with balance greater than amount_due on used channel', async ({ server }) => {
    // Mint and register a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);
    await registerChannel(server, channel);

    // Make a payment to create usage
    const message = 'X';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader = createPaymentHeader(channel, cost);
    const { status } = await fetchAsciiArt(server, paymentHeader, message);
    expect(status).toBe(200);

    // Get amount_due (should be cost)
    const { body: statusBody } = await fetchChannelStatus(server, channel.channelId);
    const amountDue = statusBody!.amount_due;
    console.log(`amount_due=${amountDue}`);
    expect(amountDue).toBeGreaterThan(0);

    // Try to close with balance > amount_due
    const overpayBalance = amountDue + 5;
    const { httpStatus, body } = await closeChannel(server, channel, overpayBalance);

    expect(httpStatus).toBe(402);
    expect(body.error).toBe('Payment required');
    expect(body.reason).toContain('balance mismatch');
    // actual/expected fields are optional - not all servers return them
    if (body.actual !== undefined) expect(body.actual).toBe(overpayBalance);
    if (body.expected !== undefined) expect(body.expected).toBe(amountDue);
    console.log('Close rejected with balance > amount_due on used channel');
  });
});

describe.concurrent('Unilateral closing', () => {
  test('server can unilaterally close channel with payments', async ({ server }) => {
    const channel = await mintFundedChannel(server, 'sat', 100);
    await registerChannel(server, channel);
    const message = 'Hello';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader = createPaymentHeader(channel, cost);
    await fetchAsciiArt(server, paymentHeader, message);

    const response = await fetch(`${server.baseUrl}/channel/${channel.channelId}/unilateral-close`, {
      method: 'POST',
    });

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.success).toBe(true);
    expect(body.channel_id).toBe(channel.channelId);
    // Server earns at least the cost (may be more due to input fees)
    expect(body.earnedBeforeStage2Fees).toBeGreaterThanOrEqual(cost);
    expect(body.already_closed).toBe(false);
  });

  test('unilateral close earns overpayment for server', async ({ server }) => {
    const channel = await mintFundedChannel(server, 'sat', 100);
    await registerChannel(server, channel);
    const message = 'Hello'; // 5 chars
    const actualCost = message.length * server.getPricePerChar('sat');
    const overpayment = 20;

    const paymentHeader = createPaymentHeader(channel, overpayment);
    const { status } = await fetchAsciiArt(server, paymentHeader, message);
    expect(status).toBe(200);

    const response = await fetch(`${server.baseUrl}/channel/${channel.channelId}/unilateral-close`, {
      method: 'POST',
    });

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.success).toBe(true);
    // Server keeps full signed balance (stage 2 fees not yet applied)
    expect(body.earnedBeforeStage2Fees).toBeGreaterThanOrEqual(overpayment);
    console.log(`Server earnedBeforeStage2Fees=${body.earnedBeforeStage2Fees} (signed balance was ${overpayment}, actual cost was ${actualCost})`);
  });

  test('unilateral close is idempotent', async ({ server }) => {
    const channel = await mintFundedChannel(server, 'sat', 100);
    await registerChannel(server, channel);
    const cost = 5;
    const paymentHeader = createPaymentHeader(channel, cost);
    await fetchAsciiArt(server, paymentHeader, 'Hello');

    const resp1 = await fetch(`${server.baseUrl}/channel/${channel.channelId}/unilateral-close`, { method: 'POST' });
    expect(resp1.status).toBe(200);
    const body1 = await resp1.json();
    expect(body1.already_closed).toBe(false);

    const resp2 = await fetch(`${server.baseUrl}/channel/${channel.channelId}/unilateral-close`, { method: 'POST' });
    expect(resp2.status).toBe(200);
    const body2 = await resp2.json();
    expect(body2.already_closed).toBe(true);
    expect(body2.earnedBeforeStage2Fees).toBe(body1.earnedBeforeStage2Fees);
  });

  test('rejects unilateral close for unknown channel', async ({ server }) => {
    const response = await fetch(`${server.baseUrl}/channel/${'dead'.repeat(16)}/unilateral-close`, {
      method: 'POST',
    });
    expect(response.status).toBe(404);
    const body = await response.json();
    expect(body.error).toBe('unknown channel');
  });

  test('rejects unilateral close for channel with no payments', async ({ server }) => {
    // Register channel then close cooperatively with balance=0
    const channel = await mintFundedChannel(server, 'sat', 100);
    await registerChannel(server, channel);
    await closeChannel(server, channel, 0);

    // Channel is now closed - unilateral should return already_closed with earnedBeforeStage2Fees=0
    const response = await fetch(`${server.baseUrl}/channel/${channel.channelId}/unilateral-close`, { method: 'POST' });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.already_closed).toBe(true);
    expect(body.earnedBeforeStage2Fees).toBe(0);
  });

  test('cooperative close works after unilateral close', async ({ server }) => {
    const channel = await mintFundedChannel(server, 'sat', 100);
    await registerChannel(server, channel);
    const cost = 5;
    const paymentHeader = createPaymentHeader(channel, cost);
    await fetchAsciiArt(server, paymentHeader, 'Hello');

    await fetch(`${server.baseUrl}/channel/${channel.channelId}/unilateral-close`, { method: 'POST' });

    const { httpStatus, body } = await closeChannel(server, channel, cost);
    expect(httpStatus).toBe(200);
    expect(body.already_closed).toBe(true);
  });

  test('rejects payment after unilateral close', async ({ server }) => {
    const channel = await mintFundedChannel(server, 'sat', 100);
    await registerChannel(server, channel);
    const cost = 5;
    const paymentHeader1 = createPaymentHeader(channel, cost);
    await fetchAsciiArt(server, paymentHeader1, 'Hello');

    await fetch(`${server.baseUrl}/channel/${channel.channelId}/unilateral-close`, { method: 'POST' });

    const paymentHeader2 = createPaymentHeader(channel, cost + 1);
    const { status, body } = await fetchAsciiArt(server, paymentHeader2, 'X');
    expect(status).toBe(402);
    expect(body.reason).toContain('channel closed');
  });
});

describe('Keyset refresh retry logic', () => {
  test('retries cooperative close with refreshed keysets when first swap fails', async ({ server }) => {
    // 1. Generate a keypair for our test bridge (Charlie/receiver)
    const charlie = generateKeypair();
    const mintUrl = server.mintUrl;

    // 2. Get keyset info for building a channel
    const keysetId = await getFirstKeysetId(mintUrl, 'sat');
    const keysetInfo = await fetchKeysetInfo(mintUrl, keysetId);

    // 3. Create a funded channel with our test Charlie as receiver
    //    (We can't use mintFundedChannel because it uses server's pubkey)
    const alice = generateKeypair();

    const setupTimestamp = Math.floor(Date.now() / 1000);
    const locktime = setupTimestamp + 7 * 24 * 60 * 60;
    const capacity = 100;

    const channelParams = {
      mint: mintUrl,
      unit: 'sat',
      capacity,
      keyset_id: keysetId,
      input_fee_ppk: keysetInfo.inputFeePpk,
      maximum_amount: 64,
      setup_timestamp: setupTimestamp,
      alice_pubkey: alice.pubkeyHex,
      charlie_pubkey: charlie.pubkeyHex,
      locktime,
      sender_nonce: randomBytes(32).toString('hex'),
    };
    const channelParamsJson = JSON.stringify(channelParams);

    // Generate funding outputs and mint them
    const fundingOutputsJson = create_funding_outputs(channelParamsJson, alice.secretHex, JSON.stringify(keysetInfo));
    const fundingOutputs = JSON.parse(fundingOutputsJson);

    const quoteRes = await fetch(`${mintUrl}/v1/mint/quote/bolt11`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount: fundingOutputs.funding_token_nominal, unit: 'sat' }),
    });
    const quote = await quoteRes.json();

    // Wait for payment (FakeWallet auto-pays)
    for (let i = 0; i < 30; i++) {
      const statusRes = await fetch(`${mintUrl}/v1/mint/quote/bolt11/${quote.quote}`);
      const status = await statusRes.json();
      if (status.state === 'PAID') break;
      await new Promise(r => setTimeout(r, 100));
    }

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

    const proofsJson = construct_proofs(
      JSON.stringify(mintData.signatures),
      JSON.stringify(fundingOutputs.secrets_with_blinding),
      JSON.stringify(keysetInfo)
    );
    const proofs = JSON.parse(proofsJson);

    const sharedSecret = compute_shared_secret(alice.secretHex, charlie.pubkeyHex);
    const channelId = channel_parameters_get_channel_id(channelParamsJson, sharedSecret, JSON.stringify(keysetInfo));

    console.log(`Channel ${channelId.substring(0, 8)} created with test keypair`);

    // 4. Track retry behavior
    let swapAttempts = 0;
    let refreshWasCalled = false;

    // 5. Build keyset cache for the test host
    const keysetCache = new Map<string, string>();
    keysetCache.set(`${mintUrl}|${keysetId}`, JSON.stringify(keysetInfo));

    // 6. Create test host with tracking
    const testHost = {
      receiverKeyIsAcceptable: (pubkeyHex: string): boolean => {
        return pubkeyHex.toLowerCase() === charlie.pubkeyHex.toLowerCase();
      },

      mintAndKeysetIsAcceptable: (mint: string, ksId: string): boolean => {
        return mint === mintUrl && keysetCache.has(`${mint}|${ksId}`);
      },

      getFundingAndParams: (chId: string): [string, string, string, string] | null => {
        if (chId !== channelId) return null;
        return [channelParamsJson, JSON.stringify(proofs), sharedSecret, JSON.stringify(keysetInfo)];
      },

      saveFunding: () => {},

      getAmountDue: (): bigint => BigInt(0), // No amount due for this test

      recordPayment: () => {},

      isClosed: (): boolean => false,

      getChannelPolicy: (): string => JSON.stringify({
        min_expiry_in_seconds: 3600,
        pricing: { sat: { per_char: 1, minCapacity: 10 } },
      }),

      nowSeconds: (): bigint => BigInt(Math.floor(Date.now() / 1000)),

      getBalanceAndSignatureForUnilateralExit: (): null => null,

      getActiveKeysetIds: (mint: string, unit: string): string[] => {
        if (mint === mintUrl && unit === 'sat') return [keysetId];
        return [];
      },

      getKeysetInfo: (mint: string, ksId: string): string | null => {
        return keysetCache.get(`${mint}|${ksId}`) ?? null;
      },

      callMintSwap: async (mint: string, swapRequestJson: string): Promise<string> => {
        swapAttempts++;
        console.log(`  [TestHost] callMintSwap attempt #${swapAttempts}`);
        if (swapAttempts === 1) {
          console.log(`  [TestHost] Returning fake "Inactive Keyset" error`);
          return JSON.stringify({ error: "Inactive Keyset", code: 12002 });
        }
        console.log(`  [TestHost] Passing through to real mint`);
        const response = await fetch(`${mint}/v1/swap`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: swapRequestJson,
        });
        return await response.text();
      },

      refreshActiveKeysets: async (mint: string): Promise<void> => {
        console.log(`  [TestHost] refreshActiveKeysets called for ${mint}`);
        refreshWasCalled = true;
        // Actually refresh keyset info
        const newKeysetInfo = await fetchKeysetInfo(mint, keysetId);
        keysetCache.set(`${mint}|${keysetId}`, JSON.stringify(newKeysetInfo));
      },

      markChannelClosed: (): void => {},
    };

    // 7. Create test bridge with our host
    const testBridge = new WasmSpilmanBridge(testHost, charlie.secretHex);

    // 8. Build close request with balance=0 (no payments made)
    const balance = 0;
    const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
      channelParamsJson,
      JSON.stringify(keysetInfo),
      alice.secretHex,
      JSON.stringify(proofs),
      BigInt(balance)
    );
    const balanceUpdate = JSON.parse(balanceUpdateJson);

    const closeBody = {
      channel_id: channelId,
      balance,
      signature: balanceUpdate.signature,
      params: channelParams,
      funding_proofs: proofs,
    };

    // 9. Execute close directly on test bridge
    const resultJson = await testBridge.executeCooperativeClose(JSON.stringify(closeBody));
    const result = JSON.parse(resultJson);

    // 10. Verify retry happened and succeeded
    console.log(`Retry test: swapAttempts=${swapAttempts}, refreshWasCalled=${refreshWasCalled}, success=${result.success}`);
    if (!result.success) {
      console.log(`  Error: ${result.error}, reason: ${result.reason}`);
    }
    expect(swapAttempts).toBe(2);
    expect(refreshWasCalled).toBe(true);
    expect(result.success).toBe(true);
    expect(result.channel_id).toBe(channelId);
  });

  test('retries unilateral close with refreshed keysets when first swap fails', async ({ server }) => {
    // 1. Generate keypairs for our test bridge
    const charlie = generateKeypair();
    const alice = generateKeypair();
    const mintUrl = server.mintUrl;

    // 2. Get keyset info for building a channel
    const keysetId = await getFirstKeysetId(mintUrl, 'sat');
    const keysetInfo = await fetchKeysetInfo(mintUrl, keysetId);

    // 3. Create channel parameters
    const setupTimestamp = Math.floor(Date.now() / 1000);
    const locktime = setupTimestamp + 7 * 24 * 60 * 60;
    const capacity = 100;

    const channelParams = {
      mint: mintUrl,
      unit: 'sat',
      capacity,
      keyset_id: keysetId,
      input_fee_ppk: keysetInfo.inputFeePpk,
      maximum_amount: 64,
      setup_timestamp: setupTimestamp,
      alice_pubkey: alice.pubkeyHex,
      charlie_pubkey: charlie.pubkeyHex,
      locktime,
      sender_nonce: randomBytes(32).toString('hex'),
    };
    const channelParamsJson = JSON.stringify(channelParams);

    // 4. Mint funded channel
    const fundingOutputsJson = create_funding_outputs(channelParamsJson, alice.secretHex, JSON.stringify(keysetInfo));
    const fundingOutputs = JSON.parse(fundingOutputsJson);

    const quoteRes = await fetch(`${mintUrl}/v1/mint/quote/bolt11`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount: fundingOutputs.funding_token_nominal, unit: 'sat' }),
    });
    const quote = await quoteRes.json();

    for (let i = 0; i < 30; i++) {
      const statusRes = await fetch(`${mintUrl}/v1/mint/quote/bolt11/${quote.quote}`);
      const status = await statusRes.json();
      if (status.state === 'PAID') break;
      await new Promise(r => setTimeout(r, 100));
    }

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

    const proofsJson = construct_proofs(
      JSON.stringify(mintData.signatures),
      JSON.stringify(fundingOutputs.secrets_with_blinding),
      JSON.stringify(keysetInfo)
    );
    const proofs = JSON.parse(proofsJson);

    const sharedSecret = compute_shared_secret(alice.secretHex, charlie.pubkeyHex);
    const channelId = channel_parameters_get_channel_id(channelParamsJson, sharedSecret, JSON.stringify(keysetInfo));

    console.log(`Channel ${channelId.substring(0, 8)} created for unilateral close retry test`);

    // 5. Create a signed balance update to simulate a recorded payment
    const paymentBalance = 50;
    const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
      channelParamsJson,
      JSON.stringify(keysetInfo),
      alice.secretHex,
      JSON.stringify(proofs),
      BigInt(paymentBalance)
    );
    const balanceUpdate = JSON.parse(balanceUpdateJson);

    // 6. Track retry behavior
    let swapAttempts = 0;
    let refreshWasCalled = false;

    // 7. Build keyset cache for the test host
    const keysetCache = new Map<string, string>();
    keysetCache.set(`${mintUrl}|${keysetId}`, JSON.stringify(keysetInfo));

    // 8. Create test host - key difference: getBalanceAndSignatureForUnilateralExit returns the payment
    const testHost = {
      receiverKeyIsAcceptable: (pubkeyHex: string): boolean => {
        return pubkeyHex.toLowerCase() === charlie.pubkeyHex.toLowerCase();
      },

      mintAndKeysetIsAcceptable: (mint: string, ksId: string): boolean => {
        return mint === mintUrl && keysetCache.has(`${mint}|${ksId}`);
      },

      getFundingAndParams: (chId: string): [string, string, string, string] | null => {
        if (chId !== channelId) return null;
        return [channelParamsJson, JSON.stringify(proofs), sharedSecret, JSON.stringify(keysetInfo)];
      },

      saveFunding: () => {},

      getAmountDue: (): bigint => BigInt(paymentBalance),

      recordPayment: () => {},

      isClosed: (): boolean => false,

      getChannelPolicy: (): string => JSON.stringify({
        min_expiry_in_seconds: 3600,
        pricing: { sat: { per_char: 1, minCapacity: 10 } },
      }),

      nowSeconds: (): bigint => BigInt(Math.floor(Date.now() / 1000)),

      // Key difference from cooperative test: return recorded balance/signature
      // IMPORTANT: Return [number, string], NOT [bigint, string] - WASM uses as_f64()
      getBalanceAndSignatureForUnilateralExit: (chId: string): [number, string] | null => {
        if (chId !== channelId) return null;
        return [paymentBalance, balanceUpdate.signature];
      },

      getActiveKeysetIds: (mint: string, unit: string): string[] => {
        if (mint === mintUrl && unit === 'sat') return [keysetId];
        return [];
      },

      getKeysetInfo: (mint: string, ksId: string): string | null => {
        return keysetCache.get(`${mint}|${ksId}`) ?? null;
      },

      callMintSwap: async (mint: string, swapRequestJson: string): Promise<string> => {
        swapAttempts++;
        console.log(`  [TestHost] callMintSwap attempt #${swapAttempts}`);
        if (swapAttempts === 1) {
          console.log(`  [TestHost] Returning fake "Inactive Keyset" error`);
          return JSON.stringify({ error: "Inactive Keyset", code: 12002 });
        }
        console.log(`  [TestHost] Passing through to real mint`);
        const response = await fetch(`${mint}/v1/swap`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: swapRequestJson,
        });
        return await response.text();
      },

      refreshActiveKeysets: async (mint: string): Promise<void> => {
        console.log(`  [TestHost] refreshActiveKeysets called for ${mint}`);
        refreshWasCalled = true;
        const newKeysetInfo = await fetchKeysetInfo(mint, keysetId);
        keysetCache.set(`${mint}|${keysetId}`, JSON.stringify(newKeysetInfo));
      },

      markChannelClosed: (): void => {},
    };

    // 9. Create test bridge
    const testBridge = new WasmSpilmanBridge(testHost, charlie.secretHex);

    // 10. Execute UNILATERAL close - should retry on keyset error
    const resultJson = await testBridge.executeUnilateralClose(channelId);
    const result = JSON.parse(resultJson);

    // 11. Verify retry happened and succeeded
    console.log(`Unilateral retry test: swapAttempts=${swapAttempts}, refreshWasCalled=${refreshWasCalled}, success=${result.success}`);
    if (!result.success) {
      console.log(`  Error: ${result.error}`);
    }
    expect(swapAttempts).toBe(2);
    expect(refreshWasCalled).toBe(true);
    expect(result.success).toBe(true);
    expect(result.channel_id).toBe(channelId);
    // Verify receiver got payment (unilateral close - receiver keeps the signed balance)
    expect(result.receiver_sum).toBeGreaterThanOrEqual(paymentBalance);
  });
});
