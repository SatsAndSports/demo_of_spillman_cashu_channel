import { randomBytes } from 'crypto';
import { test, describe, expect } from './fixtures.js';
import {
  mintFundedChannel,
  createPaymentHeader,
  fetchAsciiArt,
  fetchChannelStatus,
  closeChannel,
  generateKeypair,
  fetchKeysetInfo,
  getFirstKeysetId,
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

describe.concurrent('Unilateral closing', () => {
  test('server can unilaterally close channel with payments', async ({ server }) => {
    const channel = await mintFundedChannel(server, 'sat', 100);
    const message = 'Hello';
    const cost = message.length * server.getPricePerChar('sat');
    const paymentHeader = createPaymentHeader(channel, cost, true);
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
    const message = 'Hello'; // 5 chars
    const actualCost = message.length * server.getPricePerChar('sat');
    const overpayment = 20;

    const paymentHeader = createPaymentHeader(channel, overpayment, true);
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
    const cost = 5;
    const paymentHeader = createPaymentHeader(channel, cost, true);
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
    // Register channel by closing cooperatively with balance=0
    const channel = await mintFundedChannel(server, 'sat', 100);
    await closeChannel(server, channel, 0, true);

    // Channel is now closed - unilateral should return already_closed with earnedBeforeStage2Fees=0
    const response = await fetch(`${server.baseUrl}/channel/${channel.channelId}/unilateral-close`, { method: 'POST' });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.already_closed).toBe(true);
    expect(body.earnedBeforeStage2Fees).toBe(0);
  });

  test('cooperative close works after unilateral close', async ({ server }) => {
    const channel = await mintFundedChannel(server, 'sat', 100);
    const cost = 5;
    const paymentHeader = createPaymentHeader(channel, cost, true);
    await fetchAsciiArt(server, paymentHeader, 'Hello');

    await fetch(`${server.baseUrl}/channel/${channel.channelId}/unilateral-close`, { method: 'POST' });

    const { httpStatus, body } = await closeChannel(server, channel, cost, false);
    expect(httpStatus).toBe(200);
    expect(body.already_closed).toBe(true);
  });

  test('rejects payment after unilateral close', async ({ server }) => {
    const channel = await mintFundedChannel(server, 'sat', 100);
    const cost = 5;
    const paymentHeader1 = createPaymentHeader(channel, cost, true);
    await fetchAsciiArt(server, paymentHeader1, 'Hello');

    await fetch(`${server.baseUrl}/channel/${channel.channelId}/unilateral-close`, { method: 'POST' });

    const paymentHeader2 = createPaymentHeader(channel, cost + 1, false);
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
});
