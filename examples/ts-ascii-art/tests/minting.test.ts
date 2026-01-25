import { test, describe, expect } from './fixtures.js';
import { mintFundedChannel } from './helpers.js';

// Import WASM function for verification
import { verify_channel } from '../src/wasm/cdk_wasm.js';

describe.concurrent('Minting flow', () => {
  test('mints a funding token with deterministic outputs', async ({ server }) => {
    // Mint a funded channel using the helper
    const channel = await mintFundedChannel(server, 'sat', 100);

    console.log(`Channel ID: ${channel.channelId.substring(0, 16)}...`);
    console.log(`Alice pubkey: ${channel.alice.pubkeyHex.substring(0, 16)}...`);
    console.log(`Proofs: ${channel.proofs.length} proofs`);

    // Verify proof structure
    for (const proof of channel.proofs) {
      expect(proof.amount).toBeGreaterThan(0);
      expect(proof.secret).toBeDefined();
      expect(proof.C).toBeDefined();
      expect(proof.dleq).toBeDefined();
      expect(proof.dleq.e).toBeDefined();
      expect(proof.dleq.s).toBeDefined();
      expect(proof.dleq.r).toBeDefined();
    }

    // Calculate total
    const total = channel.proofs.reduce((sum: number, p: any) => sum + p.amount, 0);
    console.log(`Total minted: ${total} sat`);
    expect(total).toBeGreaterThanOrEqual(channel.capacity);

    // Verify the channel using verify_channel
    const verificationResultJson = verify_channel(
      channel.channelParamsJson,
      channel.sharedSecret,
      JSON.stringify(channel.proofs),
      JSON.stringify(channel.keysetInfo)
    );
    const verificationResult = JSON.parse(verificationResultJson);
    console.log(`Channel verification: valid=${verificationResult.valid}, errors=${verificationResult.errors.length}`);

    expect(verificationResult.valid).toBe(true);
    expect(verificationResult.errors).toHaveLength(0);
    console.log('Channel verified successfully');
  });
});

describe.concurrent('Channel verification', () => {
  test('detects tampered keyset keys (InvalidKeysetId)', async ({ server }) => {
    // Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);

    // Verify with correct keyset (should pass)
    const validResultJson = verify_channel(
      channel.channelParamsJson,
      channel.sharedSecret,
      JSON.stringify(channel.proofs),
      JSON.stringify(channel.keysetInfo)
    );
    const validResult = JSON.parse(validResultJson);
    expect(validResult.valid).toBe(true);
    console.log('Valid keyset verification passed');

    // Tamper with keyset - substitute a different valid pubkey
    const tamperedKeysetInfo = JSON.parse(JSON.stringify(channel.keysetInfo));
    const originalKey = tamperedKeysetInfo.keys["1"];
    // Use generator point G as a different valid pubkey
    const differentValidPubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    tamperedKeysetInfo.keys["1"] = differentValidPubkey;
    console.log(`Tampered key for amount 1: ${originalKey.substring(0, 16)}... -> ${differentValidPubkey.substring(0, 16)}...`);

    // Verify with tampered keyset (should fail)
    const tamperedResultJson = verify_channel(
      channel.channelParamsJson,
      channel.sharedSecret,
      JSON.stringify(channel.proofs),
      JSON.stringify(tamperedKeysetInfo)
    );
    const tamperedResult = JSON.parse(tamperedResultJson);
    console.log(`Tampered verification: valid=${tamperedResult.valid}, errors=${tamperedResult.errors.length}`);

    expect(tamperedResult.valid).toBe(false);
    expect(tamperedResult.errors.length).toBeGreaterThan(0);
    expect(tamperedResult.errors[0].type).toBe('InvalidKeysetId');
    console.log(`Tampered keyset detected (error: ${tamperedResult.errors[0].type})`);
  });

  test('detects tampered DLEQ proofs (InvalidDleq)', async ({ server }) => {
    // Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);

    // Verify with correct proofs (should pass)
    const validResultJson = verify_channel(
      channel.channelParamsJson,
      channel.sharedSecret,
      JSON.stringify(channel.proofs),
      JSON.stringify(channel.keysetInfo)
    );
    const validResult = JSON.parse(validResultJson);
    expect(validResult.valid).toBe(true);
    console.log('Valid DLEQ verification passed');

    // Tamper with DLEQ proof - change the 'e' value
    const tamperedProofs = JSON.parse(JSON.stringify(channel.proofs));
    const originalE = tamperedProofs[0].dleq.e;
    // Flip the last character
    tamperedProofs[0].dleq.e = originalE.slice(0, -1) + (originalE.slice(-1) === 'a' ? 'b' : 'a');
    console.log(`Tampered DLEQ e: ${originalE.substring(0, 16)}... -> ${tamperedProofs[0].dleq.e.substring(0, 16)}...`);

    // Verify with tampered DLEQ (should fail)
    const tamperedResultJson = verify_channel(
      channel.channelParamsJson,
      channel.sharedSecret,
      JSON.stringify(tamperedProofs),
      JSON.stringify(channel.keysetInfo)
    );
    const tamperedResult = JSON.parse(tamperedResultJson);
    console.log(`Tampered verification: valid=${tamperedResult.valid}, errors=${tamperedResult.errors.length}`);

    expect(tamperedResult.valid).toBe(false);
    expect(tamperedResult.errors.length).toBeGreaterThan(0);
    expect(tamperedResult.errors[0].type).toBe('InvalidDleq');
    console.log(`Tampered DLEQ detected (error: ${tamperedResult.errors[0].type})`);
  });

  test('collects multiple error types', async ({ server }) => {
    // Mint a funded channel
    const channel = await mintFundedChannel(server, 'sat', 100);

    // Create multiple tamperings
    const tamperedProofs = JSON.parse(JSON.stringify(channel.proofs));
    const tamperedKeysetInfo = JSON.parse(JSON.stringify(channel.keysetInfo));

    // Error 1: InvalidKeysetId - substitute a different valid pubkey for an unused amount
    const proofAmounts = new Set(tamperedProofs.map((p: any) => p.amount.toString()));
    const unusedAmount = Object.keys(tamperedKeysetInfo.keys).find(amt => !proofAmounts.has(amt));
    if (unusedAmount) {
      const differentValidPubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
      tamperedKeysetInfo.keys[unusedAmount] = differentValidPubkey;
      console.log(`Tampered unused key for amount ${unusedAmount} to trigger InvalidKeysetId`);
    }

    // Error 2: InvalidDleq on proof 0
    const originalE = tamperedProofs[0].dleq.e;
    tamperedProofs[0].dleq.e = originalE.slice(0, -1) + (originalE.slice(-1) === 'a' ? 'b' : 'a');
    console.log(`Tampered DLEQ e on proof 0`);

    // Error 3: Remove DLEQ from proof 1 (if exists)
    if (tamperedProofs.length > 1) {
      console.log(`Removing DLEQ from proof 1 (amount=${tamperedProofs[1].amount})`);
      delete tamperedProofs[1].dleq;
    }

    // Verify with multiple tamperings - should collect ALL errors
    const tamperedResultJson = verify_channel(
      channel.channelParamsJson,
      channel.sharedSecret,
      JSON.stringify(tamperedProofs),
      JSON.stringify(tamperedKeysetInfo)
    );
    const tamperedResult = JSON.parse(tamperedResultJson);
    console.log(`Tampered verification: valid=${tamperedResult.valid}, errors=${tamperedResult.errors.length}`);
    console.log(`Error types: ${tamperedResult.errors.map((e: any) => e.type).join(', ')}`);

    expect(tamperedResult.valid).toBe(false);

    // Check we got multiple error types
    const errorTypes = tamperedResult.errors.map((e: any) => e.type);
    expect(errorTypes).toContain('InvalidKeysetId');
    expect(errorTypes).toContain('InvalidDleq');

    // We should have at least 2 errors (keyset + DLEQ tampering)
    expect(tamperedResult.errors.length).toBeGreaterThanOrEqual(2);
    console.log(`Multiple errors collected (${tamperedResult.errors.length} total)`);
  });
});
