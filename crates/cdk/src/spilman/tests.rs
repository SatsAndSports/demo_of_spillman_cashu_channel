//! Integration tests for Spilman payment channels
//!
//! These tests require a test mint and verify the full payment flow,
//! including funding token creation with blinded P2PK and refund paths.

use cdk_common::dhke::construct_proofs;
use cdk_common::nuts::{Conditions, CurrencyUnit, SigFlag, SpendingConditions};
use cdk_common::Amount;

use crate::nuts::SecretKey;
use crate::wallet::{MintConnector, ReceiveOptions, SendOptions, WalletBuilder};
use crate::test_helpers::mint::create_test_blinded_messages;
use crate::test_helpers::nut10::{unzip3, TestMintHelper};
use crate::util::unix_time;

use super::deterministic::{CommitmentOutputs, DeterministicOutputsForOneContext};
use super::keysets_and_amounts::KeysetInfo;
use super::params::ChannelParameters;

use async_trait::async_trait;
use cdk_sqlite::wallet::memory;
use rand::random;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use crate::nuts::{
    CheckStateRequest, CheckStateResponse, Id, KeySet, KeysetResponse, MeltQuoteBolt11Request,
    MeltQuoteBolt11Response, MeltQuoteBolt12Request, MeltQuoteCustomRequest,
    MeltQuoteCustomResponse, MeltRequest, MintInfo, MintQuoteBolt11Request,
    MintQuoteBolt11Response, MintQuoteBolt12Request, MintQuoteBolt12Response,
    MintQuoteCustomRequest, MintQuoteCustomResponse, MintRequest, MintResponse, PaymentMethod,
    RestoreRequest, RestoreResponse, SwapRequest, SwapResponse,
};
use crate::Mint;

/// Test: Spilman 2-of-2 spending with blinded keys
///
/// Verifies that the mint accepts signatures from blinded secret keys.
/// The funding token uses blinded pubkeys (Alice + Charlie for 2-of-2),
/// and we sign with the corresponding blinded secret keys.
///
/// This tests the full P2BK privacy feature:
/// - Funding token uses blinded pubkeys (Alice + Charlie for 2-of-2)
/// - Refund path uses a DIFFERENT blinded pubkey for Alice
/// - Mint accepts the blinded signatures
#[tokio::test]
async fn test_spilman_2of2_spending_with_blinded_keys() {
    let test_mint = TestMintHelper::new().await.unwrap();
    let mint = test_mint.mint();

    // Generate keypairs for Alice and Charlie
    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    println!("Alice pubkey: {}", sender_pubkey.to_hex());
    println!("Charlie pubkey: {}", receiver_pubkey.to_hex());
    println!("Current time: {}", unix_time());

    // Step 1: Get keyset info from the test mint
    let keyset_id = test_mint.active_sat_keyset_id;
    let keys = test_mint.public_keys_of_the_active_sat_keyset.clone();

    // Get input_fee_ppk from the mint (keysets() is synchronous)
    let keysets_response = mint.keysets();
    let keyset_info_response = keysets_response
        .keysets
        .iter()
        .find(|k| k.id == keyset_id)
        .expect("Should find keyset");
    let input_fee_ppk = keyset_info_response.input_fee_ppk;

    let keyset_info = KeysetInfo::new(
        keyset_id,
        test_mint.unit.clone(),
        keys.clone(),
        input_fee_ppk,
        test_mint.final_expiry,
    );
    println!("Keyset: {} (fee: {} ppk)", keyset_id, input_fee_ppk);

    // Step 2: Create channel parameters
    let capacity = 10u64;
    let future_expiry = unix_time() + 3600; // 1 hour in future

    // With real fees from the mint, compute the minimum funding_token_amount
    let funding_token_amount = ChannelParameters::get_minimum_funding_token_amount(
        capacity,
        &keyset_info,
        64,
    )
    .expect("Failed to compute funding token amount");

    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "http://localhost:3338".to_string(), // mint URL (not actually used for swap)
        CurrencyUnit::Sat,
        capacity,
        funding_token_amount,
        future_expiry,
        unix_time(),
        keyset_info.clone(),
        64, // max amount per output
        &alice_secret,
    )
    .expect("Failed to create channel params");

    println!("Channel ID: {}", params.get_channel_id());

    // Get blinded pubkeys for verification
    let blinded_alice = params
        .get_sender_blinded_pubkey_for_stage1()
        .expect("Failed to get sender blinded pubkey");
    let blinded_charlie = params
        .get_receiver_blinded_pubkey_for_stage1()
        .expect("Failed to get receiver blinded pubkey");
    let blinded_alice_refund = params
        .get_sender_blinded_pubkey_for_stage1_refund()
        .expect("Failed to get refund blinded pubkey");

    println!("Blinded Alice (2of2): {}", blinded_alice.to_hex());
    println!("Blinded Charlie (2of2): {}", blinded_charlie.to_hex());
    println!("Blinded Alice (refund): {}", blinded_alice_refund.to_hex());

    // Verify all blinded keys are different
    assert_ne!(blinded_alice.to_hex(), blinded_charlie.to_hex());
    assert_ne!(blinded_alice.to_hex(), blinded_alice_refund.to_hex());
    assert_ne!(blinded_charlie.to_hex(), blinded_alice_refund.to_hex());
    println!("✓ All blinded pubkeys are distinct");

    // Step 3: Create funding outputs
    let funding_amount = params
        .get_total_funding_token_amount()
        .expect("Failed to get funding amount");
    println!("Funding token amount: {} sats", funding_amount);

    let funding_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        funding_amount,
        params.clone(),
    )
    .expect("Failed to create funding outputs");

    // Get blinded messages for mint
    let blinded_messages = funding_outputs
        .get_blinded_messages(None)
        .expect("Failed to get blinded messages");
    println!(
        "Created {} blinded messages for funding",
        blinded_messages.len()
    );

    // Step 4: Mint regular proofs first, then swap for our P2PK proofs
    // The swap requires exact balance: input = output + fee.
    // We mint the funding amount directly, calculate the fee, and accept that
    // our outputs will be slightly less than requested due to fees.
    let input_proofs = test_mint
        .mint_proofs(Amount::from(funding_amount))
        .await
        .expect("Failed to mint input proofs");

    let num_input_proofs = input_proofs.len() as u64;
    let actual_fee = (input_fee_ppk * num_input_proofs).div_ceil(1000);
    let available_for_outputs = funding_amount - actual_fee;
    println!(
        "Input proofs: {} sats ({} proofs), fee: {} sats, available: {} sats",
        funding_amount, num_input_proofs, actual_fee, available_for_outputs
    );

    // Recreate funding outputs for the available amount (slightly less due to fees)
    let adjusted_funding_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        available_for_outputs,
        params.clone(),
    )
    .expect("Failed to create adjusted funding outputs");

    let adjusted_blinded_messages = adjusted_funding_outputs
        .get_blinded_messages(None)
        .expect("Failed to get adjusted blinded messages");

    // Swap for our P2PK funding proofs
    let swap_request =
        cdk_common::nuts::SwapRequest::new(input_proofs.clone(), adjusted_blinded_messages.clone());
    let swap_response = mint
        .process_swap_request(swap_request)
        .await
        .expect("Failed to swap for P2PK proofs");
    println!(
        "Swapped for {} P2PK funding proofs",
        swap_response.signatures.len()
    );

    // Step 5: Construct the P2PK proofs using the adjusted outputs' secrets
    let secrets_with_blinding = adjusted_funding_outputs
        .get_secrets_with_blinding()
        .expect("Failed to get secrets with blinding");

    let blinding_factors: Vec<SecretKey> = secrets_with_blinding
        .iter()
        .map(|s| s.blinding_factor.clone())
        .collect();
    let secrets: Vec<crate::secret::Secret> = secrets_with_blinding
        .iter()
        .map(|s| s.secret.clone())
        .collect();

    let p2pk_proofs = construct_proofs(
        swap_response.signatures.clone(),
        blinding_factors,
        secrets,
        &keys,
    )
    .expect("Failed to construct proofs");

    let proof_amounts: Vec<String> = p2pk_proofs.iter().map(|p| p.amount.to_string()).collect();
    println!(
        "Constructed {} P2PK proof(s) [{}]",
        p2pk_proofs.len(),
        proof_amounts.join("+")
    );

    // Step 6: Try to spend with 2-of-2 (both Alice and Charlie's blinded signatures)
    // Create outputs for where the funds will go.
    // The P2PK proofs have available_for_outputs sats, minus the fee for spending them.
    let spend_fee = (input_fee_ppk * p2pk_proofs.len() as u64).div_ceil(1000);
    let final_output_amount = available_for_outputs - spend_fee;
    let (new_outputs, _) = create_test_blinded_messages(mint, Amount::from(final_output_amount))
        .await
        .expect("Failed to create output messages");

    let mut swap_request_2of2 =
        cdk_common::nuts::SwapRequest::new(p2pk_proofs.clone(), new_outputs.clone());

    // Get blinded secret keys for signing
    let alice_blinded_secret = params
        .get_sender_blinded_secret_key_for_stage1(&alice_secret)
        .expect("Failed to get Alice's blinded secret");
    let charlie_blinded_secret = params
        .get_receiver_blinded_secret_key_for_stage1(&charlie_secret)
        .expect("Failed to get Charlie's blinded secret");

    // Sign with both blinded keys (2-of-2) using SIG_ALL
    // SIG_ALL requires signing the full message (inputs + outputs), not just each proof's secret
    swap_request_2of2
        .sign_sig_all(alice_blinded_secret.clone())
        .expect("Failed to sign with Alice's blinded key");
    swap_request_2of2
        .sign_sig_all(charlie_blinded_secret.clone())
        .expect("Failed to sign with Charlie's blinded key");

    let result = mint.process_swap_request(swap_request_2of2).await;
    assert!(
        result.is_ok(),
        "2-of-2 spending with blinded keys should succeed: {:?}",
        result.err()
    );
    println!("✓ 2-of-2 spending with blinded keys succeeded");
}

/// Test: Spilman refund path spending with blinded refund key
///
/// Verifies that after expiry, Alice can spend the funding token
/// with ONLY her refund blinded secret key (1-of-1 instead of 2-of-2).
///
/// This tests the refund path of the P2BK privacy feature:
/// - Funding token has expired expiry_timestamp
/// - Refund key is Alice's SEPARATE blinded pubkey (different tweak from 2-of-2)
/// - Mint accepts the single refund signature after expiry
#[tokio::test]
async fn test_spilman_refund_spending_with_blinded_key() {
    let test_mint = TestMintHelper::new().await.unwrap();
    let mint = test_mint.mint();

    // Generate keypairs for Alice and Charlie
    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    println!("Alice pubkey: {}", sender_pubkey.to_hex());
    println!("Charlie pubkey: {}", receiver_pubkey.to_hex());
    println!("Current time: {}", unix_time());

    // Step 1: Get keyset info from the test mint
    let keyset_id = test_mint.active_sat_keyset_id;
    let keys = test_mint.public_keys_of_the_active_sat_keyset.clone();

    let keysets_response = mint.keysets();
    let keyset_info_response = keysets_response
        .keysets
        .iter()
        .find(|k| k.id == keyset_id)
        .expect("Should find keyset");
    let input_fee_ppk = keyset_info_response.input_fee_ppk;

    let keyset_info = KeysetInfo::new(
        keyset_id,
        test_mint.unit.clone(),
        keys.clone(),
        input_fee_ppk,
        test_mint.final_expiry,
    );
    println!("Keyset: {} (fee: {} ppk)", keyset_id, input_fee_ppk);

    // Step 2: Create channel parameters with FUTURE expiry
    // (needed to derive blinded pubkeys correctly via ChannelParameters)
    let capacity = 10u64;
    let future_expiry = unix_time() + 3600; // 1 hour in future

    let funding_token_amount = ChannelParameters::get_minimum_funding_token_amount(
        capacity,
        &keyset_info,
        64,
    )
    .expect("Failed to compute funding token amount");

    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        capacity,
        funding_token_amount,
        future_expiry,
        unix_time(),
        keyset_info.clone(),
        64,
        &alice_secret,
    )
    .expect("Failed to create channel params");

    println!("Channel ID: {}", params.get_channel_id());

    // Step 3: Get blinded pubkeys from params
    let blinded_alice = params
        .get_sender_blinded_pubkey_for_stage1()
        .expect("Failed to get sender blinded pubkey");
    let blinded_charlie = params
        .get_receiver_blinded_pubkey_for_stage1()
        .expect("Failed to get receiver blinded pubkey");
    let blinded_alice_refund = params
        .get_sender_blinded_pubkey_for_stage1_refund()
        .expect("Failed to get refund blinded pubkey");

    println!("Blinded Alice (2of2): {}", blinded_alice.to_hex());
    println!("Blinded Charlie (2of2): {}", blinded_charlie.to_hex());
    println!("Blinded Alice (refund): {}", blinded_alice_refund.to_hex());

    // Verify refund key is different from 2-of-2 key
    assert_ne!(blinded_alice.to_hex(), blinded_alice_refund.to_hex());
    println!("✓ Refund blinded pubkey differs from 2-of-2 blinded pubkey");

    // Step 4: Create SpendingConditions manually with PAST expiry
    // We bypass Conditions::new() because it rejects past expiry timestamps
    let past_expiry = unix_time() - 3600; // 1 hour ago (expired)
    println!("Past expiry: {} (expired 1 hour ago)", past_expiry);

    let spending_conditions = SpendingConditions::new_p2pk(
        blinded_alice, // data field: Alice's blinded pubkey for 2-of-2
        Some(Conditions {
            locktime: Some(past_expiry),                     // Expired!
            pubkeys: Some(vec![blinded_charlie]),          // Charlie for 2-of-2
            refund_keys: Some(vec![blinded_alice_refund]), // Alice's REFUND blinded key
            num_sigs: Some(2),                             // 2-of-2 before expiry
            sig_flag: SigFlag::SigAll,                     // SIG_ALL
            num_sigs_refund: Some(1),                      // 1-of-1 for refund
        }),
    );
    println!("Created P2PK conditions with expired expiry and blinded refund key");

    // Step 5: Mint input proofs, then create P2PK outputs for available amount after fees
    let input_proofs = test_mint
        .mint_proofs(Amount::from(capacity))
        .await
        .expect("Failed to mint input proofs");

    let num_input_proofs = input_proofs.len() as u64;
    let actual_fee = (input_fee_ppk * num_input_proofs).div_ceil(1000);
    let available_for_outputs = capacity - actual_fee;
    println!(
        "Input proofs: {} sats ({} proofs), fee: {} sats, available: {} sats",
        capacity, num_input_proofs, actual_fee, available_for_outputs
    );

    // Create P2PK blinded messages for the available amount
    let output_amount = Amount::from(available_for_outputs);
    let split_amounts = test_mint.split_amount(output_amount).unwrap();
    let (p2pk_outputs, blinding_factors, secrets) = unzip3(
        split_amounts
            .iter()
            .map(|&amt| test_mint.create_blinded_message(amt, &spending_conditions))
            .collect(),
    );
    println!("Created {} P2PK blinded messages", p2pk_outputs.len());

    // Step 6: Swap for P2PK proofs
    let swap_request = cdk_common::nuts::SwapRequest::new(input_proofs.clone(), p2pk_outputs);
    let swap_response = mint
        .process_swap_request(swap_request)
        .await
        .expect("Failed to swap for P2PK proofs");
    println!(
        "Swapped for {} P2PK funding proofs",
        swap_response.signatures.len()
    );

    // Step 7: Construct the P2PK proofs
    let p2pk_proofs = construct_proofs(
        swap_response.signatures.clone(),
        blinding_factors,
        secrets,
        &keys,
    )
    .expect("Failed to construct proofs");

    let proof_amounts: Vec<String> = p2pk_proofs.iter().map(|p| p.amount.to_string()).collect();
    println!(
        "Constructed {} P2PK proof(s) [{}]",
        p2pk_proofs.len(),
        proof_amounts.join("+")
    );

    // Step 8: Spend with ONLY Alice's refund blinded key (expiry passed)
    // The P2PK proofs we got are worth `available_for_outputs` sats.
    // We need to account for fees again when spending them.
    let refund_fee = (input_fee_ppk * p2pk_proofs.len() as u64).div_ceil(1000);
    let refund_output_amount = available_for_outputs - refund_fee;
    let (new_outputs, _) = create_test_blinded_messages(mint, Amount::from(refund_output_amount))
        .await
        .expect("Failed to create output messages");

    let mut swap_request_refund =
        cdk_common::nuts::SwapRequest::new(p2pk_proofs.clone(), new_outputs);

    // Get Alice's refund blinded secret key
    let alice_refund_blinded_secret = params
        .get_sender_blinded_secret_key_for_stage1_refund(&alice_secret)
        .expect("Failed to get Alice's refund blinded secret");

    // Sign with ONLY the refund key (1-of-1 after expiry)
    swap_request_refund
        .sign_sig_all(alice_refund_blinded_secret)
        .expect("Failed to sign with Alice's refund blinded key");

    let result = mint.process_swap_request(swap_request_refund).await;
    assert!(
        result.is_ok(),
        "Refund spending with blinded key should succeed after expiry: {:?}",
        result.err()
    );
    println!("✓ Refund spending with Alice's blinded refund key succeeded");
}

/// Test: Stage2 blinded pubkeys differ from stage1 and raw pubkeys
///
/// Verifies that stage2 blinding context produces different keys from:
/// - Raw pubkeys (no blinding)
/// - Stage1 blinded pubkeys (different context)
/// - Each other (sender vs receiver)
#[test]
fn test_stage2_blinded_pubkeys_differ_from_stage1_and_raw() {
    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    // Create minimal keyset info for the test
    let mut keys = std::collections::BTreeMap::new();
    keys.insert(
        cdk_common::Amount::from(1u64),
        cdk_common::nuts::PublicKey::from_hex(
            "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104",
        )
        .unwrap(),
    );
    let keyset_keys = cdk_common::nuts::Keys::new(keys);
    let keyset_id = cdk_common::nuts::Id::v1_from_keys(&keyset_keys);
    let keyset_info = KeysetInfo::new(keyset_id, CurrencyUnit::Sat, keyset_keys, 0, None);

    // Create channel params (fees=0, so funding_token_amount == capacity)
    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        100, // capacity
        100, // funding_token_amount
        crate::util::unix_time() + 3600,
        crate::util::unix_time(),
        keyset_info,
        64,
        &alice_secret,
    )
    .expect("Failed to create params");

    // Get all the different pubkeys
    let alice_raw = sender_pubkey.to_hex();
    let charlie_raw = receiver_pubkey.to_hex();

    let alice_stage1 = params
        .get_sender_blinded_pubkey_for_stage1()
        .unwrap()
        .to_hex();
    let charlie_stage1 = params
        .get_receiver_blinded_pubkey_for_stage1()
        .unwrap()
        .to_hex();

    // Test per-proof stage2 pubkeys with a specific (amount, index)
    let alice_stage2_64_0 = params
        .get_sender_blinded_pubkey_for_stage2_output(64, 0)
        .unwrap()
        .to_hex();
    let charlie_stage2_64_0 = params
        .get_receiver_blinded_pubkey_for_stage2_output(64, 0)
        .unwrap()
        .to_hex();

    let alice_refund = params
        .get_sender_blinded_pubkey_for_stage1_refund()
        .unwrap()
        .to_hex();

    println!("Alice raw:         {}", alice_raw);
    println!("Alice stage1:      {}", alice_stage1);
    println!("Alice stage2(64,0):{}", alice_stage2_64_0);
    println!("Alice refund:      {}", alice_refund);
    println!("Charlie raw:       {}", charlie_raw);
    println!("Charlie stage1:    {}", charlie_stage1);
    println!("Charlie stage2(64,0):{}", charlie_stage2_64_0);

    // Verify stage2 keys differ from raw
    assert_ne!(
        alice_stage2_64_0, alice_raw,
        "Alice stage2 should differ from raw"
    );
    assert_ne!(
        charlie_stage2_64_0, charlie_raw,
        "Charlie stage2 should differ from raw"
    );

    // Verify stage2 keys differ from stage1
    assert_ne!(
        alice_stage2_64_0, alice_stage1,
        "Alice stage2 should differ from stage1"
    );
    assert_ne!(
        charlie_stage2_64_0, charlie_stage1,
        "Charlie stage2 should differ from stage1"
    );

    // Verify sender and receiver stage2 keys differ from each other
    assert_ne!(
        alice_stage2_64_0, charlie_stage2_64_0,
        "Alice and Charlie stage2 should differ"
    );

    // Verify stage2 keys differ from refund key
    assert_ne!(
        alice_stage2_64_0, alice_refund,
        "Alice stage2 should differ from refund"
    );

    // Verify per-proof uniqueness: different (amount, index) pairs produce different pubkeys
    let alice_stage2_64_1 = params
        .get_sender_blinded_pubkey_for_stage2_output(64, 1)
        .unwrap()
        .to_hex();
    let alice_stage2_32_0 = params
        .get_sender_blinded_pubkey_for_stage2_output(32, 0)
        .unwrap()
        .to_hex();

    assert_ne!(
        alice_stage2_64_0, alice_stage2_64_1,
        "Different index should produce different pubkey"
    );
    assert_ne!(
        alice_stage2_64_0, alice_stage2_32_0,
        "Different amount should produce different pubkey"
    );
    println!("✓ Per-proof stage2 pubkeys are unique for different (amount, index)");

    println!("✓ All stage2 blinded pubkeys are unique");
}

/// Test: Sender can derive secret keys for stage 2 outputs
///
/// After a channel closes, Alice receives "sender" proofs locked to her blinded pubkeys.
/// This test verifies that Alice can derive the correct blinded secret key for each
/// returned proof using `get_sender_blinded_secret_key_for_stage2_output()`.
///
/// The derived secret key's public key must match the pubkey locked in the P2PK secret.
/// This is essential for Alice to be able to spend her returned proofs.
///
/// Migrated from TypeScript test:
/// "closes unused channel and verifies sender can derive secret keys for returned proofs"
#[test]
fn test_sender_can_derive_secret_keys_for_stage2_outputs() {
    use std::collections::HashMap;

    // 1. Setup: Generate keypairs for Alice and Charlie
    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    println!("Alice pubkey: {}", sender_pubkey.to_hex());
    println!("Charlie pubkey: {}", receiver_pubkey.to_hex());

    // 2. Create minimal keyset info for the test
    // Generate valid public keys by deriving them from secret keys
    let mut keys = std::collections::BTreeMap::new();
    for amount in [1u64, 2, 4, 8, 16, 32, 64] {
        // Generate a deterministic but valid public key for each denomination
        let mint_secret = SecretKey::generate();
        keys.insert(cdk_common::Amount::from(amount), mint_secret.public_key());
    }

    let keyset_keys = cdk_common::nuts::Keys::new(keys);
    let keyset_id = cdk_common::nuts::Id::v1_from_keys(&keyset_keys);
    let keyset_info = KeysetInfo::new(keyset_id, CurrencyUnit::Sat, keyset_keys, 0, None);
    println!("Keyset ID: {}", keyset_id);

    // 3. Create channel parameters with a reasonable capacity (fees=0, so funding_token_amount == capacity)
    let capacity = 100u64;
    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        capacity,
        capacity, // funding_token_amount == capacity when fees are 0
        crate::util::unix_time() + 3600, // 1 hour in future
        crate::util::unix_time(),
        keyset_info,
        64, // max amount per output
        &alice_secret,
    )
    .expect("Failed to create channel params");

    println!("Channel ID: {}", params.get_channel_id());
    println!("Capacity: {} sats", capacity);

    // 4. Create sender outputs for the full capacity
    // This simulates what Alice receives when closing a channel with balance=0
    let sender_outputs = DeterministicOutputsForOneContext::new(
        "sender".to_string(),
        capacity,
        params.clone(),
    )
    .expect("Failed to create sender outputs");

    let secrets_with_blinding = sender_outputs
        .get_secrets_with_blinding()
        .expect("Failed to get secrets with blinding");

    println!(
        "Created {} sender outputs for {} sats",
        secrets_with_blinding.len(),
        capacity
    );

    // 5. Verify Alice can derive the secret key for each output
    // Track index per amount (outputs are sorted smallest-amount-first)
    let mut index_by_amount: HashMap<u64, usize> = HashMap::new();
    let mut verified_count = 0;

    for output in &secrets_with_blinding {
        let amount = output.amount;
        let index = *index_by_amount.get(&amount).unwrap_or(&0);
        index_by_amount.insert(amount, index + 1);

        // Get Alice's blinded secret key for this specific (amount, index)
        let blinded_secret = params
            .get_sender_blinded_secret_key_for_stage2_output(&alice_secret, amount, index)
            .expect("Failed to derive blinded secret key");

        // Derive the public key from the secret key
        let derived_pubkey = blinded_secret.public_key();

        // Parse the P2PK secret to extract the locked pubkey
        // Secret format: ["P2PK", {"nonce": "...", "data": "pubkey_hex", ...}]
        let secret_str = output.secret.to_string();
        let secret_json: serde_json::Value =
            serde_json::from_str(&secret_str).expect("Failed to parse secret JSON");

        assert!(
            secret_json.is_array(),
            "Secret should be a JSON array, got: {}",
            secret_str
        );
        assert_eq!(
            secret_json[0].as_str(),
            Some("P2PK"),
            "Secret should start with 'P2PK'"
        );

        let locked_pubkey_hex = secret_json[1]["data"]
            .as_str()
            .expect("Secret should have 'data' field with pubkey");

        // Verify the derived pubkey matches the locked pubkey
        assert_eq!(
            derived_pubkey.to_hex(),
            locked_pubkey_hex,
            "Derived pubkey should match locked pubkey for amount={} index={}",
            amount,
            index
        );

        verified_count += 1;
    }

    println!(
        "✓ Alice can derive secret keys for all {} sender outputs",
        verified_count
    );

    // 6. Also verify different amounts produce different keys (sanity check)
    // Get keys for two different amounts
    let key_64_0 = params
        .get_sender_blinded_secret_key_for_stage2_output(&alice_secret, 64, 0)
        .unwrap()
        .public_key()
        .to_hex();
    let key_32_0 = params
        .get_sender_blinded_secret_key_for_stage2_output(&alice_secret, 32, 0)
        .unwrap()
        .public_key()
        .to_hex();
    let key_64_1 = params
        .get_sender_blinded_secret_key_for_stage2_output(&alice_secret, 64, 1)
        .unwrap()
        .public_key()
        .to_hex();

    assert_ne!(
        key_64_0, key_32_0,
        "Different amounts should produce different keys"
    );
    assert_ne!(
        key_64_0, key_64_1,
        "Different indices should produce different keys"
    );
    println!("✓ Per-proof keys are unique for different (amount, index) pairs");
}

/// Test: Swap-to-funding flow
///
/// Verifies the full flow of creating channel funding from an existing token:
/// 1. Mint some proofs and wrap them in a token
/// 2. compute_channel_from_token() - parse token, compute capacity/change
/// 3. create_funding_swap() - create swap request with funding + change outputs
/// 4. Execute swap with mint
/// 5. complete_funding_swap() - unblind signatures with DLEQ verification
/// 6. Verify we got valid funding and change proofs
#[tokio::test]
async fn test_swap_to_funding() {
    use super::bindings::{
        complete_funding_swap, compute_channel_from_token, create_funding_swap,
        parse_keyset_info_from_json,
    };
    use cdk_common::nuts::{Proof, Token};

    let test_mint = TestMintHelper::new().await.unwrap();
    let mint = test_mint.mint();

    // Generate keypairs for Alice and Charlie
    let alice_secret = SecretKey::generate();
    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    println!("Alice pubkey: {}", alice_secret.public_key().to_hex());
    println!("Charlie pubkey: {}", receiver_pubkey.to_hex());

    // Step 1: Get keyset info from the test mint
    let keyset_id = test_mint.active_sat_keyset_id;
    let keys = test_mint.public_keys_of_the_active_sat_keyset.clone();

    let keysets_response = mint.keysets();
    let keyset_info_response = keysets_response
        .keysets
        .iter()
        .find(|k| k.id == keyset_id)
        .expect("Should find keyset");
    let input_fee_ppk = keyset_info_response.input_fee_ppk;

    // We use keyset_info_json (string) for bindings, so we don't need the struct here
    println!("Keyset: {} (fee: {} ppk)", keyset_id, input_fee_ppk);

    // Build keyset_info_json for the bindings functions
    let keyset_info_json = serde_json::json!({
        "keysetId": keyset_id.to_string(),
        "unit": "sat",
        "inputFeePpk": input_fee_ppk,
        "keys": keys.iter().map(|(amt, pk)| {
            (u64::from(*amt).to_string(), pk.to_hex())
        }).collect::<std::collections::HashMap<_, _>>()
    })
    .to_string();

    // Verify keyset_info_json parses correctly
    let parsed_info = parse_keyset_info_from_json(&keyset_info_json)
        .expect("Should parse keyset_info_json");
    assert_eq!(parsed_info.keyset_id, keyset_id);
    println!("✓ Keyset info JSON parses correctly");

    // Step 2: Mint some proofs as input (100 sats)
    let input_amount = Amount::from(100u64);
    let input_proofs = test_mint
        .mint_proofs(input_amount)
        .await
        .expect("Failed to mint input proofs");

    let input_value: u64 = input_proofs.iter().map(|p| u64::from(p.amount)).sum();
    println!("Minted {} sats in {} proofs", input_value, input_proofs.len());

    // Step 3: Create token from proofs
    let token = Token::new(
        "http://localhost:3338".parse().unwrap(),
        input_proofs.clone(),
        None,
        CurrencyUnit::Sat,
    );
    let token_string = token.to_string();
    println!("Token: {}...", &token_string[..50]);

    // Step 4: Call compute_channel_from_token
    let expiry_timestamp = unix_time() + 3600; // 1 hour in future
    let max_amount = 64u64;

    // Compute channel secret via the utility function (what the host would do)
    let channel_secret_hex = super::bindings::compute_channel_secret_from_hex(
        &alice_secret.to_secret_hex(),
        &receiver_pubkey.to_hex(),
    )
    .expect("compute_channel_secret_from_hex should succeed");

    let compute_result = compute_channel_from_token(
        &token_string,
        &receiver_pubkey.to_hex(),
        &alice_secret.public_key().to_hex(),
        &channel_secret_hex,
        expiry_timestamp,
        &keyset_info_json,
        max_amount,
    )
    .expect("compute_channel_from_token should succeed");

    let compute_json: serde_json::Value =
        serde_json::from_str(&compute_result).expect("Should parse compute result");

    let capacity = compute_json["capacity"].as_u64().expect("Should have capacity");
    let funding_token_amount = compute_json["funding_token_amount"]
        .as_u64()
        .expect("Should have funding_token_amount");
    let params_json = compute_json["params_json"]
        .as_str()
        .expect("Should have params_json");
    let proofs_json = compute_json["proofs_json"]
        .as_str()
        .expect("Should have proofs_json");

    println!("Input value: {} sats", input_value);
    println!("Capacity: {} sats", capacity);
    println!("Funding token amount: {} sats", funding_token_amount);

    // Verify the math makes sense
    assert!(capacity > 0, "Capacity should be positive");
    assert!(
        capacity <= input_value,
        "Capacity should not exceed input value"
    );
    assert!(
        funding_token_amount <= input_value,
        "Funding amount should not exceed input value"
    );
    println!("✓ compute_channel_from_token values are reasonable");

    // Step 5: Call create_funding_swap (now uses channel_secret_hex instead of alice_secret_hex)
    let swap_result = create_funding_swap(
        params_json,
        &channel_secret_hex,
        &keyset_info_json,
        proofs_json,
    )
    .expect("create_funding_swap should succeed");

    let swap_json: serde_json::Value =
        serde_json::from_str(&swap_result).expect("Should parse swap result");

    let swap_request_json = swap_json["swap_request_json"]
        .as_str()
        .expect("Should have swap_request_json");
    let funding_secrets_json = swap_json["funding_secrets_json"]
        .as_str()
        .expect("Should have funding_secrets_json");
    let funding_count = swap_json["funding_count"]
        .as_u64()
        .expect("Should have funding_count");

    println!("Created swap request with {} funding outputs", funding_count);
    println!("✓ create_funding_swap succeeded");

    // Step 6: Execute swap with mint
    let swap_request: cdk_common::nuts::SwapRequest =
        serde_json::from_str(swap_request_json).expect("Should parse swap request");

    let swap_response = mint
        .process_swap_request(swap_request)
        .await
        .expect("Mint swap should succeed");

    println!(
        "Mint returned {} signatures",
        swap_response.signatures.len()
    );

    // Verify DLEQ proofs are present
    for (i, sig) in swap_response.signatures.iter().enumerate() {
        assert!(
            sig.dleq.is_some(),
            "Signature {} should have DLEQ proof",
            i
        );
    }
    println!("✓ All signatures have DLEQ proofs");

    // Step 7: Call complete_funding_swap
    let swap_response_json =
        serde_json::to_string(&swap_response).expect("Should serialize swap response");

    let complete_result = complete_funding_swap(
        &swap_response_json,
        funding_secrets_json,
        &keyset_info_json,
    )
    .expect("complete_funding_swap should succeed");

    let complete_json: serde_json::Value =
        serde_json::from_str(&complete_result).expect("Should parse complete result");

    let funding_proofs_json = complete_json["funding_proofs_json"]
        .as_str()
        .expect("Should have funding_proofs_json");

    let funding_proofs: Vec<Proof> =
        serde_json::from_str(funding_proofs_json).expect("Should parse funding proofs");

    println!("Got {} funding proofs", funding_proofs.len());

    // Verify counts match
    assert_eq!(
        funding_proofs.len(),
        funding_count as usize,
        "Funding proof count should match"
    );

    // Verify funding proofs have expected total
    let funding_total: u64 = funding_proofs.iter().map(|p| u64::from(p.amount)).sum();
    assert_eq!(
        funding_total, funding_token_amount,
        "Funding proofs should sum to funding_token_amount"
    );

    // Verify all proofs have DLEQ
    for (i, proof) in funding_proofs.iter().enumerate() {
        assert!(
            proof.dleq.is_some(),
            "Funding proof {} should have DLEQ",
            i
        );
    }
    println!("✓ All proofs have DLEQ proofs (verified during unblinding)");

    println!(
        "✓ Swap-to-funding complete: {} sats → {} capacity",
        input_value, capacity
    );
}

/// Test: SpilmanClientBridge end-to-end
///
/// Creates a client bridge, opens a channel from a token, signs balance
/// updates, builds payment headers, and verifies them against the server bridge.
#[tokio::test(flavor = "multi_thread")]
async fn test_client_bridge() {
    use super::bridge::{BridgeError, ChannelFunding, ChannelState, PaymentProof, SpilmanBridge, SpilmanHost, SpilmanNetworking};
    use super::client_bridge::{base64_decode, SpilmanClientBridge, SpilmanClientHost};
    use cdk_common::nuts::{CurrencyUnit as CU, Id, PublicKey, Token};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    // ====================================================================
    // Test Client Host: wraps an in-process mint
    // ====================================================================

    struct TestClientHost {
        mint: Arc<crate::mint::Mint>,
        /// Channel storage: channel_id -> (channel_json, channel_secret_hex)
        channels: Mutex<HashMap<String, (String, String)>>,
        /// Key storage: pubkey_hex -> secret_hex (for sign_with_tweaked_key)
        keys: Mutex<HashMap<String, String>>,
    }

    impl TestClientHost {
        /// Register a keypair so the host can sign on behalf of this key.
        fn register_key(&self, secret_hex: &str, pubkey_hex: &str) {
            self.keys
                .lock()
                .unwrap()
                .insert(pubkey_hex.to_string(), secret_hex.to_string());
        }
    }

    impl SpilmanClientHost for TestClientHost {
        fn call_mint_swap(
            &self,
            _mint_url: &str,
            swap_request_json: &str,
        ) -> Result<String, String> {
            let swap_request: cdk_common::nuts::SwapRequest =
                serde_json::from_str(swap_request_json)
                    .map_err(|e| format!("Failed to parse swap request: {}", e))?;

            let mint = Arc::clone(&self.mint);
            let response = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async { mint.process_swap_request(swap_request).await })
            })
            .map_err(|e| format!("Mint swap failed: {}", e))?;

            serde_json::to_string(&response)
                .map_err(|e| format!("Failed to serialize swap response: {}", e))
        }

        fn save_channel(&self, channel_id: &str, channel_json: &str, channel_secret_hex: &str) {
            self.channels.lock().unwrap().insert(
                channel_id.to_string(),
                (channel_json.to_string(), channel_secret_hex.to_string()),
            );
        }

        fn get_channel(
            &self,
            channel_id: &str,
        ) -> Option<super::client_bridge::ChannelData> {
            let channels = self.channels.lock().unwrap();
            let (json, secret) = channels.get(channel_id)?;
            Some(super::client_bridge::ChannelData {
                channel_json: json.clone(),
                channel_secret_hex: secret.clone(),
            })
        }

        fn list_channel_ids(&self) -> Vec<String> {
            self.channels.lock().unwrap().keys().cloned().collect()
        }

        fn delete_channel(&self, channel_id: &str) {
            self.channels.lock().unwrap().remove(channel_id);
        }

        fn sign_with_tweaked_key(
            &self,
            signer_pubkey_hex: &str,
            message_hex: &str,
            tweak_scalar_hex: &str,
        ) -> Result<String, String> {
            let secret_hex = self
                .keys
                .lock()
                .unwrap()
                .get(signer_pubkey_hex)
                .cloned()
                .ok_or_else(|| {
                    format!("No key registered for pubkey: {}", signer_pubkey_hex)
                })?;
            super::bindings::sign_with_tweaked_key_util(
                &secret_hex,
                message_hex,
                tweak_scalar_hex,
            )
        }

        fn compute_channel_secret(
            &self,
            sender_pubkey_hex: &str,
            receiver_pubkey_hex: &str,
        ) -> Result<String, String> {
            let secret_hex = self
                .keys
                .lock()
                .unwrap()
                .get(sender_pubkey_hex)
                .cloned()
                .ok_or_else(|| {
                    format!(
                        "No key registered for pubkey: {}",
                        sender_pubkey_hex
                    )
                })?;
            super::bindings::compute_channel_secret_from_hex(
                &secret_hex,
                receiver_pubkey_hex,
            )
        }
    }

    // ====================================================================
    // Test Server Host: wraps an in-process mint + stores channels
    // ====================================================================

    struct TestServerHost {
        keyset_ids: Vec<Id>,
        keyset_infos: HashMap<Id, String>,
        funding_data: Mutex<HashMap<String, (String, String, String, String)>>,
        payments: Mutex<HashMap<String, PaymentProof>>, // channel_id -> payment proof
        charlie_secret_hex: String,
        amount_due: Arc<AtomicU64>,
    }

    impl SpilmanHost<String> for TestServerHost {
        fn receiver_key_is_acceptable(&self, _receiver_pubkey: &PublicKey) -> bool {
            true
        }
        fn mint_and_keyset_is_acceptable(&self, _mint: &str, _keyset_id: &Id) -> bool {
            true
        }
        fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
            self.funding_data
                .lock()
                .unwrap()
                .get(channel_id)
                .cloned()
                .map(|(params_json, funding_proofs_json, channel_secret_hex, keyset_info_json)| {
                    ChannelFunding { params_json, funding_proofs_json, channel_secret_hex, keyset_info_json }
                })
        }
        fn save_funding(
            &self,
            channel_id: &str,
            funding: ChannelFunding,
            _initial_payment: PaymentProof,
        ) {
            self.funding_data.lock().unwrap().insert(
                channel_id.to_string(),
                (
                    funding.params_json,
                    funding.funding_proofs_json,
                    funding.channel_secret_hex,
                    funding.keyset_info_json,
                ),
            );
        }
        fn get_amount_due(&self, _channel_id: &str, _context_json: Option<&String>) -> u64 {
            self.amount_due.load(Ordering::Relaxed)
        }
        fn record_payment(
            &self,
            channel_id: &str,
            payment: PaymentProof,
            _context_json: &String,
        ) {
            self.payments
                .lock()
                .unwrap()
                .insert(channel_id.to_string(), payment);
        }
        fn get_channel_state(&self, _channel_id: &str) -> ChannelState {
            ChannelState::Open
        }
        fn mark_channel_closing(
            &self,
            _channel_id: &str,
            _expiry_timestamp: u64,
            _payment: PaymentProof,
        ) -> Result<(), String> {
            Ok(())
        }
        fn get_closing_data(
            &self,
            _channel_id: &str,
        ) -> Option<super::bridge::ClosingData> {
            None
        }
        fn get_channel_policy(&self, _unit: &str) -> Option<super::bridge::ChannelPolicy> {
            Some(super::bridge::ChannelPolicy { min_expiry_in_seconds: 3600, min_capacity: 10, max_amount_per_output: None })
        }
        fn now_seconds(&self) -> u64 {
            crate::util::unix_time()
        }
        fn get_balance_and_signature_for_unilateral_exit(
            &self,
            channel_id: &str,
        ) -> Option<PaymentProof> {
            self.payments.lock().unwrap().get(channel_id).cloned()
        }
        fn get_active_keyset_ids(&self, _mint: &str, _unit: &CU) -> Vec<Id> {
            self.keyset_ids.clone()
        }
        fn get_keyset_info(&self, _mint: &str, keyset_id: &Id) -> Option<String> {
            self.keyset_infos.get(keyset_id).cloned()
        }
        fn mark_channel_closed(
            &self,
            _channel_id: &str,
            _expiry_timestamp: u64,
            _balance: u64,
            _receiver_proofs_json: &str,
            _sender_proofs_json: &str,
            _receiver_sum: u64,
            _sender_sum: u64,
        ) -> Result<(), String> {
            Ok(())
        }

        fn compute_channel_secret(
            &self,
            _receiver_pubkey_hex: &str,
            sender_pubkey_hex: &str,
        ) -> Result<String, String> {
            super::bindings::compute_channel_secret_from_hex(
                &self.charlie_secret_hex,
                sender_pubkey_hex,
            )
        }

        fn sign_with_tweaked_key(
            &self,
            _signer_pubkey_hex: &str,
            message_hex: &str,
            tweak_scalar_hex: &str,
        ) -> Result<String, String> {
            super::bindings::sign_with_tweaked_key_util(
                &self.charlie_secret_hex,
                message_hex,
                tweak_scalar_hex,
            )
        }
    }

    impl SpilmanNetworking for TestServerHost {
        fn call_mint_swap(
            &self,
            _mint_url: &str,
            _swap_request_json: &str,
        ) -> Result<String, String> {
            Err("not used in this test".to_string())
        }

        fn refresh_all_keysets(&self, _mint: &str) -> Result<(), String> {
            Ok(())
        }
    }

    // ====================================================================
    // Setup: create a shared mint instance used for both minting and swapping
    // ====================================================================

    // Generate Charlie (server) keypair
    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let shared_mint = Arc::new(
        crate::test_helpers::mint::create_test_mint()
            .await
            .unwrap(),
    );

    // Derive keyset info from the shared mint
    let active_keyset_id = shared_mint
        .get_active_keysets()
        .get(&CurrencyUnit::Sat)
        .cloned()
        .expect("Should have SAT keyset");
    let keyset_pubkeys = shared_mint
        .keyset_pubkeys(&active_keyset_id)
        .expect("Should get pubkeys");
    let keyset = keyset_pubkeys.keysets.first().expect("Should have keyset");
    let shared_keys = keyset.keys.clone();
    let shared_fee_ppk = shared_mint
        .keysets()
        .keysets
        .iter()
        .find(|k| k.id == active_keyset_id)
        .expect("Should find keyset")
        .input_fee_ppk;

    let keyset_info_json = serde_json::json!({
        "keysetId": active_keyset_id.to_string(),
        "unit": "sat",
        "inputFeePpk": shared_fee_ppk,
        "keys": shared_keys.iter().map(|(amt, pk)| {
            (u64::from(*amt).to_string(), pk.to_hex())
        }).collect::<HashMap<_, _>>()
    })
    .to_string();

    // Mint proofs from the shared mint
    let input_amount = Amount::from(100u64);
    let proofs = crate::test_helpers::mint::mint_test_proofs(&shared_mint, input_amount)
        .await
        .expect("Failed to mint proofs");
    let token = Token::new(
        "http://localhost:3338".parse().unwrap(),
        proofs,
        None,
        CurrencyUnit::Sat,
    );
    let token_string = token.to_string();

    // Generate Alice's keypair externally (the bridge never sees the secret)
    let alice_secret = SecretKey::generate();
    let sender_pubkey_hex = alice_secret.public_key().to_hex();

    let client_host = TestClientHost {
        mint: Arc::clone(&shared_mint),
        channels: Mutex::new(HashMap::new()),  // (channel_json, channel_secret_hex)
        keys: Mutex::new(HashMap::new()),
    };

    // Register Alice's key with the host so it can sign and compute ECDH
    client_host.register_key(
        &alice_secret.to_secret_hex(),
        &sender_pubkey_hex,
    );

    let client_bridge = SpilmanClientBridge::new(client_host);

    println!(
        "Client bridge created, sender_pubkey: {}",
        sender_pubkey_hex
    );

    // ====================================================================
    // Open channel from token
    // ====================================================================

    let expiry_timestamp = unix_time() + 7200; // 2 hours (well above the 1-hour min_expiry)
    let max_amount = 64u64;

    let open_result = client_bridge
        .open_channel_from_token(
            &token_string,
            &receiver_pubkey.to_hex(),
            &sender_pubkey_hex,
            expiry_timestamp,
            &keyset_info_json,
            max_amount,
        )
        .expect("open_channel_from_token should succeed");

    println!(
        "Channel opened: id={}, capacity={}, funding={}",
        open_result.channel_id, open_result.capacity, open_result.funding_token_amount
    );

    assert!(open_result.capacity > 0, "Capacity should be positive");
    assert!(
        open_result.capacity <= 100,
        "Capacity should not exceed input value"
    );
    println!("✓ open_channel_from_token succeeded");

    // Verify channel is stored
    let channels = client_bridge.list_channels();
    assert_eq!(channels.len(), 1, "Should have one channel");
    assert_eq!(channels[0], open_result.channel_id);

    let info = client_bridge
        .get_channel_info(&open_result.channel_id)
        .expect("Should get channel info");
    assert_eq!(info.capacity, open_result.capacity);
    println!("✓ Channel stored and retrievable");

    // ====================================================================
    // Sign balance updates
    // ====================================================================

    let update_json = client_bridge
        .sign_balance_update(&open_result.channel_id, 10)
        .expect("sign_balance_update should succeed");

    let update: serde_json::Value =
        serde_json::from_str(&update_json).expect("Should parse update");
    assert_eq!(
        update["channel_id"].as_str().unwrap(),
        open_result.channel_id
    );
    assert_eq!(update["amount"].as_u64().unwrap(), 10);
    assert!(
        update["signature"].as_str().is_some(),
        "Should have signature"
    );
    println!("✓ sign_balance_update returned valid JSON");

    // ====================================================================
    // Build payment header (with funding)
    // ====================================================================

    let header_with_funding = client_bridge
        .build_payment_header(&open_result.channel_id, 10, true)
        .expect("build_payment_header should succeed");

    // Decode and verify
    let decoded = base64_decode(&header_with_funding).expect("Should decode base64");
    let header_json: serde_json::Value =
        serde_json::from_str(&decoded).expect("Should parse header JSON");

    assert_eq!(
        header_json["channel_id"].as_str().unwrap(),
        open_result.channel_id
    );
    assert_eq!(header_json["balance"].as_u64().unwrap(), 10);
    assert!(header_json["signature"].as_str().is_some());
    assert!(header_json["params"].is_object(), "Should include params");
    assert!(
        header_json["funding_proofs"].is_array(),
        "Should include funding_proofs"
    );
    println!("✓ Payment header (with funding) is valid base64-encoded JSON");

    // ====================================================================
    // Build payment header (without funding)
    // ====================================================================

    let header_no_funding = client_bridge
        .build_payment_header(&open_result.channel_id, 20, false)
        .expect("build_payment_header should succeed");

    let decoded2 = base64_decode(&header_no_funding).expect("Should decode base64");
    let header_json2: serde_json::Value =
        serde_json::from_str(&decoded2).expect("Should parse header JSON");

    assert_eq!(header_json2["balance"].as_u64().unwrap(), 20);
    assert!(
        header_json2.get("params").is_none(),
        "Should NOT include params"
    );
    assert!(
        header_json2.get("funding_proofs").is_none(),
        "Should NOT include funding_proofs"
    );
    println!("✓ Payment header (without funding) omits params/proofs");

    // ====================================================================
    // Feed headers into server-side SpilmanBridge (end-to-end!)
    // ====================================================================

    let mut keyset_infos = HashMap::new();
    keyset_infos.insert(active_keyset_id, keyset_info_json.clone());

    let amount_due = Arc::new(AtomicU64::new(0));
    let server_host = TestServerHost {
        keyset_ids: vec![active_keyset_id],
        keyset_infos,
        funding_data: Mutex::new(HashMap::new()),
        payments: Mutex::new(HashMap::new()),
        charlie_secret_hex: charlie_secret.to_secret_hex(),
        amount_due: amount_due.clone(),
    };

    let server_bridge = SpilmanBridge::new(server_host);

    // First request: header with funding
    let payment_result = server_bridge
        .process_payment_via_base64_header(
            &header_with_funding,
            &serde_json::json!({"type": "test"}).to_string(),
        )
        .expect("Server should accept payment header with funding");

    assert_eq!(payment_result.channel_id, open_result.channel_id);
    assert_eq!(payment_result.balance, 10);
    assert_eq!(payment_result.capacity, open_result.capacity);
    println!(
        "✓ Server accepted first payment (balance={}, capacity={})",
        payment_result.balance, payment_result.capacity
    );

    // Second request: header without funding (server already knows channel)
    let payment_result2 = server_bridge
        .process_payment_via_base64_header(
            &header_no_funding,
            &serde_json::json!({"type": "test"}).to_string(),
        )
        .expect("Server should accept payment header without funding");

    assert_eq!(payment_result2.balance, 20);
    println!(
        "✓ Server accepted second payment (balance={})",
        payment_result2.balance
    );

    // ====================================================================
    // Amount due checks (no side effects)
    // ====================================================================

    amount_due.store(15, Ordering::Relaxed);

    let due = server_bridge
        .verify_payment_covers_amount_due_via_base64_header(
            &header_no_funding,
            &serde_json::json!({"type": "test"}).to_string(),
        )
        .expect("Should verify payment covers amount due");
    assert_eq!(due, 15);

    let ok = server_bridge
        .payment_covers_amount_due_via_base64_header(
            &header_no_funding,
            &serde_json::json!({"type": "test"}).to_string(),
        )
        .expect("Should return boolean for payment coverage");
    assert!(ok, "Expected payment to cover amount due");

    let ok = server_bridge
        .payment_covers_amount_due_via_base64_header(
            &header_with_funding,
            &serde_json::json!({"type": "test"}).to_string(),
        )
        .expect("Should return boolean for payment coverage");
    assert!(!ok, "Expected payment to be insufficient");

    let err = server_bridge
        .verify_payment_covers_amount_due_via_base64_header(
            &header_with_funding,
            &serde_json::json!({"type": "test"}).to_string(),
        )
        .unwrap_err();
    match err {
        BridgeError::InsufficientBalance { balance, amount_due } => {
            assert_eq!(balance, 10);
            assert_eq!(amount_due, 15);
        }
        other => panic!("Unexpected error: {:?}", other),
    }

    // ====================================================================
    // Remove channel
    // ====================================================================

    client_bridge.remove_channel(&open_result.channel_id);
    assert!(
        client_bridge
            .get_channel_info(&open_result.channel_id)
            .is_none(),
        "Channel should be removed"
    );
    assert_eq!(client_bridge.list_channels().len(), 0);
    println!("✓ Channel removed from storage");

    println!("✓ All client bridge tests passed!");
}

/// Test: Full automatic retry of cooperative close with a real mint
///
/// This exercises the complete `execute_close_for_closing_channel` retry path:
/// 1. The host lies about which keyset is active (reports the old, now-inactive one)
/// 2. The bridge builds a swap targeting the stale keyset
/// 3. The real mint rejects it (InactiveKeyset)
/// 4. The bridge calls `refresh_all_keysets` → host switches to the real active keyset
/// 5. The bridge rebuilds the swap targeting the new keyset
/// 6. The real mint accepts it
/// 7. DLEQ verification passes, `mark_channel_closed` is called with real proofs
///
/// This is the only test that exercises the full automatic retry end-to-end
/// with real mint rejection and real mint acceptance.
#[tokio::test(flavor = "multi_thread")]
async fn test_cooperative_close_full_retry_with_real_mint() {
    use super::bindings;
    use super::bridge::{ChannelFunding, ChannelPolicy, ChannelState, ClosingData, PaymentProof, SpilmanBridge, SpilmanHost, SpilmanNetworking};
    use crate::util::unix_time;
    use cdk_common::nuts::{CurrencyUnit as CU, Id, Keys, PublicKey};
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    // ====================================================================
    // RetryTestHost: a SpilmanHost that lies about keysets, calls real mint
    // ====================================================================

    struct RetryTestHost {
        /// The real in-process mint for swap calls
        mint: Arc<crate::mint::Mint>,
        /// Active keyset IDs -- starts with [stale], switches to [fresh] after refresh
        active_keyset_ids: RefCell<Vec<Id>>,
        /// The fresh keyset ID to switch to after refresh
        fresh_keyset_id: Id,
        /// All keyset infos (both stale and fresh, real keys from the mint)
        keyset_infos: HashMap<Id, String>,
        /// Channel funding data
        funding_data: Mutex<HashMap<String, (String, String, String, String)>>,
        /// Channel state (transitions Open → Closing → Closed)
        channel_state: RefCell<ChannelState>,
        /// Closing data (set by mark_channel_closing, read by get_closing_data)
        closing_data: RefCell<Option<ClosingData>>,
        /// Stored payment for unilateral close: (balance, signature)
        stored_payment: RefCell<Option<PaymentProof>>,
        /// Amount due (for cooperative close balance validation)
        amount_due: Cell<u64>,
        /// Charlie's secret key (hex) for signing
        charlie_secret_hex: String,
        /// Count of swap calls (for assertions)
        swap_call_count: Cell<u32>,
        /// Count of refresh calls (for assertions)
        refresh_count: Cell<u32>,
        /// Captured data from mark_channel_closed
        closed_data: RefCell<Option<(u64, u64, String, String)>>,
    }

    impl SpilmanHost<String> for RetryTestHost {
        fn receiver_key_is_acceptable(&self, _receiver_pubkey: &PublicKey) -> bool {
            true
        }
        fn mint_and_keyset_is_acceptable(&self, _mint: &str, _keyset_id: &Id) -> bool {
            true
        }
        fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
            self.funding_data
                .lock()
                .unwrap()
                .get(channel_id)
                .cloned()
                .map(|(params_json, funding_proofs_json, channel_secret_hex, keyset_info_json)| {
                    ChannelFunding { params_json, funding_proofs_json, channel_secret_hex, keyset_info_json }
                })
        }
        fn save_funding(
            &self,
            channel_id: &str,
            funding: ChannelFunding,
            _initial_payment: PaymentProof,
        ) {
            self.funding_data.lock().unwrap().insert(
                channel_id.to_string(),
                (
                    funding.params_json,
                    funding.funding_proofs_json,
                    funding.channel_secret_hex,
                    funding.keyset_info_json,
                ),
            );
        }
        fn get_amount_due(&self, _channel_id: &str, _context_json: Option<&String>) -> u64 {
            self.amount_due.get()
        }
        fn record_payment(
            &self,
            channel_id: &str,
            payment: PaymentProof,
            _context_json: &String,
        ) {
            *self.stored_payment.borrow_mut() = Some(payment);
            let _ = channel_id;
        }
        fn get_channel_state(&self, _channel_id: &str) -> ChannelState {
            self.channel_state.borrow().clone()
        }
        fn mark_channel_closing(
            &self,
            _channel_id: &str,
            expiry_timestamp: u64,
            payment: PaymentProof,
        ) -> Result<(), String> {
            *self.channel_state.borrow_mut() = ChannelState::Closing;
            *self.stored_payment.borrow_mut() = Some(payment.clone());
            *self.closing_data.borrow_mut() = Some(ClosingData {
                expiry_timestamp,
                balance: payment.balance,
                signature: payment.signature,
            });
            Ok(())
        }
        fn get_closing_data(
            &self,
            _channel_id: &str,
        ) -> Option<ClosingData> {
            self.closing_data.borrow().clone()
        }
        fn get_channel_policy(&self, _unit: &str) -> Option<ChannelPolicy> {
            Some(ChannelPolicy { min_expiry_in_seconds: 3600, min_capacity: 10, max_amount_per_output: None })
        }
        fn now_seconds(&self) -> u64 {
            unix_time()
        }
        fn get_balance_and_signature_for_unilateral_exit(
            &self,
            _channel_id: &str,
        ) -> Option<PaymentProof> {
            self.stored_payment.borrow().clone()
        }
        fn get_active_keyset_ids(&self, _mint: &str, _unit: &CU) -> Vec<Id> {
            self.active_keyset_ids.borrow().clone()
        }
        fn get_keyset_info(&self, _mint: &str, keyset_id: &Id) -> Option<String> {
            self.keyset_infos.get(keyset_id).cloned()
        }
        fn mark_channel_closed(
            &self,
            _channel_id: &str,
            _expiry_timestamp: u64,
            balance: u64,
            receiver_proofs_json: &str,
            sender_proofs_json: &str,
            receiver_sum: u64,
            sender_sum: u64,
        ) -> Result<(), String> {
            *self.channel_state.borrow_mut() = ChannelState::Closed;
            *self.closed_data.borrow_mut() = Some((
                balance,
                receiver_sum + sender_sum,
                receiver_proofs_json.to_string(),
                sender_proofs_json.to_string(),
            ));
            let _ = (receiver_sum, sender_sum);
            Ok(())
        }
        fn compute_channel_secret(
            &self,
            _receiver_pubkey_hex: &str,
            sender_pubkey_hex: &str,
        ) -> Result<String, String> {
            bindings::compute_channel_secret_from_hex(
                &self.charlie_secret_hex,
                sender_pubkey_hex,
            )
        }
        fn sign_with_tweaked_key(
            &self,
            _signer_pubkey_hex: &str,
            message_hex: &str,
            tweak_scalar_hex: &str,
        ) -> Result<String, String> {
            bindings::sign_with_tweaked_key_util(
                &self.charlie_secret_hex,
                message_hex,
                tweak_scalar_hex,
            )
        }
    }

    impl SpilmanNetworking for RetryTestHost {
        fn refresh_all_keysets(&self, _mint: &str) -> Result<(), String> {
            // Simulate discovering the new active keyset
            *self.active_keyset_ids.borrow_mut() = vec![self.fresh_keyset_id];
            self.refresh_count.set(self.refresh_count.get() + 1);
            Ok(())
        }

        fn call_mint_swap(
            &self,
            _mint_url: &str,
            swap_request_json: &str,
        ) -> Result<String, String> {
            self.swap_call_count.set(self.swap_call_count.get() + 1);

            let swap_request: cdk_common::nuts::SwapRequest =
                serde_json::from_str(swap_request_json)
                    .map_err(|e| format!("Failed to parse swap request: {}", e))?;

            let mint = Arc::clone(&self.mint);
            let response = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async { mint.process_swap_request(swap_request).await })
            })
            .map_err(|e| {
                // Format as JSON so the bridge can parse it (matches real mint error format)
                serde_json::json!({"detail": e.to_string(), "code": 0}).to_string()
            })?;

            serde_json::to_string(&response)
                .map_err(|e| format!("Failed to serialize swap response: {}", e))
        }
    }

    // ====================================================================
    // Helper: build keyset_info JSON from mint data for a given keyset ID
    // ====================================================================

    fn keyset_info_json_from_mint(
        mint: &crate::mint::Mint,
        keyset_id: Id,
    ) -> String {
        let pubkeys = mint.keyset_pubkeys(&keyset_id).expect("keyset pubkeys");
        let keyset = pubkeys.keysets.first().expect("keyset");
        let keys = &keyset.keys;
        let fee_ppk = mint
            .keysets()
            .keysets
            .iter()
            .find(|k| k.id == keyset_id)
            .expect("keyset info")
            .input_fee_ppk;

        serde_json::json!({
            "keysetId": keyset_id.to_string(),
            "unit": "sat",
            "inputFeePpk": fee_ppk,
            "keys": keys.iter().map(|(amt, pk)| {
                (u64::from(*amt).to_string(), pk.to_hex())
            }).collect::<HashMap<String, String>>()
        })
        .to_string()
    }

    // ====================================================================
    // Setup: create mint, mint funding proofs, rotate keyset
    // ====================================================================

    let shared_mint = Arc::new(
        crate::test_helpers::mint::create_test_mint()
            .await
            .unwrap(),
    );

    // Get keyset A (the original active keyset)
    let keyset_a_id = shared_mint
        .get_active_keysets()
        .get(&CurrencyUnit::Sat)
        .cloned()
        .expect("Should have SAT keyset");
    let keyset_a_info_json = keyset_info_json_from_mint(&shared_mint, keyset_a_id);
    let keyset_a_keys: Keys = {
        let pubkeys = shared_mint.keyset_pubkeys(&keyset_a_id).unwrap();
        pubkeys.keysets.first().unwrap().keys.clone()
    };
    let keyset_a_fee_ppk = shared_mint
        .keysets()
        .keysets
        .iter()
        .find(|k| k.id == keyset_a_id)
        .unwrap()
        .input_fee_ppk;

    println!("Keyset A (original): {} (fee: {} ppk)", keyset_a_id, keyset_a_fee_ppk);

    // Generate keypairs
    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    // Build channel parameters with keyset A.
    // We use a two-pass approach: first compute the ideal funding amount,
    // then mint proofs, calculate the fee, and rebuild params with the
    // post-fee funding_token_amount so everything is consistent.
    let keyset_info_a = super::keysets_and_amounts::KeysetInfo::new(
        keyset_a_id,
        CurrencyUnit::Sat,
        keyset_a_keys.clone(),
        keyset_a_fee_ppk,
        None,
    );
    let capacity = 10u64;
    let expiry_timestamp = unix_time() + 7200;

    // We need enough funding for the capacity to survive TWO rounds of fees:
    // the initial swap-to-P2BK fee, and later the close swap fee.
    // Use a generous input amount so fee deduction doesn't eat into capacity.
    let mint_amount = 100u64;
    let input_proofs = crate::test_helpers::mint::mint_test_proofs(
        &shared_mint, Amount::from(mint_amount),
    )
    .await
    .expect("Failed to mint proofs");

    let num_inputs = input_proofs.len() as u64;
    let actual_fee = (keyset_a_fee_ppk * num_inputs).div_ceil(1000);
    let actual_funding = mint_amount - actual_fee;
    assert!(actual_funding > 0, "Post-fee funding should be positive");

    println!("Minted: {}, fee: {}, actual funding: {}", mint_amount, actual_fee, actual_funding);

    // Build params with the actual post-fee funding amount
    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        capacity,
        actual_funding,
        expiry_timestamp,
        unix_time(),
        keyset_info_a.clone(),
        64,
        &alice_secret,
    )
    .expect("channel params");
    let channel_id = params.get_channel_id();
    let channel_secret = params.channel_secret;

    println!("Channel ID: {}", channel_id);
    println!("Capacity: {}, Funding: {}", capacity, actual_funding);

    // Create deterministic funding outputs and swap for P2BK proofs
    let adjusted_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        actual_funding,
        params.clone(),
    )
    .expect("funding outputs");

    let adjusted_messages = adjusted_outputs
        .get_blinded_messages(None)
        .expect("blinded messages");

    let swap_request =
        cdk_common::nuts::SwapRequest::new(input_proofs.clone(), adjusted_messages.clone());
    let swap_response = shared_mint
        .process_swap_request(swap_request)
        .await
        .expect("Initial funding swap should succeed");

    // Construct P2BK funding proofs
    let secrets_with_blinding = adjusted_outputs
        .get_secrets_with_blinding()
        .expect("secrets with blinding");
    let blinding_factors: Vec<SecretKey> = secrets_with_blinding
        .iter()
        .map(|s| s.blinding_factor.clone())
        .collect();
    let secrets: Vec<crate::secret::Secret> = secrets_with_blinding
        .iter()
        .map(|s| s.secret.clone())
        .collect();

    let funding_proofs = cdk_common::dhke::construct_proofs(
        swap_response.signatures,
        blinding_factors,
        secrets,
        &keyset_a_keys,
    )
    .expect("construct proofs");

    let funding_total: u64 = funding_proofs.iter().map(|p| u64::from(p.amount)).sum();
    assert_eq!(funding_total, actual_funding, "Funding proofs should match expected amount");
    println!("Funded channel with {} sats ({} proofs)", funding_total, funding_proofs.len());

    // ====================================================================
    // Rotate keyset at the mint: keyset A → inactive, keyset B → active
    // ====================================================================

    let keyset_b_info = shared_mint
        .rotate_keyset(
            CurrencyUnit::Sat,
            vec![1, 2, 4, 8, 16, 32, 64],
            keyset_a_fee_ppk, // Same fee structure
            false,
            None,
        )
        .await
        .expect("rotate keyset");
    let keyset_b_id = keyset_b_info.id;
    let keyset_b_info_json = keyset_info_json_from_mint(&shared_mint, keyset_b_id);

    // Verify keyset A is now inactive at the mint
    let keysets_after = shared_mint.keysets();
    let keyset_a_status = keysets_after.keysets.iter().find(|k| k.id == keyset_a_id).unwrap();
    let keyset_b_status = keysets_after.keysets.iter().find(|k| k.id == keyset_b_id).unwrap();
    assert!(!keyset_a_status.active, "Keyset A should be inactive after rotation");
    assert!(keyset_b_status.active, "Keyset B should be active after rotation");
    println!("Keyset B (rotated): {} -- A is now INACTIVE", keyset_b_id);

    // ====================================================================
    // Build the RetryTestHost (lies about keysets: reports A as active)
    // ====================================================================

    let params_json = params.get_channel_id_params_json();
    let funding_proofs_json = serde_json::to_string(&funding_proofs).unwrap();
    let channel_secret_hex = crate::util::hex::encode(channel_secret);
    let keyset_info_json_for_storage = keyset_a_info_json.clone();

    let mut keyset_infos = HashMap::new();
    keyset_infos.insert(keyset_a_id, keyset_a_info_json.clone());
    keyset_infos.insert(keyset_b_id, keyset_b_info_json.clone());

    let mut funding_data_map = HashMap::new();
    funding_data_map.insert(
        channel_id.clone(),
        (
            params_json.clone(),
            funding_proofs_json.clone(),
            channel_secret_hex.clone(),
            keyset_info_json_for_storage.clone(),
        ),
    );

    // Create signed balance update (Alice authorizes the close balance)
    let channel = super::EstablishedChannel::new(params.clone(), funding_proofs.clone())
        .expect("established channel");
    let sender = super::SpilmanChannelSender::new(alice_secret.clone(), channel);
    let balance = 5u64; // Charlie gets 5, Alice gets the rest
    let (balance_update, _) = sender.create_signed_balance_update(balance).unwrap();

    let host = RetryTestHost {
        mint: Arc::clone(&shared_mint),
        active_keyset_ids: RefCell::new(vec![keyset_a_id]), // LIE: report stale keyset A
        fresh_keyset_id: keyset_b_id,
        keyset_infos,
        funding_data: Mutex::new(funding_data_map),
        channel_state: RefCell::new(ChannelState::Open),
        closing_data: RefCell::new(None),
        stored_payment: RefCell::new(None),
        amount_due: Cell::new(balance),
        charlie_secret_hex: charlie_secret.to_secret_hex(),
        swap_call_count: Cell::new(0),
        refresh_count: Cell::new(0),
        closed_data: RefCell::new(None),
    };

    let bridge = SpilmanBridge::new(host);

    // ====================================================================
    // Execute cooperative close -- this should retry automatically
    // ====================================================================

    let payment_json = serde_json::json!({
        "channel_id": channel_id,
        "balance": balance,
        "signature": balance_update.signature.to_string(),
    })
    .to_string();

    println!("Executing cooperative close (expecting retry)...");
    let result = bridge.execute_cooperative_close(&payment_json, bridge.host());

    // ====================================================================
    // Assertions
    // ====================================================================

    let success = result.expect("Cooperative close should succeed after retry");

    println!("Close succeeded: total={}, receiver={}, sender={}",
        success.total_value, success.receiver_sum, success.sender_sum);

    // The swap was called twice: first attempt (rejected), retry (accepted)
    assert_eq!(
        bridge.host().swap_call_count.get(), 2,
        "Should have called mint swap exactly twice"
    );
    println!("✓ call_mint_swap called exactly 2 times");

    // refresh_all_keysets was called exactly once (between attempts)
    assert_eq!(
        bridge.host().refresh_count.get(), 1,
        "Should have called refresh_all_keysets exactly once"
    );
    println!("✓ refresh_all_keysets called exactly once");

    // Channel is now closed
    assert!(
        matches!(*bridge.host().channel_state.borrow(), ChannelState::Closed),
        "Channel should be in Closed state"
    );
    println!("✓ Channel state is Closed");

    // mark_channel_closed was called with real proofs
    let closed = bridge.host().closed_data.borrow();
    let (closed_balance, closed_total, ref receiver_proofs, ref sender_proofs) =
        closed.as_ref().expect("mark_channel_closed should have been called");
    assert_eq!(*closed_balance, balance, "Closed balance should match");
    assert!(*closed_total > 0, "Total proofs value should be positive");
    println!("✓ mark_channel_closed called with balance={}, total_proofs_value={}",
        closed_balance, closed_total);

    // Verify the proofs are parseable JSON arrays
    let receiver: Vec<serde_json::Value> = serde_json::from_str(receiver_proofs)
        .expect("receiver proofs should be valid JSON");
    let sender: Vec<serde_json::Value> = serde_json::from_str(sender_proofs)
        .expect("sender proofs should be valid JSON");
    assert!(!receiver.is_empty(), "Receiver should get proofs (balance > 0)");
    println!("✓ Receiver got {} proofs, sender got {} proofs", receiver.len(), sender.len());

    // Verify all receiver proofs have P2PK witness signatures
    for (i, proof) in receiver.iter().enumerate() {
        let witness = proof.get("witness");
        assert!(witness.is_some() && !witness.unwrap().is_null(),
            "Receiver proof {} should have P2PK witness signature", i);
    }
    println!("✓ All receiver proofs have P2PK witness signatures");

    // Verify the close returned sensible values
    assert_eq!(success.channel_id, channel_id);
    assert!(success.total_value > 0);
    assert!(success.receiver_sum > 0, "Receiver sum should be > 0 (balance={balance})");
    println!("✓ CloseSuccess: channel_id matches, total_value={}", success.total_value);

    println!("✓ Full cooperative close retry with real mint PASSED!");
}

/// Test: Full automatic retry of unilateral close with a real mint
///
/// Same as the cooperative close test, but exercises the unilateral (server-initiated)
/// close path. The server uses its stored highest payment to close the channel.
#[tokio::test(flavor = "multi_thread")]
async fn test_unilateral_close_full_retry_with_real_mint() {
    use super::bindings;
    use super::bridge::{ChannelFunding, ChannelPolicy, ChannelState, ClosingData, PaymentProof, SpilmanBridge, SpilmanHost, SpilmanNetworking};
    use crate::util::unix_time;
    use cdk_common::nuts::{CurrencyUnit as CU, Id, Keys, PublicKey};
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    // Reuse the same RetryTestHost struct (defined inline for test isolation)
    struct RetryTestHost {
        mint: Arc<crate::mint::Mint>,
        active_keyset_ids: RefCell<Vec<Id>>,
        fresh_keyset_id: Id,
        keyset_infos: HashMap<Id, String>,
        funding_data: Mutex<HashMap<String, (String, String, String, String)>>,
        channel_state: RefCell<ChannelState>,
        closing_data: RefCell<Option<ClosingData>>,
        stored_payment: RefCell<Option<PaymentProof>>,
        amount_due: Cell<u64>,
        charlie_secret_hex: String,
        swap_call_count: Cell<u32>,
        refresh_count: Cell<u32>,
        closed_data: RefCell<Option<(u64, u64, String, String)>>,
    }

    impl SpilmanHost<String> for RetryTestHost {
        fn receiver_key_is_acceptable(&self, _receiver_pubkey: &PublicKey) -> bool { true }
        fn mint_and_keyset_is_acceptable(&self, _mint: &str, _keyset_id: &Id) -> bool { true }
        fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
            self.funding_data
                .lock()
                .unwrap()
                .get(channel_id)
                .cloned()
                .map(|(params_json, funding_proofs_json, channel_secret_hex, keyset_info_json)| {
                    ChannelFunding { params_json, funding_proofs_json, channel_secret_hex, keyset_info_json }
                })
        }
        fn save_funding(&self, channel_id: &str, funding: ChannelFunding, _initial_payment: PaymentProof) {
            self.funding_data.lock().unwrap().insert(channel_id.to_string(),
                (funding.params_json, funding.funding_proofs_json,
                 funding.channel_secret_hex, funding.keyset_info_json));
        }
        fn get_amount_due(&self, _channel_id: &str, _context_json: Option<&String>) -> u64 {
            self.amount_due.get()
        }
        fn record_payment(&self, _channel_id: &str, payment: PaymentProof, _context_json: &String) {
            *self.stored_payment.borrow_mut() = Some(payment);
        }
        fn get_channel_state(&self, _channel_id: &str) -> ChannelState {
            self.channel_state.borrow().clone()
        }
        fn mark_channel_closing(&self, _channel_id: &str, expiry_timestamp: u64, payment: PaymentProof) -> Result<(), String> {
            *self.channel_state.borrow_mut() = ChannelState::Closing;
            *self.stored_payment.borrow_mut() = Some(payment.clone());
            *self.closing_data.borrow_mut() = Some(ClosingData { expiry_timestamp, balance: payment.balance, signature: payment.signature });
            Ok(())
        }
        fn get_closing_data(&self, _channel_id: &str) -> Option<ClosingData> {
            self.closing_data.borrow().clone()
        }
        fn get_channel_policy(&self, _unit: &str) -> Option<ChannelPolicy> {
            Some(ChannelPolicy { min_expiry_in_seconds: 3600, min_capacity: 10, max_amount_per_output: None })
        }
        fn now_seconds(&self) -> u64 { unix_time() }
        fn get_balance_and_signature_for_unilateral_exit(&self, _channel_id: &str) -> Option<PaymentProof> {
            self.stored_payment.borrow().clone()
        }
        fn get_active_keyset_ids(&self, _mint: &str, _unit: &CU) -> Vec<Id> {
            self.active_keyset_ids.borrow().clone()
        }
        fn get_keyset_info(&self, _mint: &str, keyset_id: &Id) -> Option<String> {
            self.keyset_infos.get(keyset_id).cloned()
        }
        fn mark_channel_closed(&self, _channel_id: &str, _expiry_timestamp: u64, balance: u64,
            receiver_proofs_json: &str, sender_proofs_json: &str,
            receiver_sum: u64, sender_sum: u64) -> Result<(), String> {
            *self.channel_state.borrow_mut() = ChannelState::Closed;
            *self.closed_data.borrow_mut() = Some((
                balance, receiver_sum + sender_sum,
                receiver_proofs_json.to_string(), sender_proofs_json.to_string(),
            ));
            Ok(())
        }
        fn compute_channel_secret(&self, _receiver_pubkey_hex: &str, sender_pubkey_hex: &str) -> Result<String, String> {
            bindings::compute_channel_secret_from_hex(&self.charlie_secret_hex, sender_pubkey_hex)
        }
        fn sign_with_tweaked_key(&self, _signer_pubkey_hex: &str, message_hex: &str, tweak_scalar_hex: &str) -> Result<String, String> {
            bindings::sign_with_tweaked_key_util(&self.charlie_secret_hex, message_hex, tweak_scalar_hex)
        }
    }

    impl SpilmanNetworking for RetryTestHost {
        fn refresh_all_keysets(&self, _mint: &str) -> Result<(), String> {
            *self.active_keyset_ids.borrow_mut() = vec![self.fresh_keyset_id];
            self.refresh_count.set(self.refresh_count.get() + 1);
            Ok(())
        }

        fn call_mint_swap(&self, _mint_url: &str, swap_request_json: &str) -> Result<String, String> {
            self.swap_call_count.set(self.swap_call_count.get() + 1);
            let swap_request: cdk_common::nuts::SwapRequest =
                serde_json::from_str(swap_request_json)
                    .map_err(|e| format!("Failed to parse swap request: {}", e))?;
            let mint = Arc::clone(&self.mint);
            let response = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async { mint.process_swap_request(swap_request).await })
            })
            .map_err(|e| serde_json::json!({"detail": e.to_string(), "code": 0}).to_string())?;
            serde_json::to_string(&response)
                .map_err(|e| format!("Failed to serialize swap response: {}", e))
        }
    }

    fn keyset_info_json_from_mint(mint: &crate::mint::Mint, keyset_id: Id) -> String {
        let pubkeys = mint.keyset_pubkeys(&keyset_id).expect("keyset pubkeys");
        let keyset = pubkeys.keysets.first().expect("keyset");
        let keys = &keyset.keys;
        let fee_ppk = mint.keysets().keysets.iter()
            .find(|k| k.id == keyset_id).expect("keyset info").input_fee_ppk;
        serde_json::json!({
            "keysetId": keyset_id.to_string(),
            "unit": "sat",
            "inputFeePpk": fee_ppk,
            "keys": keys.iter().map(|(amt, pk)| {
                (u64::from(*amt).to_string(), pk.to_hex())
            }).collect::<HashMap<String, String>>()
        }).to_string()
    }

    // ====================================================================
    // Setup (same as cooperative, but with stored payment for unilateral)
    // ====================================================================

    let shared_mint = Arc::new(
        crate::test_helpers::mint::create_test_mint().await.unwrap(),
    );

    let keyset_a_id = shared_mint.get_active_keysets()
        .get(&CurrencyUnit::Sat).cloned().expect("SAT keyset");
    let keyset_a_info_json = keyset_info_json_from_mint(&shared_mint, keyset_a_id);
    let keyset_a_keys: Keys = {
        let pubkeys = shared_mint.keyset_pubkeys(&keyset_a_id).unwrap();
        pubkeys.keysets.first().unwrap().keys.clone()
    };
    let keyset_a_fee_ppk = shared_mint.keysets().keysets.iter()
        .find(|k| k.id == keyset_a_id).unwrap().input_fee_ppk;

    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let keyset_info_a = super::keysets_and_amounts::KeysetInfo::new(
        keyset_a_id,
        CurrencyUnit::Sat,
        keyset_a_keys.clone(),
        keyset_a_fee_ppk,
        None,
    );
    let capacity = 10u64;
    let expiry_timestamp = unix_time() + 7200;
    let mint_amount = 100u64;

    let input_proofs = crate::test_helpers::mint::mint_test_proofs(
        &shared_mint, Amount::from(mint_amount),
    ).await.expect("mint proofs");

    let num_inputs = input_proofs.len() as u64;
    let actual_fee = (keyset_a_fee_ppk * num_inputs).div_ceil(1000);
    let actual_funding = mint_amount - actual_fee;

    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey, receiver_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat, capacity, actual_funding,
        expiry_timestamp, unix_time(),
        keyset_info_a.clone(), 64, &alice_secret,
    ).expect("channel params");
    let channel_id = params.get_channel_id();
    let channel_secret = params.channel_secret;

    let adjusted_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(), actual_funding, params.clone(),
    ).expect("adjusted funding outputs");
    let adjusted_messages = adjusted_outputs
        .get_blinded_messages(None).expect("blinded messages");

    let swap_request = cdk_common::nuts::SwapRequest::new(input_proofs, adjusted_messages);
    let swap_response = shared_mint.process_swap_request(swap_request).await
        .expect("funding swap");

    let secrets_with_blinding = adjusted_outputs.get_secrets_with_blinding().expect("secrets");
    let blinding_factors: Vec<SecretKey> = secrets_with_blinding.iter()
        .map(|s| s.blinding_factor.clone()).collect();
    let secrets: Vec<crate::secret::Secret> = secrets_with_blinding.iter()
        .map(|s| s.secret.clone()).collect();

    let funding_proofs = cdk_common::dhke::construct_proofs(
        swap_response.signatures, blinding_factors, secrets, &keyset_a_keys,
    ).expect("construct proofs");

    // Create signed balance update (this is what the server stores from payments)
    let channel = super::EstablishedChannel::new(params.clone(), funding_proofs.clone())
        .expect("established channel");
    let sender_obj = super::SpilmanChannelSender::new(alice_secret.clone(), channel);
    let balance = 5u64;
    let (balance_update, _) = sender_obj.create_signed_balance_update(balance).unwrap();

    // Rotate keyset: A → inactive, B → active
    let keyset_b_info = shared_mint
        .rotate_keyset(CurrencyUnit::Sat, vec![1, 2, 4, 8, 16, 32, 64], keyset_a_fee_ppk, false, None)
        .await.expect("rotate keyset");
    let keyset_b_id = keyset_b_info.id;
    let keyset_b_info_json = keyset_info_json_from_mint(&shared_mint, keyset_b_id);

    println!("Keyset A: {} (now inactive), Keyset B: {} (active)", keyset_a_id, keyset_b_id);

    // ====================================================================
    // Build host with stored payment (for unilateral close)
    // ====================================================================

    let mut keyset_infos = HashMap::new();
    keyset_infos.insert(keyset_a_id, keyset_a_info_json);
    keyset_infos.insert(keyset_b_id, keyset_b_info_json);

    let mut funding_data_map = HashMap::new();
    funding_data_map.insert(channel_id.clone(), (
        params.get_channel_id_params_json(),
        serde_json::to_string(&funding_proofs).unwrap(),
        crate::util::hex::encode(channel_secret),
        keyset_info_json_from_mint(&shared_mint, keyset_a_id),
    ));

    let host = RetryTestHost {
        mint: Arc::clone(&shared_mint),
        active_keyset_ids: RefCell::new(vec![keyset_a_id]), // LIE: report stale keyset
        fresh_keyset_id: keyset_b_id,
        keyset_infos,
        funding_data: Mutex::new(funding_data_map),
        channel_state: RefCell::new(ChannelState::Open),
        closing_data: RefCell::new(None),
        // Pre-populate stored payment (as if server recorded it during normal operation)
        stored_payment: RefCell::new(Some(PaymentProof { balance, signature: balance_update.signature.to_string() })),
        amount_due: Cell::new(balance),
        charlie_secret_hex: charlie_secret.to_secret_hex(),
        swap_call_count: Cell::new(0),
        refresh_count: Cell::new(0),
        closed_data: RefCell::new(None),
    };

    let bridge = SpilmanBridge::new(host);

    // ====================================================================
    // Execute unilateral close -- server-initiated, should retry
    // ====================================================================

    println!("Executing unilateral close (expecting retry)...");
    let result = bridge.execute_unilateral_close(&channel_id, bridge.host());

    // ====================================================================
    // Assertions
    // ====================================================================

    let success = result.expect("Unilateral close should succeed after retry");

    println!("Close succeeded: total={}, receiver={}, sender={}",
        success.total_value, success.receiver_sum, success.sender_sum);

    assert_eq!(bridge.host().swap_call_count.get(), 2,
        "Should have called mint swap exactly twice");
    println!("✓ call_mint_swap called exactly 2 times");

    assert_eq!(bridge.host().refresh_count.get(), 1,
        "Should have called refresh_all_keysets exactly once");
    println!("✓ refresh_all_keysets called exactly once");

    assert!(matches!(*bridge.host().channel_state.borrow(), ChannelState::Closed),
        "Channel should be in Closed state");
    println!("✓ Channel state is Closed");

    let closed = bridge.host().closed_data.borrow();
    let (closed_balance, closed_total, ref receiver_proofs, ref sender_proofs) =
        closed.as_ref().expect("mark_channel_closed should have been called");
    assert_eq!(*closed_balance, balance);
    assert!(*closed_total > 0);
    println!("✓ mark_channel_closed called with balance={}, total={}", closed_balance, closed_total);

    let receiver: Vec<serde_json::Value> = serde_json::from_str(receiver_proofs).unwrap();
    let sender: Vec<serde_json::Value> = serde_json::from_str(sender_proofs).unwrap();
    assert!(!receiver.is_empty(), "Receiver should get proofs");
    println!("✓ Receiver got {} proofs, sender got {} proofs", receiver.len(), sender.len());

    // Verify all receiver proofs have P2PK witness signatures
    for (i, proof) in receiver.iter().enumerate() {
        let witness = proof.get("witness");
        assert!(witness.is_some() && !witness.unwrap().is_null(),
            "Receiver proof {} should have P2PK witness signature", i);
    }
    println!("✓ All receiver proofs have P2PK witness signatures");

    assert_eq!(success.channel_id, channel_id);
    assert!(success.total_value > 0);
    assert!(success.receiver_sum > 0);
    println!("✓ CloseSuccess values are correct");

    println!("✓ Full unilateral close retry with real mint PASSED!");
}

#[tokio::test]
async fn test_stage2_receiver_can_sign_and_spend_with_wallet() {
    let test_mint = TestMintHelper::new().await.expect("create test mint");
    let mint = test_mint.mint().clone();

    // Generate keypairs for Alice and Charlie
    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    // Keyset info from mint
    let keyset_id = test_mint.active_sat_keyset_id;
    let keys = test_mint.public_keys_of_the_active_sat_keyset.clone();
    let keysets_response = mint.keysets();
    let keyset_info_response = keysets_response
        .keysets
        .iter()
        .find(|k| k.id == keyset_id)
        .expect("active keyset");
    let input_fee_ppk = keyset_info_response.input_fee_ppk;
    let keyset_info = KeysetInfo::new(
        keyset_id,
        test_mint.unit.clone(),
        keys.clone(),
        input_fee_ppk,
        test_mint.final_expiry,
    );

    // Mint regular proofs first, then compute post-fee funding amount
    let mint_amount = 100u64;
    let input_proofs = test_mint
        .mint_proofs(Amount::from(mint_amount))
        .await
        .expect("mint input proofs");

    let num_input_proofs = input_proofs.len() as u64;
    let actual_fee = (input_fee_ppk * num_input_proofs).div_ceil(1000);
    let actual_funding = mint_amount - actual_fee;

    // Channel parameters
    let capacity = 10u64;
    let balance = 5u64;
    let future_expiry = unix_time() + 3600;

    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        capacity,
        actual_funding,
        future_expiry,
        unix_time(),
        keyset_info.clone(),
        64,
        &alice_secret,
    )
    .expect("channel params");

    let funding_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        actual_funding,
        params.clone(),
    )
    .expect("funding outputs");
    let funding_blinded_messages = funding_outputs
        .get_blinded_messages(None)
        .expect("blinded messages");

    let swap_request = SwapRequest::new(input_proofs.clone(), funding_blinded_messages);
    let swap_response = mint
        .process_swap_request(swap_request)
        .await
        .expect("funding swap");

    let secrets_with_blinding = funding_outputs
        .get_secrets_with_blinding()
        .expect("secrets with blinding");
    let blinding_factors: Vec<SecretKey> = secrets_with_blinding
        .iter()
        .map(|s| s.blinding_factor.clone())
        .collect();
    let secrets: Vec<crate::secret::Secret> = secrets_with_blinding
        .iter()
        .map(|s| s.secret.clone())
        .collect();

    let funding_proofs = construct_proofs(
        swap_response.signatures,
        blinding_factors,
        secrets,
        &keys,
    )
    .expect("construct funding proofs");

    let funding_total: u64 = funding_proofs.iter().map(|p| u64::from(p.amount)).sum();
    assert_eq!(
        funding_total, actual_funding,
        "Funding proofs should match post-fee funding amount"
    );
    assert_eq!(
        funding_total,
        params
            .get_total_funding_token_amount()
            .expect("funding token amount"),
        "Funding proofs should match params funding amount"
    );

    // Create stage 2 outputs and close swap
    let commitment_outputs = CommitmentOutputs::for_balance(balance, &params)
        .expect("commitment outputs");
    let mut close_swap = commitment_outputs
        .create_swap_request(funding_proofs.clone(), None)
        .expect("close swap request");

    let alice_blinded_secret = params
        .get_sender_blinded_secret_key_for_stage1(&alice_secret)
        .expect("alice stage1 secret");
    let charlie_blinded_secret = params
        .get_receiver_blinded_secret_key_for_stage1(&charlie_secret)
        .expect("charlie stage1 secret");

    close_swap
        .sign_sig_all(alice_blinded_secret)
        .expect("sign sig_all with alice");
    close_swap
        .sign_sig_all(charlie_blinded_secret)
        .expect("sign sig_all with charlie");

    let close_response = mint
        .process_swap_request(close_swap)
        .await
        .expect("close swap response");

    let proofs_with_meta = commitment_outputs
        .unblind_all(close_response.signatures, &keys)
        .expect("unblind close outputs");

    let mut receiver_proofs = Vec::new();

    for proof_meta in proofs_with_meta.into_iter().filter(|p| p.is_receiver) {
        let signing_key = params
            .get_receiver_blinded_secret_key_for_stage2_output(
                &charlie_secret,
                proof_meta.amount,
                proof_meta.index,
            )
            .expect("stage2 signing key");
        let mut proof = proof_meta.proof;
        proof
            .sign_p2pk(signing_key)
            .expect("sign stage2 proof");
        receiver_proofs.push(proof);
    }

    assert!(!receiver_proofs.is_empty(), "Receiver should get stage2 proofs");

    let receiver_total: u64 = receiver_proofs
        .iter()
        .map(|p| u64::from(p.amount))
        .sum();
    assert!(receiver_total > 0, "Receiver proofs should have value");

    // Wallet receive: attach P2PK signatures and store proofs
    let connector = DirectMintConnection::new(mint.clone());
    let store = Arc::new(memory::empty().await.expect("wallet store"));
    let seed = random::<[u8; 64]>();
    let wallet = WalletBuilder::new()
        .mint_url("http://localhost:3338".parse().unwrap())
        .unit(CurrencyUnit::Sat)
        .localstore(store)
        .seed(seed)
        .client(connector)
        .build()
        .expect("wallet build");

    let received_amount = wallet
        .receive_proofs(
            receiver_proofs.clone(),
            ReceiveOptions::default(),
            None,
            None,
        )
        .await
        .expect("wallet receive");

    assert!(received_amount > Amount::ZERO, "Wallet should receive value");

    // Spend via wallet (online swap)
    let send_amount = Amount::from(1u64);
    assert!(received_amount >= send_amount, "Received amount too small");

    let prepared = wallet
        .prepare_send(send_amount, SendOptions::default())
        .await
        .expect("prepare send");
    let _token = prepared.confirm(None).await.expect("confirm send");
}

// ========================================================================
// Shared test infrastructure for overpayment/close balance tests
// ========================================================================

mod close_balance_tests {
    use super::*;
    use super::super::bindings;
    use super::super::bridge::{ChannelFunding, ChannelPolicy, ChannelState, ClosingData, PaymentProof, SpilmanBridge, SpilmanHost, SpilmanNetworking};
    use crate::util::unix_time;
    use cdk_common::nuts::{CurrencyUnit as CU, Id, Keys, PublicKey};
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// SpilmanHost mock where amount_due can differ from the latest payment balance.
    pub(super) struct OverpaymentTestHost {
        pub mint: Arc<crate::mint::Mint>,
        keyset_id: Id,
        keyset_infos: HashMap<Id, String>,
        funding_data: Mutex<HashMap<String, (String, String, String, String)>>,
        pub channel_state: RefCell<ChannelState>,
        closing_data: RefCell<Option<ClosingData>>,
        stored_payment: RefCell<Option<PaymentProof>>,
        amount_due: Cell<u64>,
        charlie_secret_hex: String,
        pub swap_call_count: Cell<u32>,
        pub closed_data: RefCell<Option<(u64, u64, String, String)>>,
    }

    impl SpilmanHost<String> for OverpaymentTestHost {
        fn receiver_key_is_acceptable(&self, _receiver_pubkey: &PublicKey) -> bool { true }
        fn mint_and_keyset_is_acceptable(&self, _mint: &str, _keyset_id: &Id) -> bool { true }
        fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
            self.funding_data.lock().unwrap().get(channel_id).cloned()
                .map(|(params_json, funding_proofs_json, channel_secret_hex, keyset_info_json)| {
                    ChannelFunding { params_json, funding_proofs_json, channel_secret_hex, keyset_info_json }
                })
        }
        fn save_funding(&self, channel_id: &str, funding: ChannelFunding, _initial_payment: PaymentProof) {
            self.funding_data.lock().unwrap().insert(
                channel_id.to_string(),
                (funding.params_json, funding.funding_proofs_json, funding.channel_secret_hex, funding.keyset_info_json),
            );
        }
        fn get_amount_due(&self, _channel_id: &str, _context_json: Option<&String>) -> u64 {
            self.amount_due.get()
        }
        fn record_payment(&self, _channel_id: &str, payment: PaymentProof, _context_json: &String) {
            *self.stored_payment.borrow_mut() = Some(payment);
        }
        fn get_channel_state(&self, _channel_id: &str) -> ChannelState {
            self.channel_state.borrow().clone()
        }
        fn mark_channel_closing(&self, _channel_id: &str, expiry_timestamp: u64, payment: PaymentProof) -> Result<(), String> {
            *self.channel_state.borrow_mut() = ChannelState::Closing;
            *self.stored_payment.borrow_mut() = Some(payment.clone());
            *self.closing_data.borrow_mut() = Some(ClosingData {
                expiry_timestamp, balance: payment.balance, signature: payment.signature,
            });
            Ok(())
        }
        fn get_closing_data(&self, _channel_id: &str) -> Option<ClosingData> {
            self.closing_data.borrow().clone()
        }
        fn get_channel_policy(&self, _unit: &str) -> Option<ChannelPolicy> {
            Some(ChannelPolicy { min_expiry_in_seconds: 3600, min_capacity: 10, max_amount_per_output: None })
        }
        fn now_seconds(&self) -> u64 { unix_time() }
        fn get_balance_and_signature_for_unilateral_exit(&self, _channel_id: &str) -> Option<PaymentProof> {
            self.stored_payment.borrow().clone()
        }
        fn get_active_keyset_ids(&self, _mint: &str, _unit: &CU) -> Vec<Id> {
            vec![self.keyset_id]
        }
        fn get_keyset_info(&self, _mint: &str, keyset_id: &Id) -> Option<String> {
            self.keyset_infos.get(keyset_id).cloned()
        }
        fn mark_channel_closed(&self, _channel_id: &str, _expiry_timestamp: u64, balance: u64, receiver_proofs_json: &str, sender_proofs_json: &str, receiver_sum: u64, sender_sum: u64) -> Result<(), String> {
            *self.channel_state.borrow_mut() = ChannelState::Closed;
            *self.closed_data.borrow_mut() = Some((balance, receiver_sum + sender_sum, receiver_proofs_json.to_string(), sender_proofs_json.to_string()));
            Ok(())
        }
        fn compute_channel_secret(&self, _receiver_pubkey_hex: &str, sender_pubkey_hex: &str) -> Result<String, String> {
            bindings::compute_channel_secret_from_hex(&self.charlie_secret_hex, sender_pubkey_hex)
        }
        fn sign_with_tweaked_key(&self, _signer_pubkey_hex: &str, message_hex: &str, tweak_scalar_hex: &str) -> Result<String, String> {
            bindings::sign_with_tweaked_key_util(&self.charlie_secret_hex, message_hex, tweak_scalar_hex)
        }
    }

    impl SpilmanNetworking for OverpaymentTestHost {
        fn refresh_all_keysets(&self, _mint: &str) -> Result<(), String> { Ok(()) }
        fn call_mint_swap(&self, _mint_url: &str, swap_request_json: &str) -> Result<String, String> {
            self.swap_call_count.set(self.swap_call_count.get() + 1);
            let swap_request: cdk_common::nuts::SwapRequest = serde_json::from_str(swap_request_json)
                .map_err(|e| format!("Failed to parse swap request: {}", e))?;
            let mint = Arc::clone(&self.mint);
            let response = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async { mint.process_swap_request(swap_request).await })
            })
            .map_err(|e| serde_json::json!({"detail": e.to_string(), "code": 0}).to_string())?;
            serde_json::to_string(&response)
                .map_err(|e| format!("Failed to serialize swap response: {}", e))
        }
    }

    fn keyset_info_json_from_mint(mint: &crate::mint::Mint, keyset_id: Id) -> String {
        let pubkeys = mint.keyset_pubkeys(&keyset_id).expect("keyset pubkeys");
        let keyset = pubkeys.keysets.first().expect("keyset");
        let keys = &keyset.keys;
        let fee_ppk = mint.keysets().keysets.iter().find(|k| k.id == keyset_id).expect("keyset info").input_fee_ppk;
        serde_json::json!({
            "keysetId": keyset_id.to_string(),
            "unit": "sat",
            "inputFeePpk": fee_ppk,
            "keys": keys.iter().map(|(amt, pk)| (u64::from(*amt).to_string(), pk.to_hex())).collect::<HashMap<String, String>>()
        }).to_string()
    }

    /// Everything needed by the cooperative and unilateral close tests.
    pub(super) struct OverpaymentScenario {
        pub bridge: SpilmanBridge<OverpaymentTestHost, String>,
        pub shared_mint: Arc<crate::mint::Mint>,
        pub channel_id: String,
        pub overpayment_balance: u64,
        pub amount_due: u64,
        pub close_signature: String,  // signature for amount_due (used by cooperative close)
    }

    /// Set up a channel where the latest payment (50) exceeds the amount_due (10).
    pub(super) async fn setup_overpayment_scenario() -> OverpaymentScenario {
        let shared_mint = Arc::new(crate::test_helpers::mint::create_test_mint().await.unwrap());

        let keyset_id = shared_mint.get_active_keysets().get(&CurrencyUnit::Sat).cloned().expect("SAT keyset");
        let keyset_info_json = keyset_info_json_from_mint(&shared_mint, keyset_id);
        let keyset_keys: Keys = {
            let pubkeys = shared_mint.keyset_pubkeys(&keyset_id).unwrap();
            pubkeys.keysets.first().unwrap().keys.clone()
        };
        let fee_ppk = shared_mint.keysets().keysets.iter().find(|k| k.id == keyset_id).unwrap().input_fee_ppk;

        let alice_secret = SecretKey::generate();
        let sender_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let receiver_pubkey = charlie_secret.public_key();

        let mint_amount = 200u64;
        let input_proofs = crate::test_helpers::mint::mint_test_proofs(&shared_mint, Amount::from(mint_amount)).await.expect("mint proofs");
        let num_inputs = input_proofs.len() as u64;
        let actual_fee = (fee_ppk * num_inputs).div_ceil(1000);
        let actual_funding = mint_amount - actual_fee;

        let capacity = 100u64;
        let expiry_timestamp = unix_time() + 7200;
        let keyset_info = super::KeysetInfo::new(keyset_id, CurrencyUnit::Sat, keyset_keys.clone(), fee_ppk, None);

        let params = ChannelParameters::new_with_secret_key(
            sender_pubkey, receiver_pubkey,
            "http://localhost:3338".to_string(), CurrencyUnit::Sat,
            capacity, actual_funding, expiry_timestamp, unix_time(),
            keyset_info.clone(), 64, &alice_secret,
        ).expect("channel params");
        let channel_id = params.get_channel_id();
        let channel_secret = params.channel_secret;

        println!("Channel: capacity={}, funding={}", capacity, actual_funding);

        let funding_outputs = DeterministicOutputsForOneContext::new("funding".to_string(), actual_funding, params.clone()).expect("funding outputs");
        let funding_messages = funding_outputs.get_blinded_messages(None).expect("blinded messages");
        let swap_request = cdk_common::nuts::SwapRequest::new(input_proofs.clone(), funding_messages);
        let swap_response = shared_mint.process_swap_request(swap_request).await.expect("funding swap");

        let swb = funding_outputs.get_secrets_with_blinding().expect("secrets");
        let blinding_factors: Vec<SecretKey> = swb.iter().map(|s| s.blinding_factor.clone()).collect();
        let secrets: Vec<crate::secret::Secret> = swb.iter().map(|s| s.secret.clone()).collect();
        let funding_proofs = cdk_common::dhke::construct_proofs(swap_response.signatures, blinding_factors, secrets, &keyset_keys).expect("construct proofs");

        let channel = super::super::EstablishedChannel::new(params.clone(), funding_proofs.clone()).expect("established channel");
        let sender = super::super::SpilmanChannelSender::new(alice_secret.clone(), channel);

        let overpayment_balance = 50u64;
        let (overpay_update, _) = sender.create_signed_balance_update(overpayment_balance).unwrap();

        let amount_due = 10u64;
        let (close_update, _) = sender.create_signed_balance_update(amount_due).unwrap();

        println!("Overpayment balance: {}, amount_due: {}", overpayment_balance, amount_due);

        let params_json = params.get_channel_id_params_json();
        let funding_proofs_json = serde_json::to_string(&funding_proofs).unwrap();
        let channel_secret_hex = crate::util::hex::encode(channel_secret);

        let mut keyset_infos = HashMap::new();
        keyset_infos.insert(keyset_id, keyset_info_json.clone());

        let mut funding_data_map = HashMap::new();
        funding_data_map.insert(channel_id.clone(), (
            params_json.clone(), funding_proofs_json.clone(),
            channel_secret_hex.clone(), keyset_info_json.clone(),
        ));

        let host = OverpaymentTestHost {
            mint: Arc::clone(&shared_mint),
            keyset_id,
            keyset_infos,
            funding_data: Mutex::new(funding_data_map),
            channel_state: RefCell::new(ChannelState::Open),
            closing_data: RefCell::new(None),
            stored_payment: RefCell::new(Some(PaymentProof {
                balance: overpayment_balance,
                signature: overpay_update.signature.to_string(),
            })),
            amount_due: Cell::new(amount_due),
            charlie_secret_hex: charlie_secret.to_secret_hex(),
            swap_call_count: Cell::new(0),
            closed_data: RefCell::new(None),
        };

        let bridge = SpilmanBridge::new(host);

        OverpaymentScenario {
            bridge,
            shared_mint,
            channel_id,
            overpayment_balance,
            amount_due,
            close_signature: close_update.signature.to_string(),
        }
    }

    /// Verify receiver proofs have P2PK witnesses and are spendable via wallet.receive_proofs().
    pub(super) async fn verify_receiver_proofs_spendable(
        receiver_proofs_json: &str,
        shared_mint: &Arc<crate::mint::Mint>,
    ) -> Amount {
        // Verify all receiver proofs have P2PK witness signatures
        let receiver_proofs: Vec<serde_json::Value> = serde_json::from_str(receiver_proofs_json)
            .expect("receiver proofs should be valid JSON");
        assert!(!receiver_proofs.is_empty(), "Receiver should get proofs");
        for (i, proof) in receiver_proofs.iter().enumerate() {
            let witness = proof.get("witness");
            assert!(witness.is_some() && !witness.unwrap().is_null(),
                "Receiver proof {} should have P2PK witness signature", i);
        }
        println!("✓ All {} receiver proofs have P2PK witness signatures", receiver_proofs.len());

        // Verify receiver proofs are spendable via wallet.receive_proofs()
        let typed_receiver_proofs: Vec<cdk_common::nuts::Proof> = serde_json::from_str(receiver_proofs_json)
            .expect("parse receiver proofs as typed");

        let connector = super::DirectMintConnection::new((**shared_mint).clone());
        let store = Arc::new(memory::empty().await.expect("wallet store"));
        let seed = random::<[u8; 64]>();
        let wallet = WalletBuilder::new()
            .mint_url("http://localhost:3338".parse().unwrap())
            .unit(CurrencyUnit::Sat)
            .localstore(store)
            .seed(seed)
            .client(connector)
            .build()
            .expect("wallet build");

        let received_amount = wallet
            .receive_proofs(typed_receiver_proofs, ReceiveOptions::default(), None, None)
            .await
            .expect("wallet should accept signed receiver proofs");
        assert!(received_amount > Amount::ZERO, "Wallet should receive value from signed proofs");
        println!("✓ Wallet received {} sats from signed receiver proofs", u64::from(received_amount));
        received_amount
    }
}

/// Test: Cooperative close with overpayment — verifies the Closing→Closed transition
/// uses the amount_due (from closing_data), not the latest payment balance.
#[tokio::test(flavor = "multi_thread")]
async fn test_cooperative_close_with_overpayment() {
    use super::bridge::ChannelState;

    let s = close_balance_tests::setup_overpayment_scenario().await;

    let payment_json = serde_json::json!({
        "channel_id": s.channel_id,
        "balance": s.amount_due,
        "signature": s.close_signature,
    }).to_string();

    println!("Executing cooperative close with balance={} (overpayment was {})...", s.amount_due, s.overpayment_balance);
    let result = s.bridge.execute_cooperative_close(&payment_json, s.bridge.host());

    let success = result.expect("Cooperative close should succeed");
    println!("Close succeeded: total={}, receiver={}, sender={}", success.total_value, success.receiver_sum, success.sender_sum);

    assert_eq!(s.bridge.host().swap_call_count.get(), 1, "Should call mint swap exactly once");
    assert!(matches!(*s.bridge.host().channel_state.borrow(), ChannelState::Closed));

    let closed = s.bridge.host().closed_data.borrow();
    let (closed_balance, _closed_total, ref receiver_proofs_json, ref _sender_proofs_json) =
        closed.as_ref().expect("mark_channel_closed should have been called");

    // Key assertion: closed balance is amount_due (10), NOT overpayment (50)
    assert_eq!(*closed_balance, s.amount_due,
        "Closed balance should be amount_due ({}), not overpayment ({})", s.amount_due, s.overpayment_balance);
    println!("✓ Closed balance = {} (correct, not {})", closed_balance, s.overpayment_balance);

    // Receiver sum should be consistent with balance=10
    assert!(success.receiver_sum > 0, "Receiver should get proofs");
    assert!(success.receiver_sum < 20, "Receiver sum ({}) should be close to amount_due ({})", success.receiver_sum, s.amount_due);
    println!("✓ Receiver sum = {} (consistent with amount_due={})", success.receiver_sum, s.amount_due);

    // Verify receiver proofs have valid P2PK witnesses and are spendable
    close_balance_tests::verify_receiver_proofs_spendable(receiver_proofs_json, &s.shared_mint).await;

    println!("✓ Cooperative close with overpayment PASSED!");
}

/// Test: Unilateral close uses the latest payment balance (not amount_due).
///
/// Setup: same as overpayment test — latest payment=50, amount_due=10.
/// The unilateral close reads balance=50 from the balance store.
/// We verify closed_balance == 50 (not 10) and proofs are spendable.
#[tokio::test(flavor = "multi_thread")]
async fn test_unilateral_close_uses_latest_payment_balance() {
    use super::bridge::ChannelState;

    let s = close_balance_tests::setup_overpayment_scenario().await;

    println!("Executing unilateral close (latest payment={}, amount_due={})...", s.overpayment_balance, s.amount_due);
    let result = s.bridge.execute_unilateral_close(&s.channel_id, s.bridge.host());

    let success = result.expect("Unilateral close should succeed");
    println!("Close succeeded: total={}, receiver={}, sender={}", success.total_value, success.receiver_sum, success.sender_sum);

    assert_eq!(s.bridge.host().swap_call_count.get(), 1, "Should call mint swap exactly once");
    assert!(matches!(*s.bridge.host().channel_state.borrow(), ChannelState::Closed));

    let closed = s.bridge.host().closed_data.borrow();
    let (closed_balance, _closed_total, ref receiver_proofs_json, ref _sender_proofs_json) =
        closed.as_ref().expect("mark_channel_closed should have been called");

    // Key assertion: closed balance is the latest payment (50), NOT amount_due (10)
    assert_eq!(*closed_balance, s.overpayment_balance,
        "Closed balance should be latest payment ({}), not amount_due ({})", s.overpayment_balance, s.amount_due);
    println!("✓ Closed balance = {} (correct, not {})", closed_balance, s.amount_due);

    // Receiver sum should be consistent with balance=50
    assert!(success.receiver_sum > 0, "Receiver should get proofs");
    assert!(success.receiver_sum > 30, "Receiver sum ({}) should be close to overpayment ({})", success.receiver_sum, s.overpayment_balance);
    println!("✓ Receiver sum = {} (consistent with overpayment={})", success.receiver_sum, s.overpayment_balance);

    // Verify receiver proofs have valid P2PK witnesses and are spendable
    close_balance_tests::verify_receiver_proofs_spendable(receiver_proofs_json, &s.shared_mint).await;

    println!("✓ Unilateral close uses latest payment balance PASSED!");
}

/// Direct in-process connection to a mint (no HTTP)
#[derive(Clone)]
struct DirectMintConnection {
    mint: Mint,
}

impl DirectMintConnection {
    fn new(mint: Mint) -> Self {
        Self { mint }
    }
}

impl Debug for DirectMintConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DirectMintConnection")
    }
}

#[async_trait]
impl MintConnector for DirectMintConnection {
    #[cfg(all(feature = "bip353", not(target_arch = "wasm32")))]
    async fn resolve_dns_txt(&self, _domain: &str) -> Result<Vec<String>, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }

    async fn fetch_lnurl_pay_request(
        &self,
        _url: &str,
    ) -> Result<crate::wallet::LnurlPayResponse, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }

    async fn fetch_lnurl_invoice(
        &self,
        _url: &str,
    ) -> Result<crate::wallet::LnurlPayInvoiceResponse, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }

    async fn get_mint_keys(&self) -> Result<Vec<KeySet>, crate::Error> {
        Ok(self.mint.pubkeys().keysets)
    }

    async fn get_mint_keyset(&self, keyset_id: Id) -> Result<KeySet, crate::Error> {
        self.mint
            .keyset(&keyset_id)
            .ok_or(crate::Error::UnknownKeySet)
    }

    async fn get_mint_keysets(&self) -> Result<KeysetResponse, crate::Error> {
        Ok(self.mint.keysets())
    }

    async fn post_mint_quote(
        &self,
        _request: MintQuoteBolt11Request,
    ) -> Result<MintQuoteBolt11Response<String>, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }

    async fn get_mint_quote_status(
        &self,
        _quote_id: &str,
    ) -> Result<MintQuoteBolt11Response<String>, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }

    async fn post_mint(
        &self,
        _method: &PaymentMethod,
        _request: MintRequest<String>,
    ) -> Result<MintResponse, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }

    async fn post_melt_quote(
        &self,
        _request: MeltQuoteBolt11Request,
    ) -> Result<MeltQuoteBolt11Response<String>, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }

    async fn get_melt_quote_status(
        &self,
        _quote_id: &str,
    ) -> Result<MeltQuoteBolt11Response<String>, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }

    async fn post_melt(
        &self,
        _method: &PaymentMethod,
        _request: MeltRequest<String>,
    ) -> Result<MeltQuoteBolt11Response<String>, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }

    async fn post_swap(&self, request: SwapRequest) -> Result<SwapResponse, crate::Error> {
        self.mint.process_swap_request(request).await
    }

    async fn get_mint_info(&self) -> Result<MintInfo, crate::Error> {
        Ok(self.mint.mint_info().await?.clone().time(unix_time()))
    }

    async fn post_check_state(
        &self,
        request: CheckStateRequest,
    ) -> Result<CheckStateResponse, crate::Error> {
        self.mint.check_state(&request).await
    }

    async fn post_restore(&self, request: RestoreRequest) -> Result<RestoreResponse, crate::Error> {
        self.mint.restore(request).await
    }

    async fn get_auth_wallet(&self) -> Option<crate::wallet::AuthWallet> {
        None
    }

    async fn set_auth_wallet(&self, _wallet: Option<crate::wallet::AuthWallet>) {}

    async fn post_mint_bolt12_quote(
        &self,
        _request: MintQuoteBolt12Request,
    ) -> Result<MintQuoteBolt12Response<String>, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }

    async fn get_mint_quote_bolt12_status(
        &self,
        _quote_id: &str,
    ) -> Result<MintQuoteBolt12Response<String>, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }

    async fn post_melt_bolt12_quote(
        &self,
        _request: MeltQuoteBolt12Request,
    ) -> Result<MeltQuoteBolt11Response<String>, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }

    async fn get_melt_bolt12_quote_status(
        &self,
        _quote_id: &str,
    ) -> Result<MeltQuoteBolt11Response<String>, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }

    async fn post_mint_custom_quote(
        &self,
        _method: &PaymentMethod,
        _request: MintQuoteCustomRequest,
    ) -> Result<MintQuoteCustomResponse<String>, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }

    async fn post_melt_custom_quote(
        &self,
        _request: MeltQuoteCustomRequest,
    ) -> Result<MeltQuoteCustomResponse<String>, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }

    async fn get_mint_quote_custom_status(
        &self,
        _method: &str,
        _quote_id: &str,
    ) -> Result<MintQuoteCustomResponse<String>, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }

    async fn get_melt_quote_custom_status(
        &self,
        _method: &str,
        _quote_id: &str,
    ) -> Result<MeltQuoteCustomResponse<String>, crate::Error> {
        Err(crate::Error::UnsupportedPaymentMethod)
    }
}
