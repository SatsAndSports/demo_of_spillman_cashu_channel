//! Integration tests for Spilman payment channels
//!
//! These tests require a test mint and verify the full payment flow,
//! including funding token creation with blinded P2PK and refund paths.

use cdk_common::dhke::construct_proofs;
use cdk_common::nuts::{Conditions, CurrencyUnit, SigFlag, SpendingConditions};
use cdk_common::Amount;

use crate::nuts::SecretKey;
use crate::test_helpers::mint::create_test_blinded_messages;
use crate::test_helpers::nut10::{unzip3, TestMintHelper};
use crate::util::unix_time;

use super::deterministic::DeterministicOutputsForOneContext;
use super::keysets_and_amounts::KeysetInfo;
use super::params::ChannelParameters;

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
    let alice_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let charlie_pubkey = charlie_secret.public_key();

    println!("Alice pubkey: {}", alice_pubkey.to_hex());
    println!("Charlie pubkey: {}", charlie_pubkey.to_hex());
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

    let keyset_info = KeysetInfo::new(keyset_id, keys.clone(), input_fee_ppk);
    println!("Keyset: {} (fee: {} ppk)", keyset_id, input_fee_ppk);

    // Step 2: Create channel parameters
    let capacity = 10u64;
    let future_locktime = unix_time() + 3600; // 1 hour in future

    // With real fees from the mint, compute the minimum funding_token_amount
    let funding_token_amount = ChannelParameters::get_minimum_funding_token_amount(
        capacity,
        &keyset_info,
        64,
    )
    .expect("Failed to compute funding token amount");

    let params = ChannelParameters::new_with_secret_key(
        alice_pubkey,
        charlie_pubkey,
        "http://localhost:3338".to_string(), // mint URL (not actually used for swap)
        CurrencyUnit::Sat,
        capacity,
        funding_token_amount,
        future_locktime,
        unix_time(),
        format!("test-{}", unix_time()),
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
/// Verifies that after locktime expires, Alice can spend the funding token
/// with ONLY her refund blinded secret key (1-of-1 instead of 2-of-2).
///
/// This tests the refund path of the P2BK privacy feature:
/// - Funding token has expired locktime
/// - Refund key is Alice's SEPARATE blinded pubkey (different tweak from 2-of-2)
/// - Mint accepts the single refund signature after locktime
#[tokio::test]
async fn test_spilman_refund_spending_with_blinded_key() {
    let test_mint = TestMintHelper::new().await.unwrap();
    let mint = test_mint.mint();

    // Generate keypairs for Alice and Charlie
    let alice_secret = SecretKey::generate();
    let alice_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let charlie_pubkey = charlie_secret.public_key();

    println!("Alice pubkey: {}", alice_pubkey.to_hex());
    println!("Charlie pubkey: {}", charlie_pubkey.to_hex());
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

    let keyset_info = KeysetInfo::new(keyset_id, keys.clone(), input_fee_ppk);
    println!("Keyset: {} (fee: {} ppk)", keyset_id, input_fee_ppk);

    // Step 2: Create channel parameters with FUTURE locktime
    // (needed to derive blinded pubkeys correctly via ChannelParameters)
    let capacity = 10u64;
    let future_locktime = unix_time() + 3600; // 1 hour in future

    let funding_token_amount = ChannelParameters::get_minimum_funding_token_amount(
        capacity,
        &keyset_info,
        64,
    )
    .expect("Failed to compute funding token amount");

    let params = ChannelParameters::new_with_secret_key(
        alice_pubkey,
        charlie_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        capacity,
        funding_token_amount,
        future_locktime,
        unix_time(),
        format!("test-refund-{}", unix_time()),
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

    // Step 4: Create SpendingConditions manually with PAST locktime
    // We bypass Conditions::new() because it rejects past locktimes
    let past_locktime = unix_time() - 3600; // 1 hour ago (expired)
    println!("Past locktime: {} (expired 1 hour ago)", past_locktime);

    let spending_conditions = SpendingConditions::new_p2pk(
        blinded_alice, // data field: Alice's blinded pubkey for 2-of-2
        Some(Conditions {
            locktime: Some(past_locktime),                 // Expired!
            pubkeys: Some(vec![blinded_charlie]),          // Charlie for 2-of-2
            refund_keys: Some(vec![blinded_alice_refund]), // Alice's REFUND blinded key
            num_sigs: Some(2),                             // 2-of-2 before locktime
            sig_flag: SigFlag::SigAll,                     // SIG_ALL
            num_sigs_refund: Some(1),                      // 1-of-1 for refund
        }),
    );
    println!("Created P2PK conditions with expired locktime and blinded refund key");

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

    // Step 8: Spend with ONLY Alice's refund blinded key (locktime expired)
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

    // Sign with ONLY the refund key (1-of-1 after locktime)
    swap_request_refund
        .sign_sig_all(alice_refund_blinded_secret)
        .expect("Failed to sign with Alice's refund blinded key");

    let result = mint.process_swap_request(swap_request_refund).await;
    assert!(
        result.is_ok(),
        "Refund spending with blinded key should succeed after locktime: {:?}",
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
    let alice_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let charlie_pubkey = charlie_secret.public_key();

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
    let keyset_info = KeysetInfo::new(keyset_id, keyset_keys, 0);

    // Create channel params (fees=0, so funding_token_amount == capacity)
    let params = ChannelParameters::new_with_secret_key(
        alice_pubkey,
        charlie_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        100, // capacity
        100, // funding_token_amount
        crate::util::unix_time() + 3600,
        crate::util::unix_time(),
        "test-stage2-keys".to_string(),
        keyset_info,
        64,
        &alice_secret,
    )
    .expect("Failed to create params");

    // Get all the different pubkeys
    let alice_raw = alice_pubkey.to_hex();
    let charlie_raw = charlie_pubkey.to_hex();

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
    let alice_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let charlie_pubkey = charlie_secret.public_key();

    println!("Alice pubkey: {}", alice_pubkey.to_hex());
    println!("Charlie pubkey: {}", charlie_pubkey.to_hex());

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
    let keyset_info = KeysetInfo::new(keyset_id, keyset_keys, 0);
    println!("Keyset ID: {}", keyset_id);

    // 3. Create channel parameters with a reasonable capacity (fees=0, so funding_token_amount == capacity)
    let capacity = 100u64;
    let params = ChannelParameters::new_with_secret_key(
        alice_pubkey,
        charlie_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        capacity,
        capacity, // funding_token_amount == capacity when fees are 0
        crate::util::unix_time() + 3600, // 1 hour in future
        crate::util::unix_time(),
        format!("test-sender-keys-{}", crate::util::unix_time()),
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
    let charlie_pubkey = charlie_secret.public_key();

    println!("Alice pubkey: {}", alice_secret.public_key().to_hex());
    println!("Charlie pubkey: {}", charlie_pubkey.to_hex());

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
    let locktime = unix_time() + 3600; // 1 hour in future
    let max_amount = 64u64;

    let compute_result = compute_channel_from_token(
        &token_string,
        &charlie_pubkey.to_hex(),
        &alice_secret.to_secret_hex(),
        locktime,
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

    // Step 5: Call create_funding_swap
    let swap_result = create_funding_swap(
        params_json,
        &alice_secret.to_secret_hex(),
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
    use super::bridge::{ChannelState, SpilmanBridge, SpilmanHost};
    use super::client_bridge::{base64_decode, SpilmanClientBridge, SpilmanClientHost};
    use cdk_common::nuts::{CurrencyUnit as CU, Id, PublicKey, Token};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    // ====================================================================
    // Test Client Host: wraps an in-process mint
    // ====================================================================

    struct TestClientHost {
        mint: Arc<crate::mint::Mint>,
        channels: Mutex<HashMap<String, String>>,
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

        fn save_channel(&self, channel_id: &str, channel_json: &str) {
            self.channels
                .lock()
                .unwrap()
                .insert(channel_id.to_string(), channel_json.to_string());
        }

        fn get_channel(&self, channel_id: &str) -> Option<String> {
            self.channels
                .lock()
                .unwrap()
                .get(channel_id)
                .cloned()
        }

        fn list_channel_ids(&self) -> Vec<String> {
            self.channels.lock().unwrap().keys().cloned().collect()
        }

        fn delete_channel(&self, channel_id: &str) {
            self.channels.lock().unwrap().remove(channel_id);
        }
    }

    // ====================================================================
    // Test Server Host: wraps an in-process mint + stores channels
    // ====================================================================

    struct TestServerHost {
        keyset_ids: Vec<Id>,
        keyset_infos: HashMap<Id, String>,
        funding_data: Mutex<HashMap<String, (String, String, String, String)>>,
        payments: Mutex<HashMap<String, (u64, String)>>, // channel_id -> (balance, sig)
    }

    impl SpilmanHost for TestServerHost {
        fn receiver_key_is_acceptable(&self, _receiver_pubkey: &PublicKey) -> bool {
            true
        }
        fn mint_and_keyset_is_acceptable(&self, _mint: &str, _keyset_id: &Id) -> bool {
            true
        }
        fn get_funding_and_params(
            &self,
            channel_id: &str,
        ) -> Option<(String, String, String, String)> {
            self.funding_data.lock().unwrap().get(channel_id).cloned()
        }
        fn save_funding(
            &self,
            channel_id: &str,
            params_json: &str,
            funding_proofs_json: &str,
            channel_secret_hex: &str,
            keyset_info_json: &str,
            _initial_balance: u64,
            _initial_signature: &str,
        ) {
            self.funding_data.lock().unwrap().insert(
                channel_id.to_string(),
                (
                    params_json.to_string(),
                    funding_proofs_json.to_string(),
                    channel_secret_hex.to_string(),
                    keyset_info_json.to_string(),
                ),
            );
        }
        fn get_amount_due(&self, _channel_id: &str, _context_json: Option<&str>) -> u64 {
            0
        }
        fn record_payment(
            &self,
            channel_id: &str,
            balance: u64,
            signature: &str,
            _context_json: &str,
        ) {
            self.payments
                .lock()
                .unwrap()
                .insert(channel_id.to_string(), (balance, signature.to_string()));
        }
        fn get_channel_state(&self, _channel_id: &str) -> ChannelState {
            ChannelState::Open
        }
        fn mark_channel_closing(
            &self,
            _channel_id: &str,
            _locktime: u64,
            _balance: u64,
            _signature: &str,
        ) -> Result<(), String> {
            Ok(())
        }
        fn get_closing_data(
            &self,
            _channel_id: &str,
        ) -> Option<super::bridge::ClosingData> {
            None
        }
        fn get_channel_policy(&self) -> String {
            serde_json::json!({
                "min_expiry_in_seconds": 3600,
                "pricing": { "sat": { "minCapacity": 10 } }
            })
            .to_string()
        }
        fn now_seconds(&self) -> u64 {
            crate::util::unix_time()
        }
        fn get_balance_and_signature_for_unilateral_exit(
            &self,
            channel_id: &str,
        ) -> Option<(u64, String)> {
            self.payments.lock().unwrap().get(channel_id).cloned()
        }
        fn get_active_keyset_ids(&self, _mint: &str, _unit: &CU) -> Vec<Id> {
            self.keyset_ids.clone()
        }
        fn get_keyset_info(&self, _mint: &str, keyset_id: &Id) -> Option<String> {
            self.keyset_infos.get(keyset_id).cloned()
        }
        fn call_mint_swap(
            &self,
            _mint_url: &str,
            _swap_request_json: &str,
        ) -> Result<String, String> {
            Err("not used in this test".to_string())
        }
        fn mark_channel_closed(
            &self,
            _channel_id: &str,
            _locktime: u64,
            _balance: u64,
            _receiver_proofs_json: &str,
            _sender_proofs_json: &str,
            _receiver_sum: u64,
            _sender_sum: u64,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    // ====================================================================
    // Setup: create a shared mint instance used for both minting and swapping
    // ====================================================================

    // Generate Charlie (server) keypair
    let charlie_secret = SecretKey::generate();
    let charlie_pubkey = charlie_secret.public_key();

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

    let client_host = TestClientHost {
        mint: Arc::clone(&shared_mint),
        channels: Mutex::new(HashMap::new()),
    };

    let client_bridge =
        SpilmanClientBridge::new(client_host, None).expect("Should create client bridge");

    println!(
        "Client bridge created, alice_pubkey: {}",
        client_bridge.alice_pubkey_hex()
    );

    // ====================================================================
    // Open channel from token
    // ====================================================================

    let locktime = unix_time() + 7200; // 2 hours (well above the 1-hour min_expiry)
    let max_amount = 64u64;

    let open_result = client_bridge
        .open_channel_from_token(
            &token_string,
            &charlie_pubkey.to_hex(),
            locktime,
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

    let server_host = TestServerHost {
        keyset_ids: vec![active_keyset_id],
        keyset_infos,
        funding_data: Mutex::new(HashMap::new()),
        payments: Mutex::new(HashMap::new()),
    };

    let server_bridge = SpilmanBridge::new(server_host, Some(charlie_secret));

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
