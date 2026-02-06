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

    let params = ChannelParameters::new_with_secret_key(
        alice_pubkey,
        charlie_pubkey,
        "http://localhost:3338".to_string(), // mint URL (not actually used for swap)
        CurrencyUnit::Sat,
        capacity,
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
    let input_proofs = test_mint
        .mint_proofs(Amount::from(funding_amount))
        .await
        .expect("Failed to mint input proofs");

    // Swap for our P2PK funding proofs
    let swap_request =
        cdk_common::nuts::SwapRequest::new(input_proofs.clone(), blinded_messages.clone());
    let swap_response = mint
        .process_swap_request(swap_request)
        .await
        .expect("Failed to swap for P2PK proofs");
    println!(
        "Swapped for {} P2PK funding proofs",
        swap_response.signatures.len()
    );

    // Step 5: Construct the P2PK proofs
    let secrets_with_blinding = funding_outputs
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
    // Create outputs for where the funds will go
    let (new_outputs, _) = create_test_blinded_messages(mint, Amount::from(capacity))
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

    let params = ChannelParameters::new_with_secret_key(
        alice_pubkey,
        charlie_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        capacity,
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

    // Step 5: Create P2PK blinded messages using test helper
    let input_amount = Amount::from(capacity);
    let split_amounts = test_mint.split_amount(input_amount).unwrap();
    let (p2pk_outputs, blinding_factors, secrets) = unzip3(
        split_amounts
            .iter()
            .map(|&amt| test_mint.create_blinded_message(amt, &spending_conditions))
            .collect(),
    );
    println!("Created {} P2PK blinded messages", p2pk_outputs.len());

    // Step 6: Mint regular proofs, then swap for P2PK proofs
    let input_proofs = test_mint
        .mint_proofs(input_amount)
        .await
        .expect("Failed to mint input proofs");

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
    let (new_outputs, _) = create_test_blinded_messages(mint, input_amount)
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

    // Create channel params
    let params = ChannelParameters::new_with_secret_key(
        alice_pubkey,
        charlie_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        100,
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

    // 3. Create channel parameters with a reasonable capacity
    let capacity = 100u64;
    let params = ChannelParameters::new_with_secret_key(
        alice_pubkey,
        charlie_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        capacity,
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
    let funding_token_nominal = compute_json["funding_token_nominal"]
        .as_u64()
        .expect("Should have funding_token_nominal");
    let change_amount = compute_json["change_amount"]
        .as_u64()
        .expect("Should have change_amount");
    let params_json = compute_json["params_json"]
        .as_str()
        .expect("Should have params_json");
    let proofs_json = compute_json["proofs_json"]
        .as_str()
        .expect("Should have proofs_json");

    println!("Input value: {} sats", input_value);
    println!("Capacity: {} sats", capacity);
    println!("Funding token nominal: {} sats", funding_token_nominal);
    println!("Change amount: {} sats", change_amount);

    // Verify the math makes sense
    assert!(capacity > 0, "Capacity should be positive");
    assert!(
        capacity <= input_value,
        "Capacity should not exceed input value"
    );
    assert!(
        funding_token_nominal <= input_value,
        "Funding nominal should not exceed input value"
    );
    println!("✓ compute_channel_from_token values are reasonable");

    // Step 5: Call create_funding_swap
    let swap_result = create_funding_swap(
        params_json,
        &alice_secret.to_secret_hex(),
        &keyset_info_json,
        proofs_json,
        change_amount,
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
    let change_secrets_json = swap_json["change_secrets_json"]
        .as_str()
        .expect("Should have change_secrets_json");
    let funding_count = swap_json["funding_count"]
        .as_u64()
        .expect("Should have funding_count");
    let change_count = swap_json["change_count"]
        .as_u64()
        .expect("Should have change_count");

    println!(
        "Created swap request with {} funding + {} change outputs",
        funding_count, change_count
    );
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
        change_secrets_json,
        &keyset_info_json,
    )
    .expect("complete_funding_swap should succeed");

    let complete_json: serde_json::Value =
        serde_json::from_str(&complete_result).expect("Should parse complete result");

    let funding_proofs_json = complete_json["funding_proofs_json"]
        .as_str()
        .expect("Should have funding_proofs_json");
    let change_proofs_json = complete_json["change_proofs_json"]
        .as_str()
        .expect("Should have change_proofs_json");

    let funding_proofs: Vec<Proof> =
        serde_json::from_str(funding_proofs_json).expect("Should parse funding proofs");
    let change_proofs: Vec<Proof> =
        serde_json::from_str(change_proofs_json).expect("Should parse change proofs");

    println!(
        "Got {} funding proofs, {} change proofs",
        funding_proofs.len(),
        change_proofs.len()
    );

    // Verify counts match
    assert_eq!(
        funding_proofs.len(),
        funding_count as usize,
        "Funding proof count should match"
    );
    assert_eq!(
        change_proofs.len(),
        change_count as usize,
        "Change proof count should match"
    );

    // Verify funding proofs have expected total
    let funding_total: u64 = funding_proofs.iter().map(|p| u64::from(p.amount)).sum();
    assert_eq!(
        funding_total, funding_token_nominal,
        "Funding proofs should sum to funding_token_nominal"
    );

    // Verify change proofs have expected total
    let change_total: u64 = change_proofs.iter().map(|p| u64::from(p.amount)).sum();
    assert_eq!(
        change_total, change_amount,
        "Change proofs should sum to change_amount"
    );

    // Verify all proofs have DLEQ
    for (i, proof) in funding_proofs.iter().enumerate() {
        assert!(
            proof.dleq.is_some(),
            "Funding proof {} should have DLEQ",
            i
        );
    }
    for (i, proof) in change_proofs.iter().enumerate() {
        assert!(
            proof.dleq.is_some(),
            "Change proof {} should have DLEQ",
            i
        );
    }
    println!("✓ All proofs have DLEQ proofs (verified during unblinding)");

    println!(
        "✓ Swap-to-funding complete: {} sats → {} capacity + {} change",
        input_value, capacity, change_amount
    );
}
