//! Spilman Channel Sender and Receiver
//!
//! This module contains the sender's (Alice's) and receiver's (Charlie's) views
//! of a Spilman payment channel.

use cdk::nuts::{SecretKey, SwapRequest};

use super::established_channel::EstablishedChannel;
use super::balance_update::BalanceUpdateMessage;

/// The sender's view of a Spilman payment channel
///
/// This struct holds Alice's secret key and the established channel state.
/// It provides high-level methods for Alice's operations.
pub struct SpilmanChannelSender {
    /// Alice's secret key for signing
    pub alice_secret: SecretKey,
    /// The established channel state
    pub channel: EstablishedChannel,
}

impl SpilmanChannelSender {
    /// Create a new sender instance
    pub fn new(alice_secret: SecretKey, channel: EstablishedChannel) -> Self {
        Self {
            alice_secret,
            channel,
        }
    }

    /// Create and sign a balance update for the given amount to Charlie
    ///
    /// Returns (BalanceUpdateMessage, SwapRequest with Alice's signature)
    pub fn create_signed_balance_update(
        &self,
        charlie_balance: u64,
    ) -> anyhow::Result<(BalanceUpdateMessage, SwapRequest)> {
        // Create commitment outputs for this balance
        let commitment_outputs = self.channel.extra.create_two_sets_of_outputs_for_balance(
            charlie_balance,
        )?;

        // Create unsigned swap request
        let mut swap_request = commitment_outputs.create_swap_request(
            self.channel.funding_proofs.clone(),
        )?;

        // Alice signs the swap request
        swap_request.sign_sig_all(self.alice_secret.clone())?;

        // Create the balance update message
        let balance_update = BalanceUpdateMessage::from_signed_swap_request(
            self.channel.extra.params.get_channel_id(),
            charlie_balance,
            &swap_request,
        )?;

        Ok((balance_update, swap_request))
    }

    /// Get the de facto balance (after fee rounding) for an intended balance
    pub fn get_de_facto_balance(&self, intended_balance: u64) -> anyhow::Result<u64> {
        self.channel.extra.get_de_facto_balance(intended_balance)
    }

    /// Get the channel capacity
    pub fn capacity(&self) -> u64 {
        self.channel.extra.params.capacity
    }

    /// Get the channel ID
    pub fn channel_id(&self) -> String {
        self.channel.extra.params.get_channel_id()
    }

    /// Get the shared secret with Charlie (stored in channel extra)
    pub fn get_shared_secret(&self) -> &[u8; 32] {
        &self.channel.extra.shared_secret
    }
}

/// The receiver's view of a Spilman payment channel
///
/// This struct holds Charlie's secret key and the established channel state.
/// It provides high-level methods for Charlie's operations.
pub struct SpilmanChannelReceiver {
    /// Charlie's secret key for signing
    pub charlie_secret: SecretKey,
    /// The established channel state
    pub channel: EstablishedChannel,
}

impl SpilmanChannelReceiver {
    /// Create a new receiver instance
    pub fn new(charlie_secret: SecretKey, channel: EstablishedChannel) -> Self {
        Self {
            charlie_secret,
            channel,
        }
    }

    /// Verify a balance update from the sender and add receiver's signature
    ///
    /// This verifies Alice's signature on the balance update, then adds Charlie's
    /// signature to the swap request, making it ready to submit to the mint.
    ///
    /// Returns the fully-signed SwapRequest ready for execution
    pub fn verify_and_sign_balance_update(
        &self,
        balance_update: &BalanceUpdateMessage,
        mut swap_request: SwapRequest,
    ) -> anyhow::Result<SwapRequest> {
        // Verify that Alice's signature is valid
        balance_update.verify_sender_signature(&self.channel)?;

        // Add Charlie's signature to complete the 2-of-2 multisig
        swap_request.sign_sig_all(self.charlie_secret.clone())?;

        Ok(swap_request)
    }

    /// Get the de facto balance (after fee rounding) for an intended balance
    pub fn get_de_facto_balance(&self, intended_balance: u64) -> anyhow::Result<u64> {
        self.channel.extra.get_de_facto_balance(intended_balance)
    }

    /// Get the channel capacity
    pub fn capacity(&self) -> u64 {
        self.channel.extra.params.capacity
    }

    /// Get the channel ID
    pub fn channel_id(&self) -> String {
        self.channel.extra.params.get_channel_id()
    }

    /// Get the shared secret with Alice (stored in channel extra)
    pub fn get_shared_secret(&self) -> &[u8; 32] {
        &self.channel.extra.shared_secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk::nuts::{CurrencyUnit, SecretKey};
    use cdk::util::unix_time;
    use crate::params::SpilmanChannelParameters;
    use crate::extra::SpilmanChannelExtra;

    #[tokio::test]
    async fn test_full_flow() {
        use crate::test_helpers::{setup_mint_and_wallets_for_demo, mint_deterministic_outputs};

        // 1. Generate keys for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        // 2. Setup mint and wallets
        let channel_unit = CurrencyUnit::Sat;
        let input_fee_ppk = 400; // 40% fee for testing
        let base = 2; // Powers of 2
        let (mint_connection, alice_wallet, charlie_wallet, _mint_url) =
            setup_mint_and_wallets_for_demo(None, channel_unit.clone(), input_fee_ppk, base).await.unwrap();

        // 3. Get active keyset info
        let keyset_info =
            crate::test_helpers::get_active_keyset_info(&*mint_connection, &channel_unit).await.unwrap();

        // 4. Create channel parameters
        let capacity = 100_000u64;
        let locktime = unix_time() + 86400;
        let setup_timestamp = unix_time();
        let sender_nonce = "test_nonce".to_string();
        let maximum_amount_for_one_output = 10_000u64;

        let channel_params = SpilmanChannelParameters::new(
            alice_pubkey,
            charlie_pubkey,
            "local".to_string(),
            channel_unit.clone(),
            capacity,
            locktime,
            setup_timestamp,
            sender_nonce,
            keyset_info.clone(),
            maximum_amount_for_one_output,
        ).unwrap();

        // 5. Create channel extra (computes shared secret internally)
        let channel_extra = SpilmanChannelExtra::new_with_secret_key(channel_params.clone(), &alice_secret).unwrap();

        // 5b. Create Charlie's view of channel extra (should have identical shared secret and channel_id)
        let channel_extra_charlie = SpilmanChannelExtra::new_with_secret_key(channel_params, &charlie_secret).unwrap();

        // Verify both parties derive the same shared secret and channel ID
        assert_eq!(
            channel_extra.shared_secret,
            channel_extra_charlie.shared_secret,
            "Alice and Charlie should derive the same shared secret"
        );
        assert_eq!(
            channel_extra.params.get_channel_id(),
            channel_extra_charlie.params.get_channel_id(),
            "Alice and Charlie should have the same channel ID"
        );

        // 6. Calculate funding token size and mint it
        let funding_token_nominal = channel_extra.get_total_funding_token_amount().unwrap();

        let funding_proofs = crate::test_helpers::create_funding_proofs(
            &*mint_connection,
            &channel_extra,
            funding_token_nominal,
        ).await.unwrap();

        // 7. Create established channel
        let channel = EstablishedChannel::new(channel_extra, funding_proofs).unwrap();

        // 8. Create SpilmanChannelSender (Alice's view) and SpilmanChannelReceiver (Charlie's view)
        let sender = SpilmanChannelSender::new(alice_secret.clone(), channel.clone());
        let receiver = SpilmanChannelReceiver::new(charlie_secret.clone(), channel.clone());

        // 9. Alice creates a balance update
        let charlie_balance = 10_000u64;
        let charlie_de_facto_balance = sender.get_de_facto_balance(charlie_balance).unwrap();
        let (balance_update, swap_request) = sender.create_signed_balance_update(
            charlie_balance
        ).unwrap();

        // 10. Verify the balance update has Alice's signature
        assert_eq!(balance_update.amount, charlie_balance);
        assert_eq!(balance_update.channel_id, sender.channel_id());

        // 11. Charlie verifies Alice's signature and adds his own
        let swap_request = receiver.verify_and_sign_balance_update(&balance_update, swap_request).unwrap();

        // Print swap request details
        println!("   Swap inputs: {:?}", swap_request.inputs().iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
        println!("   Swap outputs: {:?}", swap_request.outputs().iter().map(|bm| u64::from(bm.amount)).collect::<Vec<_>>());

        // 12. Execute the swap
        let swap_response = mint_connection.process_swap(swap_request).await.unwrap();

        // 13. Unblind the swap signatures to get stage 1 proofs for both parties
        let (charlie_stage1_proofs, alice_stage1_proofs) = crate::test_helpers::unblind_commitment_proofs(
            &sender.channel.extra,
            charlie_balance,
            swap_response.signatures,
        ).unwrap();

        println!("   ✓ Unblinded {} proofs for Charlie, {} for Alice",
                 charlie_stage1_proofs.len(), alice_stage1_proofs.len());

        println!("   Charlie's proofs: {:?}", charlie_stage1_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
        println!("   Alice's proofs: {:?}", alice_stage1_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());

        // 14. Verify that Charlie's proofs total the inverse of the balance
        // (the nominal value needed to achieve (de facto) charlie_balance after stage 2 fees)
        let charlie_total_after_stage1: u64 = charlie_stage1_proofs.iter().map(|p| u64::from(p.amount)).sum();
        let inverse_result = sender.channel.extra.params.keyset_info.inverse_deterministic_value_after_fees(
            charlie_balance,
            sender.channel.extra.params.maximum_amount_for_one_output
        ).unwrap();
        let expected_nominal = inverse_result.nominal_value;
        assert_eq!(
            charlie_total_after_stage1, expected_nominal,
            "Charlie's proofs should total {} sats (inverse of balance {})", expected_nominal, charlie_balance
        );
        println!("   ✓ Charlie's proofs total {} sats (inverse of balance {} sats)", charlie_total_after_stage1, charlie_balance);

        // 15. Verify that Alice's proofs total the remainder after Charlie's allocation
        let alice_total_after_stage1: u64 = alice_stage1_proofs.iter().map(|p| u64::from(p.amount)).sum();
        let value_after_stage1 = sender.channel.extra.get_value_after_stage1().unwrap();
        let expected_alice_total = value_after_stage1 - charlie_total_after_stage1;
        assert_eq!(
            alice_total_after_stage1, expected_alice_total,
            "Alice's proofs should total {} sats (value after stage1 {} - Charlie's total {})",
            expected_alice_total, value_after_stage1, charlie_total_after_stage1
        );
        println!("   ✓ Alice's proofs total {} sats (remainder after Charlie's {} sats)", alice_total_after_stage1, charlie_total_after_stage1);

        // 16. Both parties receive their proofs into wallets
        let (charlie_received, alice_received) = crate::test_helpers::receive_proofs_into_both_wallets(
            &charlie_wallet,
            charlie_stage1_proofs,
            charlie_secret,
            &alice_wallet,
            alice_stage1_proofs,
            alice_secret,
            ).await.unwrap();
        println!("   Charlie received: {} sats   Alice received: {} sats", charlie_received, alice_received);

        // 17. Assert that Charlie's received amount matches the de facto balance
        assert_eq!(
            charlie_received, charlie_de_facto_balance,
            "Charlie's received amount should match get_de_facto_balance(charlie_balance)"
        );

        println!("✅ Full channel flow test passed!");
    }

    #[tokio::test]
    async fn test_full_flow_powers_of_3() {
        use crate::test_helpers::{setup_mint_and_wallets_for_demo, mint_deterministic_outputs};

        // 1. Generate keys for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        // 2. Setup mint and wallets
        let channel_unit = CurrencyUnit::Sat;
        let input_fee_ppk = 400; // 40% fee for testing
        let base = 3; // Powers of 3 as the mint's amounts: 1,3,9,27,...
        let (mint_connection, alice_wallet, charlie_wallet, _mint_url) =
            setup_mint_and_wallets_for_demo(None, channel_unit.clone(), input_fee_ppk, base).await.unwrap();

        // 3. Get active keyset info
        let keyset_info =
            crate::test_helpers::get_active_keyset_info(&*mint_connection, &channel_unit).await.unwrap();

        // 4. Create channel parameters
        let capacity = 100_000u64;
        let locktime = unix_time() + 86400;
        let setup_timestamp = unix_time();
        let sender_nonce = "test_nonce".to_string();
        let maximum_amount_for_one_output = 10_000u64;

        let channel_params = SpilmanChannelParameters::new(
            alice_pubkey,
            charlie_pubkey,
            "local".to_string(),
            channel_unit.clone(),
            capacity,
            locktime,
            setup_timestamp,
            sender_nonce,
            keyset_info.clone(),
            maximum_amount_for_one_output,
        ).unwrap();

        // 5. Create channel extra (computes shared secret internally)
        let channel_extra = SpilmanChannelExtra::new_with_secret_key(channel_params, &alice_secret).unwrap();

        // 6. Calculate funding token size and mint it
        let funding_token_nominal = channel_extra.get_total_funding_token_amount().unwrap();

        let funding_proofs = crate::test_helpers::create_funding_proofs(
            &*mint_connection,
            &channel_extra,
            funding_token_nominal,
        ).await.unwrap();

        // 7. Create established channel
        let channel = EstablishedChannel::new(channel_extra, funding_proofs).unwrap();

        // 8. Create SpilmanChannelSender (Alice's view)
        let sender = SpilmanChannelSender::new(alice_secret.clone(), channel.clone());

        // 9. Test creating a balance update
        let charlie_balance = 10_000u64;
        let (balance_update, mut swap_request) = sender.create_signed_balance_update(
            charlie_balance
        ).unwrap();

        // 10. Verify the balance update has the expected amount
        assert_eq!(balance_update.amount, charlie_balance);
        assert_eq!(balance_update.channel_id, sender.channel_id());

        // 11. Charlie verifies the signature against the channel (doesn't need sender object)
        balance_update.verify_sender_signature(&channel).unwrap();

        // 12. Charlie can now add his signature
        swap_request.sign_sig_all(charlie_secret.clone()).unwrap();

        // Print swap request details
        println!("   Swap inputs: {:?}", swap_request.inputs().iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
        println!("   Swap outputs: {:?}", swap_request.outputs().iter().map(|bm| u64::from(bm.amount)).collect::<Vec<_>>());

        // 13. Execute the swap
        let swap_response = mint_connection.process_swap(swap_request).await.unwrap();

        // 14. Unblind the swap signatures to get stage 1 proofs for both parties
        let (charlie_stage1_proofs, alice_stage1_proofs) = crate::test_helpers::unblind_commitment_proofs(
            &sender.channel.extra,
            charlie_balance,
            swap_response.signatures,
        ).unwrap();

        println!("   ✓ Unblinded {} proofs for Charlie, {} for Alice",
                 charlie_stage1_proofs.len(), alice_stage1_proofs.len());

        println!("   Charlie's proofs: {:?}", charlie_stage1_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
        println!("   Alice's proofs: {:?}", alice_stage1_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());

        // Verify that Charlie's proofs total the inverse of the balance
        // (the nominal value needed to achieve (de facto) charlie_balance after stage1 fees
        let charlie_total_after_stage1: u64 = charlie_stage1_proofs.iter().map(|p| u64::from(p.amount)).sum();
        let inverse_result = sender.channel.extra.params.keyset_info.inverse_deterministic_value_after_fees(
            charlie_balance,
            sender.channel.extra.params.maximum_amount_for_one_output
        ).unwrap();
        let expected_nominal = inverse_result.nominal_value;
        assert_eq!(
            charlie_total_after_stage1, expected_nominal,
            "Charlie's proofs should total {} sats (inverse of balance {})", expected_nominal, charlie_balance
        );
        println!("   ✓ Charlie's proofs total {} sats (inverse of balance {} sats)", charlie_total_after_stage1, charlie_balance);

        // Verify that Alice's proofs total the remainder after Charlie's allocation
        let alice_total_after_stage1: u64 = alice_stage1_proofs.iter().map(|p| u64::from(p.amount)).sum();
        let value_after_stage1 = sender.channel.extra.get_value_after_stage1().unwrap();
        let expected_alice_total = value_after_stage1 - charlie_total_after_stage1;
        assert_eq!(
            alice_total_after_stage1, expected_alice_total,
            "Alice's proofs should total {} sats (value after stage1 {} - Charlie's total {})",
            expected_alice_total, value_after_stage1, charlie_total_after_stage1
        );
        println!("   ✓ Alice's proofs total {} sats (remainder after Charlie's {} sats)", alice_total_after_stage1, charlie_total_after_stage1);

        // As this is powers-of-3, and the CDK doesn't really support the final
        // wallet.receive_proofs, we just end this test here.

    }

    #[tokio::test]
    async fn test_multiple_balances_powers_of_3_zerofees() {
        use crate::test_helpers::{setup_mint_and_wallets_for_demo, mint_deterministic_outputs};

        // 1. Generate keys for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        // 2. Setup mint and wallets
        let channel_unit = CurrencyUnit::Sat;
        let input_fee_ppk = 0; // no fees
        let base = 3; // Powers of 3 as the mint's amounts: 1,3,9,27,...
        let (mint_connection, _alice_wallet, _charlie_wallet, _mint_url) =
            setup_mint_and_wallets_for_demo(None, channel_unit.clone(), input_fee_ppk, base).await.unwrap();

        // 3. Get active keyset info
        let keyset_info =
            crate::test_helpers::get_active_keyset_info(&*mint_connection, &channel_unit).await.unwrap();

        // Common channel parameters
        let capacity = 100_000u64;
        let locktime = unix_time() + 86400;
        let setup_timestamp = unix_time();
        let maximum_amount_for_one_output = 10_000u64;

        // Test with multiple balances: 0-10, powers of 10 (100, 1000, 10000), and 99990-100000
        let test_balances: Vec<u64> = (0..=10)
            .chain([100, 1000, 10000])
            .chain(capacity-10..=capacity)
            .collect();

        for (i, charlie_balance) in test_balances.iter().enumerate() {
            println!("\n=== Test iteration {} with balance {} ===", i + 1, charlie_balance);

            // 4. Create channel parameters (unique nonce for each iteration)
            let sender_nonce = format!("test_nonce_{}", i);
            let channel_params = SpilmanChannelParameters::new(
                alice_pubkey,
                charlie_pubkey,
                "local".to_string(),
                channel_unit.clone(),
                capacity,
                locktime,
                setup_timestamp,
                sender_nonce,
                keyset_info.clone(),
                maximum_amount_for_one_output,
            ).unwrap();

            // 5. Create channel extra (computes shared secret internally)
            let channel_extra = SpilmanChannelExtra::new_with_secret_key(channel_params, &alice_secret).unwrap();

            // 6. Calculate funding token size and mint it
            let funding_token_nominal = channel_extra.get_total_funding_token_amount().unwrap();

            let funding_proofs = crate::test_helpers::create_funding_proofs(
                &*mint_connection,
                &channel_extra,
                funding_token_nominal,
            ).await.unwrap();

            // 7. Create established channel
            let channel = EstablishedChannel::new(channel_extra, funding_proofs).unwrap();

            // 8. Create SpilmanChannelSender (Alice's view)
            let sender = SpilmanChannelSender::new(alice_secret.clone(), channel.clone());

            // 9. Test creating a balance update
            let (balance_update, mut swap_request) = sender.create_signed_balance_update(
                *charlie_balance
            ).unwrap();

            // 10. Verify the balance update has the expected amount
            assert_eq!(balance_update.amount, *charlie_balance);
            assert_eq!(balance_update.channel_id, sender.channel_id());

            // 11. Charlie verifies the signature against the channel (doesn't need sender object)
            balance_update.verify_sender_signature(&channel).unwrap();

            // 12. Charlie can now add his signature
            swap_request.sign_sig_all(charlie_secret.clone()).unwrap();

            // Print swap request details
            println!("   Swap inputs: {:?}", swap_request.inputs().iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
            println!("   Swap outputs: {:?}", swap_request.outputs().iter().map(|bm| u64::from(bm.amount)).collect::<Vec<_>>());

            // 13. Execute the swap
            let swap_response = mint_connection.process_swap(swap_request).await.unwrap();

            // 14. Unblind the swap signatures to get stage 1 proofs for both parties
            let (charlie_stage1_proofs, alice_stage1_proofs) = crate::test_helpers::unblind_commitment_proofs(
                &sender.channel.extra,
                *charlie_balance,
                swap_response.signatures,
            ).unwrap();

            println!("   ✓ Unblinded {} proofs for Charlie, {} for Alice",
                     charlie_stage1_proofs.len(), alice_stage1_proofs.len());

            println!("   Charlie's proofs: {:?}", charlie_stage1_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
            println!("   Alice's proofs: {:?}", alice_stage1_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());

            // Verify that Charlie's proofs total the inverse of the balance
            let charlie_total_after_stage1: u64 = charlie_stage1_proofs.iter().map(|p| u64::from(p.amount)).sum();
            let inverse_result = sender.channel.extra.params.keyset_info.inverse_deterministic_value_after_fees(
                *charlie_balance,
                sender.channel.extra.params.maximum_amount_for_one_output
            ).unwrap();
            let expected_nominal = inverse_result.nominal_value;
            assert_eq!(
                charlie_total_after_stage1, expected_nominal,
                "Charlie's proofs should total {} sats (inverse of balance {})", expected_nominal, charlie_balance
            );
            println!("   ✓ Charlie's proofs total {} sats (inverse of balance {} sats)", charlie_total_after_stage1, charlie_balance);

            // Verify that Alice's proofs total the remainder after Charlie's allocation
            let alice_total_after_stage1: u64 = alice_stage1_proofs.iter().map(|p| u64::from(p.amount)).sum();
            let value_after_stage1 = sender.channel.extra.get_value_after_stage1().unwrap();
            let expected_alice_total = value_after_stage1 - charlie_total_after_stage1;
            assert_eq!(
                alice_total_after_stage1, expected_alice_total,
                "Alice's proofs should total {} sats (value after stage1 {} - Charlie's total {})",
                expected_alice_total, value_after_stage1, charlie_total_after_stage1
            );
            println!("   ✓ Alice's proofs total {} sats (remainder after Charlie's {} sats)", alice_total_after_stage1, charlie_total_after_stage1);
        }

        println!("\n✅ All {} balance iterations passed!", test_balances.len());
    }

    #[tokio::test]
    async fn test_multiple_balances_powers_of_3_with400fees() {
        use crate::test_helpers::{setup_mint_and_wallets_for_demo, mint_deterministic_outputs};

        // 1. Generate keys for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        // 2. Setup mint and wallets
        let channel_unit = CurrencyUnit::Sat;
        let input_fee_ppk = 400; // 40% fee for testing
        let base = 3; // Powers of 3 as the mint's amounts: 1,3,9,27,...
        let (mint_connection, _alice_wallet, _charlie_wallet, _mint_url) =
            setup_mint_and_wallets_for_demo(None, channel_unit.clone(), input_fee_ppk, base).await.unwrap();

        // 3. Get active keyset info
        let keyset_info =
            crate::test_helpers::get_active_keyset_info(&*mint_connection, &channel_unit).await.unwrap();

        // Common channel parameters
        let capacity = 100_000u64;
        let locktime = unix_time() + 86400;
        let setup_timestamp = unix_time();
        let maximum_amount_for_one_output = 10_000u64;

        // Test with multiple balances: 0-10, powers of 10 (100, 1000, 10000), and 99990-100000
        let test_balances: Vec<u64> = (0..=10)
            .chain([100, 1000, 10000])
            .chain(capacity-10..=capacity)
            .collect();

        for (i, charlie_balance) in test_balances.iter().enumerate() {
            println!("\n=== Test iteration {} with balance {} ===", i + 1, charlie_balance);

            // 4. Create channel parameters (unique nonce for each iteration)
            let sender_nonce = format!("test_nonce_{}", i);
            let channel_params = SpilmanChannelParameters::new(
                alice_pubkey,
                charlie_pubkey,
                "local".to_string(),
                channel_unit.clone(),
                capacity,
                locktime,
                setup_timestamp,
                sender_nonce,
                keyset_info.clone(),
                maximum_amount_for_one_output,
            ).unwrap();

            // 5. Create channel extra (computes shared secret internally)
            let channel_extra = SpilmanChannelExtra::new_with_secret_key(channel_params, &alice_secret).unwrap();

            // 6. Calculate funding token size and mint it
            let funding_token_nominal = channel_extra.get_total_funding_token_amount().unwrap();

            let funding_proofs = crate::test_helpers::create_funding_proofs(
                &*mint_connection,
                &channel_extra,
                funding_token_nominal,
            ).await.unwrap();

            // 7. Create established channel
            let channel = EstablishedChannel::new(channel_extra, funding_proofs).unwrap();

            // 8. Create SpilmanChannelSender (Alice's view)
            let sender = SpilmanChannelSender::new(alice_secret.clone(), channel.clone());

            // 9. Test creating a balance update
            let (balance_update, mut swap_request) = sender.create_signed_balance_update(
                *charlie_balance
            ).unwrap();

            // 10. Verify the balance update has the expected amount
            assert_eq!(balance_update.amount, *charlie_balance);
            assert_eq!(balance_update.channel_id, sender.channel_id());

            // 11. Charlie verifies the signature against the channel (doesn't need sender object)
            balance_update.verify_sender_signature(&channel).unwrap();

            // 12. Charlie can now add his signature
            swap_request.sign_sig_all(charlie_secret.clone()).unwrap();

            // Print swap request details
            println!("   Swap inputs: {:?}", swap_request.inputs().iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
            println!("   Swap outputs: {:?}", swap_request.outputs().iter().map(|bm| u64::from(bm.amount)).collect::<Vec<_>>());

            // 13. Execute the swap
            let swap_response = mint_connection.process_swap(swap_request).await.unwrap();

            // 14. Unblind the swap signatures to get stage 1 proofs for both parties
            let (charlie_stage1_proofs, alice_stage1_proofs) = crate::test_helpers::unblind_commitment_proofs(
                &sender.channel.extra,
                *charlie_balance,
                swap_response.signatures,
            ).unwrap();

            println!("   ✓ Unblinded {} proofs for Charlie, {} for Alice",
                     charlie_stage1_proofs.len(), alice_stage1_proofs.len());

            println!("   Charlie's proofs: {:?}", charlie_stage1_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
            println!("   Alice's proofs: {:?}", alice_stage1_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());

            // Verify that Charlie's proofs total the inverse of the balance
            let charlie_total_after_stage1: u64 = charlie_stage1_proofs.iter().map(|p| u64::from(p.amount)).sum();
            let inverse_result = sender.channel.extra.params.keyset_info.inverse_deterministic_value_after_fees(
                *charlie_balance,
                sender.channel.extra.params.maximum_amount_for_one_output
            ).unwrap();
            let expected_nominal = inverse_result.nominal_value;
            assert_eq!(
                charlie_total_after_stage1, expected_nominal,
                "Charlie's proofs should total {} sats (inverse of balance {})", expected_nominal, charlie_balance
            );
            println!("   ✓ Charlie's proofs total {} sats (inverse of balance {} sats)", charlie_total_after_stage1, charlie_balance);

            // Verify that Alice's proofs total the remainder after Charlie's allocation
            let alice_total_after_stage1: u64 = alice_stage1_proofs.iter().map(|p| u64::from(p.amount)).sum();
            let value_after_stage1 = sender.channel.extra.get_value_after_stage1().unwrap();
            let expected_alice_total = value_after_stage1 - charlie_total_after_stage1;
            assert_eq!(
                alice_total_after_stage1, expected_alice_total,
                "Alice's proofs should total {} sats (value after stage1 {} - Charlie's total {})",
                expected_alice_total, value_after_stage1, charlie_total_after_stage1
            );
            println!("   ✓ Alice's proofs total {} sats (remainder after Charlie's {} sats)", alice_total_after_stage1, charlie_total_after_stage1);
        }

        println!("\n✅ All {} balance iterations passed!", test_balances.len());
    }

    #[tokio::test]
    async fn test_multiple_balances_powers_of_2_zerofees() {
        use crate::test_helpers::{setup_mint_and_wallets_for_demo, mint_deterministic_outputs};

        // 1. Generate keys for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        // 2. Setup mint and wallets
        let channel_unit = CurrencyUnit::Sat;
        let input_fee_ppk = 0; // no fees
        let base = 2; // Powers of 2 as the mint's amounts: 1,2,4,8,...
        let (mint_connection, alice_wallet, charlie_wallet, _mint_url) =
            setup_mint_and_wallets_for_demo(None, channel_unit.clone(), input_fee_ppk, base).await.unwrap();

        // 3. Get active keyset info
        let keyset_info =
            crate::test_helpers::get_active_keyset_info(&*mint_connection, &channel_unit).await.unwrap();

        // Common channel parameters
        let capacity = 100_000u64;
        let locktime = unix_time() + 86400;
        let setup_timestamp = unix_time();
        let maximum_amount_for_one_output = 10_000u64;

        // Test with multiple balances: 0-10, powers of 10 (100, 1000, 10000), and 99990-100000
        let test_balances: Vec<u64> = (0..=10)
            .chain([100, 1000, 10000])
            .chain(capacity-10..=capacity)
            .collect();

        for (i, charlie_balance) in test_balances.iter().enumerate() {
            println!("\n=== Test iteration {} with balance {} ===", i + 1, charlie_balance);

            // 4. Create channel parameters (unique nonce for each iteration)
            let sender_nonce = format!("test_nonce_{}", i);
            let channel_params = SpilmanChannelParameters::new(
                alice_pubkey,
                charlie_pubkey,
                "local".to_string(),
                channel_unit.clone(),
                capacity,
                locktime,
                setup_timestamp,
                sender_nonce,
                keyset_info.clone(),
                maximum_amount_for_one_output,
            ).unwrap();

            // 5. Create channel extra (computes shared secret internally)
            let channel_extra = SpilmanChannelExtra::new_with_secret_key(channel_params, &alice_secret).unwrap();

            // 6. Calculate funding token size and mint it
            let funding_token_nominal = channel_extra.get_total_funding_token_amount().unwrap();

            let funding_proofs = crate::test_helpers::create_funding_proofs(
                &*mint_connection,
                &channel_extra,
                funding_token_nominal,
            ).await.unwrap();

            // 7. Create established channel
            let channel = EstablishedChannel::new(channel_extra, funding_proofs).unwrap();

            // 8. Create SpilmanChannelSender (Alice's view)
            let sender = SpilmanChannelSender::new(alice_secret.clone(), channel.clone());

            // 9. Test creating a balance update
            let (balance_update, mut swap_request) = sender.create_signed_balance_update(
                *charlie_balance
            ).unwrap();

            // 10. Verify the balance update has the expected amount
            assert_eq!(balance_update.amount, *charlie_balance);
            assert_eq!(balance_update.channel_id, sender.channel_id());

            // 11. Charlie verifies the signature against the channel (doesn't need sender object)
            balance_update.verify_sender_signature(&channel).unwrap();

            // 12. Charlie can now add his signature
            swap_request.sign_sig_all(charlie_secret.clone()).unwrap();

            // Print swap request details
            println!("   Swap inputs: {:?}", swap_request.inputs().iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
            println!("   Swap outputs: {:?}", swap_request.outputs().iter().map(|bm| u64::from(bm.amount)).collect::<Vec<_>>());

            // 13. Execute the swap
            let swap_response = mint_connection.process_swap(swap_request).await.unwrap();

            // 14. Unblind the swap signatures to get stage 1 proofs for both parties
            let (charlie_stage1_proofs, alice_stage1_proofs) = crate::test_helpers::unblind_commitment_proofs(
                &sender.channel.extra,
                *charlie_balance,
                swap_response.signatures,
            ).unwrap();

            println!("   ✓ Unblinded {} proofs for Charlie, {} for Alice",
                     charlie_stage1_proofs.len(), alice_stage1_proofs.len());

            println!("   Charlie's proofs: {:?}", charlie_stage1_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
            println!("   Alice's proofs: {:?}", alice_stage1_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());

            // Verify that Charlie's proofs total the inverse of the balance
            let charlie_total_after_stage1: u64 = charlie_stage1_proofs.iter().map(|p| u64::from(p.amount)).sum();
            let inverse_result = sender.channel.extra.params.keyset_info.inverse_deterministic_value_after_fees(
                *charlie_balance,
                sender.channel.extra.params.maximum_amount_for_one_output
            ).unwrap();
            let expected_nominal = inverse_result.nominal_value;
            assert_eq!(
                charlie_total_after_stage1, expected_nominal,
                "Charlie's proofs should total {} sats (inverse of balance {})", expected_nominal, charlie_balance
            );
            println!("   ✓ Charlie's proofs total {} sats (inverse of balance {} sats)", charlie_total_after_stage1, charlie_balance);

            // Verify that Alice's proofs total the remainder after Charlie's allocation
            let alice_total_after_stage1: u64 = alice_stage1_proofs.iter().map(|p| u64::from(p.amount)).sum();
            let value_after_stage1 = sender.channel.extra.get_value_after_stage1().unwrap();
            let expected_alice_total = value_after_stage1 - charlie_total_after_stage1;
            assert_eq!(
                alice_total_after_stage1, expected_alice_total,
                "Alice's proofs should total {} sats (value after stage1 {} - Charlie's total {})",
                expected_alice_total, value_after_stage1, charlie_total_after_stage1
            );
            println!("   ✓ Alice's proofs total {} sats (remainder after Charlie's {} sats)", alice_total_after_stage1, charlie_total_after_stage1);

            // 15. Receive proofs into both wallets
            let (charlie_received, _alice_received) = crate::test_helpers::receive_proofs_into_both_wallets(
                &charlie_wallet,
                charlie_stage1_proofs,
                charlie_secret.clone(),
                &alice_wallet,
                alice_stage1_proofs,
                alice_secret.clone(),
            ).await.unwrap();

            // 16. Assert Charlie's received amount matches the de facto balance
            let charlie_de_facto_balance = sender.get_de_facto_balance(*charlie_balance).unwrap();
            assert_eq!(
                charlie_received, charlie_de_facto_balance,
                "Charlie's received amount ({}) should match de facto balance ({})",
                charlie_received, charlie_de_facto_balance
            );
            println!("   ✓ Charlie received {} sats (de facto balance)", charlie_received);
        }

        println!("\n✅ All {} balance iterations passed!", test_balances.len());
    }

    #[tokio::test]
    async fn test_multiple_balances_powers_of_2_with400fees() {
        use crate::test_helpers::{setup_mint_and_wallets_for_demo, mint_deterministic_outputs};

        // 1. Generate keys for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        // 2. Setup mint and wallets
        let channel_unit = CurrencyUnit::Sat;
        let input_fee_ppk = 400; // 40% fee for testing
        let base = 2; // Powers of 2 as the mint's amounts: 1,2,4,8,...
        let (mint_connection, alice_wallet, charlie_wallet, _mint_url) =
            setup_mint_and_wallets_for_demo(None, channel_unit.clone(), input_fee_ppk, base).await.unwrap();

        // 3. Get active keyset info
        let keyset_info =
            crate::test_helpers::get_active_keyset_info(&*mint_connection, &channel_unit).await.unwrap();

        // Common channel parameters
        let capacity = 100_000u64;
        let locktime = unix_time() + 86400;
        let setup_timestamp = unix_time();
        let maximum_amount_for_one_output = 10_000u64;

        // Test with multiple balances: 0-10, powers of 10 (100, 1000, 10000), and 99990-100000
        let test_balances: Vec<u64> = (0..=10)
            .chain([100, 1000, 10000])
            .chain(capacity-10..=capacity)
            .collect();

        for (i, charlie_balance) in test_balances.iter().enumerate() {
            println!("\n=== Test iteration {} with balance {} ===", i + 1, charlie_balance);

            // 4. Create channel parameters (unique nonce for each iteration)
            let sender_nonce = format!("test_nonce_{}", i);
            let channel_params = SpilmanChannelParameters::new(
                alice_pubkey,
                charlie_pubkey,
                "local".to_string(),
                channel_unit.clone(),
                capacity,
                locktime,
                setup_timestamp,
                sender_nonce,
                keyset_info.clone(),
                maximum_amount_for_one_output,
            ).unwrap();

            // 5. Create channel extra (computes shared secret internally)
            let channel_extra = SpilmanChannelExtra::new_with_secret_key(channel_params, &alice_secret).unwrap();

            // 6. Calculate funding token size and mint it
            let funding_token_nominal = channel_extra.get_total_funding_token_amount().unwrap();

            let funding_proofs = crate::test_helpers::create_funding_proofs(
                &*mint_connection,
                &channel_extra,
                funding_token_nominal,
            ).await.unwrap();

            // 7. Create established channel
            let channel = EstablishedChannel::new(channel_extra, funding_proofs).unwrap();

            // 8. Create SpilmanChannelSender (Alice's view)
            let sender = SpilmanChannelSender::new(alice_secret.clone(), channel.clone());

            // 9. Test creating a balance update
            let (balance_update, mut swap_request) = sender.create_signed_balance_update(
                *charlie_balance
            ).unwrap();

            // 10. Verify the balance update has the expected amount
            assert_eq!(balance_update.amount, *charlie_balance);
            assert_eq!(balance_update.channel_id, sender.channel_id());

            // 11. Charlie verifies the signature against the channel (doesn't need sender object)
            balance_update.verify_sender_signature(&channel).unwrap();

            // 12. Charlie can now add his signature
            swap_request.sign_sig_all(charlie_secret.clone()).unwrap();

            // Print swap request details
            println!("   Swap inputs: {:?}", swap_request.inputs().iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
            println!("   Swap outputs: {:?}", swap_request.outputs().iter().map(|bm| u64::from(bm.amount)).collect::<Vec<_>>());

            // 13. Execute the swap
            let swap_response = mint_connection.process_swap(swap_request).await.unwrap();

            // 14. Unblind the swap signatures to get stage 1 proofs for both parties
            let (charlie_stage1_proofs, alice_stage1_proofs) = crate::test_helpers::unblind_commitment_proofs(
                &sender.channel.extra,
                *charlie_balance,
                swap_response.signatures,
            ).unwrap();

            println!("   ✓ Unblinded {} proofs for Charlie, {} for Alice",
                     charlie_stage1_proofs.len(), alice_stage1_proofs.len());

            println!("   Charlie's proofs: {:?}", charlie_stage1_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
            println!("   Alice's proofs: {:?}", alice_stage1_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());

            // Verify that Charlie's proofs total the inverse of the balance
            let charlie_total_after_stage1: u64 = charlie_stage1_proofs.iter().map(|p| u64::from(p.amount)).sum();
            let inverse_result = sender.channel.extra.params.keyset_info.inverse_deterministic_value_after_fees(
                *charlie_balance,
                sender.channel.extra.params.maximum_amount_for_one_output
            ).unwrap();
            let expected_nominal = inverse_result.nominal_value;
            assert_eq!(
                charlie_total_after_stage1, expected_nominal,
                "Charlie's proofs should total {} sats (inverse of balance {})", expected_nominal, charlie_balance
            );
            println!("   ✓ Charlie's proofs total {} sats (inverse of balance {} sats)", charlie_total_after_stage1, charlie_balance);

            // Verify that Alice's proofs total the remainder after Charlie's allocation
            let alice_total_after_stage1: u64 = alice_stage1_proofs.iter().map(|p| u64::from(p.amount)).sum();
            let value_after_stage1 = sender.channel.extra.get_value_after_stage1().unwrap();
            let expected_alice_total = value_after_stage1 - charlie_total_after_stage1;
            assert_eq!(
                alice_total_after_stage1, expected_alice_total,
                "Alice's proofs should total {} sats (value after stage1 {} - Charlie's total {})",
                expected_alice_total, value_after_stage1, charlie_total_after_stage1
            );
            println!("   ✓ Alice's proofs total {} sats (remainder after Charlie's {} sats)", alice_total_after_stage1, charlie_total_after_stage1);

            // 15. Receive proofs into both wallets
            let (charlie_received, _alice_received) = crate::test_helpers::receive_proofs_into_both_wallets(
                &charlie_wallet,
                charlie_stage1_proofs,
                charlie_secret.clone(),
                &alice_wallet,
                alice_stage1_proofs,
                alice_secret.clone(),
            ).await.unwrap();

            // 16. Assert Charlie's received amount matches the de facto balance
            let charlie_de_facto_balance = sender.get_de_facto_balance(*charlie_balance).unwrap();
            assert_eq!(
                charlie_received, charlie_de_facto_balance,
                "Charlie's received amount ({}) should match de facto balance ({})",
                charlie_received, charlie_de_facto_balance
            );
            println!("   ✓ Charlie received {} sats (de facto balance)", charlie_received);
        }

        println!("\n✅ All {} balance iterations passed!", test_balances.len());
    }

    #[tokio::test]
    async fn test_multiple_balances_powers_of_2_with10fees() {
        use crate::test_helpers::{setup_mint_and_wallets_for_demo, mint_deterministic_outputs};

        // 1. Generate keys for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        // 2. Setup mint and wallets
        let channel_unit = CurrencyUnit::Sat;
        let input_fee_ppk = 10; // 1% fee (realistic production fee)
        let base = 2; // Powers of 2 as the mint's amounts: 1,2,4,8,...
        let (mint_connection, alice_wallet, charlie_wallet, _mint_url) =
            setup_mint_and_wallets_for_demo(None, channel_unit.clone(), input_fee_ppk, base).await.unwrap();

        // 3. Get active keyset info
        let keyset_info =
            crate::test_helpers::get_active_keyset_info(&*mint_connection, &channel_unit).await.unwrap();

        // Common channel parameters
        let capacity = 100_000u64;
        let locktime = unix_time() + 86400;
        let setup_timestamp = unix_time();
        let maximum_amount_for_one_output = 10_000u64;

        // Test with multiple balances: 0-10, powers of 10 (100, 1000, 10000), and 99990-100000
        let test_balances: Vec<u64> = (0..=10)
            .chain([100, 1000, 10000])
            .chain(capacity-10..=capacity)
            .collect();

        for (i, charlie_balance) in test_balances.iter().enumerate() {
            println!("\n=== Test iteration {} with balance {} ===", i + 1, charlie_balance);

            // 4. Create channel parameters (unique nonce for each iteration)
            let sender_nonce = format!("test_nonce_{}", i);
            let channel_params = SpilmanChannelParameters::new(
                alice_pubkey,
                charlie_pubkey,
                "local".to_string(),
                channel_unit.clone(),
                capacity,
                locktime,
                setup_timestamp,
                sender_nonce,
                keyset_info.clone(),
                maximum_amount_for_one_output,
            ).unwrap();

            // 5. Create channel extra (computes shared secret internally)
            let channel_extra = SpilmanChannelExtra::new_with_secret_key(channel_params, &alice_secret).unwrap();

            // 6. Calculate funding token size and mint it
            let funding_token_nominal = channel_extra.get_total_funding_token_amount().unwrap();

            let funding_proofs = crate::test_helpers::create_funding_proofs(
                &*mint_connection,
                &channel_extra,
                funding_token_nominal,
            ).await.unwrap();

            // 7. Create established channel
            let channel = EstablishedChannel::new(channel_extra, funding_proofs).unwrap();

            // 8. Create SpilmanChannelSender (Alice's view)
            let sender = SpilmanChannelSender::new(alice_secret.clone(), channel.clone());

            // 9. Test creating a balance update
            let (balance_update, mut swap_request) = sender.create_signed_balance_update(
                *charlie_balance
            ).unwrap();

            // 10. Verify the balance update has the expected amount
            assert_eq!(balance_update.amount, *charlie_balance);
            assert_eq!(balance_update.channel_id, sender.channel_id());

            // 11. Charlie verifies the signature against the channel (doesn't need sender object)
            balance_update.verify_sender_signature(&channel).unwrap();

            // 12. Charlie can now add his signature
            swap_request.sign_sig_all(charlie_secret.clone()).unwrap();

            // Print swap request details
            println!("   Swap inputs: {:?}", swap_request.inputs().iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
            println!("   Swap outputs: {:?}", swap_request.outputs().iter().map(|bm| u64::from(bm.amount)).collect::<Vec<_>>());

            // 13. Execute the swap
            let swap_response = mint_connection.process_swap(swap_request).await.unwrap();

            // 14. Unblind the swap signatures to get stage 1 proofs for both parties
            let (charlie_stage1_proofs, alice_stage1_proofs) = crate::test_helpers::unblind_commitment_proofs(
                &sender.channel.extra,
                *charlie_balance,
                swap_response.signatures,
            ).unwrap();

            println!("   ✓ Unblinded {} proofs for Charlie, {} for Alice",
                     charlie_stage1_proofs.len(), alice_stage1_proofs.len());

            println!("   Charlie's proofs: {:?}", charlie_stage1_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
            println!("   Alice's proofs: {:?}", alice_stage1_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());

            // Verify that Charlie's proofs total the inverse of the balance
            let charlie_total_after_stage1: u64 = charlie_stage1_proofs.iter().map(|p| u64::from(p.amount)).sum();
            let inverse_result = sender.channel.extra.params.keyset_info.inverse_deterministic_value_after_fees(
                *charlie_balance,
                sender.channel.extra.params.maximum_amount_for_one_output
            ).unwrap();
            let expected_nominal = inverse_result.nominal_value;
            assert_eq!(
                charlie_total_after_stage1, expected_nominal,
                "Charlie's proofs should total {} sats (inverse of balance {})", expected_nominal, charlie_balance
            );
            println!("   ✓ Charlie's proofs total {} sats (inverse of balance {} sats)", charlie_total_after_stage1, charlie_balance);

            // Verify that Alice's proofs total the remainder after Charlie's allocation
            let alice_total_after_stage1: u64 = alice_stage1_proofs.iter().map(|p| u64::from(p.amount)).sum();
            let value_after_stage1 = sender.channel.extra.get_value_after_stage1().unwrap();
            let expected_alice_total = value_after_stage1 - charlie_total_after_stage1;
            assert_eq!(
                alice_total_after_stage1, expected_alice_total,
                "Alice's proofs should total {} sats (value after stage1 {} - Charlie's total {})",
                expected_alice_total, value_after_stage1, charlie_total_after_stage1
            );
            println!("   ✓ Alice's proofs total {} sats (remainder after Charlie's {} sats)", alice_total_after_stage1, charlie_total_after_stage1);

            // 15. Receive proofs into both wallets
            let (charlie_received, _alice_received) = crate::test_helpers::receive_proofs_into_both_wallets(
                &charlie_wallet,
                charlie_stage1_proofs,
                charlie_secret.clone(),
                &alice_wallet,
                alice_stage1_proofs,
                alice_secret.clone(),
            ).await.unwrap();

            // 16. Assert Charlie's received amount matches the de facto balance
            let charlie_de_facto_balance = sender.get_de_facto_balance(*charlie_balance).unwrap();
            assert_eq!(
                charlie_received, charlie_de_facto_balance,
                "Charlie's received amount ({}) should match de facto balance ({})",
                charlie_received, charlie_de_facto_balance
            );
            println!("   ✓ Charlie received {} sats (de facto balance)", charlie_received);
        }

        println!("\n✅ All {} balance iterations passed!", test_balances.len());
    }

    #[tokio::test]
    async fn test_many_inexact_payments_across_some_capacities_1_to_50() {
        let max_capacity = 50;
        let input_fee_ppk = 400; // 4% fee


        use crate::test_helpers::setup_mint_and_wallets_for_demo;

        // 1. Generate keys for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        let channel_unit = CurrencyUnit::Sat;
        let base = 2; // Powers of 2
        let (mint_connection, alice_wallet, charlie_wallet, _mint_url) =
            setup_mint_and_wallets_for_demo(None, channel_unit.clone(), input_fee_ppk, base).await.unwrap();

        // Get keyset info
        let keyset_info =
            crate::test_helpers::get_active_keyset_info(&*mint_connection, &channel_unit).await.unwrap();

        println!("\n=== Inverse and Double-Inverse Fee Calculations (fee={}ppk) ===", keyset_info.input_fee_ppk);
        println!("{:>10} | {:>12} {:>12} | {:>12} {:>12}",
            "target", "inverse_nom", "inverse_act", "dbl_inv_nom", "dbl_inv_act");
        println!("{}", "-".repeat(70));

        let mut inexact_targets: Vec<u64> = Vec::new();

        let max_amount = 10_000u64; // Match the maximum_amount_for_one_output used later in the test

        for capacity in 1..=max_capacity {
            // Find capacities where the stage 1 inverse is 'inexact', i.e. where the

            // start by finding the nominal value of the stage1 outputs necessary
            let inverse_of_the_second_stage = keyset_info.inverse_deterministic_value_after_fees(capacity, max_amount).unwrap();

            // Double inverse: apply inverse a second time, to 'undo' stage 1, like the funding token calculation
            let double_inverse = keyset_info.inverse_deterministic_value_after_fees(inverse_of_the_second_stage.nominal_value, max_amount).unwrap();

            // now check of the actual outputs of stage1 are different from (bigger than) the exact
            // minimum required as input to stage 2:
            let stage1_is_inexact = double_inverse.actual_balance != inverse_of_the_second_stage.nominal_value;

            if stage1_is_inexact {
                inexact_targets.push(capacity);
            }
        }

        println!("\n✅ Printed inverse calculations for 1-10000");
        println!("\n=== Inexact targets ({} total) ===", inexact_targets.len());
        println!("{:?}", inexact_targets);

        // Now test channel creation for each inexact target
        println!("\n=== Testing channels for inexact targets ===");

        let locktime = unix_time() + 86400;
        let setup_timestamp = unix_time();
        let maximum_amount_for_one_output = 10_000u64;

        let mut total_payments = 0u64;

        for (i, &capacity) in inexact_targets.iter().enumerate() {
            // For each inexact capacity, test only inexact charlie_balance values
            for charlie_balance in 1..=capacity {
                let charlie_de_facto_balance = keyset_info.inverse_deterministic_value_after_fees(charlie_balance, max_amount).unwrap().actual_balance;
                if charlie_de_facto_balance == charlie_balance {
                    continue;
                }

                println!("\ncapacity={}, charlie_balance={}", capacity, charlie_balance);

                let sender_nonce = format!("test_nonce_{}_{}", capacity, charlie_balance);
                let channel_params = SpilmanChannelParameters::new(
                alice_pubkey,
                charlie_pubkey,
                "local".to_string(),
                channel_unit.clone(),
                capacity,
                locktime,
                setup_timestamp,
                sender_nonce,
                keyset_info.clone(),
                maximum_amount_for_one_output,
            ).unwrap();

            let channel_extra = SpilmanChannelExtra::new_with_secret_key(channel_params, &alice_secret).unwrap();

            let funding_token_nominal = channel_extra.get_total_funding_token_amount().unwrap();

            let funding_proofs = crate::test_helpers::create_funding_proofs(
                &*mint_connection,
                &channel_extra,
                funding_token_nominal,
            ).await.unwrap();

            let channel = EstablishedChannel::new(channel_extra, funding_proofs).unwrap();

            let sender = SpilmanChannelSender::new(alice_secret.clone(), channel.clone());

            // Create balance update with charlie_balance == capacity
            let (balance_update, mut swap_request) = sender.create_signed_balance_update(
                charlie_balance
            ).unwrap();

            // Charlie verifies and signs
            balance_update.verify_sender_signature(&channel).unwrap();
            swap_request.sign_sig_all(charlie_secret.clone()).unwrap();

            // Execute the swap
            let swap_response = mint_connection.process_swap(swap_request).await.unwrap();

            // Unblind proofs
            let (charlie_stage1_proofs, alice_stage1_proofs) = crate::test_helpers::unblind_commitment_proofs(
                &sender.channel.extra,
                charlie_balance,
                swap_response.signatures,
            ).unwrap();

            // Receive into both wallets
            let (charlie_received, alice_received) = crate::test_helpers::receive_proofs_into_both_wallets(
                &charlie_wallet,
                charlie_stage1_proofs,
                charlie_secret.clone(),
                &alice_wallet,
                alice_stage1_proofs,
                alice_secret.clone(),
            ).await.unwrap();

                // Assert Charlie's received amount matches the de facto balance
                assert_eq!(
                    charlie_received, charlie_de_facto_balance,
                    "capacity={}, charlie_balance={}: received ({}) should match de facto balance ({})",
                    capacity, charlie_balance, charlie_received, charlie_de_facto_balance
                );

                println!("  charlie_received={}, alice_received={}", charlie_received, alice_received);

                total_payments += 1;
            }

            if (i + 1) % 100 == 0 {
                println!("   ✓ Tested {} / {} inexact targets ({} payments so far)", i + 1, inexact_targets.len(), total_payments);
            }
        }

        println!("\n✅ All {} inexact target channels passed! ({} total payments)", inexact_targets.len(), total_payments);
    }

    #[tokio::test]
    async fn test_shared_secret_matches() {
        use crate::test_helpers::setup_mint_and_wallets_for_demo;

        // 1. Generate keys for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        // 2. Setup mint and wallets
        let channel_unit = CurrencyUnit::Sat;
        let input_fee_ppk = 0;
        let base = 2;
        let (mint_connection, _alice_wallet, _charlie_wallet, _mint_url) =
            setup_mint_and_wallets_for_demo(None, channel_unit.clone(), input_fee_ppk, base).await.unwrap();

        // 3. Get active keyset info
        let keyset_info =
            crate::test_helpers::get_active_keyset_info(&*mint_connection, &channel_unit).await.unwrap();

        // 4. Create channel parameters
        let capacity = 10_000u64;
        let locktime = unix_time() + 86400;
        let setup_timestamp = unix_time();
        let sender_nonce = "test_shared_secret".to_string();
        let maximum_amount_for_one_output = 10_000u64;

        let channel_params = SpilmanChannelParameters::new(
            alice_pubkey,
            charlie_pubkey,
            "local".to_string(),
            channel_unit.clone(),
            capacity,
            locktime,
            setup_timestamp,
            sender_nonce,
            keyset_info.clone(),
            maximum_amount_for_one_output,
        ).unwrap();

        // 5. Create channel extra (computes shared secret internally)
        let channel_extra = SpilmanChannelExtra::new_with_secret_key(channel_params, &alice_secret).unwrap();

        // 6. Create funding proofs and channel
        let funding_token_nominal = channel_extra.get_total_funding_token_amount().unwrap();
        let funding_proofs = crate::test_helpers::create_funding_proofs(
            &*mint_connection,
            &channel_extra,
            funding_token_nominal,
        ).await.unwrap();

        let channel = EstablishedChannel::new(channel_extra, funding_proofs).unwrap();

        // 7. Create Sender and Receiver
        let sender = SpilmanChannelSender::new(alice_secret, channel.clone());
        let receiver = SpilmanChannelReceiver::new(charlie_secret, channel);

        // 8. Get shared secrets from both parties (now stored in channel extra)
        let sender_shared_secret = sender.get_shared_secret();
        let receiver_shared_secret = receiver.get_shared_secret();

        // 9. Assert they are the same (both should point to the same shared_secret stored in Extra)
        assert_eq!(
            sender_shared_secret,
            receiver_shared_secret,
            "Sender and Receiver should have the same shared secret"
        );

        println!("Shared secret (hex): {}", cdk::util::hex::encode(sender_shared_secret));
        println!("✅ Sender and Receiver have the same shared secret!");
    }
}
