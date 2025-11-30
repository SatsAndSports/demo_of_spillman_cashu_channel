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
        let (active_keyset_id, input_fee_ppk, active_keys) =
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
            active_keyset_id,
            input_fee_ppk,
            maximum_amount_for_one_output,
        ).unwrap();

        // 5. Create channel extra
        let channel_extra = SpilmanChannelExtra::new(channel_params, active_keys.clone()).unwrap();

        // 6. Calculate funding token size and mint it
        let funding_token_nominal = channel_extra.get_total_funding_token_amount().unwrap();

        let funding_proofs = crate::test_helpers::create_funding_proofs(
            &*mint_connection,
            &channel_extra,
            funding_token_nominal,
        ).await.unwrap();

        // 7. Create established channel
        let channel = EstablishedChannel::new(channel_extra, funding_proofs).unwrap();

        // 8. Create SpilmanChannelSender
        let sender = SpilmanChannelSender::new(alice_secret.clone(), channel);

        // 9. Test creating a balance update
        let charlie_intended_balance = 10_000u64;
        let charlie_de_facto_balance = sender.get_de_facto_balance(charlie_intended_balance).unwrap();
        let (balance_update, mut swap_request) = sender.create_signed_balance_update(
            charlie_intended_balance
        ).unwrap();

        // 10. Verify the balance update has Alice's signature
        assert_eq!(balance_update.amount, charlie_intended_balance);
        assert_eq!(balance_update.channel_id, sender.channel_id());

        // 11. Verify that the signature can be verified against the channel
        balance_update.verify_sender_signature(&sender.channel).unwrap();

        // 12. Charlie can now add his signature
        swap_request.sign_sig_all(charlie_secret.clone()).unwrap();

        // Print swap request details
        println!("   Swap inputs: {:?}", swap_request.inputs().iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
        println!("   Swap outputs: {:?}", swap_request.outputs().iter().map(|bm| u64::from(bm.amount)).collect::<Vec<_>>());

        // 13. Execute the swap
        let swap_response = mint_connection.process_swap(swap_request).await.unwrap();

        // 14. Create commitment outputs to get the secrets for unblinding
        let commitment_outputs = sender.channel.extra.create_two_sets_of_outputs_for_balance(
            charlie_intended_balance
        ).unwrap();

        // 15. Unblind the signatures to get the commitment proofs
        let (charlie_proofs, alice_proofs) = commitment_outputs.unblind_all(
            swap_response.signatures,
            &sender.channel.extra.keyset_info.active_keys,
        ).unwrap();

        println!("   ✓ Unblinded {} proofs for Charlie, {} for Alice",
                 charlie_proofs.len(), alice_proofs.len());

        println!("   Charlie's proofs: {:?}", charlie_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
        println!("   Alice's proofs: {:?}", alice_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());

        // 16. Both parties receive their proofs into wallets
        use crate::test_helpers::receive_proofs_into_wallet;
        println!("   Charlie receiving proofs...");
        let charlie_received = receive_proofs_into_wallet(
            &charlie_wallet,
            charlie_proofs,
            charlie_secret,
        ).await.unwrap();
        println!("   Charlie received: {} sats", charlie_received);

        println!("   Alice receiving proofs...");
        let alice_received = receive_proofs_into_wallet(
            &alice_wallet,
            alice_proofs,
            alice_secret,
        ).await.unwrap();
        println!("   Alice received: {} sats", alice_received);

        // 17. Assert that Charlie's received amount matches the de facto balance
        assert_eq!(
            charlie_received, charlie_de_facto_balance,
            "Charlie's received amount should match get_de_facto_balance(charlie_intended_balance)"
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
        let base = 3; // Powers of 2
        let (mint_connection, alice_wallet, charlie_wallet, _mint_url) =
            setup_mint_and_wallets_for_demo(None, channel_unit.clone(), input_fee_ppk, base).await.unwrap();

        // 3. Get active keyset info
        let (active_keyset_id, input_fee_ppk, active_keys) =
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
            active_keyset_id,
            input_fee_ppk,
            maximum_amount_for_one_output,
        ).unwrap();

        // 5. Create channel extra
        let channel_extra = SpilmanChannelExtra::new(channel_params, active_keys.clone()).unwrap();

        // 6. Calculate funding token size and mint it
        let funding_token_nominal = channel_extra.get_total_funding_token_amount().unwrap();

        let funding_proofs = crate::test_helpers::create_funding_proofs(
            &*mint_connection,
            &channel_extra,
            funding_token_nominal,
        ).await.unwrap();

        // 7. Create established channel
        let channel = EstablishedChannel::new(channel_extra, funding_proofs).unwrap();

        // 8. Create SpilmanChannelSender
        let sender = SpilmanChannelSender::new(alice_secret.clone(), channel);

        // 9. Test creating a balance update
        let charlie_balance = 10_000u64;
        let charlie_de_facto_balance = sender.get_de_facto_balance(charlie_balance).unwrap();
        let (balance_update, mut swap_request) = sender.create_signed_balance_update(
            charlie_balance
        ).unwrap();

        // 10. Verify the balance update has Alice's signature
        assert_eq!(balance_update.amount, charlie_balance);
        assert_eq!(balance_update.channel_id, sender.channel_id());

        // 11. Verify that the signature can be verified against the channel
        balance_update.verify_sender_signature(&sender.channel).unwrap();

        // 12. Charlie can now add his signature
        swap_request.sign_sig_all(charlie_secret.clone()).unwrap();

        // Print swap request details
        println!("   Swap inputs: {:?}", swap_request.inputs().iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
        println!("   Swap outputs: {:?}", swap_request.outputs().iter().map(|bm| u64::from(bm.amount)).collect::<Vec<_>>());

        // 13. Execute the swap
        let swap_response = mint_connection.process_swap(swap_request).await.unwrap();

        // 14. Create commitment outputs to get the secrets for unblinding
        let commitment_outputs = sender.channel.extra.create_two_sets_of_outputs_for_balance(
            charlie_balance,
        ).unwrap();

        // 15. Unblind the signatures to get the commitment proofs
        let (charlie_proofs, alice_proofs) = commitment_outputs.unblind_all(
            swap_response.signatures,
            &sender.channel.extra.keyset_info.active_keys,
        ).unwrap();

        println!("   ✓ Unblinded {} proofs for Charlie, {} for Alice",
                 charlie_proofs.len(), alice_proofs.len());

        println!("   Charlie's proofs: {:?}", charlie_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());
        println!("   Alice's proofs: {:?}", alice_proofs.iter().map(|p| u64::from(p.amount)).collect::<Vec<_>>());

        // Verify that Charlie's proofs total the inverse of the balance
        // (the nominal value needed to achieve (de facto) charlie_balance after stage1 fees
        let charlie_total_after_stage1: u64 = charlie_proofs.iter().map(|p| u64::from(p.amount)).sum();
        let inverse_result = sender.channel.extra.keyset_info.inverse_deterministic_value_after_fees(
            charlie_balance
        ).unwrap();
        let expected_nominal = inverse_result.nominal_value;
        assert_eq!(
            charlie_total_after_stage1, expected_nominal,
            "Charlie's proofs should total {} sats (inverse of balance {})", expected_nominal, charlie_balance
        );
        println!("   ✓ Charlie's proofs total {} sats (inverse of balance {} sats)", charlie_total_after_stage1, charlie_balance);

        // Verify that Alice's proofs total the remainder after Charlie's allocation
        let alice_total_after_stage1: u64 = alice_proofs.iter().map(|p| u64::from(p.amount)).sum();
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
}
