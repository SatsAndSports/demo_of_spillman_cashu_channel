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
    async fn test_sender_create_balance_update() {
        use crate::test_helpers::{setup_mint_and_wallets_for_demo, mint_deterministic_outputs};

        // 1. Generate keys for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        // 2. Setup mint and wallets
        let channel_unit = CurrencyUnit::Sat;
        let input_fee_ppk = 400; // 40% fee for testing
        let (mint_connection, _alice_wallet, _charlie_wallet, _mint_url) =
            setup_mint_and_wallets_for_demo(None, channel_unit.clone(), input_fee_ppk).await.unwrap();

        // 3. Get active keyset info
        let all_keysets = mint_connection.get_keys().await.unwrap();
        let keysets_info = mint_connection.get_keysets().await.unwrap();
        let active_keyset_info = keysets_info.keysets.iter()
            .find(|k| k.active && k.unit == channel_unit)
            .unwrap();
        let active_keyset_id = active_keyset_info.id;
        let input_fee_ppk = active_keyset_info.input_fee_ppk;
        let active_keys = all_keysets.iter()
            .find(|k| k.id == active_keyset_id)
            .unwrap()
            .keys.clone();

        // 4. Create channel parameters
        let capacity = 100_000u64;
        let locktime = unix_time() + 86400;
        let setup_timestamp = unix_time();
        let sender_nonce = "test_nonce".to_string();
        let maximum_amount_for_one_output = 100_000u64;

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

        let funding_outputs = crate::extra::SetOfDeterministicOutputs::new(
            &channel_extra.keyset_info.amounts_in_this_keyset_largest_first,
            "funding".to_string(),
            funding_token_nominal,
            channel_extra.params.clone(),
        ).unwrap();

        let funding_blinded_messages = funding_outputs.get_blinded_messages().unwrap();
        let funding_secrets_with_blinding = funding_outputs.get_secrets_with_blinding().unwrap();

        let funding_proofs = mint_deterministic_outputs(
            &*mint_connection,
            channel_extra.params.unit.clone(),
            funding_blinded_messages,
            funding_secrets_with_blinding,
            &active_keys,
        ).await.unwrap();

        // 7. Create established channel
        let channel = EstablishedChannel::new(channel_extra, funding_proofs).unwrap();

        // 8. Create SpilmanChannelSender
        let sender = SpilmanChannelSender::new(alice_secret.clone(), channel);

        // 9. Test creating a balance update
        let charlie_intended_balance = 10_000u64;
        let (balance_update, mut swap_request) = sender.create_signed_balance_update(
            charlie_intended_balance
        ).unwrap();

        // 10. Verify the balance update has Alice's signature
        assert_eq!(balance_update.amount, charlie_intended_balance);
        assert_eq!(balance_update.channel_id, sender.channel_id());

        // 11. Verify that the signature can be verified against the channel
        balance_update.verify_sender_signature(&sender.channel).unwrap();

        // 12. Charlie can now add his signature
        swap_request.sign_sig_all(charlie_secret).unwrap();

        // 13. Execute the swap to verify it works
        let _swap_response = mint_connection.process_swap(swap_request).await.unwrap();

        println!("✅ Sender balance update test passed!");
    }
}
