//! Spilman Channel Outputs
//!
//! Contains deterministic output types for commitment transactions

use cdk::nuts::{BlindedMessage, BlindSignature, RestoreRequest};
use cdk::Amount;

use super::keysets_and_amounts::OrderedListOfAmounts;
use super::params::SpilmanChannelParameters;

/// A set of deterministic outputs for a specific pubkey and amount
/// This represents all the deterministic blinded messages, secrets, and blinding factors
/// for splitting a given amount into ecash outputs
#[derive(Debug, Clone)]
pub struct SetOfDeterministicOutputs {
    /// The context for these outputs: "sender", "receiver", or "funding"
    pub context: String,
    /// The total amount to allocate
    pub amount: u64,
    /// The breakdown of amounts (largest-first)
    pub ordered_amounts: OrderedListOfAmounts,
    /// Channel parameters (includes shared_secret)
    pub params: SpilmanChannelParameters,
}

/// Commitment outputs for a specific balance distribution
/// Contains the deterministic outputs for both sender (Alice) and receiver (Charlie)
/// at a specific balance point in the channel
#[derive(Debug, Clone)]
pub struct CommitmentOutputs {
    /// Receiver's (Charlie's) deterministic outputs
    pub receiver_outputs: SetOfDeterministicOutputs,
    /// Sender's (Alice's) deterministic outputs
    pub sender_outputs: SetOfDeterministicOutputs,
}

impl CommitmentOutputs {
    /// Create new commitment outputs
    pub fn new(
        receiver_outputs: SetOfDeterministicOutputs,
        sender_outputs: SetOfDeterministicOutputs,
    ) -> Self {
        Self {
            receiver_outputs,
            sender_outputs,
        }
    }

    /// Create commitment outputs for a given receiver balance
    ///
    /// Given the receiver's (Charlie's) desired final balance, this creates:
    /// - One SetOfDeterministicOutputs for the receiver (Charlie)
    /// - One SetOfDeterministicOutputs for the sender (Alice) with the remainder
    ///
    /// The process:
    /// 1. Use inverse function to find nominal value for receiver's deterministic outputs
    /// 2. Calculate sender's nominal value as: amount_after_stage1 - receiver_nominal
    /// 3. Create both sets of outputs wrapped in CommitmentOutputs
    ///
    /// Parameters:
    /// - receiver_balance: The desired final balance for the receiver (after stage 2 fees)
    /// - params: Channel parameters
    ///
    /// Returns CommitmentOutputs containing both receiver and sender outputs
    pub fn for_balance(
        receiver_balance: u64,
        params: &SpilmanChannelParameters,
    ) -> anyhow::Result<Self> {
        // Validate that receiver balance doesn't exceed channel capacity
        if receiver_balance > params.capacity {
            anyhow::bail!(
                "Receiver balance {} exceeds channel capacity {}",
                receiver_balance,
                params.capacity
            );
        }

        let max_amount = params.maximum_amount_for_one_output;

        // Get the amount available after stage 1 fees
        let amount_after_stage1 = params.get_value_after_stage1()?;

        // Find the nominal value needed for Charlie's deterministic outputs
        let inverse_result = params.keyset_info.inverse_deterministic_value_after_fees(
            receiver_balance,
            max_amount,
        )?;
        let charlie_nominal = inverse_result.nominal_value;

        // Check if there's enough left for Alice (alice_nominal would be negative otherwise)
        if charlie_nominal > amount_after_stage1 {
            anyhow::bail!(
                "Receiver balance {} requires nominal value {} which exceeds available amount {} after stage 1 fees",
                receiver_balance,
                charlie_nominal,
                amount_after_stage1
            );
        }

        let alice_nominal = amount_after_stage1 - charlie_nominal;

        // Create outputs for Charlie (receiver)
        let charlie_outputs = SetOfDeterministicOutputs::new(
            "receiver".to_string(),
            charlie_nominal,
            params.clone(),
        )?;

        // Create outputs for Alice (sender)
        let alice_outputs = SetOfDeterministicOutputs::new(
            "sender".to_string(),
            alice_nominal,
            params.clone(),
        )?;

        Ok(Self::new(charlie_outputs, alice_outputs))
    }

    /// Create an unsigned swap request from this commitment
    ///
    /// Takes the funding proofs and creates a SwapRequest with:
    /// - Inputs: all funding proofs
    /// - Outputs: all outputs sorted by amount (stable) for privacy
    ///
    /// The swap request is unsigned and needs to be signed by the sender (Alice) before sending
    pub fn create_swap_request(
        &self,
        funding_proofs: Vec<cdk::nuts::Proof>,
    ) -> Result<cdk::nuts::SwapRequest, anyhow::Error> {
        // Get blinded messages for receiver (Charlie)
        let mut outputs = self.receiver_outputs.get_blinded_messages()?;

        // Get blinded messages for sender (Alice)
        let sender_outputs = self.sender_outputs.get_blinded_messages()?;

        // Concatenate (receiver first, then sender)
        outputs.extend(sender_outputs);

        // Sort by amount (stable) for privacy - mixes receiver and sender outputs
        outputs.sort_by_key(|bm| u64::from(bm.amount));

        // Create swap request with all funding proofs as inputs
        Ok(cdk::nuts::SwapRequest::new(funding_proofs, outputs))
    }

    /// Unblind all outputs from a swap response
    ///
    /// Takes the blind signatures from the swap response and returns
    /// (receiver_proofs, sender_proofs) as two separate vectors
    pub fn unblind_all(
        &self,
        blind_signatures: Vec<cdk::nuts::BlindSignature>,
        active_keys: &cdk::nuts::Keys,
    ) -> Result<(Vec<cdk::nuts::Proof>, Vec<cdk::nuts::Proof>), anyhow::Error> {
        // Assert the number of signatures matches the expected number of outputs
        let expected_count = self.receiver_outputs.ordered_amounts.len() + self.sender_outputs.ordered_amounts.len();
        if blind_signatures.len() != expected_count {
            anyhow::bail!(
                "Expected {} blind signatures but received {}",
                expected_count,
                blind_signatures.len()
            );
        }

        // Get outputs for receiver and sender
        let receiver_outputs = self.receiver_outputs.get_secrets_with_blinding()?;
        let sender_outputs = self.sender_outputs.get_secrets_with_blinding()?;

        // Create vector with all outputs paired with ownership flag
        // Format: (DeterministicSecretWithBlinding, is_receiver)
        let mut all_outputs: Vec<(super::deterministic::DeterministicSecretWithBlinding, bool)> =
            receiver_outputs.into_iter().map(|o| (o, true)).collect();

        // Extend with sender outputs with flag = false
        all_outputs.extend(sender_outputs.into_iter().map(|o| (o, false)));

        // Sort by amount (stable) to match create_swap_request ordering, i.e.
        // smallest amounts first, tie-breaking by the partner (Charlie first,
        // then Alice). For a given amount and partner, they are ordered by 'index'
        all_outputs.sort_by_key(|(output, _)| output.amount);

        // Assert all_outputs has the correct length
        assert_eq!(all_outputs.len(), blind_signatures.len());

        // Extract secrets and blinding factors in sorted order
        let sorted_secrets: Vec<_> = all_outputs.iter().map(|(o, _)| o.secret.clone()).collect();
        let sorted_blinding: Vec<_> = all_outputs.iter().map(|(o, _)| o.blinding_factor.clone()).collect();

        // Assert sorted vectors have the correct length
        assert_eq!(sorted_secrets.len(), blind_signatures.len());
        assert_eq!(sorted_blinding.len(), blind_signatures.len());

        // Unblind all proofs in sorted order
        let all_proofs = cdk::dhke::construct_proofs(
            blind_signatures,
            sorted_blinding,
            sorted_secrets,
            active_keys,
        )?;

        // Assert result has the correct length
        assert_eq!(all_proofs.len(), all_outputs.len());

        // Separate proofs back into receiver and sender based on ownership flag
        let mut receiver_proofs = Vec::new();
        let mut sender_proofs = Vec::new();

        for (proof, (_, is_receiver)) in all_proofs.into_iter().zip(all_outputs.iter()) {
            if *is_receiver {
                receiver_proofs.push(proof);
            } else {
                sender_proofs.push(proof);
            }
        }

        Ok((receiver_proofs, sender_proofs))
    }

    /// Restore blind signatures from the mint using NUT-09
    ///
    /// This allows recovering the blind signatures for a commitment transaction
    /// without needing to have received them from the original swap.
    /// Since outputs are deterministic, we can recreate the blinded messages
    /// and ask the mint to restore the corresponding blind signatures.
    ///
    /// Returns the blind signatures in the same order as create_swap_request:
    /// sorted by amount (stable) for privacy
    ///
    /// TODO: This implementation assumes that Alice knows which balance Charlie exited
    ///       with. We should make a more robust method, as described in the NUT.
    /// TODO: think about keysets here; what if Charlie chose a different keyset?
    pub async fn restore_all_blind_signatures<M>(
        &self,
        mint_connection: &M,
    ) -> Result<Vec<BlindSignature>, anyhow::Error>
    where
        M: super::MintConnection + ?Sized,
    {
        // Get all blinded messages in the same order as create_swap_request
        // (receiver first, then sender)
        let mut all_outputs = self.receiver_outputs.get_blinded_messages()?;
        let sender_outputs = self.sender_outputs.get_blinded_messages()?;
        all_outputs.extend(sender_outputs);

        // Sort by amount (stable) for privacy - matches create_swap_request ordering
        all_outputs.sort_by_key(|bm| u64::from(bm.amount));

        // Create restore request
        let restore_request = RestoreRequest { outputs: all_outputs };

        // Call mint restore endpoint
        let restore_response = mint_connection.post_restore(restore_request).await
            .map_err(|e| anyhow::anyhow!("Restore failed: {}", e))?;

        // Extract blind signatures from the response
        let blind_signatures: Vec<BlindSignature> = restore_response.signatures;

        // Verify we got the expected number of signatures
        let expected_count = self.receiver_outputs.ordered_amounts.len() + self.sender_outputs.ordered_amounts.len();
        if blind_signatures.len() != expected_count {
            anyhow::bail!(
                "Restore returned {} blind signatures but expected {}",
                blind_signatures.len(),
                expected_count
            );
        }

        Ok(blind_signatures)
    }
}

impl SetOfDeterministicOutputs {
    /// Create a new set of deterministic outputs
    pub fn new(
        context: String,
        amount: u64,
        params: SpilmanChannelParameters,
    ) -> anyhow::Result<Self> {
        // Get the ordered list of amounts for this target
        let ordered_amounts = OrderedListOfAmounts::from_target(
            amount,
            params.maximum_amount_for_one_output,
            &params.keyset_info,
        )?;

        Ok(Self {
            context,
            amount,
            ordered_amounts,
            params,
        })
    }

    /// Calculate the value after stage 2 fees
    /// Takes the nominal amount and subtracts the fees for spending these outputs
    pub fn value_after_fees(&self) -> anyhow::Result<u64> {
        let num_outputs = self.ordered_amounts.len() as u64;
        let fees_ppk = self.params.keyset_info.input_fee_ppk * num_outputs;
        let fee = (fees_ppk + 999) / 1000;

        Ok(self.amount - fee)
    }


    /// Get the secrets with blinding for these outputs
    /// Works for all contexts: "sender", "receiver", and "funding"
    /// Returns full DeterministicSecretWithBlinding objects (secret + blinding factor)
    /// Outputs are ordered smallest-first per Cashu protocol recommendation
    pub fn get_secrets_with_blinding(&self) -> Result<Vec<super::deterministic::DeterministicSecretWithBlinding>, anyhow::Error> {
        if self.amount == 0 {
            return Ok(vec![]);
        }

        let mut outputs = Vec::new();

        // Use iter_smallest_first to track index per amount (Cashu protocol recommendation)
        for (&single_amount, &count) in self.ordered_amounts.iter_smallest_first() {
            for index in 0..count {
                let det_output = self.params.create_deterministic_output_with_blinding(&self.context, single_amount, index)?;
                outputs.push(det_output);
            }
        }

        Ok(outputs)
    }

    /// Get the blinded messages for these outputs
    /// Works for all contexts: "sender", "receiver", and "funding"
    /// Outputs are ordered smallest-first per Cashu protocol recommendation
    pub fn get_blinded_messages(&self) -> Result<Vec<BlindedMessage>, anyhow::Error> {
        // Get the secrets with blinding factors (already in smallest-first order)
        let secrets = self.get_secrets_with_blinding()?;

        // Build parallel vector of amounts in the same order as the secrets (smallest-first)
        let amounts: Vec<u64> = self.ordered_amounts.iter_smallest_first()
            .flat_map(|(&amount, &count)| std::iter::repeat(amount).take(count))
            .collect();

        // Convert each secret to a blinded message
        secrets.iter().zip(amounts.iter())
            .map(|(secret, &amount)| secret.to_blinded_message(Amount::from(amount), self.params.keyset_info.keyset_id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk::nuts::{CurrencyUnit, Id, Keys};
    use super::super::keysets_and_amounts::KeysetInfo;

    fn create_test_params(input_fee_ppk: u64, power: u64) -> SpilmanChannelParameters {
        // Create a simple keyset with powers of the given base for testing
        // power=2 gives powers-of-2: 1, 2, 4, 8, 16, ...
        // power=10 gives powers-of-10: 1, 10, 100, 1000, ...
        use std::collections::BTreeMap;
        use cdk::nuts::SecretKey;

        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();

        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        let mint_secret = SecretKey::generate();
        let mint_pubkey = mint_secret.public_key();

        let mut keys_map = BTreeMap::new();
        for i in 0..10 {
            let amount = Amount::from(power.pow(i as u32));
            keys_map.insert(amount, mint_pubkey);
        }
        let keys = Keys::new(keys_map);

        // Create keyset info
        let keyset_id = Id::from_bytes(&[0; 8]).unwrap();
        let keyset_info = KeysetInfo::new(keyset_id, keys, input_fee_ppk);

        SpilmanChannelParameters::new_with_secret_key(
            alice_pubkey,
            charlie_pubkey,
            "local".to_string(),
            CurrencyUnit::Sat,
            1000,  // capacity
            0,     // locktime
            0,     // setup_timestamp
            "test".to_string(),
            keyset_info,
            100_000, // maximum_amount_for_one_output
            &alice_secret,
        )
        .unwrap()
    }

    /// Helper to receive proofs into both wallets
    ///
    /// If a party's proofs would be worth 0 after fees, returns 0 for their amount.
    ///
    /// Returns (charlie_received, alice_received) as a tuple.
    async fn receive_proofs_for_both_parties(
        charlie_wallet: &cdk::wallet::Wallet,
        alice_wallet: &cdk::wallet::Wallet,
        charlie_proofs: Vec<cdk::nuts::Proof>,
        alice_proofs: Vec<cdk::nuts::Proof>,
        charlie_secret: cdk::nuts::SecretKey,
        alice_secret: cdk::nuts::SecretKey,
    ) -> anyhow::Result<(u64, u64)> {
        use crate::receive_proofs_into_wallet;

        let charlie_received = receive_proofs_into_wallet(
            charlie_wallet,
            charlie_proofs,
            charlie_secret,
        ).await?;

        let alice_received = receive_proofs_into_wallet(
            alice_wallet,
            alice_proofs,
            alice_secret,
        ).await?;

        Ok((charlie_received, alice_received))
    }

    #[test]
    fn test_count_by_amount() {
        let params = create_test_params(0, 2); // Powers of 2, no fees
        let max_amount = params.maximum_amount_for_one_output;
        let keyset_info = &params.keyset_info;

        // Test a specific example: 42 = 32 + 8 + 2
        let amounts = OrderedListOfAmounts::from_target(42, max_amount, keyset_info).unwrap();
        let count_map = &amounts.count_by_amount;

        // Should have 1×32, 1×8, 1×2
        assert_eq!(count_map.get(&32), Some(&1));
        assert_eq!(count_map.get(&8), Some(&1));
        assert_eq!(count_map.get(&2), Some(&1));
        assert_eq!(count_map.len(), 3);

        // Verify forward iteration gives us smallest-to-largest (BTreeMap natural order)
        let forward: Vec<(u64, usize)> = count_map.iter().map(|(&k, &v)| (k, v)).collect();
        assert_eq!(forward, vec![(2, 1), (8, 1), (32, 1)]);

        // Test another: 15 = 8 + 4 + 2 + 1
        let amounts = OrderedListOfAmounts::from_target(15, max_amount, keyset_info).unwrap();
        let count_map = &amounts.count_by_amount;
        assert_eq!(count_map.get(&8), Some(&1));
        assert_eq!(count_map.get(&4), Some(&1));
        assert_eq!(count_map.get(&2), Some(&1));
        assert_eq!(count_map.get(&1), Some(&1));
        assert_eq!(count_map.len(), 4);

        // Verify forward iteration (smallest-first)
        let forward: Vec<(u64, usize)> = count_map.iter().map(|(&k, &v)| (k, v)).collect();
        assert_eq!(forward, vec![(1, 1), (2, 1), (4, 1), (8, 1)]);

        // Test with multiple of same amount: 7 = 4 + 2 + 1
        let amounts = OrderedListOfAmounts::from_target(7, max_amount, keyset_info).unwrap();
        let count_map = &amounts.count_by_amount;
        assert_eq!(count_map.get(&4), Some(&1));
        assert_eq!(count_map.get(&2), Some(&1));
        assert_eq!(count_map.get(&1), Some(&1));

        let forward: Vec<(u64, usize)> = count_map.iter().map(|(&k, &v)| (k, v)).collect();
        assert_eq!(forward, vec![(1, 1), (2, 1), (4, 1)]);
    }

    #[test]
    fn test_roundtrip_property_powers_of_2() {
        let params = create_test_params(400, 2); // Powers of 2
        let max_amount = params.maximum_amount_for_one_output;

        // For any target balance, inverse should give us at least that balance
        for target in 0..=1000 {
            let inverse_result = params.keyset_info.inverse_deterministic_value_after_fees(target, max_amount).unwrap();

            // The actual balance should be >= target
            assert!(
                inverse_result.actual_balance >= target,
                "Target {} gave actual {} which is less than target",
                target,
                inverse_result.actual_balance
            );

            // Verify by computing forward
            let forward_result = params.keyset_info
                .deterministic_value_after_fees(inverse_result.nominal_value, max_amount)
                .unwrap();
            assert_eq!(forward_result, inverse_result.actual_balance);
        }
    }

    #[test]
    fn test_roundtrip_property_powers_of_10() {
        let params = create_test_params(400, 10); // Powers of 10
        let max_amount = params.maximum_amount_for_one_output;

        // For any target balance, inverse should give us at least that balance
        for target in 0..=1000 {
            let inverse_result = params.keyset_info.inverse_deterministic_value_after_fees(target, max_amount).unwrap();

            // The actual balance should be >= target
            assert!(
                inverse_result.actual_balance >= target,
                "Target {} gave actual {} which is less than target",
                target,
                inverse_result.actual_balance
            );

            // Verify by computing forward
            let forward_result = params.keyset_info
                .deterministic_value_after_fees(inverse_result.nominal_value, max_amount)
                .unwrap();
            assert_eq!(forward_result, inverse_result.actual_balance);
        }
    }

    #[tokio::test]
    async fn test_full_channel_flow() {
        use cdk::nuts::SecretKey;
        use cdk::util::unix_time;
        use crate::test_helpers::{setup_mint_and_wallets_for_demo, get_active_keyset_info, create_funding_proofs, receive_proofs_into_wallet};
        use crate::established_channel::EstablishedChannel;
        use crate::balance_update::BalanceUpdateMessage;

        // 1. Generate keys for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        // 2. Setup mint and wallets
        let channel_unit = CurrencyUnit::Sat;
        let input_fee_ppk = 400; // 40% fee
        let base = 2; // Powers of 2
        let (mint_connection, alice_wallet, charlie_wallet, _mint_url) =
            setup_mint_and_wallets_for_demo(None, channel_unit.clone(), input_fee_ppk, base).await.unwrap();

        // 3. Get active keyset info
        let keyset_info = get_active_keyset_info(&*mint_connection, &channel_unit).await.unwrap();

        // 4. Create channel parameters with shared secret
        let capacity = 100_000u64;
        let locktime = unix_time() + 86400; // 1 day from now
        let setup_timestamp = unix_time();
        let sender_nonce = "test_nonce".to_string();
        let maximum_amount_for_one_output = 100_000u64;

        let channel_params = SpilmanChannelParameters::new_with_secret_key(
            alice_pubkey,
            charlie_pubkey,
            "local".to_string(),
            channel_unit.clone(),
            capacity,
            locktime,
            setup_timestamp,
            sender_nonce,
            keyset_info,
            maximum_amount_for_one_output,
            &alice_secret,
        ).unwrap();

        // 5. Calculate funding token size
        let funding_token_nominal = channel_params.get_total_funding_token_amount().unwrap();

        // 6. Create and mint funding token
        let funding_proofs = create_funding_proofs(
            &*mint_connection,
            &channel_params,
            funding_token_nominal,
        ).await.unwrap();

        // 7. Create established channel
        let channel = EstablishedChannel::new(channel_params, funding_proofs).unwrap();

        // 8. Create commitment transaction for Charlie to receive 10,000 sats
        let charlie_balance = 10_000u64;
        let charlie_de_facto_balance = channel.params.get_de_facto_balance(charlie_balance).unwrap();

        dbg!(capacity, funding_token_nominal, charlie_balance, charlie_de_facto_balance);

        let commitment_outputs = CommitmentOutputs::for_balance(
            charlie_balance,
            &channel.params,
        ).unwrap();

        // 9. Create unsigned swap request
        let mut swap_request = commitment_outputs.create_swap_request(
            channel.funding_proofs.clone(),
        ).unwrap();

        // 10. Alice signs the swap request
        swap_request.sign_sig_all(alice_secret.clone()).unwrap();

        // 11. Create balance update message
        let balance_update = BalanceUpdateMessage::from_signed_swap_request(
            channel.params.get_channel_id(),
            charlie_balance,
            &swap_request,
        ).unwrap();

        // 12. Charlie verifies Alice's signature
        balance_update.verify_sender_signature(&channel).unwrap();

        // 13. Charlie signs the swap request
        swap_request.sign_sig_all(charlie_secret.clone()).unwrap();

        // 14. Execute the swap
        let swap_response = mint_connection.process_swap(swap_request.clone()).await.unwrap();

        // 15. Unblind the signatures to get proofs
        let (charlie_proofs, alice_proofs) = commitment_outputs.unblind_all(
            swap_response.signatures,
            &channel.params.keyset_info.active_keys,
        ).unwrap();

        // 17. Both parties receive their proofs
        let (charlie_received, alice_received) = receive_proofs_for_both_parties(
            &charlie_wallet,
            &alice_wallet,
            charlie_proofs,
            alice_proofs,
            charlie_secret,
            alice_secret,
        ).await.unwrap();

        // 18. Verify amounts
        assert_eq!(charlie_received, charlie_balance, "Charlie should receive the de facto balance");

        // Verify roundtrip: charlie_received == get_de_facto_balance(charlie_balance)
        let expected_received = channel.params.get_de_facto_balance(charlie_balance).unwrap();
        assert_eq!(charlie_received, expected_received,
            "Charlie's received amount should match get_de_facto_balance(charlie_balance)");

        assert!(alice_received > 0, "Alice should receive some amount");

        // Total received should equal capacity (minus fees)
        let total_received = charlie_received + alice_received;
        assert!(total_received <= capacity, "Total received should not exceed capacity");

        println!("✅ Full channel flow test passed!");
        println!("   Charlie received: {} sats", charlie_received);
        println!("   Alice received: {} sats", alice_received);
        println!("   Total: {} sats (capacity: {})", total_received, capacity);
    }

    #[tokio::test]
    async fn test_full_channel_flow_charlie_takes_all() {
        use cdk::nuts::SecretKey;
        use cdk::util::unix_time;
        use crate::test_helpers::{setup_mint_and_wallets_for_demo, get_active_keyset_info, create_funding_proofs, receive_proofs_into_wallet};
        use crate::established_channel::EstablishedChannel;
        use crate::balance_update::BalanceUpdateMessage;

        // 1. Generate keys for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        // 2. Setup mint and wallets
        let channel_unit = CurrencyUnit::Sat;
        let input_fee_ppk = 400; // 40% fee
        let base = 2; // Powers of 2
        let (mint_connection, alice_wallet, charlie_wallet, _mint_url) =
            setup_mint_and_wallets_for_demo(None, channel_unit.clone(), input_fee_ppk, base).await.unwrap();

        // 3. Get active keyset info
        let keyset_info = get_active_keyset_info(&*mint_connection, &channel_unit).await.unwrap();

        // 4. Create channel parameters with shared secret - Charlie tries to take entire capacity
        let capacity = 100_000u64;
        let locktime = unix_time() + 86400; // 1 day from now
        let setup_timestamp = unix_time();
        let sender_nonce = "test_nonce".to_string();
        let maximum_amount_for_one_output = 100_000u64;

        let channel_params = SpilmanChannelParameters::new_with_secret_key(
            alice_pubkey,
            charlie_pubkey,
            "local".to_string(),
            channel_unit.clone(),
            capacity,
            locktime,
            setup_timestamp,
            sender_nonce,
            keyset_info,
            maximum_amount_for_one_output,
            &alice_secret,
        ).unwrap();

        // 5. Calculate funding token size
        let funding_token_nominal = channel_params.get_total_funding_token_amount().unwrap();

        // 6. Create and mint funding token
        let funding_proofs = create_funding_proofs(
            &*mint_connection,
            &channel_params,
            funding_token_nominal,
        ).await.unwrap();

        // 7. Create established channel
        let channel = EstablishedChannel::new(channel_params, funding_proofs).unwrap();

        // 8. Create commitment transaction for Charlie to receive ENTIRE capacity
        let charlie_balance = capacity;  // Same as capacity!

        let commitment_outputs = CommitmentOutputs::for_balance(
            charlie_balance,
            &channel.params,
        ).unwrap();

        // 9. Create unsigned swap request
        let mut swap_request = commitment_outputs.create_swap_request(
            channel.funding_proofs.clone(),
        ).unwrap();

        // 10. Alice signs the swap request
        swap_request.sign_sig_all(alice_secret.clone()).unwrap();

        // 11. Create balance update message
        let balance_update = BalanceUpdateMessage::from_signed_swap_request(
            channel.params.get_channel_id(),
            charlie_balance,
            &swap_request,
        ).unwrap();

        // 12. Charlie verifies Alice's signature
        balance_update.verify_sender_signature(&channel).unwrap();

        // 13. Charlie signs the swap request
        swap_request.sign_sig_all(charlie_secret.clone()).unwrap();

        // 14. Execute the swap
        let swap_response = mint_connection.process_swap(swap_request.clone()).await.unwrap();

        // 15. Unblind the signatures to get proofs
        let (charlie_proofs, alice_proofs) = commitment_outputs.unblind_all(
            swap_response.signatures,
            &channel.params.keyset_info.active_keys,
        ).unwrap();

        // 17. Both parties receive their proofs
        // Alice gets effectively 0 sats after fees, so helper will skip her receive
        let (charlie_received, alice_received) = receive_proofs_for_both_parties(
            &charlie_wallet,
            &alice_wallet,
            charlie_proofs,
            alice_proofs,
            charlie_secret,
            alice_secret,
        ).await.unwrap();

        // Verify roundtrip: charlie_received == get_de_facto_balance(charlie_balance)
        let expected_received = channel.params.get_de_facto_balance(charlie_balance).unwrap();
        assert_eq!(charlie_received, expected_received,
            "Charlie's received amount should match get_de_facto_balance(charlie_balance)");

        println!("   Charlie received: {} sats", charlie_received);
        println!("   Alice received: {} sats", alice_received);
    }
}
