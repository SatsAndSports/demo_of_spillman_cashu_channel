//! Spilman Channel Extra
//!
//! Contains channel parameters plus mint-specific data (keys and amounts)

use cdk::nuts::{BlindedMessage, BlindSignature, Keys, RestoreRequest};
use cdk::Amount;

use super::params::SpilmanChannelParameters;

/// Result of inverse_deterministic_value_after_fees
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InverseFeeResult {
    /// The nominal value to allocate in deterministic outputs
    pub nominal_value: u64,
    /// The actual balance after fees (may be >= target due to discrete amounts)
    pub actual_balance: u64,
}

/// Select amounts from the keyset to reach a target value
/// Uses a largest-first greedy algorithm to minimize the number of outputs
/// Returns amounts in a BTreeMap which can be iterated smallest-first or largest-first
/// Returns an error if the target amount cannot be represented
pub fn select_amounts_to_reach_a_target(
    amounts_in_keyset: &[u64],
    target: u64,
) -> anyhow::Result<OrderedListOfAmounts> {
    use std::collections::BTreeMap;

    if target == 0 {
        return Ok(OrderedListOfAmounts::new(BTreeMap::new()));
    }

    let mut remaining = target;
    let mut count_by_amount = BTreeMap::new();

    // Greedy algorithm: use largest amounts first to minimize number of outputs
    // (The outputs will be ordered smallest-first when sent, per Cashu protocol)
    for &amount in amounts_in_keyset {
        let mut count = 0;
        while remaining >= amount {
            remaining -= amount;
            count += 1;
        }
        if count > 0 {
            count_by_amount.insert(amount, count);
        }
    }

    if remaining != 0 {
        anyhow::bail!(
            "Cannot represent {} using available amounts {:?}",
            target,
            amounts_in_keyset
        );
    }

    // Constructor will build the amounts vec from the map
    Ok(OrderedListOfAmounts::new(count_by_amount))
}

/// An ordered list of amounts that sum to a target value
///
/// Created by the greedy algorithm in select_amounts_to_reach_a_target.
/// The amounts are stored in a BTreeMap (sorted by key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedListOfAmounts {
    amounts: Vec<u64>,
    count_by_amount: std::collections::BTreeMap<u64, usize>,
}

impl OrderedListOfAmounts {
    /// Create a new ordered list of amounts from a count map
    /// Builds the amounts vector from the map, ordered largest-first
    pub fn new(count_by_amount: std::collections::BTreeMap<u64, usize>) -> Self {
        // Build amounts vector by iterating in reverse (largest-first)
        let mut amounts = Vec::new();
        for (&amount, &count) in count_by_amount.iter().rev() {
            for _ in 0..count {
                amounts.push(amount);
            }
        }

        Self { amounts, count_by_amount }
    }

    /// Get the number of amounts in the list
    pub fn len(&self) -> usize {
        self.amounts.len()
    }

    /// Iterate over the count map in normal order (smallest-first)
    /// Returns an iterator over (&amount, &count) pairs in ascending order by amount
    /// This is the recommended order for Cashu protocol outputs
    pub fn iter_smallest_first(&self) -> impl Iterator<Item = (&u64, &usize)> {
        self.count_by_amount.iter()
    }
}

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
    /// Channel parameters
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

        // Sort by amount (stable) to match create_swap_request ordering
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
        amounts_in_keyset: &[u64],
        context: String,
        amount: u64,
        params: SpilmanChannelParameters,
    ) -> anyhow::Result<Self> {
        // Get the ordered list of amounts for this target
        let ordered_amounts = select_amounts_to_reach_a_target(amounts_in_keyset, amount)?;

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
        let fees_ppk = self.params.input_fee_ppk * num_outputs;
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
            .map(|(secret, &amount)| secret.to_blinded_message(Amount::from(amount), self.params.active_keyset_id))
            .collect()
    }
}

/// Keyset information for fee calculations and amount selection
#[derive(Debug, Clone)]
pub struct KeysetInfo {
    /// Set of active keys from the mint (map from amount to pubkey)
    pub active_keys: Keys,
    /// Available amounts in the keyset, sorted largest first
    pub amounts_in_this_keyset_largest_first: Vec<u64>,
}

impl KeysetInfo {
    /// Create new keyset info from active keys
    pub fn new(active_keys: Keys) -> Self {
        // Extract and sort amounts from the keyset (largest first)
        let mut amounts_in_this_keyset_largest_first: Vec<u64> = active_keys
            .iter()
            .map(|(amt, _)| u64::from(*amt))
            .collect();
        amounts_in_this_keyset_largest_first.sort_unstable_by(|a, b| b.cmp(a)); // Descending order

        Self {
            active_keys,
            amounts_in_this_keyset_largest_first,
        }
    }

    /// Select amounts from the keyset to reach a target value
    /// Uses a largest-first greedy algorithm to minimize the number of outputs
    /// Returns amounts in a BTreeMap which can be iterated smallest-first or largest-first
    /// Returns an error if the target amount cannot be represented
    pub fn select_amounts_to_reach_a_target(&self, target: u64) -> anyhow::Result<OrderedListOfAmounts> {
        select_amounts_to_reach_a_target(&self.amounts_in_this_keyset_largest_first, target)
    }

    /// Calculate the value after stage 2 fees for a given nominal value
    ///
    /// Given a nominal value (what you allocate in deterministic outputs),
    /// this calculates what remains after paying the input fees when those outputs are used.
    pub fn deterministic_value_after_fees(&self, nominal_value: u64, input_fee_ppk: u64) -> anyhow::Result<u64> {
        if nominal_value == 0 {
            return Ok(0);
        }

        // If there are no fees, just return the nominal value
        if input_fee_ppk == 0 {
            return Ok(nominal_value);
        }

        // Get the number of outputs needed to represent this nominal value
        let amounts = self.select_amounts_to_reach_a_target(nominal_value)?;
        let num_outputs = amounts.len() as u64;

        // Calculate the fee: (input_fee_ppk * num_outputs + 999) // 1000
        // The +999 ensures we round up
        let fee = (input_fee_ppk * num_outputs + 999) / 1000;

        // Return the value after fees
        Ok(nominal_value - fee)
    }

    /// Find the inverse of deterministic_value_after_fees
    ///
    /// Given a target final balance, this returns the smallest nominal value
    /// that achieves at least the target balance, along with the actual balance
    /// you'll get (which may be slightly higher due to discrete denominations).
    pub fn inverse_deterministic_value_after_fees(&self, target_balance: u64, input_fee_ppk: u64) -> anyhow::Result<InverseFeeResult> {
        if target_balance == 0 {
            return Ok(InverseFeeResult {
                nominal_value: 0,
                actual_balance: 0,
            });
        }

        // If there are no fees, the inverse is trivial
        if input_fee_ppk == 0 {
            return Ok(InverseFeeResult {
                nominal_value: target_balance,
                actual_balance: target_balance,
            });
        }

        // Start with the target as initial guess and search upward
        let mut nominal = target_balance;

        loop {
            let actual_balance = self.deterministic_value_after_fees(nominal, input_fee_ppk)?;

            if actual_balance >= target_balance {
                // Found it! Return the nominal value and what we actually get
                return Ok(InverseFeeResult {
                    nominal_value: nominal,
                    actual_balance,
                });
            }

            // actual_balance < target_balance, need to increase nominal
            nominal += 1;
        }
    }
}

/// Channel parameters plus mint-specific data (keys)
#[derive(Debug, Clone)]
pub struct SpilmanChannelExtra {
    /// Channel parameters
    pub params: SpilmanChannelParameters,
    /// Keyset information (keys and amounts)
    pub keyset_info: KeysetInfo,
}

impl SpilmanChannelExtra {
    /// Create new channel extra from parameters and active keys
    /// Filters out amounts larger than maximum_amount_for_one_output
    pub fn new(params: SpilmanChannelParameters, active_keys: Keys) -> anyhow::Result<Self> {
        // Filter out keys with amounts larger than the maximum
        let filtered_map: std::collections::BTreeMap<_, _> = active_keys
            .iter()
            .filter(|(amount, _)| u64::from(**amount) <= params.maximum_amount_for_one_output)
            .map(|(amount, pubkey)| (*amount, *pubkey))
            .collect();

        let filtered_keys = Keys::new(filtered_map);
        let keyset_info = KeysetInfo::new(filtered_keys);

        Ok(Self {
            params,
            keyset_info,
        })
    }

    /// Get the total funding token amount using double inverse
    ///
    /// Applies the inverse fee calculation twice to the capacity:
    /// 1. capacity → post-stage-1 nominal (accounting for stage 2 fees)
    /// 2. post-stage-1 nominal → funding token nominal (accounting for stage 1 fees)
    ///
    /// Returns the nominal value needed for the funding token
    pub fn get_total_funding_token_amount(&self) -> anyhow::Result<u64> {
        // First inverse: capacity → post-stage-1 nominal (accounting for stage 2 fees)
        let first_inverse = self.keyset_info.inverse_deterministic_value_after_fees(
            self.params.capacity,
            self.params.input_fee_ppk
        )?;
        let post_stage1_nominal = first_inverse.nominal_value;

        // Second inverse: post-stage-1 nominal → funding token nominal (accounting for stage 1 fees)
        let second_inverse = self.keyset_info.inverse_deterministic_value_after_fees(
            post_stage1_nominal,
            self.params.input_fee_ppk
        )?;
        let funding_token_nominal = second_inverse.nominal_value;

        Ok(funding_token_nominal)
    }

    /// Get the value available after stage 1 fees
    ///
    /// Takes the funding token nominal and applies the forward fee calculation
    /// to determine the actual amount available after the swap transaction (stage 1).
    ///
    /// This represents the total amount that will be distributed between Alice and Charlie
    /// in the commitment transaction outputs.
    ///
    /// Returns the actual value after stage 1 fees
    pub fn get_value_after_stage1(&self) -> anyhow::Result<u64> {
        // Get the funding token nominal
        let funding_token_nominal = self.get_total_funding_token_amount()?;

        // Apply forward to get actual value after stage 1 fees (spending the funding token)
        let value_after_stage1 = self.keyset_info.deterministic_value_after_fees(
            funding_token_nominal,
            self.params.input_fee_ppk
        )?;

        Ok(value_after_stage1)
    }

    /// Compute the actual de facto balance from an intended balance
    ///
    /// Due to output denomination constraints and fee rounding, the actual balance
    /// that can be created may differ slightly from the intended balance.
    ///
    /// This method:
    /// 1. Applies inverse to find the nominal value needed for the intended balance
    /// 2. Applies deterministic_value to that nominal to get the actual de facto balance
    ///
    /// Returns the actual balance that will be created
    pub fn get_de_facto_balance(&self, intended_balance: u64) -> anyhow::Result<u64> {
        // Apply inverse to get nominal value needed
        let inverse_result = self.keyset_info.inverse_deterministic_value_after_fees(
            intended_balance,
            self.params.input_fee_ppk
        )?;
        let nominal_value = inverse_result.nominal_value;

        // Apply deterministic_value to get actual balance
        let actual_balance = self.keyset_info.deterministic_value_after_fees(
            nominal_value,
            self.params.input_fee_ppk
        )?;

        Ok(actual_balance)
    }

    /// Create two sets of deterministic outputs for a given receiver balance
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
    ///
    /// Returns CommitmentOutputs containing both receiver and sender outputs
    pub fn create_two_sets_of_outputs_for_balance(
        &self,
        receiver_balance: u64,
    ) -> anyhow::Result<CommitmentOutputs> {
        // Get the amount available after stage 1 fees
        let amount_after_stage1 = self.get_value_after_stage1()?;

        // Find the nominal value needed for Charlie's deterministic outputs
        let inverse_result = self.keyset_info.inverse_deterministic_value_after_fees(receiver_balance, self.params.input_fee_ppk)?;
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
            &self.keyset_info.amounts_in_this_keyset_largest_first,
            "receiver".to_string(),
            charlie_nominal,
            self.params.clone(),
        )?;

        // Create outputs for Alice (sender)
        let alice_outputs = SetOfDeterministicOutputs::new(
            &self.keyset_info.amounts_in_this_keyset_largest_first,
            "sender".to_string(),
            alice_nominal,
            self.params.clone(),
        )?;

        Ok(CommitmentOutputs::new(charlie_outputs, alice_outputs))
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk::nuts::{CurrencyUnit, Id};

    fn create_test_extra(input_fee_ppk: u64, power: u64) -> SpilmanChannelExtra {
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

        let params = SpilmanChannelParameters::new(
            alice_pubkey,
            charlie_pubkey,
            "local".to_string(),
            CurrencyUnit::Sat,
            1000,  // capacity
            0,     // locktime
            0,     // setup_timestamp
            "test".to_string(),
            Id::from_bytes(&[0; 8]).unwrap(),
            input_fee_ppk,
            100_000, // maximum_amount_for_one_output
        )
        .unwrap();

        SpilmanChannelExtra::new(params, keys).unwrap()
    }

    #[test]
    fn test_count_by_amount() {
        let extra = create_test_extra(0, 2); // Powers of 2, no fees

        // Test a specific example: 42 = 32 + 8 + 2
        let amounts = extra.keyset_info.select_amounts_to_reach_a_target(42).unwrap();
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
        let amounts = extra.keyset_info.select_amounts_to_reach_a_target(15).unwrap();
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
        let amounts = extra.keyset_info.select_amounts_to_reach_a_target(7).unwrap();
        let count_map = &amounts.count_by_amount;
        assert_eq!(count_map.get(&4), Some(&1));
        assert_eq!(count_map.get(&2), Some(&1));
        assert_eq!(count_map.get(&1), Some(&1));

        let forward: Vec<(u64, usize)> = count_map.iter().map(|(&k, &v)| (k, v)).collect();
        assert_eq!(forward, vec![(1, 1), (2, 1), (4, 1)]);
    }

    #[test]
    fn test_roundtrip_property_powers_of_2() {
        let extra = create_test_extra(400, 2); // Powers of 2
        let input_fee_ppk = extra.params.input_fee_ppk;

        // For any target balance, inverse should give us at least that balance
        for target in 0..=1000 {
            let inverse_result = extra.keyset_info.inverse_deterministic_value_after_fees(target, input_fee_ppk).unwrap();

            // The actual balance should be >= target
            assert!(
                inverse_result.actual_balance >= target,
                "Target {} gave actual {} which is less than target",
                target,
                inverse_result.actual_balance
            );

            // Verify by computing forward
            let forward_result = extra.keyset_info
                .deterministic_value_after_fees(inverse_result.nominal_value, input_fee_ppk)
                .unwrap();
            assert_eq!(forward_result, inverse_result.actual_balance);
        }
    }

    #[test]
    fn test_roundtrip_property_powers_of_10() {
        let extra = create_test_extra(400, 10); // Powers of 10
        let input_fee_ppk = extra.params.input_fee_ppk;

        // For any target balance, inverse should give us at least that balance
        for target in 0..=1000 {
            let inverse_result = extra.keyset_info.inverse_deterministic_value_after_fees(target, input_fee_ppk).unwrap();

            // The actual balance should be >= target
            assert!(
                inverse_result.actual_balance >= target,
                "Target {} gave actual {} which is less than target",
                target,
                inverse_result.actual_balance
            );

            // Verify by computing forward
            let forward_result = extra.keyset_info
                .deterministic_value_after_fees(inverse_result.nominal_value, input_fee_ppk)
                .unwrap();
            assert_eq!(forward_result, inverse_result.actual_balance);
        }
    }
}
