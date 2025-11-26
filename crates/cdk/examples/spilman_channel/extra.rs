//! Spilman Channel Extra
//!
//! Contains channel parameters plus mint-specific data (keys and amounts)

use cdk::nuts::{BlindedMessage, BlindSignature, Keys, RestoreRequest, SecretKey};
use cdk::secret::Secret;
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

/// Get the list of amounts that sum to the target amount
/// Uses a greedy algorithm: goes through amounts from largest to smallest
/// Returns the list in descending order (largest first)
/// Returns an error if the target amount cannot be represented
fn amounts_for_target_largest_first(
    amounts_in_keyset: &[u64],
    target: u64,
) -> anyhow::Result<OrderedListOfAmounts> {
    use std::collections::BTreeMap;

    if target == 0 {
        return Ok(OrderedListOfAmounts::new(BTreeMap::new()));
    }

    let mut remaining = target;
    let mut count_by_amount = BTreeMap::new();

    // Greedy algorithm: use largest amounts first (already sorted in our data member)
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
/// Created by the greedy algorithm in amounts_for_target_largest_first.
/// The amounts are sorted largest-first.
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

    /// Get the count map (amount -> number of outputs with that amount)
    /// Keys are sorted in ascending order (BTreeMap property)
    pub fn count_by_amount(&self) -> &std::collections::BTreeMap<u64, usize> {
        &self.count_by_amount
    }
}

/// A set of deterministic outputs for a specific pubkey and amount
/// This represents all the deterministic blinded messages, secrets, and blinding factors
/// for splitting a given amount into ecash outputs
#[derive(Debug, Clone)]
pub struct SetOfDeterministicOutputs {
    /// The pubkey these outputs are for (Alice or Charlie)
    pub pubkey: cdk::nuts::PublicKey,
    /// The total amount to allocate
    pub amount: u64,
    /// The breakdown of amounts (largest-first)
    pub ordered_amounts: OrderedListOfAmounts,
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
    /// - Outputs: receiver's deterministic outputs followed by sender's deterministic outputs
    ///
    /// The swap request is unsigned and needs to be signed by the sender (Alice) before sending
    pub fn create_swap_request(
        &self,
        funding_proofs: Vec<cdk::nuts::Proof>,
        params: &SpilmanChannelParameters,
    ) -> Result<cdk::nuts::SwapRequest, anyhow::Error> {
        // Get blinded messages for receiver (Charlie)
        let mut outputs = self.receiver_outputs.get_blinded_messages(params)?;

        // Get blinded messages for sender (Alice)
        let sender_outputs = self.sender_outputs.get_blinded_messages(params)?;

        // Concatenate (receiver first, then sender, per NUT-XX spec)
        outputs.extend(sender_outputs);

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
        params: &SpilmanChannelParameters,
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

        // Get secrets and blinding factors for receiver
        let receiver_secrets = self.receiver_outputs.get_secrets(params)?;
        let receiver_blinding_factors = self.receiver_outputs.get_blinding_factors(params)?;

        // Get secrets and blinding factors for sender
        let sender_secrets = self.sender_outputs.get_secrets(params)?;
        let sender_blinding_factors = self.sender_outputs.get_blinding_factors(params)?;

        // Split the blind signatures into receiver's and sender's portions
        let receiver_count = receiver_blinding_factors.len();
        let receiver_signatures = blind_signatures.iter().take(receiver_count).cloned().collect::<Vec<_>>();
        let sender_signatures = blind_signatures.iter().skip(receiver_count).cloned().collect::<Vec<_>>();

        // Unblind receiver's outputs
        let receiver_proofs = cdk::dhke::construct_proofs(
            receiver_signatures,
            receiver_blinding_factors,
            receiver_secrets,
            active_keys,
        )?;

        // Unblind sender's outputs
        let sender_proofs = cdk::dhke::construct_proofs(
            sender_signatures,
            sender_blinding_factors,
            sender_secrets,
            active_keys,
        )?;

        Ok((receiver_proofs, sender_proofs))
    }

    /// Restore blind signatures from the mint using NUT-09
    ///
    /// This allows recovering the blind signatures for a commitment transaction
    /// without needing to have received them from the original swap.
    /// Since outputs are deterministic, we can recreate the blinded messages
    /// and ask the mint to restore the corresponding blind signatures.
    ///
    /// Returns the blind signatures in the same order as unblind_all expects:
    /// receiver signatures first, then sender signatures
    pub async fn restore_all_blind_signatures<M>(
        &self,
        extra: &SpilmanChannelExtra,
        mint_connection: &M,
    ) -> Result<Vec<BlindSignature>, anyhow::Error>
    where
        M: super::MintConnection + ?Sized,
    {
        // Get all blinded messages in the same order as create_swap_request
        // (receiver first, then sender)
        let mut all_outputs = self.receiver_outputs.get_blinded_messages(&extra.params)?;
        let sender_outputs = self.sender_outputs.get_blinded_messages(&extra.params)?;
        all_outputs.extend(sender_outputs);

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
        pubkey: cdk::nuts::PublicKey,
        amount: u64,
    ) -> anyhow::Result<Self> {
        // Get the ordered list of amounts for this target
        let ordered_amounts = amounts_for_target_largest_first(amounts_in_keyset, amount)?;

        Ok(Self {
            pubkey,
            amount,
            ordered_amounts,
        })
    }

    /// Calculate the value after stage 2 fees
    /// Takes the nominal amount and subtracts the fees for spending these outputs
    pub fn value_after_fees(&self, input_fee_ppk: u64) -> anyhow::Result<u64> {
        let num_outputs = self.ordered_amounts.len() as u64;
        let fees_ppk = input_fee_ppk * num_outputs;
        let fee = (fees_ppk + 999) / 1000;

        Ok(self.amount - fee)
    }

    /// Get the secrets for these outputs
    pub fn get_secrets(&self, params: &SpilmanChannelParameters) -> Result<Vec<Secret>, anyhow::Error> {
        if self.amount == 0 {
            return Ok(vec![]);
        }

        let mut secrets = Vec::new();

        // Use count_by_amount to track index per amount
        for (&single_amount, &count) in self.ordered_amounts.count_by_amount().iter().rev() {
            for index in 0..count {
                let det_output = params.create_deterministic_p2pk_output_with_blinding(&self.pubkey, single_amount, index)?;
                secrets.push(det_output.secret);
            }
        }

        Ok(secrets)
    }

    /// Get the blinding factors for these outputs
    pub fn get_blinding_factors(&self, params: &SpilmanChannelParameters) -> Result<Vec<SecretKey>, anyhow::Error> {
        if self.amount == 0 {
            return Ok(vec![]);
        }

        let mut blinding_factors = Vec::new();

        // Use count_by_amount to track index per amount
        for (&single_amount, &count) in self.ordered_amounts.count_by_amount().iter().rev() {
            for index in 0..count {
                let det_output = params.create_deterministic_p2pk_output_with_blinding(&self.pubkey, single_amount, index)?;
                blinding_factors.push(det_output.blinding_factor);
            }
        }

        Ok(blinding_factors)
    }

    /// Get the blinded messages for these outputs
    pub fn get_blinded_messages(&self, params: &SpilmanChannelParameters) -> Result<Vec<BlindedMessage>, anyhow::Error> {
        if self.amount == 0 {
            return Ok(vec![]);
        }

        let mut blinded_messages = Vec::new();

        // Use count_by_amount to track index per amount
        for (&single_amount, &count) in self.ordered_amounts.count_by_amount().iter().rev() {
            for index in 0..count {
                let det_output = params.create_deterministic_p2pk_output_with_blinding(&self.pubkey, single_amount, index)?;
                let blinded_msg = det_output.to_blinded_message(Amount::from(single_amount), params.active_keyset_id)?;
                blinded_messages.push(blinded_msg);
            }
        }

        Ok(blinded_messages)
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

    /// Get the list of amounts that sum to the target amount
    /// Uses a greedy algorithm: goes through amounts from largest to smallest
    /// Returns the list in descending order (largest first)
    /// Returns an error if the target amount cannot be represented
    pub fn amounts_for_target_largest_first(&self, target: u64) -> anyhow::Result<OrderedListOfAmounts> {
        amounts_for_target_largest_first(&self.amounts_in_this_keyset_largest_first, target)
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
        let amounts = self.amounts_for_target_largest_first(nominal_value)?;
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
    pub fn new(params: SpilmanChannelParameters, active_keys: Keys) -> anyhow::Result<Self> {
        let keyset_info = KeysetInfo::new(active_keys);

        Ok(Self {
            params,
            keyset_info,
        })
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
    /// - amount_after_stage1: The nominal value available after stage 1 fees (total_locked_value - stage1_fees)
    ///
    /// Returns CommitmentOutputs containing both receiver and sender outputs
    pub fn create_two_sets_of_outputs_for_balance(
        &self,
        receiver_balance: u64,
        amount_after_stage1: u64,
    ) -> anyhow::Result<CommitmentOutputs> {
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
            self.params.charlie_pubkey,
            charlie_nominal,
        )?;

        // Create outputs for Alice (sender)
        let alice_outputs = SetOfDeterministicOutputs::new(
            &self.keyset_info.amounts_in_this_keyset_largest_first,
            self.params.alice_pubkey,
            alice_nominal,
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
        )
        .unwrap();

        SpilmanChannelExtra::new(params, keys).unwrap()
    }

    #[test]
    fn test_count_by_amount() {
        let extra = create_test_extra(0, 2); // Powers of 2, no fees

        // Test a specific example: 42 = 32 + 8 + 2
        let amounts = extra.keyset_info.amounts_for_target_largest_first(42).unwrap();
        let count_map = amounts.count_by_amount();

        // Should have 1×32, 1×8, 1×2
        assert_eq!(count_map.get(&32), Some(&1));
        assert_eq!(count_map.get(&8), Some(&1));
        assert_eq!(count_map.get(&2), Some(&1));
        assert_eq!(count_map.len(), 3);

        // Verify reversed iteration gives us largest-to-smallest
        let reversed: Vec<(u64, usize)> = count_map.iter().rev().map(|(&k, &v)| (k, v)).collect();
        assert_eq!(reversed, vec![(32, 1), (8, 1), (2, 1)]);

        // Test another: 15 = 8 + 4 + 2 + 1
        let amounts = extra.keyset_info.amounts_for_target_largest_first(15).unwrap();
        let count_map = amounts.count_by_amount();
        assert_eq!(count_map.get(&8), Some(&1));
        assert_eq!(count_map.get(&4), Some(&1));
        assert_eq!(count_map.get(&2), Some(&1));
        assert_eq!(count_map.get(&1), Some(&1));
        assert_eq!(count_map.len(), 4);

        // Verify reversed iteration
        let reversed: Vec<(u64, usize)> = count_map.iter().rev().map(|(&k, &v)| (k, v)).collect();
        assert_eq!(reversed, vec![(8, 1), (4, 1), (2, 1), (1, 1)]);

        // Test with multiple of same amount: 7 = 4 + 2 + 1
        let amounts = extra.keyset_info.amounts_for_target_largest_first(7).unwrap();
        let count_map = amounts.count_by_amount();
        assert_eq!(count_map.get(&4), Some(&1));
        assert_eq!(count_map.get(&2), Some(&1));
        assert_eq!(count_map.get(&1), Some(&1));

        let reversed: Vec<(u64, usize)> = count_map.iter().rev().map(|(&k, &v)| (k, v)).collect();
        assert_eq!(reversed, vec![(4, 1), (2, 1), (1, 1)]);
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
