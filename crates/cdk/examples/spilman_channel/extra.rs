//! Spilman Channel Extra
//!
//! Contains channel parameters plus mint-specific data (keys and amounts)

use std::collections::HashMap;

use cdk::nuts::{BlindedMessage, Keys, SecretKey};
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

/// Channel parameters plus mint-specific data (keys)
#[derive(Debug, Clone)]
pub struct SpilmanChannelExtra {
    /// Channel parameters
    pub params: SpilmanChannelParameters,
    /// Set of active keys from the mint (map from amount to pubkey)
    pub active_keys: Keys,
    /// Available amounts in the keyset, sorted largest first
    pub amounts_in_this_keyset__largest_first: Vec<u64>,
}

impl SpilmanChannelExtra {
    /// Create new channel extra from parameters and active keys
    pub fn new(params: SpilmanChannelParameters, active_keys: Keys) -> anyhow::Result<Self> {
        // Extract and sort amounts from the keyset (largest first)
        let mut amounts_in_this_keyset__largest_first: Vec<u64> = active_keys
            .iter()
            .map(|(amt, _)| u64::from(*amt))
            .collect();
        amounts_in_this_keyset__largest_first.sort_unstable_by(|a, b| b.cmp(a)); // Descending order

        Ok(Self {
            params,
            active_keys,
            amounts_in_this_keyset__largest_first,
        })
    }

    /// Get the list of amounts that sum to the target amount
    /// Uses a greedy algorithm: goes through amounts from largest to smallest
    /// Returns the list in descending order (largest first)
    /// Returns an error if the target amount cannot be represented
    pub fn amounts_for_target__largest_first(&self, target: u64) -> anyhow::Result<Vec<u64>> {
        if target == 0 {
            return Ok(vec![]);
        }

        let mut remaining = target;
        let mut result = Vec::new();

        // Greedy algorithm: use largest amounts first (already sorted in our data member)
        for &amount in &self.amounts_in_this_keyset__largest_first {
            while remaining >= amount {
                result.push(amount);
                remaining -= amount;
            }
        }

        if remaining != 0 {
            anyhow::bail!(
                "Cannot represent {} using available amounts {:?}",
                target,
                self.amounts_in_this_keyset__largest_first
            );
        }

        // Result is already in descending order from the greedy algorithm
        Ok(result)
    }

    /// Calculate the value after fees for a given nominal value
    ///
    /// Given a nominal value x, this returns the actual value after subtracting
    /// the fees that would be charged when swapping the deterministic outputs.
    ///
    /// Formula: deterministic_value_after_fees(x) = x - (input_fee_ppk * num_outputs + 999) // 1000
    ///
    /// Returns an error if the nominal value cannot be represented using available amounts
    pub fn deterministic_value_after_fees(&self, nominal_value: u64) -> anyhow::Result<u64> {
        if nominal_value == 0 {
            return Ok(0);
        }

        // If there are no fees, just return the nominal value
        if self.params.input_fee_ppk == 0 {
            return Ok(nominal_value);
        }

        // Get the number of outputs needed to represent this nominal value
        let amounts = self.amounts_for_target__largest_first(nominal_value)?;
        let num_outputs = amounts.len() as u64;

        // Calculate the fee: (input_fee_ppk * num_outputs + 999) // 1000
        // The +999 ensures we round up
        let fee = (self.params.input_fee_ppk * num_outputs + 999) / 1000;

        // Return the value after fees
        Ok(nominal_value - fee)
    }

    /// Find the inverse of deterministic_value_after_fees
    ///
    /// Given a target final balance, this returns the smallest nominal value
    /// that achieves at least the target balance, along with the actual balance
    /// after fees.
    ///
    /// Note: Due to the discrete nature of available amounts and fee rounding, some
    /// target balances may not be exactly achievable. In such cases, this returns
    /// the smallest nominal value that gives you the closest achievable balance >= target.
    ///
    /// Returns: InverseFeeResult with nominal_value and actual_balance
    pub fn inverse_deterministic_value_after_fees(&self, target_balance: u64) -> anyhow::Result<InverseFeeResult> {
        if target_balance == 0 {
            return Ok(InverseFeeResult {
                nominal_value: 0,
                actual_balance: 0,
            });
        }

        // If there are no fees, the inverse is trivial
        if self.params.input_fee_ppk == 0 {
            return Ok(InverseFeeResult {
                nominal_value: target_balance,
                actual_balance: target_balance,
            });
        }

        // Start with the target as initial guess and search upward
        let mut nominal = target_balance;

        loop {
            let actual_balance = self.deterministic_value_after_fees(nominal)?;

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

    /// Create deterministic secrets for a given amount
    /// Returns a vector of secrets in the same order as amounts_for_target__largest_first
    pub fn create_deterministic_secrets_for_amount(
        &self,
        pubkey: &cdk::nuts::PublicKey,
        amount: u64,
    ) -> Result<Vec<Secret>, anyhow::Error> {
        if amount == 0 {
            return Ok(vec![]);
        }

        let amounts = self.amounts_for_target__largest_first(amount)?;

        let mut secrets = Vec::new();
        let mut index_by_amount: HashMap<u64, usize> = HashMap::new();

        for single_amount in amounts {
            let index = *index_by_amount.get(&single_amount).unwrap_or(&0);

            let det_output = self.params.create_deterministic_p2pk_output_with_blinding(pubkey, index)?;
            secrets.push(det_output.secret);

            index_by_amount.insert(single_amount, index + 1);
        }

        Ok(secrets)
    }

    /// Create deterministic blinding factors for a given amount
    /// Returns a vector of blinding factors in the same order as amounts_for_target__largest_first
    pub fn create_deterministic_blinding_factors_for_amount(
        &self,
        pubkey: &cdk::nuts::PublicKey,
        amount: u64,
    ) -> Result<Vec<SecretKey>, anyhow::Error> {
        if amount == 0 {
            return Ok(vec![]);
        }

        let amounts = self.amounts_for_target__largest_first(amount)?;

        let mut blinding_factors = Vec::new();
        let mut index_by_amount: HashMap<u64, usize> = HashMap::new();

        for single_amount in amounts {
            let index = *index_by_amount.get(&single_amount).unwrap_or(&0);

            let det_output = self.params.create_deterministic_p2pk_output_with_blinding(pubkey, index)?;
            blinding_factors.push(det_output.blinding_factor);

            index_by_amount.insert(single_amount, index + 1);
        }

        Ok(blinding_factors)
    }

    /// Create deterministic blinded messages for a given amount
    /// Returns a vector of blinded messages in the same order as amounts_for_target__largest_first
    pub fn create_deterministic_blinded_messages_for_amount(
        &self,
        pubkey: &cdk::nuts::PublicKey,
        amount: u64,
    ) -> Result<Vec<BlindedMessage>, anyhow::Error> {
        if amount == 0 {
            return Ok(vec![]);
        }

        let amounts = self.amounts_for_target__largest_first(amount)?;

        let mut blinded_messages = Vec::new();
        let mut index_by_amount: HashMap<u64, usize> = HashMap::new();

        for single_amount in amounts {
            let index = *index_by_amount.get(&single_amount).unwrap_or(&0);

            let det_output = self.params.create_deterministic_p2pk_output_with_blinding(pubkey, index)?;
            let blinded_msg = det_output.to_blinded_message(Amount::from(single_amount), self.params.active_keyset_id)?;
            blinded_messages.push(blinded_msg);

            index_by_amount.insert(single_amount, index + 1);
        }

        Ok(blinded_messages)
    }

    /// Create deterministic blinded messages and blinding factors for a given amount
    /// Returns both blinded messages and blinding factors in the same order
    pub fn create_deterministic_blinded_messages_and_blinding_factors_for_amount(
        &self,
        pubkey: &cdk::nuts::PublicKey,
        amount: u64,
    ) -> Result<(Vec<BlindedMessage>, Vec<SecretKey>), anyhow::Error> {
        if amount == 0 {
            return Ok((vec![], vec![]));
        }

        let amounts = self.amounts_for_target__largest_first(amount)?;

        let mut blinded_messages = Vec::new();
        let mut blinding_factors = Vec::new();
        let mut index_by_amount: HashMap<u64, usize> = HashMap::new();

        for single_amount in amounts {
            let index = *index_by_amount.get(&single_amount).unwrap_or(&0);

            let det_output = self.params.create_deterministic_p2pk_output_with_blinding(pubkey, index)?;
            let blinded_msg = det_output.to_blinded_message(Amount::from(single_amount), self.params.active_keyset_id)?;
            blinded_messages.push(blinded_msg);
            blinding_factors.push(det_output.blinding_factor);

            index_by_amount.insert(single_amount, index + 1);
        }

        Ok((blinded_messages, blinding_factors))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk::nuts::{CurrencyUnit, Id};

    fn create_test_extra(input_fee_ppk: u64) -> SpilmanChannelExtra {
        // Create a simple keyset with powers of 2 for testing
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
            let amount = Amount::from(1u64 << i); // 1, 2, 4, 8, 16, 32, 64, 128, 256, 512
            keys_map.insert(amount, mint_pubkey);
        }
        let keys = Keys::new(keys_map);

        let params = SpilmanChannelParameters::new(
            alice_pubkey,
            charlie_pubkey,
            CurrencyUnit::Sat,
            1000,
            0,
            0,
            "test".to_string(),
            Id::from_bytes(&[0; 8]).unwrap(),
            input_fee_ppk,
        )
        .unwrap();

        SpilmanChannelExtra::new(params, keys).unwrap()
    }

    #[test]
    fn test_roundtrip_property() {
        let extra = create_test_extra(400);

        // For any target balance, inverse should give us at least that balance
        for target in [0, 1, 2, 5, 10, 15, 20, 42, 100, 255, 500] {
            let inverse_result = extra.inverse_deterministic_value_after_fees(target).unwrap();

            // The actual balance should be >= target
            assert!(
                inverse_result.actual_balance >= target,
                "Target {} gave actual {} which is less than target",
                target,
                inverse_result.actual_balance
            );

            // Verify by computing forward
            let forward_result = extra
                .deterministic_value_after_fees(inverse_result.nominal_value)
                .unwrap();
            assert_eq!(forward_result, inverse_result.actual_balance);
        }
    }
}
