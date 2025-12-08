//! Keyset Information
//!
//! Contains keyset-related types and fee calculation functions.
//! This module is separate to avoid circular dependencies between params.rs and extra.rs.

use cdk::nuts::{Id, Keys};

/// Result of inverse_deterministic_value_after_fees
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InverseFeeResult {
    /* Certain post-fee balances are impossible, if there are non-zero fees,
     * in this deterministic system. So even if we intend the post-fee
     * balance to be 100 sats, it may need to be 101 sats (actual_balance)
     * and the pre-fee amount may need to be larger, e.g. 104 sats (nominal).
     * So the funding token it swapped to created 104 sats of P2PK commitment
     * outputs to Charlie, which become 101 sats after he swaps them into his
     * own wallet
     */

    /// The nominal value to allocate in deterministic outputs
    pub nominal_value: u64,
    /// The actual balance after fees (may be >= target due to discrete amounts)
    pub actual_balance: u64,
}

/// An ordered list of amounts that sum to a target value
///
/// Created by the greedy algorithm in from_target.
/// The amounts are stored in a BTreeMap (sorted by the amount).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedListOfAmounts {
    amounts: Vec<u64>,
    /// Map from amount to count, for iteration/inspection
    pub count_by_amount: std::collections::BTreeMap<u64, usize>,
    /// Input fee in parts per thousand (from keyset)
    input_fee_ppk: u64,
}

impl OrderedListOfAmounts {
    /// Create amounts to reach a target value using keyset info
    ///
    /// Uses a largest-first greedy algorithm to minimize the number of outputs.
    /// Only considers amounts <= maximum_amount from the keyset.
    pub fn from_target(
        target: u64,
        maximum_amount: u64,
        keyset_info: &KeysetInfo,
    ) -> anyhow::Result<Self> {
        use std::collections::BTreeMap;

        let mut count_by_amount = BTreeMap::new();

        if target == 0 {
            return Ok(Self {
                amounts: Vec::new(),
                count_by_amount,
                input_fee_ppk: keyset_info.input_fee_ppk,
            });
        }

        let mut remaining = target;

        // Greedy algorithm: use largest amounts first to minimize number of outputs
        // keyset_info.amounts_largest_first is already sorted descending
        for &amount in &keyset_info.amounts_largest_first {
            if amount > maximum_amount {
                continue;
            }
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
                "Cannot represent {} using available amounts (max {})",
                target,
                maximum_amount
            );
        }

        // Build amounts vector by iterating in reverse (largest-first)
        let mut amounts = Vec::new();
        for (&amount, &count) in count_by_amount.iter().rev() {
            for _ in 0..count {
                amounts.push(amount);
            }
        }

        Ok(Self { amounts, count_by_amount, input_fee_ppk: keyset_info.input_fee_ppk })
    }

    /// Get the number of amounts in the list
    pub fn len(&self) -> usize {
        self.amounts.len()
    }

    /// Get the total nominal value (sum of all amounts)
    pub fn total(&self) -> u64 {
        self.amounts.iter().sum()
    }

    /// Calculate the value after fees
    ///
    /// Uses the fee formula: (input_fee_ppk * num_outputs + 999) / 1000 (rounds up)
    pub fn value_after_fees(&self) -> u64 {
        let total = self.total();
        if self.input_fee_ppk == 0 {
            return total;
        }
        let num_outputs = self.amounts.len() as u64;
        let fee = (self.input_fee_ppk * num_outputs + 999) / 1000;
        total.saturating_sub(fee)
    }

    /// Iterate over the count map in normal order (smallest-first)
    /// Returns an iterator over (&amount, &count) pairs in ascending order by amount
    /// This is the recommended order for Cashu protocol outputs
    pub fn iter_smallest_first(&self) -> impl Iterator<Item = (&u64, &usize)> {
        self.count_by_amount.iter()
    }
}

/// Keyset information for fee calculations and amount selection
///
/// Represents a real keyset from a mint. The keys and amounts are not filtered;
/// methods that need to respect a maximum amount take it as a parameter.
#[derive(Debug, Clone)]
pub struct KeysetInfo {
    /// Keyset ID
    pub keyset_id: Id,
    /// Set of active keys from the mint (map from amount to pubkey)
    pub active_keys: Keys,
    /// Available amounts in the keyset, sorted largest first
    pub amounts_largest_first: Vec<u64>,
    /// Input fee in parts per thousand
    pub input_fee_ppk: u64,
}

impl KeysetInfo {
    /// Create new keyset info from active keys
    pub fn new(keyset_id: Id, active_keys: Keys, input_fee_ppk: u64) -> Self {
        // Extract and sort amounts from the keyset (largest first)
        let mut amounts_largest_first: Vec<u64> = active_keys
            .iter()
            .map(|(amt, _)| u64::from(*amt))
            .collect();
        amounts_largest_first.sort_unstable_by(|a, b| b.cmp(a)); // Descending order

        Self {
            keyset_id,
            active_keys,
            amounts_largest_first,
            input_fee_ppk,
        }
    }

    /// Calculate the value after fees for a given nominal value
    ///
    /// Given a nominal value (what you allocate in deterministic outputs),
    /// this calculates what remains after paying the input fees when those outputs are used.
    /// Only considers amounts <= maximum_amount when determining output count.
    pub fn deterministic_value_after_fees(
        &self,
        nominal_value: u64,
        maximum_amount: u64,
    ) -> anyhow::Result<u64> {
        let amounts = OrderedListOfAmounts::from_target(nominal_value, maximum_amount, self)?;
        Ok(amounts.value_after_fees())
    }

    /// Find the inverse of deterministic_value_after_fees
    ///
    /// Given a target final balance, this returns the smallest nominal value
    /// that achieves at least the target balance, along with the actual balance
    /// you'll get (which may be slightly higher due to discrete denominations).
    /// Only considers amounts <= maximum_amount.
    pub fn inverse_deterministic_value_after_fees(
        &self,
        target_balance: u64,
        maximum_amount: u64,
    ) -> anyhow::Result<InverseFeeResult> {
        if target_balance == 0 {
            return Ok(InverseFeeResult {
                nominal_value: 0,
                actual_balance: 0,
            });
        }

        // If there are no fees, the inverse is trivial
        if self.input_fee_ppk == 0 {
            return Ok(InverseFeeResult {
                nominal_value: target_balance,
                actual_balance: target_balance,
            });
        }

        // Get the smallest amount in the filtered keyset
        let smallest = self.amounts_largest_first
            .iter()
            .copied()
            .filter(|&amt| amt <= maximum_amount)
            .last()
            .unwrap_or(1);

        // Start with the target as initial guess and search upward
        let mut nominal = target_balance;

        loop {
            let actual_balance = self.deterministic_value_after_fees(nominal, maximum_amount)?;

            if actual_balance >= target_balance {
                // Found it! Return the nominal value and what we actually get
                return Ok(InverseFeeResult {
                    nominal_value: nominal,
                    actual_balance,
                });
            }

            // Need more - increment by the smallest amount in the keyset
            nominal += smallest;

            // Safety check to prevent infinite loops
            if nominal > target_balance * 2 {
                anyhow::bail!(
                    "Could not find nominal value for target balance {} after searching up to {}",
                    target_balance,
                    nominal
                );
            }
        }
    }
}
