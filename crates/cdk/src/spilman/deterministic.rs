//! Deterministic P2PK Output Generation
//!
//! Types for creating deterministic P2PK outputs for Spilman payment channels.
//! Contains a hierarchy of output types:
//! - `DeterministicSecretWithBlinding` - single output (secret + blinding + amount)
//! - `DeterministicOutputsForOneContext` - all outputs for one party
//! - `CommitmentOutputs` - outputs for both parties (receiver + sender)

use async_trait::async_trait;

use crate::dhke::blind_message;
use crate::nuts::{BlindedMessage, BlindSignature, Id, RestoreRequest, SecretKey};
use crate::nuts::nut11::{Conditions, SigFlag};
use crate::secret::Secret;
use crate::Amount;

use super::keysets_and_amounts::OrderedListOfAmounts;
use super::params::ChannelParameters;

/// Trait for mint connection operations needed by Spilman channels
#[async_trait]
pub trait MintConnection: Send + Sync {
    /// Process a swap request
    async fn process_swap(&self, request: crate::nuts::SwapRequest) -> anyhow::Result<crate::nuts::SwapResponse>;
    /// Post a restore request
    async fn post_restore(&self, request: RestoreRequest) -> anyhow::Result<crate::nuts::RestoreResponse>;
    /// Check proof state
    async fn check_state(&self, ys: Vec<crate::nuts::PublicKey>) -> anyhow::Result<crate::nuts::CheckStateResponse>;
}

/// Deterministic secret with blinding factor
/// Can hold any type of secret (simple P2PK, P2PK with conditions, HTLC, etc.)
#[derive(Debug, Clone)]
pub struct DeterministicSecretWithBlinding {
    /// The secret (can be any NUT-10 secret with specified nonce)
    pub secret: Secret,
    /// The blinding factor
    pub blinding_factor: SecretKey,
    /// The amount for this output
    pub amount: u64,
}

impl DeterministicSecretWithBlinding {
    /// Create a simple P2PK output (1-of-1 signature)
    /// Used for commitment outputs (sender or receiver)
    pub fn new_p2pk(
        pubkey: &crate::nuts::PublicKey,
        nonce: String,
        blinding_factor: SecretKey,
        amount: u64,
    ) -> Result<Self, anyhow::Error> {
        // Manually construct the NUT-10 P2PK secret JSON
        // Format: ["P2PK", {"nonce": "...", "data": "pubkey_hex", "tags": null}]
        let secret_json = serde_json::json!([
            "P2PK",
            {
                "nonce": nonce,
                "data": pubkey.to_hex(),
                "tags": null
            }
        ]);

        // Create a Secret from the JSON string
        let secret = Secret::new(secret_json.to_string());

        Ok(Self {
            secret,
            blinding_factor,
            amount,
        })
    }

    /// Create a funding output with 2-of-2 multisig + locktime conditions
    /// Used for the funding token that both parties must sign to spend,
    /// or Alice alone can reclaim after locktime
    pub fn new_funding(
        alice_pubkey: &crate::nuts::PublicKey,
        charlie_pubkey: &crate::nuts::PublicKey,
        locktime: u64,
        nonce: String,
        blinding_factor: SecretKey,
        amount: u64,
    ) -> Result<Self, anyhow::Error> {
        // Create the spending conditions: 2-of-2 multisig (Alice + Charlie) before locktime
        // After locktime, Alice can refund with just her signature
        let conditions = Conditions::new(
            Some(locktime),                       // Locktime for Alice's refund
            Some(vec![*charlie_pubkey]),          // Charlie's key as additional pubkey for 2-of-2
            Some(vec![*alice_pubkey]),            // Alice can refund after locktime
            Some(2),                              // Require 2 signatures (Alice + Charlie) before locktime
            Some(SigFlag::SigAll),                // SigAll: signatures commit to outputs
            Some(1),                              // Only 1 signature needed for refund (Alice)
        )?;

        // Convert conditions to proper NUT-10/11 tag array format
        let tags: Vec<Vec<String>> = conditions.into();
        let tags_json = serde_json::to_value(tags)
            .map_err(|e| anyhow::anyhow!("Failed to serialize spending conditions: {}", e))?;

        // Manually construct the NUT-10 P2PK secret JSON with spending conditions
        // Format: ["P2PK", {"nonce": "...", "data": "pubkey_hex", "tags": [...conditions...]}]
        let secret_json = serde_json::json!([
            "P2PK",
            {
                "nonce": nonce,
                "data": alice_pubkey.to_hex(),
                "tags": tags_json
            }
        ]);

        // Create a Secret from the JSON string
        let secret = Secret::new(secret_json.to_string());

        Ok(Self {
            secret,
            blinding_factor,
            amount,
        })
    }

    /// Create a BlindedMessage from this deterministic output
    pub fn to_blinded_message(
        &self,
        amount: Amount,
        keyset_id: Id,
    ) -> Result<BlindedMessage, anyhow::Error> {
        // Blind the secret using the deterministic blinding factor
        let (blinded_point, _) = blind_message(&self.secret.to_bytes(), Some(self.blinding_factor.clone()))?;

        Ok(BlindedMessage::new(amount, keyset_id, blinded_point))
    }
}

/// A set of deterministic outputs for a specific pubkey and amount
/// This represents all the deterministic blinded messages, secrets, and blinding factors
/// for splitting a given amount into ecash outputs
#[derive(Debug, Clone)]
pub struct DeterministicOutputsForOneContext {
    /// The context for these outputs: "sender", "receiver", or "funding"
    pub context: String,
    /// The total amount to allocate
    pub amount: u64,
    /// The breakdown of amounts (largest-first)
    pub ordered_amounts: OrderedListOfAmounts,
    /// Channel parameters (includes shared_secret)
    pub params: ChannelParameters,
}

impl DeterministicOutputsForOneContext {
    /// Create a new set of deterministic outputs
    pub fn new(
        context: String,
        amount: u64,
        params: ChannelParameters,
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
    pub fn value_after_fees(&self) -> u64 {
        self.ordered_amounts.value_after_fees()
    }

    /// Get the secrets with blinding for these outputs
    /// Works for all contexts: "sender", "receiver", and "funding"
    /// Returns full DeterministicSecretWithBlinding objects (secret + blinding factor)
    /// Outputs are ordered smallest-first per Cashu protocol recommendation
    pub fn get_secrets_with_blinding(&self) -> Result<Vec<DeterministicSecretWithBlinding>, anyhow::Error> {
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

/// Commitment outputs for a specific balance distribution
/// Contains the deterministic outputs for both sender (Alice) and receiver (Charlie)
/// at a specific balance point in the channel
#[derive(Debug, Clone)]
pub struct CommitmentOutputs {
    /// Receiver's (Charlie's) deterministic outputs
    pub receiver_outputs: DeterministicOutputsForOneContext,
    /// Sender's (Alice's) deterministic outputs
    pub sender_outputs: DeterministicOutputsForOneContext,
}

impl CommitmentOutputs {
    /// Create new commitment outputs
    pub fn new(
        receiver_outputs: DeterministicOutputsForOneContext,
        sender_outputs: DeterministicOutputsForOneContext,
    ) -> Self {
        Self {
            receiver_outputs,
            sender_outputs,
        }
    }

    /// Create commitment outputs for a given receiver balance
    ///
    /// Given the receiver's (Charlie's) desired final balance, this creates:
    /// - One DeterministicOutputsForOneContext for the receiver (Charlie)
    /// - One DeterministicOutputsForOneContext for the sender (Alice) with the remainder
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
        params: &ChannelParameters,
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
        let charlie_outputs = DeterministicOutputsForOneContext::new(
            "receiver".to_string(),
            charlie_nominal,
            params.clone(),
        )?;

        // Create outputs for Alice (sender)
        let alice_outputs = DeterministicOutputsForOneContext::new(
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
        funding_proofs: Vec<crate::nuts::Proof>,
    ) -> Result<crate::nuts::SwapRequest, anyhow::Error> {
        // Get blinded messages for receiver (Charlie)
        let mut outputs = self.receiver_outputs.get_blinded_messages()?;

        // Get blinded messages for sender (Alice)
        let sender_outputs = self.sender_outputs.get_blinded_messages()?;

        // Concatenate (receiver first, then sender)
        outputs.extend(sender_outputs);

        // Sort by amount (stable) for privacy - mixes receiver and sender outputs
        outputs.sort_by_key(|bm| u64::from(bm.amount));

        // Create swap request with all funding proofs as inputs
        Ok(crate::nuts::SwapRequest::new(funding_proofs, outputs))
    }

    /// Unblind all outputs from a swap response
    ///
    /// Takes the blind signatures from the swap response and returns
    /// (receiver_proofs, sender_proofs) as two separate vectors
    pub fn unblind_all(
        &self,
        blind_signatures: Vec<BlindSignature>,
        active_keys: &crate::nuts::Keys,
    ) -> Result<(Vec<crate::nuts::Proof>, Vec<crate::nuts::Proof>), anyhow::Error> {
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
        let mut all_outputs: Vec<(DeterministicSecretWithBlinding, bool)> =
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
        let all_proofs = crate::dhke::construct_proofs(
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
        M: MintConnection + ?Sized,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nuts::{CurrencyUnit, Id, Keys};
    use super::super::keysets_and_amounts::KeysetInfo;

    fn create_test_params(input_fee_ppk: u64, power: u64) -> ChannelParameters {
        // Create a simple keyset with powers of the given base for testing
        // power=2 gives powers-of-2: 1, 2, 4, 8, 16, ...
        // power=10 gives powers-of-10: 1, 10, 100, 1000, ...
        use std::collections::BTreeMap;

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

        ChannelParameters::new_with_secret_key(
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
}
