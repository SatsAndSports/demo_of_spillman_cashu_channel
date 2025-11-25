//! Spilman Channel Fixtures
//!
//! Contains the fixed channel components known to both parties

use cdk::nuts::{BlindSignature, KeysetResponse, Proof, SwapRequest};

use super::extra::SpilmanChannelExtra;

/// Fixed channel components known to both parties
/// These are established at channel creation and never change
#[derive(Debug, Clone)]
pub struct ChannelFixtures {
    /// Channel parameters plus mint-specific data
    pub extra: SpilmanChannelExtra,
    /// Locked proofs (2-of-2 multisig with locktime refund)
    pub funding_proofs: Vec<Proof>,
    /// Total raw value of the locked proofs in the base unit
    pub total_locked_value: u64,
    /// Total input fee in sats for the locked proofs (rounded up from ppk)
    pub total_input_fee: u64,
}

impl ChannelFixtures {
    /// Create new channel fixtures
    /// Calculates total input fee from the locked proofs
    pub fn new(
        extra: SpilmanChannelExtra,
        funding_proofs: Vec<Proof>,
        keyset_response: &KeysetResponse,
    ) -> Result<Self, anyhow::Error> {
        // Calculate total raw value of the locked proofs
        let total_locked_value: u64 = funding_proofs.iter()
            .map(|proof| u64::from(proof.amount))
            .sum();

        // Calculate total input fee using the fee formula
        // sum_fees_ppk = sum of (input_fee_ppk for each proof's keyset)
        // total_fee_sats = (sum_fees_ppk + 999) / 1000  (integer division, rounds up)
        let mut sum_fees_ppk = 0u64;

        for proof in &funding_proofs {
            // Find the keyset info for this proof's keyset ID
            let keyset_info = keyset_response.keysets.iter()
                .find(|k| k.id == proof.keyset_id)
                .ok_or_else(|| anyhow::anyhow!("Keyset {} not found for proof", proof.keyset_id))?;

            sum_fees_ppk += keyset_info.input_fee_ppk;
        }

        // Round up: (sum_fees_ppk + 999) / 1000
        let total_input_fee = (sum_fees_ppk + 999) / 1000;

        Ok(Self {
            extra,
            funding_proofs,
            total_locked_value,
            total_input_fee,
        })
    }

    /// Create an unsigned swap request for a given balance to Charlie
    /// Returns a SwapRequest with all funding_proofs as inputs,
    /// and deterministic outputs for Charlie (his balance) and Alice (the remainder)
    pub fn create_unsigned_swap_request(&self, charlie_balance: u64) -> Result<SwapRequest, anyhow::Error> {
        let capacity = self.extra.get_capacity()?;

        if charlie_balance > capacity {
            anyhow::bail!("Charlie's balance {} exceeds channel capacity {}", charlie_balance, capacity);
        }

        let alice_remainder = capacity - charlie_balance;

        // Create deterministic blinded messages for Charlie's balance
        let mut outputs = self.extra.create_deterministic_blinded_messages_for_amount(
            &self.extra.params.charlie_pubkey,
            charlie_balance,
        )?;

        // Create deterministic blinded messages for Alice's remainder
        let alice_outputs = self.extra.create_deterministic_blinded_messages_for_amount(
            &self.extra.params.alice_pubkey,
            alice_remainder,
        )?;

        // Charlie's outputs first, then Alice's
        outputs.extend(alice_outputs);

        // Use all funding_proofs as inputs
        let swap_request = SwapRequest::new(self.funding_proofs.clone(), outputs);

        Ok(swap_request)
    }

    /// Unblind all outputs from a swap response
    /// Takes the blind signatures from the swap response and charlie_balance
    /// Returns (charlie_proofs, alice_proofs) as two separate vectors
    pub fn unblind_all_outputs(
        &self,
        blind_signatures: Vec<BlindSignature>,
        charlie_balance: u64,
    ) -> Result<(Vec<Proof>, Vec<Proof>), anyhow::Error> {
        let capacity = self.extra.get_capacity()?;

        if charlie_balance > capacity {
            anyhow::bail!("Charlie's balance {} exceeds channel capacity {}", charlie_balance, capacity);
        }

        let alice_remainder = capacity - charlie_balance;

        // Get blinding factors for Charlie and Alice
        let charlie_blinding_factors = self.extra.create_deterministic_blinding_factors_for_amount(
            &self.extra.params.charlie_pubkey,
            charlie_balance,
        )?;

        let alice_blinding_factors = self.extra.create_deterministic_blinding_factors_for_amount(
            &self.extra.params.alice_pubkey,
            alice_remainder,
        )?;

        // Get secrets for Charlie and Alice
        let charlie_secrets = self.extra.create_deterministic_secrets_for_amount(
            &self.extra.params.charlie_pubkey,
            charlie_balance,
        )?;

        let alice_secrets = self.extra.create_deterministic_secrets_for_amount(
            &self.extra.params.alice_pubkey,
            alice_remainder,
        )?;

        // Split the blind signatures into Charlie's and Alice's portions
        let charlie_count = charlie_blinding_factors.len();
        let charlie_signatures = blind_signatures.iter().take(charlie_count).cloned().collect::<Vec<_>>();
        let alice_signatures = blind_signatures.iter().skip(charlie_count).cloned().collect::<Vec<_>>();

        // Unblind Charlie's outputs
        let charlie_proofs = cdk::dhke::construct_proofs(
            charlie_signatures,
            charlie_blinding_factors,
            charlie_secrets,
            &self.extra.active_keys,
        )?;

        // Unblind Alice's outputs
        let alice_proofs = cdk::dhke::construct_proofs(
            alice_signatures,
            alice_blinding_factors,
            alice_secrets,
            &self.extra.active_keys,
        )?;

        Ok((charlie_proofs, alice_proofs))
    }
}
