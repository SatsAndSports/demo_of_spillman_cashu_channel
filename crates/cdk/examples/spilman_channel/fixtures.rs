//! Spilman Channel Fixtures
//!
//! Contains the fixed channel components known to both parties

use cdk::nuts::{CheckStateRequest, CheckStateResponse, Proof};

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
    ) -> Result<Self, anyhow::Error> {
        // Assert all proofs have the expected keyset_id from params
        let expected_keyset_id = extra.params.active_keyset_id;
        for proof in &funding_proofs {
            if proof.keyset_id != expected_keyset_id {
                anyhow::bail!(
                    "Funding proof has keyset_id {} but expected {} from params",
                    proof.keyset_id,
                    expected_keyset_id
                );
            }
        }

        // Calculate total raw value of the locked proofs
        let total_locked_value: u64 = funding_proofs.iter()
            .map(|proof| u64::from(proof.amount))
            .sum();

        // Calculate total input fee using the fee formula
        // Since all proofs have the same keyset_id, we can simply multiply:
        // total_fee_sats = (input_fee_ppk * num_proofs + 999) / 1000  (rounds up)
        let num_proofs = funding_proofs.len() as u64;
        let sum_fees_ppk = extra.params.input_fee_ppk * num_proofs;
        let total_input_fee = (sum_fees_ppk + 999) / 1000;

        Ok(Self {
            extra,
            funding_proofs,
            total_locked_value,
            total_input_fee,
        })
    }

    /// Get the nominal value available after stage 1 fees
    /// This is the amount that will be distributed as deterministic outputs
    /// Returns: total_locked_value - total_input_fee
    pub fn post_fee_amount_in_the_funding_token(&self) -> u64 {
        self.total_locked_value - self.total_input_fee
    }

    /// Get the Y value for checking the funding token state
    ///
    /// Since all funding proofs are spent together (they're all inputs to the commitment transaction),
    /// checking any one of them is sufficient to determine if the funding token has been spent.
    /// This returns the Y value of the first funding proof for use with NUT-07 state checks.
    pub fn get_funding_token_y_for_state_check(&self) -> Result<cdk::nuts::PublicKey, anyhow::Error> {
        let proof = self.funding_proofs.first()
            .ok_or_else(|| anyhow::anyhow!("No funding proofs available"))?;
        Ok(proof.y()?)
    }

    /// Check the state of the funding token using NUT-07
    ///
    /// Since all funding proofs are spent together (they're all inputs to the commitment transaction),
    /// checking any one of them is sufficient to determine if the funding token has been spent.
    /// This method checks the first funding proof and returns the full response.
    ///
    /// The response will indicate if the funding token is UNSPENT, PENDING, or SPENT.
    pub async fn check_funding_token_state<M>(&self, mint_connection: &M) -> Result<CheckStateResponse, anyhow::Error>
    where
        M: super::MintConnection + ?Sized,
    {
        let y = self.get_funding_token_y_for_state_check()?;
        let request = CheckStateRequest { ys: vec![y] };
        Ok(mint_connection.check_state(request).await?)
    }

}
