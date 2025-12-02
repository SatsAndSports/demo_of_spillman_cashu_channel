//! Established Spilman Channel
//!
//! Contains the complete channel state after funding

use cdk::nuts::{CheckStateRequest, Proof};

use super::extra::SpilmanChannelExtra;

/// An established Spilman payment channel
/// Contains all channel components after funding transaction is complete
#[derive(Debug, Clone)]
pub struct EstablishedChannel {
    /// Channel parameters plus mint-specific data
    pub extra: SpilmanChannelExtra,
    /// Locked proofs (2-of-2 multisig with locktime refund)
    pub funding_proofs: Vec<Proof>,
}

impl EstablishedChannel {
    /// Create new established channel
    pub fn new(
        extra: SpilmanChannelExtra,
        funding_proofs: Vec<Proof>,
    ) -> Result<Self, anyhow::Error> {
        // TODO: verify everything, especially for Charlie's security, either
        // here or in another function


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

        // Assert the total value of funding proofs matches the expected funding token amount
        let actual_funding_value: u64 = funding_proofs.iter()
            .map(|proof| u64::from(proof.amount))
            .sum();
        let expected_funding_value = extra.get_total_funding_token_amount()?;

        if actual_funding_value != expected_funding_value {
            anyhow::bail!(
                "Funding proofs total value {} does not match expected funding token amount {}",
                actual_funding_value,
                expected_funding_value
            );
        }

        Ok(Self {
            extra,
            funding_proofs,
        })
    }

    /// Get the Y value for checking the funding token state
    ///
    /// Since all funding proofs are spent together (they're all inputs to the commitment transaction),
    /// checking any one of them is sufficient to determine if the funding token has been spent.
    /// This returns the Y value of the first funding proof for use with NUT-07 state checks.
    fn get_one_funding_token_y_for_state_check(&self) -> Result<cdk::nuts::PublicKey, anyhow::Error> {
        let proof = self.funding_proofs.first()
            .ok_or_else(|| anyhow::anyhow!("No funding proofs available"))?;
        Ok(proof.y()?)
    }

    /// Check the state of the funding token using NUT-07
    ///
    /// Since all funding proofs are spent together (they're all inputs to the commitment transaction),
    /// checking any one of them is sufficient to determine if the funding token has been spent.
    /// This method checks the first funding proof and returns its state.
    ///
    /// Returns the state (UNSPENT, PENDING, or SPENT) of the funding token.
    pub async fn check_funding_token_state<M>(&self, mint_connection: &M) -> Result<cdk::nuts::ProofState, anyhow::Error>
    where
        M: super::MintConnection + ?Sized,
    {
        let y = self.get_one_funding_token_y_for_state_check()?;
        let request = CheckStateRequest { ys: vec![y] };
        let response = mint_connection.check_state(request).await?;
        response.states.into_iter().next()
            .ok_or_else(|| anyhow::anyhow!("No state returned for funding token"))
    }

}
