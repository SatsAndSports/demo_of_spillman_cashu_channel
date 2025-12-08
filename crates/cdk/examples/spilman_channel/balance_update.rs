//! Balance Update Message
//!
//! Represents a signed balance update in a Spilman payment channel

use bitcoin::secp256k1::schnorr::Signature;
use cdk::nuts::nut10::SpendingConditionVerification;
use cdk::nuts::SwapRequest;

use super::established_channel::EstablishedChannel;
use super::extra::CommitmentOutputs;
use super::test_helpers::get_signatures_from_swap_request;

/// A balance update message from Alice to Charlie
///
/// This represents a signed commitment to a new channel balance.
/// Alice signs a swap request that distributes the channel funds according to the new balance.
#[derive(Debug, Clone)]
pub struct BalanceUpdateMessage {
    /// Channel ID to identify which channel this update is for
    pub channel_id: String,
    /// New balance for the receiver (Charlie)
    pub amount: u64,
    /// Alice's signature over the swap request
    pub signature: Signature,
}

impl BalanceUpdateMessage {
    /// Used by Alice to create a balance update message from a swap request
    /// which is signed by her. She then sends the resulting message to Charlie.
    pub fn from_signed_swap_request(
        channel_id: String,
        amount: u64,
        swap_request: &SwapRequest,
    ) -> Result<Self, anyhow::Error> {
        // Extract Alice's signature from the swap request
        let signatures = get_signatures_from_swap_request(swap_request)?;

        // Ensure there is exactly one signature (Alice's only)
        if signatures.len() != 1 {
            anyhow::bail!(
                "Expected exactly 1 signature (Alice's), but found {}",
                signatures.len()
            );
        }

        let signature = signatures[0].clone();

        Ok(Self {
            channel_id,
            amount,
            signature,
        })
    }

    /// Verify the signature using the established channel
    /// Charlie reconstructs the swap request from the amount to verify the signature
    /// Throws an error if the signature is invalid
    pub fn verify_sender_signature(&self, channel: &EstablishedChannel) -> Result<(), anyhow::Error> {
        // Reconstruct the commitment outputs for this balance
        let commitment_outputs = CommitmentOutputs::for_balance(
            self.amount,
            &channel.params,
        )?;

        // Reconstruct the unsigned swap request
        let swap_request = commitment_outputs.create_swap_request(
            channel.funding_proofs.clone(),
        )?;

        // Extract the SIG_ALL message from the swap request
        let msg_to_sign = swap_request.sig_all_msg_to_sign();

        // Verify the signature using Alice's pubkey from channel params
        channel.params.alice_pubkey
            .verify(msg_to_sign.as_bytes(), &self.signature)
            .map_err(|_| anyhow::anyhow!("Invalid signature: Alice did not authorize this balance update"))?;

        Ok(())
    }
}
