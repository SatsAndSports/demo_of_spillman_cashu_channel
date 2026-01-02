//! Spilman Channel Sender and Receiver
//!
//! This module contains the sender's (Alice's) and receiver's (Charlie's) views
//! of a Spilman payment channel, plus standalone verification functions.

use serde::Serialize;

use crate::nuts::{Proof, PublicKey, RestoreRequest, SecretKey, SwapRequest};
use crate::Amount;

use super::established_channel::EstablishedChannel;
use super::balance_update::BalanceUpdateMessage;
use super::deterministic::{CommitmentOutputs, MintConnection};
use super::params::ChannelParameters;

// ============================================================================
// Channel Verification
// ============================================================================

/// Errors that can occur during channel verification
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum ChannelVerificationError {
    /// DLEQ proof is missing for a proof
    MissingDleq { proof_index: usize, amount: u64 },
    /// DLEQ proof is invalid (cryptographic verification failed)
    InvalidDleq { proof_index: usize, amount: u64, reason: String },
    /// No mint public key found for this amount in the keyset
    MissingMintKey { proof_index: usize, amount: u64 },
    /// Keyset ID doesn't match the keys (keys may have been tampered with)
    InvalidKeysetId { expected: String, computed: String },
}

/// Result of verifying a channel
#[derive(Debug, Serialize)]
pub struct ChannelVerificationResult {
    /// Whether all verifications passed
    pub valid: bool,
    /// List of errors found (empty if valid)
    pub errors: Vec<ChannelVerificationError>,
}

impl ChannelVerificationResult {
    /// Create a successful result
    pub fn ok() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
        }
    }

    /// Create a failed result with errors
    pub fn failed(errors: Vec<ChannelVerificationError>) -> Self {
        Self {
            valid: false,
            errors,
        }
    }

    /// Check if verification passed
    pub fn is_ok(&self) -> bool {
        self.valid
    }
}

/// Verify that a channel is valid
///
/// This function verifies everything about a channel that the receiver (Charlie)
/// needs to check before accepting it:
///
/// 1. Keyset ID matches the keys (prevents key substitution attacks)
/// 2. DLEQ proofs - the mint actually signed each funding proof (offline verification)
///
/// Future verifications to add:
/// - Secret structure matches expected deterministic derivation
/// - Spending conditions are correct (2-of-2 multisig with locktime)
/// - Total value matches expected funding amount
///
/// Returns a result containing all verification errors found (if any)
pub fn verify_valid_channel(
    funding_proofs: &[Proof],
    params: &ChannelParameters,
) -> ChannelVerificationResult {
    use crate::nuts::Id;

    let mut errors = Vec::new();

    // 1. Verify keyset ID matches the keys
    // This prevents an attacker from providing fake keys while claiming a legitimate keyset ID
    let expected_keyset_id = params.keyset_info.keyset_id;
    let computed_keyset_id = Id::v1_from_keys(&params.keyset_info.active_keys);

    if expected_keyset_id != computed_keyset_id {
        errors.push(ChannelVerificationError::InvalidKeysetId {
            expected: expected_keyset_id.to_string(),
            computed: computed_keyset_id.to_string(),
        });
        // Continue to collect other errors
    }

    // 2. Verify DLEQ for each funding proof
    for (i, proof) in funding_proofs.iter().enumerate() {
        let amount = u64::from(proof.amount);

        // Check that DLEQ is present
        if proof.dleq.is_none() {
            errors.push(ChannelVerificationError::MissingDleq {
                proof_index: i,
                amount,
            });
            continue;
        }

        // Get the mint's public key for this amount
        let mint_pubkey: Option<PublicKey> = params
            .keyset_info
            .active_keys
            .amount_key(proof.amount);

        let mint_pubkey = match mint_pubkey {
            Some(key) => key,
            None => {
                errors.push(ChannelVerificationError::MissingMintKey {
                    proof_index: i,
                    amount,
                });
                continue;
            }
        };

        // Verify the DLEQ cryptographically
        if let Err(e) = proof.verify_dleq(mint_pubkey) {
            errors.push(ChannelVerificationError::InvalidDleq {
                proof_index: i,
                amount,
                reason: e.to_string(),
            });
        }
    }

    if errors.is_empty() {
        ChannelVerificationResult::ok()
    } else {
        ChannelVerificationResult::failed(errors)
    }
}

// ============================================================================
// Sender and Receiver
// ============================================================================

/// The sender's view of a Spilman payment channel
///
/// This struct holds Alice's secret key and the established channel state.
/// It provides high-level methods for Alice's operations.
pub struct SpilmanChannelSender {
    /// Alice's secret key for signing
    pub alice_secret: SecretKey,
    /// The established channel state
    pub channel: EstablishedChannel,
}

impl SpilmanChannelSender {
    /// Create a new sender instance
    pub fn new(alice_secret: SecretKey, channel: EstablishedChannel) -> Self {
        Self {
            alice_secret,
            channel,
        }
    }

    /// Create and sign a balance update for the given amount to Charlie
    ///
    /// Returns (BalanceUpdateMessage, SwapRequest with Alice's signature)
    pub fn create_signed_balance_update(
        &self,
        charlie_balance: u64,
    ) -> anyhow::Result<(BalanceUpdateMessage, SwapRequest)> {
        // Create commitment outputs for this balance
        let commitment_outputs = CommitmentOutputs::for_balance(
            charlie_balance,
            &self.channel.params,
        )?;

        // Create unsigned swap request
        let mut swap_request = commitment_outputs.create_swap_request(
            self.channel.funding_proofs.clone(),
        )?;

        // Alice signs the swap request
        swap_request.sign_sig_all(self.alice_secret.clone())?;

        // Create the balance update message
        let balance_update = BalanceUpdateMessage::from_signed_swap_request(
            self.channel.params.get_channel_id(),
            charlie_balance,
            &swap_request,
        )?;

        Ok((balance_update, swap_request))
    }

    /// Get the de facto balance (after fee rounding) for an intended balance
    pub fn get_de_facto_balance(&self, intended_balance: u64) -> anyhow::Result<u64> {
        self.channel.params.get_de_facto_balance(intended_balance)
    }

    /// Get the channel capacity
    pub fn capacity(&self) -> u64 {
        self.channel.params.capacity
    }

    /// Get the channel ID
    pub fn channel_id(&self) -> String {
        self.channel.params.get_channel_id()
    }

    /// Get the shared secret with Charlie (stored in channel params)
    pub fn get_shared_secret(&self) -> &[u8; 32] {
        &self.channel.params.shared_secret
    }

    /// Restore sender's proofs after Charlie has exited the channel
    ///
    /// When Charlie exits by submitting the commitment transaction, Alice may not
    /// receive her blind signatures directly. This method uses NUT-09 restore to
    /// recover Alice's proofs by iterating over all possible (amount, index) pairs.
    ///
    /// The algorithm:
    /// - For each amount in the keyset (ascending, filtered by max_amount):
    ///   - For index starting at 0:
    ///     - Try to restore the deterministic output for ("sender", amount, index)
    ///     - If restore fails (no signature), break to next amount
    ///     - If restore succeeds, unblind and collect the proof, increment index
    ///
    /// Returns all recovered proofs for Alice.
    pub async fn restore_sender_proofs<M: MintConnection + ?Sized>(
        &self,
        mint_connection: &M,
    ) -> anyhow::Result<Vec<Proof>> {
        let params = &self.channel.params;
        let keyset_id = params.keyset_info.keyset_id;
        let max_amount = params.maximum_amount_for_one_output;

        // Get amounts in ascending order (smallest first)
        let mut amounts: Vec<u64> = params.keyset_info.amounts_largest_first
            .iter()
            .copied()
            .filter(|&amt| amt <= max_amount)
            .collect();
        amounts.reverse(); // Now smallest first

        let mut recovered_proofs = Vec::new();

        for amount in amounts {
            let mut index = 0usize;

            loop {
                // Create deterministic output for this (amount, index)
                let det_output = params.create_deterministic_output_with_blinding(
                    "sender",
                    amount,
                    index,
                )?;

                // Create blinded message for restore request
                let blinded_message = det_output.to_blinded_message(
                    Amount::from(amount),
                    keyset_id,
                )?;

                // Try to restore this single output
                let restore_request = RestoreRequest {
                    outputs: vec![blinded_message],
                };

                let restore_response = mint_connection.post_restore(restore_request).await;

                match restore_response {
                    Ok(response) if !response.signatures.is_empty() => {
                        // Success! Unblind the signature to get the proof
                        let blind_signature = response.signatures.into_iter().next().unwrap();

                        let proof = crate::dhke::construct_proofs(
                            vec![blind_signature],
                            vec![det_output.blinding_factor.clone()],
                            vec![det_output.secret.clone()],
                            &params.keyset_info.active_keys,
                        )?.into_iter().next().unwrap();

                        recovered_proofs.push(proof);
                        index += 1;
                    }
                    _ => {
                        // No signature found for this (amount, index), move to next amount
                        break;
                    }
                }
            }
        }

        Ok(recovered_proofs)
    }
}

/// The receiver's view of a Spilman payment channel
///
/// This struct holds Charlie's secret key and the established channel state.
/// It provides high-level methods for Charlie's operations.
pub struct SpilmanChannelReceiver {
    /// Charlie's secret key for signing
    pub charlie_secret: SecretKey,
    /// The established channel state
    pub channel: EstablishedChannel,
}

impl SpilmanChannelReceiver {
    /// Create a new receiver instance
    pub fn new(charlie_secret: SecretKey, channel: EstablishedChannel) -> Self {
        Self {
            charlie_secret,
            channel,
        }
    }

    /// Verify a balance update signature from the sender
    pub fn verify_sender_signature(&self, balance_update: &BalanceUpdateMessage) -> anyhow::Result<()> {
        balance_update.verify_sender_signature(&self.channel)
    }

    /// Add receiver's signature to complete the 2-of-2 multisig
    ///
    /// This verifies Alice's signature on the balance update, then adds Charlie's
    /// signature to the swap request, making it ready to submit to the mint.
    ///
    /// Returns the fully-signed SwapRequest ready for execution
    pub fn add_second_signature(
        &self,
        balance_update: &BalanceUpdateMessage,
        mut swap_request: SwapRequest,
    ) -> anyhow::Result<SwapRequest> {
        // Verify that Alice's signature is valid
        self.verify_sender_signature(balance_update)?;

        // Add Charlie's signature to complete the 2-of-2 multisig
        swap_request.sign_sig_all(self.charlie_secret.clone())?;

        Ok(swap_request)
    }

    /// Get the de facto balance (after fee rounding) for an intended balance
    pub fn get_de_facto_balance(&self, intended_balance: u64) -> anyhow::Result<u64> {
        self.channel.params.get_de_facto_balance(intended_balance)
    }

    /// Get the channel capacity
    pub fn capacity(&self) -> u64 {
        self.channel.params.capacity
    }

    /// Get the channel ID
    pub fn channel_id(&self) -> String {
        self.channel.params.get_channel_id()
    }

    /// Get the shared secret with Alice (stored in channel params)
    pub fn get_shared_secret(&self) -> &[u8; 32] {
        &self.channel.params.shared_secret
    }
}
