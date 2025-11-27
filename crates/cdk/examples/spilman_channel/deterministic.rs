//! Deterministic P2PK Output Generation
//!
//! Functions and types for creating deterministic P2PK outputs

use cdk::dhke::blind_message;
use cdk::nuts::{BlindedMessage, Id, SecretKey};
use cdk::nuts::nut11::{Conditions, SigFlag};
use cdk::secret::Secret;
use cdk::Amount;

/// Deterministic nonce and blinding factor pair
#[derive(Debug, Clone)]
pub struct DeterministicNonceAndBlinding {
    /// The deterministically derived nonce (as hex string)
    pub nonce: String,
    /// The deterministically derived blinding factor
    pub blinding_factor: SecretKey,
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

/// Create a deterministic commitment output from a nonce/blinding pair and pubkey
/// Takes a DeterministicNonceAndBlinding and a pubkey for Charlie (receiver) or Alice (sender)
/// Returns a DeterministicSecretWithBlinding with a simple P2PK secret (no conditions)
pub fn create_deterministic_commitment_output(
    pubkey: &cdk::nuts::PublicKey,
    nonce_and_blinding: DeterministicNonceAndBlinding,
    amount: u64,
) -> Result<DeterministicSecretWithBlinding, anyhow::Error> {
    // Extract nonce and blinding factor directly
    let nonce = nonce_and_blinding.nonce;
    let blinding_factor = nonce_and_blinding.blinding_factor;

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

    Ok(DeterministicSecretWithBlinding {
        secret,
        blinding_factor,
        amount,
    })
}

/// Create a deterministic funding output from a nonce/blinding pair
/// Takes both Alice and Charlie's pubkeys, locktime, and DeterministicNonceAndBlinding
/// Returns a DeterministicSecretWithBlinding with P2PK secret with 2-of-2 multisig + locktime conditions
pub fn create_deterministic_funding_output(
    alice_pubkey: &cdk::nuts::PublicKey,
    charlie_pubkey: &cdk::nuts::PublicKey,
    locktime: u64,
    nonce_and_blinding: DeterministicNonceAndBlinding,
    amount: u64,
) -> Result<DeterministicSecretWithBlinding, anyhow::Error> {
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

    // Extract nonce and blinding factor directly
    let nonce = nonce_and_blinding.nonce;
    let blinding_factor = nonce_and_blinding.blinding_factor;

    // Serialize the conditions for the secret
    let conditions_json = serde_json::to_value(&conditions)
        .map_err(|e| anyhow::anyhow!("Failed to serialize spending conditions: {}", e))?;

    // Manually construct the NUT-10 P2PK secret JSON with spending conditions
    // Format: ["P2PK", {"nonce": "...", "data": "pubkey_hex", "tags": [...conditions...]}]
    let secret_json = serde_json::json!([
        "P2PK",
        {
            "nonce": nonce,
            "data": alice_pubkey.to_hex(),
            "tags": conditions_json
        }
    ]);

    // Create a Secret from the JSON string
    let secret = Secret::new(secret_json.to_string());

    Ok(DeterministicSecretWithBlinding {
        secret,
        blinding_factor,
        amount,
    })
}
