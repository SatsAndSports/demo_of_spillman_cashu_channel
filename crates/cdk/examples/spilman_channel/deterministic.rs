//! Deterministic P2PK Output Generation
//!
//! Functions and types for creating deterministic P2PK outputs

use cdk::dhke::blind_message;
use cdk::nuts::{BlindedMessage, Id, SecretKey};
use cdk::secret::Secret;
use cdk::Amount;

/// Deterministic P2PK output containing a secret and blinding factor
#[derive(Debug, Clone)]
pub struct DeterministicP2pkOutputWithBlinding {
    /// The secret (NUT-10 P2PK secret with specified nonce)
    pub secret: Secret,
    /// The blinding factor
    pub blinding_factor: SecretKey,
}

impl DeterministicP2pkOutputWithBlinding {
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

/// Create a deterministic P2PK output from explicit inputs
/// Takes a pubkey, nonce (as hex string), and blinding factor
/// Returns a DeterministicP2pkOutputWithBlinding with the constructed secret
pub fn create_deterministic_p2pk_output(
    pubkey: &cdk::nuts::PublicKey,
    nonce: String,
    blinding_factor: SecretKey,
) -> Result<DeterministicP2pkOutputWithBlinding, anyhow::Error> {
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

    Ok(DeterministicP2pkOutputWithBlinding {
        secret,
        blinding_factor,
    })
}
