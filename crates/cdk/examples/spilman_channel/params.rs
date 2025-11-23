//! Spilman Channel Parameters
//!
//! Contains the protocol parameters for a Spilman payment channel

use bitcoin::hashes::{sha256, Hash};
use cdk::nuts::{CurrencyUnit, Id, SecretKey};
use cdk::util::hex;

use super::deterministic::{create_deterministic_p2pk_output, DeterministicP2pkOutputWithBlinding};

/// Parameters for a Spilman payment channel (protocol parameters only)
#[derive(Debug, Clone)]
pub struct SpilmanChannelParameters {
    /// Alice's public key (sender)
    pub alice_pubkey: cdk::nuts::PublicKey,
    /// Charlie's public key (receiver)
    pub charlie_pubkey: cdk::nuts::PublicKey,
    /// Currency unit for the channel
    pub unit: CurrencyUnit,
    /// Total channel capacity
    pub capacity: u64,
    /// Locktime after which Alice can reclaim funds (unix timestamp)
    pub locktime: u64,
    /// Setup timestamp (unix timestamp when channel was created)
    pub setup_timestamp: u64,
    /// Sender nonce (random value created by Alice for channel identification)
    pub sender_nonce: String,
    /// Active keyset ID from the mint
    pub active_keyset_id: Id,
    /// Input fee in parts per thousand for this keyset
    pub input_fee_ppk: u64,
}

impl SpilmanChannelParameters {
    /// Create new channel parameters
    pub fn new(
        alice_pubkey: cdk::nuts::PublicKey,
        charlie_pubkey: cdk::nuts::PublicKey,
        unit: CurrencyUnit,
        capacity: u64,
        locktime: u64,
        setup_timestamp: u64,
        sender_nonce: String,
        active_keyset_id: Id,
        input_fee_ppk: u64,
    ) -> anyhow::Result<Self> {
        // Validate input_fee_ppk is in valid range
        if input_fee_ppk > 999 {
            anyhow::bail!(
                "input_fee_ppk must be between 0 and 999 (inclusive), got {}",
                input_fee_ppk
            );
        }

        Ok(Self {
            alice_pubkey,
            charlie_pubkey,
            unit,
            capacity,
            locktime,
            setup_timestamp,
            sender_nonce,
            active_keyset_id,
            input_fee_ppk,
        })
    }

    /// Get channel ID
    /// Format: setup_timestamp|sender_pubkey|receiver_pubkey|locktime|sender_nonce
    pub fn get_id(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.setup_timestamp,
            self.alice_pubkey.to_hex(),
            self.charlie_pubkey.to_hex(),
            self.locktime,
            self.sender_nonce
        )
    }

    /// Get a string representation of the unit
    pub fn unit_name(&self) -> &str {
        match self.unit {
            CurrencyUnit::Sat => "sat",
            CurrencyUnit::Msat => "msat",
            CurrencyUnit::Usd => "usd",
            CurrencyUnit::Eur => "eur",
            _ => "units",
        }
    }

    /// Create a deterministic P2PK output with blinding using the channel ID
    /// Uses channel_id in the derivation for better uniqueness
    pub fn create_deterministic_p2pk_output_with_blinding(
        &self,
        pubkey: &cdk::nuts::PublicKey,
        index: usize,
    ) -> Result<DeterministicP2pkOutputWithBlinding, anyhow::Error> {
        let channel_id = self.get_id();
        let pubkey_bytes = pubkey.to_bytes();
        let index_bytes = index.to_le_bytes();

        // Derive deterministic nonce: SHA256(channel_id || pubkey || index || "nonce")
        let mut nonce_input = Vec::new();
        nonce_input.extend_from_slice(channel_id.as_bytes());
        nonce_input.extend_from_slice(&pubkey_bytes);
        nonce_input.extend_from_slice(&index_bytes);
        nonce_input.extend_from_slice(b"nonce");

        let nonce_hash = sha256::Hash::hash(&nonce_input);
        let nonce_hex = hex::encode(nonce_hash.as_byte_array());

        // Derive deterministic blinding factor: SHA256(channel_id || pubkey || index || "blinding")
        let mut blinding_input = Vec::new();
        blinding_input.extend_from_slice(channel_id.as_bytes());
        blinding_input.extend_from_slice(&pubkey_bytes);
        blinding_input.extend_from_slice(&index_bytes);
        blinding_input.extend_from_slice(b"blinding");

        let blinding_hash = sha256::Hash::hash(&blinding_input);
        let blinding_factor = SecretKey::from_slice(blinding_hash.as_byte_array())?;

        // Create deterministic P2PK output using these derived values
        create_deterministic_p2pk_output(pubkey, nonce_hex, blinding_factor)
    }
}
