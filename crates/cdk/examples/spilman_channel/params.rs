//! Spilman Channel Parameters
//!
//! Contains the protocol parameters for a Spilman payment channel

use bitcoin::hashes::{sha256, Hash};
use cdk::nuts::{CurrencyUnit, Id, SecretKey};
use cdk::nuts::nut11::{Conditions, SigFlag, SpendingConditions};
use cdk::util::hex;

use super::deterministic::{create_deterministic_p2pk_output, DeterministicP2pkOutputWithBlinding};

/// Parameters for a Spilman payment channel (protocol parameters only)
#[derive(Debug, Clone)]
pub struct SpilmanChannelParameters {
    /// Alice's public key (sender)
    pub alice_pubkey: cdk::nuts::PublicKey,
    /// Charlie's public key (receiver)
    pub charlie_pubkey: cdk::nuts::PublicKey,
    /// Mint URL (or "local" for in-process mint)
    pub mint: String,
    /// Currency unit for the channel
    pub unit: CurrencyUnit,
    /// Channel capacity: maximum final value (after both fee stages) that Charlie can receive
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
        mint: String,
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
            mint,
            unit,
            capacity,
            locktime,
            setup_timestamp,
            sender_nonce,
            active_keyset_id,
            input_fee_ppk,
        })
    }

    /// Get channel capacity
    /// Returns the maximum final value (after both fee stages) that Charlie can receive
    pub fn get_capacity(&self) -> u64 {
        self.capacity
    }

    /// Get channel ID
    /// Format: mint|unit|setup_timestamp|sender_pubkey|receiver_pubkey|locktime|sender_nonce
    pub fn get_id(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.mint,
            self.unit_name(),
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
    /// Uses channel_id, amount, and index in the derivation per NUT-XX spec
    pub fn create_deterministic_p2pk_output_with_blinding(
        &self,
        pubkey: &cdk::nuts::PublicKey,
        amount: u64,
        index: usize,
    ) -> Result<DeterministicP2pkOutputWithBlinding, anyhow::Error> {
        let channel_id = self.get_id();
        let pubkey_bytes = pubkey.to_bytes();
        let amount_bytes = amount.to_le_bytes();
        let index_bytes = index.to_le_bytes();

        // Derive deterministic nonce: SHA256(channel_id || pubkey || amount || "nonce" || index)
        let mut nonce_input = Vec::new();
        nonce_input.extend_from_slice(channel_id.as_bytes());
        nonce_input.extend_from_slice(&pubkey_bytes);
        nonce_input.extend_from_slice(&amount_bytes);
        nonce_input.extend_from_slice(b"nonce");
        nonce_input.extend_from_slice(&index_bytes);

        let nonce_hash = sha256::Hash::hash(&nonce_input);
        let nonce_hex = hex::encode(nonce_hash.as_byte_array());

        // Derive deterministic blinding factor: SHA256(channel_id || pubkey || amount || "blinding" || index)
        let mut blinding_input = Vec::new();
        blinding_input.extend_from_slice(channel_id.as_bytes());
        blinding_input.extend_from_slice(&pubkey_bytes);
        blinding_input.extend_from_slice(&amount_bytes);
        blinding_input.extend_from_slice(b"blinding");
        blinding_input.extend_from_slice(&index_bytes);

        let blinding_hash = sha256::Hash::hash(&blinding_input);
        let blinding_factor = SecretKey::from_slice(blinding_hash.as_byte_array())?;

        // Create deterministic P2PK output using these derived values
        create_deterministic_p2pk_output(pubkey, nonce_hex, blinding_factor)
    }

    /// Create spending conditions for the funding token
    /// This creates P2PK conditions with 2-of-2 multisig (Alice + Charlie) before locktime
    /// After locktime, Alice can refund with just her signature
    pub fn create_funding_token_spending_conditions(&self) -> Result<SpendingConditions, anyhow::Error> {
        // Create conditions for the P2PK spending
        let conditions = Conditions::new(
            Some(self.locktime),                    // Locktime for Alice's refund
            Some(vec![self.charlie_pubkey]),        // Charlie's key as additional pubkey for 2-of-2
            Some(vec![self.alice_pubkey]),          // Alice can refund after locktime
            Some(2),                                // Require 2 signatures (Alice + Charlie) before locktime
            Some(SigFlag::SigAll),                  // SigAll: signatures commit to outputs
            Some(1),                                // Only 1 signature needed for refund (Alice)
        )?;

        // Construct SpendingConditions with Alice as the main P2PK pubkey
        Ok(SpendingConditions::new_p2pk(self.alice_pubkey, Some(conditions)))
    }
}
