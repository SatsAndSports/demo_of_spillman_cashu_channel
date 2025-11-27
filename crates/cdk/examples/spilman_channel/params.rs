//! Spilman Channel Parameters
//!
//! Contains the protocol parameters for a Spilman payment channel

use bitcoin::hashes::{sha256, Hash};
use cdk::nuts::{CurrencyUnit, Id, SecretKey};
use cdk::util::hex;

use super::deterministic::{create_deterministic_commitment_output, DeterministicNonceAndBlinding, DeterministicSecretWithBlinding};

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
    /// Maximum amount for one output (amounts larger than this are filtered out)
    pub maximum_amount_for_one_output: u64,
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
        maximum_amount_for_one_output: u64,
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
            maximum_amount_for_one_output,
        })
    }

    /// Get channel capacity
    /// Returns the maximum final value (after both fee stages) that Charlie can receive
    pub fn get_capacity(&self) -> u64 {
        self.capacity
    }

    /// Get channel ID as a hash of the channel parameters
    /// The hash is computed over: mint|unit|setup_timestamp|sender_pubkey|receiver_pubkey|locktime|sender_nonce
    pub fn get_channel_id(&self) -> String {
        let params_string = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.mint,
            self.unit_name(),
            self.setup_timestamp,
            self.alice_pubkey.to_hex(),
            self.charlie_pubkey.to_hex(),
            self.locktime,
            self.sender_nonce
        );
        let hash = sha256::Hash::hash(params_string.as_bytes());
        hex::encode(hash.as_byte_array())
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

    /// Get the pubkey for a commitment context ("sender" or "receiver")
    /// Returns Charlie's pubkey for "receiver", Alice's pubkey for "sender"
    /// Returns an error for "funding" since funding requires both pubkeys
    pub fn get_pubkey_from_commitment_context(&self, context: &str) -> Result<cdk::nuts::PublicKey, anyhow::Error> {
        match context {
            "receiver" => Ok(self.charlie_pubkey),
            "sender" => Ok(self.alice_pubkey),
            "funding" => anyhow::bail!("Funding context requires both pubkeys, use create_deterministic_funding_output instead"),
            _ => anyhow::bail!("Unknown context: {}", context),
        }
    }

    /// Create a deterministic output with blinding using the channel ID
    /// Uses channel_id, context, amount, and index in the derivation per NUT-XX spec
    ///
    /// The context parameter specifies the role: "sender", "receiver", or "funding"
    /// - "sender"/"receiver" create simple P2PK outputs for commitments
    /// - "funding" creates P2PK outputs with 2-of-2 multisig + locktime conditions
    pub fn create_deterministic_output_with_blinding(
        &self,
        context: &str,
        amount: u64,
        index: usize,
    ) -> Result<DeterministicSecretWithBlinding, anyhow::Error> {
        // Derive the deterministic nonce and blinding factor
        let nonce_and_blinding = self.derive_nonce_and_blinding(context, amount, index)?;

        // Handle funding context separately (requires both pubkeys + locktime)
        if context == "funding" {
            super::deterministic::create_deterministic_funding_output(
                &self.alice_pubkey,
                &self.charlie_pubkey,
                self.locktime,
                nonce_and_blinding,
                amount,
            )
        } else {
            // For sender/receiver contexts, create simple P2PK outputs
            let pubkey = self.get_pubkey_from_commitment_context(context)?;
            create_deterministic_commitment_output(&pubkey, nonce_and_blinding, amount)
        }
    }

    /// Derive deterministic nonce and blinding factor using the channel ID
    /// Uses channel_id, context, amount, and index in the derivation
    ///
    /// The context parameter specifies the role: "sender", "receiver", or "funding"
    /// Since the context already identifies which pubkey is involved, the pubkey
    /// itself is not included in the derivation (but is still needed to construct the secret).
    pub fn derive_nonce_and_blinding(
        &self,
        context: &str,
        amount: u64,
        index: usize,
    ) -> Result<DeterministicNonceAndBlinding, anyhow::Error> {
        let channel_id = self.get_channel_id();
        let amount_bytes = amount.to_le_bytes();
        let index_bytes = index.to_le_bytes();

        // Derive deterministic nonce: SHA256(channel_id || context || amount || "nonce" || index)
        let mut nonce_input = Vec::new();
        nonce_input.extend_from_slice(channel_id.as_bytes());
        nonce_input.extend_from_slice(context.as_bytes());
        nonce_input.extend_from_slice(&amount_bytes);
        nonce_input.extend_from_slice(b"nonce");
        nonce_input.extend_from_slice(&index_bytes);

        let nonce_hash = sha256::Hash::hash(&nonce_input);
        let nonce_hex = hex::encode(nonce_hash.as_byte_array());

        // Derive deterministic blinding factor: SHA256(channel_id || context || amount || "blinding" || index)
        let mut blinding_input = Vec::new();
        blinding_input.extend_from_slice(channel_id.as_bytes());
        blinding_input.extend_from_slice(context.as_bytes());
        blinding_input.extend_from_slice(&amount_bytes);
        blinding_input.extend_from_slice(b"blinding");
        blinding_input.extend_from_slice(&index_bytes);

        let blinding_hash = sha256::Hash::hash(&blinding_input);
        let blinding_factor = SecretKey::from_slice(blinding_hash.as_byte_array())?;

        Ok(DeterministicNonceAndBlinding {
            nonce: nonce_hex,
            blinding_factor,
        })
    }
}
