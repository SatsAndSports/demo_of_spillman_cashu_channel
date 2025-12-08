//! Spilman Channel Parameters
//!
//! Contains the protocol parameters for a Spilman payment channel

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::ecdh::SharedSecret;
use cdk::nuts::{CurrencyUnit, SecretKey};
use cdk::util::hex;

use super::deterministic::{create_deterministic_commitment_output, DeterministicNonceAndBlinding, DeterministicSecretWithBlinding};
use super::keysets_and_amounts::KeysetInfo;

/// Parameters for a Spilman payment channel
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
    /// Keyset information (ID, keys, amounts, fees)
    pub keyset_info: KeysetInfo,
    /// Maximum amount for one output (amounts larger than this are filtered out)
    pub maximum_amount_for_one_output: u64,
    /// Shared secret derived from ECDH between Alice and Charlie
    pub shared_secret: [u8; 32],
}

impl SpilmanChannelParameters {
    /// Create new channel parameters with a pre-computed shared secret
    pub fn new(
        alice_pubkey: cdk::nuts::PublicKey,
        charlie_pubkey: cdk::nuts::PublicKey,
        mint: String,
        unit: CurrencyUnit,
        capacity: u64,
        locktime: u64,
        setup_timestamp: u64,
        sender_nonce: String,
        keyset_info: KeysetInfo,
        maximum_amount_for_one_output: u64,
        shared_secret: [u8; 32],
    ) -> anyhow::Result<Self> {
        // Validate input_fee_ppk is in valid range
        if keyset_info.input_fee_ppk > 999 {
            anyhow::bail!(
                "input_fee_ppk must be between 0 and 999 (inclusive), got {}",
                keyset_info.input_fee_ppk
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
            keyset_info,
            maximum_amount_for_one_output,
            shared_secret,
        })
    }

    /// Create new channel parameters by computing the shared secret from a secret key
    ///
    /// This constructor computes the ECDH shared secret automatically.
    /// It auto-detects whether the provided secret key belongs to Alice or Charlie by checking
    /// if its public key matches either party, then uses the counterparty's public key for ECDH.
    ///
    /// # Arguments
    /// * `my_secret` - Either Alice's or Charlie's secret key
    /// * All other arguments are the same as `new`
    ///
    /// # Errors
    /// Returns an error if the secret key's public key doesn't match either alice_pubkey or charlie_pubkey
    pub fn new_with_secret_key(
        alice_pubkey: cdk::nuts::PublicKey,
        charlie_pubkey: cdk::nuts::PublicKey,
        mint: String,
        unit: CurrencyUnit,
        capacity: u64,
        locktime: u64,
        setup_timestamp: u64,
        sender_nonce: String,
        keyset_info: KeysetInfo,
        maximum_amount_for_one_output: u64,
        my_secret: &SecretKey,
    ) -> anyhow::Result<Self> {
        let my_pubkey = my_secret.public_key();

        // Determine which party we are and get the counterparty's pubkey
        let their_pubkey = if my_pubkey == alice_pubkey {
            // We are Alice, use Charlie's pubkey
            &charlie_pubkey
        } else if my_pubkey == charlie_pubkey {
            // We are Charlie, use Alice's pubkey
            &alice_pubkey
        } else {
            anyhow::bail!(
                "Secret key's public key doesn't match either alice_pubkey or charlie_pubkey"
            );
        };

        // Compute shared secret via ECDH
        let shared_secret = SharedSecret::new(their_pubkey, my_secret);

        Self::new(
            alice_pubkey,
            charlie_pubkey,
            mint,
            unit,
            capacity,
            locktime,
            setup_timestamp,
            sender_nonce,
            keyset_info,
            maximum_amount_for_one_output,
            shared_secret.secret_bytes(),
        )
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

    /// Create a deterministic output with blinding using the channel ID and shared secret
    /// Uses shared_secret, channel_id, context, amount, and index in the derivation per NUT-XX spec
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

    /// Derive deterministic nonce and blinding factor using the shared secret and channel ID
    /// Uses shared_secret, channel_id, context, amount, and index in the derivation
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

        // Derive deterministic nonce: SHA256(shared_secret || channel_id || context || amount || "nonce" || index)
        let mut nonce_input = Vec::new();
        nonce_input.extend_from_slice(&self.shared_secret);
        nonce_input.extend_from_slice(channel_id.as_bytes());
        nonce_input.extend_from_slice(context.as_bytes());
        nonce_input.extend_from_slice(&amount_bytes);
        nonce_input.extend_from_slice(b"nonce");
        nonce_input.extend_from_slice(&index_bytes);

        let nonce_hash = sha256::Hash::hash(&nonce_input);
        let nonce_hex = hex::encode(nonce_hash.as_byte_array());

        // Derive deterministic blinding factor: SHA256(shared_secret || channel_id || context || amount || "blinding" || index)
        let mut blinding_input = Vec::new();
        blinding_input.extend_from_slice(&self.shared_secret);
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

    /// Get the total funding token amount using double inverse
    ///
    /// Applies the inverse fee calculation twice to the capacity:
    /// 1. capacity → post-stage-1 nominal (accounting for stage 2 fees)
    /// 2. post-stage-1 nominal → funding token nominal (accounting for stage 1 fees)
    ///
    /// Returns the nominal value needed for the funding token
    pub fn get_total_funding_token_amount(&self) -> anyhow::Result<u64> {
        let max_amt = self.maximum_amount_for_one_output;

        // First inverse: capacity → post-stage-1 nominal (accounting for stage 2 fees)
        let first_inverse = self.keyset_info.inverse_deterministic_value_after_fees(
            self.capacity,
            max_amt,
        )?;
        let post_stage1_nominal = first_inverse.nominal_value;

        // Second inverse: post-stage-1 nominal → funding token nominal (accounting for stage 1 fees)
        let second_inverse = self.keyset_info.inverse_deterministic_value_after_fees(
            post_stage1_nominal,
            max_amt,
        )?;
        let funding_token_nominal = second_inverse.nominal_value;

        Ok(funding_token_nominal)
    }

    /// Get the value available after stage 1 fees
    ///
    /// Takes the funding token nominal and applies the forward fee calculation
    /// to determine the actual amount available after the swap transaction (stage 1).
    ///
    /// This represents the total amount that will be distributed between Alice and Charlie
    /// in the commitment transaction outputs.
    ///
    /// Returns the actual value after stage 1 fees
    pub fn get_value_after_stage1(&self) -> anyhow::Result<u64> {
        // Get the funding token nominal
        let funding_token_nominal = self.get_total_funding_token_amount()?;

        // Apply forward to get actual value after stage 1 fees (spending the funding token)
        let value_after_stage1 = self.keyset_info.deterministic_value_after_fees(
            funding_token_nominal,
            self.maximum_amount_for_one_output,
        )?;

        Ok(value_after_stage1)
    }

    /// Compute the actual de facto balance from an intended balance
    ///
    /// Due to output denomination constraints and fee rounding, the actual balance
    /// that can be created may differ slightly from the intended balance.
    ///
    /// This method:
    /// 1. Applies inverse to find the nominal value needed for the intended balance
    /// 2. Applies deterministic_value to that nominal to get the actual de facto balance
    ///
    /// Returns the actual balance that will be created
    pub fn get_de_facto_balance(&self, intended_balance: u64) -> anyhow::Result<u64> {
        let max_amt = self.maximum_amount_for_one_output;

        // Apply inverse to get nominal value needed
        let inverse_result = self.keyset_info.inverse_deterministic_value_after_fees(
            intended_balance,
            max_amt,
        )?;
        let nominal_value = inverse_result.nominal_value;

        // Apply deterministic_value to get actual balance
        let actual_balance = self.keyset_info.deterministic_value_after_fees(
            nominal_value,
            max_amt,
        )?;

        Ok(actual_balance)
    }
}
