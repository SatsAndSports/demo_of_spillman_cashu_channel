//! Spilman Channel Parameters
//!
//! Contains the protocol parameters for a Spilman payment channel

use crate::nuts::{CurrencyUnit, SecretKey};
use crate::util::hex;
use crate::SECP256K1;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{Parity, Scalar};

use super::deterministic::DeterministicSecretWithBlinding;
use super::keysets_and_amounts::KeysetInfo;

/// Parameters for a Spilman payment channel
#[derive(Debug, Clone)]
pub struct ChannelParameters {
    /// Alice's public key (sender)
    pub alice_pubkey: crate::nuts::PublicKey,
    /// Charlie's public key (receiver)
    pub charlie_pubkey: crate::nuts::PublicKey,
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

/// Compute ECDH shared secret from a secret key and counterparty's public key
///
/// Returns the 32-byte x-coordinate of the shared point.
pub fn compute_shared_secret(
    my_secret: &crate::nuts::SecretKey,
    their_pubkey: &crate::nuts::PublicKey,
) -> [u8; 32] {
    SharedSecret::new(their_pubkey, my_secret).secret_bytes()
}

/// Derive a blinded secret key for P2BK signing
///
/// Computes k = p + r (mod n), handling BIP-340 parity.
/// If the pubkey has odd Y, we use k = -p + r instead.
///
/// This ensures that signing with k produces a valid signature for the blinded pubkey P' = P + r*G.
fn derive_blinded_secret_key(secret: &SecretKey, r: &Scalar) -> anyhow::Result<SecretKey> {
    // Get parity of the public key by accessing the underlying secp256k1 pubkey
    // Our wrapper's x_only_public_key() only returns XOnlyPublicKey, but the inner
    // secp256k1::PublicKey::x_only_public_key() returns (XOnlyPublicKey, Parity)
    let pubkey = secret.public_key();
    let inner_pubkey: &bitcoin::secp256k1::PublicKey = &*pubkey;
    let (_, parity) = inner_pubkey.x_only_public_key();

    // Get the underlying secp256k1 secret key
    // We need to clone because negate() consumes self
    let inner_secret: bitcoin::secp256k1::SecretKey = (**secret).clone();

    // If parity is odd, negate the secret key before adding the tweak
    // This is because BIP-340 signing will use the negated key for odd-Y pubkeys
    let effective_secret = if parity == Parity::Odd {
        inner_secret.negate()
    } else {
        inner_secret
    };

    // Add the blinding scalar: k = p + r (or k = -p + r if odd parity)
    let blinded = effective_secret
        .add_tweak(r)
        .map_err(|e| anyhow::anyhow!("Failed to add blinding tweak: {}", e))?;

    Ok(blinded.into())
}

/// Derive a blinded pubkey for P2BK verification
///
/// This is the pubkey-side counterpart to `derive_blinded_secret_key`.
/// It computes the pubkey that corresponds to the blinded secret key.
///
/// For BIP-340 compatibility:
/// - If pubkey has even Y: P' = P + r*G
/// - If pubkey has odd Y:  P' = -P + r*G
///
/// This ensures that `k*G = P'` where `k` is the blinded secret key.
fn derive_blinded_pubkey(
    pubkey: &crate::nuts::PublicKey,
    r: &Scalar,
) -> anyhow::Result<crate::nuts::PublicKey> {
    // Get parity of the public key
    let inner_pubkey: &bitcoin::secp256k1::PublicKey = &**pubkey;
    let (_, parity) = inner_pubkey.x_only_public_key();

    // If parity is odd, negate the pubkey before adding the tweak
    // This matches what derive_blinded_secret_key does with the secret key
    let effective_pubkey = if parity == Parity::Odd {
        inner_pubkey.negate(&SECP256K1)
    } else {
        *inner_pubkey
    };

    // Add the tweak: P' = P + r*G (or P' = -P + r*G if odd parity)
    let blinded = effective_pubkey
        .add_exp_tweak(&SECP256K1, r)
        .map_err(|e| anyhow::anyhow!("Failed to blind pubkey: {}", e))?;

    Ok(blinded.into())
}

impl ChannelParameters {
    /// Create new channel parameters with a pre-computed shared secret
    pub fn new(
        alice_pubkey: crate::nuts::PublicKey,
        charlie_pubkey: crate::nuts::PublicKey,
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
        alice_pubkey: crate::nuts::PublicKey,
        charlie_pubkey: crate::nuts::PublicKey,
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

    /// Create channel parameters from a JSON string and a secret key
    ///
    /// The JSON should contain: mint, unit, capacity, keyset_id, input_fee_ppk,
    /// maximum_amount, setup_timestamp, alice_pubkey, charlie_pubkey, locktime,
    /// sender_nonce (as produced by `get_channel_id_params_json`)
    ///
    /// Additional parameters needed:
    /// * `keyset_info` - Keyset information from the mint (keyset_id and input_fee_ppk must match JSON)
    /// * `my_secret` - Either Alice's or Charlie's secret key for ECDH
    pub fn from_json_with_secret_key(
        json_str: &str,
        keyset_info: KeysetInfo,
        my_secret: &SecretKey,
    ) -> anyhow::Result<Self> {
        // Parse JSON to get pubkeys for ECDH
        let json: serde_json::Value =
            serde_json::from_str(json_str).map_err(|e| anyhow::anyhow!("Invalid JSON: {}", e))?;

        let alice_pubkey_hex = json["alice_pubkey"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'alice_pubkey' field"))?;
        let alice_pubkey: crate::nuts::PublicKey = alice_pubkey_hex
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid alice_pubkey: {}", e))?;

        let charlie_pubkey_hex = json["charlie_pubkey"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'charlie_pubkey' field"))?;
        let charlie_pubkey: crate::nuts::PublicKey = charlie_pubkey_hex
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid charlie_pubkey: {}", e))?;

        // Determine counterparty and compute shared secret
        let my_pubkey = my_secret.public_key();
        let their_pubkey = if my_pubkey == alice_pubkey {
            &charlie_pubkey
        } else if my_pubkey == charlie_pubkey {
            &alice_pubkey
        } else {
            anyhow::bail!(
                "Secret key's public key doesn't match either alice_pubkey or charlie_pubkey"
            );
        };

        let shared_secret = compute_shared_secret(my_secret, their_pubkey);

        Self::from_json_with_shared_secret(json_str, keyset_info, shared_secret)
    }

    /// Create channel parameters from a JSON string with a pre-computed shared secret
    ///
    /// Same as `from_json` but takes the shared secret directly instead of computing it.
    pub fn from_json_with_shared_secret(
        json_str: &str,
        keyset_info: KeysetInfo,
        shared_secret: [u8; 32],
    ) -> anyhow::Result<Self> {
        let json: serde_json::Value =
            serde_json::from_str(json_str).map_err(|e| anyhow::anyhow!("Invalid JSON: {}", e))?;

        // Parse keyset_id and input_fee_ppk first to validate against keyset_info
        let keyset_id_str = json["keyset_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'keyset_id' field"))?;
        let json_keyset_id: crate::nuts::Id = keyset_id_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid keyset_id: {}", e))?;

        let json_input_fee_ppk = json["input_fee_ppk"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'input_fee_ppk' field"))?;

        // Validate keyset_info matches JSON
        if keyset_info.keyset_id != json_keyset_id {
            anyhow::bail!(
                "keyset_id mismatch: JSON has {}, KeysetInfo has {}",
                json_keyset_id,
                keyset_info.keyset_id
            );
        }
        if keyset_info.input_fee_ppk != json_input_fee_ppk {
            anyhow::bail!(
                "input_fee_ppk mismatch: JSON has {}, KeysetInfo has {}",
                json_input_fee_ppk,
                keyset_info.input_fee_ppk
            );
        }

        // Parse remaining fields
        let mint = json["mint"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'mint' field"))?
            .to_string();

        let unit_str = json["unit"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'unit' field"))?;
        let unit = match unit_str {
            "sat" => CurrencyUnit::Sat,
            "msat" => CurrencyUnit::Msat,
            "usd" => CurrencyUnit::Usd,
            "eur" => CurrencyUnit::Eur,
            _ => anyhow::bail!("Unknown unit: {}", unit_str),
        };

        let capacity = json["capacity"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'capacity' field"))?;

        let maximum_amount_for_one_output = json["maximum_amount"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'maximum_amount' field"))?;

        let setup_timestamp = json["setup_timestamp"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'setup_timestamp' field"))?;

        let alice_pubkey_hex = json["alice_pubkey"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'alice_pubkey' field"))?;
        let alice_pubkey: crate::nuts::PublicKey = alice_pubkey_hex
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid alice_pubkey: {}", e))?;

        let charlie_pubkey_hex = json["charlie_pubkey"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'charlie_pubkey' field"))?;
        let charlie_pubkey: crate::nuts::PublicKey = charlie_pubkey_hex
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid charlie_pubkey: {}", e))?;

        let locktime = json["locktime"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'locktime' field"))?;

        let sender_nonce = json["sender_nonce"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'sender_nonce' field"))?
            .to_string();

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
            shared_secret,
        )
    }

    /// Get channel capacity
    /// Returns the maximum final value (after both fee stages) that Charlie can receive
    pub fn get_capacity(&self) -> u64 {
        self.capacity
    }

    /// Get channel ID as raw bytes (32-byte SHA256 hash)
    /// The hash is computed over: mint|unit|capacity|keyset_id|input_fee_ppk|maximum_amount|setup_timestamp|sender_pubkey|receiver_pubkey|locktime|sender_nonce
    pub fn get_channel_id_bytes(&self) -> [u8; 32] {
        let params_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.mint,
            self.unit_name(),
            self.capacity,
            self.keyset_info.keyset_id.to_string(),
            self.keyset_info.input_fee_ppk,
            self.maximum_amount_for_one_output,
            self.setup_timestamp,
            self.alice_pubkey.to_hex(),
            self.charlie_pubkey.to_hex(),
            self.locktime,
            self.sender_nonce
        );
        sha256::Hash::hash(params_string.as_bytes()).to_byte_array()
    }

    /// Get channel ID as a hex string
    pub fn get_channel_id(&self) -> String {
        hex::encode(self.get_channel_id_bytes())
    }

    /// Get a JSON string representation of the data that contributes to the channel ID
    /// This excludes the shared secret and other derived data
    pub fn get_channel_id_params_json(&self) -> String {
        serde_json::json!({
            "mint": self.mint,
            "unit": self.unit_name(),
            "capacity": self.capacity,
            "keyset_id": self.keyset_info.keyset_id.to_string(),
            "input_fee_ppk": self.keyset_info.input_fee_ppk,
            "maximum_amount": self.maximum_amount_for_one_output,
            "setup_timestamp": self.setup_timestamp,
            "alice_pubkey": self.alice_pubkey.to_hex(),
            "charlie_pubkey": self.charlie_pubkey.to_hex(),
            "locktime": self.locktime,
            "sender_nonce": self.sender_nonce
        })
        .to_string()
    }

    /// Derive a blinding scalar for P2BK
    ///
    /// The `context` parameter specifies which blinded key to derive:
    /// - "sender_stage1" / "receiver_stage1" - for funding token 2-of-2
    /// - "sender_stage1_refund" - for funding token locktime refund
    /// - "sender_stage2" / "receiver_stage2" - for stage 1 outputs (spent in stage 2)
    ///
    /// Computes: SHA256("Cashu_Spilman_P2BK_v1" || channel_id || shared_secret || context || retry_counter)
    /// Retries with incrementing retry_counter until a valid scalar in [1, n-1] is found.
    fn derive_blinding_scalar(&self, context: &str) -> anyhow::Result<Scalar> {
        let channel_id_bytes = self.get_channel_id_bytes();

        for retry_counter in 0u8..=255 {
            let mut input = Vec::new();
            input.extend_from_slice(b"Cashu_Spilman_P2BK_v1");
            input.extend_from_slice(&channel_id_bytes);
            input.extend_from_slice(&self.shared_secret);
            input.extend_from_slice(context.as_bytes());
            input.push(retry_counter);

            let hash = sha256::Hash::hash(&input);
            let bytes: [u8; 32] = hash.to_byte_array();

            // Try to create a valid scalar (must be in range [1, n-1])
            if let Ok(scalar) = Scalar::from_be_bytes(bytes) {
                // Scalar::from_be_bytes rejects values >= n, and we also reject zero
                if scalar != Scalar::ZERO {
                    return Ok(scalar);
                }
            }
        }

        anyhow::bail!("Failed to derive valid blinding scalar after 256 attempts")
    }

    /// Get the blinded sender (Alice) pubkey for stage 1 P2BK
    ///
    /// Computes the blinded pubkey that corresponds to Alice's blinded secret key.
    /// This handles BIP-340 parity: if Alice's pubkey has odd Y, we negate it first.
    ///
    /// The formula matches `derive_blinded_secret_key`:
    /// - If even Y: P' = P + r*G (matches k = p + r)
    /// - If odd Y:  P' = -P + r*G (matches k = -p + r)
    pub fn get_sender_blinded_pubkey_for_stage1(&self) -> anyhow::Result<crate::nuts::PublicKey> {
        let r = self.derive_blinding_scalar("sender_stage1")?;
        derive_blinded_pubkey(&self.alice_pubkey, &r)
    }

    /// Get the blinded receiver (Charlie) pubkey for stage 1 P2BK
    ///
    /// Computes the blinded pubkey that corresponds to Charlie's blinded secret key.
    /// This handles BIP-340 parity: if Charlie's pubkey has odd Y, we negate it first.
    ///
    /// The formula matches `derive_blinded_secret_key`:
    /// - If even Y: P' = P + r*G (matches k = p + r)
    /// - If odd Y:  P' = -P + r*G (matches k = -p + r)
    pub fn get_receiver_blinded_pubkey_for_stage1(&self) -> anyhow::Result<crate::nuts::PublicKey> {
        let r = self.derive_blinding_scalar("receiver_stage1")?;
        derive_blinded_pubkey(&self.charlie_pubkey, &r)
    }

    /// Derive the blinded sender secret key for stage 1 signing
    ///
    /// For P2BK, Alice must sign with a blinded private key k such that k*G = P'.
    /// This handles BIP-340 parity: if Alice's pubkey has odd Y, we negate her
    /// private key before adding the blinding scalar.
    pub fn get_sender_blinded_secret_key_for_stage1(
        &self,
        alice_secret: &SecretKey,
    ) -> anyhow::Result<SecretKey> {
        let r = self.derive_blinding_scalar("sender_stage1")?;
        derive_blinded_secret_key(alice_secret, &r)
    }

    /// Get the blinded sender (Alice) pubkey for stage 1 locktime refund
    ///
    /// Uses a DIFFERENT blinding tweak than the 2-of-2 spending path, so the mint
    /// cannot correlate Alice's refund to the normal channel close.
    pub fn get_sender_blinded_pubkey_for_stage1_refund(
        &self,
    ) -> anyhow::Result<crate::nuts::PublicKey> {
        let r = self.derive_blinding_scalar("sender_stage1_refund")?;
        derive_blinded_pubkey(&self.alice_pubkey, &r)
    }

    /// Derive the blinded sender secret key for stage 1 locktime refund
    ///
    /// Uses a DIFFERENT blinding tweak than the 2-of-2 spending path.
    /// Alice uses this to sign when reclaiming funds after locktime.
    pub fn get_sender_blinded_secret_key_for_stage1_refund(
        &self,
        alice_secret: &SecretKey,
    ) -> anyhow::Result<SecretKey> {
        let r = self.derive_blinding_scalar("sender_stage1_refund")?;
        derive_blinded_secret_key(alice_secret, &r)
    }

    /// Derive the blinded receiver secret key for stage 1 signing
    ///
    /// For P2BK, Charlie must sign with a blinded private key k such that k*G = P'.
    /// This handles BIP-340 parity: if Charlie's pubkey has odd Y, we negate his
    /// private key before adding the blinding scalar.
    pub fn get_receiver_blinded_secret_key_for_stage1(
        &self,
        charlie_secret: &SecretKey,
    ) -> anyhow::Result<SecretKey> {
        let r = self.derive_blinding_scalar("receiver_stage1")?;
        derive_blinded_secret_key(charlie_secret, &r)
    }

    /// Get the blinded sender (Alice) pubkey for stage 2
    ///
    /// Used for stage 1 outputs - Alice's proofs are locked to this pubkey,
    /// and she'll need to sign with the corresponding secret key in stage 2.
    pub fn get_sender_blinded_pubkey_for_stage2(&self) -> anyhow::Result<crate::nuts::PublicKey> {
        let r = self.derive_blinding_scalar("sender_stage2")?;
        derive_blinded_pubkey(&self.alice_pubkey, &r)
    }

    /// Get the blinded receiver (Charlie) pubkey for stage 2
    ///
    /// Used for stage 1 outputs - Charlie's proofs are locked to this pubkey,
    /// and he'll need to sign with the corresponding secret key in stage 2.
    pub fn get_receiver_blinded_pubkey_for_stage2(&self) -> anyhow::Result<crate::nuts::PublicKey> {
        let r = self.derive_blinding_scalar("receiver_stage2")?;
        derive_blinded_pubkey(&self.charlie_pubkey, &r)
    }

    /// Derive the blinded sender secret key for stage 2 signing
    ///
    /// Alice uses this to sign when spending her stage 1 proofs in stage 2.
    pub fn get_sender_blinded_secret_key_for_stage2(
        &self,
        alice_secret: &SecretKey,
    ) -> anyhow::Result<SecretKey> {
        let r = self.derive_blinding_scalar("sender_stage2")?;
        derive_blinded_secret_key(alice_secret, &r)
    }

    /// Derive the blinded receiver secret key for stage 2 signing
    ///
    /// Charlie uses this to sign when spending his stage 1 proofs in stage 2.
    pub fn get_receiver_blinded_secret_key_for_stage2(
        &self,
        charlie_secret: &SecretKey,
    ) -> anyhow::Result<SecretKey> {
        let r = self.derive_blinding_scalar("receiver_stage2")?;
        derive_blinded_secret_key(charlie_secret, &r)
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

    /// Get the BLINDED pubkey for a stage 1 output context ("sender" or "receiver")
    ///
    /// Returns the blinded pubkey for use in stage 1 commitment outputs:
    /// - "receiver" → Charlie's blinded pubkey (stage2 context)
    /// - "sender" → Alice's blinded pubkey (stage2 context)
    /// - "funding" → error (funding uses 2-of-2 with stage1 blinded pubkeys)
    ///
    /// Uses "stage2" blinding context because these are the keys needed to sign in stage 2.
    pub fn get_blinded_pubkey_for_stage1_output(
        &self,
        context: &str,
    ) -> Result<crate::nuts::PublicKey, anyhow::Error> {
        match context {
            "receiver" => self.get_receiver_blinded_pubkey_for_stage2(),
            "sender" => self.get_sender_blinded_pubkey_for_stage2(),
            "funding" => anyhow::bail!(
                "Funding context requires 2-of-2 blinded pubkeys, use new_funding() instead"
            ),
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
        let nonce = hex::encode(nonce_hash.as_byte_array());

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

        // Handle funding context separately (requires 2-of-2 blinded pubkeys + locktime)
        if context == "funding" {
            DeterministicSecretWithBlinding::new_funding(self, nonce, blinding_factor, amount)
        } else {
            // For sender/receiver contexts, create simple P2PK outputs with BLINDED pubkeys
            // (Stage 1 outputs use stage2 blinded keys for spending in stage 2)
            let pubkey = self.get_blinded_pubkey_for_stage1_output(context)?;
            DeterministicSecretWithBlinding::new_p2pk(&pubkey, nonce, blinding_factor, amount)
        }
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
        let first_inverse = self
            .keyset_info
            .inverse_deterministic_value_after_fees(self.capacity, max_amt)?;
        let post_stage1_nominal = first_inverse.nominal_value;

        // Second inverse: post-stage-1 nominal → funding token nominal (accounting for stage 1 fees)
        let second_inverse = self
            .keyset_info
            .inverse_deterministic_value_after_fees(post_stage1_nominal, max_amt)?;
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
        let inverse_result = self
            .keyset_info
            .inverse_deterministic_value_after_fees(intended_balance, max_amt)?;
        let nominal_value = inverse_result.nominal_value;

        // Apply deterministic_value to get actual balance
        let actual_balance = self
            .keyset_info
            .deterministic_value_after_fees(nominal_value, max_amt)?;

        Ok(actual_balance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nuts::{Id, Keys, PublicKey};
    use crate::Amount;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    // Helper to create a simple KeysetInfo for testing
    fn mock_keyset_info(amounts: Vec<u64>, input_fee_ppk: u64) -> KeysetInfo {
        let mut keys_map = BTreeMap::new();
        let dummy_pubkey = PublicKey::from_str(
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
        )
        .unwrap();
        for &amt in &amounts {
            keys_map.insert(Amount::from(amt), dummy_pubkey);
        }

        let mut amounts_largest_first = amounts;
        amounts_largest_first.sort_by(|a, b| b.cmp(a));

        KeysetInfo {
            keyset_id: Id::from_str("00deadbeef123456").unwrap(),
            active_keys: Keys::new(keys_map),
            amounts_largest_first,
            input_fee_ppk,
        }
    }

    #[test]
    fn test_json_roundtrip_preserves_channel_id() {
        // Create keypairs for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        // Create a keyset_info for testing (powers of 2 up to 64, with 100 ppk fee)
        let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

        // Create channel parameters (as Alice)
        let original_params = ChannelParameters::new_with_secret_key(
            alice_pubkey,
            charlie_pubkey,
            "https://testmint.cash".to_string(),
            CurrencyUnit::Sat,
            1000,       // capacity
            1700000000, // locktime
            1699999000, // setup_timestamp
            "test-nonce-12345".to_string(),
            keyset_info.clone(),
            64, // maximum_amount_for_one_output
            &alice_secret,
        )
        .expect("Failed to create original params");

        // Get the channel ID and JSON
        let original_channel_id = original_params.get_channel_id();
        let json = original_params.get_channel_id_params_json();

        println!("Channel ID: {}", original_channel_id);
        println!("JSON: {}", json);

        // Recreate from JSON (as Charlie this time, to also test ECDH works both ways)
        let reconstructed_params =
            ChannelParameters::from_json_with_secret_key(&json, keyset_info, &charlie_secret)
                .expect("Failed to reconstruct params from JSON");

        let reconstructed_channel_id = reconstructed_params.get_channel_id();

        println!("Reconstructed Channel ID: {}", reconstructed_channel_id);

        // Verify shared secrets match (ECDH should produce same result from both sides)
        assert_eq!(
            original_params.shared_secret, reconstructed_params.shared_secret,
            "Shared secrets should match (ECDH is symmetric)"
        );

        // Assert channel IDs match
        assert_eq!(
            original_channel_id, reconstructed_channel_id,
            "Channel IDs should match after JSON roundtrip"
        );
    }

    #[test]
    fn test_p2bk_blinded_pubkey_consistency() {
        // Test that blinded pubkeys are computed consistently regardless of which
        // party creates the ChannelParameters (Alice or Charlie)

        // Create keypairs for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        // Create keyset_info
        let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

        // Alice creates params using her secret key
        let alice_params = ChannelParameters::new_with_secret_key(
            alice_pubkey,
            charlie_pubkey,
            "https://testmint.cash".to_string(),
            CurrencyUnit::Sat,
            1000,
            1700000000,
            1699999000,
            "test-nonce-12345".to_string(),
            keyset_info.clone(),
            64,
            &alice_secret,
        )
        .expect("Failed to create Alice's params");

        // Charlie recreates params from JSON using his secret key
        let json = alice_params.get_channel_id_params_json();
        let charlie_params =
            ChannelParameters::from_json_with_secret_key(&json, keyset_info, &charlie_secret)
                .expect("Failed to create Charlie's params");

        // Verify shared secrets match (ECDH symmetry)
        assert_eq!(
            alice_params.shared_secret, charlie_params.shared_secret,
            "Shared secrets should match"
        );

        // Verify blinded sender pubkey is the same
        let alice_blinded_sender = alice_params
            .get_sender_blinded_pubkey_for_stage1()
            .expect("Alice failed to get blinded sender pubkey");
        let charlie_blinded_sender = charlie_params
            .get_sender_blinded_pubkey_for_stage1()
            .expect("Charlie failed to get blinded sender pubkey");
        assert_eq!(
            alice_blinded_sender.to_hex(),
            charlie_blinded_sender.to_hex(),
            "Blinded sender pubkeys should match"
        );

        // Verify blinded receiver pubkey is the same
        let alice_blinded_receiver = alice_params
            .get_receiver_blinded_pubkey_for_stage1()
            .expect("Alice failed to get blinded receiver pubkey");
        let charlie_blinded_receiver = charlie_params
            .get_receiver_blinded_pubkey_for_stage1()
            .expect("Charlie failed to get blinded receiver pubkey");
        assert_eq!(
            alice_blinded_receiver.to_hex(),
            charlie_blinded_receiver.to_hex(),
            "Blinded receiver pubkeys should match"
        );

        println!(
            "Alice's blinded sender pubkey: {}",
            alice_blinded_sender.to_hex()
        );
        println!(
            "Charlie's blinded sender pubkey: {}",
            charlie_blinded_sender.to_hex()
        );
        println!(
            "Alice's blinded receiver pubkey: {}",
            alice_blinded_receiver.to_hex()
        );
        println!(
            "Charlie's blinded receiver pubkey: {}",
            charlie_blinded_receiver.to_hex()
        );
    }

    #[test]
    fn test_p2bk_signature_roundtrip() {
        use bitcoin::secp256k1::Message;
        use bitcoin::secp256k1::SECP256K1;

        // Create keypairs for Alice and Charlie
        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        // Create keyset_info
        let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

        // Alice creates params
        let alice_params = ChannelParameters::new_with_secret_key(
            alice_pubkey,
            charlie_pubkey,
            "https://testmint.cash".to_string(),
            CurrencyUnit::Sat,
            1000,
            1700000000,
            1699999000,
            "test-nonce-12345".to_string(),
            keyset_info.clone(),
            64,
            &alice_secret,
        )
        .expect("Failed to create Alice's params");

        // Alice gets her blinded secret key and signs a message
        let blinded_secret = alice_params
            .get_sender_blinded_secret_key_for_stage1(&alice_secret)
            .expect("Failed to get blinded secret");

        let test_msg = b"test message to sign";
        let msg_hash = bitcoin::hashes::sha256::Hash::hash(test_msg);
        let msg = Message::from_digest_slice(msg_hash.as_ref()).unwrap();

        // Get the secp256k1 keypair for signing
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(SECP256K1, &*blinded_secret);
        let signature = SECP256K1.sign_schnorr(&msg, &keypair);

        println!("Message: {}", hex::encode(msg_hash.to_byte_array()));
        println!("Signature: {}", hex::encode(signature.serialize()));

        // Charlie recreates params and verifies
        let json = alice_params.get_channel_id_params_json();
        let charlie_params =
            ChannelParameters::from_json_with_secret_key(&json, keyset_info, &charlie_secret)
                .expect("Failed to create Charlie's params");

        // Charlie gets Alice's blinded pubkey
        let blinded_pubkey = charlie_params
            .get_sender_blinded_pubkey_for_stage1()
            .expect("Failed to get blinded sender pubkey");

        println!("Blinded pubkey: {}", blinded_pubkey.to_hex());

        // Charlie verifies the signature
        let verify_result = blinded_pubkey.verify(test_msg, &signature);
        assert!(
            verify_result.is_ok(),
            "Signature verification failed: {:?}",
            verify_result
        );
        println!("Signature verified successfully!");
    }

    #[test]
    fn test_refund_blinded_pubkey_differs_from_sender() {
        // Test that the refund blinded pubkey uses a different tweak than the sender pubkey

        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

        let params = ChannelParameters::new_with_secret_key(
            alice_pubkey,
            charlie_pubkey,
            "https://testmint.cash".to_string(),
            CurrencyUnit::Sat,
            1000,
            1700000000,
            1699999000,
            "test-nonce-12345".to_string(),
            keyset_info,
            64,
            &alice_secret,
        )
        .expect("Failed to create params");

        // Get the three pubkeys
        let raw_alice = params.alice_pubkey;
        let blinded_sender = params
            .get_sender_blinded_pubkey_for_stage1()
            .expect("Failed to get sender blinded pubkey");
        let blinded_refund = params
            .get_sender_blinded_pubkey_for_stage1_refund()
            .expect("Failed to get refund blinded pubkey");

        println!("Raw Alice pubkey:      {}", raw_alice.to_hex());
        println!("Blinded sender pubkey: {}", blinded_sender.to_hex());
        println!("Blinded refund pubkey: {}", blinded_refund.to_hex());

        // All three should be different
        assert_ne!(
            raw_alice.to_hex(),
            blinded_sender.to_hex(),
            "Blinded sender should differ from raw Alice pubkey"
        );
        assert_ne!(
            raw_alice.to_hex(),
            blinded_refund.to_hex(),
            "Blinded refund should differ from raw Alice pubkey"
        );
        assert_ne!(
            blinded_sender.to_hex(),
            blinded_refund.to_hex(),
            "Blinded sender and refund should use different tweaks"
        );

        println!("✓ All three pubkeys are distinct");
    }

    #[test]
    fn test_refund_signature_roundtrip() {
        use bitcoin::secp256k1::Message;
        use bitcoin::secp256k1::SECP256K1;

        // Test that signing with refund blinded key verifies against refund blinded pubkey

        let alice_secret = SecretKey::generate();
        let alice_pubkey = alice_secret.public_key();
        let charlie_secret = SecretKey::generate();
        let charlie_pubkey = charlie_secret.public_key();

        let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

        // Alice creates params
        let alice_params = ChannelParameters::new_with_secret_key(
            alice_pubkey,
            charlie_pubkey,
            "https://testmint.cash".to_string(),
            CurrencyUnit::Sat,
            1000,
            1700000000,
            1699999000,
            "test-nonce-12345".to_string(),
            keyset_info.clone(),
            64,
            &alice_secret,
        )
        .expect("Failed to create Alice's params");

        // Alice gets her REFUND blinded secret key and signs a message
        let blinded_refund_secret = alice_params
            .get_sender_blinded_secret_key_for_stage1_refund(&alice_secret)
            .expect("Failed to get refund blinded secret");

        let test_msg = b"refund message to sign";
        let msg_hash = bitcoin::hashes::sha256::Hash::hash(test_msg);
        let msg = Message::from_digest_slice(msg_hash.as_ref()).unwrap();

        // Sign with refund blinded key
        let keypair =
            bitcoin::secp256k1::Keypair::from_secret_key(SECP256K1, &*blinded_refund_secret);
        let signature = SECP256K1.sign_schnorr(&msg, &keypair);

        println!("Message: {}", hex::encode(msg_hash.to_byte_array()));
        println!("Signature: {}", hex::encode(signature.serialize()));

        // Charlie recreates params and verifies using REFUND blinded pubkey
        let json = alice_params.get_channel_id_params_json();
        let charlie_params =
            ChannelParameters::from_json_with_secret_key(&json, keyset_info, &charlie_secret)
                .expect("Failed to create Charlie's params");

        let blinded_refund_pubkey = charlie_params
            .get_sender_blinded_pubkey_for_stage1_refund()
            .expect("Failed to get refund blinded pubkey");

        println!("Refund blinded pubkey: {}", blinded_refund_pubkey.to_hex());

        // Verify the signature
        let verify_result = blinded_refund_pubkey.verify(test_msg, &signature);
        assert!(
            verify_result.is_ok(),
            "Refund signature verification failed: {:?}",
            verify_result
        );
        println!("✓ Refund signature verified successfully!");

        // Also verify that the WRONG pubkey (sender, not refund) fails
        let blinded_sender_pubkey = charlie_params
            .get_sender_blinded_pubkey_for_stage1()
            .expect("Failed to get sender blinded pubkey");

        let wrong_verify_result = blinded_sender_pubkey.verify(test_msg, &signature);
        assert!(
            wrong_verify_result.is_err(),
            "Signature should NOT verify against sender pubkey (wrong tweak)"
        );
        println!("✓ Signature correctly fails against sender pubkey (different tweak)");
    }
}
