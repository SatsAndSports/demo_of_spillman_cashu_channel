//! Example: Spilman (Unidirectional) Payment Channel
//!
//! This example will demonstrate a Cashu implementation of Spilman channels,
//! allowing Alice and Bob to set up an offline unidirectional payment channel.

use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bip39::Mnemonic;
use bitcoin::secp256k1::schnorr::Signature;
use cdk::nuts::{MeltQuoteBolt12Request, MintQuoteBolt12Request, MintQuoteBolt12Response};
use cdk_common::{QuoteId, SpendingConditionVerification};
use cdk::mint::{MintBuilder, MintMeltLimits};
use cdk::util::hex;
use cdk::nuts::nut11::{Conditions, SigFlag};
use cdk::nuts::{
    CheckStateRequest, CheckStateResponse, CurrencyUnit, Id, Keys, KeySet, KeysetResponse,
    MeltQuoteBolt11Request, MeltQuoteBolt11Response, MeltRequest, MintInfo,
    MintQuoteBolt11Request, MintQuoteBolt11Response, MintRequest, MintResponse, PaymentMethod,
    RestoreRequest, RestoreResponse, SecretKey, SpendingConditions, State, SwapRequest, SwapResponse,
};
use cdk::types::{FeeReserve, ProofInfo, QuoteTTL};
use cdk::util::unix_time;
use cdk::wallet::{AuthWallet, HttpClient, MintConnector, ReceiveOptions, Wallet, WalletBuilder};
use cdk::{dhke::{blind_message, construct_proofs}, Error, Mint, StreamExt};
use cdk::amount::SplitTarget;
use cdk_common::mint_url::MintUrl;
use cdk_fake_wallet::FakeWallet;
use tokio::sync::RwLock;
use cdk::nuts::{BlindedMessage, BlindSignature, nut10::Secret as Nut10Secret, ProofsMethods};
use cdk::secret::Secret;
use cdk::Amount;
use cdk::nuts::nut10::Kind;
use cdk::nuts::Proof;

/// Format a boolean vector as binary string [101] instead of [true, false, true]
fn format_spend_vector(vector: &[bool]) -> String {
    let bits: String = vector.iter().map(|&b| if b { '1' } else { '0' }).collect();
    format!("[{}]", bits)
}

/// Deterministic P2PK output containing a secret and blinding factor
#[derive(Debug, Clone)]
struct DeterministicP2pkOutputWithBlinding {
    /// The secret (NUT-10 P2PK secret with specified nonce)
    secret: Secret,
    /// The blinding factor
    blinding_factor: SecretKey,
}

impl DeterministicP2pkOutputWithBlinding {
    /// Get the secret
    pub fn secret(&self) -> &Secret {
        &self.secret
    }

    /// Get the blinding factor
    pub fn blinding_factor(&self) -> &SecretKey {
        &self.blinding_factor
    }

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

/// Derive deterministic nonce and blinding factor from pubkey and index
/// Returns (nonce_hex_string, blinding_factor)
fn derive_deterministic_nonce_and_blinding(
    pubkey: &cdk::nuts::PublicKey,
    index: usize,
) -> Result<(String, SecretKey), anyhow::Error> {
    use bitcoin::hashes::{sha256, Hash};

    // Derive deterministic nonce: SHA256(pubkey || index || "nonce")
    let mut nonce_input = Vec::new();
    nonce_input.extend_from_slice(&pubkey.to_bytes());
    nonce_input.extend_from_slice(&index.to_le_bytes());
    nonce_input.extend_from_slice(b"nonce");

    let nonce_hash = sha256::Hash::hash(&nonce_input);
    let nonce_hex = hex::encode(nonce_hash.as_byte_array());

    // Derive deterministic blinding factor: SHA256(pubkey || index || "blinding")
    let mut blinding_input = Vec::new();
    blinding_input.extend_from_slice(&pubkey.to_bytes());
    blinding_input.extend_from_slice(&index.to_le_bytes());
    blinding_input.extend_from_slice(b"blinding");

    let blinding_hash = sha256::Hash::hash(&blinding_input);
    let blinding_factor = SecretKey::from_slice(blinding_hash.as_byte_array())?;

    Ok((nonce_hex, blinding_factor))
}

/// Create a deterministic P2PK output from explicit inputs
/// Takes a pubkey, nonce (as hex string), and blinding factor
/// Returns a DeterministicP2pkOutputWithBlinding with the constructed secret
fn create_deterministic_p2pk_output(
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

/// Create a deterministic P2PK blinded message
/// Takes pubkey, index, amount, and keyset_id and returns a BlindedMessage
/// Also returns the DeterministicP2pkOutputWithBlinding for later use (contains secret and blinding factor)
fn create_deterministic_p2pk_det_output(
    pubkey: &cdk::nuts::PublicKey,
    index: usize,
) -> Result<DeterministicP2pkOutputWithBlinding, anyhow::Error> {
    // Derive deterministic nonce and blinding factor
    let (nonce, blinding_factor) = derive_deterministic_nonce_and_blinding(pubkey, index)?;

    // Create deterministic P2PK output
    let det_output = create_deterministic_p2pk_output(pubkey, nonce, blinding_factor)?;

    Ok(det_output)
}

/// Extract signatures from the first proof's witness in a swap request
/// For SigAll, all signatures are stored in the witness of the FIRST proof only
fn get_signatures_from_swap_request(swap_request: &SwapRequest) -> Result<Vec<Signature>, anyhow::Error> {
    let first_proof = swap_request.inputs().first()
        .ok_or_else(|| anyhow::anyhow!("No inputs in swap request"))?;

    let signatures = if let Some(ref witness) = first_proof.witness {
        if let cdk::nuts::Witness::P2PKWitness(p2pk_witness) = witness {
            // Parse all signature strings into Signature objects
            p2pk_witness.signatures.iter()
                .filter_map(|sig_str| sig_str.parse::<Signature>().ok())
                .collect()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    Ok(signatures)
}

/// A signed balance update message that can be sent from Alice to Bob
/// Represents Alice's commitment to a new channel balance
#[derive(Debug, Clone)]
struct BalanceUpdateMessage {
    /// Channel ID to identify which channel this update is for
    channel_id: String,
    /// New balance for the receiver (Bob)
    amount: u64,
    /// Alice's signature over the swap request
    signature: Signature,
}

impl BalanceUpdateMessage {
    /// Create a balance update message from a signed swap request
    fn from_signed_swap_request(
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

    /// Verify the signature using the channel fixtures
    /// Bob reconstructs the swap request from the amount to verify the signature
    /// Throws an error if the signature is invalid
    fn verify_sender_signature(&self, channel_fixtures: &ChannelFixtures) -> Result<(), anyhow::Error> {
        // Reconstruct the unsigned swap request from the amount
        let swap_request = channel_fixtures.create_unsigned_swap_request(self.amount)?;

        // Extract the SIG_ALL message from the swap request
        let msg_to_sign = swap_request.sig_all_msg_to_sign();

        // Verify the signature using Alice's pubkey from channel params
        channel_fixtures.params.alice_pubkey
            .verify(msg_to_sign.as_bytes(), &self.signature)
            .map_err(|_| anyhow::anyhow!("Invalid signature: Alice did not authorize this balance update"))?;

        Ok(())
    }

    /*
    /// Reconstruct the swap request with the sender's signature
    /// This allows Bob to get a fully signed swap request that he can submit to the mint
    fn get_sender_signed_swap_request(
        &self,
        channel_fixtures: &ChannelFixtures,
    ) -> SwapRequest {
        // Reconstruct the unsigned swap request from the amount
        let (mut swap_request, _) = channel_fixtures.create_updated_swap_request(self.amount);

        // Add the signature to the first proof's witness
        let signature_str = self.signature.to_string();
        let witness = cdk::nuts::P2PKWitness {
            signatures: vec![signature_str],
        };

        // Set the witness on the first input proof
        if let Some(first_proof) = swap_request.inputs_mut().first_mut() {
            first_proof.witness = Some(cdk::nuts::Witness::P2PKWitness(witness));
        }

        swap_request
    }
    */
}

/// Fixed channel components known to both parties
/// These are established at channel creation and never change
#[derive(Debug, Clone)]
struct ChannelFixtures {
    /// Channel parameters
    params: SpilmanChannelParameters,
    /// Locked proofs (2-of-2 multisig with locktime refund)
    funding_proofs: Vec<Proof>,
    /// Total raw value of the locked proofs in the base unit
    total_locked_value: u64,
    /// Total input fee in sats for the locked proofs (rounded up from ppk)
    total_input_fee: u64,
}

impl ChannelFixtures {
    /// Create new channel fixtures
    /// Calculates total input fee from the locked proofs
    fn new(
        params: SpilmanChannelParameters,
        funding_proofs: Vec<Proof>,
        keyset_response: &KeysetResponse,
    ) -> Result<Self, anyhow::Error> {
        assert_eq!(
            funding_proofs.len(),
            params.denominations.len(),
            "Locked proofs must match denominations count"
        );

        // Calculate total raw value of the locked proofs
        let total_locked_value: u64 = funding_proofs.iter()
            .map(|proof| u64::from(proof.amount))
            .sum();

        // Calculate total input fee using the fee formula
        // sum_fees_ppk = sum of (input_fee_ppk for each proof's keyset)
        // total_fee_sats = (sum_fees_ppk + 999) / 1000  (integer division, rounds up)
        let mut sum_fees_ppk = 0u64;

        for proof in &funding_proofs {
            // Find the keyset info for this proof's keyset ID
            let keyset_info = keyset_response.keysets.iter()
                .find(|k| k.id == proof.keyset_id)
                .ok_or_else(|| anyhow::anyhow!("Keyset {} not found for proof", proof.keyset_id))?;

            sum_fees_ppk += keyset_info.input_fee_ppk;
        }

        // Round up: (sum_fees_ppk + 999) / 1000
        let total_input_fee = (sum_fees_ppk + 999) / 1000;

        Ok(Self {
            params,
            funding_proofs,
            total_locked_value,
            total_input_fee,
        })
    }

    /// Get the actual usable capacity (total value minus fees)
    fn get_capacity(&self) -> u64 {
        self.total_locked_value - self.total_input_fee
    }

    /// Create an unsigned swap request for a given balance to Bob
    /// Returns a SwapRequest with all funding_proofs as inputs,
    /// and deterministic outputs for Bob (his balance) and Alice (the remainder)
    fn create_unsigned_swap_request(&self, bob_balance: u64) -> Result<SwapRequest, anyhow::Error> {
        let capacity = self.get_capacity();

        if bob_balance > capacity {
            anyhow::bail!("Bob's balance {} exceeds channel capacity {}", bob_balance, capacity);
        }

        let alice_remainder = capacity - bob_balance;

        // Create deterministic blinded messages for Bob's balance
        let mut outputs = self.params.create_deterministic_blinded_messages_for_amount(
            &self.params.bob_pubkey,
            bob_balance,
        )?;

        // Create deterministic blinded messages for Alice's remainder
        let alice_outputs = self.params.create_deterministic_blinded_messages_for_amount(
            &self.params.alice_pubkey,
            alice_remainder,
        )?;

        // Bob's outputs first, then Alice's
        outputs.extend(alice_outputs);

        // Use all funding_proofs as inputs
        let swap_request = SwapRequest::new(self.funding_proofs.clone(), outputs);

        Ok(swap_request)
    }

    /// Unblind all outputs from a swap response
    /// Takes the blind signatures from the swap response and bob_balance
    /// Returns (bob_proofs, alice_proofs) as two separate vectors
    fn unblind_all_outputs(
        &self,
        blind_signatures: Vec<BlindSignature>,
        bob_balance: u64,
    ) -> Result<(Vec<Proof>, Vec<Proof>), anyhow::Error> {
        let capacity = self.get_capacity();

        if bob_balance > capacity {
            anyhow::bail!("Bob's balance {} exceeds channel capacity {}", bob_balance, capacity);
        }

        let alice_remainder = capacity - bob_balance;

        // Get blinding factors for Bob and Alice
        let bob_blinding_factors = self.params.create_deterministic_blinding_factors_for_amount(
            &self.params.bob_pubkey,
            bob_balance,
        )?;

        let alice_blinding_factors = self.params.create_deterministic_blinding_factors_for_amount(
            &self.params.alice_pubkey,
            alice_remainder,
        )?;

        // Get secrets for Bob and Alice
        let bob_secrets = self.params.create_deterministic_secrets_for_amount(
            &self.params.bob_pubkey,
            bob_balance,
        )?;

        let alice_secrets = self.params.create_deterministic_secrets_for_amount(
            &self.params.alice_pubkey,
            alice_remainder,
        )?;

        // Split the blind signatures into Bob's and Alice's portions
        let bob_count = bob_blinding_factors.len();
        let bob_signatures = blind_signatures.iter().take(bob_count).cloned().collect::<Vec<_>>();
        let alice_signatures = blind_signatures.iter().skip(bob_count).cloned().collect::<Vec<_>>();

        // Unblind Bob's outputs
        let bob_proofs = cdk::dhke::construct_proofs(
            bob_signatures,
            bob_blinding_factors,
            bob_secrets,
            &self.params.active_keys,
        )?;

        // Unblind Alice's outputs
        let alice_proofs = cdk::dhke::construct_proofs(
            alice_signatures,
            alice_blinding_factors,
            alice_secrets,
            &self.params.active_keys,
        )?;

        Ok((bob_proofs, alice_proofs))
    }

    /*
    /// Create an unsigned SwapRequest for an updated receiver balance
    /// Computes the spend vector and delegates to create_swap_request_from_vector
    /// Returns the swap request and total amount being spent
    fn create_updated_swap_request(&self, new_balance_for_receiver: u64) -> (SwapRequest, u64) {
        let spend_vector = self.params.balance_to_spend_vector(new_balance_for_receiver);
        self.create_swap_request_from_vector(&spend_vector)
    }
    */

    /*
    /// Create an unsigned SwapRequest based on a spend vector
    /// Returns the swap request and total amount being spent
    fn create_swap_request_from_vector(&self, spend_vector: &[bool]) -> (SwapRequest, u64) {
        // Select proofs to spend based on spend_vector
        let proofs_to_spend: Vec<Proof> = spend_vector
            .iter()
            .enumerate()
            .filter_map(|(i, &should_spend)| {
                if should_spend {
                    Some(self.funding_proofs[i].clone())
                } else {
                    None
                }
            })
            .collect();

        // Calculate total spending
        let total_spending: u64 = proofs_to_spend.iter().map(|p| u64::from(p.amount)).sum();

        // Regenerate Bob's outputs on-demand based on spend_vector
        let bob_outputs_to_use: Vec<BlindedMessage> = spend_vector
            .iter()
            .enumerate()
            .filter_map(|(i, &should_spend)| {
                if should_spend {
                    // Regenerate Bob's blinded message deterministically
                    let amount = self.params.denominations[i];
                    let det_output = create_deterministic_p2pk_det_output(
                        &self.params.bob_pubkey,
                        i,
                    ).ok()?;
                    let blinded_msg = det_output.to_blinded_message(
                        Amount::from(amount),
                        self.params.active_keyset_id,
                    ).ok()?;
                    Some(blinded_msg)
                } else {
                    None
                }
            })
            .collect();

        // Create and return the unsigned swap request and total
        let swap_request = SwapRequest::new(proofs_to_spend, bob_outputs_to_use);
        (swap_request, total_spending)
    }
    */
}

/// Parameters for a Spilman payment channel
#[derive(Debug, Clone)]
struct SpilmanChannelParameters {
    /// Alice's public key (sender)
    alice_pubkey: cdk::nuts::PublicKey,
    /// Bob's public key (receiver)
    bob_pubkey: cdk::nuts::PublicKey,
    /// Currency unit for the channel
    unit: CurrencyUnit,
    /// Log2 of capacity (e.g., 30 for 2^30)
    log2_capacity: u32,
    /// Total channel capacity (2^log2_capacity)
    capacity: u64,
    /// Locktime after which Alice can reclaim funds (unix timestamp)
    locktime: u64,
    /// Setup timestamp (unix timestamp when channel was created)
    setup_timestamp: u64,
    /// Sender nonce (random value created by Alice for channel identification)
    sender_nonce: String,
    /// Active keyset ID from the mint
    active_keyset_id: Id,
    /// Set of active keys from the mint (map from amount to pubkey)
    active_keys: Keys,
    /// Denomination sizes for channel outputs
    /// First element is special 1-unit output, rest are powers of 2
    /// Example: for capacity 8, this is [1, 1, 2, 4]
    denominations: Vec<u64>,
}

impl SpilmanChannelParameters {
    /// Create new channel parameters
    ///
    /// # Errors
    ///
    /// Returns an error if capacity != 2^log2_capacity
    fn new(
        alice_pubkey: cdk::nuts::PublicKey,
        bob_pubkey: cdk::nuts::PublicKey,
        unit: CurrencyUnit,
        log2_capacity: u32,
        capacity: u64,
        locktime: u64,
        setup_timestamp: u64,
        sender_nonce: String,
        active_keyset_id: Id,
        active_keys: Keys,
    ) -> anyhow::Result<Self> {
        // Validate that capacity == 2^log2_capacity
        if log2_capacity >= 64 {
            anyhow::bail!("log2_capacity must be less than 64, got {}", log2_capacity);
        }

        let expected_capacity = 1u64
            .checked_shl(log2_capacity)
            .ok_or_else(|| anyhow::anyhow!("log2_capacity {} is too large", log2_capacity))?;

        if capacity != expected_capacity {
            anyhow::bail!(
                "Capacity mismatch: expected 2^{} = {}, got {}",
                log2_capacity,
                expected_capacity,
                capacity
            );
        }

        // Build denominations vector
        // First element: special 1-unit output (for double-spend prevention)
        // Remaining elements: powers of 2 from 2^0 to 2^(log2_capacity - 1)
        let mut denominations = vec![1]; // Special output

        for i in 0..log2_capacity {
            denominations.push(1u64 << i); // 2^i
        }

        // Verify sum of denominations equals capacity
        let sum: u64 = denominations.iter().sum();
        if sum != capacity {
            anyhow::bail!(
                "Denominations sum mismatch: sum({:?}) = {}, expected capacity {}",
                denominations,
                sum,
                capacity
            );
        }

        Ok(Self {
            alice_pubkey,
            bob_pubkey,
            unit,
            log2_capacity,
            capacity,
            locktime,
            setup_timestamp,
            sender_nonce,
            active_keyset_id,
            active_keys,
            denominations,
        })
    }

    /// Get channel ID
    /// Format: setup_timestamp|sender_pubkey|receiver_pubkey|locktime|sender_nonce
    fn get_id(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.setup_timestamp,
            self.alice_pubkey.to_hex(),
            self.bob_pubkey.to_hex(),
            self.locktime,
            self.sender_nonce
        )
    }

    /// Get a string representation of the unit
    fn unit_name(&self) -> &str {
        match self.unit {
            CurrencyUnit::Sat => "sat",
            CurrencyUnit::Msat => "msat",
            CurrencyUnit::Usd => "usd",
            CurrencyUnit::Eur => "eur",
            _ => "units",
        }
    }

    /// Get the list of amounts from active_keys that sum to the target amount
    /// Uses a greedy algorithm: goes through amounts from largest to smallest
    /// Returns the list in ascending order
    /// Returns an error if the target amount cannot be represented
    fn amounts_for_target(&self, target: u64) -> anyhow::Result<Vec<u64>> {
        if target == 0 {
            return Ok(vec![]);
        }

        // Get all available amounts from the active_keys, sorted descending
        let mut available_amounts: Vec<u64> = self.active_keys.iter()
            .map(|(amt, _)| u64::from(*amt))
            .collect();
        available_amounts.sort_unstable_by(|a, b| b.cmp(a)); // Sort descending

        let mut remaining = target;
        let mut result = Vec::new();

        // Greedy algorithm: use largest amounts first
        for &amount in &available_amounts {
            while remaining >= amount {
                result.push(amount);
                remaining -= amount;
            }
        }

        if remaining != 0 {
            anyhow::bail!(
                "Cannot represent {} using available amounts {:?}",
                target,
                available_amounts
            );
        }

        // Sort result in ascending order before returning
        result.sort_unstable();
        Ok(result)
    }

    /// Create a deterministic P2PK output with blinding using the channel ID
    /// Uses channel_id in the derivation for better uniqueness
    fn create_deterministic_p2pk_output_with_blinding(
        &self,
        pubkey: &cdk::nuts::PublicKey,
        index: usize,
    ) -> Result<DeterministicP2pkOutputWithBlinding, anyhow::Error> {
        use bitcoin::hashes::{sha256, Hash};

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

    /// Create deterministic blinded messages and blinding factors for a given pubkey and target amount
    /// Returns a vector of (BlindedMessage, SecretKey) tuples that sum to the target amount
    /// Uses amounts_for_target to determine which amounts to use, then creates outputs for each
    fn create_deterministic_blinded_messages_and_blinding_factors_for_amount(
        &self,
        pubkey: &cdk::nuts::PublicKey,
        target_amount: u64,
    ) -> Result<Vec<(BlindedMessage, SecretKey)>, anyhow::Error> {
        // Get the list of amounts that sum to the target
        let amounts = self.amounts_for_target(target_amount)?;

        // For each amount with its index, create the deterministic blinded message and blinding factor
        let results: Result<Vec<(BlindedMessage, SecretKey)>, anyhow::Error> = amounts.iter()
            .enumerate()
            .map(|(index, &amount)| {
                // Create the deterministic output for this index
                let det_output = self.create_deterministic_p2pk_output_with_blinding(pubkey, index)?;

                // Convert to BlindedMessage using the amount and keyset_id
                let blinded_message = det_output.to_blinded_message(Amount::from(amount), self.active_keyset_id)?;

                // Return both the blinded message and the blinding factor
                Ok((blinded_message, det_output.blinding_factor))
            })
            .collect();

        results
    }

    /// Create deterministic blinded messages for a given pubkey and target amount
    /// Returns a vector of BlindedMessages that sum to the target amount
    /// Uses amounts_for_target to determine which amounts to use, then creates outputs for each
    fn create_deterministic_blinded_messages_for_amount(
        &self,
        pubkey: &cdk::nuts::PublicKey,
        target_amount: u64,
    ) -> Result<Vec<BlindedMessage>, anyhow::Error> {
        // Get the blinded messages and blinding factors
        let results = self.create_deterministic_blinded_messages_and_blinding_factors_for_amount(pubkey, target_amount)?;

        // Extract just the blinded messages
        let blinded_messages = results.into_iter()
            .map(|(blinded_message, _blinding_factor)| blinded_message)
            .collect();

        Ok(blinded_messages)
    }

    /// Create deterministic blinding factors for a given pubkey and target amount
    /// Returns a vector of SecretKeys (blinding factors) that correspond to the target amount
    /// Uses amounts_for_target to determine which amounts to use, then creates blinding factors for each
    fn create_deterministic_blinding_factors_for_amount(
        &self,
        pubkey: &cdk::nuts::PublicKey,
        target_amount: u64,
    ) -> Result<Vec<SecretKey>, anyhow::Error> {
        // Get the blinded messages and blinding factors
        let results = self.create_deterministic_blinded_messages_and_blinding_factors_for_amount(pubkey, target_amount)?;

        // Extract just the blinding factors
        let blinding_factors = results.into_iter()
            .map(|(_blinded_message, blinding_factor)| blinding_factor)
            .collect();

        Ok(blinding_factors)
    }

    /// Create deterministic secrets for a given pubkey and target amount
    /// Returns a vector of Secrets that correspond to the target amount
    /// Uses amounts_for_target to determine which amounts to use, then creates secrets for each
    fn create_deterministic_secrets_for_amount(
        &self,
        pubkey: &cdk::nuts::PublicKey,
        target_amount: u64,
    ) -> Result<Vec<Secret>, anyhow::Error> {
        // Get the list of amounts that sum to the target
        let amounts = self.amounts_for_target(target_amount)?;

        // For each amount with its index, create the deterministic secret
        let secrets: Result<Vec<Secret>, anyhow::Error> = amounts.iter()
            .enumerate()
            .map(|(index, _amount)| {
                // Create the deterministic output for this index
                let det_output = self.create_deterministic_p2pk_output_with_blinding(pubkey, index)?;
                Ok(det_output.secret)
            })
            .collect();

        secrets
    }

    /// Convert a balance to a boolean spend vector
    /// The first element is always true (we always include the first proof)
    /// The remaining elements are the binary representation of (balance - 1)
    fn balance_to_spend_vector(&self, balance: u64) -> Vec<bool> {
        assert!(balance > 0, "Balance must be greater than 0");
        assert!(balance <= self.capacity, "Balance exceeds channel capacity");

        let mut vector = Vec::with_capacity(1 + self.log2_capacity as usize);

        // First element is always true (the special first proof)
        vector.push(true);

        // Remaining balance after the first proof
        let remainder = balance - 1;

        // Binary representation of remainder
        for i in 0..self.log2_capacity {
            let bit_set = (remainder & (1 << i)) != 0;
            vector.push(bit_set);
        }

        vector
    }
}

/// Create a wallet connected to a local in-process mint
async fn create_wallet_local(mint: &Mint, unit: CurrencyUnit) -> anyhow::Result<Wallet> {
    let connector = DirectMintConnection::new(mint.clone());
    let store = Arc::new(cdk_sqlite::wallet::memory::empty().await?);
    let seed = Mnemonic::generate(12)?.to_seed_normalized("");

    let wallet = WalletBuilder::new()
        .mint_url("http://localhost:8080".parse().unwrap())
        .unit(unit)
        .localstore(store)
        .seed(seed)
        .client(connector)
        .build()?;

    Ok(wallet)
}

/// Create a wallet connected to an external mint via HTTP
async fn create_wallet_http(mint_url: MintUrl, unit: CurrencyUnit) -> anyhow::Result<Wallet> {
    let http_client = HttpClient::new(mint_url.clone(), None);
    let store = Arc::new(cdk_sqlite::wallet::memory::empty().await?);
    let seed = Mnemonic::generate(12)?.to_seed_normalized("");

    let wallet = WalletBuilder::new()
        .mint_url(mint_url)
        .unit(unit)
        .localstore(store)
        .seed(seed)
        .client(http_client)
        .build()?;

    Ok(wallet)
}

/// Create a local mint with FakeWallet backend for testing
async fn create_local_mint(unit: CurrencyUnit) -> anyhow::Result<Mint> {
    let mint_store = Arc::new(cdk_sqlite::mint::memory::empty().await?);

    let fee_reserve = FeeReserve {
        min_fee_reserve: 1.into(),
        percent_fee_reserve: 1.0,
    };

    let fake_ln = FakeWallet::new(
        fee_reserve,
        HashMap::default(),
        HashSet::default(),
        2,
        unit.clone(),
    );

    let mut mint_builder = MintBuilder::new(mint_store.clone());
    mint_builder
        .add_payment_processor(
            unit,
            PaymentMethod::Bolt11,
            MintMeltLimits::new(1, 2_000_000_000),  // 2B msat = 2M sat
            Arc::new(fake_ln),
        )
        .await?;

    let mnemonic = Mnemonic::generate(12)?;
    mint_builder = mint_builder
        .with_name("local test mint".to_string())
        .with_urls(vec!["http://localhost:8080".to_string()]);

    let mint = mint_builder
        .build_with_seed(mint_store, &mnemonic.to_seed_normalized(""))
        .await?;

    mint.set_quote_ttl(QuoteTTL::new(10000, 10000)).await?;
    mint.start().await?;

    Ok(mint)
}

/// Trait for interacting with a mint (either local or HTTP)
#[async_trait]
trait MintConnection {
    async fn get_mint_info(&self) -> Result<MintInfo, Error>;
    async fn get_keysets(&self) -> Result<KeysetResponse, Error>;
    async fn get_keys(&self) -> Result<Vec<KeySet>, Error>;
    async fn process_swap(&self, swap_request: SwapRequest) -> Result<SwapResponse, Error>;
    async fn post_restore(&self, restore_request: cdk::nuts::RestoreRequest) -> Result<cdk::nuts::RestoreResponse, Error>;
}

/// Local mint wrapper implementing MintConnection
struct LocalMintConnection {
    mint: Mint,
}

impl LocalMintConnection {
    fn new(mint: Mint) -> Self {
        Self { mint }
    }
}

#[async_trait]
impl MintConnection for LocalMintConnection {
    async fn get_mint_info(&self) -> Result<MintInfo, Error> {
        Ok(self.mint.mint_info().await?.clone().time(unix_time()))
    }

    async fn get_keysets(&self) -> Result<KeysetResponse, Error> {
        Ok(self.mint.keysets())
    }

    async fn get_keys(&self) -> Result<Vec<KeySet>, Error> {
        Ok(self.mint.pubkeys().keysets)
    }

    async fn process_swap(&self, swap_request: SwapRequest) -> Result<SwapResponse, Error> {
        self.mint.process_swap_request(swap_request).await
    }

    async fn post_restore(&self, restore_request: cdk::nuts::RestoreRequest) -> Result<cdk::nuts::RestoreResponse, Error> {
        self.mint.restore(restore_request).await
    }
}

/// HTTP mint wrapper implementing MintConnection
struct HttpMintConnection {
    http_client: HttpClient,
}

impl HttpMintConnection {
    fn new(mint_url: MintUrl) -> Self {
        let http_client = HttpClient::new(mint_url, None);
        Self { http_client }
    }
}

#[async_trait]
impl MintConnection for HttpMintConnection {
    async fn get_mint_info(&self) -> Result<MintInfo, Error> {
        self.http_client.get_mint_info().await
    }

    async fn get_keysets(&self) -> Result<KeysetResponse, Error> {
        self.http_client.get_mint_keysets().await
    }

    async fn get_keys(&self) -> Result<Vec<KeySet>, Error> {
        self.http_client.get_mint_keys().await
    }

    async fn process_swap(&self, swap_request: SwapRequest) -> Result<SwapResponse, Error> {
        self.http_client.post_swap(swap_request).await
    }

    async fn post_restore(&self, restore_request: cdk::nuts::RestoreRequest) -> Result<cdk::nuts::RestoreResponse, Error> {
        self.http_client.post_restore(restore_request).await
    }
}

/// Direct in-process connection to a mint (no HTTP)
#[derive(Clone)]
struct DirectMintConnection {
    mint: Mint,
    auth_wallet: Arc<RwLock<Option<AuthWallet>>>,
}

impl DirectMintConnection {
    fn new(mint: Mint) -> Self {
        Self {
            mint,
            auth_wallet: Arc::new(RwLock::new(None)),
        }
    }
}

impl Debug for DirectMintConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DirectMintConnection")
    }
}

#[async_trait]
impl MintConnector for DirectMintConnection {
    async fn resolve_dns_txt(&self, _domain: &str) -> Result<Vec<String>, Error> {
        panic!("Not implemented");
    }

    async fn get_mint_keys(&self) -> Result<Vec<KeySet>, Error> {
        Ok(self.mint.pubkeys().keysets)
    }

    async fn get_mint_keyset(&self, keyset_id: Id) -> Result<KeySet, Error> {
        self.mint.keyset(&keyset_id).ok_or(Error::UnknownKeySet)
    }

    async fn get_mint_keysets(&self) -> Result<KeysetResponse, Error> {
        Ok(self.mint.keysets())
    }

    async fn post_mint_quote(
        &self,
        request: MintQuoteBolt11Request,
    ) -> Result<MintQuoteBolt11Response<String>, Error> {
        self.mint
            .get_mint_quote(request.into())
            .await
            .map(Into::into)
    }

    async fn get_mint_quote_status(
        &self,
        quote_id: &str,
    ) -> Result<MintQuoteBolt11Response<String>, Error> {
        self.mint
            .check_mint_quote(&QuoteId::from_str(quote_id)?)
            .await
            .map(Into::into)
    }

    async fn post_mint(&self, request: MintRequest<String>) -> Result<MintResponse, Error> {
        let request_id: MintRequest<QuoteId> = request.try_into().unwrap();
        self.mint.process_mint_request(request_id).await
    }

    async fn post_melt_quote(
        &self,
        request: MeltQuoteBolt11Request,
    ) -> Result<MeltQuoteBolt11Response<String>, Error> {
        self.mint
            .get_melt_quote(request.into())
            .await
            .map(Into::into)
    }

    async fn get_melt_quote_status(
        &self,
        quote_id: &str,
    ) -> Result<MeltQuoteBolt11Response<String>, Error> {
        self.mint
            .check_melt_quote(&QuoteId::from_str(quote_id)?)
            .await
            .map(Into::into)
    }

    async fn post_melt(
        &self,
        request: MeltRequest<String>,
    ) -> Result<MeltQuoteBolt11Response<String>, Error> {
        let request_uuid = request.try_into().unwrap();
        self.mint.melt(&request_uuid).await.map(Into::into)
    }

    async fn post_swap(&self, swap_request: SwapRequest) -> Result<SwapResponse, Error> {
        self.mint.process_swap_request(swap_request).await
    }

    async fn get_mint_info(&self) -> Result<MintInfo, Error> {
        Ok(self.mint.mint_info().await?.clone().time(unix_time()))
    }

    async fn post_check_state(
        &self,
        request: CheckStateRequest,
    ) -> Result<CheckStateResponse, Error> {
        self.mint.check_state(&request).await
    }

    async fn post_restore(&self, request: RestoreRequest) -> Result<RestoreResponse, Error> {
        self.mint.restore(request).await
    }

    async fn get_auth_wallet(&self) -> Option<AuthWallet> {
        self.auth_wallet.read().await.clone()
    }

    async fn set_auth_wallet(&self, wallet: Option<AuthWallet>) {
        let mut auth_wallet = self.auth_wallet.write().await;
        *auth_wallet = wallet;
    }

    async fn post_mint_bolt12_quote(
        &self,
        request: MintQuoteBolt12Request,
    ) -> Result<MintQuoteBolt12Response<String>, Error> {
        let res: MintQuoteBolt12Response<QuoteId> =
            self.mint.get_mint_quote(request.into()).await?.try_into()?;
        Ok(res.into())
    }

    async fn get_mint_quote_bolt12_status(
        &self,
        quote_id: &str,
    ) -> Result<MintQuoteBolt12Response<String>, Error> {
        let quote: MintQuoteBolt12Response<QuoteId> = self
            .mint
            .check_mint_quote(&QuoteId::from_str(quote_id)?)
            .await?
            .try_into()?;
        Ok(quote.into())
    }

    async fn post_melt_bolt12_quote(
        &self,
        request: MeltQuoteBolt12Request,
    ) -> Result<MeltQuoteBolt11Response<String>, Error> {
        self.mint
            .get_melt_quote(request.into())
            .await
            .map(Into::into)
    }

    async fn get_melt_bolt12_quote_status(
        &self,
        quote_id: &str,
    ) -> Result<MeltQuoteBolt11Response<String>, Error> {
        self.mint
            .check_melt_quote(&QuoteId::from_str(quote_id)?)
            .await
            .map(Into::into)
    }

    async fn post_melt_bolt12(
        &self,
        _request: MeltRequest<String>,
    ) -> Result<MeltQuoteBolt11Response<String>, Error> {
        Err(Error::UnsupportedPaymentMethod)
    }
}

use clap::Parser;

/// Spilman Payment Channel Demo
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Mint URL (if not specified, uses in-process CDK mint)
    #[arg(long)]
    mint: Option<String>,

    /// Delay in seconds until Alice can refund (locktime)
    #[arg(long)]
    delay_until_refund: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // 1. GENERATE KEYS FOR ALICE AND BOB
    println!("🔑 Generating keypairs...");
    let alice_secret = SecretKey::generate();
    let alice_pubkey = alice_secret.public_key();
    println!("   Alice pubkey: {}", alice_pubkey);

    let bob_secret = SecretKey::generate();
    let bob_pubkey = bob_secret.public_key();
    println!("   Bob pubkey:   {}\n", bob_pubkey);

    // 2. SETUP INITIAL CHANNEL PARAMETERS
    println!("📋 Setting up Spilman channel parameters...");

    let setup_timestamp = unix_time();

    // Generate random sender nonce (created by Alice)
    let sender_nonce = Secret::generate().to_string();

    let channel_unit = CurrencyUnit::Sat;
    let log2_capacity = 20;
    let capacity = 1 << 20;
    let locktime = setup_timestamp + args.delay_until_refund;

    println!("   Capacity: {} {:?} (2^{})", capacity, channel_unit, log2_capacity);
    println!("   Locktime: {} ({} seconds from now)\n", locktime, locktime - unix_time());

    // 3. CREATE OR CONNECT TO MINT AND GET KEYSET
    let (mint_connection, alice_wallet, bob_wallet, active_keyset_id, keysets_response): (Box<dyn MintConnection>, Wallet, Wallet, Id, KeysetResponse) = if let Some(mint_url_str) = args.mint {
        println!("🏦 Connecting to external mint at {}...", mint_url_str);
        let mint_url: MintUrl = mint_url_str.parse()?;

        println!("👩 Setting up Alice's wallet...");
        let alice = create_wallet_http(mint_url.clone(), channel_unit.clone()).await?;

        println!("👨 Setting up Bob's wallet...");
        let bob = create_wallet_http(mint_url.clone(), channel_unit.clone()).await?;

        let http_mint = HttpMintConnection::new(mint_url);
        println!("✅ Connected to external mint\n");

        // Get active keyset from mint
        println!("📦 Getting active keyset from mint...");
        let keysets = http_mint.get_keysets().await?;
        let active_keyset_info = keysets.keysets.iter()
            .find(|k| k.active && k.unit == channel_unit)
            .expect("No active keyset");
        let keyset_id = active_keyset_info.id;
        println!("   Using keyset: {}\n", keyset_id);

        (Box::new(http_mint), alice, bob, keyset_id, keysets)
    } else {
        println!("🏦 Setting up local in-process mint...");
        let mint = create_local_mint(channel_unit.clone()).await?;
        println!("✅ Local mint running\n");

        println!("👩 Setting up Alice's wallet...");
        let alice = create_wallet_local(&mint, channel_unit.clone()).await?;

        println!("👨 Setting up Bob's wallet...");
        let bob = create_wallet_local(&mint, channel_unit.clone()).await?;

        let local_mint = LocalMintConnection::new(mint);

        // Get active keyset from mint
        println!("📦 Getting active keyset from mint...");
        let keysets = local_mint.get_keysets().await?;
        let active_keyset_info = keysets.keysets.iter()
            .find(|k| k.active && k.unit == channel_unit)
            .expect("No active keyset");
        let keyset_id = active_keyset_info.id;
        println!("   Using keyset: {}\n", keyset_id);

        (Box::new(local_mint), alice, bob, keyset_id, keysets)
    };

    // Get the mint's public keys for the active keyset
    let all_keysets = mint_connection.get_keys().await?;
    let set_of_active_keys = all_keysets.iter()
        .find(|k| k.id == active_keyset_id)
        .ok_or_else(|| anyhow::anyhow!("Active keyset not found"))?;

    // Print all amounts in the active keyset
    let mut amounts: Vec<u64> = set_of_active_keys.keys.iter().map(|(amt, _)| u64::from(*amt)).collect();
    amounts.sort_unstable();
    println!("   Active keyset amounts: {:?}\n", amounts);

    // 4. CREATE CHANNEL PARAMETERS WITH KEYSET_ID
    let channel_params = SpilmanChannelParameters::new(
        alice_pubkey,
        bob_pubkey,
        channel_unit,
        log2_capacity,
        capacity,
        locktime,
        setup_timestamp,
        sender_nonce,
        active_keyset_id,
        set_of_active_keys.keys.clone(),
    )?;

    println!("   Channel ID: {}\n", channel_params.get_id());

    // 5. CHECK MINT CAPABILITIES
    println!("🔍 Checking mint capabilities...");
    let mint_info = mint_connection.get_mint_info().await?;

    // Check for NUT-09 support (Restore)
    if mint_info.nuts.nut09.supported {
        println!("   ✓ Mint supports NUT-09 (Restore signatures)");
    } else {
        println!("   ✗ Mint does not support NUT-09 (Restore)");
    }

    // Check for NUT-11 support (P2PK)
    if mint_info.nuts.nut11.supported {
        println!("   ✓ Mint supports NUT-11 (P2PK spending conditions)");
    } else {
        anyhow::bail!("Mint does not support NUT-11 (P2PK). This is required for Spilman channels.");
    }

    // Check for NUT-12 support (DLEQ proofs)
    if mint_info.nuts.nut12.supported {
        println!("   ✓ Mint supports NUT-12 (DLEQ proofs)");
    } else {
        println!("   ✗ Mint does not support NUT-12 (DLEQ proofs)");
    }
    println!();

    // 6. ALICE MINTS TOKENS FOR THE CHANNEL CAPACITY
    println!("💰 Alice minting {} {} (full channel capacity)...", channel_params.capacity, channel_params.unit_name());
    let quote = alice_wallet.mint_quote(channel_params.capacity.into(), None).await?;
    let mut proof_stream = alice_wallet.proof_stream(quote, Default::default(), None);
    let _proofs = proof_stream.next().await.expect("proofs")?;
    println!("✅ Alice has {} {}\n", alice_wallet.total_balance().await?, channel_params.unit_name());

    // 8. PREPARE 2-OF-2 MULTISIG SPENDING CONDITIONS WITH LOCKTIME REFUND
    println!("🔐 Preparing 2-of-2 multisig spending conditions with locktime refund...");

    let conditions = Conditions::new(
        Some(channel_params.locktime),                // Locktime for Alice's refund
        Some(vec![channel_params.bob_pubkey]),        // Bob's key as additional pubkey
        Some(vec![channel_params.alice_pubkey]),      // Alice can refund after locktime
        Some(2),                                      // Require 2 signatures (Alice + Bob)
        Some(SigFlag::SigAll),                        // SigAll: signatures commit to outputs
        Some(1),                                      // Only 1 signature needed for refund (Alice)
    )?;

    let spending_conditions = SpendingConditions::new_p2pk(
        channel_params.alice_pubkey,  // Alice's key as primary
        Some(conditions),
    );

    println!("   Before locktime: Requires BOTH Alice and Bob signatures to spend");
    println!("   After locktime:  Alice can reclaim with only her signature\n");

    // 9. CREATE NEW BLINDED MESSAGES WITH 2-OF-2 CONDITIONS
    println!("🔒 Creating BlindedMessage with 2-of-2 multisig...");

    let mut locked_outputs = Vec::new();
    let mut locked_secrets_and_rs = Vec::new();

    for (i, &amount) in channel_params.denominations.iter().enumerate() {
        // Create a fresh NUT-10 secret with the same spending conditions
        // Each proof MUST have a unique secret to avoid DuplicateInputs error
        let nut10_secret: Nut10Secret = spending_conditions.clone().into();
        let secret: Secret = nut10_secret.try_into()?;

        // Blind the secret to get B_ = Y + rG
        let (blinded_point, blinding_factor) = blind_message(&secret.to_bytes(), None)?;

        // Create BlindedMessage
        let blinded_msg = BlindedMessage::new(
            Amount::from(amount),
            active_keyset_id,
            blinded_point,
        );

        locked_outputs.push(blinded_msg);
        locked_secrets_and_rs.push((secret, blinding_factor));

        println!("   Output {}: {} {} - locked to 2-of-2", i + 1, amount, channel_params.unit_name());
    }

    println!("✅ Created locked BlindedMessage\n");

    // 10. ALICE SWAPS HER TOKENS FOR 2-OF-2 LOCKED PROOF
    println!("🔄 Alice swapping her tokens for 2-of-2 locked proof...");

    let alice_proofs = alice_wallet
        .localstore
        .get_proofs(
            Some(alice_wallet.mint_url.clone()),
            Some(alice_wallet.unit.clone()),
            None,
            None,
        )
        .await?
        .into_iter()
        .map(|p| p.proof)
        .collect::<Vec<_>>();

    println!("   Alice inputs: {} {}", alice_proofs.iter().map(|p| u64::from(p.amount)).sum::<u64>(), channel_params.unit_name());
    println!("   Locked outputs: {:?}", channel_params.denominations);

    // Create and execute the swap
    let swap_request = SwapRequest::new(alice_proofs, locked_outputs);
    let swap_response = mint_connection.process_swap(swap_request).await?;

    println!("✅ Swap successful! Received {} blind signatures\n", swap_response.signatures.len());

    // 11. UNBLIND SIGNATURES TO CREATE 2-OF-2 LOCKED PROOF
    println!("🔓 Unblinding signature to create final 2-of-2 locked proof...");

    // Unblind the signatures to create usable proofs
    let funding_proofs = construct_proofs(
        swap_response.signatures,
        locked_secrets_and_rs.iter().map(|(_, r)| r.clone()).collect(),
        locked_secrets_and_rs.iter().map(|(s, _)| s.clone()).collect(),
        &set_of_active_keys.keys,
    )?;

    println!("✅ Created {} locked proofs - locked to 2-of-2 multisig\n", funding_proofs.len());

    // Create channel fixtures (fixed for the lifetime of the channel)
    let channel_fixtures = ChannelFixtures::new(
        channel_params.clone(),
        funding_proofs.clone(),
        &keysets_response,
    )?;

    println!("🎉 Setup complete!");
    println!("   Alice has {} proofs locked to Alice + Bob 2-of-2", funding_proofs.len());
    println!("   Total locked value: {} {}", channel_fixtures.total_locked_value, channel_params.unit_name());
    println!("   Total input fee: {} {}", channel_fixtures.total_input_fee, channel_params.unit_name());
    println!("   Usable capacity: {} {}", channel_fixtures.get_capacity(), channel_params.unit_name());
    println!("   Requires BOTH Alice and Bob to spend\n");

    println!("\n🎊 CHANNEL OPEN! 🎊");
    println!("   Both parties have verified all conditions.");
    println!("   The channel is now ready for off-chain payments.");
    println!("   Capacity: {} {}", channel_params.capacity, channel_params.unit_name());
    println!("   Alice can send up to {} {} to Bob via signed balance updates", channel_params.capacity, channel_params.unit_name());

    // DEMO: Test creating and executing a swap request for 42 sats to Bob
    println!("\n🧪 DEMO: Creating swap request for 42 {} to Bob...", channel_params.unit_name());

    let bob_balance = 42;
    let mut swap_request = channel_fixtures.create_unsigned_swap_request(bob_balance)?;
    println!("   ✓ Created unsigned swap request");
    println!("   Bob's balance: {} {}", bob_balance, channel_params.unit_name());
    println!("   Alice's remainder: {} {}", channel_fixtures.get_capacity() - bob_balance, channel_params.unit_name());

    // Alice signs first
    println!("\n   🔏 Alice signing...");
    swap_request.sign_sig_all(alice_secret.clone())?;
    println!("   ✓ Alice signed");

    // Create a balance update message (Alice -> Bob)
    println!("\n   📨 Creating balance update message...");
    let balance_update_msg = BalanceUpdateMessage::from_signed_swap_request(
        channel_params.get_id(),
        bob_balance,
        &swap_request,
    )?;
    println!("   ✓ Balance update message created");
    println!("   Channel ID: {}", balance_update_msg.channel_id);
    println!("   Bob's new balance: {} {}", balance_update_msg.amount, channel_params.unit_name());
    println!("   Signature: {}...{}",
        &balance_update_msg.signature.to_string()[..8],
        &balance_update_msg.signature.to_string()[balance_update_msg.signature.to_string().len()-8..]
    );

    // Verify the signature (Bob would do this when receiving the message)
    println!("\n   🔍 Bob verifying Alice's signature...");
    balance_update_msg.verify_sender_signature(&channel_fixtures)?;
    println!("   ✓ Signature is valid! Alice authorized this balance update.");

    // Bob signs second
    println!("\n   🔏 Bob signing...");
    swap_request.sign_sig_all(bob_secret.clone())?;
    println!("   ✓ Bob signed");

    // Execute the swap
    println!("\n   💱 Executing swap at mint...");
    let swap_response = mint_connection.process_swap(swap_request).await?;
    println!("   ✓ Swap successful!");
    println!("   Received {} blind signatures", swap_response.signatures.len());

    // Unblind the outputs
    println!("\n   🔓 Unblinding outputs...");
    let (bob_proofs, alice_proofs) = channel_fixtures.unblind_all_outputs(swap_response.signatures, bob_balance)?;
    println!("   ✓ Unblinded successfully!");
    println!("   Bob received {} proofs totaling {} {}",
        bob_proofs.len(),
        bob_proofs.iter().map(|p| u64::from(p.amount)).sum::<u64>(),
        channel_params.unit_name()
    );
    println!("   Alice received {} proofs totaling {} {}",
        alice_proofs.len(),
        alice_proofs.iter().map(|p| u64::from(p.amount)).sum::<u64>(),
        channel_params.unit_name()
    );

    // Add the proofs to each wallet (they are still P2PK locked, so wallets will swap them)
    println!("\n   💼 Adding proofs to wallets...");

    // Bob receives his proofs (wallet will sign and swap to remove P2PK)
    let bob_receive_opts = ReceiveOptions {
        amount_split_target: SplitTarget::default(),
        p2pk_signing_keys: vec![bob_secret.clone()],
        preimages: vec![],
        metadata: HashMap::new(),
    };
    let bob_received_amount = bob_wallet.receive_proofs(bob_proofs, bob_receive_opts, None).await?;
    println!("   ✓ Bob received {} {} into wallet", bob_received_amount, channel_params.unit_name());
    println!("   Bob's total balance: {} {}", bob_wallet.total_balance().await?, channel_params.unit_name());

    // Alice receives her proofs (wallet will sign and swap to remove P2PK)
    let alice_receive_opts = ReceiveOptions {
        amount_split_target: SplitTarget::default(),
        p2pk_signing_keys: vec![alice_secret.clone()],
        preimages: vec![],
        metadata: HashMap::new(),
    };
    let alice_received_amount = alice_wallet.receive_proofs(alice_proofs, alice_receive_opts, None).await?;
    println!("   ✓ Alice received {} {} into wallet", alice_received_amount, channel_params.unit_name());
    println!("   Alice's total balance: {} {}", alice_wallet.total_balance().await?, channel_params.unit_name());

    Ok(())
}
