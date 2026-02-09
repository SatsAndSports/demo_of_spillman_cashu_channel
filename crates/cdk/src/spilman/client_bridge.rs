//! Client-side Spilman channel bridge
//!
//! This module provides a high-level client-side API for managing Spilman payment channels,
//! mirroring the server-side `SpilmanBridge` / `SpilmanHost` pattern.
//!
//! The `SpilmanClientHost` trait provides storage and mint communication callbacks,
//! while `SpilmanClientBridge` orchestrates channel creation, payment signing, and
//! header construction.
//!
//! # Example (pseudocode)
//! ```ignore
//! let host = MyClientHost::new();
//! let bridge = SpilmanClientBridge::new(host, None)?;
//!
//! // Open a channel from an existing Cashu token
//! let result = bridge.open_channel_from_token(token, charlie_pubkey, locktime, keyset_info, 64)?;
//!
//! // Make payments
//! let header = bridge.build_payment_header(&result.channel_id, 10, true)?;  // first request
//! let header = bridge.build_payment_header(&result.channel_id, 20, false)?; // subsequent
//! ```

use crate::nuts::SecretKey;
use serde::{Deserialize, Serialize};

use super::bindings::{
    attach_signature_to_balance_update, complete_funding_swap, compute_channel_from_token,
    create_funding_swap, create_unsigned_balance_update,
};

// ============================================================================
// SpilmanClientHost trait
// ============================================================================

/// Trait for client-side host callbacks.
///
/// Provides mint communication and channel storage. This is the client-side
/// counterpart of the server-side `SpilmanHost` trait.
///
/// Implementations are responsible for:
/// - Making HTTP calls to the mint's `/v1/swap` endpoint
/// - Persisting channel state (in-memory, database, etc.)
pub trait SpilmanClientHost {
    /// Execute a swap with the mint.
    ///
    /// Posts `swap_request_json` to `{mint_url}/v1/swap` and returns the
    /// response body as a JSON string.
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String>;

    /// Save channel state. Called after successful channel creation.
    ///
    /// The `channel_json` is an opaque JSON blob managed by the bridge.
    fn save_channel(&self, channel_id: &str, channel_json: &str);

    /// Retrieve channel state by channel ID.
    ///
    /// Returns `None` if the channel is not found.
    fn get_channel(&self, channel_id: &str) -> Option<String>;

    /// List all stored channel IDs.
    fn list_channel_ids(&self) -> Vec<String>;

    /// Delete a channel from storage.
    fn delete_channel(&self, channel_id: &str);

    /// Sign a message with a tweaked key (BIP-340 Schnorr).
    ///
    /// The bridge computes the tweak (P2BK blinding scalar) and message hash,
    /// then asks the host to produce a BIP-340 Schnorr signature using
    /// the key `(secret + tweak)` where `secret` is the key corresponding
    /// to `signer_pubkey_hex`.
    ///
    /// The host must handle BIP-340 parity: if the public key has odd Y,
    /// negate the secret key before adding the tweak.
    ///
    /// For hosts that hold raw secret keys, the convenience function
    /// `crate::spilman::bindings::sign_with_tweaked_key_util()` provides
    /// a standard implementation.
    ///
    /// # Arguments
    /// * `signer_pubkey_hex` - Identifies which key to use (Alice's pubkey for this channel)
    /// * `message_hex` - SHA-256 hash of the SIG_ALL message (32 bytes, hex-encoded)
    /// * `tweak_scalar_hex` - The P2BK blinding scalar to add to the secret key (32 bytes, hex)
    ///
    /// # Returns
    /// The BIP-340 Schnorr signature as a 64-byte hex string.
    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String>;
}

// ============================================================================
// Result/info types
// ============================================================================

/// Result of opening a new channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenChannelResult {
    pub channel_id: String,
    pub capacity: u64,
    pub funding_token_amount: u64,
    pub mint_url: String,
}

/// Information about a stored channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientChannelInfo {
    pub channel_id: String,
    pub capacity: u64,
    pub funding_token_amount: u64,
    pub mint_url: String,
    pub params_json: String,
}

/// Internal channel state stored via the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredChannel {
    channel_id: String,
    params_json: String,
    keyset_info_json: String,
    funding_proofs_json: String,
    capacity: u64,
    funding_token_amount: u64,
    mint_url: String,
}

// ============================================================================
// SpilmanClientBridge
// ============================================================================

/// Client-side bridge for managing Spilman payment channels.
///
/// This is the client-side counterpart of `SpilmanBridge`. It orchestrates
/// channel creation from tokens, payment signing, and HTTP header construction.
///
/// The bridge itself is stateless — all channel state is stored via the host.
/// One bridge instance uses a single Alice keypair for all channels.
pub struct SpilmanClientBridge<H: SpilmanClientHost> {
    host: H,
    alice_secret_hex: String,
    alice_pubkey_hex: String,
}

impl<H: SpilmanClientHost> SpilmanClientBridge<H> {
    /// Create a new client bridge.
    ///
    /// If `alice_secret_hex` is `None`, a new keypair is generated.
    pub fn new(host: H, alice_secret_hex: Option<&str>) -> Result<Self, String> {
        let (secret_hex, pubkey_hex) = match alice_secret_hex {
            Some(hex) => {
                let sk = SecretKey::from_hex(hex)
                    .map_err(|e| format!("Invalid alice secret key: {}", e))?;
                (hex.to_string(), sk.public_key().to_hex())
            }
            None => {
                let sk = SecretKey::generate();
                (sk.to_secret_hex(), sk.public_key().to_hex())
            }
        };

        Ok(Self {
            host,
            alice_secret_hex: secret_hex,
            alice_pubkey_hex: pubkey_hex,
        })
    }

    /// Get Alice's public key (hex-encoded, compressed).
    ///
    /// Give this to the server when setting up a channel.
    pub fn alice_pubkey_hex(&self) -> &str {
        &self.alice_pubkey_hex
    }

    /// Get Alice's secret key (hex-encoded).
    ///
    /// Needed for persistence/restoration of the bridge.
    pub fn alice_secret_hex(&self) -> &str {
        &self.alice_secret_hex
    }

    /// Get a reference to the host.
    pub fn host(&self) -> &H {
        &self.host
    }

    /// Open a new channel from a Cashu token.
    ///
    /// This performs the full funding flow:
    /// 1. Parse the token and compute channel parameters
    /// 2. Create a funding swap request (deterministic 2-of-2 locked outputs)
    /// 3. Submit the swap to the mint via `host.call_mint_swap()`
    /// 4. Unblind signatures and verify DLEQ proofs
    /// 5. Save the channel via `host.save_channel()`
    ///
    /// # Arguments
    /// * `token_string` - Cashu token (cashuA... or cashuB...)
    /// * `charlie_pubkey_hex` - Receiver's public key (from server's `/channel/params`)
    /// * `locktime` - Unix timestamp for refund locktime
    /// * `keyset_info_json` - Keyset info JSON (from mint's `/v1/keys/{id}`)
    /// * `max_amount` - Maximum amount per output (from server policy, 0 = no limit)
    pub fn open_channel_from_token(
        &self,
        token_string: &str,
        charlie_pubkey_hex: &str,
        locktime: u64,
        keyset_info_json: &str,
        max_amount: u64,
    ) -> Result<OpenChannelResult, String> {
        // Step 1: Parse token and compute channel parameters
        let compute_result = compute_channel_from_token(
            token_string,
            charlie_pubkey_hex,
            &self.alice_secret_hex,
            locktime,
            keyset_info_json,
            max_amount,
        )?;

        let compute_json: serde_json::Value = serde_json::from_str(&compute_result)
            .map_err(|e| format!("Failed to parse compute result: {}", e))?;

        let capacity = compute_json["capacity"]
            .as_u64()
            .ok_or("Missing 'capacity' in compute result")?;
        let funding_token_amount = compute_json["funding_token_amount"]
            .as_u64()
            .ok_or("Missing 'funding_token_amount' in compute result")?;
        let mint_url = compute_json["mint_url"]
            .as_str()
            .ok_or("Missing 'mint_url' in compute result")?
            .to_string();
        let params_json = compute_json["params_json"]
            .as_str()
            .ok_or("Missing 'params_json' in compute result")?;
        let proofs_json = compute_json["proofs_json"]
            .as_str()
            .ok_or("Missing 'proofs_json' in compute result")?;

        // Step 2: Create funding swap request
        let swap_result = create_funding_swap(
            params_json,
            &self.alice_secret_hex,
            keyset_info_json,
            proofs_json,
        )?;

        let swap_json: serde_json::Value = serde_json::from_str(&swap_result)
            .map_err(|e| format!("Failed to parse swap result: {}", e))?;

        let swap_request_json = swap_json["swap_request_json"]
            .as_str()
            .ok_or("Missing 'swap_request_json' in swap result")?;
        let funding_secrets_json = swap_json["funding_secrets_json"]
            .as_str()
            .ok_or("Missing 'funding_secrets_json' in swap result")?;

        // Step 3: Submit swap to mint
        let swap_response_json = self.host.call_mint_swap(&mint_url, swap_request_json)?;

        // Step 4: Unblind signatures and verify DLEQ
        let complete_result =
            complete_funding_swap(&swap_response_json, funding_secrets_json, keyset_info_json)?;

        let complete_json: serde_json::Value = serde_json::from_str(&complete_result)
            .map_err(|e| format!("Failed to parse complete result: {}", e))?;

        let funding_proofs_json = complete_json["funding_proofs_json"]
            .as_str()
            .ok_or("Missing 'funding_proofs_json' in complete result")?;

        // Compute channel ID (we need the shared secret and keyset info)
        let channel_secret_hex = super::bindings::compute_channel_secret_from_hex(
            &self.alice_secret_hex,
            charlie_pubkey_hex,
        )?;
        let channel_id = super::bindings::channel_parameters_get_channel_id(
            params_json,
            &channel_secret_hex,
            keyset_info_json,
        )?;

        // Step 5: Save channel state
        let stored = StoredChannel {
            channel_id: channel_id.clone(),
            params_json: params_json.to_string(),
            keyset_info_json: keyset_info_json.to_string(),
            funding_proofs_json: funding_proofs_json.to_string(),
            capacity,
            funding_token_amount,
            mint_url: mint_url.clone(),
        };

        let channel_json = serde_json::to_string(&stored)
            .map_err(|e| format!("Failed to serialize channel state: {}", e))?;

        self.host.save_channel(&channel_id, &channel_json);

        Ok(OpenChannelResult {
            channel_id,
            capacity,
            funding_token_amount,
            mint_url,
        })
    }

    /// Create a signed balance update for a channel.
    ///
    /// Returns JSON with `{channel_id, amount, signature}`.
    ///
    /// The `balance` is the cumulative amount the receiver (Charlie) can claim.
    /// It must increase monotonically across calls.
    ///
    /// Signing is delegated to the host via `sign_with_tweaked_key()`.
    pub fn sign_balance_update(&self, channel_id: &str, balance: u64) -> Result<String, String> {
        let stored = self.load_channel(channel_id)?;

        // Step 1: Create unsigned balance update (computes message hash + tweak)
        let unsigned_json = create_unsigned_balance_update(
            &stored.params_json,
            &stored.keyset_info_json,
            &self.alice_secret_hex,
            &stored.funding_proofs_json,
            balance,
        )?;

        let unsigned: serde_json::Value = serde_json::from_str(&unsigned_json)
            .map_err(|e| format!("Failed to parse unsigned update: {}", e))?;

        let unsigned_swap_request_json = unsigned["unsigned_swap_request_json"]
            .as_str()
            .ok_or("Missing 'unsigned_swap_request_json'")?;
        let message_hex = unsigned["message_hex"]
            .as_str()
            .ok_or("Missing 'message_hex'")?;
        let tweak_scalar_hex = unsigned["tweak_scalar_hex"]
            .as_str()
            .ok_or("Missing 'tweak_scalar_hex'")?;
        let channel_id_from_update = unsigned["channel_id"]
            .as_str()
            .ok_or("Missing 'channel_id'")?;
        let amount = unsigned["amount"].as_u64().ok_or("Missing 'amount'")?;

        // Step 2: Delegate signing to the host
        let signature_hex = self.host.sign_with_tweaked_key(
            &self.alice_pubkey_hex,
            message_hex,
            tweak_scalar_hex,
        )?;

        // Step 3: Attach signature and build the BalanceUpdateMessage
        attach_signature_to_balance_update(
            unsigned_swap_request_json,
            &signature_hex,
            channel_id_from_update,
            amount,
        )
    }

    /// Build a complete `X-Cashu-Channel` payment header value.
    ///
    /// Returns a base64-encoded JSON string ready to use as the header value.
    ///
    /// If `include_funding` is true, the header includes `params` and `funding_proofs`
    /// (needed for the first request, or when the server doesn't know this channel yet).
    /// Subsequent requests can set `include_funding` to false for smaller headers.
    ///
    /// Signing is delegated to the host via `sign_with_tweaked_key()`.
    pub fn build_payment_header(
        &self,
        channel_id: &str,
        balance: u64,
        include_funding: bool,
    ) -> Result<String, String> {
        // Sign the balance update (uses host.sign_with_tweaked_key internally)
        let update_json = self.sign_balance_update(channel_id, balance)?;

        let update: serde_json::Value = serde_json::from_str(&update_json)
            .map_err(|e| format!("Failed to parse balance update: {}", e))?;

        // Build the payment header JSON
        let mut header = serde_json::json!({
            "channel_id": update["channel_id"],
            "balance": update["amount"],
            "signature": update["signature"]
        });

        if include_funding {
            let stored = self.load_channel(channel_id)?;

            // Parse params_json into a JSON object for inclusion
            let params: serde_json::Value = serde_json::from_str(&stored.params_json)
                .map_err(|e| format!("Failed to parse params: {}", e))?;
            let funding_proofs: serde_json::Value =
                serde_json::from_str(&stored.funding_proofs_json)
                    .map_err(|e| format!("Failed to parse funding proofs: {}", e))?;

            header["params"] = params;
            header["funding_proofs"] = funding_proofs;
        }

        // Base64 encode
        let header_str = header.to_string();
        Ok(base64_encode(&header_str))
    }

    /// Get information about a stored channel.
    pub fn get_channel_info(&self, channel_id: &str) -> Option<ClientChannelInfo> {
        let json = self.host.get_channel(channel_id)?;
        let stored: StoredChannel = serde_json::from_str(&json).ok()?;
        Some(ClientChannelInfo {
            channel_id: stored.channel_id,
            capacity: stored.capacity,
            funding_token_amount: stored.funding_token_amount,
            mint_url: stored.mint_url,
            params_json: stored.params_json,
        })
    }

    /// List all stored channel IDs.
    pub fn list_channels(&self) -> Vec<String> {
        self.host.list_channel_ids()
    }

    /// Remove a channel from storage.
    pub fn remove_channel(&self, channel_id: &str) {
        self.host.delete_channel(channel_id);
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    fn load_channel(&self, channel_id: &str) -> Result<StoredChannel, String> {
        let json = self
            .host
            .get_channel(channel_id)
            .ok_or_else(|| format!("Channel not found: {}", channel_id))?;
        serde_json::from_str(&json).map_err(|e| format!("Failed to parse channel state: {}", e))
    }
}

/// Base64 encode a string (standard encoding, matches btoa()).
fn base64_encode(input: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let bytes = input.as_bytes();
    let mut result = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Base64 decode a string (standard encoding).
pub fn base64_decode(input: &str) -> Result<String, String> {
    let input = input.trim_end_matches('=');
    let bytes: Vec<u8> = input.bytes().collect();

    let decode_char = |c: u8| -> Result<u32, String> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("Invalid base64 character: {}", c as char)),
        }
    };

    let mut result = Vec::new();
    for chunk in bytes.chunks(4) {
        let vals: Vec<u32> = chunk
            .iter()
            .map(|&c| decode_char(c))
            .collect::<Result<Vec<_>, _>>()?;

        let triple = match vals.len() {
            4 => (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3],
            3 => (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6),
            2 => (vals[0] << 18) | (vals[1] << 12),
            _ => return Err("Invalid base64 chunk length".to_string()),
        };

        result.push(((triple >> 16) & 0xFF) as u8);
        if vals.len() > 2 {
            result.push(((triple >> 8) & 0xFF) as u8);
        }
        if vals.len() > 3 {
            result.push((triple & 0xFF) as u8);
        }
    }

    String::from_utf8(result).map_err(|e| format!("Invalid UTF-8 in base64 decode: {}", e))
}
