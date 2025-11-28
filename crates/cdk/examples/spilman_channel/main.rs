//! Example: Spilman (Unidirectional) Payment Channel
//!
//! This example will demonstrate a Cashu implementation of Spilman channels,
//! allowing Alice and Charlie to set up an offline unidirectional payment channel.

mod deterministic;
mod params;
mod extra;
mod fixtures;

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
use cdk::nuts::{
    CheckStateRequest, CheckStateResponse, CurrencyUnit, Id, KeySet, KeysetResponse,
    MeltQuoteBolt11Request, MeltQuoteBolt11Response, MeltRequest, MintInfo,
    MintQuoteBolt11Request, MintQuoteBolt11Response, MintRequest, MintResponse, PaymentMethod,
    RestoreRequest, RestoreResponse, SecretKey, SwapRequest, SwapResponse,
};
use cdk::types::{FeeReserve, QuoteTTL};
use cdk::util::unix_time;
use cdk::wallet::{AuthWallet, HttpClient, MintConnector, Wallet, WalletBuilder};
use cdk::{Error, Mint};
use cdk_common::mint_url::MintUrl;
use cdk_fake_wallet::FakeWallet;
use tokio::sync::RwLock;
use cdk::secret::Secret;
use clap::Parser;

use params::SpilmanChannelParameters;
use extra::SpilmanChannelExtra;
use fixtures::ChannelFixtures;

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

/// A signed balance update message that can be sent from Alice to Charlie
/// Represents Alice's commitment to a new channel balance
#[derive(Debug, Clone)]
struct BalanceUpdateMessage {
    /// Channel ID to identify which channel this update is for
    channel_id: String,
    /// New balance for the receiver (Charlie)
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
    /// Charlie reconstructs the swap request from the amount to verify the signature
    /// Throws an error if the signature is invalid
    fn verify_sender_signature(&self, channel_fixtures: &ChannelFixtures) -> Result<(), anyhow::Error> {
        // Get the amount available after stage 1 fees
        let amount_after_stage1 = channel_fixtures.extra.get_value_after_stage1()?;

        // Reconstruct the commitment outputs for this balance
        let commitment_outputs = channel_fixtures.extra.create_two_sets_of_outputs_for_balance(
            self.amount,
            amount_after_stage1,
        )?;

        // Reconstruct the unsigned swap request
        let swap_request = commitment_outputs.create_swap_request(
            channel_fixtures.funding_proofs.clone(),
        )?;

        // Extract the SIG_ALL message from the swap request
        let msg_to_sign = swap_request.sig_all_msg_to_sign();

        // Verify the signature using Alice's pubkey from channel params
        channel_fixtures.extra.params.alice_pubkey
            .verify(msg_to_sign.as_bytes(), &self.signature)
            .map_err(|_| anyhow::anyhow!("Invalid signature: Alice did not authorize this balance update"))?;

        Ok(())
    }
}

/// Create a wallet connected to a local in-process mint
async fn create_wallet_local(mint: &Mint, unit: CurrencyUnit) -> anyhow::Result<Wallet> {
    let connector = DirectMintConnection::new(mint.clone());
    let store = Arc::new(cdk_sqlite::wallet::memory::empty().await?);
    let seed = Mnemonic::generate(12)?.to_seed_normalized("");

    // Use a dummy mint URL for local wallet (actual connection is via DirectMintConnection)
    let wallet = WalletBuilder::new()
        .mint_url("http://localhost:8080".parse()?)
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

/// Setup mint connection and wallets for both parties
///
/// Creates either a local in-process mint or connects to an external mint via HTTP,
/// creates wallets for both Alice and Charlie, and verifies mint capabilities.
///
/// # Arguments
/// * `mint_url_opt` - Optional mint URL; None creates a local in-process mint
/// * `unit` - The currency unit to use
///
/// # Returns
/// (MintConnection, Alice's Wallet, Charlie's Wallet, Mint URL string)
async fn setup_mint_and_wallets_for_demo(
    mint_url_opt: Option<String>, // None = create local in-process mint
    unit: CurrencyUnit,
) -> anyhow::Result<(Box<dyn MintConnection>, Wallet, Wallet, String)> {
    let (mint_connection, alice, charlie, mint_url): (Box<dyn MintConnection>, Wallet, Wallet, String) = if let Some(mint_url_str) = mint_url_opt {
        println!("🏦 Connecting to external mint at {}...", mint_url_str);
        let mint_url: MintUrl = mint_url_str.parse()?;

        println!("👩 Setting up Alice's wallet...");
        let alice = create_wallet_http(mint_url.clone(), unit.clone()).await?;

        println!("👨 Setting up Charlie's wallet...");
        let charlie = create_wallet_http(mint_url.clone(), unit.clone()).await?;

        let http_mint = HttpMintConnection::new(mint_url);
        println!("✅ Connected to external mint\n");

        (Box::new(http_mint), alice, charlie, mint_url_str)
    } else {
        println!("🏦 Setting up local in-process mint...");
        let mint = create_local_mint(unit.clone()).await?;
        println!("✅ Local mint running\n");

        println!("👩 Setting up Alice's wallet...");
        let alice = create_wallet_local(&mint, unit.clone()).await?;

        println!("👨 Setting up Charlie's wallet...");
        let charlie = create_wallet_local(&mint, unit.clone()).await?;

        let local_mint = DirectMintConnection::new(mint);

        (Box::new(local_mint), alice, charlie, "local".to_string())
    };

    // Verify mint capabilities
    let mint_info = mint_connection.get_mint_info().await?;
    verify_mint_capabilities(&mint_info)?;

    Ok((mint_connection, alice, charlie, mint_url))
}

/// Get active keyset information for a unit
/// Returns (keyset_id, input_fee_ppk, keys)
async fn get_active_keyset_info(
    mint_connection: &dyn MintConnection,
    unit: &CurrencyUnit,
) -> anyhow::Result<(Id, u64, cdk::nuts::Keys)> {
    // Get all keysets and their info
    let all_keysets = mint_connection.get_keys().await?;
    let keysets_info = mint_connection.get_keysets().await?;

    // Find the active keyset for our unit
    let active_keyset_info = keysets_info.keysets.iter()
        .find(|k| k.active && k.unit == *unit)
        .ok_or_else(|| anyhow::anyhow!("No active keyset for unit {:?}", unit))?;

    let active_keyset_id = active_keyset_info.id;
    let input_fee_ppk = active_keyset_info.input_fee_ppk;

    // Get the actual keys for this keyset
    let set_of_active_keys = all_keysets.iter()
        .find(|k| k.id == active_keyset_id)
        .ok_or_else(|| anyhow::anyhow!("Active keyset keys not found"))?;

    Ok((active_keyset_id, input_fee_ppk, set_of_active_keys.keys.clone()))
}

/// Create and mint the funding token for a Spilman channel
///
/// This creates deterministic funding outputs with 2-of-2 multisig conditions
/// and mints them directly using NUT-20 authentication.
///
/// Returns the minted funding proofs
async fn create_and_mint_funding_token(
    channel_extra: &SpilmanChannelExtra,
    funding_token_nominal: u64,
    mint_connection: &dyn MintConnection,
    active_keys: &cdk::nuts::Keys,
) -> anyhow::Result<Vec<cdk::nuts::Proof>> {
    println!("\n🔐 Creating deterministic funding token outputs ({} sats with 2-of-2 multisig)...", funding_token_nominal);
    println!("   P2PK conditions: 2-of-2 multisig (Alice + Charlie) before locktime");
    println!("   After locktime: Alice can refund with just her signature");

    // Create deterministic outputs for the funding token
    let funding_outputs = extra::SetOfDeterministicOutputs::new(
        &channel_extra.keyset_info.amounts_in_this_keyset_largest_first,
        "funding".to_string(),
        funding_token_nominal,
        channel_extra.params.clone(),
    )?;

    // Get the blinded messages for the funding outputs
    let funding_blinded_messages = funding_outputs.get_blinded_messages()?;
    let funding_secrets_with_blinding = funding_outputs.get_secrets_with_blinding()?;

    println!("   ✓ Created {} deterministic funding outputs", funding_blinded_messages.len());

    // Verify that the total output value equals the funding token nominal
    assert_eq!(
        funding_blinded_messages.iter().map(|bm| u64::from(bm.amount)).sum::<u64>(),
        funding_token_nominal,
        "Total funding output value should equal funding_token_nominal"
    );

    // Mint the funding token directly (using NUT-20 signed MintRequest)
    println!("\n🪙 Minting funding token directly...");

    let funding_proofs = mint_deterministic_outputs(
        mint_connection,
        channel_extra.params.unit.clone(),
        funding_blinded_messages.clone(),
        funding_secrets_with_blinding,
        active_keys,
    ).await?;

    for (i, proof) in funding_proofs.iter().enumerate() {
        println!("      Proof {}: {} sats", i, u64::from(proof.amount));
    }
    println!("   ✅ Funding token minted directly!\n");

    Ok(funding_proofs)
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
            unit.clone(),
            PaymentMethod::Bolt11,
            MintMeltLimits::new(1, 2_000_000_000),  // 2B msat = 2M sat
            Arc::new(fake_ln),
        )
        .await?;

    // Set input fee to 400 parts per thousand (40%)
    mint_builder.set_unit_fee(&unit, 400)?;

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
pub trait MintConnection {
    async fn get_mint_info(&self) -> Result<MintInfo, Error>;
    async fn get_keysets(&self) -> Result<KeysetResponse, Error>;
    async fn get_keys(&self) -> Result<Vec<KeySet>, Error>;
    async fn process_swap(&self, swap_request: SwapRequest) -> Result<SwapResponse, Error>;
    async fn check_state(&self, request: CheckStateRequest) -> Result<CheckStateResponse, Error>;
    async fn post_restore(&self, request: RestoreRequest) -> Result<RestoreResponse, Error>;
    async fn post_mint(&self, request: MintRequest<String>) -> Result<MintResponse, Error>;
    async fn post_mint_quote(&self, request: MintQuoteBolt11Request) -> Result<MintQuoteBolt11Response<String>, Error>;
    async fn get_mint_quote_status(&self, quote_id: &str) -> Result<MintQuoteBolt11Response<String>, Error>;
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

    async fn check_state(&self, request: CheckStateRequest) -> Result<CheckStateResponse, Error> {
        self.http_client.post_check_state(request).await
    }

    async fn post_restore(&self, request: RestoreRequest) -> Result<RestoreResponse, Error> {
        self.http_client.post_restore(request).await
    }

    async fn post_mint(&self, request: MintRequest<String>) -> Result<MintResponse, Error> {
        self.http_client.post_mint(request).await
    }

    async fn post_mint_quote(&self, request: MintQuoteBolt11Request) -> Result<MintQuoteBolt11Response<String>, Error> {
        self.http_client.post_mint_quote(request).await
    }

    async fn get_mint_quote_status(&self, quote_id: &str) -> Result<MintQuoteBolt11Response<String>, Error> {
        self.http_client.get_mint_quote_status(quote_id).await
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

    async fn fetch_lnurl_pay_request(
        &self,
        _lnurl: &str,
    ) -> Result<cdk::wallet::LnurlPayResponse, Error> {
        Err(Error::UnsupportedPaymentMethod)
    }

    async fn fetch_lnurl_invoice(
        &self,
        _callback_url: &str,
    ) -> Result<cdk::wallet::LnurlPayInvoiceResponse, Error> {
        Err(Error::UnsupportedPaymentMethod)
    }
}

// Also implement the simpler MintConnection trait for channel operations
#[async_trait]
impl MintConnection for DirectMintConnection {
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

    async fn check_state(&self, request: CheckStateRequest) -> Result<CheckStateResponse, Error> {
        self.mint.check_state(&request).await
    }

    async fn post_restore(&self, request: RestoreRequest) -> Result<RestoreResponse, Error> {
        self.mint.restore(request).await
    }

    async fn post_mint(&self, request: MintRequest<String>) -> Result<MintResponse, Error> {
        let request_id: MintRequest<QuoteId> = request.try_into().unwrap();
        self.mint.process_mint_request(request_id).await
    }

    async fn post_mint_quote(&self, request: MintQuoteBolt11Request) -> Result<MintQuoteBolt11Response<String>, Error> {
        self.mint
            .get_mint_quote(request.into())
            .await
            .map(Into::into)
    }

    async fn get_mint_quote_status(&self, quote_id: &str) -> Result<MintQuoteBolt11Response<String>, Error> {
        self.mint
            .check_mint_quote(&QuoteId::from_str(quote_id)?)
            .await
            .map(Into::into)
    }
}

/// Mint deterministic outputs directly using NUT-20 signed MintRequest
///
/// This helper function:
/// 1. Creates a mint quote for the total amount with NUT-20
/// 2. Waits for the quote to be paid
/// 3. Builds a MintRequest with the provided blinded messages
/// 4. Signs the request with NUT-20
/// 5. Submits the request to the mint
/// 6. Unblinds the response to get the proofs
///
/// # Arguments
/// * `mint_connection` - The mint connection to use
/// * `unit` - The currency unit for the quote
/// * `blinded_messages` - The deterministic blinded messages to mint
/// * `secrets_with_blinding` - The secrets and blinding factors for unblinding
/// * `keyset_keys` - The mint's public keys for the keyset
///
/// # Returns
/// The unblinded proofs
async fn mint_deterministic_outputs(
    mint_connection: &dyn MintConnection,
    unit: CurrencyUnit,
    blinded_messages: Vec<cdk::nuts::BlindedMessage>,
    secrets_with_blinding: Vec<deterministic::DeterministicSecretWithBlinding>,
    keyset_keys: &cdk::nuts::Keys,
) -> anyhow::Result<Vec<cdk::nuts::Proof>> {
    // Calculate total amount
    let total_amount: u64 = blinded_messages.iter().map(|bm| u64::from(bm.amount)).sum();

    println!("   Creating quote for {} sats ({} outputs)...", total_amount, blinded_messages.len());

    // Generate NUT-20 keypair for the quote
    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();

    // Create mint quote with NUT-20
    let quote_request = MintQuoteBolt11Request {
        amount: cdk::Amount::from(total_amount),
        unit,
        description: None,
        pubkey: Some(pubkey),
    };

    let quote = mint_connection.post_mint_quote(quote_request).await?;
    println!("   Created quote with NUT-20: {}", quote.quote);

    // Poll for quote to be paid
    println!("   Waiting for quote to be paid...");
    let quote_id = quote.quote.clone();
    loop {
        let quote_status = mint_connection.get_mint_quote_status(&quote_id).await?;
        if quote_status.state == cdk_common::MintQuoteState::Paid {
            println!("   ✓ Quote paid!");
            break;
        }
        println!("   Polling... quote not yet paid (state: {:?})", quote_status.state);
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    // Create MintRequest with the deterministic blinded messages
    println!("   Creating MintRequest with {} outputs...", blinded_messages.len());
    let mut mint_request = MintRequest {
        quote: quote_id.clone(),
        outputs: blinded_messages,
        signature: None,
    };

    // Sign the request with NUT-20
    println!("   Signing MintRequest with NUT-20...");
    mint_request.sign(secret_key)?;
    println!("   ✓ MintRequest signed");

    // Submit the signed MintRequest to the mint
    println!("   Submitting MintRequest to mint...");
    let mint_response = mint_connection.post_mint(mint_request).await?;

    println!("   ✓ Received {} blind signature(s)", mint_response.signatures.len());

    // Unblind to get the proofs
    let proofs = cdk::dhke::construct_proofs(
        mint_response.signatures,
        secrets_with_blinding.iter().map(|s| s.blinding_factor.clone()).collect(),
        secrets_with_blinding.iter().map(|s| s.secret.clone()).collect(),
        keyset_keys,
    )?;

    let total: u64 = proofs.iter().map(|p| u64::from(p.amount)).sum();
    println!("   ✓ Unblinded {} proofs totaling {} sats", proofs.len(), total);

    Ok(proofs)
}

/// Verify that the mint supports all required capabilities for Spilman channels
///
/// Required: NUT-07 (token state check), NUT-09 (restore signatures),
///           NUT-11 (P2PK), NUT-12 (DLEQ)
/// Optional: NUT-17 (WebSocket subscriptions)
fn verify_mint_capabilities(mint_info: &MintInfo) -> anyhow::Result<()> {
    println!("🔍 Checking mint capabilities...");

    let mut all_required_supported = true;

    // Check for NUT-07 support (Token state check)
    if mint_info.nuts.nut07.supported {
        println!("   ✓ Mint supports NUT-07 (Token state check)");
    } else {
        println!("   ✗ Mint does not support NUT-07 (Token state check) - REQUIRED");
        all_required_supported = false;
    }

    // Check for NUT-09 support (Restore signatures)
    if mint_info.nuts.nut09.supported {
        println!("   ✓ Mint supports NUT-09 (Restore signatures)");
    } else {
        println!("   ✗ Mint does not support NUT-09 (Restore signatures) - REQUIRED");
        all_required_supported = false;
    }

    // Check for NUT-11 support (P2PK spending conditions)
    if mint_info.nuts.nut11.supported {
        println!("   ✓ Mint supports NUT-11 (P2PK spending conditions)");
    } else {
        println!("   ✗ Mint does not support NUT-11 (P2PK) - REQUIRED");
        all_required_supported = false;
    }

    // Check for NUT-12 support (DLEQ proofs)
    if mint_info.nuts.nut12.supported {
        println!("   ✓ Mint supports NUT-12 (DLEQ proofs)");
    } else {
        println!("   ✗ Mint does not support NUT-12 (DLEQ proofs) - REQUIRED");
        all_required_supported = false;
    }

    // Check for NUT-17 support (WebSocket subscriptions) - optional but beneficial
    if !mint_info.nuts.nut17.supported.is_empty() {
        println!("   ✓ Mint supports NUT-17 (WebSocket subscriptions) - beneficial for detecting channel closure");
    } else {
        println!("   ⚠ Mint does not support NUT-17 (WebSocket subscriptions) - optional but beneficial");
    }

    println!();

    if !all_required_supported {
        anyhow::bail!("Mint does not support all required capabilities for Spilman channels");
    }

    Ok(())
}

/// Spilman Payment Channel Demo
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Mint URL (if not specified, uses in-process CDK mint)
    #[arg(long)]
    mint: Option<String>,

    /// Delay in seconds until Alice can refund (locktime)
    #[arg(long, default_value = "10")]
    delay_until_refund: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // 1. GENERATE KEYS FOR ALICE AND CHARLIE
    println!("🔑 Generating keypairs...");
    let alice_secret = SecretKey::generate();
    let alice_pubkey = alice_secret.public_key();
    println!("   Alice pubkey: {}", alice_pubkey);

    let charlie_secret = SecretKey::generate();
    let charlie_pubkey = charlie_secret.public_key();
    println!("   Charlie pubkey:   {}\n", charlie_pubkey);

    // 2. SETUP INITIAL CHANNEL PARAMETERS
    println!("📋 Setting up Spilman channel parameters...");

    let channel_unit = CurrencyUnit::Sat;

    // 3. CREATE OR CONNECT TO MINT
    let (mint_connection, alice_wallet, charlie_wallet, mint_url) =
        setup_mint_and_wallets_for_demo(args.mint, channel_unit.clone()).await?;

    // Get active keyset information
    let (active_keyset_id, input_fee_ppk, active_keys) =
        get_active_keyset_info(mint_connection.as_ref(), &channel_unit).await?;

    let capacity = 1_000_000;  // Desired channel capacity (maximum Charlie can receive after all fees)
    let setup_timestamp = unix_time();
    let locktime = setup_timestamp + args.delay_until_refund;

    // Generate random sender nonce (created by Alice)
    let sender_nonce = Secret::generate().to_string();

    // 4. CREATE CHANNEL PARAMETERS WITH KEYSET_ID
    let maximum_amount_for_one_output = 100_000; // 100k sats maximum per output

    let channel_params = SpilmanChannelParameters::new(
        alice_pubkey,
        charlie_pubkey,
        mint_url.clone(),
        channel_unit.clone(),
        capacity,
        locktime,
        setup_timestamp,
        sender_nonce,
        active_keyset_id,
        input_fee_ppk,
        maximum_amount_for_one_output,
    )?;

    println!("   Desired capacity: {} {:?}", capacity, channel_unit);
    println!("   Locktime: {} ({} seconds from now)\n", locktime, locktime - unix_time());
    println!("   Using keyset: {}", active_keyset_id);
    println!("   Input fee: {} ppk\n", input_fee_ppk);
    println!("   Mint: {}", mint_url);
    println!("   Unit: {}", channel_params.unit_name());
    println!("   Channel ID: {}\n", channel_params.get_channel_id());

    // 4b. CREATE CHANNEL EXTRA (params + mint-specific data)
    let channel_extra = SpilmanChannelExtra::new(channel_params, active_keys.clone())?;

    // 5. CALCULATE EXACT FUNDING TOKEN SIZE using double inverse
    println!("\n💡 Calculating exact funding token size using double inverse...");
    println!("   Capacity: {} sats", capacity);

    let funding_token_nominal = channel_extra.get_total_funding_token_amount()?;

    println!("   Funding token nominal: {} sats\n", funding_token_nominal);

    // 7. CREATE AND MINT FUNDING TOKEN
    let funding_proofs = create_and_mint_funding_token(
        &channel_extra,
        funding_token_nominal,
        &*mint_connection,
        &active_keys,
    ).await?;

    // Use the minted funding token as the P2PK proofs for the channel
    let p2pk_proofs = funding_proofs;

    println!("\n✅ Deterministic funding token created!");

    // 9. CREATE CHANNEL FIXTURES
    println!("\n📦 Creating channel fixtures...");

    let channel_fixtures = ChannelFixtures::new(
        channel_extra,
        p2pk_proofs,
    )?;

    println!("   Channel capacity: {} sats", channel_fixtures.extra.params.get_capacity());

    println!("\n✅ Channel fixtures created!");

    // 10. CHECK FUNDING TOKEN STATE (should be UNSPENT)
    println!("\n🔍 Checking funding token state (NUT-07)...");
    let state_before = channel_fixtures.check_funding_token_state(&*mint_connection).await?;
    println!("   Funding token state: {:?}", state_before.state);
    if state_before.state != cdk::nuts::State::Unspent {
        anyhow::bail!("Funding token should be UNSPENT but is {:?}", state_before.state);
    }
    println!("   ✓ Funding token is unspent and ready for commitment transaction");

    // 11. CREATE COMMITMENT TRANSACTION AND SWAP
    let charlie_balance = 100_000u64; // Charlie gets 100,000 sats
    println!("\n💱 Creating commitment transaction for balance: {} sats to Charlie...", charlie_balance);

    // Get the amount available after stage 1 fees
    let amount_after_stage1 = channel_fixtures.extra.get_value_after_stage1()?;
    println!("   Amount after stage 1 fees: {} sats", amount_after_stage1);

    // Create commitment outputs for this balance
    let commitment_outputs = channel_fixtures.extra.create_two_sets_of_outputs_for_balance(
        charlie_balance,
        amount_after_stage1,
    )?;
    println!("   ✓ Created deterministic outputs for both parties");
    let charlie_final = commitment_outputs.receiver_outputs.value_after_fees(channel_fixtures.extra.params.input_fee_ppk)?;
    let alice_final = commitment_outputs.sender_outputs.value_after_fees(channel_fixtures.extra.params.input_fee_ppk)?;
    println!("      Charlie: {} sats nominal → {} proofs → {} sats final",
        commitment_outputs.receiver_outputs.amount,
        commitment_outputs.receiver_outputs.ordered_amounts.len(),
        charlie_final);
    println!("      Alice: {} sats nominal → {} proofs → {} sats final",
        commitment_outputs.sender_outputs.amount,
        commitment_outputs.sender_outputs.ordered_amounts.len(),
        alice_final);

    // Create unsigned swap request
    let mut swap_request = commitment_outputs.create_swap_request(
        channel_fixtures.funding_proofs.clone(),
    )?;
    println!("   ✓ Created unsigned swap request");

    // Alice signs first (as the sender/funder)
    swap_request.sign_sig_all(alice_secret.clone())?;
    println!("   ✓ Alice signed the swap request");

    // Create a balance update message (this is what Alice would send to Charlie off-chain)
    let balance_update = BalanceUpdateMessage::from_signed_swap_request(
        channel_fixtures.extra.params.get_channel_id(),
        charlie_balance,
        &swap_request,
    )?;
    println!("   ✓ Created off-chain balance update message");
    println!("      Channel: {}", balance_update.channel_id);
    println!("      Amount: {} sats", balance_update.amount);
    println!("      Signature: {}", balance_update.signature);

    // Charlie verifies Alice's signature before adding his own
    balance_update.verify_sender_signature(&channel_fixtures)?;
    println!("   ✓ Charlie verified Alice's signature on the balance update");

    // Charlie signs second (as the receiver)
    swap_request.sign_sig_all(charlie_secret.clone())?;
    println!("   ✓ Charlie signed the swap request");

    // Submit the signed swap request to the mint
    println!("\n🔄 Submitting swap to mint...");
    let swap_output_amounts: Vec<u64> = swap_request.outputs().iter().map(|bm| u64::from(bm.amount)).collect();
    println!("   Swap output amounts: {:?}", swap_output_amounts);
    let swap_response = mint_connection.process_swap(swap_request).await?;
    println!("   ✓ Mint processed swap successfully!");
    println!("   Received {} blind signatures", swap_response.signatures.len());

    // Check funding token state after swap (should be SPENT)
    println!("\n🔍 Checking funding token state after swap (NUT-07)...");
    let state_after = channel_fixtures.check_funding_token_state(&*mint_connection).await?;
    println!("   Funding token state: {:?}", state_after.state);
    if state_after.state != cdk::nuts::State::Spent {
        println!("   ⚠ WARNING: Expected SPENT but got {:?}", state_after.state);
    } else {
        println!("   ✓ Funding token has been spent (commitment transaction executed)");
    }

    // Restore blind signatures using NUT-09 (demonstrates that deterministic outputs can be recovered)
    println!("\n🔄 Restoring blind signatures from mint (NUT-09)...");
    let restored_signatures = commitment_outputs.restore_all_blind_signatures(
        &*mint_connection,
    ).await?;
    println!("   ✓ Restored {} blind signatures from mint", restored_signatures.len());

    // Verify that restored signatures match the original signatures from the swap
    assert_eq!(
        restored_signatures, swap_response.signatures,
        "Restored signatures should match original swap response signatures"
    );
    println!("   ✓ Restored signatures match original signatures - NUT-09 working correctly!");

    // Unblind the signatures to get the commitment proofs
    let (charlie_proofs, alice_proofs) = commitment_outputs.unblind_all(
        swap_response.signatures,
        &channel_fixtures.extra.keyset_info.active_keys,
    )?;
    println!("   ✓ Unblinded proofs: {} for Charlie, {} for Alice", charlie_proofs.len(), alice_proofs.len());

    // Add proofs to the wallets (each party will sign and swap to remove P2PK conditions)
    println!("\n💰 Receiving proofs into wallets...");

    // Charlie receives his proofs (wallet will sign and swap to remove P2PK)
    let charlie_receive_opts = cdk::wallet::ReceiveOptions {
        amount_split_target: cdk::amount::SplitTarget::default(),
        p2pk_signing_keys: vec![charlie_secret.clone()],
        preimages: vec![],
        metadata: std::collections::HashMap::new(),
    };
    let charlie_received_amount = charlie_wallet.receive_proofs(charlie_proofs, charlie_receive_opts, None).await?;
    println!("   Charlie received: {} sats", u64::from(charlie_received_amount));

    // Alice receives her proofs (wallet will sign and swap to remove P2PK)
    let alice_receive_opts = cdk::wallet::ReceiveOptions {
        amount_split_target: cdk::amount::SplitTarget::default(),
        p2pk_signing_keys: vec![alice_secret.clone()],
        preimages: vec![],
        metadata: std::collections::HashMap::new(),
    };
    let alice_received_amount = alice_wallet.receive_proofs(alice_proofs, alice_receive_opts, None).await?;
    println!("   Alice received: {} sats", u64::from(alice_received_amount));

    println!("\n✅ Commitment transaction completed and proofs distributed!");

    Ok(())
}
