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
use cdk::{Error, Mint, StreamExt};
use cdk_common::mint_url::MintUrl;
use cdk_fake_wallet::FakeWallet;
use tokio::sync::RwLock;
use cdk::secret::Secret;
use clap::Parser;
use uuid::Uuid;

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
        let amount_after_stage1 = channel_fixtures.post_fee_amount_in_the_funding_token();

        // Reconstruct the commitment outputs for this balance
        let commitment_outputs = channel_fixtures.extra.create_two_sets_of_outputs_for_balance(
            self.amount,
            amount_after_stage1,
        )?;

        // Reconstruct the unsigned swap request
        let swap_request = commitment_outputs.create_swap_request(
            channel_fixtures.funding_proofs.clone(),
            &channel_fixtures.extra.params,
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

    let setup_timestamp = unix_time();

    // Generate random sender nonce (created by Alice)
    let sender_nonce = Secret::generate().to_string();

    let channel_unit = CurrencyUnit::Sat;
    let capacity = 1_000_000;  // Desired channel capacity (maximum Charlie can receive after all fees)
    let locktime = setup_timestamp + args.delay_until_refund;

    println!("   Desired capacity: {} {:?}", capacity, channel_unit);
    println!("   Locktime: {} ({} seconds from now)\n", locktime, locktime - unix_time());

    // 3. CREATE OR CONNECT TO MINT AND GET KEYSET
    let (mint_connection, alice_wallet, charlie_wallet, active_keyset_id, input_fee_ppk, mint_url): (Box<dyn MintConnection>, Wallet, Wallet, Id, u64, String) = if let Some(mint_url_str) = args.mint {
        println!("🏦 Connecting to external mint at {}...", mint_url_str);
        let mint_url: MintUrl = mint_url_str.parse()?;

        println!("👩 Setting up Alice's wallet...");
        let alice = create_wallet_http(mint_url.clone(), channel_unit.clone()).await?;

        println!("👨 Setting up Charlie's wallet...");
        let charlie = create_wallet_http(mint_url.clone(), channel_unit.clone()).await?;

        let http_mint = HttpMintConnection::new(mint_url);
        println!("✅ Connected to external mint\n");

        // Get active keyset from mint
        println!("📦 Getting active keyset from mint...");
        let keysets = http_mint.get_keysets().await?;
        let active_keyset_info = keysets.keysets.iter()
            .find(|k| k.active && k.unit == channel_unit)
            .expect("No active keyset");
        let keyset_id = active_keyset_info.id;
        let fee_ppk = active_keyset_info.input_fee_ppk;
        println!("   Using keyset: {}\n", keyset_id);
        println!("   Input fee: {} ppk\n", fee_ppk);

        (Box::new(http_mint), alice, charlie, keyset_id, fee_ppk, mint_url_str)
    } else {
        println!("🏦 Setting up local in-process mint...");
        let mint = create_local_mint(channel_unit.clone()).await?;
        println!("✅ Local mint running\n");

        println!("👩 Setting up Alice's wallet...");
        let alice = create_wallet_local(&mint, channel_unit.clone()).await?;

        println!("👨 Setting up Charlie's wallet...");
        let charlie = create_wallet_local(&mint, channel_unit.clone()).await?;

        let local_mint = DirectMintConnection::new(mint);

        // Get active keyset from mint
        println!("📦 Getting active keyset from mint...");
        let keysets = local_mint.get_keysets().await?;
        let active_keyset_info = keysets.keysets.iter()
            .find(|k| k.active && k.unit == channel_unit)
            .expect("No active keyset");
        let keyset_id = active_keyset_info.id;
        let fee_ppk = active_keyset_info.input_fee_ppk;
        println!("   Using keyset: {}\n", keyset_id);
        println!("   Input fee: {} ppk\n", fee_ppk);

        (Box::new(local_mint), alice, charlie, keyset_id, fee_ppk, "local".to_string())
    };

    // Get the mint's public keys for the active keyset
    let all_keysets = mint_connection.get_keys().await?;
    let set_of_active_keys = all_keysets.iter()
        .find(|k| k.id == active_keyset_id)
        .ok_or_else(|| anyhow::anyhow!("Active keyset not found"))?;

    // 4. CREATE CHANNEL PARAMETERS WITH KEYSET_ID
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
    )?;

    println!("   Mint: {}", mint_url);
    println!("   Unit: {}", channel_params.unit_name());
    println!("   Channel ID: {}\n", channel_params.get_channel_id());

    // 4b. CREATE CHANNEL EXTRA (params + mint-specific data)
    let channel_extra = SpilmanChannelExtra::new(channel_params, set_of_active_keys.keys.clone())?;

    // Print all amounts in the active keyset
    println!("   Active keyset amounts: {:?}\n", channel_extra.keyset_info.amounts_in_this_keyset_largest_first);

    // Demo: Show deterministic_value_after_fees for small values
    println!("💰 Deterministic value after fees (nominal → actual):");
    for nominal in 0..=16 {
        match channel_extra.keyset_info.deterministic_value_after_fees(nominal, channel_extra.params.input_fee_ppk) {
            Ok(actual) => {
                println!("   {} → {} (fee: {})", nominal, actual, nominal - actual);
            }
            Err(e) => {
                println!("   {} → ERROR: {}", nominal, e);
            }
        }
    }
    println!();

    // 5. CHECK MINT CAPABILITIES
    let mint_info = mint_connection.get_mint_info().await?;
    verify_mint_capabilities(&mint_info)?;

    // 6. ALICE MINTS REGULAR PROOFS (2x capacity to have plenty)
    let mint_amount_sats = capacity * 2;
    println!("💰 Alice minting {} sats as regular proofs (2x capacity)...", mint_amount_sats);

    // Use Alice's wallet to mint
    let mint_amount = cdk::Amount::from(mint_amount_sats);
    let quote = alice_wallet.mint_quote(mint_amount, None).await?;
    let mut proof_stream = alice_wallet.proof_stream(quote, Default::default(), None);
    let regular_proofs = proof_stream.next().await.expect("proofs")?;

    println!("   ✓ Minted {} sats", mint_amount_sats);

    // 6b. TEST MANUAL MINT (with NUT-20 automatic signing)
    println!("\n🧪 Testing manual mint with custom BlindedMessages...");

    // Create mint quote (NUT-20 enabled by default)
    let test_quote = alice_wallet.mint_quote(cdk::Amount::from(64u64), None).await?;
    println!("   Created quote with NUT-20: {}", test_quote.id);

    // Wait for FakeWallet to pay the quote
    println!("   Waiting for quote to be paid...");
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Create one arbitrary blinded message
    let test_secret = Secret::new(format!("test_manual_{}", Uuid::new_v4()));
    let test_blinding = SecretKey::generate();
    let (test_blinded_point, _) = cdk::dhke::blind_message(&test_secret.to_bytes(), Some(test_blinding.clone()))?;
    let test_blinded_msg = cdk::nuts::BlindedMessage::new(
        cdk::Amount::from(64u64),
        channel_extra.params.active_keyset_id,
        test_blinded_point,
    );

    println!("   Created arbitrary BlindedMessage for 64 sats");

    // Create MintRequest with custom blinded message
    println!("   Creating MintRequest...");
    let mut test_mint_request = MintRequest {
        quote: test_quote.id.clone(),
        outputs: vec![test_blinded_msg],
        signature: None,
    };

    // Sign the request with NUT-20 (using the secret_key from the quote)
    if let Some(secret_key) = &test_quote.secret_key {
        println!("   Signing MintRequest with NUT-20 (secret_key from quote)...");
        test_mint_request.sign(secret_key.clone())?;
        println!("   ✓ MintRequest signed");
    }

    // Submit the signed MintRequest to the mint
    println!("   Submitting MintRequest to mint...");
    let manual_mint_response = mint_connection.post_mint(test_mint_request).await?;

    println!("   ✓ Received {} blind signature(s)", manual_mint_response.signatures.len());

    // Unblind to get the proof
    let manual_proof = cdk::dhke::construct_proofs(
        vec![manual_mint_response.signatures[0].clone()],
        vec![test_blinding],
        vec![test_secret],
        &set_of_active_keys.keys,
    )?;

    println!("   ✓ Unblinded proof: {} sats", u64::from(manual_proof[0].amount));
    println!("   ✅ Manual mint with NUT-20 succeeded!\n");

    // 7. CALCULATE EXACT FUNDING TOKEN SIZE using double inverse
    println!("\n💡 Calculating exact funding token size using double inverse...");

    // First inverse: capacity → post-stage-1 nominal (accounting for stage 2 fees)
    let post_stage1_result = channel_extra.keyset_info.inverse_deterministic_value_after_fees(capacity, channel_extra.params.input_fee_ppk)?;
    println!("   Capacity: {} sats", capacity);
    println!("   Post-stage-1 nominal (after inverse 1): {} sats (actual: {} sats)",
             post_stage1_result.nominal_value, post_stage1_result.actual_balance);

    // Second inverse: post-stage-1 nominal → funding token nominal (accounting for stage 1 fees)
    let funding_token_result = channel_extra.keyset_info.inverse_deterministic_value_after_fees(post_stage1_result.nominal_value, channel_extra.params.input_fee_ppk)?;
    println!("   Funding token nominal (after inverse 2): {} sats (actual: {} sats)",
             funding_token_result.nominal_value, funding_token_result.actual_balance);

    let funding_token_nominal = funding_token_result.nominal_value;

    // 8. CREATE DETERMINISTIC FUNDING OUTPUTS
    println!("\n🔐 Creating deterministic funding token outputs ({} sats with 2-of-2 multisig)...", funding_token_nominal);

    println!("   P2PK conditions: 2-of-2 multisig (Alice + Charlie) before locktime");
    println!("   After locktime: Alice can refund with just her signature");

    // Create deterministic outputs for the funding token
    let funding_outputs = extra::SetOfDeterministicOutputs::new(
        &channel_extra.keyset_info.amounts_in_this_keyset_largest_first,
        "funding".to_string(),
        funding_token_nominal,
    )?;

    // Get the blinded messages for the funding outputs
    let funding_blinded_messages = funding_outputs.get_blinded_messages(&channel_extra.params)?;
    let funding_secrets_with_blinding = funding_outputs.get_secrets_with_blinding(&channel_extra.params)?;

    println!("   ✓ Created {} deterministic funding outputs", funding_blinded_messages.len());

    let total_output_value: u64 = funding_blinded_messages.iter().map(|bm| u64::from(bm.amount)).sum();
    println!("   Total funding output value: {} sats", total_output_value);

    // 9. SELECT INPUT PROOFS iteratively until we have enough for outputs + fees
    println!("\n📊 Selecting input proofs to cover outputs + fees...");

    let mut selected_inputs = Vec::new();
    let mut input_total = 0u64;
    let mut fee = 0u64;

    for proof in &regular_proofs {
        selected_inputs.push(proof.clone());
        input_total += u64::from(proof.amount);

        let num_inputs = selected_inputs.len();
        fee = (channel_extra.params.input_fee_ppk * num_inputs as u64 + 999) / 1000;

        if input_total >= total_output_value + fee {
            break;
        }
    }

    println!("   Selected {} input proofs totaling {} sats", selected_inputs.len(), input_total);
    println!("   Expected fee: {} sats", fee);

    let change = input_total - total_output_value - fee;
    println!("   Change: {} sats", change);

    // 10. CREATE CHANGE OUTPUTS
    println!("\n💵 Creating change outputs...");

    let change_amounts_list = if change > 0 {
        extra::amounts_for_target_largest_first(
            &channel_extra.keyset_info.amounts_in_this_keyset_largest_first,
            change
        )?
    } else {
        extra::OrderedListOfAmounts::new(std::collections::BTreeMap::new())
    };

    let change_amounts: Vec<u64> = change_amounts_list.iter_largest_first()
        .flat_map(|(&amount, &count)| std::iter::repeat(amount).take(count))
        .collect();

    println!("   Change amounts: {:?}", change_amounts);

    // Create random blinded messages for change
    let mut change_blinded_messages = Vec::new();
    let mut change_secrets = Vec::new();
    let mut change_blinding_factors = Vec::new();

    for &amount in &change_amounts {
        let secret = Secret::new(format!("change_{}", Uuid::new_v4()));
        let blinding_factor = SecretKey::generate();

        let (blinded_point, _) = cdk::dhke::blind_message(&secret.to_bytes(), Some(blinding_factor.clone()))?;
        let blinded_message = cdk::nuts::BlindedMessage::new(
            cdk::Amount::from(amount),
            channel_extra.params.active_keyset_id,
            blinded_point,
        );

        change_blinded_messages.push(blinded_message);
        change_secrets.push(secret);
        change_blinding_factors.push(blinding_factor);
    }

    println!("   ✓ Created {} change outputs", change_blinded_messages.len());

    // 11. BUILD MANUAL SWAP REQUEST
    println!("\n🔄 Building manual swap request...");

    // Combine funding outputs + change outputs
    let mut all_outputs = funding_blinded_messages.clone();
    all_outputs.extend(change_blinded_messages.clone());

    let total_all_outputs: u64 = all_outputs.iter().map(|bm| u64::from(bm.amount)).sum();
    println!("   Total inputs: {} sats ({} proofs)", input_total, selected_inputs.len());
    println!("   Total outputs: {} sats ({} outputs: {} funding + {} change)",
             total_all_outputs, all_outputs.len(),
             funding_blinded_messages.len(), change_blinded_messages.len());
    println!("   Fee: {} sats", fee);

    // Verify the equation
    if input_total != total_all_outputs + fee {
        anyhow::bail!(
            "Input/output mismatch: {} inputs ≠ {} outputs + {} fee",
            input_total, total_all_outputs, fee
        );
    }

    println!("   ✓ Equation verified: {} = {} + {}", input_total, total_all_outputs, fee);

    // Create the swap request (no signatures needed - regular proofs)
    let swap_request = SwapRequest::new(selected_inputs.clone(), all_outputs);

    println!("\n🔄 Submitting swap to mint...");
    let swap_response = mint_connection.process_swap(swap_request).await?;

    println!("   ✓ Received {} blind signatures", swap_response.signatures.len());

    // 12. UNBLIND THE RESPONSES
    println!("\n🔓 Unblinding signatures...");

    // Unblind funding token signatures
    let funding_proofs = cdk::dhke::construct_proofs(
        swap_response.signatures[0..funding_blinded_messages.len()].to_vec(),
        funding_secrets_with_blinding.iter().map(|s| s.blinding_factor.clone()).collect(),
        funding_secrets_with_blinding.iter().map(|s| s.secret.clone()).collect(),
        &set_of_active_keys.keys,
    )?;

    let p2pk_total: u64 = funding_proofs.iter().map(|p| u64::from(p.amount)).sum();
    println!("   ✓ Unblinded {} funding token proofs totaling {} sats", funding_proofs.len(), p2pk_total);

    // Unblind change signatures (if any)
    if !change_blinded_messages.is_empty() {
        let change_proofs = cdk::dhke::construct_proofs(
            swap_response.signatures[funding_blinded_messages.len()..].to_vec(),
            change_blinding_factors,
            change_secrets,
            &set_of_active_keys.keys,
        )?;

        let change_total: u64 = change_proofs.iter().map(|p| u64::from(p.amount)).sum();
        println!("   ✓ Unblinded {} change proofs totaling {} sats", change_proofs.len(), change_total);
    }

    let p2pk_proofs = funding_proofs;

    println!("\n✅ Deterministic funding token created!");

    // 13. CREATE CHANNEL FIXTURES
    println!("\n📦 Creating channel fixtures...");

    let channel_fixtures = ChannelFixtures::new(
        channel_extra,
        p2pk_proofs,
    )?;

    println!("   Total locked value: {} sats", channel_fixtures.total_locked_value);
    println!("   Total input fee: {} sats", channel_fixtures.total_input_fee);
    println!("   Post-fee value: {} sats", channel_fixtures.post_fee_amount_in_the_funding_token());
    println!("   Channel capacity: {} sats", channel_fixtures.extra.params.get_capacity());

    println!("\n✅ Channel fixtures created!");

    // 9. CHECK FUNDING TOKEN STATE (should be UNSPENT)
    println!("\n🔍 Checking funding token state (NUT-07)...");
    let state_before = channel_fixtures.check_funding_token_state(&*mint_connection).await?;
    let state_info = &state_before.states[0];
    println!("   Funding token state: {:?}", state_info.state);
    if state_info.state != cdk::nuts::State::Unspent {
        anyhow::bail!("Funding token should be UNSPENT but is {:?}", state_info.state);
    }
    println!("   ✓ Funding token is unspent and ready for commitment transaction");

    // 10. CREATE COMMITMENT TRANSACTION AND SWAP
    let charlie_balance = 100_000u64; // Charlie gets 100,000 sats
    println!("\n💱 Creating commitment transaction for balance: {} sats to Charlie...", charlie_balance);

    // Get the amount available after stage 1 fees
    let amount_after_stage1 = channel_fixtures.post_fee_amount_in_the_funding_token();
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
        &channel_fixtures.extra.params,
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
    let swap_response = mint_connection.process_swap(swap_request).await?;
    println!("   ✓ Mint processed swap successfully!");
    println!("   Received {} blind signatures", swap_response.signatures.len());

    // Check funding token state after swap (should be SPENT)
    println!("\n🔍 Checking funding token state after swap (NUT-07)...");
    let state_after = channel_fixtures.check_funding_token_state(&*mint_connection).await?;
    let state_info_after = &state_after.states[0];
    println!("   Funding token state: {:?}", state_info_after.state);
    if state_info_after.state != cdk::nuts::State::Spent {
        println!("   ⚠ WARNING: Expected SPENT but got {:?}", state_info_after.state);
    } else {
        println!("   ✓ Funding token has been spent (commitment transaction executed)");
    }

    // Restore blind signatures using NUT-09 (demonstrates that deterministic outputs can be recovered)
    println!("\n🔄 Restoring blind signatures from mint (NUT-09)...");
    let restored_signatures = commitment_outputs.restore_all_blind_signatures(
        &channel_fixtures.extra,
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
        &channel_fixtures.extra.params,
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
