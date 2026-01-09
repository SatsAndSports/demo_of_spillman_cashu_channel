//! Test helpers for Spilman channel examples and tests

use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bip39::Mnemonic;
use bitcoin::secp256k1::schnorr::Signature;
use cdk::nuts::{MeltQuoteBolt12Request, MintQuoteBolt12Request, MintQuoteBolt12Response};
use cdk_common::{ProofsMethods, QuoteId};
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

// Import Spilman types from the library
use cdk::spilman::{
    DeterministicOutputsForOneContext, DeterministicSecretWithBlinding,
    MintConnection as SpilmanMintConnection,
};

/// Extract signatures from the first proof's witness in a swap request
/// For SigAll, all signatures are stored in the witness of the FIRST proof only
pub fn get_signatures_from_swap_request(swap_request: &SwapRequest) -> Result<Vec<Signature>, anyhow::Error> {
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

/// Create a wallet connected to a local in-process mint
pub async fn create_wallet_local(mint: &Mint, unit: CurrencyUnit) -> anyhow::Result<Wallet> {
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
pub async fn create_wallet_http(mint_url: MintUrl, unit: CurrencyUnit) -> anyhow::Result<Wallet> {
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
pub async fn create_local_mint(unit: CurrencyUnit, input_fee_ppk: u64) -> anyhow::Result<Mint> {
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

    // Set input fee (parts per thousand)
    mint_builder.set_unit_fee(&unit, input_fee_ppk)?;

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

/// Combined trait for interacting with a mint that supports both example operations and library Spilman operations
pub trait FullMintConnection: MintConnection + SpilmanMintConnection {}
impl<T: MintConnection + SpilmanMintConnection> FullMintConnection for T {}

/// Trait for interacting with a mint (either local or HTTP)
#[async_trait]
pub trait MintConnection: Send + Sync {
    async fn get_mint_info(&self) -> Result<MintInfo, Error>;
    async fn get_keysets(&self) -> Result<KeysetResponse, Error>;
    async fn get_keys(&self) -> Result<Vec<KeySet>, Error>;
    async fn process_swap(&self, swap_request: SwapRequest) -> Result<SwapResponse, Error>;
    async fn check_state(&self, request: CheckStateRequest) -> Result<CheckStateResponse, Error>;
    async fn post_restore(&self, request: RestoreRequest) -> Result<RestoreResponse, Error>;
    async fn post_mint(&self, request: MintRequest<String>) -> Result<MintResponse, Error>;
    async fn post_mint_quote(&self, request: MintQuoteBolt11Request) -> Result<MintQuoteBolt11Response<String>, Error>;
    async fn get_mint_quote_status(&self, quote_id: &str) -> Result<MintQuoteBolt11Response<String>, Error>;

    /// Immediately pay a mint quote (only for local/direct connections)
    /// Returns an error for HTTP connections
    async fn pay_mint_quote_directly(&self, _quote_id: &str) -> Result<(), Error> {
        Err(Error::Custom("pay_mint_quote_directly is only supported for DirectMintConnection".to_string()))
    }
}

/// HTTP mint wrapper implementing MintConnection
pub struct HttpMintConnection {
    http_client: HttpClient,
}

impl HttpMintConnection {
    pub fn new(mint_url: MintUrl) -> Self {
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

// Implement the library's MintConnection trait for HttpMintConnection
#[async_trait]
impl SpilmanMintConnection for HttpMintConnection {
    async fn process_swap(&self, request: SwapRequest) -> anyhow::Result<SwapResponse> {
        Ok(self.http_client.post_swap(request).await?)
    }

    async fn post_restore(&self, request: RestoreRequest) -> anyhow::Result<RestoreResponse> {
        Ok(self.http_client.post_restore(request).await?)
    }

    async fn check_state(&self, ys: Vec<cdk::nuts::PublicKey>) -> anyhow::Result<CheckStateResponse> {
        let request = CheckStateRequest { ys };
        Ok(self.http_client.post_check_state(request).await?)
    }
}

/// Direct in-process connection to a mint (no HTTP)
#[derive(Clone)]
pub struct DirectMintConnection {
    mint: Mint,
    auth_wallet: Arc<RwLock<Option<AuthWallet>>>,
}

impl DirectMintConnection {
    pub fn new(mint: Mint) -> Self {
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

    async fn pay_mint_quote_directly(&self, quote_id: &str) -> Result<(), Error> {
        use cdk::cdk_payment::WaitPaymentResponse;
        use cdk::mint::QuoteId;

        // Get the mint quote to extract its request_lookup_id
        let quote_id_obj: QuoteId = quote_id.parse()
            .map_err(|e| Error::Custom(format!("Invalid quote ID: {}", e)))?;
        let mint_quote = self.mint.localstore()
            .get_mint_quote(&quote_id_obj)
            .await?
            .ok_or_else(|| Error::Custom(format!("Quote {} not found", quote_id)))?;

        // Construct a WaitPaymentResponse with the correct fields
        let wait_response = WaitPaymentResponse {
            payment_identifier: mint_quote.request_lookup_id.clone(),
            payment_amount: mint_quote.amount.unwrap_or(cdk::Amount::ZERO),
            unit: mint_quote.unit.clone(),
            payment_id: mint_quote.request_lookup_id.to_string(),
        };

        self.mint.pay_mint_quote_for_request_id(wait_response).await
    }
}

// Implement the library's MintConnection trait for DirectMintConnection
#[async_trait]
impl SpilmanMintConnection for DirectMintConnection {
    async fn process_swap(&self, request: SwapRequest) -> anyhow::Result<SwapResponse> {
        Ok(self.mint.process_swap_request(request).await?)
    }

    async fn post_restore(&self, request: RestoreRequest) -> anyhow::Result<RestoreResponse> {
        Ok(self.mint.restore(request).await?)
    }

    async fn check_state(&self, ys: Vec<cdk::nuts::PublicKey>) -> anyhow::Result<CheckStateResponse> {
        let request = CheckStateRequest { ys };
        Ok(self.mint.check_state(&request).await?)
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
pub async fn mint_deterministic_outputs(
    mint_connection: &dyn MintConnection,
    unit: CurrencyUnit,
    blinded_messages: Vec<cdk::nuts::BlindedMessage>,
    secrets_with_blinding: Vec<DeterministicSecretWithBlinding>,
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

    // Try to pay the quote directly (for local mints); ignore errors (for HTTP mints)
    let _ = mint_connection.pay_mint_quote_directly(&quote.quote).await;

    // Poll for quote to be paid
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
    let mut mint_request = MintRequest {
        quote: quote_id.clone(),
        outputs: blinded_messages,
        signature: None,
    };

    // Sign the mint request with NUT-20
    mint_request.sign(secret_key)?;

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
pub fn verify_mint_capabilities(mint_info: &MintInfo) -> anyhow::Result<()> {
    let nut07 = if mint_info.nuts.nut07.supported { "✓" } else { "✗" };
    let nut09 = if mint_info.nuts.nut09.supported { "✓" } else { "✗" };
    let nut11 = if mint_info.nuts.nut11.supported { "✓" } else { "✗" };
    let nut12 = if mint_info.nuts.nut12.supported { "✓" } else { "✗" };
    let nut17 = if !mint_info.nuts.nut17.supported.is_empty() { "✓" } else { "⚠" };

    println!("🔍 Mint capabilities: NUT-07:{} NUT-09:{} NUT-11:{} NUT-12:{} NUT-17:{}", nut07, nut09, nut11, nut12, nut17);

    let all_required_supported = mint_info.nuts.nut07.supported
        && mint_info.nuts.nut09.supported
        && mint_info.nuts.nut11.supported
        && mint_info.nuts.nut12.supported;

    if !all_required_supported {
        anyhow::bail!("Mint does not support all required capabilities for Spilman channels");
    }

    Ok(())
}

/// Get active keyset information for a unit
///
/// Returns KeysetInfo with keyset_id, keys, and fee information
pub async fn get_active_keyset_info(
    mint_connection: &dyn MintConnection,
    unit: &CurrencyUnit,
) -> anyhow::Result<cdk::spilman::KeysetInfo> {
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

    Ok(cdk::spilman::KeysetInfo::new(active_keyset_id, set_of_active_keys.keys.clone(), input_fee_ppk))
}

/// Setup mint and wallets for demo/testing
///
/// Creates either a local in-process mint or connects to an external mint,
/// and sets up wallets for Alice and Charlie.
///
/// Returns (mint_connection, alice_wallet, charlie_wallet, mint_url)
pub async fn setup_mint_and_wallets_for_demo(
    mint_url_opt: Option<String>, // None = create local in-process mint
    unit: CurrencyUnit,
    input_fee_ppk: u64, // Fee in parts per thousand (e.g., 400 = 40%)
) -> anyhow::Result<(Box<dyn FullMintConnection>, Wallet, Wallet, String)> {
    let (mint_connection, alice, charlie, mint_url): (Box<dyn FullMintConnection>, Wallet, Wallet, String) = if let Some(mint_url_str) = mint_url_opt {
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
        let mint = create_local_mint(unit.clone(), input_fee_ppk).await?;
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

/// Receive proofs into a wallet with P2PK signing
///
/// The wallet will automatically sign and swap the proofs to remove P2PK conditions.
/// Returns the amount received in the base unit.
/// Returns 0 if proofs are empty or worth nothing after fees.
pub async fn receive_proofs_into_wallet(
    wallet: &Wallet,
    proofs: Vec<cdk::nuts::Proof>,
    secret_key: cdk::nuts::SecretKey,
) -> anyhow::Result<u64> {
    // Handle empty proofs case (e.g., balance 0)
    if proofs.is_empty() {
        return Ok(0);
    }

    // Calculate value after fees - if it's 0 or negative, return 0 without calling wallet
    let nominal_value = proofs.total_amount()?;
    let fee = wallet.get_proofs_fee(&proofs).await?;
    if nominal_value <= fee {
        println!("   ⚠ Skipping receive: proofs worth 0 after fees (nominal: {}, fee: {})", nominal_value, fee);
        return Ok(0);
    }

    let receive_opts = cdk::wallet::ReceiveOptions {
        amount_split_target: cdk::amount::SplitTarget::default(),
        p2pk_signing_keys: vec![secret_key],
        preimages: vec![],
        metadata: std::collections::HashMap::new(),
    };

    let received_amount = wallet.receive_proofs(proofs, receive_opts, None).await?;
    Ok(u64::from(received_amount))
}

/// Create and mint funding proofs for a channel
///
/// Creates deterministic funding outputs and mints them using NUT-20 authentication.
/// Returns the minted funding proofs.
pub async fn create_funding_proofs(
    mint_connection: &dyn MintConnection,
    channel_params: &cdk::spilman::ChannelParameters,
    funding_token_nominal: u64,
) -> anyhow::Result<Vec<cdk::nuts::Proof>> {
    let funding_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        funding_token_nominal,
        channel_params.clone(),
    )?;

    let funding_blinded_messages = funding_outputs.get_blinded_messages()?;
    let funding_secrets_with_blinding = funding_outputs.get_secrets_with_blinding()?;

    let funding_proofs = mint_deterministic_outputs(
        mint_connection,
        channel_params.unit.clone(),
        funding_blinded_messages,
        funding_secrets_with_blinding,
        &channel_params.keyset_info.active_keys,
    ).await?;

    Ok(funding_proofs)
}

/// Unblind swap signatures to create stage 1 proofs for both parties
///
/// Creates commitment outputs for the given balance and unblinds the signatures
/// to create proofs for both the receiver (Charlie) and sender (Alice) after stage 1.
///
/// Returns (receiver_stage1_proofs, sender_stage1_proofs)
pub fn unblind_commitment_proofs(
    channel_params: &cdk::spilman::ChannelParameters,
    balance: u64,
    signatures: Vec<cdk::nuts::BlindSignature>,
) -> anyhow::Result<(Vec<cdk::nuts::Proof>, Vec<cdk::nuts::Proof>)> {
    // Create commitment outputs to get the secrets for unblinding
    let commitment_outputs = cdk::spilman::CommitmentOutputs::for_balance(balance, channel_params)?;

    // Unblind the signatures to get the commitment proofs
    let all_proofs = commitment_outputs.unblind_all(
        signatures,
        &channel_params.keyset_info.active_keys,
    )?;

    // Split proofs by ownership (receiver vs sender)
    let receiver_stage1_proofs: Vec<_> = all_proofs.iter()
        .filter(|p| p.is_receiver)
        .map(|p| p.proof.clone())
        .collect();
    let sender_stage1_proofs: Vec<_> = all_proofs.iter()
        .filter(|p| !p.is_receiver)
        .map(|p| p.proof.clone())
        .collect();

    Ok((receiver_stage1_proofs, sender_stage1_proofs))
}

/// Receive proofs into both wallets (stage 2 - removes P2PK conditions)
///
/// Takes stage 1 proofs for both parties and receives them into their respective wallets.
/// Each wallet will sign and swap the proofs to remove the P2PK conditions.
///
/// Returns (receiver_received_amount, sender_received_amount)
pub async fn receive_proofs_into_both_wallets(
    receiver_wallet: &cdk::wallet::Wallet,
    receiver_proofs: Vec<cdk::nuts::Proof>,
    receiver_secret: cdk::nuts::SecretKey,
    sender_wallet: &cdk::wallet::Wallet,
    sender_proofs: Vec<cdk::nuts::Proof>,
    sender_secret: cdk::nuts::SecretKey,
) -> anyhow::Result<(u64, u64)> {
    let receiver_amount = receive_proofs_into_wallet(receiver_wallet, receiver_proofs, receiver_secret).await?;
    let sender_amount = receive_proofs_into_wallet(sender_wallet, sender_proofs, sender_secret).await?;
    Ok((receiver_amount, sender_amount))
}
