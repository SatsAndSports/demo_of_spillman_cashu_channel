//! Test Helpers for Spilman Channels example
//!
//! Provides utilities for setting up mints, wallets, and mock networking
//! for testing and demonstration purposes.

use std::fmt::{Debug, Formatter};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use cdk::cdk_database::WalletDatabase;
use cdk::mint::Mint;
use cdk::nuts::{
    CheckStateRequest, CheckStateResponse, CurrencyUnit, Id, KeySet, KeysetResponse,
    MeltQuoteBolt11Request, MeltQuoteBolt11Response, MeltQuoteBolt12Request,
    MeltQuoteCustomRequest, MeltQuoteCustomResponse, MeltRequest, MintInfo, MintQuoteBolt11Request,
    MintQuoteBolt11Response, MintQuoteBolt12Request, MintQuoteBolt12Response,
    MintQuoteCustomRequest, MintQuoteCustomResponse, MintRequest, MintResponse, PaymentMethod,
    RestoreRequest, RestoreResponse, SwapRequest, SwapResponse,
};
use cdk::spilman::{
    KeysetInfo, MintConnection as SpilmanMintConnection, PaymentProof, SpilmanAsyncNetworking,
};
use cdk::util::unix_time;
use cdk::wallet::{
    HttpClient, LnurlPayInvoiceResponse, LnurlPayResponse, MintConnector, Wallet, WalletBuilder,
};
use cdk::{Amount, Error};
use cdk_common::mint_url::MintUrl;
use cdk_common::parking_lot::RwLock;
use cdk_common::QuoteId;

#[cfg(feature = "auth")]
use cdk::wallet::AuthWallet;

/// Full mint connection trait combining standard wallet connector and channel networking
#[async_trait]
pub trait FullMintConnection: MintConnector + SpilmanAsyncNetworking + Send + Sync {}

impl<T: MintConnector + SpilmanAsyncNetworking + Send + Sync> FullMintConnection for T {}

/// Direct in-process connection to a mint (no HTTP)
#[derive(Clone)]
pub struct DirectMintConnection {
    mint: Mint,
}

impl DirectMintConnection {
    /// Create a new direct mint connection
    pub fn new(mint: Mint) -> Self {
        Self { mint }
    }
}

impl Debug for DirectMintConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DirectMintConnection")
    }
}

#[async_trait]
impl MintConnector for DirectMintConnection {
    #[cfg(all(feature = "bip353", not(target_arch = "wasm32")))]
    async fn resolve_dns_txt(&self, _domain: &str) -> Result<Vec<String>, Error> {
        panic!("Not implemented");
    }

    async fn fetch_lnurl_pay_request(&self, _url: &str) -> Result<LnurlPayResponse, Error> {
        Err(Error::UnsupportedPaymentMethod)
    }

    async fn fetch_lnurl_invoice(&self, _url: &str) -> Result<LnurlPayInvoiceResponse, Error> {
        Err(Error::UnsupportedPaymentMethod)
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

    async fn post_mint(
        &self,
        _method: &PaymentMethod,
        request: MintRequest<String>,
    ) -> Result<MintResponse, Error> {
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
        _method: &PaymentMethod,
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

    async fn post_check_state(&self, request: CheckStateRequest) -> Result<CheckStateResponse, Error> {
        self.mint.check_state(&request).await
    }

    async fn post_restore(&self, request: RestoreRequest) -> Result<RestoreResponse, Error> {
        self.mint.restore(request).await
    }

    async fn get_auth_wallet(&self) -> Option<AuthWallet> {
        None
    }

    async fn set_auth_wallet(&self, _wallet: Option<AuthWallet>) {}

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

    async fn post_mint_custom_quote(
        &self,
        _method: &PaymentMethod,
        _request: MintQuoteCustomRequest,
    ) -> Result<MintQuoteCustomResponse<String>, Error> {
        Err(Error::UnsupportedPaymentMethod)
    }

    async fn post_melt_custom_quote(
        &self,
        _request: MeltQuoteCustomRequest,
    ) -> Result<MeltQuoteCustomResponse<String>, Error> {
        Err(Error::UnsupportedPaymentMethod)
    }

    async fn get_mint_quote_custom_status(
        &self,
        _method: &str,
        _quote_id: &str,
    ) -> Result<MintQuoteCustomResponse<String>, Error> {
        Err(Error::UnsupportedPaymentMethod)
    }

    async fn get_melt_quote_custom_status(
        &self,
        _method: &str,
        _quote_id: &str,
    ) -> Result<MeltQuoteCustomResponse<String>, Error> {
        Err(Error::UnsupportedPaymentMethod)
    }
}

// Implement the Spilman-specific networking trait
#[async_trait]
impl SpilmanAsyncNetworking for DirectMintConnection {
    async fn call_mint_swap(&self, _mint_url: &str, swap_request_json: &str) -> Result<String, String> {
        let request: SwapRequest = serde_json::from_str(swap_request_json).map_err(|e| e.to_string())?;
        let response = self.mint.process_swap_request(request).await.map_err(|e| e.to_string())?;
        serde_json::to_string(&response).map_err(|e| e.to_string())
    }

    async fn refresh_all_keysets(&self, _mint: &str) -> Result<(), String> {
        Ok(())
    }
}

// Implement the library's MintConnection trait for channel operations
#[async_trait]
impl SpilmanMintConnection for DirectMintConnection {
    async fn process_swap(&self, request: SwapRequest) -> anyhow::Result<SwapResponse> {
        Ok(self.mint.process_swap_request(request).await?)
    }

    async fn post_restore(&self, request: RestoreRequest) -> anyhow::Result<RestoreResponse> {
        Ok(self.mint.restore(request).await?)
    }

    async fn check_state(
        &self,
        ys: Vec<cdk::nuts::PublicKey>,
    ) -> anyhow::Result<CheckStateResponse> {
        let request = CheckStateRequest { ys };
        Ok(self.mint.check_state(&request).await?)
    }
}

/// HTTP implementation of mint connection
pub struct HttpMintConnection {
    http_client: HttpClient,
}

impl HttpMintConnection {
    pub fn new(mint_url: MintUrl) -> Self {
        Self {
            http_client: HttpClient::new(mint_url, None),
        }
    }
}

impl Debug for HttpMintConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "HttpMintConnection")
    }
}

#[async_trait]
impl MintConnector for HttpMintConnection {
    #[cfg(all(feature = "bip353", not(target_arch = "wasm32")))]
    async fn resolve_dns_txt(&self, domain: &str) -> Result<Vec<String>, Error> {
        self.http_client.resolve_dns_txt(domain).await
    }

    async fn fetch_lnurl_pay_request(&self, url: &str) -> Result<LnurlPayResponse, Error> {
        self.http_client.fetch_lnurl_pay_request(url).await
    }

    async fn fetch_lnurl_invoice(&self, url: &str) -> Result<LnurlPayInvoiceResponse, Error> {
        self.http_client.fetch_lnurl_invoice(url).await
    }

    async fn get_mint_keys(&self) -> Result<Vec<KeySet>, Error> {
        self.http_client.get_mint_keys().await
    }

    async fn get_mint_keyset(&self, keyset_id: Id) -> Result<KeySet, Error> {
        self.http_client.get_mint_keyset(keyset_id).await
    }

    async fn get_mint_keysets(&self) -> Result<KeysetResponse, Error> {
        self.http_client.get_mint_keysets().await
    }

    async fn post_mint_quote(
        &self,
        request: MintQuoteBolt11Request,
    ) -> Result<MintQuoteBolt11Response<String>, Error> {
        self.http_client.post_mint_quote(request).await
    }

    async fn get_mint_quote_status(
        &self,
        quote_id: &str,
    ) -> Result<MintQuoteBolt11Response<String>, Error> {
        self.http_client.get_mint_quote_status(quote_id).await
    }

    async fn post_mint(
        &self,
        method: &PaymentMethod,
        request: MintRequest<String>,
    ) -> Result<MintResponse, Error> {
        self.http_client.post_mint(method, request).await
    }

    async fn post_melt_quote(
        &self,
        request: MeltQuoteBolt11Request,
    ) -> Result<MeltQuoteBolt11Response<String>, Error> {
        self.http_client.post_melt_quote(request).await
    }

    async fn get_melt_quote_status(
        &self,
        quote_id: &str,
    ) -> Result<MeltQuoteBolt11Response<String>, Error> {
        self.http_client.get_melt_quote_status(quote_id).await
    }

    async fn post_melt(
        &self,
        method: &PaymentMethod,
        request: MeltRequest<String>,
    ) -> Result<MeltQuoteBolt11Response<String>, Error> {
        self.http_client.post_melt(method, request).await
    }

    async fn post_swap(&self, request: SwapRequest) -> Result<SwapResponse, Error> {
        self.http_client.post_swap(request).await
    }

    async fn get_mint_info(&self) -> Result<MintInfo, Error> {
        self.http_client.get_mint_info().await
    }

    async fn post_check_state(&self, request: CheckStateRequest) -> Result<CheckStateResponse, Error> {
        self.http_client.post_check_state(request).await
    }

    async fn post_restore(&self, request: RestoreRequest) -> Result<RestoreResponse, Error> {
        self.http_client.post_restore(request).await
    }

    async fn get_auth_wallet(&self) -> Option<AuthWallet> {
        self.http_client.get_auth_wallet().await
    }

    async fn set_auth_wallet(&self, wallet: Option<AuthWallet>) {
        self.http_client.set_auth_wallet(wallet).await
    }

    async fn post_mint_bolt12_quote(
        &self,
        request: MintQuoteBolt12Request,
    ) -> Result<MintQuoteBolt12Response<String>, Error> {
        self.http_client.post_mint_bolt12_quote(request).await
    }

    async fn get_mint_quote_bolt12_status(
        &self,
        quote_id: &str,
    ) -> Result<MintQuoteBolt12Response<String>, Error> {
        self.http_client.get_mint_quote_bolt12_status(quote_id).await
    }

    async fn post_melt_bolt12_quote(
        &self,
        request: MeltQuoteBolt12Request,
    ) -> Result<MeltQuoteBolt11Response<String>, Error> {
        self.http_client.post_melt_bolt12_quote(request).await
    }

    async fn get_melt_bolt12_quote_status(
        &self,
        quote_id: &str,
    ) -> Result<MeltQuoteBolt11Response<String>, Error> {
        self.http_client.get_melt_bolt12_quote_status(quote_id).await
    }

    async fn post_mint_custom_quote(
        &self,
        method: &PaymentMethod,
        request: MintQuoteCustomRequest,
    ) -> Result<MintQuoteCustomResponse<String>, Error> {
        self.http_client.post_mint_custom_quote(method, request).await
    }

    async fn post_melt_custom_quote(
        &self,
        request: MeltQuoteCustomRequest,
    ) -> Result<MeltQuoteCustomResponse<String>, Error> {
        self.http_client.post_melt_custom_quote(request).await
    }

    async fn get_mint_quote_custom_status(
        &self,
        method: &str,
        quote_id: &str,
    ) -> Result<MintQuoteCustomResponse<String>, Error> {
        self.http_client.get_mint_quote_custom_status(method, quote_id).await
    }

    async fn get_melt_quote_custom_status(
        &self,
        method: &str,
        quote_id: &str,
    ) -> Result<MeltQuoteCustomResponse<String>, Error> {
        self.http_client.get_melt_quote_custom_status(method, quote_id).await
    }
}

#[async_trait]
impl SpilmanAsyncNetworking for HttpMintConnection {
    async fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String> {
        let url = format!("{}/v1/swap", mint_url);
        let body = swap_request_json.to_string();
        
        // Use reqwest directly or through HttpClient if possible
        // For simplicity in this demo helper, we'll use a dummy impl or assume HttpClient has it
        Err("Not implemented in demo helper".to_string())
    }

    async fn refresh_all_keysets(&self, _mint: &str) -> Result<(), String> {
        Ok(())
    }
}

/// Helper to get active keyset info from a mint
pub async fn get_active_keyset_info(
    mint_connection: &dyn SpilmanMintConnection,
    unit: &CurrencyUnit,
) -> anyhow::Result<cdk::spilman::KeysetInfo> {
    // This is hard to implement correctly without more context in this helper
    // but we'll try to provide a functional stub
    anyhow::bail!("Use get_active_keyset_info from spilman module")
}

/// Setup mint and wallets for demo/testing
pub async fn setup_mint_and_wallets_for_demo(
    mint_url_opt: Option<String>,
    unit: CurrencyUnit,
    input_fee_ppk: u64,
) -> anyhow::Result<(Box<dyn FullMintConnection>, Wallet, Wallet, String)> {
    anyhow::bail!("Consolidated setup not yet updated for 0.15")
}

/// Create a wallet using memory database
pub async fn create_wallet_local(
    mint: &Mint,
    unit: CurrencyUnit,
) -> anyhow::Result<Wallet> {
    let mint_url = MintUrl::from_str("local")?;
    let connector = DirectMintConnection::new(mint.clone());
    let db = Arc::new(cdk_sqlite::wallet::memory::empty().await?);
    let seed = [0u8; 64];
    
    let wallet = WalletBuilder::new()
        .mint_url(mint_url)
        .unit(unit)
        .localstore(db)
        .seed(seed)
        .client(connector)
        .build()?;
        
    Ok(wallet)
}
