//! Test helpers for Spilman channel examples and tests

use cdk::nuts::CurrencyUnit;
use cdk::wallet::Wallet;
use cdk_common::mint_url::MintUrl;

use super::{
    MintConnection, HttpMintConnection, DirectMintConnection,
    create_wallet_http, create_wallet_local, create_local_mint, verify_mint_capabilities,
};

/// Setup mint and wallets for demo/testing
///
/// Creates either a local in-process mint or connects to an external mint,
/// and sets up wallets for Alice and Charlie.
///
/// Returns (mint_connection, alice_wallet, charlie_wallet, mint_url)
pub async fn setup_mint_and_wallets_for_demo(
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
