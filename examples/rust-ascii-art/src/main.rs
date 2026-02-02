//! ASCII Art Server - Pay per character using Spilman payment channels.
//!
//! Demonstrates Spilman payment channels in Rust using Axum.
//!
//! Endpoints:
//!   GET  /channel/params              - Get server pubkey and pricing info
//!   POST /channel/register            - Pre-register a channel (balance=0, no usage)
//!   POST /ascii                       - Generate ASCII art (requires X-Cashu-Channel header)
//!   GET  /channel/:id/status          - Get channel status and amount_due
//!   POST /channel/:id/close           - Close channel cooperatively (client-initiated)
//!   POST /channel/:id/unilateral-close - Close channel unilaterally (server-initiated)

mod host;
mod routes;
mod stores;

use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use cdk::nuts::SecretKey;
use cdk::spilman::SpilmanBridge;

use host::AsciiArtHost;
use routes::{create_router, AppStateInner};
use stores::{Stores, UnitPricing};

// ============================================================================
// Configuration
// ============================================================================

/// Default secret key for development (same pattern as TS/Python/Go servers)
const DEFAULT_SECRET_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Default mint URL
const DEFAULT_MINT_URL: &str = "http://localhost:3338";

/// Default port
const DEFAULT_PORT: u16 = 5003;

/// Minimum channel expiry in seconds
const MIN_EXPIRY_SECONDS: u64 = 3600;

// ============================================================================
// Main Entry Point
// ============================================================================

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,cdk_ascii_art=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    println!("{}", "=".repeat(60));
    println!("ASCII Art Server - Spilman Payment Channel Demo (Rust)");
    println!("{}", "=".repeat(60));
    println!();

    // Read config from environment
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let mint_url = env::var("MINT_URL").unwrap_or_else(|_| DEFAULT_MINT_URL.to_string());

    let secret_key_hex =
        env::var("SERVER_SECRET_KEY").unwrap_or_else(|_| DEFAULT_SECRET_KEY.to_string());

    // Parse secret key and derive public key
    let secret_key = SecretKey::from_hex(&secret_key_hex).expect("Invalid secret key hex");
    let server_pubkey = secret_key.public_key();

    // Initialize stores
    let stores = Arc::new(Stores::new());

    // Configure pricing (matching other servers)
    let pricing: HashMap<String, UnitPricing> = [
        (
            "sat".to_string(),
            UnitPricing {
                per_char: 1,
                min_capacity: 10,
            },
        ),
        (
            "msat".to_string(),
            UnitPricing {
                per_char: 1000,
                min_capacity: 10000,
            },
        ),
        (
            "usd".to_string(),
            UnitPricing {
                per_char: 1,
                min_capacity: 10,
            },
        ),
    ]
    .into_iter()
    .collect();

    // Create host
    let host = Arc::new(AsciiArtHost::new(
        stores.clone(),
        &mint_url,
        server_pubkey,
        pricing.clone(),
        MIN_EXPIRY_SECONDS,
    ));

    // Fetch keysets from mint at startup
    println!("Fetching keysets from {}...", mint_url);
    if let Err(e) = host.fetch_keysets_async().await {
        eprintln!("WARNING: Failed to fetch keysets: {}", e);
        eprintln!("Payment validation may fail for new channels");
    } else {
        println!("Cached keysets for {}", mint_url);
    }
    println!();

    // Create bridge
    let bridge = SpilmanBridge::new((*host).clone(), Some(secret_key));

    // Load figlet font
    let figlet_font = figlet_rs::FIGfont::standard().expect("Failed to load figlet font");

    // Create app state
    let state = Arc::new(AppStateInner {
        bridge,
        host: host.clone(),
        stores: stores.clone(),
        pricing: pricing.clone(),
        figlet_font,
    });

    // Create router
    let app = create_router(state);

    // Start server
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await.expect("Failed to bind to address");

    println!("Server pubkey: {}", server_pubkey.to_hex());
    println!("Mint URL:      {}", mint_url);

    let active_units = stores.get_active_units();
    let pricing_str: String = pricing
        .iter()
        .filter(|(unit, _)| active_units.contains(*unit))
        .map(|(u, p)| format!("{}={}/char", u, p.per_char))
        .collect::<Vec<_>>()
        .join(", ");
    println!(
        "Pricing:       {}",
        if pricing_str.is_empty() {
            "(no active units)".to_string()
        } else {
            pricing_str
        }
    );
    println!("Listening on:  http://{}", addr);
    println!();
    println!("Endpoints:");
    println!("  GET  http://localhost:{}/channel/params", port);
    println!("  POST http://localhost:{}/channel/register", port);
    println!("  POST http://localhost:{}/ascii", port);
    println!("  GET  http://localhost:{}/channel/:id/status", port);
    println!("  POST http://localhost:{}/channel/:id/close", port);
    println!("  POST http://localhost:{}/channel/:id/unilateral-close", port);
    println!();
    println!("{}", "=".repeat(60));
    println!();

    tracing::info!("Rust ASCII Art server listening on {}", addr);

    axum::serve(listener, app)
        .await
        .expect("Server failed to start");
}
