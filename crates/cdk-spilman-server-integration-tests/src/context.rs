//! Test context and fixtures for integration tests.
//!
//! Provides a `TestContext` that holds the test environment (mint + server)
//! and provides convenient access to helpers.
//!
//! # Parallel Test Execution
//!
//! Tests run in parallel by default. To ensure only ONE mint and ONE server
//! are spawned (even when 50+ tests start simultaneously), we use `tokio::sync::OnceCell`.
//!
//! The `OnceCell::get_or_try_init()` method guarantees that:
//! - The initialization closure runs exactly once
//! - All concurrent callers wait for initialization to complete
//! - All callers receive a reference to the same `TestEnvironment`
//!
//! This means the first test to call `TestContext::new()` spawns the mint and server,
//! while all other tests wait and then share that same infrastructure.

use anyhow::Result;
use tokio::sync::OnceCell;

use crate::helpers::{
    mint_funded_channel, Channel, HttpClient, MintFundedChannelOptions, ServerChannelParams,
};
use crate::orchestration::{ServerType, TestEnvironment};

/// Global test environment - shared across ALL tests running in parallel.
///
/// Uses `tokio::sync::OnceCell` to ensure thread-safe lazy initialization:
/// - First caller initializes (spawns mint + server)
/// - All other callers wait and receive the same instance
/// - No duplicate processes, no race conditions
static TEST_ENV: OnceCell<TestEnvironment> = OnceCell::const_new();

/// Test context providing access to server and helpers.
///
/// Each test creates its own `TestContext`, but they all share the same
/// underlying `TestEnvironment` (mint + server processes).
pub struct TestContext {
    pub client: HttpClient,
    pub server_params: ServerChannelParams,
    pub server_type: ServerType,
}

impl TestContext {
    /// Create a new test context, initializing the global environment if needed.
    ///
    /// Safe to call from multiple tests in parallel - only one environment
    /// will be created, and all tests will share it.
    pub async fn new() -> Result<Self> {
        let env = get_or_init_environment().await?;

        let client = HttpClient::new(env.server.base_url.clone(), env.mint.url.clone());

        let server_params = client.fetch_channel_params().await?;

        Ok(Self {
            client,
            server_params,
            server_type: env.server.server_type,
        })
    }

    /// Get the mint URL
    pub fn mint_url(&self) -> &str {
        &self.client.mint_url
    }

    /// Get the server base URL
    pub fn server_url(&self) -> &str {
        &self.client.base_url
    }

    /// Get price per character for a unit
    pub fn get_price_per_char(&self, unit: &str) -> u64 {
        self.server_params
            .pricing
            .get(unit)
            .map(|p| p.per_char)
            .unwrap_or(1)
    }

    /// Get minimum capacity for a unit
    pub fn get_min_capacity(&self, unit: &str) -> u64 {
        self.server_params
            .pricing
            .get(unit)
            .map(|p| p.min_capacity)
            .unwrap_or(10)
    }

    /// Calculate amount due for characters served
    pub fn get_amount_due(&self, chars_served: u64, unit: &str) -> u64 {
        chars_served * self.get_price_per_char(unit)
    }

    /// Mint a funded channel with default options
    pub async fn mint_channel(&self, unit: &str, capacity: u64) -> Result<Channel> {
        mint_funded_channel(
            &self.client,
            &self.server_params,
            unit,
            capacity,
            MintFundedChannelOptions::default(),
        )
        .await
    }

    /// Mint a funded channel with custom options
    pub async fn mint_channel_with_options(
        &self,
        unit: &str,
        capacity: u64,
        options: MintFundedChannelOptions,
    ) -> Result<Channel> {
        mint_funded_channel(&self.client, &self.server_params, unit, capacity, options).await
    }
}

/// Get or initialize the global test environment.
///
/// Thread-safe: uses `OnceCell::get_or_try_init()` which guarantees that
/// the initialization closure runs exactly once, even when called concurrently
/// from multiple test threads.
async fn get_or_init_environment() -> Result<&'static TestEnvironment> {
    TEST_ENV
        .get_or_try_init(|| async {
            let server_type = ServerType::from_env()?;
            tracing::info!(
                "Initializing test environment for {} server",
                server_type.name()
            );
            TestEnvironment::new(server_type).await
        })
        .await
}

/// Macro to create a test with TestContext
#[macro_export]
macro_rules! test_with_context {
    ($name:ident, $body:expr) => {
        #[tokio::test]
        async fn $name() -> anyhow::Result<()> {
            let ctx = $crate::context::TestContext::new().await?;
            $body(ctx).await
        }
    };
}
