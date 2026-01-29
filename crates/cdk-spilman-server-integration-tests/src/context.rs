//! Test context and fixtures for integration tests.
//!
//! Provides a `TestContext` that holds the test environment (mint + server)
//! and provides convenient access to helpers.

use anyhow::Result;
use once_cell::sync::OnceCell;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::helpers::{
    mint_funded_channel, Channel, HttpClient, MintFundedChannelOptions, ServerChannelParams,
};
use crate::orchestration::{ServerType, TestEnvironment};

/// Global test environment - shared across all tests
static TEST_ENV: OnceCell<Arc<Mutex<TestEnvironment>>> = OnceCell::new();

/// Test context providing access to server and helpers
pub struct TestContext {
    pub client: HttpClient,
    pub server_params: ServerChannelParams,
    pub server_type: ServerType,
}

impl TestContext {
    /// Create a new test context, initializing the global environment if needed
    pub async fn new() -> Result<Self> {
        // Get or initialize the test environment
        let env = get_or_init_environment().await?;
        let env_guard = env.lock().await;

        let client = HttpClient::new(
            env_guard.server.base_url.clone(),
            env_guard.mint.url.clone(),
        );

        let server_params = client.fetch_channel_params().await?;

        Ok(Self {
            client,
            server_params,
            server_type: env_guard.server.server_type,
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

/// Get or initialize the global test environment
async fn get_or_init_environment() -> Result<Arc<Mutex<TestEnvironment>>> {
    // Check if already initialized
    if let Some(env) = TEST_ENV.get() {
        return Ok(env.clone());
    }

    // Initialize new environment
    let server_type = ServerType::from_env()?;
    tracing::info!("Initializing test environment for {} server", server_type.name());

    let env = TestEnvironment::new(server_type).await?;
    let env = Arc::new(Mutex::new(env));

    // Store in global
    let _ = TEST_ENV.set(env.clone());

    Ok(env)
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
