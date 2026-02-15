//! Configurable SpilmanHost
//!
//! A generic, YAML-configurable implementation of [`SpilmanHost`] that tracks
//! usage via named **usage variables** — monotonically increasing integer
//! counters (e.g. `"requests"`, `"bytes"`, `"chars"`).
//!
//! The amount due for a channel is computed as a **linear combination**:
//!
//! ```text
//! amount_due = sum_over_var(accumulated[var] * price_per_unit[var])
//! ```
//!
//! The context JSON passed to [`SpilmanHost::get_amount_due`] and
//! [`SpilmanHost::record_payment`] contains the increments for each variable,
//! using the same keys:
//!
//! ```json
//! { "requests": 1, "bytes": 4096 }
//! ```
//!
//! # Example YAML configuration
//!
//! ```yaml
//! mints:
//!   "http://localhost:3338": [sat, msat, usd]
//! min_expiry_seconds: 3600
//!
//! pricing:
//!   sat:
//!     min_capacity: 10
//!     variables:
//!       chars: 1
//!       requests: 5
//!   msat:
//!     min_capacity: 10000
//!     variables:
//!       chars: 1000
//!       requests: 5000
//!   usd:
//!     min_capacity: 10
//!     max_amount_per_output: 64
//!     variables:
//!       chars: 1
//!       requests: 5
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::nuts::{CurrencyUnit, Id, PublicKey, SecretKey};
use crate::spilman::{
    ChannelFunding, ChannelId, ChannelPolicy, ChannelState, ClosingData, PaymentProof, SpilmanHost,
};

// ============================================================================
// Configuration types
// ============================================================================

/// Per-unit pricing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitPricingConfig {
    /// Minimum channel capacity required for this unit.
    pub min_capacity: u64,

    /// Optional maximum amount per blinded output (for testing maximum_amount policy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount_per_output: Option<u64>,

    /// Mapping from usage variable name to price-per-unit.
    ///
    /// For example: `{ "chars": 1, "requests": 5 }` means 1 sat per char
    /// and 5 sat per request.
    pub variables: HashMap<String, u64>,
}

/// Top-level YAML configuration for [`ConfigurableHost`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurableHostConfig {
    /// Trusted mints, mapping each mint URL to the set of units trusted at
    /// that mint (e.g. `{ "http://localhost:3338": ["sat", "msat"] }`).
    pub mints: HashMap<String, Vec<String>>,

    /// Minimum channel expiry in seconds.
    #[serde(default = "default_min_expiry")]
    pub min_expiry_seconds: u64,

    /// Per-unit pricing. Keys are unit names (`"sat"`, `"msat"`, `"usd"`, …).
    pub pricing: HashMap<String, UnitPricingConfig>,
}

fn default_min_expiry() -> u64 {
    3600
}

impl ConfigurableHostConfig {
    /// Parse a [`ConfigurableHostConfig`] from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        serde_yml::from_str(yaml).map_err(|e| format!("YAML parse error: {e}"))
    }
}

// ============================================================================
// In-memory stores
// ============================================================================

/// Per-channel accumulated usage: `variable_name -> value`.
pub type UsageMap = HashMap<String, u64>;

/// Cached keyset entry.
#[derive(Clone)]
pub struct KeysetCacheEntry {
    pub info_json: String,
    pub active: bool,
    pub unit: CurrencyUnit,
}

/// Thread-safe in-memory stores.
struct Stores {
    /// Immutable channel founding data (params, funding proofs, shared secret, keyset info).
    /// Written once by `save_funding()`; read by payment validation and pricing lookups.
    /// Keyed by channel ID.
    funding: RwLock<HashMap<ChannelId, ChannelFunding>>,

    /// Highest balance the client has signed over, plus the Schnorr signature proving it.
    /// Monotonically increasing — lower values never overwrite higher ones. This is the
    /// server's proof-of-debt for unilateral close. Keyed by channel ID.
    balance: RwLock<HashMap<ChannelId, PaymentProof>>,

    /// Accumulated per-channel resource consumption counters (e.g. {"chars": 150, "requests": 3}).
    /// Fed into `compute_amount_due()` which applies linear pricing to determine the total owed.
    /// Keyed by channel ID.
    usage: RwLock<HashMap<ChannelId, UsageMap>>,

    /// Transient state for channels that have initiated closing but not yet completed the
    /// mint swap — the intermediate step between Open and Closed. Payments are no longer
    /// accepted by the server. Removed once the channel is fully closed. Keyed by channel ID.
    /// The server and client may agree a cooperative close at any balance between 0 and 'capacity'
    /// inclusive; this allows a refund if the client has been overpaying.
    closing: RwLock<HashMap<ChannelId, ClosingData>>,

    /// Permanent final settlement records: proof distribution between sender and receiver,
    /// balances, and locktime. Enables idempotent close responses and prevents double-closes.
    /// Keyed by channel ID.
    closed: RwLock<HashMap<ChannelId, ClosedDataView>>,

    /// Cached mint keyset metadata for validating channel funding and advertising accepted
    /// currency units. Keyed by `(mint_url, keyset_id)`.
    /// The server operator is NOT required to keep the keyset information up-to-date; the
    /// bridge will explicitly request — via the host's `networking.refresh_all_keysets()` — to
    /// update the set of (active) keysets if a swap fails due to an inactive keyset.
    keysets: RwLock<HashMap<(String, Id), KeysetCacheEntry>>,
}

impl Stores {
    fn new() -> Self {
        Self {
            funding: RwLock::new(HashMap::new()),
            balance: RwLock::new(HashMap::new()),
            usage: RwLock::new(HashMap::new()),
            closing: RwLock::new(HashMap::new()),
            closed: RwLock::new(HashMap::new()),
            keysets: RwLock::new(HashMap::new()),
        }
    }

    // -- keyset helpers --

    fn get_keyset(&self, mint: &str, keyset_id: &Id) -> Option<KeysetCacheEntry> {
        let key = (mint.to_string(), *keyset_id);
        self.keysets
            .read()
            .expect("keysets lock poisoned")
            .get(&key)
            .cloned()
    }

    fn set_keyset(&self, mint: &str, keyset_id: Id, entry: KeysetCacheEntry) {
        self.keysets
            .write()
            .expect("keysets lock poisoned")
            .insert((mint.to_string(), keyset_id), entry);
    }

    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id> {
        // There is no requirement that this be 'up-to-date'. So this is
        // the set of keysets were active the last time the server updated
        // its records of the keysets
        self.keysets
            .read()
            .expect("keysets lock poisoned")
            .iter()
            .filter(|((m, _), entry)| m == mint && entry.unit == *unit && entry.active)
            .map(|((_, kid), _)| *kid)
            .collect()
    }

    /// Returns `{ mint_url: { unit: [keyset_id, …] } }` for all active keysets.
    fn get_mints_units_keysets(&self) -> HashMap<String, HashMap<String, Vec<String>>> {
        let mut result: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
        let store = self.keysets.read().expect("keysets lock poisoned");
        for ((mint, keyset_id), entry) in store.iter() {
            if !entry.active {
                continue;
            }
            result
                .entry(mint.clone())
                .or_default()
                .entry(entry.unit.to_string())
                .or_default()
                .push(keyset_id.to_string());
        }
        result
    }

    /// Returns the set of units that have at least one active keyset.
    fn get_active_units(&self) -> std::collections::HashSet<String> {
        self.keysets
            .read()
            .expect("keysets lock poisoned")
            .values()
            .filter(|e| e.active)
            .map(|e| e.unit.to_string())
            .collect()
    }
}

// ============================================================================
// ConfigurableHost
// ============================================================================

/// A generic, YAML-configurable [`SpilmanHost`] implementation.
///
/// Tracks usage via named usage variables and computes pricing as a linear
/// combination.  Storage is in-memory (`RwLock<HashMap>`).
///
/// `Clone` is cheap (stores are behind `Arc`), which allows passing the host
/// by value to [`SpilmanBridge::new`] while sharing state with route handlers.
///
/// Construct via [`ConfigurableHost::new`] or [`ConfigurableHost::from_yaml`].
#[derive(Clone)]
pub struct ConfigurableHost {
    config: ConfigurableHostConfig,
    server_pubkey: PublicKey,
    server_secret_hex: String,
    stores: Arc<Stores>,
}

impl ConfigurableHost {
    /// Create a new host from an already-parsed config and a hex-encoded
    /// secret key.
    pub fn new(config: ConfigurableHostConfig, secret_key_hex: &str) -> Result<Self, String> {
        let secret_key =
            SecretKey::from_hex(secret_key_hex).map_err(|e| format!("invalid secret key: {e}"))?;
        let server_pubkey = secret_key.public_key();

        // Validate: every unit trusted by at least one mint must have pricing.
        let trusted_units: std::collections::HashSet<&str> = config
            .mints
            .values()
            .flat_map(|units| units.iter().map(String::as_str))
            .collect();
        let priced_units: std::collections::HashSet<&str> =
            config.pricing.keys().map(String::as_str).collect();

        let mut missing: Vec<&str> = trusted_units.difference(&priced_units).copied().collect();
        if !missing.is_empty() {
            missing.sort();
            return Err(format!(
                "units trusted by at least one mint but missing from pricing: {missing:?}"
            ));
        }

        // Warn: pricing entries that no mint trusts are dead config.
        let mut unused: Vec<&str> = priced_units.difference(&trusted_units).copied().collect();
        if !unused.is_empty() {
            unused.sort();
            tracing::warn!("pricing defined for units not trusted by any mint: {unused:?}");
        }

        Ok(Self {
            config,
            server_pubkey,
            server_secret_hex: secret_key_hex.to_string(),
            stores: Arc::new(Stores::new()),
        })
    }

    /// Parse YAML and construct the host.
    pub fn from_yaml(yaml: &str, secret_key_hex: &str) -> Result<Self, String> {
        let config = ConfigurableHostConfig::from_yaml(yaml)?;
        Self::new(config, secret_key_hex)
    }

    // -- public accessors -----------------------------------------------------

    /// The server's public key.
    pub fn server_pubkey(&self) -> &PublicKey {
        &self.server_pubkey
    }

    /// The parsed configuration.
    pub fn config(&self) -> &ConfigurableHostConfig {
        &self.config
    }

    /// The trusted mints and their accepted units.
    pub fn mints(&self) -> &HashMap<String, Vec<String>> {
        &self.config.mints
    }

    // -- keyset management (called by the server at startup / on refresh) -----

    /// Insert or update a keyset in the cache.
    pub fn set_keyset(&self, mint: &str, keyset_id: Id, entry: KeysetCacheEntry) {
        self.stores.set_keyset(mint, keyset_id, entry);
    }

    /// Returns `{ mint: { unit: [keyset_id, …] } }` for active keysets.
    pub fn get_mints_units_keysets(&self) -> HashMap<String, HashMap<String, Vec<String>>> {
        self.stores.get_mints_units_keysets()
    }

    /// Returns the set of units that have at least one active keyset.
    pub fn get_active_units(&self) -> std::collections::HashSet<String> {
        self.stores.get_active_units()
    }

    // -- channel data accessors (for route handlers) --------------------------

    /// Get the stored funding data for a channel (for status endpoints, etc.).
    pub fn get_funding_data(&self, channel_id: &str) -> Option<ChannelFunding> {
        self.stores
            .funding
            .read()
            .expect("funding lock")
            .get(channel_id)
            .cloned()
    }

    /// Get the current balance for a channel.
    pub fn get_balance(&self, channel_id: &str) -> Option<PaymentProof> {
        self.stores
            .balance
            .read()
            .expect("balance lock")
            .get(channel_id)
            .cloned()
    }

    /// Get the accumulated usage for a channel.
    pub fn get_usage(&self, channel_id: &str) -> Option<UsageMap> {
        self.stores
            .usage
            .read()
            .expect("usage lock")
            .get(channel_id)
            .cloned()
    }

    /// Check whether a channel is closed.
    pub fn is_closed(&self, channel_id: &str) -> bool {
        self.stores
            .closed
            .read()
            .expect("closed lock")
            .contains_key(channel_id)
    }

    /// Get the closed channel data (for idempotent close responses).
    pub fn get_closed_data(&self, channel_id: &str) -> Option<ClosedDataView> {
        self.stores
            .closed
            .read()
            .expect("closed lock")
            .get(channel_id)
            .cloned()
    }

    // -- pricing helpers ------------------------------------------------------

    /// Get the unit for a channel from its stored params.
    fn channel_unit(&self, channel_id: &str) -> Option<String> {
        let store = self.stores.funding.read().expect("funding lock");
        let funding = store.get(channel_id)?;
        let params: serde_json::Value = serde_json::from_str(&funding.params_json).ok()?;
        params.get("unit")?.as_str().map(String::from)
    }

    /// Compute the amount due for a channel given accumulated usage + pending
    /// increments from context.
    fn compute_amount_due(&self, channel_id: &str, context_json: Option<&String>) -> u64 {
        let unit = self.channel_unit(channel_id).unwrap_or_default();
        let unit_pricing = match self.config.pricing.get(&unit) {
            Some(p) => p,
            None => return 0,
        };

        // Get accumulated usage.
        let accumulated = self
            .stores
            .usage
            .read()
            .expect("usage lock")
            .get(channel_id)
            .cloned()
            .unwrap_or_default();

        // Parse pending increments from context.
        let pending: HashMap<String, u64> = context_json
            .and_then(|c| serde_json::from_str(c).ok())
            .unwrap_or_default();

        // Linear combination over all priced variables.
        let mut total: u64 = 0;
        for (var_name, &price) in &unit_pricing.variables {
            let acc = accumulated.get(var_name).copied().unwrap_or(0);
            let pend = pending.get(var_name).copied().unwrap_or(0);
            total = total.saturating_add((acc + pend).saturating_mul(price));
        }
        total
    }

    /// Apply usage increments from context to the accumulated store.
    fn apply_usage_increments(&self, channel_id: &str, context_json: &str) {
        let increments: HashMap<String, u64> = match serde_json::from_str(context_json) {
            Ok(m) => m,
            Err(_) => return,
        };

        let mut store = self.stores.usage.write().expect("usage lock");
        let usage = store.entry(channel_id.to_string()).or_default();
        for (var, delta) in increments {
            *usage.entry(var).or_insert(0) += delta;
        }
    }

    /// Returns pricing filtered to only units with active keysets.
    pub fn get_active_pricing(&self) -> HashMap<String, &UnitPricingConfig> {
        let active_units = self.stores.get_active_units();
        self.config
            .pricing
            .iter()
            .filter(|(unit, _)| active_units.contains(*unit))
            .map(|(unit, cfg)| (unit.clone(), cfg))
            .collect()
    }
}

/// Public view of closed channel data.
#[derive(Debug, Clone)]
pub struct ClosedDataView {
    pub locktime: u64,
    pub closed_amount: u64,
    pub value_after_stage1: u64,
    pub receiver_sum: u64,
    pub sender_sum: u64,
    pub receiver_proofs_json: String,
    pub sender_proofs_json: String,
}

// ============================================================================
// SpilmanHost implementation
// ============================================================================

impl SpilmanHost for ConfigurableHost {
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool {
        receiver_pubkey == &self.server_pubkey
    }

    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool {
        let trusted_units = match self.config.mints.get(mint) {
            Some(units) => units,
            None => return false,
        };
        match self.stores.get_keyset(mint, keyset_id) {
            Some(entry) => trusted_units.iter().any(|u| u == &entry.unit.to_string()),
            None => false,
        }
    }

    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        self.stores
            .funding
            .read()
            .expect("funding lock")
            .get(channel_id)
            .cloned()
    }

    /// `save_funding` is called once per channel, when it first receives the
    /// funding token from the client.  The guards inside are defensive against
    /// concurrent first-payment races for the same channel.
    fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
    ) {
        {
            let mut store = self.stores.funding.write().expect("funding lock");
            if !store.contains_key(channel_id) {
                store.insert(channel_id.to_string(), funding);
            }
        }
        // Store initial balance.
        let mut bal_store = self.stores.balance.write().expect("balance lock");
        let should_update = bal_store
            .get(channel_id)
            .map(|b| initial_payment.balance > b.balance)
            .unwrap_or(true);
        if should_update {
            bal_store.insert(channel_id.to_string(), initial_payment);
        }
    }

    fn get_amount_due(&self, channel_id: &str, context: Option<&String>) -> u64 {
        self.compute_amount_due(channel_id, context)
    }

    /// This is called where the server has decided to accept the payment, i.e.
    /// the balance is sufficient to cover the usage. This both keeps a copy
    /// of the payment, and it also updates the usage records for this channel
    /// so that the server keeps track of how much service has been provided on
    /// this channel.
    fn record_payment(&self, channel_id: &str, payment: PaymentProof, context: &String) {
        // Update balance (monotonically increasing).
        {
            let mut store = self.stores.balance.write().expect("balance lock");
            let should_update = store
                .get(channel_id)
                .map(|b| payment.balance > b.balance)
                .unwrap_or(true);
            if should_update {
                store.insert(channel_id.to_string(), payment);
            }
        }
        // Apply usage increments.
        self.apply_usage_increments(channel_id, context);
    }

    fn get_channel_state(&self, channel_id: &str) -> ChannelState {
        if self
            .stores
            .closed
            .read()
            .expect("closed lock")
            .contains_key(channel_id)
        {
            ChannelState::Closed
        } else if self
            .stores
            .closing
            .read()
            .expect("closing lock")
            .contains_key(channel_id)
        {
            ChannelState::Closing
        } else {
            ChannelState::Open
        }
    }

    fn mark_channel_closing(
        &self,
        channel_id: &str,
        locktime: u64,
        payment: PaymentProof,
    ) -> Result<(), String> {
        if self
            .stores
            .closed
            .read()
            .expect("closed lock")
            .contains_key(channel_id)
        {
            return Err("channel already closed".to_string());
        }
        self.stores.closing.write().expect("closing lock").insert(
            channel_id.to_string(),
            ClosingData {
                locktime,
                balance: payment.balance,
                signature: payment.signature,
            },
        );
        Ok(())
    }

    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        self.stores
            .closing
            .read()
            .expect("closing lock")
            .get(channel_id)
            .cloned()
    }

    fn get_channel_policy(&self, unit: &str) -> Option<ChannelPolicy> {
        let cfg = self.config.pricing.get(unit)?;
        Some(ChannelPolicy {
            min_expiry_in_seconds: self.config.min_expiry_seconds,
            min_capacity: cfg.min_capacity,
            max_amount_per_output: cfg.max_amount_per_output,
        })
    }

    fn now_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs()
    }

    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        channel_id: &str,
    ) -> Option<PaymentProof> {
        self.stores
            .balance
            .read()
            .expect("balance lock")
            .get(channel_id)
            .cloned()
    }

    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id> {
        self.stores.get_active_keyset_ids(mint, unit)
    }

    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String> {
        self.stores.get_keyset(mint, keyset_id).map(|e| e.info_json)
    }

    fn compute_channel_secret(
        &self,
        _charlie_pubkey_hex: &str,
        alice_pubkey_hex: &str,
    ) -> Result<String, String> {
        super::compute_channel_secret_from_hex(&self.server_secret_hex, alice_pubkey_hex)
    }

    fn sign_with_tweaked_key(
        &self,
        _signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String> {
        super::sign_with_tweaked_key_util(&self.server_secret_hex, message_hex, tweak_scalar_hex)
    }

    fn mark_channel_closed(
        &self,
        channel_id: &str,
        locktime: u64,
        balance: u64,
        receiver_proofs_json: &str,
        sender_proofs_json: &str,
        receiver_sum: u64,
        sender_sum: u64,
    ) -> Result<(), String> {
        if self
            .stores
            .closed
            .read()
            .expect("closed lock")
            .contains_key(channel_id)
        {
            return Err("channel already closed".to_string());
        }
        // Insert into closed before removing from closing, so that
        // get_channel_state (which checks closed first) never sees the
        // channel in neither store and briefly reports it as Open.
        self.stores.closed.write().expect("closed lock").insert(
            channel_id.to_string(),
            ClosedDataView {
                locktime,
                closed_amount: balance,
                value_after_stage1: receiver_sum + sender_sum,
                receiver_sum,
                sender_sum,
                receiver_proofs_json: receiver_proofs_json.to_string(),
                sender_proofs_json: sender_proofs_json.to_string(),
            },
        );
        self.stores
            .closing
            .write()
            .expect("closing lock")
            .remove(channel_id);
        Ok(())
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic secret key for tests (same as dev servers).
    const TEST_SECRET_KEY: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    const TEST_YAML: &str = r#"
mints:
  "http://localhost:3338": [sat, msat, usd]
min_expiry_seconds: 3600

pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
      requests: 5
  msat:
    min_capacity: 10000
    variables:
      chars: 1000
      requests: 5000
  usd:
    min_capacity: 10
    max_amount_per_output: 64
    variables:
      chars: 1
      requests: 5
"#;

    fn make_host() -> ConfigurableHost {
        ConfigurableHost::from_yaml(TEST_YAML, TEST_SECRET_KEY).unwrap()
    }

    // -- config parsing -------------------------------------------------------

    #[test]
    fn test_yaml_parsing() {
        let config = ConfigurableHostConfig::from_yaml(TEST_YAML).unwrap();
        let trusted = &config.mints["http://localhost:3338"];
        assert_eq!(trusted, &vec!["sat", "msat", "usd"]);
        assert_eq!(config.min_expiry_seconds, 3600);
        assert_eq!(config.pricing.len(), 3);

        let sat = &config.pricing["sat"];
        assert_eq!(sat.min_capacity, 10);
        assert_eq!(sat.max_amount_per_output, None);
        assert_eq!(sat.variables["chars"], 1);
        assert_eq!(sat.variables["requests"], 5);

        let usd = &config.pricing["usd"];
        assert_eq!(usd.max_amount_per_output, Some(64));
    }

    #[test]
    fn test_yaml_default_expiry() {
        let yaml = r#"
mints:
  "http://example.com": [sat]
pricing:
  sat:
    min_capacity: 10
    variables:
      requests: 1
"#;
        let config = ConfigurableHostConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.min_expiry_seconds, 3600);
    }

    #[test]
    fn test_yaml_invalid() {
        let result = ConfigurableHostConfig::from_yaml("not: valid: yaml: [");
        assert!(result.is_err());
    }

    #[test]
    fn test_yaml_missing_required_fields() {
        let yaml = r#"
min_expiry_seconds: 3600
"#;
        let result = ConfigurableHostConfig::from_yaml(yaml);
        assert!(result.is_err());
    }

    // -- host construction ----------------------------------------------------

    #[test]
    fn test_host_construction() {
        let host = make_host();
        assert!(host.mints().contains_key("http://localhost:3338"));
        assert_eq!(host.config().min_expiry_seconds, 3600);
    }

    #[test]
    fn test_host_invalid_secret_key() {
        let result = ConfigurableHost::from_yaml(TEST_YAML, "not-hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_pricing_for_trusted_unit() {
        // Mint trusts "sat" and "foo", but pricing only covers "sat".
        let yaml = r#"
mints:
  "http://localhost:3338": [sat, foo]
pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
"#;
        let msg = ConfigurableHost::from_yaml(yaml, TEST_SECRET_KEY)
            .err()
            .expect("should fail for missing pricing");
        assert!(
            msg.contains("foo"),
            "error should mention the missing unit: {msg}"
        );
    }

    #[test]
    fn test_unused_pricing_accepted() {
        // Pricing defines "sat" and "usd", but the only mint trusts just "sat".
        // This should succeed (unused pricing is a warning, not an error).
        let yaml = r#"
mints:
  "http://localhost:3338": [sat]
pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
  usd:
    min_capacity: 10
    variables:
      chars: 1
"#;
        let host = ConfigurableHost::from_yaml(yaml, TEST_SECRET_KEY);
        assert!(host.is_ok());
    }

    #[test]
    fn test_server_pubkey_derived() {
        let host = make_host();
        let pubkey_hex = host.server_pubkey().to_hex();
        let sk = SecretKey::from_hex(TEST_SECRET_KEY).unwrap();
        assert_eq!(pubkey_hex, sk.public_key().to_hex());
    }

    // -- receiver key ---------------------------------------------------------

    #[test]
    fn test_receiver_key_acceptable() {
        let host = make_host();
        assert!(host.receiver_key_is_acceptable(host.server_pubkey()));
    }

    #[test]
    fn test_receiver_key_wrong() {
        let host = make_host();
        let other_sk =
            SecretKey::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        assert!(!host.receiver_key_is_acceptable(&other_sk.public_key()));
    }

    // -- mint & keyset --------------------------------------------------------

    #[test]
    fn test_mint_keyset_acceptable() {
        let host = make_host();
        let fake_id: Id = "001b6c716bf42c7e".parse().unwrap();
        assert!(!host.mint_and_keyset_is_acceptable("http://localhost:3338", &fake_id));

        host.set_keyset(
            "http://localhost:3338",
            fake_id,
            KeysetCacheEntry {
                info_json: "{}".to_string(),
                active: true,
                unit: CurrencyUnit::Sat,
            },
        );
        assert!(host.mint_and_keyset_is_acceptable("http://localhost:3338", &fake_id));
    }

    #[test]
    fn test_wrong_mint_rejected() {
        let host = make_host();
        let fake_id: Id = "001b6c716bf42c7e".parse().unwrap();
        host.set_keyset(
            "http://localhost:3338",
            fake_id,
            KeysetCacheEntry {
                info_json: "{}".to_string(),
                active: true,
                unit: CurrencyUnit::Sat,
            },
        );
        assert!(!host.mint_and_keyset_is_acceptable("http://other-mint:3338", &fake_id));
    }

    #[test]
    fn test_untrusted_unit_rejected() {
        // Config only trusts [sat] at this mint — a cached "usd" keyset must
        // be rejected even though the mint itself is trusted.
        let yaml = r#"
mints:
  "http://localhost:3338": [sat]
pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
"#;
        let host = ConfigurableHost::from_yaml(yaml, TEST_SECRET_KEY).unwrap();
        let fake_id: Id = "001b6c716bf42c7e".parse().unwrap();
        host.set_keyset(
            "http://localhost:3338",
            fake_id,
            KeysetCacheEntry {
                info_json: "{}".to_string(),
                active: true,
                unit: CurrencyUnit::Usd,
            },
        );
        assert!(!host.mint_and_keyset_is_acceptable("http://localhost:3338", &fake_id));

        // But a "sat" keyset at the same mint should be accepted.
        host.set_keyset(
            "http://localhost:3338",
            fake_id,
            KeysetCacheEntry {
                info_json: "{}".to_string(),
                active: true,
                unit: CurrencyUnit::Sat,
            },
        );
        assert!(host.mint_and_keyset_is_acceptable("http://localhost:3338", &fake_id));
    }

    // -- amount due (linear combination) --------------------------------------

    fn seed_channel(host: &ConfigurableHost, channel_id: &str, unit: &str) {
        let params_json = serde_json::json!({
            "unit": unit,
            "capacity": 1000,
        })
        .to_string();
        host.stores.funding.write().unwrap().insert(
            channel_id.to_string(),
            ChannelFunding {
                params_json,
                funding_proofs_json: "[]".to_string(),
                channel_secret_hex: "deadbeef".to_string(),
                keyset_info_json: "{}".to_string(),
            },
        );
    }

    #[test]
    fn test_amount_due_no_usage_no_context() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");
        assert_eq!(host.get_amount_due("ch1", None), 0);
    }

    #[test]
    fn test_amount_due_with_context_only() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        // Context: 10 chars, 1 request -> 10*1 + 1*5 = 15 sat
        let ctx = serde_json::json!({"chars": 10, "requests": 1}).to_string();
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 15);
    }

    #[test]
    fn test_amount_due_accumulated_plus_context() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        // Seed accumulated usage: 20 chars, 2 requests.
        {
            let mut store = host.stores.usage.write().unwrap();
            let mut usage = HashMap::new();
            usage.insert("chars".to_string(), 20);
            usage.insert("requests".to_string(), 2);
            store.insert("ch1".to_string(), usage);
        }

        // Context adds 5 chars, 1 request.
        // Total: (20+5)*1 + (2+1)*5 = 25 + 15 = 40 sat
        let ctx = serde_json::json!({"chars": 5, "requests": 1}).to_string();
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 40);
    }

    #[test]
    fn test_amount_due_msat_unit() {
        let host = make_host();
        seed_channel(&host, "ch1", "msat");

        let ctx = serde_json::json!({"chars": 10, "requests": 1}).to_string();
        // 10*1000 + 1*5000 = 15000 msat
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 15_000);
    }

    #[test]
    fn test_amount_due_unknown_variable_in_context() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        // "bytes" is not in the sat pricing -- should be ignored.
        let ctx = serde_json::json!({"chars": 10, "bytes": 9999}).to_string();
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 10);
    }

    #[test]
    fn test_amount_due_unknown_unit() {
        let host = make_host();
        seed_channel(&host, "ch1", "btc"); // not in pricing

        let ctx = serde_json::json!({"chars": 10}).to_string();
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 0);
    }

    #[test]
    fn test_amount_due_empty_context() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        let ctx = "{}".to_string();
        assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 0);
    }

    // -- record_payment -------------------------------------------------------

    #[test]
    fn test_record_payment_updates_usage() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        let ctx1 = serde_json::json!({"chars": 10, "requests": 1}).to_string();
        host.record_payment(
            "ch1",
            PaymentProof {
                balance: 15,
                signature: "sig1".to_string(),
            },
            &ctx1,
        );

        let usage = host.get_usage("ch1").unwrap();
        assert_eq!(usage["chars"], 10);
        assert_eq!(usage["requests"], 1);

        let ctx2 = serde_json::json!({"chars": 5, "requests": 1}).to_string();
        host.record_payment(
            "ch1",
            PaymentProof {
                balance: 30,
                signature: "sig2".to_string(),
            },
            &ctx2,
        );

        let usage = host.get_usage("ch1").unwrap();
        assert_eq!(usage["chars"], 15);
        assert_eq!(usage["requests"], 2);
    }

    #[test]
    fn test_record_payment_updates_balance_monotonically() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        let ctx = serde_json::json!({"chars": 5}).to_string();
        host.record_payment(
            "ch1",
            PaymentProof {
                balance: 20,
                signature: "sig20".to_string(),
            },
            &ctx,
        );
        assert_eq!(host.get_balance("ch1").unwrap().balance, 20);

        // Lower balance should NOT overwrite.
        host.record_payment(
            "ch1",
            PaymentProof {
                balance: 10,
                signature: "sig10".to_string(),
            },
            &ctx,
        );
        assert_eq!(host.get_balance("ch1").unwrap().balance, 20);
        assert_eq!(host.get_balance("ch1").unwrap().signature, "sig20");
    }

    // -- channel lifecycle ----------------------------------------------------

    #[test]
    fn test_channel_lifecycle() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        assert_eq!(host.get_channel_state("ch1"), ChannelState::Open);

        host.mark_channel_closing(
            "ch1",
            1000,
            PaymentProof {
                balance: 50,
                signature: "sig".to_string(),
            },
        )
        .unwrap();
        assert_eq!(host.get_channel_state("ch1"), ChannelState::Closing);

        let closing = host.get_closing_data("ch1").unwrap();
        assert_eq!(closing.locktime, 1000);
        assert_eq!(closing.balance, 50);

        host.mark_channel_closed("ch1", 1000, 50, "[]", "[]", 40, 10)
            .unwrap();
        assert_eq!(host.get_channel_state("ch1"), ChannelState::Closed);

        assert!(host.get_closing_data("ch1").is_none());

        let closed = host.get_closed_data("ch1").unwrap();
        assert_eq!(closed.closed_amount, 50);
        assert_eq!(closed.receiver_sum, 40);
        assert_eq!(closed.sender_sum, 10);
    }

    #[test]
    fn test_closing_already_closed_channel() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        host.mark_channel_closed("ch1", 1000, 50, "[]", "[]", 40, 10)
            .unwrap();

        let result = host.mark_channel_closing(
            "ch1",
            2000,
            PaymentProof {
                balance: 60,
                signature: "sig".to_string(),
            },
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already closed"));
    }

    #[test]
    fn test_double_close_rejected() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        host.mark_channel_closed("ch1", 1000, 50, "[]", "[]", 40, 10)
            .unwrap();
        let result = host.mark_channel_closed("ch1", 1000, 50, "[]", "[]", 40, 10);
        assert!(result.is_err());
    }

    // -- unilateral exit ------------------------------------------------------

    #[test]
    fn test_unilateral_exit_data() {
        let host = make_host();
        seed_channel(&host, "ch1", "sat");

        assert!(host
            .get_balance_and_signature_for_unilateral_exit("ch1")
            .is_none());

        let ctx = serde_json::json!({"chars": 5}).to_string();
        host.record_payment(
            "ch1",
            PaymentProof {
                balance: 25,
                signature: "sig25".to_string(),
            },
            &ctx,
        );

        let proof = host
            .get_balance_and_signature_for_unilateral_exit("ch1")
            .unwrap();
        assert_eq!(proof.balance, 25);
        assert_eq!(proof.signature, "sig25");
    }

    // -- save_funding ---------------------------------------------------------

    #[test]
    fn test_save_funding() {
        let host = make_host();

        let funding = ChannelFunding {
            params_json: r#"{"unit":"sat","capacity":100}"#.to_string(),
            funding_proofs_json: "[]".to_string(),
            channel_secret_hex: "abcd".to_string(),
            keyset_info_json: "{}".to_string(),
        };
        host.save_funding(
            "ch1",
            funding.clone(),
            PaymentProof {
                balance: 0,
                signature: "sig0".to_string(),
            },
        );

        let f = host.get_funding("ch1").unwrap();
        assert_eq!(f.params_json, r#"{"unit":"sat","capacity":100}"#);
        assert_eq!(host.get_balance("ch1").unwrap().balance, 0);

        // Second save with same channel_id should NOT overwrite.
        let funding2 = ChannelFunding {
            params_json: r#"{"unit":"msat","capacity":999}"#.to_string(),
            funding_proofs_json: "[1]".to_string(),
            channel_secret_hex: "ffff".to_string(),
            keyset_info_json: "{}".to_string(),
        };
        host.save_funding(
            "ch1",
            funding2,
            PaymentProof {
                balance: 0,
                signature: "sig0b".to_string(),
            },
        );
        let f2 = host.get_funding("ch1").unwrap();
        assert_eq!(f2.params_json, r#"{"unit":"sat","capacity":100}"#); // unchanged
    }

    // -- keyset cache ---------------------------------------------------------

    #[test]
    fn test_keyset_cache() {
        let host = make_host();
        let ks1: Id = "001b6c716bf42c7e".parse().unwrap();
        let ks2: Id = "00ffedc2dbb87212".parse().unwrap();
        let ks3: Id = "00818d176a78e7f0".parse().unwrap();

        host.set_keyset(
            "http://localhost:3338",
            ks1,
            KeysetCacheEntry {
                info_json: r#"{"keysetId":"001b6c716bf42c7e"}"#.to_string(),
                active: true,
                unit: CurrencyUnit::Sat,
            },
        );
        host.set_keyset(
            "http://localhost:3338",
            ks2,
            KeysetCacheEntry {
                info_json: r#"{"keysetId":"00ffedc2dbb87212"}"#.to_string(),
                active: false,
                unit: CurrencyUnit::Sat,
            },
        );
        host.set_keyset(
            "http://localhost:3338",
            ks3,
            KeysetCacheEntry {
                info_json: r#"{"keysetId":"00818d176a78e7f0"}"#.to_string(),
                active: true,
                unit: CurrencyUnit::Msat,
            },
        );

        let active_sat = host
            .stores
            .get_active_keyset_ids("http://localhost:3338", &CurrencyUnit::Sat);
        assert_eq!(active_sat, vec![ks1]);

        let mints = host.get_mints_units_keysets();
        assert!(mints["http://localhost:3338"]["sat"].contains(&ks1.to_string()));
        assert!(mints["http://localhost:3338"]["msat"].contains(&ks3.to_string()));
        assert!(!mints["http://localhost:3338"]
            .get("sat")
            .unwrap()
            .contains(&ks2.to_string()));
    }

    // -- channel policy -------------------------------------------------------

    #[test]
    fn test_channel_policy_returns_per_unit() {
        let host = make_host();

        let sat_policy = host.get_channel_policy("sat").unwrap();
        assert_eq!(sat_policy.min_expiry_in_seconds, 3600);
        assert_eq!(sat_policy.min_capacity, 10);
        assert!(sat_policy.max_amount_per_output.is_none());

        // Unknown unit returns None.
        assert!(host.get_channel_policy("unknown").is_none());
    }

    // -- crypto ---------------------------------------------------------------

    #[test]
    fn test_compute_channel_secret() {
        let host = make_host();
        let alice_sk =
            SecretKey::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        let alice_pub = alice_sk.public_key().to_hex();
        let charlie_pub = host.server_pubkey().to_hex();

        let secret = host
            .compute_channel_secret(&charlie_pub, &alice_pub)
            .unwrap();
        assert_eq!(secret.len(), 64); // 32 bytes hex
    }

    #[test]
    fn test_get_active_pricing() {
        let host = make_host();

        assert!(host.get_active_pricing().is_empty());

        let ks1: Id = "001b6c716bf42c7e".parse().unwrap();
        host.set_keyset(
            "http://localhost:3338",
            ks1,
            KeysetCacheEntry {
                info_json: "{}".to_string(),
                active: true,
                unit: CurrencyUnit::Sat,
            },
        );
        let pricing = host.get_active_pricing();
        assert_eq!(pricing.len(), 1);
        assert!(pricing.contains_key("sat"));
        assert_eq!(pricing["sat"].variables["chars"], 1);
    }

    // -- clone shares state ---------------------------------------------------

    #[test]
    fn test_clone_shares_stores() {
        let host = make_host();
        let host2 = host.clone();

        seed_channel(&host, "ch1", "sat");

        // The clone should see the same data.
        assert!(host2.get_funding("ch1").is_some());
    }
}
