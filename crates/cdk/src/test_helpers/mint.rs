#![cfg(test)]
//! Test helpers for creating test mints and related utilities

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bip39::Mnemonic;
use cdk_common::amount::SplitTarget;
use cdk_common::dhke::construct_proofs;
use cdk_common::nut00::KnownMethod;
use cdk_common::nuts::{BlindedMessage, CurrencyUnit, Id, PaymentMethod, PreMintSecrets, Proofs};
use cdk_common::{
    Amount, MintQuoteBolt11Request, MintQuoteBolt11Response, MintQuoteState, MintRequest,
};
use cdk_fake_wallet::FakeWallet;
use tokio::time::sleep;

use crate::mint::{Mint, MintBuilder, MintMeltLimits};
use crate::types::{FeeReserve, QuoteTTL};
use crate::Error;

thread_local! {
    /// Thread-local storage for test failure flags.
    /// Using thread-local instead of env vars prevents race conditions
    /// when tests run in parallel (each test thread has its own copy).
    static TEST_FAILURES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Sets a failure flag for the current thread only.
/// Use this instead of `std::env::set_var("TEST_FAIL_X", "1")`.
#[cfg(test)]
pub(crate) fn set_fail_for(operation: &str) {
    TEST_FAILURES.with(|failures| {
        failures.borrow_mut().push(operation.to_string());
    });
}

/// Clears a failure flag for the current thread only.
/// Use this instead of `std::env::remove_var("TEST_FAIL_X")`.
#[cfg(test)]
pub(crate) fn clear_fail_for(operation: &str) {
    TEST_FAILURES.with(|failures| {
        failures.borrow_mut().retain(|s| s != operation);
    });
}

#[cfg(test)]
pub(crate) fn should_fail_in_test() -> bool {
    TEST_FAILURES.with(|failures| failures.borrow().contains(&"GENERAL".to_string()))
}

#[cfg(test)]
pub(crate) fn should_fail_for(operation: &str) -> bool {
    TEST_FAILURES.with(|failures| failures.borrow().contains(&operation.to_string()))
}

/// Get the input fee PPK for a given unit from environment variable or default.
///
/// Environment variable format: TEST_MINT_FEE_PPK_{UNIT}
/// Examples:
/// - TEST_MINT_FEE_PPK_SAT=400
/// - TEST_MINT_FEE_PPK_USD=0
///
/// Default is 400 ppk for all units if not set.
/// Maximum allowed value is 999 (must be < 1000).
fn get_test_fee_ppk_for_unit(unit: &CurrencyUnit) -> u64 {
    const DEFAULT_FEE_PPK: u64 = 400;
    const MAX_FEE_PPK: u64 = 999;

    let unit_str = unit.to_string().to_uppercase();
    let var_name = format!("TEST_MINT_FEE_PPK_{}", unit_str);

    match std::env::var(&var_name) {
        Ok(value) => match value.parse::<u64>() {
            Ok(fee) => {
                assert!(
                    fee < 1000,
                    "Test mint: {} must be < 1000, got {}",
                    var_name,
                    fee
                );
                if fee != DEFAULT_FEE_PPK {
                    println!("Test mint: Using {}={} (from env)", var_name, fee);
                }
                fee.min(MAX_FEE_PPK)
            }
            Err(_) => {
                println!(
                    "Test mint: Invalid value for {}: '{}', using default {}",
                    var_name, value, DEFAULT_FEE_PPK
                );
                DEFAULT_FEE_PPK
            }
        },
        Err(_) => DEFAULT_FEE_PPK,
    }
}

/// Creates and starts a test mint with in-memory storage and a fake Lightning backend.
///
/// This mint can be used for unit tests without requiring external dependencies
/// like Lightning nodes or persistent databases.
///
/// # Example
///
/// ```
/// use cdk::test_helpers::mint::create_test_mint;
///
/// #[tokio::test]
/// async fn test_something() {
///     let mint = create_test_mint().await.unwrap();
///     // Use the mint for testing
/// }
/// ```
pub async fn create_test_mint() -> Result<Mint, Error> {
    let db = Arc::new(cdk_sqlite::mint::memory::empty().await?);

    let mut mint_builder = MintBuilder::new(db.clone());

    let fee_reserve = FeeReserve {
        min_fee_reserve: 1.into(),
        percent_fee_reserve: 1.0,
    };

    let ln_fake_backend = FakeWallet::new(
        fee_reserve.clone(),
        HashMap::default(),
        HashSet::default(),
        2,
        CurrencyUnit::Sat,
    );

    mint_builder
        .add_payment_processor(
            CurrencyUnit::Sat,
            PaymentMethod::Known(KnownMethod::Bolt11),
            MintMeltLimits::new(1, 10_000),
            Arc::new(ln_fake_backend),
        )
        .await?;

    // Set input fee from environment variable or default (400 ppk)
    let sat_fee_ppk = get_test_fee_ppk_for_unit(&CurrencyUnit::Sat);
    mint_builder.set_unit_fee(&CurrencyUnit::Sat, sat_fee_ppk)?;

    let mnemonic = Mnemonic::generate(12).map_err(|e| Error::Custom(e.to_string()))?;

    mint_builder = mint_builder
        .with_name("test mint".to_string())
        .with_description("test mint for unit tests".to_string())
        .with_urls(vec!["https://test-mint".to_string()]);

    let quote_ttl = QuoteTTL::new(10000, 10000);

    let mint = mint_builder
        .build_with_seed(db.clone(), &mnemonic.to_seed_normalized(""))
        .await?;

    mint.set_quote_ttl(quote_ttl).await?;

    mint.start().await?;

    Ok(mint)
}

/// Creates test proofs by performing a mock mint operation.
///
/// This helper creates valid proofs for the given amount by:
/// 1. Creating blinded messages
/// 2. Performing a swap to get signatures
/// 3. Constructing valid proofs from the signatures
///
/// # Arguments
///
/// * `mint` - The test mint to use for creating proofs
/// * `amount` - The total amount to create proofs for
pub async fn mint_test_proofs(mint: &Mint, amount: Amount) -> Result<Proofs, Error> {
    // Just use fund_mint_with_proofs which creates proofs via swap
    let mint_quote: MintQuoteBolt11Response<_> = mint
        .get_mint_quote(
            MintQuoteBolt11Request {
                amount,
                unit: CurrencyUnit::Sat,
                description: None,
                pubkey: None,
            }
            .into(),
        )
        .await?
        .into();

    loop {
        let check: MintQuoteBolt11Response<_> = mint
            .check_mint_quote(&cdk_common::QuoteId::from_str(&mint_quote.quote).unwrap())
            .await
            .unwrap()
            .into();

        if check.state == MintQuoteState::Paid {
            break;
        }

        sleep(Duration::from_secs(1)).await;
    }

    let keysets = *mint.get_active_keysets().get(&CurrencyUnit::Sat).unwrap();

    let keys = mint
        .keyset_pubkeys(&keysets)?
        .keysets
        .first()
        .unwrap()
        .keys
        .clone();

    let fees: (u64, Vec<u64>) = (0, keys.iter().map(|a| a.0.to_u64()).collect::<Vec<_>>());

    let premint_secrets =
        PreMintSecrets::random(keysets, amount, &SplitTarget::None, &fees.into()).unwrap();

    let request = MintRequest {
        quote: mint_quote.quote,
        outputs: premint_secrets.blinded_messages(),
        signature: None,
    };

    let mint_res = mint
        .process_mint_request(request.try_into().unwrap())
        .await?;

    Ok(construct_proofs(
        mint_res.signatures,
        premint_secrets.rs(),
        premint_secrets.secrets(),
        &keys,
    )?)
}

/// Creates test blinded messages for the given amount.
///
/// This is useful for testing operations that require blinded messages as input.
///
/// # Arguments
///
/// * `mint` - The test mint (used to get the active keyset)
/// * `amount` - The total amount to create blinded messages for
///
/// # Returns
///
/// A tuple containing:
/// - Vector of blinded messages
/// - PreMintSecrets (needed to construct proofs later)
pub async fn create_test_blinded_messages(
    mint: &Mint,
    amount: Amount,
) -> Result<(Vec<BlindedMessage>, PreMintSecrets), Error> {
    let keyset_id = get_active_keyset_id(mint).await?;
    let split_target = SplitTarget::default();
    let fee_and_amounts = (0, ((0..32).map(|x| 2u64.pow(x)).collect::<Vec<_>>())).into();

    let pre_mint = PreMintSecrets::random(keyset_id, amount, &split_target, &fee_and_amounts)?;
    let blinded_messages = pre_mint.blinded_messages().to_vec();

    Ok((blinded_messages, pre_mint))
}

/// Gets the active keyset ID from the mint.
pub async fn get_active_keyset_id(mint: &Mint) -> Result<Id, Error> {
    let keys = mint
        .pubkeys()
        .keysets
        .first()
        .ok_or(Error::Internal)?
        .clone();
    keys.verify_id()?;
    Ok(keys.id)
}
