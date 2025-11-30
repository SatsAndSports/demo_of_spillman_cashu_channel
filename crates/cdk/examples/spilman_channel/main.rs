//! Example: Spilman (Unidirectional) Payment Channel
//!
//! This example will demonstrate a Cashu implementation of Spilman channels,
//! allowing Alice and Charlie to set up an offline unidirectional payment channel.

mod deterministic;
mod params;
mod extra;
mod established_channel;
mod balance_update;
mod sender_and_receiver;
mod test_helpers;

use cdk::nuts::{CurrencyUnit, SecretKey};
use cdk::util::unix_time;
use cdk::secret::Secret;
use clap::Parser;

use params::SpilmanChannelParameters;
use extra::SpilmanChannelExtra;
use established_channel::EstablishedChannel;
use balance_update::BalanceUpdateMessage;

use test_helpers::{MintConnection, setup_mint_and_wallets_for_demo, mint_deterministic_outputs, get_active_keyset_info};

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
    println!("\n🪙 Minting funding token, via those deterministic funding token outputs ...");

    let funding_proofs = mint_deterministic_outputs(
        mint_connection,
        channel_extra.params.unit.clone(),
        funding_blinded_messages.clone(),
        funding_secrets_with_blinding,
        active_keys,
    ).await?;

    Ok(funding_proofs)
}

/// Receive proofs into a wallet with P2PK signing
///
/// The wallet will automatically sign and swap the proofs to remove P2PK conditions.
/// Returns the amount received in the base unit.
async fn receive_proofs_into_wallet(
    wallet: &cdk::wallet::Wallet,
    proofs: Vec<cdk::nuts::Proof>,
    secret_key: cdk::nuts::SecretKey,
) -> anyhow::Result<u64> {
    let receive_opts = cdk::wallet::ReceiveOptions {
        amount_split_target: cdk::amount::SplitTarget::default(),
        p2pk_signing_keys: vec![secret_key],
        preimages: vec![],
        metadata: std::collections::HashMap::new(),
    };

    let received_amount = wallet.receive_proofs(proofs, receive_opts, None).await?;
    Ok(u64::from(received_amount))
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
    let alice_secret = SecretKey::generate();
    let alice_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let charlie_pubkey = charlie_secret.public_key();

    // 2. SETUP INITIAL CHANNEL PARAMETERS
    println!("📋 Setting up Spilman channel parameters...");

    let channel_unit = CurrencyUnit::Sat;
    let requested_input_fee_ppk = 400; // 40% input fee (only for local mints)
    let base = 2; // Powers of 2 (only for local mints)

    // 3. CREATE OR CONNECT TO MINT
    let (mint_connection, alice_wallet, charlie_wallet, mint_url) =
        setup_mint_and_wallets_for_demo(args.mint, channel_unit.clone(), requested_input_fee_ppk, base).await?;

    // Get active keyset information (will use actual fee from mint)
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
    println!("   Input fee: {} ppk", input_fee_ppk);
    println!("   Mint: {}", mint_url);
    println!("   Unit: {}", channel_params.unit_name());
    println!("   Channel ID: {}", channel_params.get_channel_id());

    // 4b. CREATE CHANNEL EXTRA (params + mint-specific data)
    let channel_extra = SpilmanChannelExtra::new(channel_params, active_keys.clone())?;

    // 5. CALCULATE EXACT FUNDING TOKEN SIZE using double inverse
    println!("\n💡 Calculating exact funding token size using double inverse...");

    let funding_token_nominal = channel_extra.get_total_funding_token_amount()?;

    println!("   Capacity: {} sats   Funding token nominal: {} sats", capacity, funding_token_nominal);

    // 7. CREATE AND MINT FUNDING TOKEN
    let funding_proofs = create_and_mint_funding_token(
        &channel_extra,
        funding_token_nominal,
        &*mint_connection,
        &active_keys,
    ).await?;

    println!("\n✅ Deterministic funding token created!");

    // 9. CREATE CHANNEL FIXTURES

    let channel_fixtures = EstablishedChannel::new(
        channel_extra,
        funding_proofs,
    )?;

    // 10. CREATE COMMITMENT TRANSACTION AND SWAP
    let charlie_intended_balance = 100_000u64;
    let charlie_balance = channel_fixtures.extra.get_de_facto_balance(charlie_intended_balance)?;
    println!("\n💱 Creating commitment transaction for balance: {} sats intended → {} sats de facto for Charlie...",
             charlie_intended_balance, charlie_balance);

    // Create commitment outputs for this balance
    let commitment_outputs = channel_fixtures.extra.create_two_sets_of_outputs_for_balance(
        charlie_balance,
    )?;
    println!("   ✓ Created deterministic outputs for both parties");
    let charlie_final = commitment_outputs.receiver_outputs.value_after_fees()?;
    let alice_final = commitment_outputs.sender_outputs.value_after_fees()?;
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

    // Create a balance update message (this is what Alice would send to Charlie off-chain)
    let balance_update = BalanceUpdateMessage::from_signed_swap_request(
        channel_fixtures.extra.params.get_channel_id(),
        charlie_balance,
        &swap_request,
    )?;
    println!("   ✓ Created off-chain balance update message, with Alice's signature");

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
    let charlie_received_amount = receive_proofs_into_wallet(&charlie_wallet, charlie_proofs, charlie_secret.clone()).await?;

    // Alice receives her proofs (wallet will sign and swap to remove P2PK)
    let alice_received_amount = receive_proofs_into_wallet(&alice_wallet, alice_proofs, alice_secret.clone()).await?;
    println!("   Charlie received: {} sats   Alice received: {} sats", charlie_received_amount, alice_received_amount);

    // Assert that Charlie's received amount matches the de facto balance
    assert_eq!(
        charlie_received_amount, charlie_balance,
        "Charlie's received amount ({}) should match the de facto balance ({})",
        charlie_received_amount, charlie_balance
    );

    println!("\n✅ Commitment transaction completed and proofs distributed!");

    Ok(())
}
