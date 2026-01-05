//! Spilman Payment Channels
//!
//! This module implements Spilman-style unidirectional payment channels for Cashu.
//!
//! A Spilman channel allows Alice (sender) to make incremental payments to Charlie (receiver)
//! without requiring on-chain transactions for each payment. The channel uses:
//!
//! - 2-of-2 multisig funding with locktime refund for Alice
//! - Deterministic output derivation using shared secrets
//! - Off-chain balance updates signed by Alice
//! - Final commitment transaction signed by both parties

mod balance_update;
mod bindings;
mod deterministic;
mod established_channel;
mod keysets_and_amounts;
mod params;
mod sender_and_receiver;

pub use balance_update::{get_signatures_from_swap_request, BalanceUpdateMessage};
pub use bindings::{channel_parameters_get_channel_id, compute_shared_secret_from_hex};
pub use deterministic::{
    CommitmentOutputs, DeterministicOutputsForOneContext, DeterministicSecretWithBlinding,
    MintConnection,
};
pub use established_channel::EstablishedChannel;
pub use keysets_and_amounts::{KeysetInfo, OrderedListOfAmounts};
pub use params::{compute_shared_secret, ChannelParameters};
pub use sender_and_receiver::{
    ChannelVerificationError, ChannelVerificationResult, SpilmanChannelReceiver,
    SpilmanChannelSender, verify_valid_channel,
};

#[cfg(test)]
mod tests;
