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
mod bridge;
mod client_bridge;
#[cfg(feature = "configurable-host")]
pub mod configurable_host;
#[cfg(feature = "spilman-axum")]
pub mod axum;
#[cfg(feature = "configurable-host-reqwest")]
pub mod configurable_networking;
mod deterministic;
mod established_channel;
mod keysets_and_amounts;
mod params;
mod sender_and_receiver;

pub use balance_update::{get_signatures_from_swap_request, BalanceUpdateMessage};
pub use bindings::{
    attach_signature_to_balance_update, build_cashu_a_token, channel_parameters_get_channel_id,
    complete_funding_swap, compute_channel_from_token, compute_channel_secret_from_hex,
    compute_funding_token_amount, construct_proofs, create_funding_outputs, create_funding_swap,
    create_plain_blinded_messages, create_signed_balance_update, create_unsigned_balance_update,
    mint_proofs_from_mint, parse_keyset_info_from_json, sign_with_tweaked_key_util,
};
pub use client_bridge::{
    base64_decode, ChannelData, ClientChannelInfo, OpenChannelResult, SpilmanClientBridge,
    SpilmanClientHost,
};
pub use bridge::{
    unblind_and_verify_dleq, unblind_and_verify_stage1_response, BridgeError, ChannelFunding,
    ChannelPolicy, ChannelState, CloseData, CloseError, ClosePreparationError, CloseSuccess,
    ClosingData, FundChannelResult, PaymentProof, PaymentSuccess, PaymentValidationResult,
    PreparedClose, SpilmanAsyncNetworking, SpilmanBridge, SpilmanHost, SpilmanNetworking,
    UnblindResult,
};
pub use deterministic::{
    CommitmentOutputs, DeterministicOutputsForOneContext, DeterministicSecretWithBlinding,
    MintConnection,
};
pub use established_channel::EstablishedChannel;
pub use keysets_and_amounts::{KeysetInfo, OrderedListOfAmounts};
pub use params::{compute_channel_secret, ChannelId, ChannelParameters};
pub use sender_and_receiver::{
    verify_valid_channel, ChannelVerificationError, ChannelVerificationResult,
    SpilmanChannelSender,
};

#[cfg(test)]
mod tests;
