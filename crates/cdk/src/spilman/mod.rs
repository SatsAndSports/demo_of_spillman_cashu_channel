//! Spilman Payment Channels
//!
//! This module re-exports the standalone `cdk-spilman` crate while keeping the
//! existing `cdk::spilman` API available during the extraction.

pub use cdk_spilman::{
    attach_signature_to_balance_update, base64_decode, build_cashu_a_token, build_cashu_b_token,
    channel_parameters_get_channel_id, compute_channel_from_token,
    compute_channel_secret, compute_channel_secret_from_hex, compute_funding_token_amount,
    create_funding_outputs, create_funding_swap, create_signed_balance_update,
    create_unsigned_balance_update, get_signatures_from_swap_request,
    parse_keyset_info_from_json, sign_with_tweaked_key_util, BalanceUpdateMessage, BridgeError,
    BridgeErrorResponse, ChannelData, ChannelFunding, ChannelId, ChannelParameters, ChannelPolicy,
    ChannelState, ChannelVerificationError, ChannelVerificationResult, ClientChannelInfo,
    CloseData, CloseError, ClosePreparationError, CloseSuccess, ClosingData, CommitmentOutputs,
    DeterministicOutputsForOneContext, DeterministicSecretWithBlinding, EstablishedChannel,
    FundChannelResult, KeysetInfo, MintConnection, OpenChannelResult, OrderedListOfAmounts,
    PaymentProof, PaymentSuccess, PaymentValidationResult, PreparedClose, SpilmanAsyncNetworking,
    SpilmanBridge, SpilmanChannelSender, SpilmanClientBridge, SpilmanClientHost, SpilmanHost,
    SpilmanNetworking, UnblindResult, verify_valid_channel, unblind_and_verify_stage1_response,
};
#[cfg(feature = "wallet")]
pub use cdk_spilman::{
    complete_funding_swap, construct_proofs, create_plain_blinded_messages, mint_proofs_from_mint,
};
#[cfg(feature = "configurable-host")]
pub use cdk_spilman::configurable_host;
#[cfg(feature = "spilman-axum")]
pub use cdk_spilman::axum;
#[cfg(feature = "configurable-host-reqwest")]
pub use cdk_spilman::configurable_networking;

/// Compatibility re-exports for balance update types and helpers.
pub mod balance_update {
    pub use cdk_spilman::{get_signatures_from_swap_request, BalanceUpdateMessage};
}

/// Compatibility re-exports for FFI-oriented bindings helpers.
pub mod bindings {
    pub use cdk_spilman::{
        attach_signature_to_balance_update, build_cashu_a_token, build_cashu_b_token,
        channel_parameters_get_channel_id, compute_channel_from_token,
        compute_channel_secret_from_hex, compute_funding_token_amount, create_funding_outputs,
        create_funding_swap, create_signed_balance_update, create_unsigned_balance_update,
        parse_keyset_info_from_json, sign_with_tweaked_key_util,
    };
    #[cfg(feature = "wallet")]
    pub use cdk_spilman::{
        complete_funding_swap, construct_proofs, create_plain_blinded_messages,
        mint_proofs_from_mint,
    };
}

/// Compatibility re-exports for the server bridge types and traits.
pub mod bridge {
    pub use cdk_spilman::{
        unblind_and_verify_stage1_response, BridgeError, BridgeErrorResponse, ChannelFunding,
        ChannelPolicy, ChannelState, CloseData, CloseError, ClosePreparationError, CloseSuccess,
        ClosingData, FundChannelResult, PaymentProof, PaymentSuccess, PaymentValidationResult,
        PreparedClose, SpilmanAsyncNetworking, SpilmanBridge, SpilmanHost, SpilmanNetworking,
        UnblindResult,
    };
}

/// Compatibility re-exports for the client bridge API.
pub mod client_bridge {
    pub use cdk_spilman::{
        base64_decode, ChannelData, ClientChannelInfo, OpenChannelResult, SpilmanClientBridge,
        SpilmanClientHost,
    };
}

/// Compatibility re-exports for deterministic output construction types.
pub mod deterministic {
    pub use cdk_spilman::{
        CommitmentOutputs, DeterministicOutputsForOneContext, DeterministicSecretWithBlinding,
        MintConnection,
    };
}

/// Compatibility re-exports for established channel state.
pub mod established_channel {
    pub use cdk_spilman::EstablishedChannel;
}

/// Compatibility re-exports for keyset metadata helpers.
pub mod keysets_and_amounts {
    pub use cdk_spilman::{KeysetInfo, OrderedListOfAmounts};
}

/// Compatibility re-exports for channel parameter types and helpers.
pub mod params {
    pub use cdk_spilman::{compute_channel_secret, ChannelId, ChannelParameters};
}

/// Compatibility re-exports for sender-side channel helpers.
pub mod sender_and_receiver {
    pub use cdk_spilman::{
        verify_valid_channel, ChannelVerificationError, ChannelVerificationResult,
        SpilmanChannelSender,
    };
}

#[cfg(test)]
mod tests;
