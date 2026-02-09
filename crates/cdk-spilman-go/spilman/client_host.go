package spilman

// SpilmanClientHost is the interface that client applications must implement
// to provide mint communication and channel storage for the client bridge.
//
// This is the client-side counterpart of the server-side SpilmanHost interface.
// It has only 5 methods compared to the server's 17, because clients don't need
// pricing policy, payment validation, or close orchestration.
type SpilmanClientHost interface {
	// CallMintSwap executes a swap with the mint.
	// Posts swapRequestJSON to {mintURL}/v1/swap and returns the response body.
	// Returns the response JSON string on success, or an error.
	CallMintSwap(mintURL, swapRequestJSON string) (string, error)

	// SaveChannel persists channel state.
	// The channelJSON is an opaque JSON blob managed by the bridge.
	SaveChannel(channelID, channelJSON string)

	// GetChannel retrieves channel state by channel ID.
	// Returns nil if the channel is not found.
	GetChannel(channelID string) *string

	// ListChannelIDs returns all stored channel IDs.
	ListChannelIDs() []string

	// DeleteChannel removes a channel from storage.
	DeleteChannel(channelID string)

	// SignWithTweakedKey signs a message with a tweaked key (BIP-340 Schnorr).
	//
	// The bridge computes the tweak (P2BK blinding scalar) and message hash,
	// then asks the host to produce a signature using (secret + tweak) where
	// secret is the key corresponding to signerPubkeyHex.
	//
	// For hosts that hold raw secret keys, use SignWithTweakedKeyUtil() as
	// a convenience implementation.
	//
	// Arguments:
	//   signerPubkeyHex: identifies which key to use (Alice's pubkey for this channel)
	//   messageHex: SHA-256 hash of the SIG_ALL message (32 bytes, hex)
	//   tweakScalarHex: P2BK blinding scalar to add to secret key (32 bytes, hex)
	//
	// Returns the BIP-340 Schnorr signature (64 bytes, hex).
	SignWithTweakedKey(signerPubkeyHex, messageHex, tweakScalarHex string) (string, error)
}

// OpenChannelResult contains the result of opening a new channel.
type OpenChannelResult struct {
	ChannelID          string `json:"channel_id"`
	Capacity           uint64 `json:"capacity"`
	FundingTokenAmount uint64 `json:"funding_token_amount"`
	MintURL            string `json:"mint_url"`
}

// ClientChannelInfo contains information about a stored channel.
type ClientChannelInfo struct {
	ChannelID          string `json:"channel_id"`
	Capacity           uint64 `json:"capacity"`
	FundingTokenAmount uint64 `json:"funding_token_amount"`
	MintURL            string `json:"mint_url"`
	ParamsJSON         string `json:"params_json"`
}
