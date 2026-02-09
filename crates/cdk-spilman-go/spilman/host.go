package spilman

// SpilmanHost is the interface that the Go application must implement to handle
// channel persistence and policy decisions.
//
// The bridge calls these methods to:
// - Validate incoming requests (ReceiverKeyIsAcceptable, MintAndKeysetIsAcceptable)
// - Store and retrieve channel data (GetFundingAndParams, SaveFunding, etc.)
// - Determine pricing (GetAmountDue, GetChannelPolicy)
// - Communicate with the mint (CallMintSwap, RefreshActiveKeysets)
// - Track channel lifecycle (GetChannelState, MarkChannelClosing, MarkChannelClosed)
type SpilmanHost interface {
	// ReceiverKeyIsAcceptable returns true if the given receiver public key is acceptable.
	// Typically, you would check if the pubkey matches your server's expected receiver key.
	ReceiverKeyIsAcceptable(pubkeyHex string) bool

	// MintAndKeysetIsAcceptable returns true if the given mint URL and keyset ID are acceptable.
	// Use this to restrict which mints and keysets your server will accept payments from.
	MintAndKeysetIsAcceptable(mint string, keysetId string) bool

	// GetFundingAndParams retrieves stored channel data for an existing channel.
	// Returns (paramsJson, proofsJson, channelSecretHex, keysetInfoJson, true) if found,
	// or ("", "", "", "", false) if the channel is not known.
	GetFundingAndParams(channelId string) (paramsJson, proofsJson, channelSecretHex, keysetInfoJson string, ok bool)

	// SaveFunding stores channel data when a new channel is registered.
	// Called after validating the initial funding (balance=0 signature).
	SaveFunding(channelId, paramsJson, proofsJson, channelSecretHex, keysetInfoJson string, initialBalance uint64, initialSignature string)

	// GetAmountDue returns the amount owed for a request on the given channel.
	// contextJson contains request-specific data (e.g., the requested resource).
	// This is where you implement your pricing logic.
	GetAmountDue(channelId string, contextJson *string) uint64

	// RecordPayment is called after a payment is validated and accepted.
	// Store the new balance and signature for potential unilateral close.
	RecordPayment(channelId string, balance uint64, signature, contextJson string)

	// GetChannelState returns the current state of a channel.
	// Must return one of: "open", "closing", or "closed".
	GetChannelState(channelId string) string

	// MarkChannelClosing marks a channel as being in the CLOSING state (pre-swap).
	// This is called when a cooperative close is initiated but before the swap completes.
	MarkChannelClosing(channelId string, locktime, balance uint64, signature string) error

	// GetClosingData returns the closing data for a channel in CLOSING state.
	// Returns nil if the channel is not in CLOSING state.
	GetClosingData(channelId string) *ClosingData

	// GetChannelPolicy returns the server's channel policy as a JSON string.
	// The policy includes min_locktime, min_capacity, pricing, etc.
	GetChannelPolicy() string

	// NowSeconds returns the current Unix timestamp in seconds.
	// Used for locktime validation.
	NowSeconds() uint64

	// GetBalanceAndSignatureForUnilateralExit retrieves the last recorded payment
	// for unilateral close. Returns (balance, signature, true) if available.
	GetBalanceAndSignatureForUnilateralExit(channelId string) (balance uint64, signature string, ok bool)

	// GetActiveKeysetIds returns the active keyset IDs for the given mint and unit.
	// Used to validate that incoming payments use acceptable keysets.
	GetActiveKeysetIds(mint, unit string) []string

	// GetKeysetInfo returns the keyset info JSON for the given mint and keyset ID.
	// Returns ("", false) if the keyset is not known.
	GetKeysetInfo(mint, keysetId string) (string, bool)

	// CallMintSwap submits a swap request to the mint and returns the response.
	// This is called during channel close to exchange the channel proofs for new proofs.
	CallMintSwap(mintUrl, swapRequestJson string) (string, error)

	// RefreshActiveKeysets fetches and caches the active keysets from the mint.
	// Called when a keyset is not found in the local cache.
	RefreshActiveKeysets(mintUrl string) error

	// MarkChannelClosed marks a channel as fully CLOSED after a successful swap.
	// Called with the final proof distribution for record-keeping.
	MarkChannelClosed(channelId string, locktime, balance uint64, receiverProofsJson, senderProofsJson string, receiverSum, senderSum uint64) error
}

// ClosingData holds the pre-swap state for a channel in CLOSING state.
// This is used to resume a close operation if the initial swap attempt failed.
type ClosingData struct {
	Locktime  uint64
	Balance   uint64
	Signature string
}
