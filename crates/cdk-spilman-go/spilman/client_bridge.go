package spilman

// Client bridge uses the Rust SpilmanClientBridge via CGO.
// C type CResult is already declared in bridge.go's CGO preamble.
// SpilmanClientHostCallbacks is declared in client_gateway.c.
// We declare only the new function prototypes here.

/*
#include <stdlib.h>
#include "client_bridge_types.h"

// From client_gateway.c
SpilmanClientHostCallbacks fill_client_callbacks(void* user_data);

// From Rust FFI (cdk-spilman-go/src/lib.rs)
void* spilman_client_bridge_new(SpilmanClientHostCallbacks callbacks, const char* alice_secret_hex);
void spilman_client_bridge_free(void* ptr);
char* spilman_client_bridge_alice_pubkey_hex(void* ptr);
char* spilman_client_bridge_alice_secret_hex(void* ptr);
void spilman_client_bridge_remove_channel(void* ptr, const char* channel_id);
void spilman_free_string(char* ptr);
*/
import "C"
import (
	"encoding/json"
	"errors"
	"runtime/cgo"
	"unsafe"
)

// freeClientCResult frees the data and error fields of a CResult returned by client bridge functions.
// We can't reference CResult type from bridge.go's preamble, so client bridge methods
// call the Rust FFI directly and manage memory manually.

// ClientBridge is the main entry point for client-side Spilman channel operations.
// It wraps the Rust SpilmanClientBridge and delegates storage/network to a SpilmanClientHost.
//
// One ClientBridge uses a single Alice keypair for all channels.
type ClientBridge struct {
	ptr    unsafe.Pointer
	handle cgo.Handle
	freed  bool
}

// NewClientBridge creates a new ClientBridge with the given host implementation.
// If aliceSecretHex is nil or empty, a new keypair is generated.
func NewClientBridge(host SpilmanClientHost, aliceSecretHex *string) (*ClientBridge, error) {
	handle := cgo.NewHandle(host)
	callbacks := C.fill_client_callbacks(unsafe.Pointer(handle)) //nolint:govet

	var cSecret *C.char
	if aliceSecretHex != nil && *aliceSecretHex != "" {
		cSecret = C.CString(*aliceSecretHex)
		defer C.free(unsafe.Pointer(cSecret))
	}

	ptr := C.spilman_client_bridge_new(callbacks, cSecret)
	if ptr == nil {
		handle.Delete()
		return nil, errors.New("failed to create client bridge")
	}
	return &ClientBridge{ptr: ptr, handle: handle}, nil
}

// Free releases the resources held by the ClientBridge.
// Must be called when the ClientBridge is no longer needed.
// Safe to call multiple times.
func (b *ClientBridge) Free() {
	if b.freed {
		return
	}
	b.freed = true
	if b.ptr != nil {
		C.spilman_client_bridge_free(b.ptr)
		b.ptr = nil
	}
	b.handle.Delete()
}

// AlicePubkeyHex returns Alice's public key (hex-encoded, compressed).
// Give this to the server when setting up a channel.
func (b *ClientBridge) AlicePubkeyHex() string {
	ptr := C.spilman_client_bridge_alice_pubkey_hex(b.ptr)
	defer C.spilman_free_string(ptr)
	return C.GoString(ptr)
}

// AliceSecretHex returns Alice's secret key (hex-encoded).
// Needed for persistence/restoration of the bridge.
func (b *ClientBridge) AliceSecretHex() string {
	ptr := C.spilman_client_bridge_alice_secret_hex(b.ptr)
	defer C.spilman_free_string(ptr)
	return C.GoString(ptr)
}

// OpenChannelFromToken opens a new channel from a Cashu token.
//
// This performs the full funding flow:
//  1. Parse the token and compute channel parameters
//  2. Create a funding swap request (deterministic 2-of-2 locked outputs)
//  3. Submit the swap to the mint via host.CallMintSwap()
//  4. Unblind signatures and verify DLEQ proofs
//  5. Save the channel via host.SaveChannel()
func (b *ClientBridge) OpenChannelFromToken(token, charliePubkeyHex string, locktime uint64, keysetInfoJSON string, maxAmount uint64) (*OpenChannelResult, error) {
	return clientBridgeOpenChannel(b.ptr, token, charliePubkeyHex, locktime, keysetInfoJSON, maxAmount)
}

// SignBalanceUpdate creates a signed balance update for a channel.
// Returns JSON with {channel_id, amount, signature}.
func (b *ClientBridge) SignBalanceUpdate(channelID string, balance uint64) (string, error) {
	return clientBridgeSignBalanceUpdate(b.ptr, channelID, balance)
}

// BuildPaymentHeader builds a complete X-Cashu-Channel payment header value.
// Returns a base64-encoded JSON string ready to use as the header value.
//
// If includeFunding is true, the header includes params and funding_proofs
// (needed for the first request, or when the server doesn't know this channel yet).
func (b *ClientBridge) BuildPaymentHeader(channelID string, balance uint64, includeFunding bool) (string, error) {
	return clientBridgeBuildPaymentHeader(b.ptr, channelID, balance, includeFunding)
}

// GetChannelInfo returns information about a stored channel.
// Returns nil if the channel is not found.
func (b *ClientBridge) GetChannelInfo(channelID string) *ClientChannelInfo {
	return clientBridgeGetChannelInfo(b.ptr, channelID)
}

// ListChannels returns all stored channel IDs.
func (b *ClientBridge) ListChannels() []string {
	return clientBridgeListChannels(b.ptr)
}

// RemoveChannel removes a channel from storage.
func (b *ClientBridge) RemoveChannel(channelID string) {
	cID := C.CString(channelID)
	defer C.free(unsafe.Pointer(cID))
	C.spilman_client_bridge_remove_channel(b.ptr, cID)
}

// --- Client Host Callbacks Implementation ---
// These are exported to C and called by the Rust client bridge via client_gateway.c

//export go_client_call_mint_swap
func go_client_call_mint_swap(userData unsafe.Pointer, mintURL *C.char, swapRequestJSON *C.char, responseOut **C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	resp, err := host.CallMintSwap(C.GoString(mintURL), C.GoString(swapRequestJSON))
	if err != nil {
		*responseOut = C.CString(err.Error())
		return 0
	}
	*responseOut = C.CString(resp)
	return 1
}

//export go_client_save_channel
func go_client_save_channel(userData unsafe.Pointer, channelID *C.char, channelJSON *C.char) {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	host.SaveChannel(C.GoString(channelID), C.GoString(channelJSON))
}

//export go_client_get_channel
func go_client_get_channel(userData unsafe.Pointer, channelID *C.char) *C.char {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	result := host.GetChannel(C.GoString(channelID))
	if result == nil {
		return nil
	}
	return C.CString(*result)
}

//export go_client_list_channel_ids
func go_client_list_channel_ids(userData unsafe.Pointer) *C.char {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	ids := host.ListChannelIDs()
	jsonBytes, err := json.Marshal(ids)
	if err != nil {
		return C.CString("[]")
	}
	return C.CString(string(jsonBytes))
}

//export go_client_delete_channel
func go_client_delete_channel(userData unsafe.Pointer, channelID *C.char) {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	host.DeleteChannel(C.GoString(channelID))
}

//export go_client_sign_with_tweaked_key
func go_client_sign_with_tweaked_key(userData unsafe.Pointer, signerPubkeyHex *C.char, messageHex *C.char, tweakScalarHex *C.char, responseOut **C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	resp, err := host.SignWithTweakedKey(C.GoString(signerPubkeyHex), C.GoString(messageHex), C.GoString(tweakScalarHex))
	if err != nil {
		*responseOut = C.CString(err.Error())
		return 0
	}
	*responseOut = C.CString(resp)
	return 1
}
