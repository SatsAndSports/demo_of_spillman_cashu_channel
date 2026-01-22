package spilman

/*
#cgo LDFLAGS: -L../../../target/debug -lcdk_spilman_go -lpthread -ldl -lm
#include <stdlib.h>
#include <stdint.h>

typedef struct {
    char* data;
    char* error;
} CResult;

typedef struct {
    void* user_data;
    int (*receiver_key_is_acceptable)(void*, const char*);
    int (*mint_and_keyset_is_acceptable)(void*, const char*, const char*);
    int (*get_funding_and_params)(void*, const char*, char**, char**, char**, char**);
    void (*save_funding)(void*, const char*, const char*, const char*, const char*, const char*);
    uint64_t (*get_amount_due)(void*, const char*, const char*);
    void (*record_payment)(void*, const char*, uint64_t, const char*, const char*);
    int (*is_closed)(void*, const char*);
    char* (*get_channel_policy)(void*);
    uint64_t (*now_seconds)(void*);
    int (*get_balance_and_signature_for_unilateral_exit)(void*, const char*, uint64_t*, char**);
    char* (*get_active_keyset_ids)(void*, const char*, const char*);
    char* (*get_keyset_info)(void*, const char*, const char*);
} SpilmanHostCallbacks;

// Function declarations from gateway.c and Rust
SpilmanHostCallbacks fill_callbacks(void* user_data);
void* spilman_bridge_new(SpilmanHostCallbacks callbacks, const char* server_secret_key_hex);
void spilman_bridge_free(void* ptr);
CResult spilman_bridge_process_payment(void* ptr, const char* payment_json, const char* context_json);
CResult spilman_bridge_create_close_data(void* ptr, const char* payment_json);
CResult spilman_bridge_create_unilateral_close_data(void* ptr, const char* channel_id);
void spilman_free_string(char* ptr);
void spilman_free_cresult(CResult res);

CResult spilman_generate_keypair();
CResult spilman_secret_key_to_pubkey(const char* secret_hex);
CResult spilman_compute_shared_secret(const char* my_secret_hex, const char* their_pubkey_hex);
CResult spilman_unblind_and_verify_dleq(const char* sigs, const char* secrets, const char* params, const char* keyset, const char* shared_secret, uint64_t balance, const char* output_keyset);
CResult spilman_create_signed_balance_update(const char* params, const char* keyset, const char* secret, const char* proofs, uint64_t balance);
CResult spilman_channel_parameters_get_channel_id(const char* params, const char* shared_secret, const char* keyset);
CResult spilman_create_funding_outputs(const char* params, const char* alice_secret, const char* keyset);
CResult spilman_construct_proofs(const char* blind_signatures, const char* secrets_with_blinding, const char* keyset);
*/
import "C"
import (
	"encoding/json"
	"errors"
	"runtime/cgo"
	"unsafe"
)

// SpilmanHost is the interface that the Go application must implement to handle
// channel persistence and policy.
type SpilmanHost interface {
	ReceiverKeyIsAcceptable(pubkeyHex string) bool
	MintAndKeysetIsAcceptable(mint string, keysetId string) bool
	GetFundingAndParams(channelId string) (paramsJson, proofsJson, sharedSecretHex, keysetInfoJson string, ok bool)
	SaveFunding(channelId, paramsJson, proofsJson, sharedSecretHex, keysetInfoJson string)
	GetAmountDue(channelId string, contextJson *string) uint64
	RecordPayment(channelId string, balance uint64, signature, contextJson string)
	IsClosed(channelId string) bool
	GetChannelPolicy() string
	NowSeconds() uint64
	GetBalanceAndSignatureForUnilateralExit(channelId string) (balance uint64, signature string, ok bool)
	GetActiveKeysetIds(mint, unit string) []string
	GetKeysetInfo(mint, keysetId string) (string, bool)
}

type Bridge struct {
	ptr    unsafe.Pointer
	handle cgo.Handle
}

func NewBridge(host SpilmanHost, serverSecretKeyHex string) *Bridge {
	handle := cgo.NewHandle(host)
	callbacks := C.fill_callbacks(unsafe.Pointer(handle))

	var cSecret *C.char
	if serverSecretKeyHex != "" {
		cSecret = C.CString(serverSecretKeyHex)
		defer C.free(unsafe.Pointer(cSecret))
	}

	ptr := C.spilman_bridge_new(callbacks, cSecret)
	return &Bridge{ptr: ptr, handle: handle}
}

func (b *Bridge) Free() {
	if b.ptr != nil {
		C.spilman_bridge_free(b.ptr)
		b.ptr = nil
	}
	b.handle.Delete()
}

func (b *Bridge) ProcessPayment(paymentJson, contextJson string) (string, error) {
	cPayment := C.CString(paymentJson)
	defer C.free(unsafe.Pointer(cPayment))
	cContext := C.CString(contextJson)
	defer C.free(unsafe.Pointer(cContext))

	res := C.spilman_bridge_process_payment(b.ptr, cPayment, cContext)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

func (b *Bridge) CreateCloseData(paymentJson string) (string, error) {
	cPayment := C.CString(paymentJson)
	defer C.free(unsafe.Pointer(cPayment))

	res := C.spilman_bridge_create_close_data(b.ptr, cPayment)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

func (b *Bridge) CreateUnilateralCloseData(channelId string) (string, error) {
	cId := C.CString(channelId)
	defer C.free(unsafe.Pointer(cId))

	res := C.spilman_bridge_create_unilateral_close_data(b.ptr, cId)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

// Client functions

func GenerateKeypair() (secret, pubkey string, err error) {
	res := C.spilman_generate_keypair()
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", "", errors.New(C.GoString(res.error))
	}

	var data struct {
		Secret string `json:"secret"`
		Pubkey string `json:"pubkey"`
	}
	if err := json.Unmarshal([]byte(C.GoString(res.data)), &data); err != nil {
		return "", "", err
	}
	return data.Secret, data.Pubkey, nil
}

func SecretKeyToPubkey(secretHex string) (string, error) {
	cSecret := C.CString(secretHex)
	defer C.free(unsafe.Pointer(cSecret))

	res := C.spilman_secret_key_to_pubkey(cSecret)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

func ComputeSharedSecret(mySecretHex, theirPubkeyHex string) (string, error) {
	cSecret := C.CString(mySecretHex)
	defer C.free(unsafe.Pointer(cSecret))
	cPubkey := C.CString(theirPubkeyHex)
	defer C.free(unsafe.Pointer(cPubkey))

	res := C.spilman_compute_shared_secret(cSecret, cPubkey)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

func UnblindAndVerifyDleq(sigs, secrets, params, keyset, sharedSecret string, balance uint64, outputKeyset *string) (string, error) {
	cSigs := C.CString(sigs)
	defer C.free(unsafe.Pointer(cSigs))
	cSecrets := C.CString(secrets)
	defer C.free(unsafe.Pointer(cSecrets))
	cParams := C.CString(params)
	defer C.free(unsafe.Pointer(cParams))
	cKeyset := C.CString(keyset)
	defer C.free(unsafe.Pointer(cKeyset))
	cSecret := C.CString(sharedSecret)
	defer C.free(unsafe.Pointer(cSecret))

	var cOutputKeyset *C.char
	if outputKeyset != nil {
		cOutputKeyset = C.CString(*outputKeyset)
		defer C.free(unsafe.Pointer(cOutputKeyset))
	}

	res := C.spilman_unblind_and_verify_dleq(cSigs, cSecrets, cParams, cKeyset, cSecret, C.uint64_t(balance), cOutputKeyset)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

func CreateSignedBalanceUpdate(params, keyset, secret, proofs string, balance uint64) (string, error) {
	cParams := C.CString(params)
	defer C.free(unsafe.Pointer(cParams))
	cKeyset := C.CString(keyset)
	defer C.free(unsafe.Pointer(cKeyset))
	cSecret := C.CString(secret)
	defer C.free(unsafe.Pointer(cSecret))
	cProofs := C.CString(proofs)
	defer C.free(unsafe.Pointer(cProofs))

	res := C.spilman_create_signed_balance_update(cParams, cKeyset, cSecret, cProofs, C.uint64_t(balance))
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

func ChannelParametersGetChannelId(params, sharedSecret, keyset string) (string, error) {
	cParams := C.CString(params)
	defer C.free(unsafe.Pointer(cParams))
	cSecret := C.CString(sharedSecret)
	defer C.free(unsafe.Pointer(cSecret))
	cKeyset := C.CString(keyset)
	defer C.free(unsafe.Pointer(cKeyset))

	res := C.spilman_channel_parameters_get_channel_id(cParams, cSecret, cKeyset)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

func CreateFundingOutputs(params, aliceSecret, keyset string) (string, error) {
	cParams := C.CString(params)
	defer C.free(unsafe.Pointer(cParams))
	cSecret := C.CString(aliceSecret)
	defer C.free(unsafe.Pointer(cSecret))
	cKeyset := C.CString(keyset)
	defer C.free(unsafe.Pointer(cKeyset))

	res := C.spilman_create_funding_outputs(cParams, cSecret, cKeyset)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

func ConstructProofs(blindSignatures, secretsWithBlinding, keyset string) (string, error) {
	cSigs := C.CString(blindSignatures)
	defer C.free(unsafe.Pointer(cSigs))
	cSecrets := C.CString(secretsWithBlinding)
	defer C.free(unsafe.Pointer(cSecrets))
	cKeyset := C.CString(keyset)
	defer C.free(unsafe.Pointer(cKeyset))

	res := C.spilman_construct_proofs(cSigs, cSecrets, cKeyset)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

// --- Callbacks Implementation ---

//export go_receiver_key_is_acceptable
func go_receiver_key_is_acceptable(userData unsafe.Pointer, pubkeyHex *C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	if host.ReceiverKeyIsAcceptable(C.GoString(pubkeyHex)) {
		return 1
	}
	return 0
}

//export go_mint_and_keyset_is_acceptable
func go_mint_and_keyset_is_acceptable(userData unsafe.Pointer, mint *C.char, keysetId *C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	if host.MintAndKeysetIsAcceptable(C.GoString(mint), C.GoString(keysetId)) {
		return 1
	}
	return 0
}

//export go_get_funding_and_params
func go_get_funding_and_params(userData unsafe.Pointer, channelId *C.char, paramsOut **C.char, proofsOut **C.char, secretOut **C.char, keysetOut **C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	p, pr, s, k, ok := host.GetFundingAndParams(C.GoString(channelId))
	if !ok {
		return 0
	}
	*paramsOut = C.CString(p)
	*proofsOut = C.CString(pr)
	*secretOut = C.CString(s)
	*keysetOut = C.CString(k)
	return 1
}

//export go_save_funding
func go_save_funding(userData unsafe.Pointer, channelId *C.char, paramsJson *C.char, fundingProofsJson *C.char, sharedSecretHex *C.char, keysetInfoJson *C.char) {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	host.SaveFunding(C.GoString(channelId), C.GoString(paramsJson), C.GoString(fundingProofsJson), C.GoString(sharedSecretHex), C.GoString(keysetInfoJson))
}

//export go_get_amount_due
func go_get_amount_due(userData unsafe.Pointer, channelId *C.char, contextJson *C.char) C.uint64_t {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	var ctx *string
	if contextJson != nil {
		s := C.GoString(contextJson)
		ctx = &s
	}
	return C.uint64_t(host.GetAmountDue(C.GoString(channelId), ctx))
}

//export go_record_payment
func go_record_payment(userData unsafe.Pointer, channelId *C.char, balance C.uint64_t, signature *C.char, contextJson *C.char) {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	host.RecordPayment(C.GoString(channelId), uint64(balance), C.GoString(signature), C.GoString(contextJson))
}

//export go_is_closed
func go_is_closed(userData unsafe.Pointer, channelId *C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	if host.IsClosed(C.GoString(channelId)) {
		return 1
	}
	return 0
}

//export go_get_channel_policy
func go_get_channel_policy(userData unsafe.Pointer) *C.char {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	return C.CString(host.GetChannelPolicy())
}

//export go_now_seconds
func go_now_seconds(userData unsafe.Pointer) C.uint64_t {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	return C.uint64_t(host.NowSeconds())
}

//export go_get_balance_and_signature_for_unilateral_exit
func go_get_balance_and_signature_for_unilateral_exit(userData unsafe.Pointer, channelId *C.char, balanceOut *C.uint64_t, signatureOut **C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	balance, signature, ok := host.GetBalanceAndSignatureForUnilateralExit(C.GoString(channelId))
	if !ok {
		return 0
	}
	*balanceOut = C.uint64_t(balance)
	*signatureOut = C.CString(signature)
	return 1
}

//export go_get_active_keyset_ids
func go_get_active_keyset_ids(userData unsafe.Pointer, mint *C.char, unit *C.char) *C.char {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	ids := host.GetActiveKeysetIds(C.GoString(mint), C.GoString(unit))
	jsonBytes, _ := json.Marshal(ids)
	return C.CString(string(jsonBytes))
}

//export go_get_keyset_info
func go_get_keyset_info(userData unsafe.Pointer, mint *C.char, keysetId *C.char) *C.char {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	info, ok := host.GetKeysetInfo(C.GoString(mint), C.GoString(keysetId))
	if !ok {
		return nil
	}
	return C.CString(info)
}
