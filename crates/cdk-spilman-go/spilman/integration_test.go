//go:build integration

package spilman

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

func getMintURL() string {
	if url := os.Getenv("MINT_URL"); url != "" {
		return url
	}
	return "http://localhost:3338"
}

// TestMintConnectivity verifies we can reach the mint
func TestMintConnectivity(t *testing.T) {
	mintURL := getMintURL()
	resp, err := http.Get(mintURL + "/v1/info")
	if err != nil {
		t.Fatalf("Cannot connect to mint at %s: %v", mintURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("Mint returned status %d", resp.StatusCode)
	}

	var info struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	json.NewDecoder(resp.Body).Decode(&info)
	t.Logf("Connected to mint: %s (version %s)", info.Name, info.Version)
}

// TestFundingOutputsAndChannelId tests the client-side channel setup flow.
// This requires a mint to fetch keyset info, but doesn't require minting tokens.
func TestFundingOutputsAndChannelId(t *testing.T) {
	mintURL := getMintURL()

	// 1. Generate sender keypair
	aliceSecret, alicePubkey, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	t.Logf("Generated sender pubkey: %s...", alicePubkey[:16])

	// 2. Generate receiver keypair (normally this comes from the server)
	_, receiverPubkey, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	t.Logf("Generated receiver pubkey: %s...", receiverPubkey[:16])

	// 3. Fetch active keyset from mint
	keysetInfo, err := fetchActiveKeyset(mintURL, "sat")
	if err != nil {
		t.Fatalf("Failed to fetch keyset: %v", err)
	}
	t.Logf("Fetched keyset: %s", keysetInfo["keysetId"])

	keysetJson, _ := json.Marshal(keysetInfo)

	// 4. Compute shared secret
	sharedSecret, err := ComputeSharedSecret(aliceSecret, receiverPubkey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret failed: %v", err)
	}
	t.Logf("Computed shared secret: %s...", sharedSecret[:16])

	// 5. Build channel parameters
	fundingTokenAmount, err := ComputeFundingTokenAmount(uint64(100), string(keysetJson), uint64(64))
	if err != nil {
		t.Fatalf("ComputeFundingTokenAmount failed: %v", err)
	}
	params := map[string]interface{}{
		"alice_pubkey":         alicePubkey,
		"charlie_pubkey":       receiverPubkey,
		"mint":                 mintURL,
		"unit":                 "sat",
		"capacity":             uint64(100),
		"funding_token_amount": fundingTokenAmount,
		"maximum_amount":       uint64(64),
		"locktime":             time.Now().Unix() + 7200,
		"setup_timestamp":      time.Now().Unix(),
		"sender_nonce":         fmt.Sprintf("test-%d", time.Now().UnixNano()),
		"keyset_id":            keysetInfo["keysetId"],
		"input_fee_ppk":        keysetInfo["inputFeePpk"],
	}
	paramsJson, _ := json.Marshal(params)

	// 6. Get channel ID
	channelId, err := ChannelParametersGetChannelId(string(paramsJson), sharedSecret, string(keysetJson))
	if err != nil {
		t.Fatalf("ChannelParametersGetChannelId failed: %v", err)
	}
	t.Logf("Channel ID: %s", channelId)

	// 7. Create funding outputs
	fundingJson, err := CreateFundingOutputs(string(paramsJson), aliceSecret, string(keysetJson))
	if err != nil {
		t.Fatalf("CreateFundingOutputs failed: %v", err)
	}

	var funding struct {
		FundingTokenNominal uint64        `json:"funding_token_nominal"`
		BlindedMessages     []interface{} `json:"blinded_messages"`
	}
	json.Unmarshal([]byte(fundingJson), &funding)

	t.Logf("Funding nominal: %d sat, outputs: %d", funding.FundingTokenNominal, len(funding.BlindedMessages))

	// Verify we got reasonable outputs
	if funding.FundingTokenNominal < 100 {
		t.Errorf("Expected funding >= 100, got %d", funding.FundingTokenNominal)
	}
	if len(funding.BlindedMessages) == 0 {
		t.Error("Expected at least one blinded message")
	}
}

// ============================================================================
// TestClientBridge: end-to-end test of SpilmanClientBridge + server Bridge
// ============================================================================

// testClientHost implements SpilmanClientHost with HTTP swap and in-memory storage.
type testClientHost struct {
	mintURL  string
	mu       sync.Mutex
	channels map[string]string
}

func newTestClientHost(mintURL string) *testClientHost {
	return &testClientHost{
		mintURL:  mintURL,
		channels: make(map[string]string),
	}
}

func (h *testClientHost) CallMintSwap(mintURL, swapRequestJSON string) (string, error) {
	resp, err := http.Post(
		mintURL+"/v1/swap",
		"application/json",
		bytes.NewBufferString(swapRequestJSON),
	)
	if err != nil {
		return "", fmt.Errorf("HTTP error: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("swap failed (HTTP %d): %s", resp.StatusCode, string(body))
	}
	return string(body), nil
}

func (h *testClientHost) SaveChannel(channelID, channelJSON string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.channels[channelID] = channelJSON
}

func (h *testClientHost) GetChannel(channelID string) *string {
	h.mu.Lock()
	defer h.mu.Unlock()
	v, ok := h.channels[channelID]
	if !ok {
		return nil
	}
	return &v
}

func (h *testClientHost) ListChannelIDs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	ids := make([]string, 0, len(h.channels))
	for id := range h.channels {
		ids = append(ids, id)
	}
	return ids
}

func (h *testClientHost) DeleteChannel(channelID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.channels, channelID)
}

// testServerHost implements SpilmanHost for the server-side bridge in tests.
type testServerHost struct {
	keysetID       string
	keysetInfoJSON string
	mu             sync.Mutex
	fundingData    map[string]serverFunding
	payments       map[string]serverPayment
}

type serverFunding struct {
	paramsJSON      string
	proofsJSON      string
	sharedSecretHex string
	keysetInfoJSON  string
}

type serverPayment struct {
	balance   uint64
	signature string
}

func newTestServerHost(keysetID, keysetInfoJSON string) *testServerHost {
	return &testServerHost{
		keysetID:       keysetID,
		keysetInfoJSON: keysetInfoJSON,
		fundingData:    make(map[string]serverFunding),
		payments:       make(map[string]serverPayment),
	}
}

func (h *testServerHost) ReceiverKeyIsAcceptable(pubkeyHex string) bool        { return true }
func (h *testServerHost) MintAndKeysetIsAcceptable(mint, keysetId string) bool { return true }

func (h *testServerHost) GetFundingAndParams(channelId string) (string, string, string, string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f, ok := h.fundingData[channelId]
	if !ok {
		return "", "", "", "", false
	}
	return f.paramsJSON, f.proofsJSON, f.sharedSecretHex, f.keysetInfoJSON, true
}

func (h *testServerHost) SaveFunding(channelId, paramsJSON, proofsJSON, sharedSecretHex, keysetInfoJSON string, initialBalance uint64, initialSignature string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fundingData[channelId] = serverFunding{
		paramsJSON:      paramsJSON,
		proofsJSON:      proofsJSON,
		sharedSecretHex: sharedSecretHex,
		keysetInfoJSON:  keysetInfoJSON,
	}
}

func (h *testServerHost) GetAmountDue(channelId string, contextJson *string) uint64 { return 0 }

func (h *testServerHost) RecordPayment(channelId string, balance uint64, signature, contextJson string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.payments[channelId] = serverPayment{balance: balance, signature: signature}
}

func (h *testServerHost) GetChannelState(channelId string) string { return "open" }

func (h *testServerHost) MarkChannelClosing(channelId string, locktime, balance uint64, signature string) error {
	return nil
}

func (h *testServerHost) GetClosingData(channelId string) *ClosingData { return nil }

func (h *testServerHost) GetChannelPolicy() string {
	return `{"min_expiry_in_seconds":3600,"pricing":{"sat":{"minCapacity":10}}}`
}

func (h *testServerHost) NowSeconds() uint64 { return uint64(time.Now().Unix()) }

func (h *testServerHost) GetBalanceAndSignatureForUnilateralExit(channelId string) (uint64, string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, ok := h.payments[channelId]
	if !ok {
		return 0, "", false
	}
	return p.balance, p.signature, true
}

func (h *testServerHost) GetActiveKeysetIds(mint, unit string) []string {
	return []string{h.keysetID}
}

func (h *testServerHost) GetKeysetInfo(mint, keysetId string) (string, bool) {
	if keysetId == h.keysetID {
		return h.keysetInfoJSON, true
	}
	return "", false
}

func (h *testServerHost) CallMintSwap(mintUrl, swapRequestJson string) (string, error) {
	return "", fmt.Errorf("not used in this test")
}

func (h *testServerHost) RefreshActiveKeysets(mintUrl string) error { return nil }

func (h *testServerHost) MarkChannelClosed(channelId string, locktime, balance uint64, receiverProofsJson, senderProofsJson string, receiverSum, senderSum uint64) error {
	return nil
}

// mintPlainProofs mints plain (non-P2PK) proofs via the mint HTTP API.
// Uses CreatePlainBlindedMessages to create blinded messages, mints them via
// the /v1/mint/bolt11 endpoint (fakewallet auto-pays), and constructs proofs.
// Returns the proofs as a JSON array string.
func mintPlainProofs(t *testing.T, mintURL string, amountSat uint64, keysetInfoJSON string) string {
	t.Helper()

	// 1. Create plain blinded messages
	resultJSON, err := CreatePlainBlindedMessages(amountSat, keysetInfoJSON)
	if err != nil {
		t.Fatalf("CreatePlainBlindedMessages failed: %v", err)
	}

	var result struct {
		BlindedMessages     []interface{} `json:"blinded_messages"`
		SecretsWithBlinding []interface{} `json:"secrets_with_blinding"`
	}
	if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
		t.Fatalf("Failed to parse blinded messages result: %v", err)
	}

	t.Logf("Created %d plain blinded messages", len(result.BlindedMessages))

	// 2. Request a mint quote
	quoteReq, _ := json.Marshal(map[string]interface{}{"amount": amountSat, "unit": "sat"})
	resp, err := http.Post(mintURL+"/v1/mint/quote/bolt11", "application/json", bytes.NewBuffer(quoteReq))
	if err != nil {
		t.Fatalf("Mint quote request failed: %v", err)
	}
	defer resp.Body.Close()

	var quote struct {
		Quote string `json:"quote"`
	}
	json.NewDecoder(resp.Body).Decode(&quote)
	t.Logf("Got mint quote: %s", quote.Quote)

	// 3. Poll until paid (fakewallet auto-pays)
	for i := 0; i < 60; i++ {
		r, err := http.Get(fmt.Sprintf("%s/v1/mint/quote/bolt11/%s", mintURL, quote.Quote))
		if err != nil {
			t.Fatalf("Quote poll failed: %v", err)
		}
		var status struct {
			State string `json:"state"`
		}
		json.NewDecoder(r.Body).Decode(&status)
		r.Body.Close()

		if status.State == "PAID" {
			t.Log("Mint quote is PAID")
			break
		}
		if i == 59 {
			t.Fatal("Timeout waiting for mint quote to be paid")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// 4. Mint tokens
	mintReq, _ := json.Marshal(map[string]interface{}{
		"quote":   quote.Quote,
		"outputs": result.BlindedMessages,
	})
	resp2, err := http.Post(mintURL+"/v1/mint/bolt11", "application/json", bytes.NewBuffer(mintReq))
	if err != nil {
		t.Fatalf("Mint request failed: %v", err)
	}
	defer resp2.Body.Close()

	body, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != 200 {
		t.Fatalf("Mint request failed (HTTP %d): %s", resp2.StatusCode, string(body))
	}

	var mintResp struct {
		Signatures []interface{} `json:"signatures"`
	}
	if err := json.Unmarshal(body, &mintResp); err != nil {
		t.Fatalf("Failed to parse mint response: %v", err)
	}
	t.Logf("Got %d blind signatures from mint", len(mintResp.Signatures))

	// 5. Construct proofs
	sigsJSON, _ := json.Marshal(mintResp.Signatures)
	secretsJSON, _ := json.Marshal(result.SecretsWithBlinding)

	proofsJSON, err := ConstructProofs(string(sigsJSON), string(secretsJSON), keysetInfoJSON)
	if err != nil {
		t.Fatalf("ConstructProofs failed: %v", err)
	}

	return proofsJSON
}

// buildCashuAToken constructs a cashuA token string from proofs JSON.
// The cashuA format is: "cashuA" + base64url(JSON({token:[{mint,proofs}],unit}))
func buildCashuAToken(mintURL, proofsJSON string) string {
	// Parse proofs to get the array
	var proofs []interface{}
	json.Unmarshal([]byte(proofsJSON), &proofs)

	tokenPayload := map[string]interface{}{
		"token": []map[string]interface{}{
			{
				"mint":   mintURL,
				"proofs": proofs,
			},
		},
		"unit": "sat",
	}
	jsonBytes, _ := json.Marshal(tokenPayload)
	return "cashuA" + base64.URLEncoding.EncodeToString(jsonBytes)
}

// TestClientBridge tests the full SpilmanClientBridge end-to-end:
// 1. Mints plain proofs via HTTP
// 2. Constructs a cashuA token
// 3. Opens a channel via ClientBridge.OpenChannelFromToken
// 4. Signs balance updates and builds payment headers
// 5. Validates headers on a server-side Bridge (full round-trip)
func TestClientBridge(t *testing.T) {
	mintURL := getMintURL()

	// ================================================================
	// Setup: fetch keyset, generate keypairs
	// ================================================================

	keysetInfo, err := fetchActiveKeyset(mintURL, "sat")
	if err != nil {
		t.Fatalf("Failed to fetch keyset: %v", err)
	}
	keysetJSON, _ := json.Marshal(keysetInfo)
	keysetID := keysetInfo["keysetId"].(string)
	t.Logf("Using keyset: %s", keysetID)

	// Generate Charlie (server/receiver) keypair
	charlieSecret, charliePubkey, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (charlie) failed: %v", err)
	}
	t.Logf("Charlie pubkey: %s...", charliePubkey[:16])

	// ================================================================
	// Step 1: Mint plain proofs and build cashuA token
	// ================================================================

	proofsJSON := mintPlainProofs(t, mintURL, 100, string(keysetJSON))
	token := buildCashuAToken(mintURL, proofsJSON)
	t.Logf("Built cashuA token: %s...%s", token[:20], token[len(token)-10:])

	// ================================================================
	// Step 2: Create client bridge and open channel
	// ================================================================

	clientHost := newTestClientHost(mintURL)
	clientBridge, err := NewClientBridge(clientHost, nil)
	if err != nil {
		t.Fatalf("NewClientBridge failed: %v", err)
	}
	defer clientBridge.Free()
	t.Logf("Client bridge created, alice_pubkey: %s...", clientBridge.AlicePubkeyHex()[:16])

	locktime := uint64(time.Now().Unix()) + 7200 // 2 hours
	maxAmount := uint64(64)

	openResult, err := clientBridge.OpenChannelFromToken(token, charliePubkey, locktime, string(keysetJSON), maxAmount)
	if err != nil {
		t.Fatalf("OpenChannelFromToken failed: %v", err)
	}

	t.Logf("Channel opened: id=%s, capacity=%d, funding=%d",
		openResult.ChannelID, openResult.Capacity, openResult.FundingTokenAmount)

	if openResult.Capacity == 0 {
		t.Fatal("Capacity should be positive")
	}
	if openResult.Capacity > 100 {
		t.Fatalf("Capacity should not exceed input value, got %d", openResult.Capacity)
	}

	// Verify channel is stored
	channels := clientBridge.ListChannels()
	if len(channels) != 1 {
		t.Fatalf("Expected 1 channel, got %d", len(channels))
	}
	if channels[0] != openResult.ChannelID {
		t.Fatalf("Channel ID mismatch: %s != %s", channels[0], openResult.ChannelID)
	}

	info := clientBridge.GetChannelInfo(openResult.ChannelID)
	if info == nil {
		t.Fatal("GetChannelInfo returned nil")
	}
	if info.Capacity != openResult.Capacity {
		t.Fatalf("Capacity mismatch: %d != %d", info.Capacity, openResult.Capacity)
	}
	t.Log("Channel stored and retrievable")

	// ================================================================
	// Step 3: Sign balance updates
	// ================================================================

	updateJSON, err := clientBridge.SignBalanceUpdate(openResult.ChannelID, 10)
	if err != nil {
		t.Fatalf("SignBalanceUpdate failed: %v", err)
	}

	var update map[string]interface{}
	json.Unmarshal([]byte(updateJSON), &update)

	if update["channel_id"].(string) != openResult.ChannelID {
		t.Fatal("Balance update channel_id mismatch")
	}
	if uint64(update["amount"].(float64)) != 10 {
		t.Fatal("Balance update amount mismatch")
	}
	if _, ok := update["signature"]; !ok {
		t.Fatal("Balance update missing signature")
	}
	t.Log("SignBalanceUpdate returned valid JSON")

	// ================================================================
	// Step 4: Build payment headers
	// ================================================================

	// Header WITH funding (first request to server)
	headerWithFunding, err := clientBridge.BuildPaymentHeader(openResult.ChannelID, 10, true)
	if err != nil {
		t.Fatalf("BuildPaymentHeader (with funding) failed: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(headerWithFunding)
	if err != nil {
		t.Fatalf("Failed to base64 decode header: %v", err)
	}

	var headerJSON map[string]interface{}
	if err := json.Unmarshal(decoded, &headerJSON); err != nil {
		t.Fatalf("Failed to parse header JSON: %v", err)
	}

	if headerJSON["channel_id"].(string) != openResult.ChannelID {
		t.Fatal("Header channel_id mismatch")
	}
	if uint64(headerJSON["balance"].(float64)) != 10 {
		t.Fatal("Header balance mismatch")
	}
	if _, ok := headerJSON["signature"]; !ok {
		t.Fatal("Header missing signature")
	}
	if _, ok := headerJSON["params"]; !ok {
		t.Fatal("Header with funding should include params")
	}
	if _, ok := headerJSON["funding_proofs"]; !ok {
		t.Fatal("Header with funding should include funding_proofs")
	}
	t.Log("Payment header (with funding) is valid")

	// Header WITHOUT funding (subsequent requests)
	headerNoFunding, err := clientBridge.BuildPaymentHeader(openResult.ChannelID, 20, false)
	if err != nil {
		t.Fatalf("BuildPaymentHeader (no funding) failed: %v", err)
	}

	decoded2, err := base64.StdEncoding.DecodeString(headerNoFunding)
	if err != nil {
		t.Fatalf("Failed to base64 decode header: %v", err)
	}

	var headerJSON2 map[string]interface{}
	json.Unmarshal(decoded2, &headerJSON2)

	if uint64(headerJSON2["balance"].(float64)) != 20 {
		t.Fatal("Header balance mismatch")
	}
	if _, ok := headerJSON2["params"]; ok {
		t.Fatal("Header without funding should NOT include params")
	}
	if _, ok := headerJSON2["funding_proofs"]; ok {
		t.Fatal("Header without funding should NOT include funding_proofs")
	}
	t.Log("Payment header (without funding) omits params/proofs")

	// ================================================================
	// Step 5: Server-side validation (end-to-end!)
	// ================================================================

	serverHost := newTestServerHost(keysetID, string(keysetJSON))
	serverBridge := NewBridge(serverHost, charlieSecret)
	if serverBridge == nil {
		t.Fatal("NewBridge returned nil")
	}
	defer serverBridge.Free()

	// First payment: header with funding (server learns about channel)
	paymentResult, err := serverBridge.ProcessPayment(string(decoded), `{"type":"test"}`)
	if err != nil {
		t.Fatalf("Server ProcessPayment (first) failed: %v", err)
	}

	if paymentResult.ChannelID != openResult.ChannelID {
		t.Fatal("Server channel_id mismatch")
	}
	if paymentResult.Balance != 10 {
		t.Fatalf("Server balance mismatch: expected 10, got %d", paymentResult.Balance)
	}
	if paymentResult.Capacity != openResult.Capacity {
		t.Fatalf("Server capacity mismatch: expected %d, got %d", openResult.Capacity, paymentResult.Capacity)
	}
	t.Logf("Server accepted first payment (balance=%d, capacity=%d)",
		paymentResult.Balance, paymentResult.Capacity)

	// Second payment: header without funding (server already knows channel)
	paymentResult2, err := serverBridge.ProcessPayment(string(decoded2), `{"type":"test"}`)
	if err != nil {
		t.Fatalf("Server ProcessPayment (second) failed: %v", err)
	}

	if paymentResult2.Balance != 20 {
		t.Fatalf("Server balance mismatch: expected 20, got %d", paymentResult2.Balance)
	}
	t.Logf("Server accepted second payment (balance=%d)", paymentResult2.Balance)

	// ================================================================
	// Step 6: Remove channel
	// ================================================================

	clientBridge.RemoveChannel(openResult.ChannelID)

	if clientBridge.GetChannelInfo(openResult.ChannelID) != nil {
		t.Fatal("Channel should be removed")
	}
	if len(clientBridge.ListChannels()) != 0 {
		t.Fatal("Channel list should be empty")
	}
	t.Log("Channel removed from storage")

	t.Log("All client bridge tests passed!")
}

// fetchActiveKeyset fetches the active keyset for a unit from the mint
func fetchActiveKeyset(mintURL, unit string) (map[string]interface{}, error) {
	resp, err := http.Get(mintURL + "/v1/keysets")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var keysetsResp struct {
		Keysets []struct {
			Id          string `json:"id"`
			Unit        string `json:"unit"`
			Active      bool   `json:"active"`
			InputFeePpk uint64 `json:"input_fee_ppk"`
		} `json:"keysets"`
	}
	json.NewDecoder(resp.Body).Decode(&keysetsResp)

	var activeId string
	var inputFeePpk uint64
	for _, k := range keysetsResp.Keysets {
		if k.Unit == unit && k.Active {
			activeId = k.Id
			inputFeePpk = k.InputFeePpk
			break
		}
	}
	if activeId == "" {
		return nil, fmt.Errorf("no active %s keyset found", unit)
	}

	// Fetch keys for this keyset
	resp, err = http.Get(fmt.Sprintf("%s/v1/keys/%s", mintURL, activeId))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var keysResp struct {
		Keysets []struct {
			Keys map[string]string `json:"keys"`
		} `json:"keysets"`
	}
	json.Unmarshal(body, &keysResp)

	return map[string]interface{}{
		"keysetId":    activeId,
		"unit":        unit,
		"inputFeePpk": inputFeePpk,
		"keys":        keysResp.Keysets[0].Keys,
	}, nil
}
