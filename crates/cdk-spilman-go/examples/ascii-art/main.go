package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cashubtc/spilman-go/spilman"
	"github.com/common-nighthawk/go-figure"
	"github.com/skip2/go-qrcode"
)

// ============================================================================
// Configuration & Common
// ============================================================================

const (
	MINT_URL_DEFAULT   = "http://localhost:3338"
	SERVER_URL_DEFAULT = "http://localhost:5001"
	PORT               = 5001
)

// Pricing per character for each unit (superset — filtered dynamically by active mint keysets)
// usd has MaxAmountPerOutput to test enforcement of maximum_amount policy
type UnitPricing struct {
	PerChar            int  `json:"per_char"`
	MinCapacity        int  `json:"minCapacity"`
	MaxAmountPerOutput *int `json:"maxAmountPerOutput,omitempty"`
}

var maxAmountPerOutputUsd = 64
var allPricing = map[string]UnitPricing{
	"sat":  {PerChar: 1, MinCapacity: 10},
	"msat": {PerChar: 1000, MinCapacity: 10000},                                       // 1 sat = 1000 msat
	"usd":  {PerChar: 1, MinCapacity: 10, MaxAmountPerOutput: &maxAmountPerOutputUsd}, // 1 cent per char, max 64 per output
}

// getActivePricing returns pricing filtered to only units with active keysets
func getActivePricing() map[string]UnitPricing {
	keysetCacheMu.RLock()
	defer keysetCacheMu.RUnlock()
	activeUnits := map[string]bool{}
	for _, entry := range keysetCache {
		if entry.Active {
			activeUnits[entry.Unit] = true
		}
	}
	result := map[string]UnitPricing{}
	for unit, pricing := range allPricing {
		if activeUnits[unit] {
			result[unit] = pricing
		}
	}
	return result
}

// getMintsUnitsKeysets returns {mintUrl: {unit: [keysetId, ...]}} for all active keysets
func getMintsUnitsKeysets() map[string]map[string][]string {
	keysetCacheMu.RLock()
	defer keysetCacheMu.RUnlock()
	result := map[string]map[string][]string{}
	for kid, entry := range keysetCache {
		if !entry.Active {
			continue
		}
		// keysetCache key is just keysetId; we need to find the mint
		// Since we only support one mint, use MINT_URL
		mint := MINT_URL
		if result[mint] == nil {
			result[mint] = map[string][]string{}
		}
		result[mint][entry.Unit] = append(result[mint][entry.Unit], kid)
	}
	return result
}

// getPricePerChar returns the per_char price for a given unit
func getPricePerChar(unit string) uint64 {
	if p, ok := allPricing[unit]; ok {
		return uint64(p.PerChar)
	}
	return uint64(allPricing["sat"].PerChar)
}

var (
	MINT_URL          = getEnv("MINT_URL", MINT_URL_DEFAULT)
	SERVER_URL        = getEnv("SERVER_URL", SERVER_URL_DEFAULT)
	SERVER_PORT       = getEnv("PORT", "5001")
	SERVER_SECRET_KEY = getEnv("SERVER_SECRET_KEY", "0000000000000000000000000000000000000000000000000000000000000001")
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func normalizeUrl(url string) string {
	return strings.TrimSuffix(url, "/")
}

// ============================================================================
// Server State & Storage
// ============================================================================

type KeysetCacheEntry struct {
	InfoJson string
	Active   bool
	Unit     string
}

// ClosingChannelData holds the pre-swap state for a channel in CLOSING state
type ClosingChannelData struct {
	Locktime  uint64
	Balance   uint64
	Signature string
}

var (
	// In-memory data stores
	channelFunding = make(map[string]map[string]string)
	channelBalance = make(map[string]map[string]interface{})
	channelUsage   = make(map[string]map[string]uint64)
	channelClosing = make(map[string]*ClosingChannelData)
	channelClosed  = make(map[string]interface{})
	keysetCache    = make(map[string]KeysetCacheEntry)
	keysetCacheMu  sync.RWMutex
	mu             sync.Mutex
)

// ============================================================================
// Spilman Host Implementation
// ============================================================================

type AsciiArtHost struct {
	pubkey string
}

func (h *AsciiArtHost) ReceiverKeyIsAcceptable(pubkeyHex string) bool {
	result := strings.ToLower(pubkeyHex) == strings.ToLower(h.pubkey)
	log.Printf("  [Host] ReceiverKeyIsAcceptable: received=%s, expected=%s, result=%v\n",
		pubkeyHex[:16], h.pubkey[:16], result)
	return result
}

func (h *AsciiArtHost) MintAndKeysetIsAcceptable(mint string, keysetId string) bool {
	normMint := normalizeUrl(mint)
	normConfig := normalizeUrl(MINT_URL)
	log.Printf("  [Host] MintAndKeysetIsAcceptable: mint=%s (norm=%s), configured=%s (norm=%s)\n", mint, normMint, MINT_URL, normConfig)
	return normMint == normConfig
}

func (h *AsciiArtHost) GetFundingAndParams(channelId string) (string, string, string, string, bool) {
	log.Printf("  [Host] GetFundingAndParams for %s\n", channelId[:8])
	mu.Lock()
	defer mu.Unlock()
	data, ok := channelFunding[channelId]
	if !ok {
		return "", "", "", "", false
	}
	return data["params"], data["proofs"], data["secret"], data["keyset"], true
}

func (h *AsciiArtHost) SaveFunding(channelId, paramsJson, proofsJson, sharedSecretHex, keysetInfoJson string, initialBalance uint64, initialSignature string) {
	log.Printf("  [Host] SaveFunding for %s\n", channelId[:8])
	mu.Lock()
	defer mu.Unlock()
	channelFunding[channelId] = map[string]string{
		"params": paramsJson,
		"proofs": proofsJson,
		"secret": sharedSecretHex,
		"keyset": keysetInfoJson,
	}
	// Store the initial balance/signature for closing
	current := channelBalance[channelId]
	if current == nil || initialBalance > current["balance"].(uint64) {
		channelBalance[channelId] = map[string]interface{}{
			"balance":   initialBalance,
			"signature": initialSignature,
		}
	}
	log.Printf("  [Host] Saved funding for channel %s\n", channelId[:8])
}

func (h *AsciiArtHost) GetAmountDue(channelId string, contextJson *string) uint64 {
	log.Printf("  [Host] GetAmountDue for %s\n", channelId[:8])
	mu.Lock()
	defer mu.Unlock()

	usage := channelUsage[channelId]
	if usage == nil {
		usage = make(map[string]uint64)
	}

	totalChars := usage["chars"]

	if contextJson != nil {
		var context struct {
			MessageLength int `json:"message_length"`
		}
		json.Unmarshal([]byte(*contextJson), &context)
		totalChars += uint64(context.MessageLength)
	}

	// Look up unit from stored channel params
	pricePerChar := uint64(allPricing["sat"].PerChar) // default
	if funding, ok := channelFunding[channelId]; ok {
		var params struct {
			Unit string `json:"unit"`
		}
		json.Unmarshal([]byte(funding["params"]), &params)
		if params.Unit != "" {
			pricePerChar = getPricePerChar(params.Unit)
		}
	}
	return totalChars * pricePerChar
}

func (h *AsciiArtHost) RecordPayment(channelId string, balance uint64, signature, contextJson string) {
	log.Printf("  [Host] RecordPayment for %s, balance=%d\n", channelId[:8], balance)
	mu.Lock()
	defer mu.Unlock()

	var context struct {
		MessageLength int `json:"message_length"`
	}
	json.Unmarshal([]byte(contextJson), &context)

	current := channelBalance[channelId]
	if current == nil || balance > current["balance"].(uint64) {
		channelBalance[channelId] = map[string]interface{}{
			"balance":   balance,
			"signature": signature,
		}
	}

	usage := channelUsage[channelId]
	if usage == nil {
		usage = make(map[string]uint64)
		channelUsage[channelId] = usage
	}
	usage["requests"]++
	usage["chars"] += uint64(context.MessageLength)

	log.Printf("  [Host] Recorded payment: %d sats for %s\n", balance, channelId[:8])
}

// GetChannelState returns: "open", "closing", or "closed"
func (h *AsciiArtHost) GetChannelState(channelId string) string {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := channelClosed[channelId]; ok {
		return "closed"
	}
	if _, ok := channelClosing[channelId]; ok {
		return "closing"
	}
	return "open"
}

// MarkChannelClosing marks a channel as CLOSING (pre-swap state)
func (h *AsciiArtHost) MarkChannelClosing(channelId string, locktime, balance uint64, signature string) error {
	log.Printf("  [Host] MarkChannelClosing: channel=%s balance=%d\n", channelId[:8], balance)
	mu.Lock()
	defer mu.Unlock()
	// Check if channel is already closed
	if _, ok := channelClosed[channelId]; ok {
		return fmt.Errorf("channel already closed")
	}
	channelClosing[channelId] = &ClosingChannelData{
		Locktime:  locktime,
		Balance:   balance,
		Signature: signature,
	}
	return nil
}

// GetClosingData returns the closing data for a channel in CLOSING state, or nil if not closing
func (h *AsciiArtHost) GetClosingData(channelId string) *spilman.ClosingData {
	mu.Lock()
	defer mu.Unlock()
	data, ok := channelClosing[channelId]
	if !ok {
		return nil
	}
	return &spilman.ClosingData{
		Locktime:  data.Locktime,
		Balance:   data.Balance,
		Signature: data.Signature,
	}
}

func (h *AsciiArtHost) GetChannelPolicy() string {
	b, _ := json.Marshal(map[string]interface{}{
		"min_expiry_in_seconds": 3600,
		"pricing":               getActivePricing(),
	})
	return string(b)
}

func (h *AsciiArtHost) NowSeconds() uint64 {
	return uint64(time.Now().Unix())
}

func (h *AsciiArtHost) GetBalanceAndSignatureForUnilateralExit(channelId string) (uint64, string, bool) {
	mu.Lock()
	defer mu.Unlock()
	data, ok := channelBalance[channelId]
	if !ok {
		return 0, "", false
	}
	return data["balance"].(uint64), data["signature"].(string), true
}

func (h *AsciiArtHost) GetActiveKeysetIds(mint, unit string) []string {
	keysetCacheMu.RLock()
	defer keysetCacheMu.RUnlock()
	var ids []string
	for id, entry := range keysetCache {
		if entry.Active && entry.Unit == unit {
			ids = append(ids, id)
		}
	}
	return ids
}

func (h *AsciiArtHost) GetKeysetInfo(mint, keysetId string) (string, bool) {
	keysetCacheMu.RLock()
	defer keysetCacheMu.RUnlock()
	entry, ok := keysetCache[keysetId]
	if !ok {
		return "", false
	}
	return entry.InfoJson, true
}

func (h *AsciiArtHost) CallMintSwap(mintUrl, swapRequestJson string) (string, error) {
	log.Printf("  [Host] CallMintSwap to %s\n", mintUrl)
	resp, err := http.Post(mintUrl+"/v1/swap", "application/json", bytes.NewBufferString(swapRequestJson))
	if err != nil {
		return "", fmt.Errorf("failed to contact mint: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("mint rejected swap: %s", string(body))
	}

	var swapResp struct {
		Signatures []interface{} `json:"signatures"`
	}
	json.Unmarshal(body, &swapResp)
	log.Printf("  [Host] Got %d blind signatures\n", len(swapResp.Signatures))

	return string(body), nil
}

func (h *AsciiArtHost) RefreshActiveKeysets(mintUrl string) error {
	log.Printf("  [Host] RefreshActiveKeysets for %s\n", mintUrl)
	refreshActiveKeysets(mintUrl)
	return nil
}

func (h *AsciiArtHost) MarkChannelClosed(channelId string, locktime, balance uint64, receiverProofsJson, senderProofsJson string, receiverSum, senderSum uint64) error {
	log.Printf("  [Host] MarkChannelClosed: channel=%s receiver=%d sender=%d\n", channelId[:8], receiverSum, senderSum)
	mu.Lock()
	defer mu.Unlock()
	// Check if channel is already closed
	if _, ok := channelClosed[channelId]; ok {
		return fmt.Errorf("channel already closed")
	}
	channelClosed[channelId] = map[string]interface{}{
		"locktime":        locktime,
		"balance":         balance,
		"receiver_proofs": receiverProofsJson,
		"sender_proofs":   senderProofsJson,
		"receiver_sum":    receiverSum,
		"sender_sum":      senderSum,
	}
	return nil
}

// ============================================================================
// Initialization & Server Helpers
// ============================================================================

func fetchKeysetInfo(mintUrl, keysetId, unit string, inputFeePpk uint64, active bool) string {
	keysetCacheMu.Lock()
	defer keysetCacheMu.Unlock()

	if entry, ok := keysetCache[keysetId]; ok {
		if active {
			entry.Active = true
			keysetCache[keysetId] = entry
		}
		return entry.InfoJson
	}

	log.Printf("  [Keyset] Fetching keyset %s from %s...\n", keysetId, mintUrl)
	resp, err := http.Get(fmt.Sprintf("%s/v1/keys/%s", mintUrl, keysetId))
	if err != nil {
		log.Printf("  [Error] Failed to fetch keys: %v", err)
		return ""
	}
	defer resp.Body.Close()

	var data struct {
		Keysets []struct {
			Keys map[string]string `json:"keys"`
		} `json:"keysets"`
	}
	json.NewDecoder(resp.Body).Decode(&data)

	if len(data.Keysets) == 0 {
		return ""
	}

	keys := data.Keysets[0].Keys
	var amounts []uint64
	for k := range keys {
		var val uint64
		fmt.Sscanf(k, "%d", &val)
		amounts = append(amounts, val)
	}
	sort.Slice(amounts, func(i, j int) bool { return amounts[i] > amounts[j] })

	info := map[string]interface{}{
		"keysetId":    keysetId,
		"unit":        unit,
		"keys":        keys,
		"inputFeePpk": inputFeePpk,
		"amounts":     amounts,
	}
	infoJson, _ := json.Marshal(info)
	keysetCache[keysetId] = KeysetCacheEntry{
		InfoJson: string(infoJson),
		Active:   active,
		Unit:     unit,
	}
	return string(infoJson)
}

func getMintVersion(mintUrl string) string {
	resp, err := http.Get(mintUrl + "/v1/info")
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()

	var info struct{ Version string }
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "unknown"
	}
	if info.Version == "" {
		return "unknown"
	}
	return info.Version
}

func initializeKeysets() {
	log.Printf("Fetching keysets from %s...\n", MINT_URL)
	resp, err := http.Get(MINT_URL + "/v1/keysets")
	if err != nil {
		log.Printf("WARNING: Failed to fetch keysets: %v", err)
		return
	}
	defer resp.Body.Close()

	var data struct {
		Keysets []struct {
			Id          string `json:"id"`
			Unit        string `json:"unit"`
			Active      bool   `json:"active"`
			InputFeePpk uint64 `json:"input_fee_ppk"`
		} `json:"keysets"`
	}
	json.NewDecoder(resp.Body).Decode(&data)

	for _, k := range data.Keysets {
		if _, ok := allPricing[k.Unit]; ok {
			fetchKeysetInfo(MINT_URL, k.Id, k.Unit, k.InputFeePpk, k.Active)
		}
	}
	log.Printf("Cached %d keysets\n", len(keysetCache))
}

func refreshActiveKeysets(mintUrl string) {
	log.Printf("  [Keyset] Refreshing keysets from %s...\n", mintUrl)
	resp, err := http.Get(mintUrl + "/v1/keysets")
	if err != nil {
		log.Printf("  [Keyset] Refresh failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var data struct {
		Keysets []struct {
			Id          string `json:"id"`
			Unit        string `json:"unit"`
			Active      bool   `json:"active"`
			InputFeePpk uint64 `json:"input_fee_ppk"`
		} `json:"keysets"`
	}
	json.NewDecoder(resp.Body).Decode(&data)

	for _, k := range data.Keysets {
		if _, ok := allPricing[k.Unit]; ok {
			fetchKeysetInfo(mintUrl, k.Id, k.Unit, k.InputFeePpk, k.Active)
		}
	}
	log.Printf("  [Keyset] Refresh complete, %d keysets cached\n", len(keysetCache))
}

// ============================================================================
// Client Helpers
// ============================================================================

func clientFetchActiveKeysetInfo(mintUrl string) (map[string]interface{}, error) {
	log.Printf("  Fetching keysets from %s...\n", mintUrl)
	resp, err := http.Get(fmt.Sprintf("%s/v1/keysets", mintUrl))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var keysetsData struct {
		Keysets []struct {
			Id          string `json:"id"`
			Unit        string `json:"unit"`
			Active      bool   `json:"active"`
			InputFeePpk uint64 `json:"input_fee_ppk"`
		} `json:"keysets"`
	}
	json.NewDecoder(resp.Body).Decode(&keysetsData)

	var activeId string
	var inputFeePpk uint64
	for _, k := range keysetsData.Keysets {
		if k.Unit == "sat" && k.Active {
			activeId = k.Id
			inputFeePpk = k.InputFeePpk
			break
		}
	}
	if activeId == "" {
		return nil, fmt.Errorf("no active sat keyset found")
	}

	resp, err = http.Get(fmt.Sprintf("%s/v1/keys/%s", mintUrl, activeId))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var keysData struct {
		Keysets []struct {
			Keys map[string]string `json:"keys"`
		} `json:"keysets"`
	}
	json.NewDecoder(resp.Body).Decode(&keysData)

	return map[string]interface{}{
		"keysetId":    activeId,
		"unit":        "sat",
		"inputFeePpk": inputFeePpk,
		"keys":        keysData.Keysets[0].Keys,
	}, nil
}

func mintFundingToken(mintUrl string, amount uint64, blindedMessages []interface{}) ([]interface{}, error) {
	log.Printf("  Requesting mint quote for %d sat...\n", amount)
	quoteReq, _ := json.Marshal(map[string]interface{}{"amount": amount, "unit": "sat"})
	resp, err := http.Post(fmt.Sprintf("%s/v1/mint/quote/bolt11", mintUrl), "application/json", bytes.NewBuffer(quoteReq))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var quote struct {
		Quote   string `json:"quote"`
		Request string `json:"request"`
	}
	json.NewDecoder(resp.Body).Decode(&quote)

	if quote.Request != "" {
		fmt.Println("\n  " + strings.Repeat("=", 56))
		fmt.Println("  PAY THIS INVOICE TO FUND THE CHANNEL")
		fmt.Println("  " + strings.Repeat("=", 56))
		fmt.Printf("\n  %s\n\n", quote.Request)

		qr, err := qrcode.New(strings.ToUpper(quote.Request), qrcode.Medium)
		if err == nil {
			fmt.Println("  Scan this QR code with your Lightning wallet:")
			fmt.Print(qr.ToSmallString(false))
		}
		fmt.Println("\n  " + strings.Repeat("=", 56) + "\n")
	}

	log.Println("  Waiting for payment (Nutshell test mint may auto-pay)...")
	for i := 0; i < 120; i++ {
		r, _ := http.Get(fmt.Sprintf("%s/v1/mint/quote/bolt11/%s", mintUrl, quote.Quote))
		var status struct {
			State string `json:"state"`
			Paid  bool   `json:"paid"`
		}
		json.NewDecoder(r.Body).Decode(&status)
		r.Body.Close()

		if status.State == "PAID" || status.Paid {
			log.Println("  Payment received!")
			break
		}
		if i%10 == 0 && i > 0 {
			log.Printf("  Still waiting... (%ds)\n", i/2)
		}
		time.Sleep(500 * time.Millisecond)
		if i == 119 {
			return nil, fmt.Errorf("timeout waiting for payment")
		}
	}

	mintReq, _ := json.Marshal(map[string]interface{}{"quote": quote.Quote, "outputs": blindedMessages})
	resp, err = http.Post(fmt.Sprintf("%s/v1/mint/bolt11", mintUrl), "application/json", bytes.NewBuffer(mintReq))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var mintResp struct {
		Signatures []interface{} `json:"signatures"`
	}
	json.NewDecoder(resp.Body).Decode(&mintResp)
	return mintResp.Signatures, nil
}

// ============================================================================
// Runners
// ============================================================================

func closeChannel(id string, bridge *spilman.Bridge) (*spilman.CloseSuccess, error) {
	log.Printf("\n[Close] Attempting to close channel %s...\n", id[:16])

	// Execute unilateral close via bridge (handles swap, retry, unblind, mark closed)
	// Returns CloseSuccess on success, error (with JSON-encoded CloseError) on failure
	result, err := bridge.ExecuteUnilateralClose(id)
	if err != nil {
		log.Printf("  [Close] Failed: %s\n", err.Error())
		return nil, err
	}

	log.Printf("  [Close] SUCCESS! Channel %s closed. Earned %d sat\n", id[:8], result.ReceiverSum)
	return result, nil
}

func runServer() {
	initializeKeysets()
	log.Printf("Starting server with MINT_URL: %s\n", MINT_URL)
	log.Printf("Mint version: %s\n", getMintVersion(MINT_URL))

	pubkey, _ := spilman.SecretKeyToPubkey(SERVER_SECRET_KEY)
	host := &AsciiArtHost{pubkey: pubkey}
	bridge := spilman.NewBridge(host, SERVER_SECRET_KEY)
	defer bridge.Free()

	http.HandleFunc("/channel/params", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"receiver_pubkey":       host.pubkey,
			"pricing":               getActivePricing(),
			"mints_units_keysets":   getMintsUnitsKeysets(),
			"min_expiry_in_seconds": 3600,
		})
	})

	http.HandleFunc("/channel/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			ChannelId     string      `json:"channel_id"`
			Balance       int         `json:"balance"`
			Signature     string      `json:"signature"`
			Params        interface{} `json:"params"`
			FundingProofs interface{} `json:"funding_proofs"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		// Validate required fields
		if req.ChannelId == "" || req.Signature == "" || req.Params == nil || req.FundingProofs == nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":  "Bad request",
				"reason": "missing required fields: channel_id, signature, params, funding_proofs",
			})
			return
		}

		// balance must be 0 for registration
		if req.Balance != 0 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":  "Bad request",
				"reason": fmt.Sprintf("funding requires balance=0, got %d", req.Balance),
			})
			return
		}

		shortId := req.ChannelId
		if len(shortId) > 16 {
			shortId = shortId[:16]
		}
		log.Printf("\n[Register] Channel %s...\n", shortId)

		// Build request body in the same format as payment
		registerBody := map[string]interface{}{
			"channel_id":     req.ChannelId,
			"balance":        0,
			"signature":      req.Signature,
			"params":         req.Params,
			"funding_proofs": req.FundingProofs,
		}
		registerJson, _ := json.Marshal(registerBody)

		// Use FundChannel to validate and store the channel
		// FundChannel now returns (*FundChannelResult, error)
		result, err := bridge.FundChannel(string(registerJson))
		if err != nil {
			errorMsg := err.Error()
			log.Printf("  [Register] REJECTED: %s\n", errorMsg)

			// Determine HTTP status from error type
			status := http.StatusPaymentRequired // 402 default
			lowerMsg := strings.ToLower(errorMsg)
			if strings.Contains(lowerMsg, "invalid base64") ||
				strings.Contains(lowerMsg, "invalid utf8") ||
				strings.Contains(lowerMsg, "invalid json") ||
				strings.Contains(lowerMsg, "missing field") ||
				strings.Contains(lowerMsg, "missing channel_id") ||
				strings.Contains(lowerMsg, "missing signature") ||
				(strings.Contains(lowerMsg, "expected") && (strings.Contains(lowerMsg, "string") || strings.Contains(lowerMsg, "integer") || strings.Contains(lowerMsg, "u64"))) {
				status = http.StatusBadRequest
			} else if strings.Contains(lowerMsg, "internal") || strings.Contains(lowerMsg, "misconfigured") {
				status = http.StatusInternalServerError
			}

			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Registration failed",
				"reason":  errorMsg,
				"status":  status,
			})
			return
		}

		log.Printf("  [Register] SUCCESS! channel=%s capacity=%d already_known=%v\n",
			result.ChannelID[:16], result.Capacity, result.AlreadyKnown)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":       true,
			"channel_id":    result.ChannelID,
			"capacity":      result.Capacity,
			"already_known": result.AlreadyKnown,
		})
	})

	http.HandleFunc("/ascii", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received request to /ascii")
		if r.Method != http.MethodPost {
			return
		}
		paymentHeaderB64 := r.Header.Get("X-Cashu-Channel")

		// Check for missing header
		if paymentHeaderB64 == "" {
			w.WriteHeader(http.StatusPaymentRequired)
			json.NewEncoder(w).Encode(map[string]string{"error": "Payment required", "reason": "Missing X-Cashu-Channel header"})
			return
		}

		// Decode base64-encoded payment header
		paymentHeaderBytes, err := base64.StdEncoding.DecodeString(paymentHeaderB64)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid payment header", "reason": "invalid base64 encoding"})
			return
		}
		paymentHeader := string(paymentHeaderBytes)

		var req struct{ Message string }
		json.NewDecoder(r.Body).Decode(&req)

		ctxJson, _ := json.Marshal(map[string]interface{}{"message_length": len(req.Message)})

		// ProcessPayment now returns (*PaymentSuccess, error)
		result, err := bridge.ProcessPayment(paymentHeader, string(ctxJson))
		if err != nil {
			errorMsg := err.Error()
			log.Printf("  [Error] ProcessPayment failed: %s", errorMsg)

			// Determine HTTP status from error type
			status := http.StatusPaymentRequired // 402 default
			lowerMsg := strings.ToLower(errorMsg)
			if strings.Contains(lowerMsg, "invalid base64") ||
				strings.Contains(lowerMsg, "invalid utf8") ||
				strings.Contains(lowerMsg, "invalid json") ||
				strings.Contains(lowerMsg, "missing field") ||
				strings.Contains(lowerMsg, "missing channel_id") ||
				strings.Contains(lowerMsg, "missing signature") ||
				(strings.Contains(lowerMsg, "expected") && (strings.Contains(lowerMsg, "string") || strings.Contains(lowerMsg, "integer") || strings.Contains(lowerMsg, "u64"))) {
				status = http.StatusBadRequest
			} else if strings.Contains(lowerMsg, "internal") || strings.Contains(lowerMsg, "misconfigured") {
				status = http.StatusInternalServerError
			}

			w.Header().Set("X-Cashu-Channel", fmt.Sprintf(`{"error":"%s"}`, errorMsg))
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]string{"error": "Payment failed", "reason": errorMsg})
			return
		}

		art := figure.NewFigure(req.Message, "", true).String()

		// Calculate cost based on message length and unit pricing
		channelId := result.ChannelID
		mu.Lock()
		funding := channelFunding[channelId]
		mu.Unlock()

		pricePerChar := uint64(1) // default sat
		if funding != nil {
			var params struct {
				Unit string `json:"unit"`
			}
			json.Unmarshal([]byte(funding["params"]), &params)
			if params.Unit != "" {
				pricePerChar = getPricePerChar(params.Unit)
			}
		}
		cost := uint64(len(req.Message)) * pricePerChar

		// Build header data from result
		headerData := map[string]interface{}{
			"channel_id": result.ChannelID,
			"balance":    result.Balance,
			"amount_due": result.AmountDue,
			"capacity":   result.Capacity,
		}
		headerJson, _ := json.Marshal(headerData)
		w.Header().Set("X-Cashu-Channel", string(headerJson))
		json.NewEncoder(w).Encode(map[string]interface{}{
			"art":     art,
			"message": req.Message,
			"cost":    cost,
			"payment": headerData,
		})
	})

	http.HandleFunc("/channel/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 3 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		channelId := parts[2]
		action := ""
		if len(parts) >= 4 {
			action = parts[3]
		}

		switch action {
		case "status":
			// GET /channel/{id}/status
			mu.Lock()
			funding, hasFunding := channelFunding[channelId]
			payment := channelBalance[channelId]
			closedInfoRaw, isClosed := channelClosed[channelId]
			mu.Unlock()

			if !hasFunding {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"error": "unknown channel"})
				return
			}

			var params struct {
				Capacity uint64 `json:"capacity"`
			}
			json.Unmarshal([]byte(funding["params"]), &params)

			balance := uint64(0)
			if payment != nil {
				if b, ok := payment["balance"].(uint64); ok {
					balance = b
				}
			}

			var closedAmount interface{} = nil
			if isClosed {
				if closedInfo, ok := closedInfoRaw.(map[string]interface{}); ok {
					closedAmount = closedInfo["balance"]
				}
			}

			json.NewEncoder(w).Encode(map[string]interface{}{
				"channel_id":    channelId,
				"capacity":      params.Capacity,
				"balance":       balance,
				"amount_due":    host.GetAmountDue(channelId, nil),
				"closed":        isClosed,
				"closed_amount": closedAmount,
			})

		case "close":
			// POST /channel/{id}/close - Cooperative close
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}

			var req struct {
				Balance       uint64      `json:"balance"`
				Signature     string      `json:"signature"`
				Params        interface{} `json:"params"`
				FundingProofs interface{} `json:"funding_proofs"`
			}
			json.NewDecoder(r.Body).Decode(&req)

			if req.Signature == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "missing signature"})
				return
			}

			log.Printf("\n[CooperativeClose] Channel %s... balance=%d\n", channelId[:min(16, len(channelId))], req.Balance)

			// Check if already closed
			mu.Lock()
			closedInfoRaw, isClosed := channelClosed[channelId]
			mu.Unlock()

			if isClosed {
				closedInfo, _ := closedInfoRaw.(map[string]interface{})
				if closedInfo["balance"] == req.Balance {
					log.Printf("  [CooperativeClose] Already closed at same balance, returning cached result\n")
					json.NewEncoder(w).Encode(map[string]interface{}{
						"success":        true,
						"channel_id":     channelId,
						"already_closed": true,
						"total_value":    closedInfo["receiver_sum"].(uint64) + closedInfo["sender_sum"].(uint64),
						"receiver_sum":   closedInfo["receiver_sum"],
						"sender_sum":     closedInfo["sender_sum"],
						"sender_proofs":  json.RawMessage(closedInfo["sender_proofs"].(string)),
					})
					return
				}
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":            "channel already closed at different balance",
					"closed_amount":    closedInfo["balance"],
					"requested_amount": req.Balance,
				})
				return
			}

			// Build payment request for bridge
			paymentRequest := map[string]interface{}{
				"channel_id": channelId,
				"balance":    req.Balance,
				"signature":  req.Signature,
			}
			if req.Params != nil {
				paymentRequest["params"] = req.Params
			}
			if req.FundingProofs != nil {
				paymentRequest["funding_proofs"] = req.FundingProofs
			}
			paymentRequestJson, _ := json.Marshal(paymentRequest)

			// Execute cooperative close via bridge (handles swap, retry, unblind, mark closed)
			// Returns CloseSuccess on success, error (with JSON-encoded CloseError) on failure
			result, err := bridge.ExecuteCooperativeClose(string(paymentRequestJson))
			if err != nil {
				// Try to parse CloseError from error message
				var closeError struct {
					Type   string `json:"type"`
					Reason string `json:"reason"`
					Status int    `json:"status"`
				}
				if json.Unmarshal([]byte(err.Error()), &closeError) == nil {
					status := closeError.Status
					if status == 0 {
						status = http.StatusPaymentRequired
					}
					w.WriteHeader(status)
					json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": closeError.Reason, "reason": closeError.Reason})
				} else {
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
				}
				return
			}

			log.Printf("  [CooperativeClose] SUCCESS!\n")

			// Return CloseSuccess result
			var senderProofs interface{}
			json.Unmarshal([]byte(result.SenderProofs), &senderProofs)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":        true,
				"channel_id":     result.ChannelID,
				"total_value":    result.TotalValue,
				"receiver_sum":   result.ReceiverSum,
				"sender_sum":     result.SenderSum,
				"sender_proofs":  senderProofs,
				"already_closed": result.AlreadyClosed,
			})

		case "unilateral-close":
			// POST /channel/{id}/unilateral-close - Server-initiated close
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}

			log.Printf("\n[UnilateralClose] Channel %s...\n", channelId[:min(16, len(channelId))])

			// Check if already closed
			mu.Lock()
			closedInfoRaw, isClosed := channelClosed[channelId]
			_, hasFunding := channelFunding[channelId]
			mu.Unlock()

			if isClosed {
				closedInfo, _ := closedInfoRaw.(map[string]interface{})
				log.Printf("  [UnilateralClose] Already closed, returning cached result\n")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success":                true,
					"channel_id":             channelId,
					"already_closed":         true,
					"earnedBeforeStage2Fees": closedInfo["receiver_sum"],
				})
				return
			}

			if !hasFunding {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"error": "unknown channel"})
				return
			}

			result, err := closeChannel(channelId, bridge)
			if err != nil {
				// Try to parse CloseError from error message to get status
				var closeError struct {
					Status int `json:"status"`
				}
				status := http.StatusBadRequest
				if json.Unmarshal([]byte(err.Error()), &closeError) == nil && closeError.Status != 0 {
					status = closeError.Status
				}
				w.WriteHeader(status)
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
				return
			}

			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":                true,
				"channel_id":             channelId,
				"already_closed":         false,
				"earnedBeforeStage2Fees": result.ReceiverSum,
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	log.Printf("Go ASCII Art Server listening on :%s\n", SERVER_PORT)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", SERVER_PORT), nil))
}

func runClient(messages []string) {
	log.Printf("\n[1/8] Fetching server params from %s...\n", SERVER_URL)
	resp, err := http.Get(SERVER_URL + "/channel/params")
	if err != nil {
		log.Fatalf("Server not found: %v", err)
	}
	var sp struct {
		Receiver_pubkey     string                         `json:"receiver_pubkey"`
		Mints_units_keysets map[string]map[string][]string `json:"mints_units_keysets"`
	}
	json.NewDecoder(resp.Body).Decode(&sp)
	resp.Body.Close()

	// Derive mint URL from mints_units_keysets
	var clientMintUrl string
	for m := range sp.Mints_units_keysets {
		clientMintUrl = m
		break
	}
	log.Printf("  Using mint: %s\n", clientMintUrl)

	log.Println("[2/8] Generating keypair...")
	aliceSecret, alicePubkey, err := spilman.GenerateKeypair()
	if err != nil {
		log.Fatalf("GenerateKeypair failed: %v", err)
	}
	alice := struct{ Secret, Pubkey string }{aliceSecret, alicePubkey}
	log.Printf("  Alice pubkey: %s...\n\n", alice.Pubkey[:24])

	log.Println("[3/8] Fetching keyset info...")
	log.Printf("  Mint version: %s\n", getMintVersion(clientMintUrl))
	ki, _ := clientFetchActiveKeysetInfo(clientMintUrl)
	kiJson, _ := json.Marshal(ki)
	log.Printf("  Found keyset: %s (%s)\n", ki["keysetId"], ki["unit"])

	log.Println("[4/8] Computing shared secret...")
	ss, _ := spilman.ComputeSharedSecret(alice.Secret, sp.Receiver_pubkey)

	log.Println("[5/8] Building channel parameters...")
	total := 0
	for _, m := range messages {
		total += len(m)
	}
	cap := uint64(total + 50)
	// Compute the minimum funding_token_amount for the desired capacity
	fta, _ := spilman.ComputeFundingTokenAmount(cap, string(kiJson), 64)
	params := map[string]interface{}{
		"alice_pubkey": alice.Pubkey, "charlie_pubkey": sp.Receiver_pubkey,
		"mint": clientMintUrl, "unit": "sat", "capacity": cap,
		"funding_token_amount": fta, "maximum_amount": 64,
		"locktime": time.Now().Unix() + 7200, "setup_timestamp": time.Now().Unix(),
		"sender_nonce": fmt.Sprintf("demo-go-%d", time.Now().Unix()),
		"keyset_id":    ki["keysetId"], "input_fee_ppk": ki["inputFeePpk"],
	}
	pJson, _ := json.Marshal(params)
	cid, _ := spilman.ChannelParametersGetChannelId(string(pJson), ss, string(kiJson))
	log.Printf("  Full channel ID: %s\n", cid)

	log.Println("[6/8] Creating funding outputs...")
	fJson, _ := spilman.CreateFundingOutputs(string(pJson), alice.Secret, string(kiJson))
	var f struct {
		Funding_token_nominal uint64
		Blinded_messages      []interface{}
		Secrets_with_blinding []interface{}
	}
	json.Unmarshal([]byte(fJson), &f)

	log.Println("[7/8] Minting funding token...")
	sigs, _ := mintFundingToken(clientMintUrl, f.Funding_token_nominal, f.Blinded_messages)

	log.Println("[8/8] Constructing proofs...")
	sigsJ, _ := json.Marshal(sigs)
	swbJ, _ := json.Marshal(f.Secrets_with_blinding)
	proofsJ, _ := spilman.ConstructProofs(string(sigsJ), string(swbJ), string(kiJson))
	var proofs []interface{}
	json.Unmarshal([]byte(proofsJ), &proofs)

	log.Printf("\nChannel %s funded! Making requests...\n\n", cid[:8])
	balance := uint64(0)
	for i, msg := range messages {
		balance += uint64(len(msg))
		updJ, _ := spilman.CreateSignedBalanceUpdate(string(pJson), string(kiJson), alice.Secret, proofsJ, balance)
		var upd struct{ Signature string }
		json.Unmarshal([]byte(updJ), &upd)

		pay := map[string]interface{}{"channel_id": cid, "balance": balance, "signature": upd.Signature}
		if i == 0 {
			pay["params"] = params
			pay["funding_proofs"] = proofs
		}
		payH, _ := json.Marshal(pay)

		reqB, _ := json.Marshal(map[string]string{"message": msg})
		req, _ := http.NewRequest("POST", SERVER_URL+"/ascii", bytes.NewBuffer(reqB))
		req.Header.Set("X-Cashu-Channel", base64.StdEncoding.EncodeToString(payH))
		req.Header.Set("Content-Type", "application/json")

		r, err := (&http.Client{}).Do(req)
		if err != nil {
			log.Fatalf("Request failed: %v", err)
		}
		if r.StatusCode == 200 {
			var res struct{ Art string }
			json.NewDecoder(r.Body).Decode(&res)
			r.Body.Close()
			fmt.Printf("[%d/%d] '%s' (%d sat) -> Accepted!\n%s\n", i+1, len(messages), msg, len(msg), res.Art)
		} else {
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			log.Fatalf("[%d/%d] '%s' -> FAILED (Status %d): %s", i+1, len(messages), msg, r.StatusCode, string(body))
		}
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "client" {
		runClient(os.Args[2:])
	} else {
		runServer()
	}
}
