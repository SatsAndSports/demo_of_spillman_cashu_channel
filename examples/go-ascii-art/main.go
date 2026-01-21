package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SatsAndSports/cdk/spilman"
	"github.com/common-nighthawk/go-figure"
)

// ============================================================================
// Configuration
// ============================================================================

const (
	MINT_URL = "http://localhost:3338"
	PORT     = 5001 // Use a different port than Python (5000)
)

var (
	SERVER_SECRET_KEY = getEnv("SERVER_SECRET_KEY", "0000000000000000000000000000000000000000000000000000000000000001")
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// ============================================================================
// State & Storage
// ============================================================================

type KeysetCacheEntry struct {
	InfoJson string
	Active   bool
	Unit     string
}

var (
	// In-memory data stores
	channelFunding = make(map[string]map[string]string)
	channelBalance = make(map[string]map[string]interface{})
	channelUsage   = make(map[string]map[string]uint64)
	channelClosed  = make(map[string]interface{})
	keysetCache    = make(map[string]KeysetCacheEntry)
	keysetCacheMu  sync.RWMutex
	mu             sync.Mutex
)

// ============================================================================
// Spilman Host Implementation
// ============================================================================

type AsciiArtHost struct{}

func (h *AsciiArtHost) ReceiverKeyIsAcceptable(pubkeyHex string) bool {
	// In this demo, we accept any key intended for us
	return true
}

func (h *AsciiArtHost) MintAndKeysetIsAcceptable(mint string, keysetId string) bool {
	// We only accept our local dev mint
	return mint == MINT_URL
}

func (h *AsciiArtHost) GetFundingAndParams(channelId string) (string, string, string, string, bool) {
	mu.Lock()
	defer mu.Unlock()
	data, ok := channelFunding[channelId]
	if !ok {
		return "", "", "", "", false
	}
	return data["params"], data["proofs"], data["secret"], data["keyset"], true
}

func (h *AsciiArtHost) SaveFunding(channelId, paramsJson, proofsJson, sharedSecretHex, keysetInfoJson string) {
	mu.Lock()
	defer mu.Unlock()
	channelFunding[channelId] = map[string]string{
		"params": paramsJson,
		"proofs": proofsJson,
		"secret": sharedSecretHex,
		"keyset": keysetInfoJson,
	}
	fmt.Printf("  [Host] Saved funding for channel %s\n", channelId[:8])
}

func (h *AsciiArtHost) GetAmountDue(channelId, contextJson string) uint64 {
	mu.Lock()
	defer mu.Unlock()

	var context struct {
		MessageLength int `json:"message_length"`
	}
	json.Unmarshal([]byte(contextJson), &context)

	usage := channelUsage[channelId]
	if usage == nil {
		usage = make(map[string]uint64)
	}

	// Pricing formula: 0.5 sats per request + 0.1 sats per character
	// cost = ceil((requests * 500 + chars * 100) / 1000)
	totalRequests := usage["requests"] + 1
	totalChars := usage["chars"] + uint64(context.MessageLength)

	cost := (totalRequests*500 + totalChars*100 + 999) / 1000
	return cost
}

func (h *AsciiArtHost) RecordPayment(channelId string, balance uint64, signature, contextJson string) {
	mu.Lock()
	defer mu.Unlock()

	var context struct {
		MessageLength int `json:"message_length"`
	}
	json.Unmarshal([]byte(contextJson), &context)

	// Update balance
	channelBalance[channelId] = map[string]interface{}{
		"balance":   balance,
		"signature": signature,
	}

	// Update usage
	usage := channelUsage[channelId]
	if usage == nil {
		usage = make(map[string]uint64)
		channelUsage[channelId] = usage
	}
	usage["requests"]++
	usage["chars"] += uint64(context.MessageLength)

	fmt.Printf("  [Host] Recorded payment: %d sats for %s\n", balance, channelId[:8])
}

func (h *AsciiArtHost) IsClosed(channelId string) bool {
	mu.Lock()
	defer mu.Unlock()
	_, ok := channelClosed[channelId]
	return ok
}

func (h *AsciiArtHost) GetServerConfig() string {
	config := map[string]interface{}{
		"min_expiry_in_seconds": 3600,
		"pricing": map[string]interface{}{
			"sat": map[string]interface{}{
				"minCapacity": 10,
			},
		},
	}
	b, _ := json.Marshal(config)
	return string(b)
}

func (h *AsciiArtHost) NowSeconds() uint64 {
	return uint64(time.Now().Unix())
}

func (h *AsciiArtHost) GetLargestBalanceWithSignature(channelId string) (uint64, string, bool) {
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

// ============================================================================
// Initialization
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

	fmt.Printf("  [Keyset] Fetching keyset %s from %s...\n", keysetId, mintUrl)
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

func initializeKeysets() {
	fmt.Printf("Fetching keysets from %s...\n", MINT_URL)
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
		if k.Unit == "sat" {
			fetchKeysetInfo(MINT_URL, k.Id, k.Unit, k.InputFeePpk, k.Active)
		}
	}
	fmt.Printf("Cached %d keysets\n", len(keysetCache))
}

// ============================================================================
// Main & HTTP Handlers
// ============================================================================

func main() {
	initializeKeysets()

	host := &AsciiArtHost{}
	bridge := spilman.NewBridge(host, SERVER_SECRET_KEY)
	defer bridge.Free()

	// 1. GET /channel/params - Get server's public key and supported mints
	http.HandleFunc("/channel/params", func(w http.ResponseWriter, r *http.Request) {
		pubkey, _ := spilman.SecretKeyToPubkey(SERVER_SECRET_KEY)

		config := map[string]interface{}{
			"receiver_pubkey": pubkey,
			"mint":            MINT_URL,
		}
		json.NewEncoder(w).Encode(config)
	})

	// 2. POST /ascii - Process payment and return ASCII art
	http.HandleFunc("/ascii", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		paymentHeader := r.Header.Get("X-Cashu-Channel")
		if paymentHeader == "" {
			w.WriteHeader(http.StatusPaymentRequired)
			json.NewEncoder(w).Encode(map[string]string{"error": "Missing X-Cashu-Channel header"})
			return
		}

		var req struct {
			Message string `json:"message"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		context := map[string]interface{}{"message_length": len(req.Message)}
		contextJson, _ := json.Marshal(context)

		// Parse payment header to get keyset info if provided
		var keysetInfoJson *string
		var paymentData struct {
			Params struct {
				Mint        string `json:"mint"`
				KeysetId    string `json:"keyset_id"`
				Unit        string `json:"unit"`
				InputFeePpk uint64 `json:"input_fee_ppk"`
			} `json:"params"`
		}
		if err := json.Unmarshal([]byte(paymentHeader), &paymentData); err == nil && paymentData.Params.KeysetId != "" {
			info := fetchKeysetInfo(paymentData.Params.Mint, paymentData.Params.KeysetId, paymentData.Params.Unit, paymentData.Params.InputFeePpk, false)
			if info != "" {
				keysetInfoJson = &info
			}
		}

		respJson, err := bridge.ProcessPayment(paymentHeader, string(contextJson), keysetInfoJson)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var resp struct {
			Success bool            `json:"success"`
			Error   string          `json:"error"`
			Header  json.RawMessage `json:"header"`
		}
		json.Unmarshal([]byte(respJson), &resp)

		if !resp.Success {
			w.Header().Set("X-Cashu-Channel", string(resp.Header))
			w.WriteHeader(http.StatusPaymentRequired)
			json.NewEncoder(w).Encode(map[string]string{"error": resp.Error})
			return
		}

		// Generate ASCII art
		myFigure := figure.NewFigure(req.Message, "", true)
		asciiArt := myFigure.String()

		// Prepare response matching Python client expectations
		var headerData map[string]interface{}
		json.Unmarshal(resp.Header, &headerData)

		response := map[string]interface{}{
			"art":     asciiArt,
			"payment": headerData,
		}

		w.Header().Set("X-Cashu-Channel", string(resp.Header))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// 3. POST /channel/:id/close - Close channel
	http.HandleFunc("/channel/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 4 || parts[3] != "close" {
			http.NotFound(w, r)
			return
		}
		channelId := parts[2]

		// For now, let's just do a simple close if we have the data
		closeDataJson, err := bridge.CreateUnilateralCloseData(channelId)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// In a real server, we would now POST the swap request to the mint.
		// See Python server for full logic.
		fmt.Printf("[Close] Generated close data for %s: %s\n", channelId, closeDataJson)

		mu.Lock()
		channelClosed[channelId] = true
		mu.Unlock()

		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "channel_id": channelId})
	})

	fmt.Printf("Go ASCII Art Server listening on :%d\n", PORT)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", PORT), nil))
}
