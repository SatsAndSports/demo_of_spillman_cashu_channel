package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/SatsAndSports/cdk/spilman"
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
	PRICE_PER_CHAR     = 1 // 1 sat per character
)

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

func (h *AsciiArtHost) SaveFunding(channelId, paramsJson, proofsJson, sharedSecretHex, keysetInfoJson string) {
	log.Printf("  [Host] SaveFunding for %s\n", channelId[:8])
	mu.Lock()
	defer mu.Unlock()
	channelFunding[channelId] = map[string]string{
		"params": paramsJson,
		"proofs": proofsJson,
		"secret": sharedSecretHex,
		"keyset": keysetInfoJson,
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

	return totalChars * PRICE_PER_CHAR
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

func (h *AsciiArtHost) IsClosed(channelId string) bool {
	mu.Lock()
	defer mu.Unlock()
	_, ok := channelClosed[channelId]
	return ok
}

func (h *AsciiArtHost) GetChannelPolicy() string {
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

func (h *AsciiArtHost) MarkChannelClosed(channelId string, locktime, balance uint64, receiverProofsJson, senderProofsJson string, receiverSum, senderSum uint64) error {
	log.Printf("  [Host] MarkChannelClosed: channel=%s receiver=%d sender=%d\n", channelId[:8], receiverSum, senderSum)
	mu.Lock()
	defer mu.Unlock()
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
		if k.Unit == "sat" {
			fetchKeysetInfo(MINT_URL, k.Id, k.Unit, k.InputFeePpk, k.Active)
		}
	}
	log.Printf("Cached %d keysets\n", len(keysetCache))
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

func printStatsTable() {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("  Channel Statistics (Press Ctrl+\\ to refresh)")
	fmt.Println(strings.Repeat("=", 70))

	mu.Lock()
	defer mu.Unlock()

	if len(channelFunding) == 0 {
		fmt.Println("  No channels registered yet.")
		fmt.Println(strings.Repeat("=", 70))
		fmt.Println()
		return
	}

	// Table header
	fmt.Printf("  %-10s %-8s %10s %10s %10s\n", "ID", "Status", "Capacity", "Balance", "Usage")
	fmt.Printf("  %-10s %-8s %10s %10s %10s\n", "----------", "--------", "----------", "----------", "----------")

	var totalBalance uint64
	var totalUsage uint64

	// Sort channel IDs for stable display
	var ids []string
	for id := range channelFunding {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, cid := range ids {
		funding := channelFunding[cid]
		var params struct {
			Capacity uint64 `json:"capacity"`
			Unit     string `json:"unit"`
		}
		json.Unmarshal([]byte(funding["params"]), &params)

		usage := channelUsage[cid]["chars"]
		payment := channelBalance[cid]
		balance := uint64(0)
		if payment != nil {
			balance = payment["balance"].(uint64)
		}

		status := "OPEN"
		if _, closed := channelClosed[cid]; closed {
			status = "CLOSED"
		}

		shortId := cid[:8]
		fmt.Printf("  %-10s %-8s %7d %-3s %7d %-3s %7d ch\n",
			shortId, status, params.Capacity, params.Unit, balance, params.Unit, usage)

		totalBalance += balance
		totalUsage += usage
	}

	fmt.Printf("  %-10s %-8s %10s %10s %10s\n", "----------", "--------", "----------", "----------", "----------")
	fmt.Printf("  %-10s %-8s %10s %7d sat %7d ch\n", "TOTAL", "", "", totalBalance, totalUsage)
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()
}

func closeChannel(id string, bridge *spilman.Bridge, host *AsciiArtHost) (uint64, error) {
	log.Printf("\n[Close] Attempting to close channel %s...\n", id[:16])

	mu.Lock()
	if _, closed := channelClosed[id]; closed {
		mu.Unlock()
		return 0, fmt.Errorf("channel already closed")
	}
	payment, hasPayment := channelBalance[id]
	funding, hasFunding := channelFunding[id]
	mu.Unlock()

	if !hasPayment {
		return 0, fmt.Errorf("no payment recorded for channel")
	}
	if !hasFunding {
		return 0, fmt.Errorf("no funding data for channel")
	}

	// 1. Get close data from bridge
	resJson, err := bridge.CreateUnilateralCloseData(id)
	if err != nil {
		return 0, fmt.Errorf("bridge error: %v", err)
	}

	var res struct {
		Success               bool                   `json:"success"`
		Error                 string                 `json:"error"`
		Swap_request          interface{}            `json:"swap_request"`
		Expected_total        uint64                 `json:"expected_total"`
		Secrets_with_blinding []interface{}          `json:"secrets_with_blinding"`
		Output_keyset_info    map[string]interface{} `json:"output_keyset_info"`
	}
	json.Unmarshal([]byte(resJson), &res)

	if !res.Success {
		return 0, fmt.Errorf("bridge validation failed: %s", res.Error)
	}

	// 2. Submit swap to mint via host hook
	var params struct {
		Mint     string `json:"mint"`
		Locktime uint64 `json:"locktime"`
	}
	json.Unmarshal([]byte(funding["params"]), &params)

	log.Printf("  [Close] Submitting swap to mint: %s\n", params.Mint)
	swapReqB, _ := json.Marshal(res.Swap_request)
	swapRespBody, err := host.CallMintSwap(params.Mint, string(swapReqB))
	if err != nil {
		return 0, err
	}

	var swapResp struct {
		Signatures []interface{} `json:"signatures"`
	}
	json.Unmarshal([]byte(swapRespBody), &swapResp)

	// 3. Unblind and verify DLEQ
	sigsJ, _ := json.Marshal(swapResp.Signatures)
	swbJ, _ := json.Marshal(res.Secrets_with_blinding)
	okinfoJ, _ := json.Marshal(res.Output_keyset_info)
	balance := payment["balance"].(uint64)

	unblindResJ, err := spilman.UnblindAndVerifyDleq(
		string(sigsJ),
		string(swbJ),
		funding["params"],
		funding["keyset"],
		funding["secret"],
		balance,
		nil, // Use output_keyset from swap if different? Bridge handles this usually.
	)
	if err != nil {
		// Try again with explicit output keyset if needed
		outputKeysetStr := string(okinfoJ)
		unblindResJ, err = spilman.UnblindAndVerifyDleq(
			string(sigsJ),
			string(swbJ),
			funding["params"],
			funding["keyset"],
			funding["secret"],
			balance,
			&outputKeysetStr,
		)
	}

	if err != nil {
		return 0, fmt.Errorf("unblind/DLEQ verification failed: %v", err)
	}

	var unblindRes struct {
		Receiver_proofs           []interface{} `json:"receiver_proofs"`
		Sender_proofs             []interface{} `json:"sender_proofs"`
		Receiver_sum_after_stage1 uint64        `json:"receiver_sum_after_stage1"`
		Sender_sum_after_stage1   uint64        `json:"sender_sum_after_stage1"`
	}
	json.Unmarshal([]byte(unblindResJ), &unblindRes)

	// 4. Mark as closed via host hook
	receiverProofsJson, _ := json.Marshal(unblindRes.Receiver_proofs)
	senderProofsJson, _ := json.Marshal(unblindRes.Sender_proofs)
	err = host.MarkChannelClosed(
		id,
		params.Locktime,
		balance,
		string(receiverProofsJson),
		string(senderProofsJson),
		unblindRes.Receiver_sum_after_stage1,
		unblindRes.Sender_sum_after_stage1,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to mark channel closed: %v", err)
	}

	log.Printf("  [Close] SUCCESS! Channel %s closed. Earned %d sat\n", id[:8], unblindRes.Receiver_sum_after_stage1)
	return unblindRes.Receiver_sum_after_stage1, nil
}

func closeAllChannels(bridge *spilman.Bridge, host *AsciiArtHost) {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("  Closing all channels...")
	fmt.Println(strings.Repeat("=", 70))

	mu.Lock()
	var openIds []string
	for id := range channelFunding {
		if _, closed := channelClosed[id]; !closed {
			openIds = append(openIds, id)
		}
	}
	mu.Unlock()

	if len(openIds) == 0 {
		fmt.Println("  No open channels to close.")
		fmt.Println(strings.Repeat("=", 70))
		return
	}

	var totalEarned uint64
	var closedCount int

	for _, id := range openIds {
		earned, err := closeChannel(id, bridge, host)
		if err == nil {
			totalEarned += earned
			closedCount++
		} else {
			log.Printf("  [Close] Failed to close %s: %v\n", id[:8], err)
		}
	}

	fmt.Printf("\n  Closed %d/%d channels\n", closedCount, len(openIds))
	fmt.Printf("  Total earned: %d sat\n", totalEarned)
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()
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
			"receiver_pubkey": host.pubkey,
			"pricing": map[string]interface{}{
				"sat": map[string]interface{}{
					"per_char":    PRICE_PER_CHAR,
					"minCapacity": 10,
				},
			},
			"mint":                  MINT_URL,
			"min_expiry_in_seconds": 3600,
		})
	})

	http.HandleFunc("/ascii", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received request to /ascii")
		if r.Method != http.MethodPost {
			return
		}
		paymentHeader := r.Header.Get("X-Cashu-Channel")
		var req struct{ Message string }
		json.NewDecoder(r.Body).Decode(&req)

		ctxJson, _ := json.Marshal(map[string]interface{}{"message_length": len(req.Message)})

		respJson, err := bridge.ProcessPayment(paymentHeader, string(ctxJson))
		if err != nil {
			log.Printf("  [Error] ProcessPayment bridge error: %v", err)
		}
		var resp struct {
			Success bool
			Error   string
			Header  json.RawMessage
		}
		json.Unmarshal([]byte(respJson), &resp)

		if !resp.Success {
			log.Printf("  [Error] ProcessPayment failed: %s", resp.Error)
			w.Header().Set("X-Cashu-Channel", string(resp.Header))
			w.WriteHeader(http.StatusPaymentRequired)
			json.NewEncoder(w).Encode(map[string]string{"error": resp.Error})
			return
		}

		art := figure.NewFigure(req.Message, "", true).String()
		var headerData map[string]interface{}
		json.Unmarshal(resp.Header, &headerData)

		w.Header().Set("X-Cashu-Channel", string(resp.Header))
		json.NewEncoder(w).Encode(map[string]interface{}{"art": art, "payment": headerData})
	})

	http.HandleFunc("/channel/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) >= 4 && parts[3] == "close" {
			id := parts[2]
			earned, err := closeChannel(id, bridge, host)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "channel_id": id, "earned": earned})
		}
	})

	// Statistics signal handler (Ctrl+\)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGQUIT)
	go func() {
		for range sigChan {
			printStatsTable()
		}
	}()

	// CLI listener
	go func() {
		fmt.Println("CLI ready. Commands: 's' = stats, 'c' = close all, 'q' = quit")
		var cmd string
		for {
			fmt.Scanln(&cmd)
			cmd = strings.TrimSpace(strings.ToLower(cmd))
			if cmd == "s" {
				printStatsTable()
			} else if cmd == "c" {
				closeAllChannels(bridge, host)
			} else if cmd == "q" {
				fmt.Println("\n[Shutdown] Closing all channels before exit...")
				closeAllChannels(bridge, host)
				fmt.Println("[Shutdown] Exiting...")
				os.Exit(0)
			} else if cmd != "" {
				fmt.Printf("  Unknown command: '%s'. Use 's' (stats), 'c' (close), 'q' (quit)\n", cmd)
			}
		}
	}()

	log.Printf("Go ASCII Art Server listening on :%s\n", SERVER_PORT)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", SERVER_PORT), nil))
}

func runClient(messages []string) {
	log.Printf("\n[1/8] Fetching server params from %s...\n", SERVER_URL)
	resp, err := http.Get(SERVER_URL + "/channel/params")
	if err != nil {
		log.Fatalf("Server not found: %v", err)
	}
	var sp struct{ Receiver_pubkey, Mint string }
	json.NewDecoder(resp.Body).Decode(&sp)
	resp.Body.Close()

	log.Println("[2/8] Generating keypair...")
	aliceSecret, alicePubkey, err := spilman.GenerateKeypair()
	if err != nil {
		log.Fatalf("GenerateKeypair failed: %v", err)
	}
	alice := struct{ Secret, Pubkey string }{aliceSecret, alicePubkey}
	log.Printf("  Alice pubkey: %s...\n\n", alice.Pubkey[:24])

	log.Println("[3/8] Fetching keyset info...")
	log.Printf("  Mint version: %s\n", getMintVersion(MINT_URL))
	ki, _ := clientFetchActiveKeysetInfo(MINT_URL)
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
	params := map[string]interface{}{
		"alice_pubkey": alice.Pubkey, "charlie_pubkey": sp.Receiver_pubkey,
		"mint": MINT_URL, "unit": "sat", "capacity": cap, "maximum_amount": 64,
		"locktime": time.Now().Unix() + 7200, "setup_timestamp": time.Now().Unix(),
		"sender_nonce": fmt.Sprintf("demo-go-%d", time.Now().Unix()),
		"keyset_id":    ki["keysetId"], "input_fee_ppk": ki["inputFeePpk"],
	}
	pJson, _ := json.Marshal(params)
	cid, _ := spilman.ChannelParametersGetChannelId(string(pJson), ss, string(kiJson))

	log.Println("[6/8] Creating funding outputs...")
	fJson, _ := spilman.CreateFundingOutputs(string(pJson), alice.Secret, string(kiJson))
	var f struct {
		Funding_token_nominal uint64
		Blinded_messages      []interface{}
		Secrets_with_blinding []interface{}
	}
	json.Unmarshal([]byte(fJson), &f)

	log.Println("[7/8] Minting funding token...")
	sigs, _ := mintFundingToken(MINT_URL, f.Funding_token_nominal, f.Blinded_messages)

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
		req.Header.Set("X-Cashu-Channel", string(payH))
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
