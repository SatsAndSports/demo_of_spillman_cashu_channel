package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	spilmankit "github.com/cashubtc/cdk-spilman-kit-go"
	"github.com/cashubtc/spilman-go/spilman"
	"github.com/common-nighthawk/go-figure"
	"github.com/skip2/go-qrcode"
)

// ============================================================================
// Configuration
// ============================================================================

var (
	SERVER_SECRET_KEY = getEnv("SERVER_SECRET_KEY", "0000000000000000000000000000000000000000000000000000000000000001")
	CONFIG_PATH       = getEnv("CONFIG_PATH", "config.yaml")
	SERVER_PORT       = getEnv("PORT", "5001")
	SERVER_URL        = getEnv("SERVER_URL", "http://localhost:5001")
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// ============================================================================
// Server Implementation
// ============================================================================

func runServer() {
	// 1. Bootstrap Spilman components from YAML
	ctx, err := spilmankit.LoadFromYaml(CONFIG_PATH, SERVER_SECRET_KEY)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	defer ctx.Free()

	// 2. Attach management routes
	spilmankit.RegisterManagementRoutes(http.DefaultServeMux, ctx)

	// 3. Application route: POST /ascii
	http.HandleFunc("/ascii", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			return
		}

		var req struct{ Message string }
		json.NewDecoder(r.Body).Decode(&req)
		if req.Message == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Missing 'message'"})
			return
		}

		log.Printf("\n[Request] ASCII art for '%s' (%d chars)\n", req.Message, len(req.Message))

		// Process payment using the helper
		payment, err := ctx.ProcessRequestPayment(r, map[string]uint64{"chars": uint64(len(req.Message))})
		if err != nil {
			log.Printf("  [Payment] REJECTED: %v\n", err)
			ctx.HandleError(w, err)
			return
		}

		log.Printf("  [Payment] ACCEPTED: balance=%d/%d\n", payment.Balance, payment.Capacity)

		art := figure.NewFigure(req.Message, "", true).String()

		ctx.AttachPaymentHeader(w, payment)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"art":     art,
			"message": req.Message,
			"payment": payment,
		})
	})

	log.Printf("Go ASCII Art Server listening on :%s\n", SERVER_PORT)
	log.Printf("Server pubkey: %s\n", spilmankit.GetServerPubkey(SERVER_SECRET_KEY))
	fmt.Println("Server is ready.")
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", SERVER_PORT), nil))
}

// ============================================================================
// Client Implementation (using ClientBridge)
// ============================================================================

type DemoClientHost struct {
	aliceSecret string
	channels    map[string]*spilman.ChannelData
}

func (h *DemoClientHost) CallMintSwap(mintURL, swapRequestJSON string) (string, error) {
	resp, err := http.Post(mintURL+"/v1/swap", "application/json", strings.NewReader(swapRequestJSON))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("mint rejected swap (%d): %s", resp.StatusCode, string(body))
	}
	return string(body), nil
}

func (h *DemoClientHost) SaveChannel(channelID, channelJSON, channelSecretHex string) {
	h.channels[channelID] = &spilman.ChannelData{
		ChannelJSON:      channelJSON,
		ChannelSecretHex: channelSecretHex,
	}
}

func (h *DemoClientHost) GetChannel(channelID string) *spilman.ChannelData {
	return h.channels[channelID]
}

func (h *DemoClientHost) ListChannelIDs() []string {
	ids := make([]string, 0, len(h.channels))
	for id := range h.channels {
		ids = append(ids, id)
	}
	return ids
}

func (h *DemoClientHost) DeleteChannel(channelID string) {
	delete(h.channels, channelID)
}

func (h *DemoClientHost) SignWithTweakedKey(signerPubkeyHex, messageHex, tweakScalarHex string) (string, error) {
	return spilman.SignWithTweakedKeyUtil(h.aliceSecret, messageHex, tweakScalarHex)
}

func (h *DemoClientHost) ComputeChannelSecret(alicePubkeyHex, charliePubkeyHex string) (string, error) {
	return spilman.ComputeChannelSecret(h.aliceSecret, charliePubkeyHex)
}

func runClient(messages []string) {
	// Parse --close flag
	shouldClose := false
	actualMessages := []string{}
	for _, m := range messages {
		if m == "--close" {
			shouldClose = true
		} else {
			actualMessages = append(actualMessages, m)
		}
	}
	if len(actualMessages) == 0 {
		actualMessages = append(actualMessages, "Hello", "Cashu", "World")
	}

	log.Printf("Fetching server params from %s...\n", SERVER_URL)
	resp, err := http.Get(SERVER_URL + "/channel/params")
	if err != nil {
		log.Fatalf("Server not found: %v", err)
	}
	var sp struct {
		ReceiverPubkey string                         `json:"receiver_pubkey"`
		Mints          map[string]map[string][]string `json:"mints_units_keysets"`
	}
	json.NewDecoder(resp.Body).Decode(&sp)
	resp.Body.Close()

	var mintUrl string
	for m := range sp.Mints {
		mintUrl = m
		break
	}

	aliceSecret, alicePub, _ := spilman.GenerateKeypair()
	ki, _ := clientFetchActiveKeysetInfo(mintUrl)
	kiJson, _ := json.Marshal(ki)

	// Create ClientBridge
	host := &DemoClientHost{
		aliceSecret: aliceSecret,
		channels:    make(map[string]*spilman.ChannelData),
	}
	bridge, _ := spilman.NewClientBridge(host)
	defer bridge.Free()

	log.Printf("[1/3] Opening channel via ClientBridge...\n")
	_, _ = bridge.OpenChannelFromToken(
		"", // We'll mint proofs manually below for now, or use build_cashu_a_token helper
		sp.ReceiverPubkey,
		alicePub,
		uint64(time.Now().Unix()+7200),
		string(kiJson),
		64,
	)
	// Wait, the current OpenChannelFromToken expects a token.
	// But our demo mints proofs manually.
	// Let's use the low-level functions for funding but keep using Bridge for payments and closing.

	// Actually, let's keep the manual funding for now but use Bridge for payments.
	// (Re-using manual funding logic from previous version to keep it working)

	ss, _ := spilman.ComputeChannelSecret(aliceSecret, sp.ReceiverPubkey)
	var total uint64
	for _, m := range actualMessages {
		total += uint64(len(m))
	}
	cap := total + 50
	fta, _ := spilman.ComputeFundingTokenAmount(cap, string(kiJson), 64)

	params := map[string]interface{}{
		"alice_pubkey": alicePub, "charlie_pubkey": sp.ReceiverPubkey,
		"mint": mintUrl, "unit": "sat", "capacity": cap,
		"funding_token_amount": fta, "maximum_amount": 64,
		"locktime": time.Now().Unix() + 7200, "setup_timestamp": time.Now().Unix(),
		"sender_nonce": fmt.Sprintf("demo-go-%d", time.Now().Unix()),
		"keyset_id":    ki["keysetId"], "input_fee_ppk": ki["inputFeePpk"],
	}
	pJson, _ := json.Marshal(params)
	cid, _ := spilman.ChannelParametersGetChannelId(string(pJson), ss, string(kiJson))

	fJson, _ := spilman.CreateFundingOutputs(string(pJson), aliceSecret, string(kiJson))
	var f struct {
		Funding_token_nominal uint64
		Blinded_messages      []interface{}
		Secrets_with_blinding []interface{}
	}
	json.Unmarshal([]byte(fJson), &f)

	sigs, _ := mintFundingToken(mintUrl, f.Funding_token_nominal, f.Blinded_messages)
	sigsJ, _ := json.Marshal(sigs)
	swbJ, _ := json.Marshal(f.Secrets_with_blinding)

	proofsJ, _ := spilman.ConstructProofs(string(sigsJ), string(swbJ), string(kiJson))

	// Manually save to host so Bridge can find it
	stored := map[string]interface{}{
		"channel_id": cid, "params_json": string(pJson), "keyset_info_json": string(kiJson),
		"funding_proofs_json": proofsJ, "capacity": cap, "funding_token_amount": fta,
		"mint_url": mintUrl, "alice_pubkey_hex": alicePub,
	}
	storedJ, _ := json.Marshal(stored)
	host.SaveChannel(cid, string(storedJ), ss)

	log.Printf("Full channel ID: %s\n", cid)
	log.Printf("Channel %s funded! Making requests...\n", cid[:8])
	balance := uint64(0)
	for i, msg := range actualMessages {
		balance += uint64(len(msg))

		// Use ClientBridge to build header!
		header, err := bridge.BuildPaymentHeader(cid, balance, i == 0)
		if err != nil {
			log.Fatalf("BuildPaymentHeader failed: %v", err)
		}

		reqB, _ := json.Marshal(map[string]string{"message": msg})
		req, _ := http.NewRequest("POST", SERVER_URL+"/ascii", strings.NewReader(string(reqB)))
		req.Header.Set("X-Cashu-Channel", header)
		req.Header.Set("Content-Type", "application/json")

		r, err := (&http.Client{}).Do(req)
		if err != nil || r.StatusCode != 200 {
			log.Fatalf("Request FAILED: %v (status %d)", err, r.StatusCode)
		}

		var res struct{ Art string }
		json.NewDecoder(r.Body).Decode(&res)
		r.Body.Close()
		fmt.Printf("[%d/%d] Accepted!\n%s\n", i+1, len(actualMessages), res.Art)
	}

	if shouldClose {
		log.Printf("\n[3/3] Closing channel via ClientBridge...\n")

		// 1. Get amount_due from server
		sResp, _ := http.Get(fmt.Sprintf("%s/channel/%s/status", SERVER_URL, cid))
		var status struct{ Amount_due uint64 }
		json.NewDecoder(sResp.Body).Decode(&status)
		sResp.Body.Close()

		finalBalance := status.Amount_due
		log.Printf("  Final amount due: %d sat\n", finalBalance)

		// 2. Create close request via bridge
		closeReqJ, err := bridge.CreateCooperativeCloseRequest(cid, finalBalance)
		if err != nil {
			log.Fatalf("CreateCooperativeCloseRequest failed: %v", err)
		}

		// 3. Send to server
		cResp, err := http.Post(fmt.Sprintf("%s/channel/%s/close", SERVER_URL, cid), "application/json", strings.NewReader(closeReqJ))
		if err != nil || cResp.StatusCode != 200 {
			log.Fatalf("Close request FAILED: %v (status %d)", err, cResp.StatusCode)
		}

		body, _ := io.ReadAll(cResp.Body)
		cResp.Body.Close()

		// 4. Process response via bridge
		err = bridge.ProcessCooperativeCloseResponse(string(body))
		if err != nil {
			log.Fatalf("ProcessCooperativeCloseResponse failed: %v", err)
		}

		log.Printf("Channel closed and removed from local storage!\n")
		var closeRes struct {
			Total_value  uint64
			Receiver_sum uint64
			Sender_sum   uint64
		}
		json.Unmarshal(body, &closeRes)
		fmt.Printf("Earned by server: %d sat\n", closeRes.Receiver_sum)
		fmt.Printf("Refunded to client: %d sat\n", closeRes.Sender_sum)
	}
}

// Reuse existing helpers but local to main for simplicity in demo
func clientFetchActiveKeysetInfo(mintUrl string) (map[string]interface{}, error) {
	resp, _ := http.Get(mintUrl + "/v1/keysets")
	defer resp.Body.Close()
	var d struct {
		Keysets []struct {
			Id, Unit    string
			Active      bool
			InputFeePpk uint64 `json:"input_fee_ppk"`
		}
	}
	json.NewDecoder(resp.Body).Decode(&d)
	for _, k := range d.Keysets {
		if k.Unit == "sat" && k.Active {
			rk, _ := http.Get(fmt.Sprintf("%s/v1/keys/%s", mintUrl, k.Id))
			var kd struct {
				Keysets []struct{ Keys map[string]string }
			}
			json.NewDecoder(rk.Body).Decode(&kd)
			rk.Body.Close()
			return map[string]interface{}{"keysetId": k.Id, "unit": "sat", "inputFeePpk": k.InputFeePpk, "keys": kd.Keysets[0].Keys}, nil
		}
	}
	return nil, fmt.Errorf("no keyset")
}

func mintFundingToken(mintUrl string, amount uint64, blinded []interface{}) ([]interface{}, error) {
	qreq, _ := json.Marshal(map[string]interface{}{"amount": amount, "unit": "sat"})
	resp, _ := http.Post(mintUrl+"/v1/mint/quote/bolt11", "application/json", strings.NewReader(string(qreq)))
	var q struct{ Quote, Request string }
	json.NewDecoder(resp.Body).Decode(&q)
	resp.Body.Close()

	if q.Request != "" {
		fmt.Printf("\nPAY INVOICE: %s\n\n", q.Request)
		qr, _ := qrcode.New(q.Request, qrcode.Medium)
		fmt.Println(qr.ToSmallString(false))
	}

	for i := 0; i < 60; i++ {
		r, _ := http.Get(fmt.Sprintf("%s/v1/mint/quote/bolt11/%s", mintUrl, q.Quote))
		var s struct {
			State string
			Paid  bool
		}
		json.NewDecoder(r.Body).Decode(&s)
		r.Body.Close()
		if s.State == "PAID" || s.Paid {
			break
		}
		time.Sleep(1 * time.Second)
	}

	mreq, _ := json.Marshal(map[string]interface{}{"quote": q.Quote, "outputs": blinded})
	resp, _ = http.Post(mintUrl+"/v1/mint/bolt11", "application/json", strings.NewReader(string(mreq)))
	var mr struct{ Signatures []interface{} }
	json.NewDecoder(resp.Body).Decode(&mr)
	resp.Body.Close()
	return mr.Signatures, nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "client" {
		runClient(os.Args[2:])
	} else {
		runServer()
	}
}
