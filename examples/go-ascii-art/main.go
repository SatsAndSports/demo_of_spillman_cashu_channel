package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	setupManagementRoutes(ctx)

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
	log.Printf("Server pubkey: %s\n", getServerPubkey(SERVER_SECRET_KEY))
	fmt.Println("Server is ready.")
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", SERVER_PORT), nil))
}

func getServerPubkey(sk string) string {
	p, _ := spilman.SecretKeyToPubkey(sk)
	return p
}

func setupManagementRoutes(ctx *spilmankit.ConfigurableSpilman) {
	http.HandleFunc("/channel/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/channel/register" {
			handleRegister(w, r, ctx)
			return
		}
		if path == "/channel/params" {
			handleParams(w, r, ctx)
			return
		}

		parts := strings.Split(strings.TrimPrefix(path, "/channel/"), "/")
		if len(parts) < 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		id := parts[0]
		action := parts[1]

		switch action {
		case "status":
			handleStatus(w, r, ctx, id)
		case "close":
			handleClose(w, r, ctx, id)
		case "unilateral-close":
			handleUnilateralClose(w, r, ctx, id)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func handleParams(w http.ResponseWriter, r *http.Request, ctx *spilmankit.ConfigurableSpilman) {
	activeUnits := ctx.Stores.GetActiveUnits()
	compPricing := make(map[string]interface{})
	for unit, entry := range ctx.Config.Pricing {
		if _, ok := activeUnits[unit]; !ok {
			continue
		}
		data := map[string]interface{}{
			"min_capacity": entry.MinCapacity,
			"minCapacity":  entry.MinCapacity,
			"variables":    entry.Variables,
		}
		if entry.MaxAmountPerOutput != nil {
			data["max_amount_per_output"] = *entry.MaxAmountPerOutput
			data["maxAmountPerOutput"] = *entry.MaxAmountPerOutput
		}
		if p, ok := entry.Variables["chars"]; ok {
			data["per_char"] = p
		}
		compPricing[unit] = data
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"receiver_pubkey":       getServerPubkey(SERVER_SECRET_KEY),
		"pricing":               compPricing,
		"mints_units_keysets":   ctx.Stores.GetMintsUnitsKeysets(),
		"min_expiry_in_seconds": ctx.Config.MinExpirySeconds,
	})
}

func handleRegister(w http.ResponseWriter, r *http.Request, ctx *spilmankit.ConfigurableSpilman) {
	if r.Method != http.MethodPost {
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if b, ok := body["balance"].(float64); ok && b != 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Bad request", "reason": fmt.Sprintf("funding requires balance=0, got %v", b),
		})
		return
	}

	jsonStr, _ := json.Marshal(body)
	result, err := ctx.Bridge.FundChannel(string(jsonStr))
	if err != nil {
		ctx.HandleError(w, err)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true, "channel_id": result.ChannelID, "capacity": result.Capacity, "already_known": result.AlreadyKnown,
	})
}

func handleStatus(w http.ResponseWriter, r *http.Request, ctx *spilmankit.ConfigurableSpilman, id string) {
	funding, ok := ctx.Stores.GetFunding(id)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "unknown channel"})
		return
	}
	var params struct{ Capacity uint64 }
	json.Unmarshal([]byte(funding.ParamsJson), &params)
	balance, _ := ctx.Stores.GetBalance(id)
	closedData, isClosed := ctx.Stores.GetClosedData(id)
	usage := ctx.Stores.GetUsage(id)

	res := map[string]interface{}{
		"channel_id": id, "capacity": params.Capacity, "balance": uint64(0),
		"usage": usage, "chars_served": usage["chars"], "amount_due": ctx.Host.GetAmountDue(id, nil),
		"closed": isClosed,
	}
	if balance != nil {
		res["balance"] = balance.Balance
	}
	if isClosed {
		res["closed_amount"] = closedData.ClosedAmount
	}
	json.NewEncoder(w).Encode(res)
}

func handleClose(w http.ResponseWriter, r *http.Request, ctx *spilmankit.ConfigurableSpilman, id string) {
	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	balanceRaw, ok := data["balance"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing balance"})
		return
	}
	balance := uint64(balanceRaw.(float64))

	// Check if already closed
	if closedInfo, ok := ctx.Stores.GetClosedData(id); ok {
		if closedInfo.ClosedAmount == balance {
			var sp interface{}
			json.Unmarshal([]byte(closedInfo.SenderProofsJson), &sp)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "channel_id": id, "already_closed": true,
				"total_value":  closedInfo.ReceiverSum + closedInfo.SenderSum,
				"receiver_sum": closedInfo.ReceiverSum, "sender_sum": closedInfo.SenderSum,
				"sender_proofs": sp,
			})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":         "channel already closed at different balance",
			"closed_amount": closedInfo.ClosedAmount, "requested_amount": balance,
		})
		return
	}

	data["channel_id"] = id
	jsonStr, _ := json.Marshal(data)
	res, err := ctx.Bridge.ExecuteCooperativeClose(string(jsonStr))
	if err != nil {
		ctx.HandleError(w, err)
		return
	}
	var sp interface{}
	json.Unmarshal([]byte(res.SenderProofs), &sp)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true, "channel_id": res.ChannelID, "total_value": res.TotalValue,
		"receiver_sum": res.ReceiverSum, "sender_sum": res.SenderSum, "sender_proofs": sp,
		"already_closed": res.AlreadyClosed,
	})
}

func handleUnilateralClose(w http.ResponseWriter, r *http.Request, ctx *spilmankit.ConfigurableSpilman, id string) {
	// Check if already closed
	if closedInfo, ok := ctx.Stores.GetClosedData(id); ok {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true, "channel_id": id, "earnedBeforeStage2Fees": closedInfo.ReceiverSum, "already_closed": true,
		})
		return
	}

	if _, ok := ctx.Stores.GetFunding(id); !ok {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "unknown channel"})
		return
	}

	res, err := ctx.Bridge.ExecuteUnilateralClose(id)
	if err != nil {
		ctx.HandleError(w, err)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true, "channel_id": id, "earnedBeforeStage2Fees": res.ReceiverSum, "already_closed": res.AlreadyClosed,
	})
}

// ============================================================================
// Client Implementation (simplified)
// ============================================================================

func runClient(messages []string) {
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
	ss, _ := spilman.ComputeChannelSecret(aliceSecret, sp.ReceiverPubkey)

	var total uint64
	for _, m := range messages {
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
	}
	json.Unmarshal([]byte(fJson), &f)

	sigs, _ := mintFundingToken(mintUrl, f.Funding_token_nominal, f.Blinded_messages)
	sigsJ, _ := json.Marshal(sigs)

	// Create swbJ correctly
	var fFull struct{ Secrets_with_blinding []interface{} }
	json.Unmarshal([]byte(fJson), &fFull)
	swbJ, _ := json.Marshal(fFull.Secrets_with_blinding)

	proofsJ, _ := spilman.ConstructProofs(string(sigsJ), string(swbJ), string(kiJson))
	var proofs []interface{}
	json.Unmarshal([]byte(proofsJ), &proofs)

	log.Printf("Full channel ID: %s\n", cid)
	log.Printf("Channel %s funded! Making requests...\n", cid[:8])
	balance := uint64(0)
	for i, msg := range messages {
		balance += uint64(len(msg))
		updJ, _ := spilman.CreateSignedBalanceUpdate(string(pJson), string(kiJson), aliceSecret, proofsJ, balance)
		var upd struct{ Signature string }
		json.Unmarshal([]byte(updJ), &upd)

		pay := map[string]interface{}{"channel_id": cid, "balance": balance, "signature": upd.Signature}
		if i == 0 {
			pay["params"] = params
			pay["funding_proofs"] = proofs
		}
		payH, _ := json.Marshal(pay)

		reqB, _ := json.Marshal(map[string]string{"message": msg})
		req, _ := http.NewRequest("POST", SERVER_URL+"/ascii", strings.NewReader(string(reqB)))
		req.Header.Set("X-Cashu-Channel", base64.StdEncoding.EncodeToString(payH))
		req.Header.Set("Content-Type", "application/json")

		r, _ := (&http.Client{}).Do(req)
		if r.StatusCode == 200 {
			var res struct{ Art string }
			json.NewDecoder(r.Body).Decode(&res)
			fmt.Printf("[%d/%d] Accepted!\n%s\n", i+1, len(messages), res.Art)
		} else {
			log.Fatalf("FAILED: %d", r.StatusCode)
		}
		r.Body.Close()
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
