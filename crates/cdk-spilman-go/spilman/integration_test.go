//go:build integration

package spilman

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
