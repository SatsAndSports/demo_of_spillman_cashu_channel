// nutmix-setup-units - Create keysets for NutMix mint via admin API
//
// Usage: nutmix-setup-units <unit1> [unit2] [unit3] ...
//
// Examples:
//   nutmix-setup-units sat
//   nutmix-setup-units sat msat usd
//
// Environment variables:
//   MINT_URL         - Mint base URL (default: http://localhost:3338)
//   ADMIN_NOSTR_NSEC - Admin's Nostr secret key (nsec format, required)
//
// This tool authenticates via Nostr (NIP-07 style) and calls the admin API
// to create keysets for the specified units.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// Unit constants matching NutMix api/cashu/types.go
const (
	UnitSat  = 1
	UnitMsat = 2
	UnitUSD  = 3
	UnitEUR  = 4
	UnitAUTH = 5
)

var unitMap = map[string]int{
	"sat":  UnitSat,
	"msat": UnitMsat,
	"usd":  UnitUSD,
	"eur":  UnitEUR,
	"auth": UnitAUTH,
}

type RotateRequest struct {
	Unit             int  `json:"Unit"`
	Fee              uint `json:"Fee"`
	ExpireLimitHours uint `json:"ExpireLimitHours"`
}

func main() {
	// Load .env file (optional, for local development)
	if err := godotenv.Load(); err != nil {
		// Not an error - env vars can be set directly
	}

	// Get units from command line args (required)
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <unit1> [unit2] ...\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s sat msat usd\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Units: sat, msat, usd, eur, auth\n")
		fmt.Fprintf(os.Stderr, "Environment: MINT_URL (default: http://localhost:3338), ADMIN_NOSTR_NSEC (required)\n")
		os.Exit(1)
	}
	units := os.Args[1:]

	// Validate units
	for _, unit := range units {
		if _, ok := unitMap[strings.ToLower(unit)]; !ok {
			log.Fatalf("Unknown unit: %s (valid: sat, msat, usd, eur, auth)", unit)
		}
	}

	// Get configuration from environment
	mintURL := os.Getenv("MINT_URL")
	if mintURL == "" {
		mintURL = "http://localhost:3338"
	}

	nsecStr := os.Getenv("ADMIN_NOSTR_NSEC")
	if nsecStr == "" {
		log.Fatal("ADMIN_NOSTR_NSEC environment variable is required")
	}

	// Decode nsec to get private key
	prefix, privateKeyHex, err := nip19.Decode(nsecStr)
	if err != nil || prefix != "nsec" {
		log.Fatalf("Invalid ADMIN_NOSTR_NSEC: %v", err)
	}
	privateKey := privateKeyHex.(string)

	// Create HTTP client with cookie jar
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
	}

	fmt.Printf("Connecting to mint at %s\n", mintURL)

	// Step 1: Get login page to extract nonce
	nonce, err := getNonce(client, mintURL)
	if err != nil {
		log.Fatalf("Failed to get nonce: %v", err)
	}
	fmt.Printf("Got nonce: %s\n", nonce)

	// Step 2: Create and sign Nostr event
	signedEvent, err := createSignedEvent(privateKey, nonce)
	if err != nil {
		log.Fatalf("Failed to sign event: %v", err)
	}
	fmt.Println("Signed login event")

	// Step 3: Login
	err = login(client, mintURL, signedEvent)
	if err != nil {
		log.Fatalf("Failed to login: %v", err)
	}
	fmt.Println("Login successful")

	// Step 4: Create keysets for each unit
	for _, unit := range units {
		unitLower := strings.ToLower(unit)
		unitInt := unitMap[unitLower]

		err = createKeyset(client, mintURL, unitInt)
		if err != nil {
			log.Printf("Failed to create keyset for %s: %v", unit, err)
			continue
		}
		fmt.Printf("Created keyset for unit: %s\n", unit)
	}

	fmt.Println("Setup complete!")
}

func getNonce(client *http.Client, mintURL string) (string, error) {
	resp, err := client.Get(mintURL + "/admin/login")
	if err != nil {
		return "", fmt.Errorf("GET /admin/login failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Extract nonce from: <input name="passwordNonce" hidden value="..."/>
	re := regexp.MustCompile(`name="passwordNonce"[^>]*value="([^"]+)"`)
	matches := re.FindSubmatch(body)
	if len(matches) < 2 {
		return "", fmt.Errorf("nonce not found in login page")
	}

	return string(matches[1]), nil
}

func createSignedEvent(privateKey string, nonce string) (*nostr.Event, error) {
	pubkey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	event := &nostr.Event{
		PubKey:    pubkey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      27235,
		Tags:      nostr.Tags{},
		Content:   nonce,
	}

	err = event.Sign(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign event: %w", err)
	}

	return event, nil
}

func login(client *http.Client, mintURL string, event *nostr.Event) error {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	resp, err := client.Post(
		mintURL+"/admin/login",
		"application/json",
		bytes.NewReader(eventJSON),
	)
	if err != nil {
		return fmt.Errorf("POST /admin/login failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func createKeyset(client *http.Client, mintURL string, unit int) error {
	reqBody := RotateRequest{
		Unit:             unit,
		Fee:              0,
		ExpireLimitHours: 8760, // 1 year
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := client.Post(
		mintURL+"/admin/rotate/sats",
		"application/json",
		bytes.NewReader(jsonBody),
	)
	if err != nil {
		return fmt.Errorf("POST /admin/rotate/sats failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("rotate failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
