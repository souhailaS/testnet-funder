package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
)

var claims int

var faucetCmd = &cobra.Command{
	Use:   "faucet [addresses...]",
	Short: "Request free testnet ETH from the Coinbase CDP faucet",
	Long: `Claim Base Sepolia ETH from the Coinbase Developer Platform faucet.

Each claim sends 0.0001 ETH. Use --claims to request multiple times per address
(max 1000 claims/day across all addresses).

Requires a free CDP API key from https://portal.cdp.coinbase.com/
Set CDP_API_KEY_ID and CDP_API_KEY_SECRET in your .env file.

Examples:
  tf faucet 0xAddr1 0xAddr2
  tf faucet --claims 100 0xAddr1`,
	Args: cobra.MinimumNArgs(1),
	RunE: runFaucet,
}

func init() {
	faucetCmd.Flags().IntVar(&claims, "claims", 1, "number of faucet claims per address (0.0001 ETH each)")
	rootCmd.AddCommand(faucetCmd)
}

const cdpFaucetURL = "https://api.cdp.coinbase.com/platform/v2/evm/faucet"

func runFaucet(cmd *cobra.Command, args []string) error {
	keyID := os.Getenv("CDP_API_KEY_ID")
	keySecret := os.Getenv("CDP_API_KEY_SECRET")
	if keyID == "" || keySecret == "" {
		return fmt.Errorf("CDP_API_KEY_ID and CDP_API_KEY_SECRET required — get a free key at https://portal.cdp.coinbase.com/")
	}

	privKey, err := parseEd25519Key(keySecret)
	if err != nil {
		return fmt.Errorf("invalid CDP_API_KEY_SECRET: %w", err)
	}

	fmt.Printf("\n  Faucet: Coinbase CDP (Base Sepolia)\n")
	fmt.Printf("  Claims: %d per address (%.4f ETH each)\n\n", claims, float64(claims)*0.0001)

	totalSent := 0
	totalFailed := 0

	for _, arg := range args {
		if !common.IsHexAddress(arg) {
			fmt.Printf("  SKIP  %s  (invalid address)\n", arg)
			continue
		}
		addr := common.HexToAddress(arg)

		for i := 0; i < claims; i++ {
			token, err := buildJWT(keyID, privKey)
			if err != nil {
				fmt.Printf("  FAIL  %s  claim %d: jwt: %v\n", addr.Hex(), i+1, err)
				totalFailed++
				continue
			}

			txHash, err := callFaucet(token, addr.Hex())
			if err != nil {
				fmt.Printf("  FAIL  %s  claim %d: %v\n", addr.Hex(), i+1, err)
				totalFailed++
				continue
			}

			fmt.Printf("  SENT  %s  claim %d/%d  tx: %s\n", addr.Hex(), i+1, claims, txHash)
			totalSent++
		}
	}

	fmt.Printf("\n  Done: %d claims sent, %d failed (%.4f ETH total)\n\n",
		totalSent, totalFailed, float64(totalSent)*0.0001)
	return nil
}

func callFaucet(jwtToken, address string) (string, error) {
	body := fmt.Sprintf(`{"network":"base-sepolia","address":"%s","token":"eth"}`, address)
	req, err := http.NewRequest("POST", cdpFaucetURL, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 429 {
		return "", fmt.Errorf("rate limited — try again later")
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		TransactionHash string `json:"transactionHash"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	return result.TransactionHash, nil
}

func parseEd25519Key(secret string) (ed25519.PrivateKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		// try URL-safe base64
		decoded, err = base64.RawURLEncoding.DecodeString(secret)
		if err != nil {
			return nil, fmt.Errorf("failed to base64-decode key secret")
		}
	}
	if len(decoded) < 32 {
		return nil, fmt.Errorf("key secret too short (got %d bytes, need 32)", len(decoded))
	}
	seed := decoded[:32]
	return ed25519.NewKeyFromSeed(seed), nil
}

func buildJWT(keyID string, privKey ed25519.PrivateKey) (string, error) {
	nonce, err := randomHex(16)
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()

	header := map[string]string{
		"alg":   "EdDSA",
		"typ":   "JWT",
		"kid":   keyID,
		"nonce": nonce,
	}
	payload := map[string]interface{}{
		"sub":   keyID,
		"iss":   "cdp",
		"aud":   []string{"cdp_service"},
		"nbf":   now,
		"exp":   now + 120,
		"uris":  []string{"POST api.cdp.coinbase.com/platform/v2/evm/faucet"},
		"nonce": nonce,
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64
	sig := ed25519.Sign(privKey, []byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
