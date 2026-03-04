package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
)

var (
	claims       int
	faucetToken  string
	faucetConfig string

	errRateLimit      = fmt.Errorf("rate limited")
	errFaucetLimitHit = fmt.Errorf("daily faucet limit reached")
)

var tokenInfo = map[string]struct {
	perClaim string
	amount   float64
	maxDay   int
}{
	"eth":  {"0.0001 ETH", 0.0001, 1000},
	"usdc": {"1 USDC", 1, 10},
}

var faucetCmd = &cobra.Command{
	Use:   "faucet [addresses...]",
	Short: "Request free testnet tokens from the Coinbase CDP faucet",
	Long: `Claim Base Sepolia tokens from the Coinbase Developer Platform faucet.

Supported tokens:
  eth    0.0001 per claim, max 1000/day
  usdc   1 per claim, max 10/day

Requires a free CDP API key — run "tf init" to set up.

Examples:
  tf faucet 0xAddr1 0xAddr2
  tf faucet --claims 100 0xAddr1
  tf faucet --token usdc 0xAddr1
  tf faucet --config wallets.json
  tf faucet --config wallets.json --claims 10 --token usdc`,
	RunE: runFaucet,
}

func init() {
	faucetCmd.Flags().IntVar(&claims, "claims", 1, "number of faucet claims per address")
	faucetCmd.Flags().StringVar(&faucetToken, "token", "eth", "token to claim: eth, usdc")
	faucetCmd.Flags().StringVar(&faucetConfig, "config", "", "path to wallets JSON config file (use instead of addresses)")
	rootCmd.AddCommand(faucetCmd)
}

const cdpFaucetURL = "https://api.cdp.coinbase.com/platform/v2/evm/faucet"

func runFaucet(cmd *cobra.Command, args []string) error {
	// Build address list from --config or positional args
	type target struct {
		name string
		addr common.Address
	}
	var targets []target

	if faucetConfig != "" {
		data, err := os.ReadFile(faucetConfig)
		if err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}
		var entries []walletEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			return fmt.Errorf("failed to parse config file: %w", err)
		}
		for _, e := range entries {
			pk := strings.TrimPrefix(e.PK, "0x")
			key, err := crypto.HexToECDSA(pk)
			if err != nil {
				return fmt.Errorf("invalid private key for %s: %w", e.Name, err)
			}
			targets = append(targets, target{
				name: e.Name,
				addr: crypto.PubkeyToAddress(key.PublicKey),
			})
		}
	} else {
		if len(args) == 0 {
			return fmt.Errorf("provide addresses or use --config <wallets.json>")
		}
		for _, arg := range args {
			if !common.IsHexAddress(arg) {
				fmt.Printf("  SKIP  %s  (invalid address)\n", arg)
				continue
			}
			targets = append(targets, target{
				name: arg[:10],
				addr: common.HexToAddress(arg),
			})
		}
	}

	if len(targets) == 0 {
		return fmt.Errorf("no valid addresses to fund")
	}

	keyID := os.Getenv("CDP_API_KEY_ID")
	keySecret := os.Getenv("CDP_API_KEY_SECRET")

	// Fallback to ~/.tf/config.json
	if keyID == "" || keySecret == "" {
		cfg, _ := loadConfig()
		if keyID == "" {
			keyID = cfg.CDPAPIKeyID
		}
		if keySecret == "" {
			keySecret = cfg.CDPAPIKeySecret
		}
	}

	// Still missing — run interactive setup
	if keyID == "" || keySecret == "" {
		fmt.Println("\n  No CDP API keys found. Let's set them up.")
		cfg, err := promptCDPKeys()
		if err != nil {
			return err
		}
		keyID = cfg.CDPAPIKeyID
		keySecret = cfg.CDPAPIKeySecret
	}

	privKey, err := parseEd25519Key(keySecret)
	if err != nil {
		return fmt.Errorf("invalid CDP_API_KEY_SECRET: %w", err)
	}

	info, ok := tokenInfo[faucetToken]
	if !ok {
		return fmt.Errorf("unknown token %q — use eth or usdc", faucetToken)
	}

	total := float64(claims*len(targets)) * info.amount
	fmt.Printf("\n  Faucet: Coinbase CDP (Base Sepolia)\n")
	fmt.Printf("  Token:  %s (%s per claim, max %d/day)\n", strings.ToUpper(faucetToken), info.perClaim, info.maxDay)
	fmt.Printf("  Claims: %d per address, %d addresses (~%.4f %s total)\n\n", claims, len(targets), total, strings.ToUpper(faucetToken))

	totalSent := 0
	totalFailed := 0

	const maxRetries = 5
	limitHit := false

	for _, t := range targets {
		if limitHit {
			break
		}
		retries := 0
		for i := 0; i < claims; i++ {
			token, err := buildJWT(keyID, privKey)
			if err != nil {
				fmt.Printf("  FAIL  %-10s %s  claim %d: jwt: %v\n", t.name, t.addr.Hex(), i+1, err)
				totalFailed++
				continue
			}

			txHash, err := callFaucet(token, t.addr.Hex(), faucetToken)
			if err != nil {
				if errors.Is(err, errFaucetLimitHit) {
					fmt.Printf("\n  STOP  %v\n", err)
					limitHit = true
					break
				}
				if errors.Is(err, errRateLimit) {
					retries++
					if retries > maxRetries {
						fmt.Printf("  FAIL  %-10s %s  claim %d: %v (after %d retries)\n", t.name, t.addr.Hex(), i+1, err, maxRetries)
						totalFailed++
						retries = 0
						continue
					}
					wait := time.Duration(retries) * 10 * time.Second
					fmt.Printf("  WAIT  %-10s %s  claim %d: %v — retrying in %s...\n", t.name, t.addr.Hex(), i+1, err, wait)
					time.Sleep(wait)
					i-- // retry this claim
					continue
				}
				fmt.Printf("  FAIL  %-10s %s  claim %d: %v\n", t.name, t.addr.Hex(), i+1, err)
				totalFailed++
				continue
			}

			retries = 0
			fmt.Printf("  SENT  %-10s %s  claim %d/%d  tx: %s\n", t.name, t.addr.Hex(), i+1, claims, txHash)
			totalSent++
		}
	}

	fmt.Printf("\n  Done: %d claims sent, %d failed (%.4f %s total)\n\n",
		totalSent, totalFailed, float64(totalSent)*info.amount, strings.ToUpper(faucetToken))
	return nil
}

func callFaucet(jwtToken, address, token string) (string, error) {
	body := fmt.Sprintf(`{"network":"base-sepolia","address":"%s","token":"%s"}`, address, token)
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
		var apiErr struct {
			ErrorType    string `json:"errorType"`
			ErrorMessage string `json:"errorMessage"`
		}
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.ErrorType == "faucet_limit_exceeded" {
			return "", fmt.Errorf("%w for this token/network — try again tomorrow", errFaucetLimitHit)
		}
		return "", fmt.Errorf("%w: %s", errRateLimit, string(respBody))
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
