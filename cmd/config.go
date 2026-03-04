package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type config struct {
	CDPAPIKeyID     string `json:"cdp_api_key_id"`
	CDPAPIKeySecret string `json:"cdp_api_key_secret"`
}

func configPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".tf", "config.json")
}

func loadConfig() (config, error) {
	var cfg config
	path := configPath()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}

	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

func saveConfig(cfg config) error {
	path := configPath()
	if path == "" {
		return fmt.Errorf("could not determine home directory")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

func printCDPInstructions() {
	fmt.Println()
	fmt.Println("  To use the faucet, you need a free Coinbase Developer Platform (CDP) API key.")
	fmt.Println()
	fmt.Println("  1. Go to https://portal.cdp.coinbase.com/")
	fmt.Println("  2. Sign up or log in")
	fmt.Println("  3. Navigate to \"API Keys\" in the sidebar")
	fmt.Println("  4. Click \"Create API Key\"")
	fmt.Println("  5. Copy the API Key ID and API Key Secret")
	fmt.Println()
}

func promptCDPKeys() (config, error) {
	printCDPInstructions()

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("  API Key ID: ")
	keyID, err := reader.ReadString('\n')
	if err != nil {
		return config{}, fmt.Errorf("failed to read input: %w", err)
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return config{}, fmt.Errorf("API Key ID cannot be empty")
	}

	fmt.Print("  API Key Secret: ")
	keySecret, err := reader.ReadString('\n')
	if err != nil {
		return config{}, fmt.Errorf("failed to read input: %w", err)
	}
	keySecret = strings.TrimSpace(keySecret)
	if keySecret == "" {
		return config{}, fmt.Errorf("API Key Secret cannot be empty")
	}

	cfg := config{
		CDPAPIKeyID:     keyID,
		CDPAPIKeySecret: keySecret,
	}

	if err := saveConfig(cfg); err != nil {
		return cfg, fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("\n  Saved to %s\n", configPath())
	return cfg, nil
}
