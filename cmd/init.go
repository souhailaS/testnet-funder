package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Set up CDP API keys for the faucet",
	Long: `Walks you through setting up a free Coinbase Developer Platform (CDP) API key.
Keys are saved to ~/.tf/config.json and used automatically by the faucet command.`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.CDPAPIKeyID != "" && cfg.CDPAPIKeySecret != "" {
		fmt.Printf("\n  CDP API keys already configured in %s\n", configPath())
		fmt.Print("  Overwrite? (y/N): ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(answer)) != "y" {
			fmt.Println("  Keeping existing keys.")
			return nil
		}
	}

	if _, err := promptCDPKeys(); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("  You're all set! Try:")
	fmt.Println("    tf faucet 0xYourAddress")
	fmt.Println()
	return nil
}
