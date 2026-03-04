package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
)

var balanceConfig string

var balanceCmd = &cobra.Command{
	Use:   "balance [addresses...]",
	Short: "Check ETH balance of one or more addresses",
	Long: `Query the ETH balance of each provided address.

Examples:
  tf balance 0xAddr1 0xAddr2
  tf balance --config wallets.json
  tf balance --rpc https://sepolia.base.org 0xAddr1`,
	RunE: runBalance,
}

func init() {
	balanceCmd.Flags().StringVar(&balanceConfig, "config", "", "path to wallets JSON config file (use instead of addresses)")
	rootCmd.AddCommand(balanceCmd)
}

func runBalance(cmd *cobra.Command, args []string) error {
	type target struct {
		name string
		addr common.Address
	}
	var targets []target

	if balanceConfig != "" {
		data, err := os.ReadFile(balanceConfig)
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
				fmt.Printf("  %s  %s  (invalid address)\n", tagSkip("SKIP"), arg)
				continue
			}
			targets = append(targets, target{
				name: arg[:10],
				addr: common.HexToAddress(arg),
			})
		}
	}

	if len(targets) == 0 {
		return fmt.Errorf("no valid addresses to check")
	}

	client, err := dialRPC()
	if err != nil {
		return fmt.Errorf("failed to connect to RPC: %w", err)
	}
	defer client.Close()

	if _, err := printHeader(client); err != nil {
		return err
	}

	ctx := context.Background()

	for _, t := range targets {
		bal, err := client.BalanceAt(ctx, t.addr, nil)
		if err != nil {
			fmt.Printf("  %s  %-10s %s  %v\n", tagFail("FAIL"), t.name, t.addr.Hex(), err)
			continue
		}

		fmt.Printf("  %-10s %s  %s ETH\n", t.name, t.addr.Hex(), weiToEthStr(bal))
	}

	fmt.Println()
	return nil
}
