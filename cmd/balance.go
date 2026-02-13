package cmd

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
)

var balanceCmd = &cobra.Command{
	Use:   "balance [addresses...]",
	Short: "Check ETH balance of one or more addresses",
	Long: `Query the ETH balance of each provided address.

Examples:
  testnet-funder balance 0xAddr1 0xAddr2
  testnet-funder balance --rpc https://sepolia.base.org 0xAddr1`,
	Args: cobra.MinimumNArgs(1),
	RunE: runBalance,
}

func init() {
	rootCmd.AddCommand(balanceCmd)
}

func runBalance(cmd *cobra.Command, args []string) error {
	client, err := dialRPC()
	if err != nil {
		return fmt.Errorf("failed to connect to RPC: %w", err)
	}
	defer client.Close()

	if _, err := printHeader(client); err != nil {
		return err
	}

	ctx := context.Background()

	for _, arg := range args {
		if !common.IsHexAddress(arg) {
			fmt.Printf("  SKIP  %s  (invalid address)\n", arg)
			continue
		}
		addr := common.HexToAddress(arg)

		bal, err := client.BalanceAt(ctx, addr, nil)
		if err != nil {
			fmt.Printf("  FAIL  %s  %v\n", addr.Hex(), err)
			continue
		}

		fmt.Printf("  %s  %s ETH\n", addr.Hex(), weiToEthStr(bal))
	}

	fmt.Println()
	return nil
}
