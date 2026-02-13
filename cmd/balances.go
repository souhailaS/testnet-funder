package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
)

var balancesCmd = &cobra.Command{
	Use:   "balances",
	Short: "Show ETH (and optional ERC-20) balances for all wallets in a config file",
	Long: `Show balances for every wallet defined in a JSON config file.
ETH balances are always displayed. Provide --token or --symbol to include
an ERC-20 token column.

Examples:
  tf balances --config wallets.json
  tf balances --config wallets.json --symbol PUSD
  tf balances --config wallets.json --token 0xBA904917a1A7e68263F564FaE157aA283F6857e4`,
	RunE: runBalances,
}

func init() {
	balancesCmd.Flags().StringVar(&configFile, "config", "", "path to wallets JSON config file (required)")
	balancesCmd.Flags().StringVar(&tokenAddr, "token", "", "ERC-20 token contract address")
	balancesCmd.Flags().StringVar(&tokenSymbol, "symbol", "", "known token symbol (e.g. PUSD)")
	_ = balancesCmd.MarkFlagRequired("config")
	rootCmd.AddCommand(balancesCmd)
}

func runBalances(cmd *cobra.Command, args []string) error {
	// Load wallets from config
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	var entries []walletEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("no wallets found in config file")
	}

	// Derive addresses from private keys
	type wallet struct {
		name string
		addr common.Address
	}
	wallets := make([]wallet, len(entries))
	for i, e := range entries {
		pk := strings.TrimPrefix(e.PK, "0x")
		key, err := crypto.HexToECDSA(pk)
		if err != nil {
			return fmt.Errorf("invalid private key for %s: %w", e.Name, err)
		}
		wallets[i] = wallet{
			name: e.Name,
			addr: crypto.PubkeyToAddress(key.PublicKey),
		}
	}

	client, err := dialRPC()
	if err != nil {
		return fmt.Errorf("failed to connect to RPC: %w", err)
	}
	defer client.Close()

	ctx := context.Background()
	chainID, err := printHeader(client)
	if err != nil {
		return err
	}

	// Resolve token if requested
	wantToken := tokenAddr != "" || tokenSymbol != ""
	var (
		token    common.Address
		tokenSym string
		decimals uint8
	)
	if wantToken {
		token, err = resolveToken(chainID)
		if err != nil {
			return err
		}
		decimals, err = queryDecimals(ctx, client, token)
		if err != nil {
			return fmt.Errorf("failed to query decimals: %w", err)
		}
		tokenSym, err = querySymbol(ctx, client, token)
		if err != nil {
			return fmt.Errorf("failed to query symbol: %w", err)
		}
		fmt.Printf("  Token:  %s (%s, %d decimals)\n\n", tokenSym, token.Hex(), decimals)
	}

	// Query balances
	ethBals := make([]*big.Int, len(wallets))
	tokenBals := make([]*big.Int, len(wallets))
	totalETH := new(big.Int)
	totalToken := new(big.Int)

	for i, w := range wallets {
		bal, err := client.BalanceAt(ctx, w.addr, nil)
		if err != nil {
			return fmt.Errorf("failed to query ETH balance for %s: %w", w.name, err)
		}
		ethBals[i] = bal
		totalETH.Add(totalETH, bal)

		if wantToken {
			tbal, err := queryBalanceOf(ctx, client, token, w.addr)
			if err != nil {
				return fmt.Errorf("failed to query token balance for %s: %w", w.name, err)
			}
			tokenBals[i] = tbal
			totalToken.Add(totalToken, tbal)
		}
	}

	// Print table
	if wantToken {
		fmt.Printf("  %-14s  %-42s  %15s  %s\n", "Wallet", "Address", "ETH", tokenSym)
		fmt.Printf("  %-14s  %-42s  %15s  %s\n", "------", "-------", "---", strings.Repeat("-", len(tokenSym)))
	} else {
		fmt.Printf("  %-14s  %-42s  %15s\n", "Wallet", "Address", "ETH")
		fmt.Printf("  %-14s  %-42s  %15s\n", "------", "-------", "---")
	}

	for i, w := range wallets {
		ethStr := weiToEthStr(ethBals[i])
		if wantToken {
			tokStr := formatUnits(tokenBals[i], decimals)
			fmt.Printf("  %-14s  %s  %15s  %s\n", w.name, w.addr.Hex(), ethStr, tokStr)
		} else {
			fmt.Printf("  %-14s  %s  %15s\n", w.name, w.addr.Hex(), ethStr)
		}
	}

	// Total row
	fmt.Println()
	if wantToken {
		fmt.Printf("  %-14s  %-42s  %15s  %s\n", "Total", "", weiToEthStr(totalETH), formatUnits(totalToken, decimals))
	} else {
		fmt.Printf("  %-14s  %-42s  %15s\n", "Total", "", weiToEthStr(totalETH))
	}
	fmt.Println()

	return nil
}
