package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
)

var (
	amount     float64
	fundConfig string
)

var fundCmd = &cobra.Command{
	Use:   "fund [addresses...]",
	Short: "Send ETH to one or more target addresses",
	Long: `Send a fixed amount of ETH from the funder wallet to each target address.

Examples:
  tf fund 0xAddr1 0xAddr2
  tf fund --amount 0.5 0xAddr1
  tf fund --config wallets.json --amount 0.01`,
	RunE: runFund,
}

func init() {
	fundCmd.Flags().Float64Var(&amount, "amount", 0.1, "amount of ETH to send per address")
	fundCmd.Flags().StringVar(&fundConfig, "config", "", "path to wallets JSON config file (use instead of addresses)")
	rootCmd.AddCommand(fundCmd)
}

func runFund(cmd *cobra.Command, args []string) error {
	// Build address list from --config or positional args
	type target struct {
		name string
		addr common.Address
	}
	var targets []target

	if fundConfig != "" {
		data, err := os.ReadFile(fundConfig)
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
		return fmt.Errorf("no valid addresses to fund")
	}

	privateKey, err := loadFunderKey()
	if err != nil {
		return err
	}
	funderAddr := crypto.PubkeyToAddress(privateKey.PublicKey)

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

	funderBal, err := client.BalanceAt(ctx, funderAddr, nil)
	if err != nil {
		return fmt.Errorf("failed to get funder balance: %w", err)
	}
	fmt.Printf("  %s %s\n", cyan("Funder:"), funderAddr.Hex())
	fmt.Printf("  %s %s ETH\n", cyan("Balance:"), weiToEthStr(funderBal))
	fmt.Printf("  %s %.4f ETH x %d addresses\n\n", cyan("Sending:"), amount, len(targets))

	weiAmount := ethToWei(amount)

	totalNeeded := new(big.Int).Mul(weiAmount, big.NewInt(int64(len(targets))))
	if funderBal.Cmp(totalNeeded) < 0 {
		return fmt.Errorf("insufficient balance: need %s ETH, have %s ETH",
			weiToEthStr(totalNeeded), weiToEthStr(funderBal))
	}

	nonce, err := client.PendingNonceAt(ctx, funderAddr)
	if err != nil {
		return fmt.Errorf("failed to get nonce: %w", err)
	}

	signer := types.NewLondonSigner(chainID)
	sent, failed := 0, 0

	for _, t := range targets {
		to := t.addr

		balBefore, err := client.BalanceAt(ctx, to, nil)
		if err != nil {
			fmt.Printf("  %s  %-10s %s  %v\n", tagFail("FAIL"), t.name, to.Hex(), err)
			failed++
			continue
		}

		gasTip, err := client.SuggestGasTipCap(ctx)
		if err != nil {
			fmt.Printf("  %s  %-10s %s  suggest gas tip: %v\n", tagFail("FAIL"), t.name, to.Hex(), err)
			failed++
			continue
		}

		head, err := client.HeaderByNumber(ctx, nil)
		if err != nil {
			fmt.Printf("  %s  %-10s %s  get header: %v\n", tagFail("FAIL"), t.name, to.Hex(), err)
			failed++
			continue
		}
		gasFeeCap := new(big.Int).Add(head.BaseFee, gasTip)
		gasFeeCap.Add(gasFeeCap, head.BaseFee)

		tx := types.NewTx(&types.DynamicFeeTx{
			ChainID:   chainID,
			Nonce:     nonce,
			GasFeeCap: gasFeeCap,
			GasTipCap: gasTip,
			Gas:       21000,
			To:        &to,
			Value:     weiAmount,
		})

		signedTx, err := types.SignTx(tx, signer, privateKey)
		if err != nil {
			fmt.Printf("  %s  %-10s %s  sign: %v\n", tagFail("FAIL"), t.name, to.Hex(), err)
			failed++
			continue
		}

		err = client.SendTransaction(ctx, signedTx)
		if err != nil {
			fmt.Printf("  %s  %-10s %s  send: %v\n", tagFail("FAIL"), t.name, to.Hex(), err)
			failed++
			continue
		}

		fmt.Printf("  %s  %-10s %s  bal: %s ETH  tx: %s\n", tagSent("SENT"),
			t.name, to.Hex(), weiToEthStr(balBefore), signedTx.Hash().Hex())
		sent++
		nonce++
	}

	fmt.Printf("\n  %s %d sent, %d failed\n\n", cyan("Done:"), sent, failed)
	return nil
}
