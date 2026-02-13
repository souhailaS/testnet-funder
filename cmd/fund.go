package cmd

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
)

var amount float64

var fundCmd = &cobra.Command{
	Use:   "fund [addresses...]",
	Short: "Send ETH to one or more target addresses",
	Long: `Send a fixed amount of ETH from the funder wallet to each target address.

Examples:
  tf fund 0xAddr1 0xAddr2
  tf fund --amount 0.5 0xAddr1
  tf fund --amount 0.01 --rpc https://sepolia.base.org 0xAddr1`,
	Args: cobra.MinimumNArgs(1),
	RunE: runFund,
}

func init() {
	fundCmd.Flags().Float64Var(&amount, "amount", 0.1, "amount of ETH to send per address")
	rootCmd.AddCommand(fundCmd)
}

func runFund(cmd *cobra.Command, args []string) error {
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
	fmt.Printf("  Funder: %s\n", funderAddr.Hex())
	fmt.Printf("  Balance: %s ETH\n", weiToEthStr(funderBal))
	fmt.Printf("  Sending: %.4f ETH x %d addresses\n\n", amount, len(args))

	weiAmount := ethToWei(amount)

	totalNeeded := new(big.Int).Mul(weiAmount, big.NewInt(int64(len(args))))
	if funderBal.Cmp(totalNeeded) < 0 {
		return fmt.Errorf("insufficient balance: need %s ETH, have %s ETH",
			weiToEthStr(totalNeeded), weiToEthStr(funderBal))
	}

	nonce, err := client.PendingNonceAt(ctx, funderAddr)
	if err != nil {
		return fmt.Errorf("failed to get nonce: %w", err)
	}

	signer := types.NewLondonSigner(chainID)
	sent, skipped, failed := 0, 0, 0

	for _, arg := range args {
		if !common.IsHexAddress(arg) {
			fmt.Printf("  SKIP  %s  (invalid address)\n", arg)
			skipped++
			continue
		}
		to := common.HexToAddress(arg)

		balBefore, err := client.BalanceAt(ctx, to, nil)
		if err != nil {
			fmt.Printf("  FAIL  %s  %v\n", to.Hex(), err)
			failed++
			continue
		}

		gasTip, err := client.SuggestGasTipCap(ctx)
		if err != nil {
			fmt.Printf("  FAIL  %s  suggest gas tip: %v\n", to.Hex(), err)
			failed++
			continue
		}

		head, err := client.HeaderByNumber(ctx, nil)
		if err != nil {
			fmt.Printf("  FAIL  %s  get header: %v\n", to.Hex(), err)
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
			fmt.Printf("  FAIL  %s  sign: %v\n", to.Hex(), err)
			failed++
			continue
		}

		err = client.SendTransaction(ctx, signedTx)
		if err != nil {
			fmt.Printf("  FAIL  %s  send: %v\n", to.Hex(), err)
			failed++
			continue
		}

		fmt.Printf("  SENT  %s  bal: %s ETH  tx: %s\n",
			to.Hex(), weiToEthStr(balBefore), signedTx.Hash().Hex())
		sent++
		nonce++
	}

	fmt.Printf("\n  Done: %d sent, %d skipped, %d failed\n\n", sent, skipped, failed)
	return nil
}
