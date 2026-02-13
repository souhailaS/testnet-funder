package cmd

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

var (
	rpcURL   string
	funderPK string
)

var rootCmd = &cobra.Command{
	Use:   "testnet-funder",
	Short: "Send testnet ETH from a funder wallet to target addresses",
	Long: `A CLI tool to distribute testnet ETH to multiple wallets.

Set FUNDER_PK in your .env file or pass it via --pk flag.
Default RPC is https://sepolia.base.org (Base Sepolia).`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(loadEnv)

	rootCmd.PersistentFlags().StringVar(&rpcURL, "rpc", "", "RPC endpoint URL (default: $RPC_URL or https://sepolia.base.org)")
	rootCmd.PersistentFlags().StringVar(&funderPK, "pk", "", "funder private key (default: $FUNDER_PK)")
}

func loadEnv() {
	_ = godotenv.Load()

	if rpcURL == "" {
		rpcURL = os.Getenv("RPC_URL")
	}
	if rpcURL == "" {
		rpcURL = "https://sepolia.base.org"
	}

	if funderPK == "" {
		funderPK = os.Getenv("FUNDER_PK")
	}
	funderPK = strings.TrimPrefix(funderPK, "0x")
}

func dialRPC() (*ethclient.Client, error) {
	return ethclient.Dial(rpcURL)
}

func loadFunderKey() (*ecdsa.PrivateKey, error) {
	if funderPK == "" {
		return nil, fmt.Errorf("funder private key required — set FUNDER_PK in .env or use --pk flag")
	}
	return crypto.HexToECDSA(funderPK)
}

func ethToWei(eth float64) *big.Int {
	f := new(big.Float).SetFloat64(eth)
	f.Mul(f, new(big.Float).SetFloat64(1e18))
	wei, _ := f.Int(nil)
	return wei
}

func weiToEthStr(wei *big.Int) string {
	f := new(big.Float).SetInt(wei)
	f.Quo(f, new(big.Float).SetFloat64(1e18))
	return f.Text('f', 6)
}

func getChainName(chainID *big.Int) string {
	switch chainID.Int64() {
	case 84532:
		return "Base Sepolia"
	case 8453:
		return "Base"
	case 11155111:
		return "Sepolia"
	case 1:
		return "Ethereum"
	default:
		return "unknown"
	}
}

func printHeader(client *ethclient.Client) (*big.Int, error) {
	ctx := context.Background()
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain ID: %w", err)
	}
	fmt.Printf("\n  Chain:  %s (%s)\n", getChainName(chainID), chainID.String())
	fmt.Printf("  RPC:    %s\n\n", rpcURL)
	return chainID, nil
}
