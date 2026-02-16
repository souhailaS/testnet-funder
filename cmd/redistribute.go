package cmd

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/spf13/cobra"
)

var (
	tokenAddr   string
	tokenSymbol string
	configFile  string
)

// Known tokens per chain ID
var knownTokens = map[int64]map[string]string{
	84532: { // Base Sepolia
		"PUSD": "0xBA904917a1A7e68263F564FaE157aA283F6857e4",
	},
}

type walletEntry struct {
	Name   string `json:"name"`
	PK     string `json:"pk"`
	PubKey string `json:"pubkey,omitempty"`
}

var redistributeCmd = &cobra.Command{
	Use:   "redistribute",
	Short: "Redistribute ETH or ERC-20 tokens equally across wallets",
	Long: `Redistribute native ETH or an ERC-20 token so that all wallets in
the config file end up with an equal share of the total balance.

Examples:
  tf redistribute --symbol ETH --config wallets.json
  tf redistribute --symbol dPUSD --config wallets.json
  tf redistribute --token 0x91367E14Aad4e26034d8cb3dA119BF49CD8C3391 --config wallets.json`,
	RunE: runRedistribute,
}

func init() {
	redistributeCmd.Flags().StringVar(&tokenAddr, "token", "", "ERC-20 token contract address")
	redistributeCmd.Flags().StringVar(&tokenSymbol, "symbol", "", "known token symbol (e.g. dPUSD)")
	redistributeCmd.Flags().StringVar(&configFile, "config", "", "path to wallets JSON config file (required)")
	_ = redistributeCmd.MarkFlagRequired("config")
	rootCmd.AddCommand(redistributeCmd)
}

// Minimal ERC-20 ABI selectors
var (
	// balanceOf(address) → uint256
	sigBalanceOf = crypto.Keccak256([]byte("balanceOf(address)"))[:4]
	// decimals() → uint8
	sigDecimals = crypto.Keccak256([]byte("decimals()"))[:4]
	// symbol() → string
	sigSymbol = crypto.Keccak256([]byte("symbol()"))[:4]
	// transfer(address,uint256)
	sigTransfer = crypto.Keccak256([]byte("transfer(address,uint256)"))[:4]
)

func resolveToken(chainID *big.Int) (common.Address, error) {
	if tokenAddr != "" && tokenSymbol != "" {
		return common.Address{}, fmt.Errorf("use --token or --symbol, not both")
	}
	if tokenAddr == "" && tokenSymbol == "" {
		return common.Address{}, fmt.Errorf("provide --token <address> or --symbol <name>")
	}
	if tokenAddr != "" {
		if !common.IsHexAddress(tokenAddr) {
			return common.Address{}, fmt.Errorf("invalid token address: %s", tokenAddr)
		}
		return common.HexToAddress(tokenAddr), nil
	}
	// Lookup by symbol
	chain := chainID.Int64()
	tokens, ok := knownTokens[chain]
	if !ok {
		return common.Address{}, fmt.Errorf("no known tokens for chain %d", chain)
	}
	// Case-insensitive lookup
	for sym, addr := range tokens {
		if strings.EqualFold(sym, tokenSymbol) {
			fmt.Printf("  Resolved %s → %s\n", sym, addr)
			return common.HexToAddress(addr), nil
		}
	}
	known := make([]string, 0, len(tokens))
	for sym := range tokens {
		known = append(known, sym)
	}
	return common.Address{}, fmt.Errorf("unknown symbol %q for chain %d (known: %s)", tokenSymbol, chain, strings.Join(known, ", "))
}

func runRedistribute(cmd *cobra.Command, args []string) error {
	// Load wallets from config
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	var entries []walletEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}
	if len(entries) < 2 {
		return fmt.Errorf("need at least 2 wallets, got %d", len(entries))
	}

	// Derive keys and addresses
	type wallet struct {
		name string
		key  *ecdsa.PrivateKey
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
			key:  key,
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

	isETH := strings.EqualFold(tokenSymbol, "ETH")

	var token common.Address
	var decimals uint8
	var symbol string

	if isETH {
		if tokenAddr != "" {
			return fmt.Errorf("use --symbol ETH or --token <address>, not both")
		}
		decimals = 18
		symbol = "ETH"
		fmt.Printf("  Asset:  ETH (native)\n\n")
	} else {
		var err error
		token, err = resolveToken(chainID)
		if err != nil {
			return err
		}
		decimals, err = queryDecimals(ctx, client, token)
		if err != nil {
			return fmt.Errorf("failed to query decimals: %w", err)
		}
		symbol, err = querySymbol(ctx, client, token)
		if err != nil {
			return fmt.Errorf("failed to query symbol: %w", err)
		}
		fmt.Printf("  Token:  %s (%s, %d decimals)\n\n", symbol, token.Hex(), decimals)
	}

	// Query balances
	total := new(big.Int)
	balances := make([]*big.Int, len(wallets))
	for i, w := range wallets {
		var bal *big.Int
		var err error
		if isETH {
			bal, err = client.BalanceAt(ctx, w.addr, nil)
		} else {
			bal, err = queryBalanceOf(ctx, client, token, w.addr)
		}
		if err != nil {
			return fmt.Errorf("failed to query balance for %s: %w", w.name, err)
		}
		balances[i] = bal
		total.Add(total, bal)
	}

	// Print current balances
	fmt.Printf("  %-12s  %-42s  %s\n", "Wallet", "Address", "Balance")
	fmt.Printf("  %-12s  %-42s  %s\n", "------", "-------", "-------")
	for i, w := range wallets {
		fmt.Printf("  %-12s  %s  %s\n", w.name, w.addr.Hex(), formatUnits(balances[i], decimals))
	}
	fmt.Printf("\n  Total: %s %s\n", formatUnits(total, decimals), symbol)

	// Calculate target = total / n
	n := big.NewInt(int64(len(wallets)))
	target := new(big.Int).Div(total, n)
	fmt.Printf("  Target per wallet: %s %s\n\n", formatUnits(target, decimals), symbol)

	// Build transfer plan: senders (balance > target) → receivers (balance < target)
	type transfer struct {
		fromIdx int
		toIdx   int
		amount  *big.Int
	}
	var transfers []transfer

	excess := make([]*big.Int, len(wallets))
	deficit := make([]*big.Int, len(wallets))
	for i := range wallets {
		diff := new(big.Int).Sub(balances[i], target)
		if diff.Sign() > 0 {
			excess[i] = new(big.Int).Set(diff)
		} else if diff.Sign() < 0 {
			deficit[i] = new(big.Int).Neg(diff)
		}
	}

	// Greedy matching: each sender fills receivers in order
	for si := range wallets {
		if excess[si] == nil || excess[si].Sign() == 0 {
			continue
		}
		for ri := range wallets {
			if deficit[ri] == nil || deficit[ri].Sign() == 0 {
				continue
			}
			amt := new(big.Int).Set(excess[si])
			if amt.Cmp(deficit[ri]) > 0 {
				amt.Set(deficit[ri])
			}
			transfers = append(transfers, transfer{fromIdx: si, toIdx: ri, amount: amt})
			excess[si].Sub(excess[si], amt)
			deficit[ri].Sub(deficit[ri], amt)
			if excess[si].Sign() == 0 {
				break
			}
		}
	}

	if len(transfers) == 0 {
		fmt.Printf("  All wallets already balanced — nothing to do.\n\n")
		return nil
	}

	fmt.Printf("  Transfers:\n")
	sent, failed := 0, 0

	signer := types.NewLondonSigner(chainID)

	// Track nonces locally so back-to-back txs from the same sender don't collide.
	nonceMap := make(map[common.Address]uint64)

	for _, t := range transfers {
		from := wallets[t.fromIdx]
		to := wallets[t.toIdx]

		nonce, ok := nonceMap[from.addr]
		if !ok {
			var err error
			nonce, err = client.PendingNonceAt(ctx, from.addr)
			if err != nil {
				fmt.Printf("  FAIL  %s → %s  nonce: %v\n", from.name, to.name, err)
				failed++
				continue
			}
		}
		nonceMap[from.addr] = nonce + 1

		gasTip, err := client.SuggestGasTipCap(ctx)
		if err != nil {
			fmt.Printf("  FAIL  %s → %s  gas tip: %v\n", from.name, to.name, err)
			failed++
			continue
		}
		head, err := client.HeaderByNumber(ctx, nil)
		if err != nil {
			fmt.Printf("  FAIL  %s → %s  header: %v\n", from.name, to.name, err)
			failed++
			continue
		}
		gasFeeCap := new(big.Int).Add(head.BaseFee, gasTip)
		gasFeeCap.Add(gasFeeCap, head.BaseFee) // 2*baseFee + tip

		var tx *types.Transaction
		if isETH {
			toAddr := to.addr
			tx = types.NewTx(&types.DynamicFeeTx{
				ChainID:   chainID,
				Nonce:     nonce,
				GasFeeCap: gasFeeCap,
				GasTipCap: gasTip,
				Gas:       21000,
				To:        &toAddr,
				Value:     t.amount,
			})
		} else {
			calldata := packTransfer(to.addr, t.amount)
			tx = types.NewTx(&types.DynamicFeeTx{
				ChainID:   chainID,
				Nonce:     nonce,
				GasFeeCap: gasFeeCap,
				GasTipCap: gasTip,
				Gas:       65000,
				To:        &token,
				Data:      calldata,
			})
		}

		signedTx, err := types.SignTx(tx, signer, from.key)
		if err != nil {
			fmt.Printf("  FAIL  %s → %s  sign: %v\n", from.name, to.name, err)
			failed++
			continue
		}

		err = client.SendTransaction(ctx, signedTx)
		if err != nil {
			fmt.Printf("  FAIL  %s → %s  send: %v\n", from.name, to.name, err)
			failed++
			continue
		}

		// Wait for receipt to get gas consumed
		var gasUsed uint64
		for i := 0; i < 60; i++ {
			receipt, err := client.TransactionReceipt(ctx, signedTx.Hash())
			if err == nil {
				gasUsed = receipt.GasUsed
				break
			}
			time.Sleep(time.Second)
		}

		if gasUsed > 0 {
			fmt.Printf("  SENT  %s → %s  %s %s  gas: %d  tx: %s\n",
				from.name, to.name, formatUnits(t.amount, decimals), symbol, gasUsed, signedTx.Hash().Hex())
		} else {
			fmt.Printf("  SENT  %s → %s  %s %s  gas: pending  tx: %s\n",
				from.name, to.name, formatUnits(t.amount, decimals), symbol, signedTx.Hash().Hex())
		}
		sent++
	}

	fmt.Printf("\n  Done: %d sent, %d failed\n\n", sent, failed)
	return nil
}

// --- ERC-20 call helpers ---

func queryBalanceOf(ctx context.Context, client *ethclient.Client, token, account common.Address) (*big.Int, error) {
	// balanceOf(address): selector + address padded to 32 bytes
	data := make([]byte, 4+32)
	copy(data, sigBalanceOf)
	copy(data[4+12:], account.Bytes()) // left-pad 20-byte address to 32

	out, err := client.CallContract(ctx, ethereum.CallMsg{To: &token, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	if len(out) < 32 {
		return nil, fmt.Errorf("unexpected return length %d", len(out))
	}
	return new(big.Int).SetBytes(out[:32]), nil
}

func queryDecimals(ctx context.Context, client *ethclient.Client, token common.Address) (uint8, error) {
	out, err := client.CallContract(ctx, ethereum.CallMsg{To: &token, Data: sigDecimals}, nil)
	if err != nil {
		return 0, err
	}
	if len(out) < 32 {
		return 0, fmt.Errorf("unexpected return length %d", len(out))
	}
	return uint8(new(big.Int).SetBytes(out[:32]).Uint64()), nil
}

func querySymbol(ctx context.Context, client *ethclient.Client, token common.Address) (string, error) {
	out, err := client.CallContract(ctx, ethereum.CallMsg{To: &token, Data: sigSymbol}, nil)
	if err != nil {
		return "", err
	}
	// ABI-encoded string: offset (32) + length (32) + data
	if len(out) < 64 {
		return "", fmt.Errorf("unexpected return length %d", len(out))
	}
	length := new(big.Int).SetBytes(out[32:64]).Uint64()
	if uint64(len(out)) < 64+length {
		return "", fmt.Errorf("string data truncated")
	}
	return string(out[64 : 64+length]), nil
}

func packTransfer(to common.Address, amount *big.Int) []byte {
	// transfer(address,uint256): selector + address(32) + uint256(32)
	data := make([]byte, 4+32+32)
	copy(data, sigTransfer)
	copy(data[4+12:], to.Bytes())
	amount.FillBytes(data[4+32:])
	return data
}

func formatUnits(wei *big.Int, decimals uint8) string {
	divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	whole := new(big.Int).Div(wei, divisor)
	frac := new(big.Int).Mod(wei, divisor)

	// Format fractional part with leading zeros, then trim trailing zeros
	fracStr := fmt.Sprintf("%0*s", int(decimals), frac.String())
	fracStr = strings.TrimRight(fracStr, "0")
	if fracStr == "" {
		return whole.String()
	}
	// Keep at most 6 decimal places
	if len(fracStr) > 6 {
		fracStr = fracStr[:6]
	}
	return whole.String() + "." + fracStr
}
