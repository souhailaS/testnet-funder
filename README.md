# tf: a testnet funder CLI

A command-line tool for managing testnet wallets on Base Sepolia. Claim faucet tokens, check balances, send ETH, and redistribute tokens across wallets.

## Install

**Homebrew** (macOS/Linux):

```bash
brew install souhailas/tap/tf
```

**Go:**

```bash
go install github.com/souhailas/testnet-funder/cmd/tf@latest
```

**Download binary:**

Grab the latest release for your platform from [GitHub Releases](https://github.com/souhailas/testnet-funder/releases):

| OS      | Arch  | File                        |
|---------|-------|-----------------------------|
| macOS   | amd64 | `tf_darwin_amd64.tar.gz`    |
| macOS   | arm64 | `tf_darwin_arm64.tar.gz`    |
| Linux   | amd64 | `tf_linux_amd64.tar.gz`     |
| Linux   | arm64 | `tf_linux_arm64.tar.gz`     |
| Windows | amd64 | `tf_windows_amd64.zip`      |
| Windows | arm64 | `tf_windows_arm64.zip`      |

**From source:**

```bash
git clone https://github.com/souhailas/testnet-funder.git
cd testnet-funder
make build
# binary is at dist/tf
```

## Quick start

```bash
# Set up your free CDP API key (needed for the faucet)
tf init

# Claim 0.0001 ETH
tf faucet 0xYourAddress

# Claim 1 USDC
tf faucet --token usdc 0xYourAddress

# Claim 100x (0.01 ETH total)
tf faucet --claims 100 0xYourAddress

# Check balances
tf balance 0xYourAddress
```

## Commands

### `tf init`

Interactive setup for your CDP API keys. Keys are saved to `~/.tf/config.json`.

To get your free CDP API key:

1. Go to https://portal.cdp.coinbase.com/
2. Sign up or log in
3. Navigate to **API Keys** in the sidebar
4. Click **Create API Key**
5. Copy the **API Key ID** and **API Key Secret**

Then run `tf init` and paste them when prompted.

### `tf faucet`

Claim free testnet tokens from the Coinbase CDP faucet.

```bash
tf faucet 0xAddr1 0xAddr2
tf faucet --config wallets.json
tf faucet --config wallets.json --claims 100
tf faucet --config wallets.json --token usdc --claims 10
```

| Flag       | Default | Description                         |
|------------|---------|-------------------------------------|
| `--token`  | `eth`   | Token to claim: `eth`, `usdc`       |
| `--claims` | `1`     | Number of faucet claims per address |
| `--config` | —       | Path to wallets JSON config file    |

| Token  | Per claim    | Max/day | Max/day total |
|--------|------------- |---------|---------------|
| `eth`  | 0.0001 ETH   | 1000    | 0.1 ETH       |
| `usdc` | 1 USDC       | 10      | 10 USDC       |

### `tf balance`

Check ETH balance of one or more addresses.

```bash
tf balance 0xAddr1 0xAddr2
```

### `tf balances`

Show ETH (and optional ERC-20) balances for all wallets in a config file.

```bash
tf balances --config wallets.json
tf balances --config wallets.json --symbol PUSD
```

| Flag       | Required | Description                      |
|------------|----------|----------------------------------|
| `--config` | yes      | Path to wallets JSON file        |
| `--symbol` | no       | Known token symbol (e.g. `PUSD`) |
| `--token`  | no       | ERC-20 token contract address    |

### `tf fund`

Send ETH from a funder wallet to one or more addresses.

```bash
tf fund --pk 0xYourFunderPK 0xAddr1 0xAddr2
tf fund --amount 0.5 0xAddr1
```

| Flag       | Default                    | Description             |
|------------|----------------------------|-------------------------|
| `--amount` | `0.1`                      | ETH to send per address |
| `--pk`     | `$FUNDER_PK`               | Funder private key      |
| `--rpc`    | `$RPC_URL` or Base Sepolia | RPC endpoint            |

### `tf redistribute`

Redistribute native ETH or an ERC-20 token equally across wallets.

```bash
tf redistribute --symbol ETH --config wallets.json
tf redistribute --symbol PUSD --config wallets.json
tf redistribute --token 0xContractAddress --config wallets.json
```

| Flag       | Required | Description                                      |
|------------|----------|--------------------------------------------------|
| `--symbol` | *        | Token symbol (`ETH` for native, or e.g. `PUSD`)  |
| `--token`  | *        | ERC-20 token contract address                     |
| `--config` | yes      | Path to wallets JSON file                         |

\* one of `--symbol` or `--token` is required

## Wallets config file

Commands that take `--config` expect a JSON file like this:

```json
[
  { "name": "trader", "pk": "0xabc123...", "pubkey": "0xAddr1" },
  { "name": "hedger", "pk": "0xdef456...", "pubkey": "0xAddr2" }
]
```

## Global flags

| Flag    | Default                    | Description        |
|---------|----------------------------|--------------------|
| `--rpc` | `$RPC_URL` or Base Sepolia | RPC endpoint URL   |
| `--pk`  | `$FUNDER_PK`               | Funder private key |
