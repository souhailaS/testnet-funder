# tf — testnet funder

CLI tool for managing testnet wallets on Base Sepolia.

## Setup

```bash
go build -o tf .
```

Create a `.env` file (or use `--pk` / `--rpc` flags):

```
FUNDER_PK=your_private_key
RPC_URL=https://sepolia.base.org
CDP_API_KEY_ID=your_cdp_key_id
CDP_API_KEY_SECRET=your_cdp_key_secret
```

## Commands

### `balance`

Check ETH balance of one or more addresses.

```bash
tf balance 0xAddr1 0xAddr2
tf balance --rpc https://sepolia.base.org 0xAddr1
```

| Flag    | Default                    | Description  |
|---------|----------------------------|--------------|
| `--rpc` | `$RPC_URL` or Base Sepolia | RPC endpoint |

### `balances`

Show ETH (and optional ERC-20) balances for all wallets in a config file.

```bash
tf balances --config wallets.json
tf balances --config wallets.json --symbol PUSD
tf balances --config wallets.json --token 0xBA904917a1A7e68263F564FaE157aA283F6857e4
```

| Flag       | Required | Description                       |
|------------|----------|-----------------------------------|
| `--config` | yes      | Path to wallets JSON file         |
| `--symbol` | no       | Known token symbol (e.g. `PUSD`)  |
| `--token`  | no       | ERC-20 token contract address     |
| `--rpc`    | no       | RPC endpoint (default: Base Sepolia) |

### `fund`

Send ETH from a funder wallet to one or more addresses.

```bash
tf fund 0xAddr1 0xAddr2
tf fund --amount 0.5 0xAddr1
tf fund --amount 0.01 --rpc https://sepolia.base.org 0xAddr1
```

| Flag       | Default                    | Description             |
|------------|----------------------------|-------------------------|
| `--amount` | `0.1`                      | ETH to send per address |
| `--pk`     | `$FUNDER_PK`               | Funder private key      |
| `--rpc`    | `$RPC_URL` or Base Sepolia | RPC endpoint            |

### `faucet`

Request free testnet tokens from the Coinbase CDP faucet. Pass addresses directly or use `--config` to fund all wallets from a config file.

```bash
tf faucet 0xAddr1 0xAddr2
tf faucet --config wallets.json
tf faucet --config wallets.json --claims 100
tf faucet --config wallets.json --token usdc --claims 10
```

| Flag       | Default | Description                                    |
|------------|---------|------------------------------------------------|
| `--token`  | `eth`   | Token to claim: `eth`, `usdc`, `eurc`, `cbbtc` |
| `--claims` | `1`     | Number of faucet claims per address             |
| `--config` | —       | Path to wallets JSON config file                |

Requires `CDP_API_KEY_ID` and `CDP_API_KEY_SECRET` in `.env` (free from https://portal.cdp.coinbase.com/).

| Token   | Per claim     | Max/day |
|---------|---------------|---------|
| `eth`   | 0.0001 ETH    | 1000    |
| `usdc`  | 1 USDC        | 10      |
| `eurc`  | 1 EURC        | 10      |
| `cbbtc` | 0.0001 cbBTC  | 100     |

### `redistribute`

Redistribute native ETH or an ERC-20 token equally across a set of wallets.

```bash
tf redistribute --symbol ETH --config wallets.json
tf redistribute --symbol dPUSD --config wallets.json
tf redistribute --token 0xYourTokenAddress --config wallets.json
```

Provide either `--symbol` or `--token` (not both). Use `--symbol ETH` for native ETH.

| Flag       | Required | Description                                       |
|------------|----------|---------------------------------------------------|
| `--symbol` | *        | Token symbol (`ETH` for native, or e.g. `dPUSD`)  |
| `--token`  | *        | ERC-20 token contract address                      |
| `--config` | yes      | Path to wallets JSON file                          |
| `--rpc`    | no       | RPC endpoint (default: Base Sepolia)               |

\* one of `--symbol` or `--token` is required

**Known symbols** (Base Sepolia): `dPUSD`

## Wallets config

The config file lists wallets with their private keys and addresses:

```json
[
  { "name": "trader", "pk": "0xabc123...", "pubkey": "0xAddr1" },
  { "name": "hedger", "pk": "0xdef456...", "pubkey": "0xAddr2" }
]
```

Used by `balances`, `faucet --config`, and `redistribute`.
