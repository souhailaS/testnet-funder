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
```

## Commands

### `fund`

Send ETH from a funder wallet to one or more addresses.

```bash
tf fund 0xAddr1 0xAddr2
tf fund --amount 0.5 0xAddr1
tf fund --amount 0.01 --rpc https://sepolia.base.org 0xAddr1
```

| Flag       | Default                  | Description                |
|------------|--------------------------|----------------------------|
| `--amount` | `0.1`                    | ETH to send per address    |
| `--pk`     | `$FUNDER_PK`             | Funder private key         |
| `--rpc`    | `$RPC_URL` or Base Sepolia | RPC endpoint             |

### `redistribute`

Redistribute an ERC-20 token equally across a set of wallets.

```bash
tf redistribute --token 0xYourTokenAddress --config wallets.json
```

| Flag       | Required | Description                          |
|------------|----------|--------------------------------------|
| `--token`  | yes      | ERC-20 token contract address        |
| `--config` | yes      | Path to wallets JSON file            |
| `--rpc`    | no       | RPC endpoint (default: Base Sepolia) |

The config file lists wallets with their private keys:

```json
[
  { "name": "hedger0", "pk": "abc123..." },
  { "name": "hedger1", "pk": "def456..." }
]
```

The command queries each wallet's token balance, computes an equal target, and sends transfers from wallets with excess to those with a deficit.
