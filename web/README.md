# Web Frontend

The web app is a Next.js/Bun frontend on port `3001`. It lets users submit text for summarization, receives `402 Payment Required` contexts from the gateway, prompts an EVM wallet to switch chain and sign EIP-712 typed data, and retries the request with x402 headers.

## Responsibilities

- Send unsigned summarize requests to the gateway.
- Detect `402` responses and read `paymentContext`.
- Detect an injected EVM provider such as MetaMask, Rabby, or Coinbase Wallet.
- Switch or add the requested chain when the wallet is on the wrong network.
- Sign the gateway-provided EIP-712 payment context.
- Retry with `X-402-Signature`, `X-402-Nonce`, and `X-402-Timestamp`.
- Display summary results or user-facing errors.

## Current Configuration

The current frontend reads one public environment variable:

| Variable | Default | Notes |
| --- | --- | --- |
| `NEXT_PUBLIC_GATEWAY_URL` | `http://localhost:3000` | Gateway base URL used by browser fetch calls. |

The current app does not read `NEXT_PUBLIC_CHAIN_ID`, `NEXT_PUBLIC_RPC_URL`, or `NEXT_PUBLIC_RECIPIENT`. Chain ID, recipient, amount, nonce, and timestamp come from the gateway payment context.

## Payment Signing Shape

The frontend signs the same EIP-712 domain and type enforced by the verifier:

```text
Domain:
  name: MicroAI Paygate
  version: 1
  chainId: paymentContext.chainId
  verifyingContract: 0x0000000000000000000000000000000000000000

Payment:
  recipient address
  token string
  amount string
  nonce string
  timestamp uint256
```

If this shape changes, update gateway, verifier, web, E2E tests, OpenAPI, and docs together.

## Local Development

Install dependencies:

```bash
cd web
bun install
```

Run the app:

```bash
bun run dev
```

Open `http://localhost:3001`.

The gateway must be reachable at `NEXT_PUBLIC_GATEWAY_URL` or `http://localhost:3000`.

## Production Build

```bash
cd web
bun run lint
bun run build
bun run test
```

`bun run test` runs `tsc --noEmit`.

## Deployment Notes

`web/vercel.json` configures Vercel to install with Bun and build with `bun run build`. Set `NEXT_PUBLIC_GATEWAY_URL` in Vercel project environment settings; do not hard-code the real gateway URL in committed files.

When linking the Vercel project, use `web` as the project root.
