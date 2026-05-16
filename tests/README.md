# E2E Tests

The `tests/` directory contains Bun end-to-end coverage for the gateway and verifier payment flow.

## What The E2E Flow Covers

- Unsigned `POST /api/ai/summarize` returns `402 Payment Required`.
- The 402 response includes a payment context with nonce, chain ID, and timestamp.
- A test wallet signs the payment context with EIP-712 typed data.
- The signed retry includes `X-402-Signature`, `X-402-Nonce`, and `X-402-Timestamp`.
- The signed request is accepted by the verifier and proceeds to the AI provider.
- Reusing the same signed context returns `409 nonce_already_used`.

## Prerequisites

- Bun
- Go toolchain
- Rust toolchain
- Ports `3000` and `3002` free
- `OPENROUTER_API_KEY` for the default OpenRouter gateway startup path

The helper defaults to:

- `RECEIPT_STORE=memory`
- `CACHE_ENABLED=false`

Redis is not required unless you override those variables.

## Run

From the repository root:

```bash
bun run test:e2e
```

This runs `run_e2e.sh`, which builds and starts the verifier and gateway before executing:

```bash
bun test tests/e2e.test.ts
```

Do not use plain `bun test` as a replacement unless you have already started the required services yourself.

## Manual Flow

In one shell:

```bash
bun run stack
```

In another shell:

```bash
bun test tests/e2e.test.ts
```

## Reading Failures

The signed request may return `502 upstream_unavailable` or `504 upstream_timeout` after payment verification succeeds if OpenRouter is unavailable or slow. That usually means the x402 verification path passed and only the upstream AI call failed.

Failures that usually indicate payment-flow regressions:

- Initial request is not `402`.
- Payment context lacks `nonce`, `chainId`, or `timestamp`.
- Signed retry returns `400 invalid_timestamp`.
- Signed retry returns `403 invalid_signature`.
- Replay does not return `409 nonce_already_used`.
