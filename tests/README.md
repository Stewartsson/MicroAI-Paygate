# MicroAI Paygate Tests

This directory contains End-to-End (E2E) tests for the MicroAI Paygate system.

## Prerequisites

- [Bun](https://bun.sh) installed
- Go toolchain (for gateway build in helper script)
- Rust toolchain (for verifier build in helper script)

Manual flow:
- Start the MicroAI Paygate stack first (`bun run stack` in the root directory; memory receipts and cache disabled unless overridden)

Helper flow:
- `bun run test:e2e` uses `run_e2e.sh` to build and start the gateway and verifier for you

## Running E2E Tests

The E2E tests target the Gateway and Verifier services. The default command uses `run_e2e.sh` to build and start both services before running tests.

```bash
bun run test:e2e
```

Or manually:

1. Start the stack:
   ```bash
   bun run stack
   ```

2. Run the tests:
   ```bash
   bun test tests/e2e.test.ts
   ```

Notes:
- The default OpenRouter path requires `OPENROUTER_API_KEY` for gateway startup; CI skips E2E when the secret is absent. With an invalid key, the signed path may return 500 after verification.
- The helper script expects ports 3000 and 3002 to be free; stop existing processes if needed.
- The helper defaults to `RECEIPT_STORE=memory` and `CACHE_ENABLED=false`, so Redis is not required unless you override those environment variables.

## Other Tests

### Gateway (Go)
Unit tests for the Go Gateway are located in `gateway/`.
Run them with:
```bash
bun run test:go
# or: cd gateway && go test ./...
```

### Verifier (Rust)
Unit tests for the Rust Verifier are located in `verifier/src/main.rs`.
Run them with:
```bash
bun run test:rust
# or: cd verifier && cargo test
```

### All Unit Tests
```bash
bun run test:unit
```

> **Note:** Do NOT use `bun test` directly - it triggers bun's native test runner without starting services.
