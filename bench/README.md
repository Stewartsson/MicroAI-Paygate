# Verifier Micro-Benchmark

This benchmark measures the Rust verifier `/verify` endpoint only. It does not measure gateway, wallet UI, OpenRouter, Redis, or end-to-end x402 latency.

## Requirements

- `wrk`
- `bun`
- repo root dependencies installed with `bun install`
- verifier running on `http://127.0.0.1:3002` unless `VERIFIER_URL` is set

The script does not install `wrk` or any system package. Install tooling separately, then record the install method with your results.

## Run

```bash
cd /path/to/MicroAI-Paygate
cd verifier && cargo run
```

In another shell:

```bash
RESULTS_FILE=bench/RESULTS-2026-05-13.txt bench/bench.sh
```

Useful overrides:

```bash
THREADS=4 CONNECTIONS=64 DURATION=60s PAYLOAD_COUNT=5000 bench/bench.sh
VERIFIER_URL=http://127.0.0.1:3002 bench/bench.sh
```

## Method

`bench.sh` pre-generates unique EIP-712 payment payloads with Bun and `ethers`, writes them to a temporary JSONL file, then gives `wrk` a Lua script that rotates request bodies across the generated payloads. This avoids benchmarking one repeated nonce/signature pair.

The default private key is a deterministic local test key used only for benchmark signing. Do not use a funded wallet.

## Reporting

Only cite numbers that appear in a committed `bench/RESULTS-*.txt` file. Keep raw `wrk` output, hardware metadata, thread/connection settings, duration, and payload count together in the results file.
