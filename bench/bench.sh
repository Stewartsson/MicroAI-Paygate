#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFIER_URL="${VERIFIER_URL:-http://127.0.0.1:3002}"
TARGET_URL="${VERIFIER_URL%/}/verify"
THREADS="${THREADS:-2}"
CONNECTIONS="${CONNECTIONS:-32}"
DURATION="${DURATION:-30s}"
PAYLOAD_COUNT="${PAYLOAD_COUNT:-1000}"
CHAIN_ID="${CHAIN_ID:-8453}"
RECIPIENT_ADDRESS="${RECIPIENT_ADDRESS:-0x1234567890123456789012345678901234567890}"
PAYMENT_TOKEN="${PAYMENT_TOKEN:-USDC}"
PAYMENT_AMOUNT="${PAYMENT_AMOUNT:-0.001}"
BENCH_WALLET_PRIVATE_KEY="${BENCH_WALLET_PRIVATE_KEY:-0x380eb0f3d505f087e438eca80bc4df9a7faa24f868e69fc0440261a0fc0567dc}"
RESULTS_FILE="${RESULTS_FILE:-}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    return 1
  fi
}

require_cmd wrk
require_cmd bun

if ! (cd "$ROOT_DIR" && bun -e 'import { Wallet } from "ethers"; void Wallet;' >/dev/null 2>&1); then
  echo "Unable to import ethers with Bun. Run 'bun install' from the repo root, then retry." >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
PAYLOADS_FILE="$TMP_DIR/payloads.jsonl"
LUA_FILE="$TMP_DIR/rotate-payloads.lua"
GENERATOR_FILE="$TMP_DIR/generate-payloads.mjs"

cat >"$GENERATOR_FILE" <<'JS'
import { randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import { Wallet } from "ethers";

const count = Number.parseInt(process.env.PAYLOAD_COUNT ?? "1000", 10);
if (!Number.isInteger(count) || count <= 0) {
  throw new Error("PAYLOAD_COUNT must be a positive integer");
}

const chainId = Number.parseInt(process.env.CHAIN_ID ?? "8453", 10);
const wallet = new Wallet(process.env.BENCH_WALLET_PRIVATE_KEY);
const domain = {
  name: "MicroAI Paygate",
  version: "1",
  chainId,
  verifyingContract: "0x0000000000000000000000000000000000000000",
};
const types = {
  Payment: [
    { name: "recipient", type: "address" },
    { name: "token", type: "string" },
    { name: "amount", type: "string" },
    { name: "nonce", type: "string" },
    { name: "timestamp", type: "uint256" },
  ],
};
const timestamp = Math.floor(Date.now() / 1000);
const lines = [];

for (let i = 0; i < count; i += 1) {
  const message = {
    recipient: process.env.RECIPIENT_ADDRESS,
    token: process.env.PAYMENT_TOKEN,
    amount: process.env.PAYMENT_AMOUNT,
    nonce: `bench-${randomUUID()}-${i}`,
    timestamp,
  };
  const signature = await wallet.signTypedData(domain, types, message);
  lines.push(JSON.stringify({
    context: {
      recipient: message.recipient,
      token: message.token,
      amount: message.amount,
      nonce: message.nonce,
      chainId,
      timestamp,
    },
    signature,
  }));
}

writeFileSync(process.env.PAYLOADS_FILE, `${lines.join("\n")}\n`);
JS

(
  cd "$ROOT_DIR"
  PAYLOADS_FILE="$PAYLOADS_FILE" \
  PAYLOAD_COUNT="$PAYLOAD_COUNT" \
  CHAIN_ID="$CHAIN_ID" \
  RECIPIENT_ADDRESS="$RECIPIENT_ADDRESS" \
  PAYMENT_TOKEN="$PAYMENT_TOKEN" \
  PAYMENT_AMOUNT="$PAYMENT_AMOUNT" \
  BENCH_WALLET_PRIVATE_KEY="$BENCH_WALLET_PRIVATE_KEY" \
  bun "$GENERATOR_FILE"
)

cat >"$LUA_FILE" <<LUA
local payloads = {}
for line in io.lines("$PAYLOADS_FILE") do
  if line ~= "" then
    table.insert(payloads, line)
  end
end

local counter = 0
request = function()
  counter = counter + 1
  local body = payloads[((counter - 1) % #payloads) + 1]
  return wrk.format("POST", "/verify", {["Content-Type"] = "application/json"}, body)
end
LUA

run_benchmark() {
  echo "# MicroAI Paygate verifier wrk benchmark"
  echo "date_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "host=$(hostname)"
  echo "uname=$(uname -a)"
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n machdep.cpu.brand_string hw.ncpu hw.memsize 2>/dev/null | awk 'NR==1{print "cpu="$0} NR==2{print "hw_ncpu="$0} NR==3{print "hw_memsize_bytes="$0}' || true
  fi
  echo "wrk=$(wrk --version 2>&1 | head -n 1)"
  echo "target=$TARGET_URL"
  echo "threads=$THREADS"
  echo "connections=$CONNECTIONS"
  echo "duration=$DURATION"
  echo "payload_count=$PAYLOAD_COUNT"
  echo
  wrk -t "$THREADS" -c "$CONNECTIONS" -d "$DURATION" -s "$LUA_FILE" "$TARGET_URL"
}

if [[ -n "$RESULTS_FILE" ]]; then
  mkdir -p "$(dirname "$RESULTS_FILE")"
  run_benchmark | tee "$RESULTS_FILE"
else
  run_benchmark
fi
