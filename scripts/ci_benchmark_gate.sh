#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_ROOT="${1:-$ROOT_DIR/artifacts/benchmark_runs}"
SUMMARY_PATH_OVERRIDE="${2:-}"

cmd=(
  cargo run
  --quiet
  --locked
  --manifest-path "$ROOT_DIR/Cargo.toml"
  --bin zkf_checks
  --
  benchmark-regression-gate
  --benchmark-root "$BENCH_ROOT"
)

if [[ -n "$SUMMARY_PATH_OVERRIDE" ]]; then
  cmd+=(--summary "$SUMMARY_PATH_OVERRIDE")
fi

"${cmd[@]}"
