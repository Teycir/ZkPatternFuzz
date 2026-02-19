#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE="safe_regression"
PROFILE="dev"
REQUIRED_PASSES=4
REPORT_OUT="$ROOT_DIR/artifacts/keygen_preflight/latest_report.json"
RUN_ID="$(date +%Y%m%d_%H%M%S)"

usage() {
  cat <<'USAGE'
Usage: scripts/keygen_preflight_validate.sh [options]

Run `zk-fuzzer preflight --setup-keys` across all targets in one benchmark suite
and emit a JSON report with per-target pass/fail status.

Options:
  --suite <name>             Benchmark suite name (default: safe_regression)
  --profile <name>           Benchmark suite profile: dev|prod|default (default: dev)
  --required-passes <n>      Minimum passing targets required (default: 4)
  --report-out <path>        Output report JSON path
  -h, --help                 Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --suite)
      SUITE="$2"
      shift 2
      ;;
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --required-passes)
      REQUIRED_PASSES="$2"
      shift 2
      ;;
    --report-out)
      REPORT_OUT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$PROFILE" in
  dev) SUITES_YAML="$ROOT_DIR/targets/benchmark_suites.dev.yaml" ;;
  prod) SUITES_YAML="$ROOT_DIR/targets/benchmark_suites.prod.yaml" ;;
  default) SUITES_YAML="$ROOT_DIR/targets/benchmark_suites.yaml" ;;
  *)
    echo "Invalid --profile: $PROFILE (expected dev|prod|default)" >&2
    exit 2
    ;;
esac

if [[ ! -f "$SUITES_YAML" ]]; then
  echo "Suite file not found: $SUITES_YAML" >&2
  exit 2
fi

if [[ "$REPORT_OUT" != /* ]]; then
  REPORT_OUT="$ROOT_DIR/$REPORT_OUT"
fi
REPORT_DIR="$(dirname "$REPORT_OUT")"
mkdir -p "$REPORT_DIR"
LOG_DIR="$REPORT_DIR/keygen_preflight_${RUN_ID}_logs"
mkdir -p "$LOG_DIR"

TMP_DIR="$(mktemp -d /tmp/zkfuzz_keygen_preflight_XXXXXX)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

TARGETS_TSV="$TMP_DIR/targets.tsv"
python3 - "$SUITES_YAML" "$SUITE" "$TARGETS_TSV" <<'PY'
import sys

import yaml

suites_yaml, suite_name, out_tsv = sys.argv[1:]
with open(suites_yaml, "r", encoding="utf-8") as f:
    data = yaml.safe_load(f) or {}
suites = (data.get("suites") or {})
suite = suites.get(suite_name)
if suite is None:
    raise SystemExit(f"Suite '{suite_name}' not found in {suites_yaml}")
targets = suite.get("targets") or []
if not targets:
    raise SystemExit(f"Suite '{suite_name}' has no targets in {suites_yaml}")

with open(out_tsv, "w", encoding="utf-8") as out:
    for target in targets:
        if not target.get("enabled", True):
            continue
        out.write(
            "\t".join(
                [
                    target["name"],
                    target["target_circuit"],
                    target["main_component"],
                    target["framework"],
                ]
            )
            + "\n"
        )
PY

if [[ ! -s "$TARGETS_TSV" ]]; then
  echo "Suite '$SUITE' has no enabled targets in $SUITES_YAML" >&2
  exit 2
fi

declare -a RESULT_LINES=()
TOTAL=0
PASSED=0
FAILED=0

while IFS=$'\t' read -r target_name target_circuit main_component framework; do
  [[ -n "$target_name" ]] || continue
  TOTAL=$((TOTAL + 1))
  campaign_yaml="$TMP_DIR/${target_name}.yaml"
  cat > "$campaign_yaml" <<YAML
campaign:
  name: "Keygen Preflight ${target_name}"
  version: "1.0"
  target:
    framework: "${framework}"
    circuit_path: "${target_circuit}"
    main_component: "${main_component}"
  parameters:
    field: "bn254"
    max_constraints: 100000
    timeout_seconds: 60
attacks:
  - type: "circom_static_lint"
    description: "preflight only"
inputs:
  - name: "input_0"
    type: "field"
    fuzz_strategy: "random"
YAML

  log_path="$LOG_DIR/${target_name}.log"
  start_ts="$(date +%s)"
  if cargo run --quiet --release --bin zk-fuzzer -- preflight "$campaign_yaml" --setup-keys >"$log_path" 2>&1; then
    status="pass"
    PASSED=$((PASSED + 1))
  else
    status="fail"
    FAILED=$((FAILED + 1))
  fi
  end_ts="$(date +%s)"
  duration="$((end_ts - start_ts))"
  RESULT_LINES+=("${target_name}"$'\t'"${status}"$'\t'"${duration}"$'\t'"${target_circuit}"$'\t'"${main_component}"$'\t'"${framework}"$'\t'"${log_path}")
  echo "preflight target=${target_name} status=${status} duration_s=${duration}"
done < "$TARGETS_TSV"

generated_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

RESULTS_TSV="$TMP_DIR/results.tsv"
printf '%s\n' "${RESULT_LINES[@]}" > "$RESULTS_TSV"

python3 - "$REPORT_OUT" "$generated_utc" "$SUITE" "$PROFILE" "$REQUIRED_PASSES" "$TOTAL" "$PASSED" "$FAILED" "$RESULTS_TSV" <<'PY'
import json
import sys

(
    report_out,
    generated_utc,
    suite_name,
    profile,
    required_passes,
    total_targets,
    passed_targets,
    failed_targets,
    results_tsv,
) = sys.argv[1:]

required_passes = int(required_passes)
total_targets = int(total_targets)
passed_targets = int(passed_targets)
failed_targets = int(failed_targets)

targets = []
with open(results_tsv, "r", encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) != 7:
            continue
        (
            name,
            status,
            duration_s,
            target_circuit,
            main_component,
            framework,
            log_path,
        ) = parts
        targets.append(
            {
                "name": name,
                "status": status,
                "duration_s": int(duration_s),
                "target_circuit": target_circuit,
                "main_component": main_component,
                "framework": framework,
                "log_path": log_path,
            }
        )

payload = {
    "generated_utc": generated_utc,
    "suite": suite_name,
    "profile": profile,
    "required_passes": required_passes,
    "total_targets": total_targets,
    "passed_targets": passed_targets,
    "failed_targets": failed_targets,
    "passes": passed_targets >= required_passes,
    "targets": targets,
}

with open(report_out, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
PY

echo "Keygen preflight summary: suite=${SUITE} profile=${PROFILE} total=${TOTAL} pass=${PASSED} fail=${FAILED} required=${REQUIRED_PASSES}"
echo "Report: $REPORT_OUT"

if (( PASSED < REQUIRED_PASSES )); then
  echo "Keygen preflight validation failed: pass count below required threshold" >&2
  exit 1
fi
