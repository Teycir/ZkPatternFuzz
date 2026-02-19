#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$ROOT_DIR/artifacts/phase3a_validation"
RUN_BACKEND_HEAVY=0
ENFORCE=0

usage() {
  cat <<'USAGE'
Usage: scripts/phase3a_validate.sh [options]

Run integrated validation checks for Phase 3A logic hardening criteria and
emit a machine-readable report.

Options:
  --output-dir <path>     Output directory for JSON report
  --run-backend-heavy     Run optional Cairo/Noir backend integration checks
  --enforce               Exit non-zero when any required check fails
  -h, --help              Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --run-backend-heavy)
      RUN_BACKEND_HEAVY=1
      shift
      ;;
    --enforce)
      ENFORCE=1
      shift
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

mkdir -p "$OUTPUT_DIR"

declare -a REQUIRED_CHECKS=()
declare -a REQUIRED_STATUS=()
declare -a OPTIONAL_CHECKS=()
declare -a OPTIONAL_STATUS=()

run_check() {
  local label="$1"
  local required="$2"
  shift 2
  local cmd=("$@")
  local log_path="$OUTPUT_DIR/${label}.log"

  echo "Running check: $label"
  if "${cmd[@]}" >"$log_path" 2>&1; then
    status="pass"
  else
    status="fail"
  fi

  if [[ "$required" == "required" ]]; then
    REQUIRED_CHECKS+=("$label")
    REQUIRED_STATUS+=("$status")
  else
    OPTIONAL_CHECKS+=("$label")
    OPTIONAL_STATUS+=("$status")
  fi
}

run_skip() {
  local label="$1"
  local required="$2"
  local reason="$3"
  local log_path="$OUTPUT_DIR/${label}.log"
  echo "SKIP: $reason" >"$log_path"
  if [[ "$required" == "required" ]]; then
    REQUIRED_CHECKS+=("$label")
    REQUIRED_STATUS+=("skip")
  else
    OPTIONAL_CHECKS+=("$label")
    OPTIONAL_STATUS+=("skip")
  fi
}

# Required checks: internal correctness hardening
run_check \
  "adaptive_orchestrator_allocation_plan" \
  "required" \
  cargo test -q --lib fuzzer::adaptive_orchestrator::tests::test_build_attack_phase_plan_prefers_higher_budget

run_check \
  "chain_runner_timeout_preemptive" \
  "required" \
  cargo test -q --lib chain_fuzzer::runner::tests::test_chain_runner_timeout_is_preemptive

run_check \
  "chain_runner_timeout_enforced" \
  "required" \
  cargo test -q --lib chain_fuzzer::runner::tests::test_chain_runner_enforces_step_timeout

if [[ "$RUN_BACKEND_HEAVY" -eq 1 ]]; then
  if command -v cairo-compile >/dev/null 2>&1 || command -v scarb >/dev/null 2>&1; then
    run_check \
      "cairo_backend_integration" \
      "optional" \
      cargo test -q --test backend_integration_tests test_cairo_integration -- --exact
  else
    run_skip "cairo_backend_integration" "optional" "Cairo tooling unavailable"
  fi

  if command -v nargo >/dev/null 2>&1; then
    run_check \
      "noir_constraint_coverage" \
      "optional" \
      cargo test -q --test backend_integration_tests test_noir_constraint_coverage -- --exact
  else
    run_skip "noir_constraint_coverage" "optional" "Noir tooling unavailable"
  fi
else
  run_skip "cairo_backend_integration" "optional" "backend-heavy checks disabled"
  run_skip "noir_constraint_coverage" "optional" "backend-heavy checks disabled"
fi

REPORT_PATH="$OUTPUT_DIR/phase3a_report.json"

python3 - "$REPORT_PATH" "$ENFORCE" \
  "$(IFS=,; echo "${REQUIRED_CHECKS[*]}")" \
  "$(IFS=,; echo "${REQUIRED_STATUS[*]}")" \
  "$(IFS=,; echo "${OPTIONAL_CHECKS[*]}")" \
  "$(IFS=,; echo "${OPTIONAL_STATUS[*]}")" <<'PY'
import json
import sys
from datetime import datetime, timezone

report_path = sys.argv[1]
enforce = bool(int(sys.argv[2]))
required_checks = [x for x in sys.argv[3].split(",") if x]
required_status = [x for x in sys.argv[4].split(",") if x]
optional_checks = [x for x in sys.argv[5].split(",") if x]
optional_status = [x for x in sys.argv[6].split(",") if x]

required_rows = [
    {"name": name, "status": status}
    for name, status in zip(required_checks, required_status)
]
optional_rows = [
    {"name": name, "status": status}
    for name, status in zip(optional_checks, optional_status)
]

required_failures = [row for row in required_rows if row["status"] == "fail"]
all_required_pass = len(required_failures) == 0

payload = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "required_checks": required_rows,
    "optional_checks": optional_rows,
    "required_pass": all_required_pass,
}

with open(report_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)

print(f"Phase 3A required checks: {'PASS' if all_required_pass else 'FAIL'}")
for row in required_rows:
    print(f"  - {row['name']}: {row['status']}")
for row in optional_rows:
    print(f"  - {row['name']}: {row['status']}")

if enforce and not all_required_pass:
    sys.exit(1)
PY

echo "Report: $REPORT_PATH"
