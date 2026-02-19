#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$ROOT_DIR/artifacts/phase3a_timeout_noir_validation"
NOIR_PROJECT="tests/noir_projects/multiplier"
NOIR_RUNS=20
MIN_IMPROVEMENT_RATIO=1.05
ENFORCE=0

usage() {
  cat <<'USAGE'
Usage: scripts/phase3a_timeout_noir_validate.sh [options]

Run dedicated Phase 3A evidence checks for:
  1) proof-forgery subprocess timeout hardening
  2) Noir repeated-run throughput improvement

Options:
  --output-dir <path>            Output directory (default: artifacts/phase3a_timeout_noir_validation)
  --noir-project <path>          Noir project path (default: tests/noir_projects/multiplier)
  --noir-runs <n>                Number of Noir execution runs (default: 20)
  --min-improvement-ratio <f>    Required cold/warm ratio (default: 1.05)
  --enforce                      Exit non-zero if any required check fails
  -h, --help                     Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --noir-project)
      NOIR_PROJECT="$2"
      shift 2
      ;;
    --noir-runs)
      NOIR_RUNS="$2"
      shift 2
      ;;
    --min-improvement-ratio)
      MIN_IMPROVEMENT_RATIO="$2"
      shift 2
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

TIMEOUT_LOG="$OUTPUT_DIR/proof_forgery_timeout.log"
NOIR_LOG="$OUTPUT_DIR/noir_throughput.log"
NOIR_REPORT="$OUTPUT_DIR/noir_throughput_report.json"
REPORT_PATH="$OUTPUT_DIR/phase3a_timeout_noir_report.json"

echo "Running proof-forgery timeout hardening tests..."
if cargo test -q --lib reporting::command_timeout::tests::test_run_with_timeout_reports_timeout_for_sleep_command >"$TIMEOUT_LOG" 2>&1 \
  && cargo test -q --lib reporting::command_timeout::tests::test_run_with_timeout_captures_stdout_and_stderr >>"$TIMEOUT_LOG" 2>&1; then
  timeout_status="pass"
else
  timeout_status="fail"
fi

echo "Running Noir repeated-run throughput check..."
if cargo run --quiet --bin zk0d_noir_throughput -- \
  --project "$NOIR_PROJECT" \
  --runs "$NOIR_RUNS" \
  --min-improvement-ratio "$MIN_IMPROVEMENT_RATIO" \
  --json-out "$NOIR_REPORT" >"$NOIR_LOG" 2>&1; then
  noir_status="pass"
else
  noir_status="fail"
fi

python3 - "$REPORT_PATH" "$timeout_status" "$noir_status" "$TIMEOUT_LOG" "$NOIR_LOG" "$NOIR_REPORT" "$NOIR_PROJECT" "$NOIR_RUNS" "$MIN_IMPROVEMENT_RATIO" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

(
    report_path,
    timeout_status,
    noir_status,
    timeout_log,
    noir_log,
    noir_report_path,
    noir_project,
    noir_runs,
    min_ratio,
) = sys.argv[1:]

noir_metrics = None
noir_report_file = Path(noir_report_path)
if noir_report_file.exists():
    try:
        noir_metrics = json.loads(noir_report_file.read_text(encoding="utf-8"))
    except Exception:
        noir_metrics = None

payload = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "required_checks": [
        {
            "name": "proof_forgery_timeout_hardening",
            "status": timeout_status,
            "log_path": timeout_log,
        },
        {
            "name": "noir_repeated_run_throughput",
            "status": noir_status,
            "log_path": noir_log,
            "report_path": noir_report_path,
            "project": noir_project,
            "runs": int(noir_runs),
            "min_improvement_ratio": float(min_ratio),
            "metrics": noir_metrics,
        },
    ],
}
payload["required_pass"] = all(check["status"] == "pass" for check in payload["required_checks"])

Path(report_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
print(f"Phase 3A timeout/noir required checks: {'PASS' if payload['required_pass'] else 'FAIL'}")
for check in payload["required_checks"]:
    print(f"  - {check['name']}: {check['status']}")
print(f"Report: {report_path}")
PY

if [[ "$ENFORCE" -eq 1 ]]; then
  if [[ "$timeout_status" != "pass" || "$noir_status" != "pass" ]]; then
    exit 1
  fi
fi
