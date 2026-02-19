#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_REPO="$ROOT_DIR"
WORK_DIR=""
KEEP_WORK_DIR=0
BOOTSTRAP_MODE="dry-run"
SUITE="safe_regression,vulnerable_ground_truth"
TRIALS=1
JOBS=1
BATCH_JOBS=1
WORKERS=1
ITERATIONS=50
TIMEOUT=10
OUTPUT_SUBDIR="artifacts/fresh_clone_validation"
MIN_ATTACK_STAGE_RATE=0.0
MIN_COMPLETION_RATE=0.0
MAX_CIRCOM_COMPILATION_FAILED=0
RUN_ID="$(date +%Y%m%d_%H%M%S)"
REPORT_OUT="$ROOT_DIR/artifacts/fresh_clone_validation/fresh_clone_${RUN_ID}_report.json"
CARGO_OFFLINE=1

usage() {
  cat <<'USAGE'
Usage: scripts/fresh_clone_bootstrap_validate.sh [options]

Clone the repo into a clean temporary directory, run bins bootstrap, and run
a compact benchmark matrix to validate fresh-environment operability.

Options:
  --source-repo <path>        Source repo path to clone (default: current repo)
  --work-dir <path>           Explicit work directory (default: auto temp dir)
  --keep-work-dir             Keep generated work directory after completion
  --bootstrap-mode <mode>     Bootstrap mode: dry-run | real (default: dry-run)
  --suite <names>             Benchmark suites (default: safe_regression,vulnerable_ground_truth)
  --trials <n>                Trials per target (default: 1)
  --jobs <n>                  Benchmark jobs (default: 1)
  --batch-jobs <n>            Batch jobs per trial (default: 1)
  --workers <n>               Workers per scan (default: 1)
  --iterations <n>            Iterations per run (default: 50)
  --timeout <seconds>         Timeout per run (default: 10)
  --output-subdir <path>      Output dir inside clone (default: artifacts/fresh_clone_validation)
  --min-attack-stage-rate <f> Minimum required attack-stage reach rate (default: 0.0)
  --min-completion-rate <f>   Minimum required completion rate (default: 0.0)
  --max-circom-compilation-failed <n>
                              Maximum allowed circom_compilation_failed runs (default: 0)
  --report-out <path>         Report output JSON path (default: artifacts/fresh_clone_validation/fresh_clone_<timestamp>_report.json)
  --no-cargo-offline          Disable cargo --offline for clone build/run steps
  -h, --help                  Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-repo)
      SOURCE_REPO="$2"
      shift 2
      ;;
    --work-dir)
      WORK_DIR="$2"
      shift 2
      ;;
    --keep-work-dir)
      KEEP_WORK_DIR=1
      shift
      ;;
    --bootstrap-mode)
      BOOTSTRAP_MODE="$2"
      shift 2
      ;;
    --suite)
      SUITE="$2"
      shift 2
      ;;
    --trials)
      TRIALS="$2"
      shift 2
      ;;
    --jobs)
      JOBS="$2"
      shift 2
      ;;
    --batch-jobs)
      BATCH_JOBS="$2"
      shift 2
      ;;
    --workers)
      WORKERS="$2"
      shift 2
      ;;
    --iterations)
      ITERATIONS="$2"
      shift 2
      ;;
    --timeout)
      TIMEOUT="$2"
      shift 2
      ;;
    --output-subdir)
      OUTPUT_SUBDIR="$2"
      shift 2
      ;;
    --min-attack-stage-rate)
      MIN_ATTACK_STAGE_RATE="$2"
      shift 2
      ;;
    --min-completion-rate)
      MIN_COMPLETION_RATE="$2"
      shift 2
      ;;
    --max-circom-compilation-failed)
      MAX_CIRCOM_COMPILATION_FAILED="$2"
      shift 2
      ;;
    --report-out)
      REPORT_OUT="$2"
      shift 2
      ;;
    --no-cargo-offline)
      CARGO_OFFLINE=0
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

if [[ "$BOOTSTRAP_MODE" != "dry-run" && "$BOOTSTRAP_MODE" != "real" ]]; then
  echo "Invalid --bootstrap-mode: $BOOTSTRAP_MODE (expected dry-run|real)" >&2
  exit 2
fi

if [[ ! -d "$SOURCE_REPO" ]]; then
  echo "Source repo does not exist: $SOURCE_REPO" >&2
  exit 2
fi

if [[ "$REPORT_OUT" != /* ]]; then
  REPORT_OUT="$ROOT_DIR/$REPORT_OUT"
fi

REPORT_DIR="$(dirname "$REPORT_OUT")"
mkdir -p "$REPORT_DIR"

write_failure_report() {
  local stage="$1"
  local error_message="$2"
  mkdir -p "$(dirname "$REPORT_OUT")"
  python3 - "$REPORT_OUT" "$stage" "$error_message" "$BOOTSTRAP_MODE" <<'PY'
import json
import sys
from datetime import datetime, timezone

report_out, stage, error_message, bootstrap_mode = sys.argv[1:]
payload = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "bootstrap_mode": bootstrap_mode,
    "passes": False,
    "stage": stage,
    "error": error_message,
}
with open(report_out, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
PY
  echo "Report: $REPORT_OUT"
}

if [[ -z "$WORK_DIR" ]]; then
  WORK_DIR="$(mktemp -d /tmp/zkfuzz_fresh_clone_XXXXXX)"
fi

if [[ "$KEEP_WORK_DIR" -eq 0 ]]; then
  cleanup() {
    rm -rf "$WORK_DIR"
  }
  trap cleanup EXIT
fi

CLONE_DIR="$WORK_DIR/repo"
echo "Cloning into clean workspace: $CLONE_DIR"
if ! git clone --depth 1 "$SOURCE_REPO" "$CLONE_DIR" >/dev/null; then
  write_failure_report "clone" "git clone failed"
  exit 1
fi

pushd "$CLONE_DIR" >/dev/null

declare -a CARGO_ARGS=()
if [[ "$CARGO_OFFLINE" -eq 1 ]]; then
  CARGO_ARGS+=(--offline)
fi

echo "Building required binaries in clone..."
if ! cargo "${CARGO_ARGS[@]}" build --release --bin zk-fuzzer --bin zk0d_benchmark >/dev/null; then
  write_failure_report "build" "cargo build failed in fresh clone"
  exit 1
fi

if [[ "$BOOTSTRAP_MODE" == "dry-run" ]]; then
  echo "Running bootstrap dry-run..."
  if ! cargo "${CARGO_ARGS[@]}" run --release --bin zk-fuzzer -- --dry-run bins bootstrap >/dev/null; then
    write_failure_report "bootstrap_dry_run" "bootstrap dry-run failed"
    exit 1
  fi
else
  echo "Running full bootstrap..."
  if ! cargo "${CARGO_ARGS[@]}" run --release --bin zk-fuzzer -- bins bootstrap; then
    write_failure_report "bootstrap_real" "bootstrap execution failed"
    exit 1
  fi
fi

echo "Running benchmark validation matrix..."
if ! cargo "${CARGO_ARGS[@]}" run --release --bin zk0d_benchmark -- \
  --config-profile dev \
  --suite "$SUITE" \
  --trials "$TRIALS" \
  --jobs "$JOBS" \
  --batch-jobs "$BATCH_JOBS" \
  --workers "$WORKERS" \
  --iterations "$ITERATIONS" \
  --timeout "$TIMEOUT" \
  --output-dir "$OUTPUT_SUBDIR" >/tmp/zkfuzz_fresh_clone_validate.log 2>&1; then
  write_failure_report "benchmark_run" "zk0d_benchmark execution failed in fresh clone"
  exit 1
fi

SUMMARY_PATH="$(
  find "$OUTPUT_SUBDIR" -type f \
    | rg '/benchmark_[0-9]{8}_[0-9]{6}/summary\.json$' \
    | sort \
    | tail -n 1
)"
OUTCOMES_PATH="$(
  find "$OUTPUT_SUBDIR" -type f \
    | rg '/benchmark_[0-9]{8}_[0-9]{6}/outcomes\.json$' \
    | sort \
    | tail -n 1
)"
if [[ -z "$SUMMARY_PATH" || ! -f "$SUMMARY_PATH" ]]; then
  write_failure_report "summary_discovery" "benchmark summary.json not found"
  echo "No benchmark summary found under '$OUTPUT_SUBDIR'" >&2
  exit 1
fi
if [[ -z "$OUTCOMES_PATH" || ! -f "$OUTCOMES_PATH" ]]; then
  write_failure_report "outcomes_discovery" "benchmark outcomes.json not found"
  echo "No benchmark outcomes found under '$OUTPUT_SUBDIR'" >&2
  exit 1
fi

COPIED_SUMMARY="$REPORT_DIR/fresh_clone_${RUN_ID}_summary.json"
COPIED_OUTCOMES="$REPORT_DIR/fresh_clone_${RUN_ID}_outcomes.json"
cp "$SUMMARY_PATH" "$COPIED_SUMMARY"
cp "$OUTCOMES_PATH" "$COPIED_OUTCOMES"

python3 - "$SUMMARY_PATH" "$OUTCOMES_PATH" "$MIN_ATTACK_STAGE_RATE" "$MIN_COMPLETION_RATE" "$MAX_CIRCOM_COMPILATION_FAILED" "$BOOTSTRAP_MODE" "$REPORT_OUT" "$COPIED_SUMMARY" "$COPIED_OUTCOMES" <<'PY'
import json
import sys
from datetime import datetime, timezone

(
    summary_path,
    outcomes_path,
    min_attack_stage_raw,
    min_completion_raw,
    max_circom_compilation_failed_raw,
    bootstrap_mode,
    report_out,
    copied_summary,
    copied_outcomes,
) = sys.argv[1:]
min_attack_stage = float(min_attack_stage_raw)
min_completion = float(min_completion_raw)
max_circom_compilation_failed = int(max_circom_compilation_failed_raw)
with open(summary_path, "r", encoding="utf-8") as f:
    summary = json.load(f)
with open(outcomes_path, "r", encoding="utf-8") as f:
    outcomes = json.load(f)

attack_stage = float(summary.get("overall_attack_stage_reach_rate", 0.0))
completion = float(summary.get("overall_completion_rate", 0.0))
total_runs = int(summary.get("total_runs", 0))
aggregated_reason_counts = {}
locked = 0
for outcome in outcomes:
    reason_counts = outcome.get("reason_counts", {})
    for key, value in reason_counts.items():
        aggregated_reason_counts[key] = aggregated_reason_counts.get(key, 0) + int(value)
    locked += int(reason_counts.get("output_dir_locked", 0))

circom_compilation_failed = int(aggregated_reason_counts.get("circom_compilation_failed", 0))
completed_runs = int(aggregated_reason_counts.get("completed", 0))

print(
    "Fresh-clone metrics:"
    f" total_runs={total_runs}"
    f" completion={completion:.4f}"
    f" attack_stage={attack_stage:.4f}"
    f" completed_runs={completed_runs}"
    f" circom_compilation_failed={circom_compilation_failed}"
    f" output_dir_locked={locked}"
)

failures = []
if total_runs <= 0:
    failures.append("total_runs must be > 0")
if min_attack_stage > 0 and attack_stage < min_attack_stage:
    failures.append(
        f"overall_attack_stage_reach_rate {attack_stage:.4f} < {min_attack_stage:.4f}"
    )
if min_completion > 0 and completion < min_completion:
    failures.append(f"overall_completion_rate {completion:.4f} < {min_completion:.4f}")
if locked != 0:
    failures.append(f"output_dir_locked occurrences must be 0 (found {locked})")
if circom_compilation_failed > max_circom_compilation_failed:
    failures.append(
        "circom_compilation_failed occurrences must be <= "
        f"{max_circom_compilation_failed} (found {circom_compilation_failed})"
    )

payload = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "bootstrap_mode": bootstrap_mode,
    "summary_path": copied_summary,
    "outcomes_path": copied_outcomes,
    "total_runs": total_runs,
    "overall_completion_rate": completion,
    "overall_attack_stage_reach_rate": attack_stage,
    "completed_runs": completed_runs,
    "output_dir_locked": locked,
    "circom_compilation_failed": circom_compilation_failed,
    "aggregated_reason_counts": aggregated_reason_counts,
    "min_attack_stage_rate": min_attack_stage,
    "min_completion_rate": min_completion,
    "max_circom_compilation_failed": max_circom_compilation_failed,
    "passes": len(failures) == 0,
    "failures": failures,
}
with open(report_out, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)

if failures:
    print("Fresh clone validation failed:")
    for item in failures:
        print(f"  - {item}")
    sys.exit(1)
PY

echo "Fresh clone bootstrap validation passed."
echo "Summary: $CLONE_DIR/$SUMMARY_PATH"
echo "Outcomes: $CLONE_DIR/$OUTCOMES_PATH"
echo "Report: $REPORT_OUT"

if [[ "$KEEP_WORK_DIR" -eq 1 ]]; then
  echo "Kept workspace: $WORK_DIR"
fi

popd >/dev/null
