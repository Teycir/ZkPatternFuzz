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
MIN_ATTACK_STAGE_RATE=0.90

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
  --min-attack-stage-rate <f> Minimum required attack-stage reach rate (default: 0.90)
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
git clone --depth 1 "$SOURCE_REPO" "$CLONE_DIR" >/dev/null

pushd "$CLONE_DIR" >/dev/null

echo "Building required binaries in clone..."
cargo build --release --bin zk-fuzzer --bin zk0d_benchmark >/dev/null

if [[ "$BOOTSTRAP_MODE" == "dry-run" ]]; then
  echo "Running bootstrap dry-run..."
  cargo run --release --bin zk-fuzzer -- --dry-run bins bootstrap >/dev/null
else
  echo "Running full bootstrap..."
  cargo run --release --bin zk-fuzzer -- bins bootstrap
fi

echo "Running benchmark validation matrix..."
cargo run --release --bin zk0d_benchmark -- \
  --config-profile dev \
  --suite "$SUITE" \
  --trials "$TRIALS" \
  --jobs "$JOBS" \
  --batch-jobs "$BATCH_JOBS" \
  --workers "$WORKERS" \
  --iterations "$ITERATIONS" \
  --timeout "$TIMEOUT" \
  --output-dir "$OUTPUT_SUBDIR" >/tmp/zkfuzz_fresh_clone_validate.log 2>&1

SUMMARY_PATH="$(find "$OUTPUT_SUBDIR" -type f -path '*/benchmark_*/summary.json' | sort | tail -n 1)"
OUTCOMES_PATH="$(find "$OUTPUT_SUBDIR" -type f -path '*/benchmark_*/outcomes.json' | sort | tail -n 1)"
if [[ -z "$SUMMARY_PATH" || ! -f "$SUMMARY_PATH" ]]; then
  echo "No benchmark summary found under '$OUTPUT_SUBDIR'" >&2
  exit 1
fi
if [[ -z "$OUTCOMES_PATH" || ! -f "$OUTCOMES_PATH" ]]; then
  echo "No benchmark outcomes found under '$OUTPUT_SUBDIR'" >&2
  exit 1
fi

python3 - "$SUMMARY_PATH" "$OUTCOMES_PATH" "$MIN_ATTACK_STAGE_RATE" <<'PY'
import json
import sys

summary_path, outcomes_path, min_attack_stage = sys.argv[1], sys.argv[2], float(sys.argv[3])
with open(summary_path, "r", encoding="utf-8") as f:
    summary = json.load(f)
with open(outcomes_path, "r", encoding="utf-8") as f:
    outcomes = json.load(f)

attack_stage = float(summary.get("overall_attack_stage_reach_rate", 0.0))
completion = float(summary.get("overall_completion_rate", 0.0))
total_runs = int(summary.get("total_runs", 0))
locked = 0
for outcome in outcomes:
    reason_counts = outcome.get("reason_counts", {})
    locked += int(reason_counts.get("output_dir_locked", 0))

print(
    "Fresh-clone metrics:"
    f" total_runs={total_runs}"
    f" completion={completion:.4f}"
    f" attack_stage={attack_stage:.4f}"
    f" output_dir_locked={locked}"
)

failures = []
if total_runs <= 0:
    failures.append("total_runs must be > 0")
if attack_stage < min_attack_stage:
    failures.append(
        f"overall_attack_stage_reach_rate {attack_stage:.4f} < {min_attack_stage:.4f}"
    )
if locked != 0:
    failures.append(f"output_dir_locked occurrences must be 0 (found {locked})")

if failures:
    print("Fresh clone validation failed:")
    for item in failures:
        print(f"  - {item}")
    sys.exit(1)
PY

echo "Fresh clone bootstrap validation passed."
echo "Summary: $CLONE_DIR/$SUMMARY_PATH"
echo "Outcomes: $CLONE_DIR/$OUTCOMES_PATH"

if [[ "$KEEP_WORK_DIR" -eq 1 ]]; then
  echo "Kept workspace: $WORK_DIR"
fi

popd >/dev/null
