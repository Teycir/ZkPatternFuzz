#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/run_constraint_guided_smoke.sh [options]

Core options (set once, used for both baseline + tuned):
  --circuit PATH            Circom circuit path
  --main NAME               Main component (default: main)
  --inputs N                Number of inputs (default: 10)
  --build-dir PATH          Build dir (default: /tmp/zkfuzz_build)
  --report-dir PATH         Report dir (default: /tmp/zkfuzz_reports)
  --work-dir PATH           Working dir for configs/logs (default: /tmp/zkfuzz_runs)
  --workers N               Worker count (default: 1)
  --seed N                  RNG seed (default: 1)
  --zk0d-root PATH           zk0d root (default: /media/elements/Repos/zk0d)

Constraint-guided tuning (applies to tuned run only):
  --cg-max-depth N
  --cg-max-paths N
  --cg-timeout-ms N
  --cg-solutions N
  --cg-pruning STR          e.g. random_sampling, depth_bounded
  --cg-simplify BOOL
  --cg-incremental BOOL
  --cg-loop-bound N

Build/run controls:
  --enable-acir-bytecode    Build/run with --features acir-bytecode
  --offline                 Use cargo --offline
  --skip-build              Skip cargo build step

Examples:
  scripts/run_constraint_guided_smoke.sh --circuit /path/to.circom --inputs 12 --workers 2
  scripts/run_constraint_guided_smoke.sh --zk0d-root ${ZK0D_BASE:-/media/elements/Repos/zk0d} --cg-max-depth 30
EOF
}

ZK0D_ROOT="${ZK0D_ROOT:-/media/elements/Repos/zk0d}"
ZKF_CIRCUIT_PATH="${ZKF_CIRCUIT_PATH:-}"
ZKF_MAIN_COMPONENT="${ZKF_MAIN_COMPONENT:-main}"
ZKF_INPUT_COUNT="${ZKF_INPUT_COUNT:-10}"
ZKF_BUILD_DIR="${ZKF_BUILD_DIR:-/tmp/zkfuzz_build}"
ZKF_REPORT_DIR="${ZKF_REPORT_DIR:-/tmp/zkfuzz_reports}"
ZKF_WORK_DIR="${ZKF_WORK_DIR:-/tmp/zkfuzz_runs}"
ZKF_SEED="${ZKF_SEED:-1}"
ZKF_WORKERS="${ZKF_WORKERS:-1}"
ZKF_ENABLE_ACIR_BYTECODE="${ZKF_ENABLE_ACIR_BYTECODE:-0}"
ZKF_CARGO_OFFLINE="${ZKF_CARGO_OFFLINE:-0}"
ZKF_SKIP_BUILD="${ZKF_SKIP_BUILD:-0}"

ZKF_CG_MAX_DEPTH="${ZKF_CG_MAX_DEPTH:-40}"
ZKF_CG_MAX_PATHS="${ZKF_CG_MAX_PATHS:-200}"
ZKF_CG_SOLVER_TIMEOUT_MS="${ZKF_CG_SOLVER_TIMEOUT_MS:-1500}"
ZKF_CG_SOLUTIONS_PER_PATH="${ZKF_CG_SOLUTIONS_PER_PATH:-1}"
ZKF_CG_PRUNING="${ZKF_CG_PRUNING:-random_sampling}"
ZKF_CG_SIMPLIFY="${ZKF_CG_SIMPLIFY:-true}"
ZKF_CG_INCREMENTAL="${ZKF_CG_INCREMENTAL:-false}"
ZKF_CG_LOOP_BOUND="${ZKF_CG_LOOP_BOUND:-5}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --circuit)
      ZKF_CIRCUIT_PATH="$2"
      shift 2
      ;;
    --main)
      ZKF_MAIN_COMPONENT="$2"
      shift 2
      ;;
    --inputs)
      ZKF_INPUT_COUNT="$2"
      shift 2
      ;;
    --build-dir)
      ZKF_BUILD_DIR="$2"
      shift 2
      ;;
    --report-dir)
      ZKF_REPORT_DIR="$2"
      shift 2
      ;;
    --work-dir)
      ZKF_WORK_DIR="$2"
      shift 2
      ;;
    --workers)
      ZKF_WORKERS="$2"
      shift 2
      ;;
    --seed)
      ZKF_SEED="$2"
      shift 2
      ;;
    --zk0d-root)
      ZK0D_ROOT="$2"
      shift 2
      ;;
    --cg-max-depth)
      ZKF_CG_MAX_DEPTH="$2"
      shift 2
      ;;
    --cg-max-paths)
      ZKF_CG_MAX_PATHS="$2"
      shift 2
      ;;
    --cg-timeout-ms)
      ZKF_CG_SOLVER_TIMEOUT_MS="$2"
      shift 2
      ;;
    --cg-solutions)
      ZKF_CG_SOLUTIONS_PER_PATH="$2"
      shift 2
      ;;
    --cg-pruning)
      ZKF_CG_PRUNING="$2"
      shift 2
      ;;
    --cg-simplify)
      ZKF_CG_SIMPLIFY="$2"
      shift 2
      ;;
    --cg-incremental)
      ZKF_CG_INCREMENTAL="$2"
      shift 2
      ;;
    --cg-loop-bound)
      ZKF_CG_LOOP_BOUND="$2"
      shift 2
      ;;
    --enable-acir-bytecode)
      ZKF_ENABLE_ACIR_BYTECODE=1
      shift 1
      ;;
    --offline)
      ZKF_CARGO_OFFLINE=1
      shift 1
      ;;
    --skip-build)
      ZKF_SKIP_BUILD=1
      shift 1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

mkdir -p "$ZKF_WORK_DIR" "$ZKF_BUILD_DIR" "$ZKF_REPORT_DIR"

if [[ -z "$ZKF_CIRCUIT_PATH" ]]; then
  default_circuit="$ZK0D_ROOT/cat3_privacy/circuits/test/circuits/utils/utils_verifyExpirationTime.circom"
  if [[ -f "$default_circuit" ]]; then
    ZKF_CIRCUIT_PATH="$default_circuit"
  elif [[ -d "$ZK0D_ROOT" ]]; then
    ZKF_CIRCUIT_PATH="$(find "$ZK0D_ROOT" -type f -name '*.circom' | head -n 1)"
  fi
fi

if [[ -z "$ZKF_CIRCUIT_PATH" || ! -f "$ZKF_CIRCUIT_PATH" ]]; then
  echo "Could not locate a Circom circuit." >&2
  echo "Set ZKF_CIRCUIT_PATH or ZK0D_ROOT to a valid path." >&2
  exit 1
fi

baseline="$ZKF_WORK_DIR/zkfuzz_circom_baseline.yaml"
tuned="$ZKF_WORK_DIR/zkfuzz_circom_tuned.yaml"

emit_inputs() {
  local count="$1"
  local idx=0
  while [[ "$idx" -lt "$count" ]]; do
    cat <<EOF
  - name: "in${idx}"
    type: "field"
    fuzz_strategy: "random"
EOF
    idx=$((idx + 1))
  done
}

cat <<EOF > "$baseline"
campaign:
  name: "zk0d_constraint_guided_baseline"
  version: "1.0"
  target:
    framework: "circom"
    circuit_path: "$ZKF_CIRCUIT_PATH"
    main_component: "$ZKF_MAIN_COMPONENT"
  parameters:
    timeout_seconds: 120
    max_constraints: 200000
    build_dir: "$ZKF_BUILD_DIR"

attacks:
  - type: "boundary"
    description: "Quick boundary check"
    config:
      test_values: ["0", "1"]

inputs:
$(emit_inputs "$ZKF_INPUT_COUNT")

reporting:
  output_dir: "$ZKF_REPORT_DIR"
EOF

cat <<EOF > "$tuned"
campaign:
  name: "zk0d_constraint_guided_tuned"
  version: "1.0"
  target:
    framework: "circom"
    circuit_path: "$ZKF_CIRCUIT_PATH"
    main_component: "$ZKF_MAIN_COMPONENT"
  parameters:
    timeout_seconds: 120
    max_constraints: 200000
    build_dir: "$ZKF_BUILD_DIR"
    constraint_guided_enabled: true
    constraint_guided_max_depth: $ZKF_CG_MAX_DEPTH
    constraint_guided_max_paths: $ZKF_CG_MAX_PATHS
    constraint_guided_solver_timeout_ms: $ZKF_CG_SOLVER_TIMEOUT_MS
    constraint_guided_solutions_per_path: $ZKF_CG_SOLUTIONS_PER_PATH
    constraint_guided_pruning_strategy: "$ZKF_CG_PRUNING"
    constraint_guided_simplify_constraints: $ZKF_CG_SIMPLIFY
    constraint_guided_incremental_solving: $ZKF_CG_INCREMENTAL
    constraint_guided_loop_bound: $ZKF_CG_LOOP_BOUND

attacks:
  - type: "boundary"
    description: "Quick boundary check"
    config:
      test_values: ["0", "1"]

inputs:
$(emit_inputs "$ZKF_INPUT_COUNT")

reporting:
  output_dir: "$ZKF_REPORT_DIR"
EOF

build_cmd=(cargo build --release)
if [[ "$ZKF_ENABLE_ACIR_BYTECODE" == "1" ]]; then
  build_cmd+=(--features acir-bytecode)
fi
if [[ "$ZKF_CARGO_OFFLINE" == "1" ]]; then
  build_cmd+=(--offline)
fi

if [[ "$ZKF_SKIP_BUILD" != "1" ]]; then
  echo "Building..."
  "${build_cmd[@]}"
fi

run_cmd=(cargo run --release --)
if [[ "$ZKF_ENABLE_ACIR_BYTECODE" == "1" ]]; then
  run_cmd=(cargo run --release --features acir-bytecode --)
fi
if [[ "$ZKF_CARGO_OFFLINE" == "1" ]]; then
  run_cmd=(cargo run --release --offline --)
fi

baseline_log="$ZKF_WORK_DIR/baseline.log"
tuned_log="$ZKF_WORK_DIR/tuned.log"

echo "Running baseline..."
"${run_cmd[@]}" --config "$baseline" --workers "$ZKF_WORKERS" --seed "$ZKF_SEED" --verbose | tee "$baseline_log"

echo "Running tuned..."
"${run_cmd[@]}" --config "$tuned" --workers "$ZKF_WORKERS" --seed "$ZKF_SEED" --verbose | tee "$tuned_log"

echo "Summary:"
grep -E "Constraint-guided seeds:" -m 1 "$baseline_log" || echo "Baseline: no constraint-guided seed summary found"
grep -E "Constraint-guided seeds:" -m 1 "$tuned_log" || echo "Tuned: no constraint-guided seed summary found"
