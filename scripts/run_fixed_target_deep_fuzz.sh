#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MATRIX_PATH="$ROOT_DIR/targets/zk0d_matrix_external_manual.yaml"
REGISTRY_PATH="$ROOT_DIR/targets/fuzzer_registry.prod.yaml"
ZKEVM_TEMPLATE_CSV="cveX15_scroll_missing_overflow_constraint.yaml,cveX16_scroll_missing_constraint.yaml,cveX35_halo2_signature_readiness_probe.yaml,cveX36_halo2_constraint_metadata_readiness_probe.yaml,cveX37_halo2_plonk_lookup_readiness_probe.yaml,cveX38_halo2_profile_k_readiness_probe.yaml,cveX39_scroll_modgadget_underconstrained_mulmod.yaml,cveX40_scroll_create_static_context_escape.yaml,cveX41_scroll_rlpu64_lt128_underconstrained.yaml"
ZKEVM_REQUIRED_OPENZEPPELIN_REL="contracts/vendor/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol"
MONITOR_INTERVAL_SECS=5

: "${TARGET_NAME:?TARGET_NAME must be provided by the standardized profile wrapper}"
: "${JOBS:?JOBS must be set by the standardized profile wrapper}"
: "${WORKERS:?WORKERS must be set by the standardized profile wrapper}"
: "${ITERATIONS:?ITERATIONS must be set by the standardized profile wrapper}"
: "${TIMEOUT_SECS:?TIMEOUT_SECS must be set by the standardized profile wrapper}"
: "${STAGE_DETECTION_TIMEOUT_SECS:?STAGE_DETECTION_TIMEOUT_SECS must be set by the standardized profile wrapper}"
: "${STAGE_PROOF_TIMEOUT_SECS:?STAGE_PROOF_TIMEOUT_SECS must be set by the standardized profile wrapper}"
: "${STUCK_STEP_WARN_SECS:?STUCK_STEP_WARN_SECS must be set by the standardized profile wrapper}"
: "${ZKF_SCAN_OUTPUT_ROOT:?ZKF_SCAN_OUTPUT_ROOT must be set in .env}"
: "${ZKF_RUN_SIGNAL_DIR:?ZKF_RUN_SIGNAL_DIR must be set in .env}"
: "${ZKF_BUILD_CACHE_DIR:?ZKF_BUILD_CACHE_DIR must be set in .env}"
: "${ZKF_SHARED_BUILD_CACHE_DIR:?ZKF_SHARED_BUILD_CACHE_DIR must be set in .env}"

if [[ ! -f "$MATRIX_PATH" ]]; then
  echo "Matrix not found: $MATRIX_PATH" >&2
  exit 1
fi
if [[ ! -f "$REGISTRY_PATH" ]]; then
  echo "Registry not found: $REGISTRY_PATH" >&2
  exit 1
fi

TARGET_ROW="$(
  awk -v wanted="$TARGET_NAME" '
    function flush() {
      if (!in_target) return;
      if (name == wanted) {
        printf("%s\t%s\t%s\t%s\t%s\t%s\n", name, target_circuit, main_component, framework, alias, enabled);
        found = 1;
        exit;
      }
    }

    /^  - name: / {
      flush();
      in_target = 1;
      name = $3;
      target_circuit = "";
      main_component = "main";
      framework = "circom";
      alias = "always";
      enabled = "true";
      next;
    }

    in_target && /^    target_circuit: / { sub(/^    target_circuit: /, "", $0); target_circuit = $0; next; }
    in_target && /^    main_component: / { sub(/^    main_component: /, "", $0); main_component = $0; next; }
    in_target && /^    framework: / { sub(/^    framework: /, "", $0); framework = $0; next; }
    in_target && /^    alias: / { sub(/^    alias: /, "", $0); alias = $0; next; }
    in_target && /^    enabled: / { sub(/^    enabled: /, "", $0); enabled = $0; next; }

    END { flush(); }
  ' "$MATRIX_PATH"
)"

if [[ -z "$TARGET_ROW" ]]; then
  echo "Target '$TARGET_NAME' not found in matrix: $MATRIX_PATH" >&2
  exit 1
fi

IFS=$'\t' read -r RESOLVED_NAME TARGET_CIRCUIT MAIN_COMPONENT FRAMEWORK ALIAS ENABLED <<< "$TARGET_ROW"

if [[ "$ENABLED" != "true" ]]; then
  echo "Target '$TARGET_NAME' is disabled in matrix (enabled=$ENABLED)." >&2
  exit 1
fi

EFFECTIVE_DETECTION_TIMEOUT_SECS="$STAGE_DETECTION_TIMEOUT_SECS"
EFFECTIVE_PROOF_TIMEOUT_SECS="$STAGE_PROOF_TIMEOUT_SECS"
if (( EFFECTIVE_DETECTION_TIMEOUT_SECS > TIMEOUT_SECS )); then
  EFFECTIVE_DETECTION_TIMEOUT_SECS="$TIMEOUT_SECS"
fi
if (( EFFECTIVE_PROOF_TIMEOUT_SECS > TIMEOUT_SECS )); then
  EFFECTIVE_PROOF_TIMEOUT_SECS="$TIMEOUT_SECS"
fi

TARGET_OUTPUT_ROOT="$ZKF_SCAN_OUTPUT_ROOT"
TARGET_LOG_DIR="$TARGET_OUTPUT_ROOT/logs"
RUN_SIGNAL_DIR="$ZKF_RUN_SIGNAL_DIR"
BUILD_CACHE_DIR="$ZKF_BUILD_CACHE_DIR"
CARGO_TARGET_DIR_FIXED="$TARGET_OUTPUT_ROOT/cargo_target"

mkdir -p "$TARGET_LOG_DIR" "$RUN_SIGNAL_DIR" "$BUILD_CACHE_DIR" "$CARGO_TARGET_DIR_FIXED"

TIMESTAMP="$(date -u +"%Y%m%d_%H%M%S")"
RUN_LOG="$TARGET_LOG_DIR/run_${TIMESTAMP}.log"

SELECTOR_ARGS=()
SELECTOR_PROFILE=""
IS_ZKEVM_TARGET=0
if [[ "$RESOLVED_NAME" == *zkevm* || "$TARGET_CIRCUIT" == *zkevm-circuits* ]]; then
  IS_ZKEVM_TARGET=1
fi

FRAMEWORK_LC="$(printf '%s' "$FRAMEWORK" | tr '[:upper:]' '[:lower:]')"
case "$FRAMEWORK_LC" in
  halo2)
    if [[ "$IS_ZKEVM_TARGET" -eq 1 ]]; then
      SELECTOR_PROFILE="zkevm_deep_templates"
      SELECTOR_ARGS=(--template "$ZKEVM_TEMPLATE_CSV")
    else
      SELECTOR_PROFILE="halo2_readiness_alias"
      SELECTOR_ARGS=(--alias "readiness_halo2")
    fi
    ;;
  circom)
    SELECTOR_PROFILE="circom_readiness_alias"
    SELECTOR_ARGS=(--alias "readiness_circom")
    ;;
  noir)
    SELECTOR_PROFILE="noir_readiness_alias"
    SELECTOR_ARGS=(--alias "readiness_noir")
    ;;
  cairo)
    SELECTOR_PROFILE="cairo_readiness_alias"
    SELECTOR_ARGS=(--alias "readiness_cairo")
    ;;
  *)
    echo "Unsupported framework for standardized selector profile: $FRAMEWORK" >&2
    exit 1
    ;;
esac

ensure_zkevm_dependency_readiness() {
  if [[ "$IS_ZKEVM_TARGET" -ne 1 ]]; then
    echo "[STEP] zkevm_dependency_preflight skipped reason=non_zkevm_target"
    return
  fi

  echo "[STEP] zkevm_dependency_preflight started"

  local manifest_dir
  if [[ -f "$TARGET_CIRCUIT" ]]; then
    manifest_dir="$(dirname "$TARGET_CIRCUIT")"
  else
    manifest_dir="$TARGET_CIRCUIT"
  fi

  local oz_required_file="$manifest_dir/$ZKEVM_REQUIRED_OPENZEPPELIN_REL"
  if [[ ! -f "$oz_required_file" ]]; then
    local zkevm_repo_root
    zkevm_repo_root="$(cd "$manifest_dir/.." && pwd)"
    echo "[STEP] zkevm_dependency_preflight repair=git_submodule_update path=$zkevm_repo_root"
    (
      cd "$zkevm_repo_root"
      git submodule update --init --recursive integration-tests/contracts/vendor/openzeppelin-contracts
    )
  fi

  if [[ ! -f "$oz_required_file" ]]; then
    echo "zkevm dependency missing after repair attempt: $oz_required_file" >&2
    echo "Cannot proceed with deep fuzz because Halo2 introspection would run at 0 constraints." >&2
    exit 1
  fi

  echo "[STEP] zkevm_dependency_preflight completed"
}

output_lock_preflight() {
  local lock_path="$TARGET_OUTPUT_ROOT/.zkfuzz.lock"
  echo "[STEP] output_lock_preflight started"
  if [[ ! -f "$lock_path" ]]; then
    echo "[STEP] output_lock_preflight completed status=absent"
    return
  fi

  local lock_pid
  lock_pid="$(sed -n 's/^pid=\([0-9][0-9]*\).*/\1/p' "$lock_path" | head -n 1 || true)"
  if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
    echo "[STEP] output_lock_preflight failed status=active_lock pid=$lock_pid lock_path=$lock_path" >&2
    echo "Refusing to run while another scan owns output lock. Stop that scan first." >&2
    exit 1
  fi

  rm -f "$lock_path"
  echo "[STEP] output_lock_preflight completed status=stale_removed lock_path=$lock_path"
}

HALO2_USE_HOST_CARGO_HOME_VALUE=0
HALO2_STRICT_READINESS_VALUE=0
if [[ "$FRAMEWORK_LC" == "halo2" ]]; then
  HALO2_USE_HOST_CARGO_HOME_VALUE=1
fi
if [[ "$IS_ZKEVM_TARGET" -eq 1 ]]; then
  HALO2_STRICT_READINESS_VALUE=1
fi

CMD=(
  cargo run --release --bin zkpatternfuzz --
  --registry "$REGISTRY_PATH"
  --framework "$FRAMEWORK"
  --target-circuit "$TARGET_CIRCUIT"
  --main-component "$MAIN_COMPONENT"
  --jobs "$JOBS"
  --workers "$WORKERS"
  --iterations "$ITERATIONS"
  --timeout "$TIMEOUT_SECS"
  --emit-reason-tsv
  "${SELECTOR_ARGS[@]}"
)

start_monitor() {
  (
    local previous=""
    while true; do
      if [[ -f "$RUN_SIGNAL_DIR/latest.json" ]]; then
        local snapshot
        snapshot="$(jq -r '[.run_id // "-", .status // "-", .stage // "-", .reason_code // "-", (.terminal // false)] | @tsv' "$RUN_SIGNAL_DIR/latest.json" 2>/dev/null || true)"
        if [[ -n "$snapshot" && "$snapshot" != "$previous" ]]; then
          IFS=$'\t' read -r run_id status stage reason_code terminal <<< "$snapshot"
          echo "[MONITOR] run_id=$run_id status=$status stage=$stage reason=$reason_code terminal=$terminal"
          previous="$snapshot"
        fi
      fi
      sleep "$MONITOR_INTERVAL_SECS"
    done
  ) &
  MONITOR_PID="$!"
}

stop_monitor() {
  if [[ -n "${MONITOR_PID:-}" ]] && kill -0 "$MONITOR_PID" 2>/dev/null; then
    kill "$MONITOR_PID" 2>/dev/null || true
    wait "$MONITOR_PID" 2>/dev/null || true
  fi
}

trap stop_monitor EXIT INT TERM

echo "=== Fixed Target Deep Fuzz ==="
echo "target_name:      $RESOLVED_NAME"
echo "target_circuit:   $TARGET_CIRCUIT"
echo "framework:        $FRAMEWORK"
echo "main_component:   $MAIN_COMPONENT"
echo "selector_profile: $SELECTOR_PROFILE"
echo "selector_mode:    ${SELECTOR_ARGS[*]}"
echo "halo2_host_cargo: $HALO2_USE_HOST_CARGO_HOME_VALUE"
echo "halo2_strict:     $HALO2_STRICT_READINESS_VALUE"
echo "timeout_secs:     $TIMEOUT_SECS"
echo "detection_timeout:$EFFECTIVE_DETECTION_TIMEOUT_SECS"
echo "proof_timeout:    $EFFECTIVE_PROOF_TIMEOUT_SECS"
echo "output_root:      $TARGET_OUTPUT_ROOT"
echo "run_log:          $RUN_LOG"
echo "[STEP] target_resolved"
echo "[STEP] selector_profile_resolved profile=$SELECTOR_PROFILE"
ensure_zkevm_dependency_readiness
output_lock_preflight
echo "[STEP] monitoring_started interval=${MONITOR_INTERVAL_SECS}s"

start_monitor

echo "[STEP] execute_fuzz"
(
  cd "$ROOT_DIR"
  CARGO_TARGET_DIR="$CARGO_TARGET_DIR_FIXED" \
  ZKF_ZKPATTERNFUZZ_DETECTION_STAGE_TIMEOUT_SECS="$EFFECTIVE_DETECTION_TIMEOUT_SECS" \
  ZKF_ZKPATTERNFUZZ_PROOF_STAGE_TIMEOUT_SECS="$EFFECTIVE_PROOF_TIMEOUT_SECS" \
  ZKF_ZKPATTERNFUZZ_STUCK_STEP_WARN_SECS="$STUCK_STEP_WARN_SECS" \
  ZKF_SCAN_OUTPUT_ROOT="$TARGET_OUTPUT_ROOT" \
  ZKF_RUN_SIGNAL_DIR="$RUN_SIGNAL_DIR" \
  ZKF_BUILD_CACHE_DIR="$BUILD_CACHE_DIR" \
  ZKF_SHARED_BUILD_CACHE_DIR="$ZKF_SHARED_BUILD_CACHE_DIR" \
  ZK_FUZZER_HALO2_USE_HOST_CARGO_HOME="$HALO2_USE_HOST_CARGO_HOME_VALUE" \
  ZKFUZZ_HALO2_STRICT_READINESS="$HALO2_STRICT_READINESS_VALUE" \
  "${CMD[@]}" 2>&1 | tee "$RUN_LOG"
)
