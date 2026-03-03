#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Only change this variable (or export TARGET_NAME before running the script).
TARGET_NAME="${TARGET_NAME:-ext006_zkevm_circuits_cargo}"

# Fixed, stable paths and behavior.
MATRIX_PATH="${MATRIX_PATH:-$ROOT_DIR/targets/zk0d_matrix_external_manual.yaml}"
REGISTRY_PATH="${REGISTRY_PATH:-$ROOT_DIR/targets/fuzzer_registry.prod.yaml}"
OUTPUT_ROOT="${OUTPUT_ROOT:-}"
STAGE_DETECTION_TIMEOUT_SECS="${STAGE_DETECTION_TIMEOUT_SECS:-5400}"
STAGE_PROOF_TIMEOUT_SECS="${STAGE_PROOF_TIMEOUT_SECS:-10800}"
STUCK_STEP_WARN_SECS="${STUCK_STEP_WARN_SECS:-180}"
JOBS="${JOBS:-1}"
WORKERS="${WORKERS:-4}"
ITERATIONS="${ITERATIONS:-20000}"
TIMEOUT_SECS="${TIMEOUT_SECS:-3600}"
DRY_RUN="${DRY_RUN:-0}"

# Deep zkevm-focused template set (fixed).
ZKEVM_TEMPLATE_CSV="cveX15_scroll_missing_overflow_constraint.yaml,cveX16_scroll_missing_constraint.yaml,cveX35_halo2_signature_readiness_probe.yaml,cveX36_halo2_constraint_metadata_readiness_probe.yaml,cveX37_halo2_plonk_lookup_readiness_probe.yaml,cveX38_halo2_profile_k_readiness_probe.yaml,cveX39_scroll_modgadget_underconstrained_mulmod.yaml,cveX40_scroll_create_static_context_escape.yaml,cveX41_scroll_rlpu64_lt128_underconstrained.yaml"

usage() {
  cat <<'EOF'
Stable target deep-fuzz runner.

Usage:
  scripts/run_fixed_target_deep_fuzz.sh

Configuration:
  Change only TARGET_NAME in this file, or run:
    TARGET_NAME=<matrix_target_name> scripts/run_fixed_target_deep_fuzz.sh

Optional env overrides:
  DRY_RUN=1                     Print commands only.
  OUTPUT_ROOT=/abs/path         Fixed root for all artifacts.
  JOBS=1 WORKERS=4 ITERATIONS=20000 TIMEOUT_SECS=3600
  STAGE_DETECTION_TIMEOUT_SECS=5400 STAGE_PROOF_TIMEOUT_SECS=10800 STUCK_STEP_WARN_SECS=180
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

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

has_runnable_halo2_bin() {
  local manifest_path="$1"
  local bin_name="${2:-}"
  local metadata

  if [[ ! -f "$manifest_path" ]]; then
    return 1
  fi

  metadata="$(cargo metadata --format-version 1 --no-deps --manifest-path "$manifest_path" --offline 2>/dev/null || true)"
  if [[ -z "$metadata" ]]; then
    return 1
  fi

  if [[ -n "$bin_name" ]]; then
    echo "$metadata" | jq -e --arg mp "$manifest_path" --arg bn "$bin_name" '
      .packages[]
      | select(.manifest_path == $mp)
      | .targets[]
      | select((.kind | index("bin")) != null and .name == $bn)
    ' >/dev/null
    return $?
  fi

  echo "$metadata" | jq -e --arg mp "$manifest_path" '
    any(
      .packages[] | select(.manifest_path == $mp) | .targets[]?;
      (.kind | index("bin")) != null
    )
  ' >/dev/null
}

if [[ "$FRAMEWORK" == "halo2" && "$TARGET_CIRCUIT" == *"/zkevm-circuits/zkevm-circuits/Cargo.toml" ]]; then
  if ! has_runnable_halo2_bin "$TARGET_CIRCUIT" "$MAIN_COMPONENT"; then
    ZKEVM_WORKSPACE_ROOT="$(cd "$(dirname "$TARGET_CIRCUIT")/.." && pwd)"
    FALLBACK_MANIFEST="$ZKEVM_WORKSPACE_ROOT/integration-tests/Cargo.toml"
    FALLBACK_BIN="gen_blockchain_data"
    if has_runnable_halo2_bin "$FALLBACK_MANIFEST" "$FALLBACK_BIN"; then
      TARGET_CIRCUIT="$FALLBACK_MANIFEST"
      MAIN_COMPONENT="$FALLBACK_BIN"
    fi
  fi
fi

slug() {
  local s="$1"
  s="${s// /_}"
  s="${s//\//_}"
  s="${s//:/_}"
  s="${s//[^a-zA-Z0-9._-]/_}"
  printf '%s' "$s"
}

TARGET_SLUG="$(slug "$RESOLVED_NAME")"
if [[ -n "$OUTPUT_ROOT" ]]; then
  # Explicit script override: keep per-target isolation under this root.
  TARGET_OUTPUT_ROOT="${OUTPUT_ROOT%/}/$TARGET_SLUG"
elif [[ -n "${ZKF_SCAN_OUTPUT_ROOT:-}" ]]; then
  # Respect caller-provided env root exactly as-is.
  TARGET_OUTPUT_ROOT="$ZKF_SCAN_OUTPUT_ROOT"
else
  TARGET_OUTPUT_ROOT="$ROOT_DIR/artifacts/fixed_target_fuzz/$TARGET_SLUG"
fi
TARGET_LOG_DIR="$TARGET_OUTPUT_ROOT/logs"
RUN_SIGNAL_DIR="$TARGET_OUTPUT_ROOT/run_signals"
BUILD_CACHE_DIR="$TARGET_OUTPUT_ROOT/_build_cache"
CARGO_TARGET_DIR_FIXED="$TARGET_OUTPUT_ROOT/cargo_target"

mkdir -p "$TARGET_LOG_DIR" "$RUN_SIGNAL_DIR" "$BUILD_CACHE_DIR" "$CARGO_TARGET_DIR_FIXED"

TIMESTAMP="$(date -u +"%Y%m%d_%H%M%S")"
RUN_LOG="$TARGET_LOG_DIR/run_${TIMESTAMP}.log"

SELECTOR_ARGS=()
if [[ "$RESOLVED_NAME" == *zkevm* || "$TARGET_CIRCUIT" == *zkevm-circuits* ]]; then
  SELECTOR_ARGS=(--template "$ZKEVM_TEMPLATE_CSV")
else
  SELECTOR_ARGS=(--alias "$ALIAS")
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

if [[ "$DRY_RUN" == "1" ]]; then
  CMD+=(--dry-run)
fi

echo "=== Fixed Target Deep Fuzz ==="
echo "target_name:      $RESOLVED_NAME"
echo "target_circuit:   $TARGET_CIRCUIT"
echo "framework:        $FRAMEWORK"
echo "main_component:   $MAIN_COMPONENT"
echo "selector_mode:    ${SELECTOR_ARGS[*]}"
echo "output_root:      $TARGET_OUTPUT_ROOT"
echo "run_log:          $RUN_LOG"
echo
echo "watch_latest:     jq '{run_id,status,stage,reason_code,terminal}' \"$RUN_SIGNAL_DIR/latest.json\""
echo "tail_run_log:     tail -f \"$RUN_LOG\""
echo

(
  cd "$ROOT_DIR"
  CARGO_TARGET_DIR="$CARGO_TARGET_DIR_FIXED" \
  ZKF_ZKPATTERNFUZZ_DETECTION_STAGE_TIMEOUT_SECS="$STAGE_DETECTION_TIMEOUT_SECS" \
  ZKF_ZKPATTERNFUZZ_PROOF_STAGE_TIMEOUT_SECS="$STAGE_PROOF_TIMEOUT_SECS" \
  ZKF_ZKPATTERNFUZZ_STUCK_STEP_WARN_SECS="$STUCK_STEP_WARN_SECS" \
  ZKF_SCAN_OUTPUT_ROOT="$TARGET_OUTPUT_ROOT" \
  ZKF_RUN_SIGNAL_DIR="$RUN_SIGNAL_DIR" \
  ZKF_BUILD_CACHE_DIR="$BUILD_CACHE_DIR" \
  ZKF_SHARED_BUILD_CACHE_DIR="$BUILD_CACHE_DIR" \
  "${CMD[@]}" 2>&1 | tee "$RUN_LOG"
)
