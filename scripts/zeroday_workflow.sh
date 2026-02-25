#!/usr/bin/env bash
# =============================================================================
# ZkPatternFuzz 0-Day Discovery Workflow
# =============================================================================
# This script orchestrates the complete workflow for finding 0-day vulnerabilities
# in ZK circuits following the AI_PENTEST_RULES.md guidelines.
#
# Phases:
#   1. SKIM    - Rapid heuristic scan (hints only)
#   2. ANALYZE - Manual invariant analysis (human step)
#   3. EVIDENCE - Bounded deterministic fuzzing with invariants
#   4. VERIFY  - Formal verification with Picus (optional)
#   5. TRIAGE  - Review findings and confirm/reject
#   6. DEEP    - Targeted edge-case fuzzing
#
# Usage:
#   ./scripts/zeroday_workflow.sh skim    <repo_path>
#   ./scripts/zeroday_workflow.sh evidence <campaign.yaml> [--iterations N] [--timeout S]
#   ./scripts/zeroday_workflow.sh verify  <circuit.circom> [--timeout MS]
#   ./scripts/zeroday_workflow.sh deep    <campaign.yaml> [--seed S]
#   ./scripts/zeroday_workflow.sh report  <output_dir>
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REBUILD_SCRIPT="$PROJECT_ROOT/scripts/rebuild_release_binaries.sh"
FUZZER="$PROJECT_ROOT/target/release/zk-fuzzer"
SKIMMER="$PROJECT_ROOT/target/release/zk0d_skimmer"
PICUS_DIR="${PICUS_DIR:-/tmp/Picus}"
PICUS_BIN="${PICUS_BIN:-}"
LOAD_ENV_MASTER_SCRIPT="$PROJECT_ROOT/scripts/load_env_master.sh"

if [[ -f "$LOAD_ENV_MASTER_SCRIPT" ]]; then
    # shellcheck disable=SC1090
    source "$LOAD_ENV_MASTER_SCRIPT"
    load_env_master "$PROJECT_ROOT"
fi

# Default values
DEFAULT_ITERATIONS=50000
DEFAULT_TIMEOUT=1800
DEFAULT_SEED=42
DEFAULT_WORKERS=$(nproc 2>/dev/null || echo 4)
DEFAULT_PICUS_TIMEOUT=60000  # 60 seconds for Picus SMT solver

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

load_prefetch_env_hints() {
    local candidates=()
    local env_file=""

    if [[ -n "${ZKFUZZ_PREFETCH_ENV_HINTS_FILE:-}" ]]; then
        candidates+=("$ZKFUZZ_PREFETCH_ENV_HINTS_FILE")
    fi
    candidates+=("$PROJECT_ROOT/build/toolchains/prefetch.env")

    for candidate in "${candidates[@]}"; do
        if [[ -f "$candidate" ]]; then
            env_file="$candidate"
            break
        fi
    done

    if [[ -z "$env_file" ]]; then
        return 0
    fi

    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
    # Cache-first defaults when prefetch hints are available.
    if [[ -z "${ZKF_ENSURE_BUILD_NO_CLEAN:-}" ]]; then
        export ZKF_ENSURE_BUILD_NO_CLEAN=1
    fi
    log_info "Loaded local toolchain cache hints: $env_file"
}

prepare_runtime_environment() {
    local requested_dir="${ZKF_RUN_SIGNAL_DIR:-$PROJECT_ROOT/artifacts/run_signals}"
    local fallback_dir="$PROJECT_ROOT/artifacts/run_signals"

    if mkdir -p "$requested_dir" 2>/dev/null; then
        export ZKF_RUN_SIGNAL_DIR="$requested_dir"
        return 0
    fi

    mkdir -p "$fallback_dir"
    export ZKF_RUN_SIGNAL_DIR="$fallback_dir"
    log_warn "Run-signal directory '$requested_dir' is not writable. Using '$fallback_dir' instead."
}

resolve_picus_bin() {
    # Priority:
    # 1) Explicit PICUS_BIN
    # 2) PICUS_DIR/run-picus
    # 3) run-picus on PATH
    # 4) picus on PATH (wrapper style install)
    if [[ -n "${PICUS_BIN:-}" && -x "${PICUS_BIN:-}" ]]; then
        printf '%s\n' "$PICUS_BIN"
        return 0
    fi

    if [[ -n "${PICUS_DIR:-}" && -x "${PICUS_DIR:-}/run-picus" ]]; then
        printf '%s\n' "${PICUS_DIR}/run-picus"
        return 0
    fi

    if command -v run-picus >/dev/null 2>&1; then
        command -v run-picus
        return 0
    fi

    if command -v picus >/dev/null 2>&1; then
        command -v picus
        return 0
    fi

    return 1
}

# Ensure release build exists and is fresh for current source state.
ensure_build() {
    if [[ ! -x "$REBUILD_SCRIPT" ]]; then
        log_error "Rebuild script not found or not executable: $REBUILD_SCRIPT"
        exit 1
    fi

    log_info "Checking release binaries freshness..."
    local rebuild_args=(
        --project-root "$PROJECT_ROOT"
        --if-changed
        --bin zk-fuzzer
        --bin zk0d_skimmer
    )
    if [[ "${ZKF_ENSURE_BUILD_NO_CLEAN:-0}" == "1" ]]; then
        rebuild_args+=(--no-clean)
    fi
    if [[ "${ZKF_ENSURE_BUILD_OFFLINE:-0}" == "1" ]]; then
        rebuild_args+=(--offline)
    fi

    "$REBUILD_SCRIPT" "${rebuild_args[@]}"

    if [[ ! -x "$FUZZER" || ! -x "$SKIMMER" ]]; then
        log_error "Required release binaries missing after rebuild: $FUZZER / $SKIMMER"
        exit 1
    fi
}

# Phase 1: SKIM
phase_skim() {
    local repo_path="$1"
    local output_dir="${2:-reports/zk0d/skimmer}"
    local config_dir="${3:-$output_dir/generated_configs}"
    local save_configs="${ZKF_SKIM_SAVE_CONFIGS:-true}"
    local config_write_mode="${ZKF_SKIM_CONFIG_WRITE_MODE:-add-only}"
    
    log_info "=== PHASE 1: SKIM (Hints Only) ==="
    log_info "Target: $repo_path"
    log_warn "This phase produces HINTS, not confirmed findings."
    
    ensure_build
    
    if [[ ! -d "$repo_path/.git" ]]; then
        log_error "Repository must contain .git directory: $repo_path"
        exit 1
    fi
    
    "$SKIMMER" \
        --root "$repo_path" \
        --max-files 1200 \
        --min-confidence 0.15 \
        --top 40 \
        --output-dir "$output_dir" \
        --config-dir "$config_dir" \
        --save-configs "$save_configs" \
        --config-write-mode "$config_write_mode"
    
    log_success "Skimmer complete!"
    echo ""
    log_info "Next steps:"
    echo "  1. Review: $output_dir/skimmer_summary.md"
    echo "  2. Fill invariants: $output_dir/candidate_invariants.yaml"
    echo "  3. Run evidence mode: ./scripts/zeroday_workflow.sh evidence <campaign.yaml>"
}

# Phase 2: Validate campaign before evidence run
validate_campaign() {
    local campaign="$1"
    
    log_info "Validating campaign: $campaign"
    
    if [[ ! -f "$campaign" ]]; then
        log_error "Campaign file not found: $campaign"
        exit 1
    fi
    
    "$FUZZER" validate "$campaign"
    
    # Check for invariants
    if ! grep -q "invariants:" "$campaign"; then
        log_warn "Campaign has no invariants section - evidence mode may not produce confirmed findings"
    else
        local inv_count=$(grep -c "name:" "$campaign" | head -1 || echo "0")
        log_info "Found invariants in campaign"
    fi
}

extract_halo2_manifest_from_campaign() {
    local campaign="$1"
    python3 - "$campaign" <<'PY'
import pathlib
import re
import sys

campaign_path = pathlib.Path(sys.argv[1])
try:
    lines = campaign_path.read_text(encoding="utf-8", errors="ignore").splitlines()
except Exception:
    sys.exit(0)

framework = None
circuit_path = None
main_component = ""

for line in lines:
    if framework is None:
        match = re.match(r"^\s*framework\s*:\s*(.+?)\s*$", line)
        if match:
            value = match.group(1).split("#", 1)[0].strip().strip('"').strip("'")
            if value:
                framework = value
    if circuit_path is None:
        match = re.match(r"^\s*circuit_path\s*:\s*(.+?)\s*$", line)
        if match:
            value = match.group(1).split("#", 1)[0].strip().strip('"').strip("'")
            if value:
                circuit_path = value
    if not main_component:
        match = re.match(r"^\s*main_component\s*:\s*(.+?)\s*$", line)
        if match:
            value = match.group(1).split("#", 1)[0].strip().strip('"').strip("'")
            if value:
                main_component = value
    if framework is not None and circuit_path is not None:
        if main_component:
            break

if (framework or "").lower() != "halo2" or not circuit_path:
    sys.exit(0)

candidate = pathlib.Path(circuit_path).expanduser()
if not candidate.is_absolute():
    candidate = (campaign_path.parent / candidate).resolve()

manifest = candidate / "Cargo.toml" if candidate.is_dir() else candidate
if manifest.is_file() and manifest.name.lower() == "cargo.toml":
    print(f"{manifest.resolve()}\t{circuit_path}\t{main_component}")
PY
}

run_halo2_prewarm_attempt() {
    local manifest="$1"
    local mode="$2"
    local toolchain="$3"
    local timeout_secs="$4"
    local log_file="$5"
    local target_dir="$6"

    local -a cmd=(cargo)
    if [[ -n "$toolchain" ]]; then
        cmd+=("+$toolchain")
    fi
    if [[ "$mode" == "constraints" ]]; then
        cmd+=(run --release --manifest-path "$manifest" -- --constraints)
    else
        cmd+=(build --release --manifest-path "$manifest")
    fi

    {
        echo "[prewarm] mode=$mode toolchain=${toolchain:-default} target_dir=${target_dir:-default} command=${cmd[*]}"
    } >>"$log_file"

    if command -v timeout >/dev/null 2>&1; then
        if [[ -n "$target_dir" ]]; then
            CARGO_TARGET_DIR="$target_dir" timeout --preserve-status "${timeout_secs}s" "${cmd[@]}" >>"$log_file" 2>&1
        else
            timeout --preserve-status "${timeout_secs}s" "${cmd[@]}" >>"$log_file" 2>&1
        fi
    else
        if [[ -n "$target_dir" ]]; then
            CARGO_TARGET_DIR="$target_dir" "${cmd[@]}" >>"$log_file" 2>&1
        else
            "${cmd[@]}" >>"$log_file" 2>&1
        fi
    fi
}

apply_halo2_runtime_toolchain() {
    local toolchain="$1"
    toolchain="${toolchain//[$'\t\r\n ']}"
    if [[ -z "$toolchain" || "$toolchain" == "default" ]]; then
        return 0
    fi

    export ZK_FUZZER_HALO2_CARGO_TOOLCHAIN="$toolchain"

    local -a merged=("$toolchain")
    local -a current=()
    IFS=',' read -r -a current <<< "${ZK_FUZZER_HALO2_CARGO_TOOLCHAIN_CANDIDATES:-}"
    for candidate in "${current[@]}"; do
        candidate="${candidate//[$'\t\r\n ']}"
        [[ -z "$candidate" ]] && continue
        local duplicate=false
        for existing in "${merged[@]}"; do
            if [[ "$existing" == "$candidate" ]]; then
                duplicate=true
                break
            fi
        done
        $duplicate && continue
        merged+=("$candidate")
    done

    local IFS=,
    export ZK_FUZZER_HALO2_CARGO_TOOLCHAIN_CANDIDATES="${merged[*]}"
    log_info "Pinned Halo2 cargo toolchain for this run: $toolchain"
}

prewarm_halo2_campaign_target() {
    local campaign="$1"
    local mode="${ZKF_HALO2_PREWARM_MODE:-constraints}"
    local mode_lc="${mode,,}"
    case "$mode_lc" in
        0|off|false|no)
            return 0
            ;;
        constraints|build)
            ;;
        *)
            log_warn "Unknown ZKF_HALO2_PREWARM_MODE='$mode'; defaulting to 'constraints'"
            mode_lc="constraints"
            ;;
    esac

    local context
    context="$(extract_halo2_manifest_from_campaign "$campaign" || true)"
    local manifest
    local circuit_path_raw
    local main_component
    IFS=$'\t' read -r manifest circuit_path_raw main_component <<< "$context"
    if [[ -z "$manifest" ]]; then
        return 0
    fi

    local prewarm_log_dir="${ZKF_HALO2_PREWARM_LOG_DIR:-$PROJECT_ROOT/artifacts/external_targets/prewarm_logs}"
    local prewarm_marker_dir="${ZKF_HALO2_PREWARM_MARKER_DIR:-$PROJECT_ROOT/build/toolchains/prewarm_markers}"
    local prewarm_timeout_secs="${ZKF_HALO2_PREWARM_TIMEOUT_SECS:-1800}"
    mkdir -p "$prewarm_log_dir" "$prewarm_marker_dir"

    local shared_target_dir=""
    if [[ -n "${ZKF_BUILD_CACHE_DIR:-}" ]]; then
        shared_target_dir="$(python3 - "$circuit_path_raw" "$main_component" "$ZKF_BUILD_CACHE_DIR" <<'PY'
import hashlib
import pathlib
import sys

circuit_path = sys.argv[1]
main_component = sys.argv[2]
base_dir = pathlib.Path(sys.argv[3])

path_obj = pathlib.Path(circuit_path)
if path_obj.is_dir():
    name = path_obj.name or "circuit"
else:
    name = (path_obj.stem or path_obj.name or "circuit")

combined = name
if main_component and main_component not in combined:
    combined = f"{combined}_{main_component}"

digest = hashlib.sha256(f"{circuit_path}|{main_component}".encode("utf-8")).hexdigest()[:12]
raw = f"{combined}__{digest}"
sanitized = "".join(ch if (ch.isalnum() or ch in "-_") else "_" for ch in raw)
if not sanitized:
    sanitized = "circuit"

print((base_dir / "halo2" / sanitized).as_posix())
PY
)"
        if [[ -n "$shared_target_dir" ]]; then
            mkdir -p "$shared_target_dir"
        fi
    fi

    local manifest_hash=""
    manifest_hash="$(sha256sum "$manifest" 2>/dev/null | awk '{print $1}' || true)"
    local lock_path
    lock_path="$(dirname "$manifest")/Cargo.lock"
    if [[ -f "$lock_path" ]]; then
        local lock_hash=""
        lock_hash="$(sha256sum "$lock_path" 2>/dev/null | awk '{print $1}' || true)"
        if [[ -n "$lock_hash" ]]; then
            manifest_hash="${manifest_hash}_${lock_hash}"
        fi
    fi
    if [[ -z "$manifest_hash" ]]; then
        manifest_hash="$(date -u +%s)"
    fi
    if [[ -n "$shared_target_dir" ]]; then
        local target_hash=""
        target_hash="$(printf '%s' "$shared_target_dir" | sha256sum 2>/dev/null | awk '{print $1}' || true)"
        if [[ -n "$target_hash" ]]; then
            manifest_hash="${manifest_hash}_${target_hash}"
        fi
    fi

    local marker_key_input="${manifest}|${mode_lc}|${manifest_hash}"
    local marker_key=""
    marker_key="$(printf '%s' "$marker_key_input" | sha256sum 2>/dev/null | awk '{print substr($1,1,24)}' || true)"
    if [[ -z "$marker_key" ]]; then
        marker_key="$(date -u +%s)"
    fi
    local marker_path="$prewarm_marker_dir/halo2_${mode_lc}_${marker_key}.ok"
    if [[ -f "$marker_path" ]]; then
        local cached_toolchain=""
        cached_toolchain="$(sed -n 's/.*toolchain=\([^ ]*\).*/\1/p' "$marker_path" | tail -n 1 || true)"
        apply_halo2_runtime_toolchain "$cached_toolchain"
        log_info "Halo2 prewarm cache hit: $manifest"
        return 0
    fi

    local timestamp
    timestamp="$(date -u +%Y%m%d_%H%M%S)"
    local base_label
    base_label="$(basename "$(dirname "$manifest")")"
    local prewarm_log="$prewarm_log_dir/halo2_prewarm_${base_label}_${timestamp}.log"

    local toolchain_candidates=()
    local -a env_toolchains=()
    IFS=',' read -r -a env_toolchains <<< "${ZK_FUZZER_HALO2_CARGO_TOOLCHAIN_CANDIDATES:-}"
    for tc in "${env_toolchains[@]}" "nightly" "nightly-2024-07-07" "stable" ""; do
        tc="${tc//[$'\t\r\n ']}"
        local duplicate=false
        for existing in "${toolchain_candidates[@]:-}"; do
            if [[ "$existing" == "$tc" ]]; then
                duplicate=true
                break
            fi
        done
        $duplicate && continue
        toolchain_candidates+=("$tc")
    done

    local rc=1
    local selected_toolchain=""
    if [[ "$mode_lc" == "constraints" ]]; then
        log_info "Prewarming Halo2 target (constraints): $manifest"
        : >"$prewarm_log"
        for tc in "${toolchain_candidates[@]}"; do
            if run_halo2_prewarm_attempt "$manifest" "constraints" "$tc" "$prewarm_timeout_secs" "$prewarm_log" "$shared_target_dir"; then
                rc=0
                selected_toolchain="$tc"
                break
            fi
            rc=$?
        done

        if [[ $rc -ne 0 ]]; then
            local fallback_log="${prewarm_log%.log}_build_fallback.log"
            log_warn "Halo2 constraints prewarm failed; retrying cargo build (see $prewarm_log)"
            : >"$fallback_log"
            rc=1
            for tc in "${toolchain_candidates[@]}"; do
                if run_halo2_prewarm_attempt "$manifest" "build" "$tc" "$prewarm_timeout_secs" "$fallback_log" "$shared_target_dir"; then
                    rc=0
                    selected_toolchain="$tc"
                    break
                fi
                rc=$?
            done
            if [[ $rc -eq 0 ]]; then
                printf '%s mode=build_fallback manifest=%s toolchain=%s\n' \
                    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$manifest" "${selected_toolchain:-default}" > "$marker_path"
                apply_halo2_runtime_toolchain "$selected_toolchain"
                log_info "Halo2 prewarm fallback complete: $manifest"
                return 0
            fi
            log_warn "Halo2 prewarm fallback failed (exit $rc); continuing (see $fallback_log)"
            return 0
        fi
    else
        log_info "Prewarming Halo2 target (build): $manifest"
        : >"$prewarm_log"
        for tc in "${toolchain_candidates[@]}"; do
            if run_halo2_prewarm_attempt "$manifest" "build" "$tc" "$prewarm_timeout_secs" "$prewarm_log" "$shared_target_dir"; then
                rc=0
                selected_toolchain="$tc"
                break
            fi
            rc=$?
        done
        if [[ $rc -ne 0 ]]; then
            log_warn "Halo2 build prewarm failed (exit $rc); continuing (see $prewarm_log)"
            return 0
        fi
    fi

    printf '%s mode=%s manifest=%s toolchain=%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$mode_lc" "$manifest" "${selected_toolchain:-default}" > "$marker_path"
    apply_halo2_runtime_toolchain "$selected_toolchain"
    log_info "Halo2 prewarm complete: $manifest"
}

# Generic strict correction without mutating the original campaign YAML.
# Adds required strict attacks only; if correction is not applicable, returns original path.
prepare_evidence_campaign() {
    local campaign="$1"
    local apply_generic="${ZKF_EVIDENCE_GENERIC_CORRECT:-true}"
    if [[ "$apply_generic" != "true" ]]; then
        echo "$campaign"
        return 0
    fi

    local stage_dir="${ZKF_CAMPAIGN_STAGE_DIR:-/tmp/zkfuzz_campaign_stage}"
    mkdir -p "$stage_dir"
    local stamp
    stamp="$(date -u +%Y%m%d_%H%M%S)"
    local base
    base="$(basename "$campaign")"
    local stem="${base%.yaml}"
    if [[ "$stem" == "$base" ]]; then
        stem="${base%.yml}"
    fi
    local staged="$stage_dir/${stem}.strict_${stamp}.yaml"

    local py_out
    set +e
    py_out="$(python3 - "$campaign" "$staged" <<'PY'
import sys
from pathlib import Path

try:
    import yaml
except Exception as exc:
    print(f"SKIP_NOT_APPLICABLE:missing_yaml_dependency:{exc}")
    sys.exit(30)

src = Path(sys.argv[1])
dst = Path(sys.argv[2])

try:
    data = yaml.safe_load(src.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"SKIP_NOT_APPLICABLE:parse_error:{exc}")
    sys.exit(30)

if not isinstance(data, dict):
    print("SKIP_NOT_APPLICABLE:root_not_mapping")
    sys.exit(30)

attacks = data.get("attacks")
if not isinstance(attacks, list):
    print("SKIP_NOT_APPLICABLE:attacks_missing_or_not_list")
    sys.exit(30)

required = [
    ("underconstrained", "Detect unconstrained witness behavior"),
    ("soundness", "Strict soundness checks"),
    ("constraint_inference", "Infer potentially missing constraints"),
    ("metamorphic", "Metamorphic consistency checks"),
    ("constraint_slice", "Constraint slice checks"),
    ("spec_inference", "Spec inference checks"),
    ("witness_collision", "Witness collision checks"),
    ("boundary", "Boundary mutation checks"),
]

existing = set()
for item in attacks:
    if isinstance(item, dict):
        attack_type = item.get("type")
        if isinstance(attack_type, str) and attack_type.strip():
            existing.add(attack_type.strip().lower())

missing = [(attack_type, desc) for attack_type, desc in required if attack_type not in existing]
if not missing:
    print("UNCHANGED")
    sys.exit(20)

# Additive-only correction: append missing strict attacks, preserve all existing fields.
for attack_type, desc in missing:
    attacks.append(
        {
            "type": attack_type,
            "description": f"Generic strict fallback: {desc}",
        }
    )

dst.parent.mkdir(parents=True, exist_ok=True)
dst.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
print("CORRECTED:" + ",".join(attack_type for attack_type, _ in missing))
sys.exit(0)
PY
)"
    local rc=$?
    set -e

    if [[ $rc -eq 0 ]]; then
        log_info "Generic campaign correction applied: ${py_out}. Using staged campaign: ${staged}" >&2
        echo "$staged"
        return 0
    fi
    if [[ $rc -eq 20 ]]; then
        echo "$campaign"
        return 0
    fi
    if [[ $rc -eq 30 ]]; then
        log_warn "Generic campaign correction skipped (not applicable): ${py_out}. Preserving original campaign to avoid precision loss." >&2
        echo "$campaign"
        return 0
    fi

    log_warn "Generic campaign correction failed (${py_out}); preserving original campaign to avoid destabilizing YAML." >&2
    echo "$campaign"
    return 0
}

# Phase 3: EVIDENCE
phase_evidence() {
    local campaign="$1"
    shift
    
    local iterations=$DEFAULT_ITERATIONS
    local timeout=$DEFAULT_TIMEOUT
    local seed=$DEFAULT_SEED
    local workers=$DEFAULT_WORKERS
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --iterations|-i)
                iterations="$2"
                shift 2
                ;;
            --timeout|-t)
                timeout="$2"
                shift 2
                ;;
            --seed|-s)
                seed="$2"
                shift 2
                ;;
            --workers|-w)
                workers="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    log_info "=== PHASE 3: EVIDENCE (Deterministic Fuzzing) ==="
    local prepared_campaign
    prepared_campaign="$(prepare_evidence_campaign "$campaign")"
    log_info "Campaign: $campaign"
    if [[ "$prepared_campaign" != "$campaign" ]]; then
        log_info "Using staged corrected campaign: $prepared_campaign"
    fi
    log_info "Iterations: $iterations"
    log_info "Timeout: ${timeout}s"
    log_info "Seed: $seed"
    log_info "Workers: $workers"
    
    ensure_build
    prepare_runtime_environment
    validate_campaign "$prepared_campaign"
    prewarm_halo2_campaign_target "$prepared_campaign"
    
    log_info "Starting evidence run..."
    
    "$FUZZER" evidence "$prepared_campaign" \
        --seed "$seed" \
        --iterations "$iterations" \
        --timeout "$timeout" \
        --workers "$workers" \
        --simple-progress
    
    log_success "Evidence run complete!"
    echo ""
    log_info "Next steps:"
    echo "  1. Review findings in reports directory"
    echo "  2. For each finding, verify reproduction"
    echo "  3. If needed, run deep fuzz: ./scripts/zeroday_workflow.sh deep <campaign.yaml>"
}

# Phase 4: VERIFY (Formal Verification with Picus)
phase_verify() {
    local circuit="$1"
    shift
    
    local timeout=$DEFAULT_PICUS_TIMEOUT
    local output_json=""
    local solver="cvc5"
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --timeout|-t)
                timeout="$2"
                shift 2
                ;;
            --output|-o)
                output_json="$2"
                shift 2
                ;;
            --solver)
                solver="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    log_info "=== PHASE 4: VERIFY (Formal Verification with Picus) ==="
    log_info "Circuit: $circuit"
    log_info "Solver timeout: ${timeout}ms"
    log_info "Solver: $solver"
    
    if [[ ! -f "$circuit" ]]; then
        log_error "Circuit file not found: $circuit"
        exit 1
    fi
    
    local picus_bin=""
    if ! picus_bin="$(resolve_picus_bin)"; then
        log_error "Picus not found via PICUS_BIN, PICUS_DIR/run-picus, run-picus PATH, or picus PATH"
        log_error "Set PICUS_BIN explicitly or PICUS_DIR to your Picus installation"
        log_error "See: VERIDISE_INTEGRATION.md"
        exit 1
    fi

    log_info "Using Picus binary: $picus_bin"
    log_info "Running Picus formal verification..."
    
    local picus_args=(--timeout "$timeout" --solver "$solver")
    
    if [[ -n "$output_json" ]]; then
        picus_args+=(--json "$output_json")
    fi
    
    local picus_tmp
    picus_tmp="$(mktemp)"
    set +e
    "$picus_bin" "${picus_args[@]}" "$circuit" 2>&1 | tee "$picus_tmp"
    local result=${PIPESTATUS[0]}
    set -e
    local picus_output
    picus_output="$(cat "$picus_tmp")"
    rm -f "$picus_tmp"

    # Some Picus builds print an inconclusive message while returning 0.
    # Treat this as UNKNOWN to avoid misclassifying ambiguous proofs as SAFE.
    if [[ "$picus_output" == *"Cannot determine whether the circuit is properly constrained"* ]]; then
        result=10
    fi
    
    echo ""
    case $result in
        0)
            log_success "Picus result: SAFE (no under-constraint found)"
            log_info "If ZkPatternFuzz found issues, they may be false positives."
            ;;
        9)
            log_warn "Picus result: UNSAFE (under-constraint detected!)"
            log_info "This is a FORMALLY CONFIRMED vulnerability (zero false positive)."
            ;;
        10)
            log_warn "Picus result: UNKNOWN (solver timeout or inconclusive)"
            log_info "Consider increasing --timeout or manual review."
            ;;
        *)
            log_error "Picus exited with unexpected code: $result"
            ;;
    esac
    
    echo ""
    log_info "Next steps:"
    echo "  1. Compare with ZkPatternFuzz findings"
    echo "  2. Update finding confidence levels based on Picus result"
    echo "  3. If UNSAFE, extract counterexample for PoC"
}

# Phase 6: DEEP (Edge Case Hunting)
phase_deep() {
    local campaign="$1"
    shift
    
    local iterations=100000
    local timeout=3600
    local seed=1337
    local workers=$DEFAULT_WORKERS
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --iterations|-i)
                iterations="$2"
                shift 2
                ;;
            --timeout|-t)
                timeout="$2"
                shift 2
                ;;
            --seed|-s)
                seed="$2"
                shift 2
                ;;
            --workers|-w)
                workers="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    log_info "=== PHASE 5: DEEP CUSTOM FUZZ (Edge Cases) ==="
    log_info "Campaign: $campaign"
    log_info "Iterations: $iterations"
    log_info "Timeout: ${timeout}s"
    log_info "Seed: $seed"
    
    ensure_build
    prepare_runtime_environment
    validate_campaign "$campaign"
    
    log_info "Starting deep fuzzing run..."
    
    "$FUZZER" evidence "$campaign" \
        --seed "$seed" \
        --iterations "$iterations" \
        --timeout "$timeout" \
        --workers "$workers" \
        --simple-progress
    
    log_success "Deep fuzz complete!"
    echo ""
    log_info "Next steps:"
    echo "  1. Review deep fuzzing findings"
    echo "  2. Consider running Picus verification on new findings"
}

# Generate summary report
phase_report() {
    local output_dir="$1"
    
    log_info "=== GENERATING SUMMARY REPORT ==="
    
    if [[ ! -d "$output_dir" ]]; then
        log_error "Output directory not found: $output_dir"
        exit 1
    fi
    
    local report_file="$output_dir/0day_summary.md"
    
    echo "# 0-Day Discovery Summary" > "$report_file"
    echo "" >> "$report_file"
    echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$report_file"
    echo "" >> "$report_file"
    
    # Count findings
    local json_files=$(find "$output_dir" -name "report.json" 2>/dev/null || true)
    
    if [[ -n "$json_files" ]]; then
        echo "## Findings Overview" >> "$report_file"
        echo "" >> "$report_file"
        for json in $json_files; do
            local dir=$(dirname "$json")
            local name=$(basename "$dir")
            local count=$(grep -c '"severity"' "$json" 2>/dev/null || echo "0")
            echo "- **$name**: $count findings" >> "$report_file"
        done
    else
        echo "No report.json files found in $output_dir" >> "$report_file"
    fi
    
    echo "" >> "$report_file"
    echo "## Classification" >> "$report_file"
    echo "" >> "$report_file"
    echo "| Finding | Status | Evidence |" >> "$report_file"
    echo "|---------|--------|----------|" >> "$report_file"
    echo "| (Review findings and update) | PENDING | |" >> "$report_file"
    
    log_success "Report generated: $report_file"
}

# Show help
show_help() {
    echo "ZkPatternFuzz 0-Day Discovery Workflow"
    echo ""
    echo "Usage:"
    echo "  $0 skim <repo_path> [output_dir] [config_dir]  Phase 1: Rapid heuristic scan"
    echo "  $0 evidence <campaign.yaml> [options]   Phase 3: Bounded evidence run"
    echo "  $0 verify <circuit.circom> [options]    Phase 4: Formal verification (Picus)"
    echo "  $0 deep <campaign.yaml> [options]       Phase 6: Deep edge-case fuzzing"
    echo "  $0 report <output_dir>                  Generate summary report"
    echo ""
    echo "Options for evidence/deep:"
    echo "  --iterations, -i N    Number of fuzzing iterations (default: $DEFAULT_ITERATIONS)"
    echo "  --timeout, -t S       Timeout in seconds (default: $DEFAULT_TIMEOUT)"
    echo "  --seed, -s S          Random seed for reproducibility (default: $DEFAULT_SEED)"
    echo "  --workers, -w W       Number of parallel workers (default: $DEFAULT_WORKERS)"
    echo ""
    echo "Options for verify:"
    echo "  --timeout, -t MS      SMT solver timeout in milliseconds (default: $DEFAULT_PICUS_TIMEOUT)"
    echo "  --output, -o FILE     Output JSON report path (optional)"
    echo "  --solver SOLVER       SMT solver: cvc5 | z3 (default: cvc5)"
    echo ""
    echo "Workflow:"
    echo "  1. skim      - Scan repo for candidate vulnerabilities (hints only)"
    echo "  2. (manual)  - Review hints, write invariants in YAML"
    echo "  3. evidence  - Run fuzzer with invariants, collect PoCs"
    echo "  4. verify    - Formal proof with Picus (OPTIONAL, eliminates false positives)"
    echo "  5. (manual)  - Triage findings, confirm/reject each"
    echo "  6. deep      - Targeted edge-case hunting"
    echo ""
    echo "Environment Variables:"
    echo "  PICUS_BIN    Absolute path to Picus executable (highest priority)"
    echo "  PICUS_DIR    Path to Picus installation (expects PICUS_DIR/run-picus; default: /tmp/Picus)"
    echo ""
    echo "See docs/AI_PENTEST_RULES.md for classification rules."
    echo "See VERIDISE_INTEGRATION.md for Picus installation."
}

# Main entry point
main() {
    if [[ $# -lt 1 ]]; then
        show_help
        exit 1
    fi
    
    local command="$1"
    shift

    load_prefetch_env_hints
    
    case "$command" in
        skim)
            [[ $# -lt 1 ]] && { log_error "Missing repo_path"; show_help; exit 1; }
            phase_skim "$@"
            ;;
        evidence)
            [[ $# -lt 1 ]] && { log_error "Missing campaign.yaml"; show_help; exit 1; }
            phase_evidence "$@"
            ;;
        verify)
            [[ $# -lt 1 ]] && { log_error "Missing circuit.circom"; show_help; exit 1; }
            phase_verify "$@"
            ;;
        deep)
            [[ $# -lt 1 ]] && { log_error "Missing campaign.yaml"; show_help; exit 1; }
            phase_deep "$@"
            ;;
        report)
            [[ $# -lt 1 ]] && { log_error "Missing output_dir"; show_help; exit 1; }
            phase_report "$@"
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
