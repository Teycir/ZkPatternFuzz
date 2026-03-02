#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/rebuild_release_binaries.sh [options]

Options:
  --project-root <path>   Project root (default: parent of this script)
  --force                 Force clean rebuild even if no source change is detected
  --if-changed            Rebuild only when fingerprint changed (default)
  --no-clean              Skip `cargo clean` before rebuild
  --features <list>       Cargo features to pass to release build
  --offline               Use cargo --offline for release build
  --bin <name>            Build only this release binary (can be repeated)
  -h, --help              Show this help

Notes:
  - Default behavior is: full clean rebuild of release binaries whenever tracked
    source/config files changed.
  - Fingerprint includes git HEAD, tracked-source dirty state, and tool versions.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FORCE_REBUILD=0
DO_CLEAN=1
BUILD_FEATURES=""
BUILD_OFFLINE=0
declare -a BIN_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-root)
      PROJECT_ROOT="$2"
      shift 2
      ;;
    --force)
      FORCE_REBUILD=1
      shift
      ;;
    --if-changed)
      shift
      ;;
    --no-clean)
      DO_CLEAN=0
      shift
      ;;
    --features)
      BUILD_FEATURES="$2"
      shift 2
      ;;
    --offline)
      BUILD_OFFLINE=1
      shift
      ;;
    --bin)
      BIN_ARGS+=("$2")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

PROJECT_ROOT="$(cd "$PROJECT_ROOT" && pwd)"
STAMP_DIR="$PROJECT_ROOT/target/release/.zkfuzz"
STAMP_FILE="$STAMP_DIR/release_build_fingerprint.txt"

compute_fingerprint() {
  local git_head="nogit"
  local git_state="nogit-state"
  local rustc_ver
  local cargo_ver

  rustc_ver="$(rustc --version 2>/dev/null || echo 'rustc-unavailable')"
  cargo_ver="$(cargo --version 2>/dev/null || echo 'cargo-unavailable')"

  if git -C "$PROJECT_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git_head="$(git -C "$PROJECT_ROOT" rev-parse HEAD 2>/dev/null || echo 'detached')"
    # Scope status to source/config paths only, to avoid artifact noise.
    git_state="$(
      git -C "$PROJECT_ROOT" status --porcelain=v1 --untracked-files=all \
        -- Cargo.toml Cargo.lock src crates scripts tests \
        2>/dev/null || true
    )"
  fi

  local build_opts
  build_opts="features=${BUILD_FEATURES};offline=${BUILD_OFFLINE};bins=${BIN_ARGS[*]:-all}"

  printf '%s\n%s\n%s\n%s\n%s\n' "$git_head" "$git_state" "$rustc_ver" "$cargo_ver" "$build_opts" \
    | sha256sum | awk '{print $1}'
}

current_fingerprint="$(compute_fingerprint)"
previous_fingerprint=""
if [[ -f "$STAMP_FILE" ]]; then
  previous_fingerprint="$(cat "$STAMP_FILE" 2>/dev/null || true)"
fi

needs_rebuild=0
if [[ "$FORCE_REBUILD" -eq 1 ]]; then
  needs_rebuild=1
elif [[ ! -f "$STAMP_FILE" ]]; then
  needs_rebuild=1
elif [[ "$current_fingerprint" != "$previous_fingerprint" ]]; then
  needs_rebuild=1
fi

if [[ "$needs_rebuild" -eq 0 ]]; then
  echo "[build] Release binaries are up to date (fingerprint match)."
  exit 0
fi

echo "[build] Source/tooling changed. Running clean release rebuild..."
cd "$PROJECT_ROOT"

if [[ "$DO_CLEAN" -eq 1 ]]; then
  cargo clean
fi

if [[ "${#BIN_ARGS[@]}" -eq 0 ]]; then
  build_cmd=(cargo build --release --bins)
else
  build_cmd=(cargo build --release)
  for bin_name in "${BIN_ARGS[@]}"; do
    build_cmd+=(--bin "$bin_name")
  done
fi

if [[ -n "$BUILD_FEATURES" ]]; then
  build_cmd+=(--features "$BUILD_FEATURES")
fi
if [[ "$BUILD_OFFLINE" -eq 1 ]]; then
  build_cmd+=(--offline)
fi

"${build_cmd[@]}"

mkdir -p "$STAMP_DIR"
printf '%s\n' "$current_fingerprint" > "$STAMP_FILE"
echo "[build] Release rebuild complete."
