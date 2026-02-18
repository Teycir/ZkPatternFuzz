#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STABLE_REF=""
WORKTREE_PATH=""

usage() {
  cat <<'USAGE'
Usage: scripts/rollback_validate.sh --stable-ref <git-ref> [options]

Validate rollback readiness by building and smoke-running a previous stable ref
in an isolated git worktree.

Options:
  --stable-ref <git-ref>   Required. Previous stable tag/commit/branch to validate.
  --worktree <path>        Optional explicit temporary worktree path.
  -h, --help               Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stable-ref)
      STABLE_REF="$2"
      shift 2
      ;;
    --worktree)
      WORKTREE_PATH="$2"
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

if [ -z "$STABLE_REF" ]; then
  echo "--stable-ref is required" >&2
  usage >&2
  exit 2
fi

if ! git -C "$ROOT_DIR" rev-parse --verify "${STABLE_REF}^{commit}" >/dev/null 2>&1; then
  echo "Invalid --stable-ref: $STABLE_REF" >&2
  exit 2
fi

if [ -z "$WORKTREE_PATH" ]; then
  WORKTREE_PATH="$(mktemp -d /tmp/zkfuzz_rollback_XXXXXX)"
  REMOVE_WORKTREE_DIR=1
else
  mkdir -p "$WORKTREE_PATH"
  REMOVE_WORKTREE_DIR=0
fi

cleanup() {
  git -C "$ROOT_DIR" worktree remove --force "$WORKTREE_PATH" >/dev/null 2>&1 || true
  if [ "${REMOVE_WORKTREE_DIR:-0}" -eq 1 ]; then
    rm -rf "$WORKTREE_PATH" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "Creating rollback validation worktree: $WORKTREE_PATH (ref: $STABLE_REF)"
git -C "$ROOT_DIR" worktree add --detach "$WORKTREE_PATH" "$STABLE_REF" >/dev/null

pushd "$WORKTREE_PATH" >/dev/null

echo "Building stable ref in release mode..."
cargo build --release --all-features

echo "Running rollback smoke checks..."
./target/release/zk-fuzzer --help >/dev/null
cargo run --release --bin zk0d_batch -- --config-profile dev --list-catalog >/dev/null

popd >/dev/null
echo "Rollback validation passed for ref: $STABLE_REF"
