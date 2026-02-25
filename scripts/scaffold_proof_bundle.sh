#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/scaffold_proof_bundle.sh \
    --target EXT-015 \
    --root artifacts/external_targets/ext_batch_013/reports \
    --mode exploit|non_exploit

Creates a proof artifact bundle directory with required files:
  replay_command.txt
  exploit_notes.md OR no_exploit_proof.md
  impact.md
EOF
}

TARGET=""
ROOT=""
MODE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --target)
      TARGET="${2:-}"
      shift 2
      ;;
    --root)
      ROOT="${2:-}"
      shift 2
      ;;
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [ -z "$TARGET" ] || [ -z "$ROOT" ] || [ -z "$MODE" ]; then
  echo "Missing required args." >&2
  usage
  exit 1
fi

case "$MODE" in
  exploit|non_exploit) ;;
  *)
    echo "--mode must be exploit or non_exploit" >&2
    exit 1
    ;;
esac

slugify() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/_/g; s/^_+//; s/_+$//'
}

ts="$(date -u +%Y%m%d_%H%M%S)"
target_slug="$(slugify "$TARGET")"
mode_slug="$(slugify "$MODE")"
bundle_dir="$ROOT/evidence/$TARGET/run_${ts}_${target_slug}_${mode_slug}"
mkdir -p "$bundle_dir"

cat > "$bundle_dir/replay_command.txt" <<'EOF'
# One-command deterministic replay
# Fill with the exact command used to reproduce this result.
# Example:
# cargo run --release -- evidence <campaign.yaml> --seed 42 --iterations 200 --timeout 60 --simple-progress
EOF

if [ "$MODE" = "exploit" ]; then
  cat > "$bundle_dir/exploit_notes.md" <<'EOF'
# Exploit Notes

## Target Identity
- repo path:
- commit sha:
- component:

## Exact Inputs / Witness / Tx Sequence

## Expected Behavior

## Observed Behavior

## Deterministic Replay Result
- replay log path:
- replay status:

## Conclusion
`exploitable`
EOF
else
  cat > "$bundle_dir/no_exploit_proof.md" <<'EOF'
# Bounded Non-Exploit Proof

## Target Identity
- repo path:
- commit sha:
- component:

## Bounded Campaign Definition
- seed:
- iterations:
- timeout:
- invariant scope:

## Assumptions

## Limits

## Replay Result
- replay log path:
- counterexample found: `no`

## Conclusion
`not exploitable within bounds`
EOF
fi

cat > "$bundle_dir/impact.md" <<'EOF'
# Impact

## Severity Rationale

## Affected Components / Backends

## Blast Radius

## Recommendation
EOF

echo "Created proof bundle scaffold:"
echo "  $bundle_dir"
ls -1 "$bundle_dir"
