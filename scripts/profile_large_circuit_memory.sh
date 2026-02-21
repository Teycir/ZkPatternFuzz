#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$ROOT_DIR/artifacts/memory_profiles"
MATRICES="targets/zk0d_matrix_noir_readiness.yaml,targets/zk0d_matrix_cairo_readiness.yaml,targets/zk0d_matrix_halo2_readiness.yaml"
REGISTRY="targets/fuzzer_registry.prod.yaml"
FRAMEWORKS="noir,cairo,halo2"
MAX_TARGETS=6
MAX_TARGETS_PER_FRAMEWORK=2
BATCH_BIN="target/release/zk0d_batch"
BATCH_JOBS=1
WORKERS=2
ITERATIONS=20
TIMEOUT=20
BUILD_IF_MISSING=true
ENFORCE=false
MAX_RSS_KB=0

usage() {
  cat <<'USAGE'
Usage: scripts/profile_large_circuit_memory.sh [options]

Profile memory usage on the largest available circuit targets from one or more
target matrices. The script wraps zk0d_batch runs with /usr/bin/time -v and
emits aggregate reports.

Options:
  --output-dir <path>                  Output directory (default: artifacts/memory_profiles)
  --matrices <csv>                     Matrix YAML paths (default: noir/cairo/halo2 readiness matrices)
  --registry <path>                    Registry YAML path (default: targets/fuzzer_registry.prod.yaml)
  --frameworks <csv>                   Framework filter (default: noir,cairo,halo2)
  --max-targets <n>                    Maximum profiled targets total (default: 6)
  --max-targets-per-framework <n>      Per-framework quota before global fill (default: 2)
  --batch-bin <path>                   zk0d_batch binary (default: target/release/zk0d_batch)
  --batch-jobs <n>                     Template jobs passed to zk0d_batch (default: 1)
  --workers <n>                        Workers per scan (default: 2)
  --iterations <n>                     Iterations per scan (default: 20)
  --timeout <seconds>                  Timeout per scan (default: 20)
  --max-rss-kb <n>                     Optional RSS threshold per run (0 disables, default: 0)
  --no-build-if-missing                Fail if batch binary is missing
  --enforce                            Exit non-zero on failed runs or threshold violations
  -h, --help                           Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --matrices) MATRICES="$2"; shift 2 ;;
    --registry) REGISTRY="$2"; shift 2 ;;
    --frameworks) FRAMEWORKS="$2"; shift 2 ;;
    --max-targets) MAX_TARGETS="$2"; shift 2 ;;
    --max-targets-per-framework) MAX_TARGETS_PER_FRAMEWORK="$2"; shift 2 ;;
    --batch-bin) BATCH_BIN="$2"; shift 2 ;;
    --batch-jobs) BATCH_JOBS="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --max-rss-kb) MAX_RSS_KB="$2"; shift 2 ;;
    --no-build-if-missing) BUILD_IF_MISSING=false; shift ;;
    --enforce) ENFORCE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -x /usr/bin/time ]]; then
  echo "/usr/bin/time is required for RSS profiling but was not found." >&2
  exit 1
fi

if [[ ! -f "$REGISTRY" ]]; then
  echo "Registry not found: $REGISTRY" >&2
  exit 1
fi

for v in "$MAX_TARGETS" "$MAX_TARGETS_PER_FRAMEWORK" "$BATCH_JOBS" "$WORKERS" "$ITERATIONS" "$TIMEOUT" "$MAX_RSS_KB"; do
  if [[ ! "$v" =~ ^[0-9]+$ ]]; then
    echo "Numeric argument expected but got: $v" >&2
    exit 1
  fi
done

if [[ ! -x "$BATCH_BIN" ]]; then
  if ! $BUILD_IF_MISSING; then
    echo "zk0d_batch binary not found/executable: $BATCH_BIN" >&2
    exit 1
  fi
  cargo build --release --bin zk0d_batch >/dev/null
fi

mkdir -p "$OUTPUT_DIR/raw"
PROFILE_HOME="${PROFILE_HOME:-$OUTPUT_DIR/profile_home}"
PROFILE_SIGNAL_DIR="${PROFILE_SIGNAL_DIR:-$PROFILE_HOME/ZkFuzz}"
HOST_HOME="${HOST_HOME:-${HOME:-$ROOT_DIR}}"
PROFILE_RUSTUP_HOME="${PROFILE_RUSTUP_HOME:-${RUSTUP_HOME:-$HOST_HOME/.rustup}}"
PROFILE_CARGO_HOME="${PROFILE_CARGO_HOME:-${CARGO_HOME:-$HOST_HOME/.cargo}}"
PROFILE_BUILD_CACHE_DIR="${PROFILE_BUILD_CACHE_DIR:-$ROOT_DIR/ZkFuzz/_build_cache}"
mkdir -p "$PROFILE_SIGNAL_DIR" "$PROFILE_BUILD_CACHE_DIR"

CANDIDATES_TSV="$OUTPUT_DIR/raw/candidates.tsv"
SELECTED_TSV="$OUTPUT_DIR/raw/selected.tsv"
RESULTS_TSV="$OUTPUT_DIR/raw/results.tsv"
LATEST_JSON="$OUTPUT_DIR/latest_report.json"
LATEST_MD="$OUTPUT_DIR/latest_report.md"

echo -e "target_name\ttarget_circuit\tmain_component\tframework\talias\tmatrix\tfile_size_bytes" > "$CANDIDATES_TSV"

IFS=',' read -r -a MATRIX_ARRAY <<< "$MATRICES"
for matrix in "${MATRIX_ARRAY[@]}"; do
  matrix_trimmed="$(echo "$matrix" | xargs)"
  if [[ -z "$matrix_trimmed" ]]; then
    continue
  fi
  if [[ ! -f "$matrix_trimmed" ]]; then
    echo "Skipping missing matrix: $matrix_trimmed" >&2
    continue
  fi

  mapfile -t rows < <(
    awk '
      /^  - name: / {
        if (in_target && enabled == "true") {
          printf("%s\t%s\t%s\t%s\t%s\n", name, target_circuit, main_component, framework, alias);
        }
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
      END {
        if (in_target && enabled == "true") {
          printf("%s\t%s\t%s\t%s\t%s\n", name, target_circuit, main_component, framework, alias);
        }
      }
    ' "$matrix_trimmed"
  )

  for row in "${rows[@]}"; do
    IFS=$'\t' read -r target_name target_circuit main_component framework alias <<< "$row"
    target_name="${target_name//$'\r'/}"
    target_circuit="${target_circuit//$'\r'/}"
    main_component="${main_component//$'\r'/}"
    framework="${framework//$'\r'/}"
    alias="${alias//$'\r'/}"
    framework_lc="$(echo "$framework" | tr '[:upper:]' '[:lower:]')"
    if [[ ",$FRAMEWORKS," != *",$framework_lc,"* ]]; then
      continue
    fi
    if [[ ! -f "$target_circuit" ]]; then
      continue
    fi

    file_size_bytes="$(stat -c%s "$target_circuit" 2>/dev/null || echo 0)"
    file_size_bytes="${file_size_bytes//$'\r'/}"
    echo -e "${target_name}\t${target_circuit}\t${main_component}\t${framework_lc}\t${alias}\t${matrix_trimmed}\t${file_size_bytes}" >> "$CANDIDATES_TSV"
  done
done

python3 - "$CANDIDATES_TSV" "$SELECTED_TSV" "$FRAMEWORKS" "$MAX_TARGETS" "$MAX_TARGETS_PER_FRAMEWORK" <<'PY'
import csv
import pathlib
import sys

candidates_path = pathlib.Path(sys.argv[1])
selected_path = pathlib.Path(sys.argv[2])
frameworks = [f.strip().lower() for f in sys.argv[3].split(",") if f.strip()]
max_targets = int(sys.argv[4])
max_per_framework = int(sys.argv[5])

rows = []
with candidates_path.open("r", encoding="utf-8") as f:
    reader = csv.DictReader(f, delimiter="\t")
    for row in reader:
        try:
            row["file_size_bytes"] = int(row.get("file_size_bytes") or 0)
        except ValueError:
            row["file_size_bytes"] = 0
        rows.append(row)

for row in rows:
    row["framework"] = row.get("framework", "").lower()

rows.sort(key=lambda r: r["file_size_bytes"], reverse=True)
selected = []
seen = set()

for fw in frameworks:
    fw_rows = [r for r in rows if r.get("framework") == fw]
    for row in fw_rows[:max_per_framework]:
        key = (row["target_name"], row["target_circuit"], row["framework"])
        if key in seen:
            continue
        seen.add(key)
        selected.append(row)

if len(selected) < max_targets:
    for row in rows:
        key = (row["target_name"], row["target_circuit"], row["framework"])
        if key in seen:
            continue
        seen.add(key)
        selected.append(row)
        if len(selected) >= max_targets:
            break

selected = selected[:max_targets]
with selected_path.open("w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "target_name",
            "target_circuit",
            "main_component",
            "framework",
            "alias",
            "matrix",
            "file_size_bytes",
        ],
        delimiter="\t",
        lineterminator="\n",
    )
    writer.writeheader()
    for row in selected:
        writer.writerow(row)
PY

selected_count="$(python3 - "$SELECTED_TSV" <<'PY'
import csv
import sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    rows = list(csv.DictReader(f, delimiter="\t"))
print(len(rows))
PY
)"

if [[ "$selected_count" -eq 0 ]]; then
  echo "No eligible targets found for frameworks '$FRAMEWORKS' in matrices '$MATRICES'." >&2
  exit 1
fi

echo -e "target_name\tframework\ttarget_circuit\tmain_component\talias\tmatrix\tfile_size_bytes\texit_code\tmax_rss_kb\telapsed_wall_seconds\treason_counts\trun_log\ttime_log" > "$RESULTS_TSV"

while IFS=$'\t' read -r target_name target_circuit main_component framework alias matrix file_size_bytes; do
  if [[ "$target_name" == "target_name" ]]; then
    continue
  fi

  target_name="${target_name//$'\r'/}"
  target_circuit="${target_circuit//$'\r'/}"
  main_component="${main_component//$'\r'/}"
  framework="${framework//$'\r'/}"
  alias="${alias//$'\r'/}"
  matrix="${matrix//$'\r'/}"
  file_size_bytes="${file_size_bytes//$'\r'/}"

  target_slug="$(echo "${framework}_${target_name}" | tr '/ ' '__' | tr -cd '[:alnum:]_.-')"
  target_dir="$OUTPUT_DIR/raw/$target_slug"
  mkdir -p "$target_dir"
  run_log="$target_dir/run.log"
  time_log="$target_dir/time.log"

  cmd=(
    "$BATCH_BIN"
    --registry "$REGISTRY"
    --alias "$alias"
    --target-circuit "$target_circuit"
    --main-component "$main_component"
    --framework "$framework"
    --jobs "$BATCH_JOBS"
    --workers "$WORKERS"
    --seed 42
    --iterations "$ITERATIONS"
    --timeout "$TIMEOUT"
    --emit-reason-tsv
  )

  set +e
  HOME="$PROFILE_HOME" \
    ZKF_RUN_SIGNAL_DIR="$PROFILE_SIGNAL_DIR" \
    ZKF_BUILD_CACHE_DIR="$PROFILE_BUILD_CACHE_DIR" \
    RUSTUP_HOME="$PROFILE_RUSTUP_HOME" \
    CARGO_HOME="$PROFILE_CARGO_HOME" \
    /usr/bin/time -v -o "$time_log" "${cmd[@]}" >"$run_log" 2>&1
  exit_code=$?
  set -e

  max_rss_kb="$(awk -F':' '/Maximum resident set size/ {gsub(/^[ \t]+/, "", $2); print $2}' "$time_log" | tail -n1)"
  if [[ -z "${max_rss_kb:-}" ]]; then
    max_rss_kb="-1"
  fi

elapsed_wall_seconds="$(python3 - "$time_log" <<'PY'
import re
import sys
from pathlib import Path

line = ""
for raw in Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").splitlines():
    if "Elapsed (wall clock) time" in raw:
        line = raw
        break

if not line:
    print("-1")
    raise SystemExit(0)

match = re.search(r"Elapsed \(wall clock\) time .*:\s*([0-9:.]+)\s*$", line)
if not match:
    print("-1")
    raise SystemExit(0)

value = match.group(1)
parts = value.split(":")
try:
    if len(parts) == 3:
        h, m, s = parts
        total = int(h) * 3600 + int(m) * 60 + float(s)
    elif len(parts) == 2:
        m, s = parts
        total = int(m) * 60 + float(s)
    else:
        total = float(parts[0])
    print(f"{total:.3f}")
except Exception:
    print("-1")
PY
)"

  reason_counts="$(awk -F'\t' '
      $0 == "REASON_TSV_START" { in_block = 1; next; }
      $0 == "REASON_TSV_END" { in_block = 0; next; }
      in_block && $0 !~ /^template\t/ && NF >= 3 {
        counts[$3] += 1;
      }
      END {
        first = 1;
        for (reason in counts) {
          if (!first) printf(";");
          printf("%s=%d", reason, counts[reason]);
          first = 0;
        }
      }
    ' "$run_log" | tr -d '\n')"
  if [[ -z "$reason_counts" ]]; then
    reason_counts="none=1"
  fi

  echo -e "${target_name}\t${framework}\t${target_circuit}\t${main_component}\t${alias}\t${matrix}\t${file_size_bytes}\t${exit_code}\t${max_rss_kb}\t${elapsed_wall_seconds}\t${reason_counts}\t${run_log}\t${time_log}" >> "$RESULTS_TSV"
done < "$SELECTED_TSV"

python3 - "$RESULTS_TSV" "$LATEST_JSON" "$LATEST_MD" "$FRAMEWORKS" "$MATRICES" "$MAX_TARGETS" "$MAX_TARGETS_PER_FRAMEWORK" "$ITERATIONS" "$TIMEOUT" "$WORKERS" "$BATCH_JOBS" "$MAX_RSS_KB" <<'PY'
import csv
import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

(
    results_tsv,
    latest_json,
    latest_md,
    frameworks,
    matrices,
    max_targets,
    max_targets_per_framework,
    iterations,
    timeout,
    workers,
    batch_jobs,
    max_rss_kb,
) = sys.argv[1:]

rows = []
def to_int(value, default=-1):
    try:
        return int(str(value).strip())
    except Exception:
        return default

def to_float(value, default=-1.0):
    try:
        return float(str(value).strip())
    except Exception:
        return default

with open(results_tsv, "r", encoding="utf-8") as f:
    reader = csv.DictReader(f, delimiter="\t")
    for row in reader:
        row["file_size_bytes"] = to_int(row.get("file_size_bytes"), 0)
        row["exit_code"] = to_int(row.get("exit_code"), 1)
        row["max_rss_kb"] = to_int(row.get("max_rss_kb"), -1)
        row["elapsed_wall_seconds"] = to_float(row.get("elapsed_wall_seconds"), -1.0)
        rows.append(row)

framework_stats = []
by_framework = defaultdict(list)
for row in rows:
    by_framework[row["framework"]].append(row)

for fw, fw_rows in sorted(by_framework.items()):
    rss_values = [r["max_rss_kb"] for r in fw_rows if r["max_rss_kb"] >= 0]
    framework_stats.append(
        {
            "framework": fw,
            "targets_profiled": len(fw_rows),
            "max_rss_kb": max(rss_values) if rss_values else -1,
            "median_rss_kb": statistics.median(rss_values) if rss_values else -1,
            "failed_runs": sum(1 for r in fw_rows if r["exit_code"] != 0),
        }
    )

top_by_rss = sorted(rows, key=lambda r: r["max_rss_kb"], reverse=True)
rss_threshold = int(max_rss_kb)
threshold_violations = []
if rss_threshold > 0:
    threshold_violations = [r for r in rows if r["max_rss_kb"] > rss_threshold]

failed_runs = [r for r in rows if r["exit_code"] != 0]
overall_pass = len(failed_runs) == 0 and len(threshold_violations) == 0

payload = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "config": {
        "frameworks": frameworks,
        "matrices": matrices,
        "max_targets": int(max_targets),
        "max_targets_per_framework": int(max_targets_per_framework),
        "iterations": int(iterations),
        "timeout_seconds": int(timeout),
        "workers": int(workers),
        "batch_jobs": int(batch_jobs),
        "max_rss_kb_threshold": rss_threshold,
    },
    "targets_profiled": len(rows),
    "framework_stats": framework_stats,
    "top_targets_by_rss": top_by_rss[:10],
    "failed_runs": failed_runs,
    "threshold_violations": threshold_violations,
    "overall_pass": overall_pass,
    "results_tsv": results_tsv,
}

Path(latest_json).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

lines = [
    "# Large Circuit Memory Profile",
    "",
    f"- Generated (UTC): {payload['generated_utc']}",
    f"- Targets profiled: {payload['targets_profiled']}",
    f"- Overall pass: {'PASS' if overall_pass else 'FAIL'}",
    "",
    "| Target | Framework | File Size (bytes) | Max RSS (kB) | Elapsed (s) | Exit |",
    "|---|---|---:|---:|---:|---:|",
]
for row in top_by_rss:
    lines.append(
        "| {target} | {framework} | {file_size} | {rss} | {elapsed:.3f} | {exit_code} |".format(
            target=row["target_name"],
            framework=row["framework"],
            file_size=row["file_size_bytes"],
            rss=row["max_rss_kb"],
            elapsed=row["elapsed_wall_seconds"],
            exit_code=row["exit_code"],
        )
    )

lines.extend(
    [
        "",
        "| Framework | Targets | Max RSS (kB) | Median RSS (kB) | Failed Runs |",
        "|---|---:|---:|---:|---:|",
    ]
)
for stat in framework_stats:
    lines.append(
        "| {framework} | {targets} | {max_rss} | {median_rss} | {failed} |".format(
            framework=stat["framework"],
            targets=stat["targets_profiled"],
            max_rss=stat["max_rss_kb"],
            median_rss=stat["median_rss_kb"],
            failed=stat["failed_runs"],
        )
    )

lines.append("")
lines.append(f"- JSON report: `{latest_json}`")
lines.append(f"- Raw TSV: `{results_tsv}`")
Path(latest_md).write_text("\n".join(lines) + "\n", encoding="utf-8")

print(f"Large-circuit memory report: {latest_json}")
print(f"Large-circuit memory markdown: {latest_md}")
print(f"Overall pass: {'PASS' if overall_pass else 'FAIL'}")
PY

if $ENFORCE; then
  python3 - "$LATEST_JSON" <<'PY'
import json
import pathlib
import sys
report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
sys.exit(0 if report.get("overall_pass") else 1)
PY
fi
