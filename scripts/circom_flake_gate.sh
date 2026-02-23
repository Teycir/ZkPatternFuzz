#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCHMARK_ROOT="$ROOT_DIR/artifacts/benchmark_runs"
BENCHMARK_SUMMARY=""
KEYGEN_PREFLIGHT="$ROOT_DIR/artifacts/keygen_preflight/latest_report.json"
OUTPUT_PATH="$ROOT_DIR/artifacts/circom_flake/latest_report.json"
HISTORY_PATH="$ROOT_DIR/artifacts/circom_flake/history.json"
REQUIRED_CONSECUTIVE_DAYS="${CIRCOM_FLAKE_CONSECUTIVE_DAYS:-14}"
ENFORCE=0

usage() {
  cat <<'USAGE'
Usage: scripts/circom_flake_gate.sh [options]

Track and gate long-horizon Circom lane stability from keygen + benchmark gate
signals. The gate computes consecutive UTC daily passes and can enforce a
minimum streak (14 days by default).

Options:
  --benchmark-root <path>            Benchmark root used to auto-discover summary.json
                                     (default: artifacts/benchmark_runs)
  --benchmark-summary <path>         Explicit benchmark summary.json (overrides --benchmark-root)
  --keygen-preflight <path>          Keygen preflight report path
                                     (default: artifacts/keygen_preflight/latest_report.json)
  --output <path>                    Output report path
                                     (default: artifacts/circom_flake/latest_report.json)
  --history-path <path>              History file used for consecutive-day streaks
                                     (default: artifacts/circom_flake/history.json)
  --required-consecutive-days <int>  Required consecutive UTC daily passes (default: 14)
  --enforce                          Exit non-zero if gate fails
  -h, --help                         Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --benchmark-root)
      BENCHMARK_ROOT="$2"
      shift 2
      ;;
    --benchmark-summary)
      BENCHMARK_SUMMARY="$2"
      shift 2
      ;;
    --keygen-preflight)
      KEYGEN_PREFLIGHT="$2"
      shift 2
      ;;
    --output)
      OUTPUT_PATH="$2"
      shift 2
      ;;
    --history-path)
      HISTORY_PATH="$2"
      shift 2
      ;;
    --required-consecutive-days)
      REQUIRED_CONSECUTIVE_DAYS="$2"
      shift 2
      ;;
    --enforce)
      ENFORCE=1
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

if ! [[ "$REQUIRED_CONSECUTIVE_DAYS" =~ ^[0-9]+$ ]]; then
  echo "required-consecutive-days must be a non-negative integer (got '$REQUIRED_CONSECUTIVE_DAYS')" >&2
  exit 2
fi

if [[ -z "$BENCHMARK_SUMMARY" ]]; then
  if [[ ! -d "$BENCHMARK_ROOT" ]]; then
    echo "Benchmark root not found: $BENCHMARK_ROOT" >&2
    exit 2
  fi

  mapfile -t summaries < <(
    find "$BENCHMARK_ROOT" -type f \
      | rg '/benchmark_[0-9]{8}_[0-9]{6}/summary\.json$' \
      | sort
  )
  if [[ "${#summaries[@]}" -eq 0 ]]; then
    echo "No benchmark summary.json found under: $BENCHMARK_ROOT" >&2
    exit 2
  fi
  BENCHMARK_SUMMARY="${summaries[${#summaries[@]}-1]}"
fi

if [[ ! -f "$BENCHMARK_SUMMARY" ]]; then
  echo "Benchmark summary not found: $BENCHMARK_SUMMARY" >&2
  exit 2
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"
mkdir -p "$(dirname "$HISTORY_PATH")"

BENCHMARK_GATE_LOG="$(dirname "$OUTPUT_PATH")/benchmark_gate_latest.log"
set +e
"$ROOT_DIR/scripts/ci_benchmark_gate.sh" "$BENCHMARK_ROOT" "$BENCHMARK_SUMMARY" >"$BENCHMARK_GATE_LOG" 2>&1
BENCHMARK_GATE_EXIT=$?
set -e

python3 - "$KEYGEN_PREFLIGHT" "$BENCHMARK_SUMMARY" "$BENCHMARK_GATE_LOG" "$BENCHMARK_GATE_EXIT" "$HISTORY_PATH" "$OUTPUT_PATH" "$REQUIRED_CONSECUTIVE_DAYS" "$ENFORCE" <<'PY'
import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional


def load_json(path: str) -> Optional[dict]:
    p = Path(path)
    if not p.is_file():
        return None
    with p.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def parse_dt(value: str) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_history_entries(path: Path) -> List[dict]:
    payload = load_json(str(path))
    if payload is None:
        return []
    if isinstance(payload, dict):
        entries = payload.get("entries")
        if isinstance(entries, list):
            return [entry for entry in entries if isinstance(entry, dict)]
        return []
    if isinstance(payload, list):
        return [entry for entry in payload if isinstance(entry, dict)]
    return []


def collapse_daily_latest(entries: List[dict]) -> List[dict]:
    by_day: Dict[date, dict] = {}
    for entry in entries:
        generated_utc = parse_dt(entry.get("generated_utc", ""))
        if generated_utc is None:
            continue
        day = generated_utc.date()
        current = by_day.get(day)
        if current is None or generated_utc > current["generated_utc"]:
            by_day[day] = {"generated_utc": generated_utc, "entry": entry}
    return [by_day[day] for day in sorted(by_day.keys())]


def compute_streak(daily_entries: List[dict]) -> int:
    streak = 0
    expected_day: Optional[date] = None
    for row in reversed(daily_entries):
        generated_utc = row["generated_utc"]
        entry = row["entry"]
        lane_pass = bool(entry.get("lane_pass", False))
        if not lane_pass:
            break
        current_day = generated_utc.date()
        if expected_day is not None and current_day != expected_day:
            break
        streak += 1
        expected_day = current_day - timedelta(days=1)
    return streak


(
    keygen_preflight_path,
    benchmark_summary_path,
    benchmark_gate_log_path,
    benchmark_gate_exit_raw,
    history_path_raw,
    output_path_raw,
    required_days_raw,
    enforce_raw,
) = sys.argv[1:]

benchmark_gate_exit = int(benchmark_gate_exit_raw)
required_days = int(required_days_raw)
enforce = int(enforce_raw) == 1

history_path = Path(history_path_raw)
output_path = Path(output_path_raw)

keygen_preflight = load_json(keygen_preflight_path) or {}
keygen_present = Path(keygen_preflight_path).is_file()
keygen_pass = bool(keygen_preflight.get("passes", False)) if keygen_present else False
keygen_total_targets = int(keygen_preflight.get("total_targets", 0) or 0) if keygen_present else 0
keygen_passed_targets = int(keygen_preflight.get("passed_targets", 0) or 0) if keygen_present else 0

benchmark_summary = load_json(benchmark_summary_path) or {}
benchmark_gate_pass = benchmark_gate_exit == 0

lane_pass = keygen_pass and benchmark_gate_pass
generated_utc = datetime.now(timezone.utc)
day_utc = generated_utc.date().isoformat()

new_entry = {
    "generated_utc": generated_utc.isoformat(),
    "day_utc": day_utc,
    "lane_pass": lane_pass,
    "keygen_setup_keys_pass": keygen_pass,
    "compile_prove_verify_pass": benchmark_gate_pass,
    "keygen_total_targets": keygen_total_targets,
    "keygen_passed_targets": keygen_passed_targets,
    "benchmark_summary_path": benchmark_summary_path,
    "benchmark_total_runs": int(benchmark_summary.get("total_runs", 0) or 0),
    "benchmark_overall_completion_rate": float(
        benchmark_summary.get("overall_completion_rate", 0.0) or 0.0
    ),
}

history_entries = load_history_entries(history_path)
history_entries.append(new_entry)

daily_entries = collapse_daily_latest(history_entries)
streak_days = compute_streak(daily_entries)
required_enabled = required_days > 0
remaining_days = max(required_days - streak_days, 0) if required_enabled else 0
projected_completion_day_utc = (
    (generated_utc.date() + timedelta(days=remaining_days)).isoformat()
    if required_enabled and streak_days > 0
    else None
)
overall_pass = True if not required_enabled else streak_days >= required_days

failures: List[str] = []
if required_enabled and streak_days < required_days:
    failures.append(
        f"circom lane streak {streak_days} < required {required_days} consecutive UTC days"
    )

if not keygen_pass:
    failures.append("latest keygen preflight signal did not pass")
if not benchmark_gate_pass:
    failures.append("latest benchmark compile/prove/verify gate did not pass")

history_payload = {
    "generated_utc": generated_utc.isoformat(),
    "entries": history_entries,
}
with history_path.open("w", encoding="utf-8") as handle:
    json.dump(history_payload, handle, indent=2)

report = {
    "generated_utc": generated_utc.isoformat(),
    "required_consecutive_days": required_days,
    "required_gate_enabled": required_enabled,
    "current_streak_days": streak_days,
    "remaining_streak_days": remaining_days,
    "projected_completion_day_utc": projected_completion_day_utc,
    "overall_pass": overall_pass,
    "history_path": str(history_path),
    "history_daily_entries": len(daily_entries),
    "latest_signals": {
        "lane_pass": lane_pass,
        "keygen_setup_keys_pass": keygen_pass,
        "compile_prove_verify_pass": benchmark_gate_pass,
    },
    "keygen_preflight": {
        "path": keygen_preflight_path,
        "present": keygen_present,
        "passes": keygen_pass,
        "total_targets": keygen_total_targets,
        "passed_targets": keygen_passed_targets,
    },
    "benchmark_gate": {
        "summary_path": benchmark_summary_path,
        "gate_log_path": benchmark_gate_log_path,
        "gate_exit_code": benchmark_gate_exit,
        "gate_pass": benchmark_gate_pass,
    },
    "failures": failures,
}
with output_path.open("w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2)

print(f"circom flake gate report: {output_path}")
print(
    f"streak={streak_days} required={required_days} "
    f"remaining={remaining_days} projected_completion_day_utc={projected_completion_day_utc} "
    f"keygen_pass={keygen_pass} benchmark_gate_pass={benchmark_gate_pass}"
)

if enforce and not overall_pass:
    sys.exit(1)
PY
