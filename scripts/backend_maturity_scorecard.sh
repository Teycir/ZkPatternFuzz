#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
READINESS_DASHBOARD="$ROOT_DIR/artifacts/backend_readiness/latest_report.json"
BENCHMARK_ROOT="$ROOT_DIR/artifacts/benchmark_runs"
BENCHMARK_SUMMARY=""
KEYGEN_PREFLIGHT="$ROOT_DIR/artifacts/keygen_preflight/latest_report.json"
RELEASE_CANDIDATE_REPORT="$ROOT_DIR/artifacts/release_candidate_validation/release_candidate_report.json"
OUTPUT_PATH="$ROOT_DIR/artifacts/backend_maturity/latest_scorecard.json"
REQUIRED_BACKENDS="${BACKEND_MATURITY_REQUIRED_LIST:-circom,noir,cairo,halo2}"
MIN_BACKEND_SCORE="${MIN_BACKEND_MATURITY_SCORE:-4.5}"
ENFORCE=0

usage() {
  cat <<'USAGE'
Usage: scripts/backend_maturity_scorecard.sh [options]

Generate a backend maturity scorecard (0.0-5.0 per backend) from current evidence artifacts.

Options:
  --readiness-dashboard <path>         Aggregated readiness dashboard JSON
                                       (default: artifacts/backend_readiness/latest_report.json)
  --benchmark-root <path>              Benchmark root used to auto-discover latest summary.json
                                       (default: artifacts/benchmark_runs)
  --benchmark-summary <path>           Explicit benchmark summary.json (overrides --benchmark-root)
  --keygen-preflight <path>            Keygen preflight report for Circom proof-lifecycle score
                                       (default: artifacts/keygen_preflight/latest_report.json)
  --release-candidate-report <path>    Release-candidate report for Circom operational hardening
                                       (default: artifacts/release_candidate_validation/release_candidate_report.json)
  --output <path>                      Output scorecard path
                                       (default: artifacts/backend_maturity/latest_scorecard.json)
  --required-backends <csv>            Required backends for gate evaluation
                                       (default: circom,noir,cairo,halo2)
  --min-score <float>                  Minimum maturity score required per backend
                                       (default: 4.5)
  --enforce                            Exit non-zero when any required backend score is below threshold
  -h, --help                           Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --readiness-dashboard)
      READINESS_DASHBOARD="$2"
      shift 2
      ;;
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
    --release-candidate-report)
      RELEASE_CANDIDATE_REPORT="$2"
      shift 2
      ;;
    --output)
      OUTPUT_PATH="$2"
      shift 2
      ;;
    --required-backends)
      REQUIRED_BACKENDS="$2"
      shift 2
      ;;
    --min-score)
      MIN_BACKEND_SCORE="$2"
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

if [[ -z "$BENCHMARK_SUMMARY" ]]; then
  if [[ -d "$BENCHMARK_ROOT" ]]; then
    mapfile -t summaries < <(
      find "$BENCHMARK_ROOT" -type f \
        | rg '/benchmark_[0-9]{8}_[0-9]{6}/summary\.json$' \
        | sort
    )
    if [[ "${#summaries[@]}" -gt 0 ]]; then
      BENCHMARK_SUMMARY="${summaries[${#summaries[@]}-1]}"
    fi
  fi
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"

python3 - \
  "$READINESS_DASHBOARD" \
  "$BENCHMARK_SUMMARY" \
  "$KEYGEN_PREFLIGHT" \
  "$RELEASE_CANDIDATE_REPORT" \
  "$OUTPUT_PATH" \
  "$REQUIRED_BACKENDS" \
  "$MIN_BACKEND_SCORE" \
  "$ENFORCE" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def as_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def load_json(path: str) -> Tuple[Optional[dict], bool]:
    if not path:
        return None, False
    p = Path(path)
    if not p.is_file():
        return None, False
    with p.open("r", encoding="utf-8") as handle:
        return json.load(handle), True


def ratio(value: float, target: float) -> float:
    safe_target = max(target, 1e-9)
    return clamp(value / safe_target)


def inverse_ratio(value: float, ceiling: float) -> float:
    safe_ceiling = max(ceiling, 1e-9)
    return clamp(1.0 - (value / safe_ceiling))


def score_readiness_backend(entry: dict, thresholds: dict) -> dict:
    selector_completion = as_float(entry.get("selector_matching_completion_rate"), 0.0)
    selector_total = max(as_int(entry.get("selector_matching_total"), 0), 0)
    selector_mismatch_rate = as_float(entry.get("selector_mismatch_rate"), 1.0)
    completion_rate = as_float(entry.get("completion_rate"), 0.0)
    run_outcome_missing_rate = as_float(entry.get("run_outcome_missing_rate"), 1.0)
    runtime_error_count = max(as_int(entry.get("runtime_error_count"), 0), 0)
    preflight_failed_count = max(as_int(entry.get("backend_preflight_failed_count"), 0), 0)
    matrix_exit_code = as_int(entry.get("matrix_exit_code"), 1)
    gate_pass = bool(entry.get("gate_pass", False))

    integration_statuses = entry.get("integration_statuses", [])
    if isinstance(integration_statuses, list) and integration_statuses:
        total_integration = len(integration_statuses)
        pass_count = sum(1 for status in integration_statuses if str(status).lower() == "pass")
        integration_pass_ratio = pass_count / total_integration
    else:
        integration_pass_ratio = 1.0 if gate_pass else 0.0

    min_selector_matching_total = as_int(thresholds.get("min_selector_matching_total"), 4)
    min_overall_completion_rate = as_float(
        thresholds.get("min_overall_completion_rate"), 0.40
    )
    max_selector_mismatch_rate = as_float(
        thresholds.get("max_selector_mismatch_rate"), 0.70
    )
    max_run_outcome_missing_rate = as_float(
        thresholds.get("max_run_outcome_missing_rate"), 0.05
    )

    execution_fidelity = clamp(
        0.45 * (1.0 if matrix_exit_code == 0 else 0.0)
        + 0.35 * ratio(selector_completion, 0.95)
        + 0.20 * integration_pass_ratio
    )
    proof_lifecycle_fidelity = clamp(
        (
            (1.0 if runtime_error_count == 0 else 0.0)
            + (1.0 if preflight_failed_count == 0 else 0.0)
            + inverse_ratio(run_outcome_missing_rate, max_run_outcome_missing_rate)
        )
        / 3.0
    )
    constraint_coverage_fidelity = clamp(
        0.65 * ratio(selector_total, float(max(min_selector_matching_total, 1)))
        + 0.35 * inverse_ratio(selector_mismatch_rate, max_selector_mismatch_rate)
    )
    breadth_readiness = clamp(
        0.50 * ratio(completion_rate, min_overall_completion_rate)
        + 0.30 * ratio(selector_completion, 0.95)
        + 0.20 * inverse_ratio(run_outcome_missing_rate, max_run_outcome_missing_rate)
    )
    operational_hardening = clamp(
        0.70 * (1.0 if gate_pass else 0.0) + 0.30 * integration_pass_ratio
    )

    breakdown = {
        "execution_fidelity": round(execution_fidelity, 3),
        "proof_lifecycle_fidelity": round(proof_lifecycle_fidelity, 3),
        "constraint_coverage_fidelity": round(constraint_coverage_fidelity, 3),
        "breadth_readiness": round(breadth_readiness, 3),
        "operational_hardening": round(operational_hardening, 3),
    }
    total_score = round(sum(breakdown.values()), 3)

    evidence = {
        "matrix_exit_code": matrix_exit_code,
        "selector_matching_completion_rate": round(selector_completion, 6),
        "selector_matching_total": selector_total,
        "selector_mismatch_rate": round(selector_mismatch_rate, 6),
        "overall_completion_rate": round(completion_rate, 6),
        "runtime_error_count": runtime_error_count,
        "backend_preflight_failed_count": preflight_failed_count,
        "run_outcome_missing_rate": round(run_outcome_missing_rate, 6),
        "integration_pass_ratio": round(integration_pass_ratio, 6),
        "gate_pass": gate_pass,
    }

    return {
        "backend": str(entry.get("backend", "unknown")),
        "score_total": total_score,
        "score_breakdown": breakdown,
        "evidence": evidence,
    }


def score_circom_backend(
    benchmark_summary: Optional[dict],
    keygen_preflight: Optional[dict],
    release_candidate_report: Optional[dict],
) -> dict:
    benchmark = benchmark_summary or {}
    keygen = keygen_preflight or {}
    release = release_candidate_report or {}

    overall_completion_rate = as_float(benchmark.get("overall_completion_rate"), 0.0)
    attack_stage_reach_rate = as_float(benchmark.get("overall_attack_stage_reach_rate"), 0.0)
    vulnerable_recall = as_float(benchmark.get("vulnerable_recall"), 0.0)
    precision = as_float(benchmark.get("precision"), 0.0)
    safe_fpr = as_float(benchmark.get("safe_false_positive_rate"), 1.0)
    safe_high_conf_fpr = as_float(
        benchmark.get("safe_high_confidence_false_positive_rate"), 1.0
    )
    total_runs = max(as_int(benchmark.get("total_runs"), 0), 0)

    passed_targets = max(as_int(keygen.get("passed_targets"), 0), 0)
    total_targets = max(as_int(keygen.get("total_targets"), 0), 0)
    keygen_pass_ratio = (passed_targets / total_targets) if total_targets > 0 else 0.0
    keygen_overall_pass = bool(keygen.get("passes", False))

    release_present = bool(release_candidate_report)
    release_overall_pass = bool(release.get("overall_pass", False)) if release_present else False
    release_gate_passes = bool(release.get("gates_passed_twice", False)) if release_present else False

    execution_fidelity = clamp(
        0.60 * ratio(overall_completion_rate, 0.95)
        + 0.40 * ratio(attack_stage_reach_rate, 0.95)
    )
    proof_lifecycle_fidelity = clamp(
        0.75 * keygen_pass_ratio + 0.25 * (1.0 if keygen_overall_pass else 0.0)
    )
    constraint_coverage_fidelity = clamp(
        0.45 * ratio(vulnerable_recall, 0.80)
        + 0.35 * ratio(precision, 0.95)
        + 0.20 * inverse_ratio(safe_high_conf_fpr, 0.05)
    )
    breadth_readiness = clamp(
        0.50 * ratio(overall_completion_rate, 0.95)
        + 0.25 * inverse_ratio(safe_fpr, 0.20)
        + 0.25 * inverse_ratio(safe_high_conf_fpr, 0.05)
    )

    if release_present:
        operational_hardening = clamp(
            0.75 * (1.0 if release_overall_pass else 0.0)
            + 0.25 * (1.0 if release_gate_passes else 0.0)
        )
    else:
        operational_hardening = clamp(
            0.60 * ratio(overall_completion_rate, 0.95)
            + 0.40 * (1.0 if keygen_overall_pass else keygen_pass_ratio)
        )

    breakdown = {
        "execution_fidelity": round(execution_fidelity, 3),
        "proof_lifecycle_fidelity": round(proof_lifecycle_fidelity, 3),
        "constraint_coverage_fidelity": round(constraint_coverage_fidelity, 3),
        "breadth_readiness": round(breadth_readiness, 3),
        "operational_hardening": round(operational_hardening, 3),
    }
    total_score = round(sum(breakdown.values()), 3)

    evidence = {
        "benchmark_total_runs": total_runs,
        "overall_completion_rate": round(overall_completion_rate, 6),
        "overall_attack_stage_reach_rate": round(attack_stage_reach_rate, 6),
        "vulnerable_recall": round(vulnerable_recall, 6),
        "precision": round(precision, 6),
        "safe_false_positive_rate": round(safe_fpr, 6),
        "safe_high_confidence_false_positive_rate": round(safe_high_conf_fpr, 6),
        "keygen_pass_ratio": round(keygen_pass_ratio, 6),
        "keygen_overall_pass": keygen_overall_pass,
        "release_report_present": release_present,
        "release_overall_pass": release_overall_pass,
        "release_gates_passed_twice": release_gate_passes,
    }

    return {
        "backend": "circom",
        "score_total": total_score,
        "score_breakdown": breakdown,
        "evidence": evidence,
    }


readiness_dashboard_path = sys.argv[1]
benchmark_summary_path = sys.argv[2]
keygen_preflight_path = sys.argv[3]
release_candidate_report_path = sys.argv[4]
output_path = sys.argv[5]
required_backends = [part.strip() for part in sys.argv[6].split(",") if part.strip()]
min_backend_score = as_float(sys.argv[7], 4.5)
enforce = as_int(sys.argv[8], 0) == 1

readiness_dashboard, readiness_present = load_json(readiness_dashboard_path)
benchmark_summary, benchmark_present = load_json(benchmark_summary_path)
keygen_preflight, keygen_present = load_json(keygen_preflight_path)
release_candidate_report, release_present = load_json(release_candidate_report_path)

readiness_thresholds = {}
if readiness_present and isinstance(readiness_dashboard.get("thresholds"), dict):
    readiness_thresholds = readiness_dashboard["thresholds"]

backend_scores: List[dict] = []
scores_by_backend: Dict[str, dict] = {}

if readiness_present and isinstance(readiness_dashboard.get("backends"), list):
    for backend_entry in readiness_dashboard["backends"]:
        if not isinstance(backend_entry, dict):
            continue
        scored = score_readiness_backend(backend_entry, readiness_thresholds)
        backend_scores.append(scored)
        scores_by_backend[scored["backend"]] = scored

circom_score = score_circom_backend(benchmark_summary, keygen_preflight, release_candidate_report)
backend_scores.append(circom_score)
scores_by_backend[circom_score["backend"]] = circom_score

backend_scores.sort(key=lambda item: item["backend"])

required_failures: List[str] = []
missing_required_backends: List[str] = []
for backend in required_backends:
    entry = scores_by_backend.get(backend)
    if entry is None:
        missing_required_backends.append(backend)
        required_failures.append(f"{backend}: missing scorecard entry")
        continue
    backend_score = as_float(entry.get("score_total"), 0.0)
    if backend_score < min_backend_score:
        required_failures.append(
            f"{backend}: score {backend_score:.3f} < required {min_backend_score:.3f}"
        )

all_non_circom_scores = [
    as_float(item.get("score_total"), 0.0)
    for item in backend_scores
    if item.get("backend") in {"noir", "cairo", "halo2"}
]
cross_backend_readiness_score = (
    round(sum(all_non_circom_scores) / len(all_non_circom_scores), 3)
    if all_non_circom_scores
    else 0.0
)

overall_pass = len(required_failures) == 0

payload = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "rubric": {
        "max_score_per_backend": 5.0,
        "dimensions": [
            "execution_fidelity",
            "proof_lifecycle_fidelity",
            "constraint_coverage_fidelity",
            "breadth_readiness",
            "operational_hardening",
        ],
    },
    "thresholds": {
        "required_backends": required_backends,
        "min_backend_score": min_backend_score,
    },
    "sources": {
        "readiness_dashboard": {
            "path": readiness_dashboard_path,
            "present": readiness_present,
        },
        "benchmark_summary": {
            "path": benchmark_summary_path,
            "present": benchmark_present,
        },
        "keygen_preflight": {
            "path": keygen_preflight_path,
            "present": keygen_present,
        },
        "release_candidate_report": {
            "path": release_candidate_report_path,
            "present": release_present,
        },
    },
    "backends": backend_scores,
    "cross_backend_readiness_score": cross_backend_readiness_score,
    "missing_required_backends": missing_required_backends,
    "gate_failures": required_failures,
    "overall_pass": overall_pass,
}

output = Path(output_path)
output.parent.mkdir(parents=True, exist_ok=True)
with output.open("w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
    handle.write("\n")

for backend in backend_scores:
    name = backend.get("backend", "unknown")
    score = as_float(backend.get("score_total"), 0.0)
    status = "PASS" if score >= min_backend_score else "FAIL"
    if name not in required_backends:
        status = "INFO"
    print(f"[{status}] {name}: maturity_score={score:.3f}/5.000")

if required_failures:
    print("Maturity gate failures:")
    for failure in required_failures:
        print(f"  - {failure}")

print(f"Cross-backend readiness score: {cross_backend_readiness_score:.3f}/5.000")
print(f"Backend maturity scorecard: {output_path}")
print(f"Overall backend maturity gate: {'PASS' if overall_pass else 'FAIL'}")

if enforce and not overall_pass:
    sys.exit(1)
PY
