#!/usr/bin/env python3
"""
Generate nightly benchmark failure-class dashboard artifacts.

Outputs:
- <output-dir>/latest_failure_dashboard.json
- <output-dir>/latest_failure_dashboard.md
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


SUCCESS_REASONS = {
    "none",
    "completed",
    "critical_findings_detected",
}

FAILURE_CLASS_RULES: List[Tuple[str, set[str]]] = [
    ("lock_contention", {"output_dir_locked"}),
    (
        "setup_tooling",
        {
            "backend_tooling_missing",
            "backend_preflight_failed",
            "circom_compilation_failed",
            "key_generation_failed",
            "missing_invariants",
            "readiness_failed",
            "filesystem_permission_denied",
        },
    ),
    ("timeouts", {"wall_clock_timeout"}),
    (
        "stability_runtime",
        {
            "runtime_error",
            "panic",
            "artifact_mirror_panic_missing_command",
            "run_outcome_missing",
            "run_outcome_unreadable",
            "run_outcome_invalid_json",
            "unknown",
            "stale_interrupted",
        },
    ),
    (
        "contract_or_config",
        {
            "engagement_contract_failed",
            "missing_chains_definition",
        },
    ),
]

CLASS_THRESHOLDS = {
    "lock_contention": 0.05,
    "setup_tooling": 0.15,
    "timeouts": 0.10,
    "stability_runtime": 0.05,
    "contract_or_config": 0.10,
    "other_failure": 0.05,
}

FAILURE_CLASSES = [
    "lock_contention",
    "setup_tooling",
    "timeouts",
    "stability_runtime",
    "contract_or_config",
    "other_failure",
]


def _latest_benchmark_dir(benchmark_root: Path) -> Path:
    candidates = sorted(p for p in benchmark_root.glob("benchmark_*") if p.is_dir())
    if not candidates:
        raise FileNotFoundError(f"No benchmark_* directory found under {benchmark_root}")
    return candidates[-1]


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _classify_reason(reason: str) -> str:
    if reason in SUCCESS_REASONS:
        return "success"
    for class_name, reasons in FAILURE_CLASS_RULES:
        if reason in reasons:
            return class_name
    return "other_failure"


def _sum_reason_counts(outcomes: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in outcomes:
        reason_counts = item.get("reason_counts", {})
        if not isinstance(reason_counts, dict):
            continue
        for reason, raw_count in reason_counts.items():
            try:
                count = int(raw_count)
            except (TypeError, ValueError):
                continue
            counts[reason] = counts.get(reason, 0) + max(count, 0)
    return counts


def _pct(value: float) -> str:
    return f"{value * 100.0:.2f}%"


def _parse_rate(raw: str, source: str) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"Invalid threshold value from {source}: {raw!r}") from exc
    if value < 0.0 or value > 1.0:
        raise ValueError(f"Threshold from {source} must be between 0.0 and 1.0, got {value}")
    return value


def _env_key_for_class(class_name: str) -> str:
    return f"ZKF_FAILURE_MAX_RATE_{class_name.upper()}"


def _resolve_thresholds(cli_overrides: List[str]) -> Dict[str, float]:
    thresholds = dict(CLASS_THRESHOLDS)

    for class_name in FAILURE_CLASSES:
        env_key = _env_key_for_class(class_name)
        raw_env = os.environ.get(env_key)
        if raw_env is None or raw_env.strip() == "":
            continue
        thresholds[class_name] = _parse_rate(raw_env.strip(), f"${env_key}")

    for override in cli_overrides:
        if "=" not in override:
            raise ValueError(f"Invalid --threshold {override!r}; expected CLASS=RATE")
        class_name_raw, rate_raw = override.split("=", 1)
        class_name = class_name_raw.strip().lower()
        if class_name not in thresholds:
            valid = ", ".join(FAILURE_CLASSES)
            raise ValueError(f"Unknown failure class {class_name!r}; valid classes: {valid}")
        thresholds[class_name] = _parse_rate(
            rate_raw.strip(), f"--threshold {class_name_raw.strip()}={rate_raw.strip()}"
        )

    return thresholds


def _dashboard(
    summary: Dict[str, Any],
    outcomes: List[Dict[str, Any]],
    summary_path: Path,
    outcomes_path: Path,
    class_thresholds: Dict[str, float],
) -> Dict[str, Any]:
    total_runs = int(summary.get("total_runs", len(outcomes)))
    if total_runs <= 0:
        total_runs = len(outcomes)

    reason_counts = _sum_reason_counts(outcomes)
    class_counts: Dict[str, int] = {}
    for reason, count in reason_counts.items():
        cls = _classify_reason(reason)
        class_counts[cls] = class_counts.get(cls, 0) + count

    class_rows: List[Dict[str, Any]] = []
    for class_name in FAILURE_CLASSES:
        count = class_counts.get(class_name, 0)
        rate = (count / total_runs) if total_runs > 0 else 0.0
        threshold = class_thresholds[class_name]
        status = "PASS" if rate <= threshold else "FAIL"
        class_rows.append(
            {
                "class": class_name,
                "count": count,
                "rate": rate,
                "max_rate": threshold,
                "status": status,
            }
        )

    overall_status = "PASS"
    for row in class_rows:
        if row["status"] == "FAIL":
            overall_status = "FAIL"
            break

    return {
        "generated_utc": summary.get("generated_utc"),
        "summary_path": str(summary_path),
        "outcomes_path": str(outcomes_path),
        "total_runs": total_runs,
        "overall_status": overall_status,
        "class_rows": class_rows,
        "reason_counts": dict(sorted(reason_counts.items())),
    }


def _write_markdown(path: Path, payload: Dict[str, Any]) -> None:
    lines: List[str] = []
    lines.append("# Benchmark Failure-Class Dashboard")
    lines.append("")
    lines.append(f"- Generated UTC: `{payload.get('generated_utc')}`")
    lines.append(f"- Summary: `{payload.get('summary_path')}`")
    lines.append(f"- Outcomes: `{payload.get('outcomes_path')}`")
    lines.append(f"- Overall status: `{payload.get('overall_status')}`")
    lines.append(f"- Total runs: `{payload.get('total_runs')}`")
    lines.append("")
    lines.append("| Failure Class | Count | Rate | Max Allowed | Status |")
    lines.append("|---|---:|---:|---:|---|")
    for row in payload.get("class_rows", []):
        lines.append(
            f"| {row['class']} | {row['count']} | {_pct(row['rate'])} | {_pct(row['max_rate'])} | {row['status']} |"
        )
    lines.append("")
    lines.append("## Reason Counts")
    lines.append("")
    lines.append("| Reason Code | Count |")
    lines.append("|---|---:|")
    reason_counts: Dict[str, int] = payload.get("reason_counts", {})
    for reason, count in reason_counts.items():
        lines.append(f"| {reason} | {count} |")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate benchmark failure-class dashboard.")
    parser.add_argument(
        "--benchmark-root",
        default="artifacts/benchmark_runs",
        help="Root directory containing benchmark_<timestamp>/summary.json and outcomes.json",
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/benchmark_trends",
        help="Directory where dashboard artifacts are written",
    )
    parser.add_argument(
        "--threshold",
        action="append",
        default=[],
        metavar="CLASS=RATE",
        help=(
            "Override class threshold (repeatable). "
            "Also supports env ZKF_FAILURE_MAX_RATE_<CLASS>, e.g. "
            "ZKF_FAILURE_MAX_RATE_SETUP_TOOLING=0.20"
        ),
    )
    args = parser.parse_args()

    benchmark_root = Path(args.benchmark_root)
    output_dir = Path(args.output_dir)
    class_thresholds = _resolve_thresholds(args.threshold)
    latest_dir = _latest_benchmark_dir(benchmark_root)
    summary_path = latest_dir / "summary.json"
    outcomes_path = latest_dir / "outcomes.json"

    if not summary_path.exists():
        raise FileNotFoundError(f"Missing summary.json at {summary_path}")
    if not outcomes_path.exists():
        raise FileNotFoundError(f"Missing outcomes.json at {outcomes_path}")

    summary = _load_json(summary_path)
    outcomes = _load_json(outcomes_path)
    if not isinstance(outcomes, list):
        raise ValueError(f"Expected list in {outcomes_path}")

    payload = _dashboard(summary, outcomes, summary_path, outcomes_path, class_thresholds)
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "latest_failure_dashboard.json"
    md_path = output_dir / "latest_failure_dashboard.md"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _write_markdown(md_path, payload)

    print(f"Failure dashboard written: {json_path}")
    print(f"Failure dashboard report written: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
