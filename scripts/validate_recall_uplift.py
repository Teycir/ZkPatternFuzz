#!/usr/bin/env python3
"""Validate vulnerable recall uplift against a baseline benchmark summary."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _load_summary(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid summary schema at {path}: expected object")
    return data


def _validate_recall_uplift(
    baseline_summary: dict[str, Any],
    candidate_summary: dict[str, Any],
    min_uplift_pp: float,
    max_safe_high_conf_fpr: float,
    require_non_dry_run: bool,
) -> dict[str, Any]:
    baseline_cfg = baseline_summary.get("config", {})
    candidate_cfg = candidate_summary.get("config", {})
    baseline_dry_run = bool(baseline_cfg.get("dry_run", False))
    candidate_dry_run = bool(candidate_cfg.get("dry_run", False))

    baseline_recall = float(baseline_summary.get("vulnerable_recall", 0.0))
    candidate_recall = float(candidate_summary.get("vulnerable_recall", 0.0))
    uplift_pp = (candidate_recall - baseline_recall) * 100.0

    safe_high_conf_fpr = float(
        candidate_summary.get("safe_high_confidence_false_positive_rate", 0.0)
    )

    failures: list[str] = []
    if require_non_dry_run and baseline_dry_run:
        failures.append("baseline summary is dry-run; non-dry-run baseline required")
    if require_non_dry_run and candidate_dry_run:
        failures.append("candidate summary is dry-run; non-dry-run candidate required")
    if uplift_pp < min_uplift_pp:
        failures.append(f"recall uplift {uplift_pp:.2f}pp < required {min_uplift_pp:.2f}pp")
    if safe_high_conf_fpr > max_safe_high_conf_fpr:
        failures.append(
            "safe_high_confidence_false_positive_rate "
            f"{safe_high_conf_fpr:.4f} > {max_safe_high_conf_fpr:.4f}"
        )

    return {
        "baseline_recall": baseline_recall,
        "candidate_recall": candidate_recall,
        "recall_uplift_pp": uplift_pp,
        "safe_high_confidence_false_positive_rate": safe_high_conf_fpr,
        "min_uplift_pp": min_uplift_pp,
        "max_safe_high_confidence_false_positive_rate": max_safe_high_conf_fpr,
        "baseline_dry_run": baseline_dry_run,
        "candidate_dry_run": candidate_dry_run,
        "passes": len(failures) == 0,
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate vulnerable recall uplift over a baseline benchmark summary."
    )
    parser.add_argument("--baseline-summary", required=True, help="Path to baseline summary.json")
    parser.add_argument(
        "--candidate-summary", required=True, help="Path to candidate summary.json"
    )
    parser.add_argument(
        "--min-uplift-pp",
        type=float,
        default=20.0,
        help="Minimum recall uplift in percentage points (default: 20.0)",
    )
    parser.add_argument(
        "--max-safe-high-conf-fpr",
        type=float,
        default=0.05,
        help="Maximum allowed safe high-confidence false positive rate (default: 0.05)",
    )
    parser.add_argument(
        "--allow-dry-run",
        action="store_true",
        help="Allow dry-run summaries for baseline/candidate",
    )
    parser.add_argument("--json-out", help="Optional JSON output path")
    parser.add_argument(
        "--enforce", action="store_true", help="Return non-zero when validation fails"
    )
    args = parser.parse_args()

    baseline_path = Path(args.baseline_summary)
    candidate_path = Path(args.candidate_summary)
    if not baseline_path.is_file():
        raise SystemExit(f"baseline summary not found: {baseline_path}")
    if not candidate_path.is_file():
        raise SystemExit(f"candidate summary not found: {candidate_path}")

    baseline_summary = _load_summary(baseline_path)
    candidate_summary = _load_summary(candidate_path)
    result = _validate_recall_uplift(
        baseline_summary,
        candidate_summary,
        args.min_uplift_pp,
        args.max_safe_high_conf_fpr,
        require_non_dry_run=not args.allow_dry_run,
    )

    payload: dict[str, Any] = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_summary_path": str(baseline_path),
        "candidate_summary_path": str(candidate_path),
        **result,
    }

    print(
        "Recall uplift validation: "
        f"baseline={payload['baseline_recall']:.4f} "
        f"candidate={payload['candidate_recall']:.4f} "
        f"uplift={payload['recall_uplift_pp']:.2f}pp "
        f"safe_high_conf_fpr={payload['safe_high_confidence_false_positive_rate']:.4f} "
        f"status={'PASS' if payload['passes'] else 'FAIL'}"
    )

    if args.json_out:
        json_out = Path(args.json_out)
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if args.enforce and not payload["passes"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
