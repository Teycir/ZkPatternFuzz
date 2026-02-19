#!/usr/bin/env python3
"""Validate that every missed vulnerable run has machine-readable root-cause categories."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _load_outcomes(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"Invalid outcomes schema at {path}: expected list")
    return data


def _misses_with_reason_coverage(outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    misses: list[dict[str, Any]] = []
    missing_reason_rows: list[dict[str, Any]] = []
    reason_counter: Counter[str] = Counter()

    for row in outcomes:
        is_vulnerable = bool(row.get("positive", False))
        detected = bool(row.get("detected", False))
        if not is_vulnerable or detected:
            continue
        misses.append(row)
        reason_counts = row.get("reason_counts", {})
        if not isinstance(reason_counts, dict):
            reason_counts = {}
        normalized = {str(k): int(v) for k, v in reason_counts.items() if int(v) > 0}
        if not normalized:
            missing_reason_rows.append(row)
            continue
        for reason, count in normalized.items():
            reason_counter[reason] += count

    return {
        "total_misses": len(misses),
        "covered_misses": len(misses) - len(missing_reason_rows),
        "uncovered_misses": len(missing_reason_rows),
        "passes": len(missing_reason_rows) == 0,
        "reason_counts": dict(sorted(reason_counter.items())),
        "uncovered_rows": [
            {
                "suite_name": row.get("suite_name"),
                "target_name": row.get("target_name"),
                "trial_idx": row.get("trial_idx"),
                "reason_counts": row.get("reason_counts"),
            }
            for row in missing_reason_rows
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate machine-readable miss root-cause coverage in benchmark outcomes."
    )
    parser.add_argument("--outcomes", required=True, help="Path to outcomes.json")
    parser.add_argument("--json-out", help="Optional JSON output path")
    parser.add_argument("--md-out", help="Optional Markdown output path")
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Return non-zero if any missed vulnerable run lacks reason categories",
    )
    args = parser.parse_args()

    outcomes_path = Path(args.outcomes)
    if not outcomes_path.is_file():
        raise SystemExit(f"outcomes file not found: {outcomes_path}")

    outcomes = _load_outcomes(outcomes_path)
    result = _misses_with_reason_coverage(outcomes)
    payload: dict[str, Any] = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "outcomes_path": str(outcomes_path),
        **result,
    }

    print(
        "Miss reason coverage: "
        f"{payload['covered_misses']}/{payload['total_misses']} "
        f"(uncovered={payload['uncovered_misses']}) "
        f"status={'PASS' if payload['passes'] else 'FAIL'}"
    )

    if args.json_out:
        json_out = Path(args.json_out)
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if args.md_out:
        md_out = Path(args.md_out)
        md_out.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# Miss Reason Coverage",
            "",
            f"Generated: `{payload['generated_utc']}`",
            "",
            f"- Total misses: `{payload['total_misses']}`",
            f"- Covered misses: `{payload['covered_misses']}`",
            f"- Uncovered misses: `{payload['uncovered_misses']}`",
            f"- Status: `{'PASS' if payload['passes'] else 'FAIL'}`",
            "",
            "## Reason Counts",
            "",
        ]
        if payload["reason_counts"]:
            for reason, count in payload["reason_counts"].items():
                lines.append(f"- `{reason}`: `{count}`")
        else:
            lines.append("- (none)")
        lines.append("")
        md_out.write_text("\n".join(lines), encoding="utf-8")

    if args.enforce and not payload["passes"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
