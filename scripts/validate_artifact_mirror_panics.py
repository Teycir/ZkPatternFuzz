#!/usr/bin/env python3
"""Validate benchmark outcomes for artifact-mirroring panic regressions."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PANIC_REASONS = ("artifact_mirror_panic_missing_command", "panic")


def _load_outcomes(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"Invalid outcomes schema at {path}: expected list")
    return data


def _panic_summary(outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    reason_counter: Counter[str] = Counter()
    affected_rows: list[dict[str, Any]] = []
    total_rows = len(outcomes)

    for row in outcomes:
        reason_counts = row.get("reason_counts", {})
        if not isinstance(reason_counts, dict):
            reason_counts = {}
        row_total = 0
        row_reasons: dict[str, int] = {}
        for reason in PANIC_REASONS:
            count = int(reason_counts.get(reason, 0))
            if count > 0:
                row_reasons[reason] = count
                row_total += count
                reason_counter[reason] += count
        if row_total > 0:
            affected_rows.append(
                {
                    "suite_name": row.get("suite_name"),
                    "target_name": row.get("target_name"),
                    "trial_idx": row.get("trial_idx"),
                    "panic_reason_counts": row_reasons,
                }
            )

    panic_total = sum(reason_counter.values())
    return {
        "total_runs": total_rows,
        "panic_occurrences": panic_total,
        "passes": panic_total == 0,
        "reason_counts": {k: int(v) for k, v in sorted(reason_counter.items())},
        "affected_rows": affected_rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate benchmark outcomes for artifact mirroring panic regressions."
    )
    parser.add_argument("--outcomes", required=True, help="Path to outcomes.json")
    parser.add_argument("--json-out", help="Optional JSON output path")
    parser.add_argument("--md-out", help="Optional Markdown output path")
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Return non-zero when panic regressions are detected",
    )
    args = parser.parse_args()

    outcomes_path = Path(args.outcomes)
    if not outcomes_path.is_file():
        raise SystemExit(f"outcomes file not found: {outcomes_path}")

    outcomes = _load_outcomes(outcomes_path)
    result = _panic_summary(outcomes)
    payload: dict[str, Any] = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "outcomes_path": str(outcomes_path),
        **result,
    }

    print(
        "Artifact-mirror panic regression: "
        f"occurrences={payload['panic_occurrences']} "
        f"runs={payload['total_runs']} "
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
            "# Artifact Mirror Panic Regression Check",
            "",
            f"Generated: `{payload['generated_utc']}`",
            "",
            f"- Total runs: `{payload['total_runs']}`",
            f"- Panic occurrences: `{payload['panic_occurrences']}`",
            f"- Status: `{'PASS' if payload['passes'] else 'FAIL'}`",
            "",
            "## Panic Reason Counts",
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
