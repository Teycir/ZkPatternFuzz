#!/usr/bin/env python3
"""Compute selector hit-rate from zk0d benchmark outcomes."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class HitStats:
    total: int = 0
    hits: int = 0

    def record(self, hit: bool) -> None:
        self.total += 1
        if hit:
            self.hits += 1

    @property
    def rate(self) -> float:
        if self.total == 0:
            return 0.0
        return self.hits / self.total


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _compute_selector_hit_metrics(outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    overall = HitStats()
    by_suite: dict[str, HitStats] = defaultdict(HitStats)
    by_target: dict[str, HitStats] = defaultdict(HitStats)

    for outcome in outcomes:
        suite = str(outcome.get("suite_name", "unknown"))
        target = str(outcome.get("target_name", "unknown"))
        hit = bool(outcome.get("attack_stage_reached", False))
        overall.record(hit)
        by_suite[suite].record(hit)
        by_target[f"{suite}::{target}"].record(hit)

    return {
        "total_runs": overall.total,
        "hits": overall.hits,
        "selector_hit_rate": overall.rate,
        "suites": {
            suite: {"total_runs": stats.total, "hits": stats.hits, "hit_rate": stats.rate}
            for suite, stats in sorted(by_suite.items())
        },
        "targets": {
            target: {"total_runs": stats.total, "hits": stats.hits, "hit_rate": stats.rate}
            for target, stats in sorted(by_target.items())
        },
    }


def _to_markdown(payload: dict[str, Any], min_hit_rate: float) -> str:
    lines = [
        "# Selector Hit-Rate Report",
        "",
        f"Generated: `{payload['generated_utc']}`",
        "",
        "## Global",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Total runs | {payload['total_runs']} |",
        f"| Hits | {payload['hits']} |",
        f"| Selector hit-rate | {payload['selector_hit_rate'] * 100:.1f}% |",
        f"| Threshold | {min_hit_rate * 100:.1f}% |",
        f"| Status | {'PASS' if payload['passes_threshold'] else 'FAIL'} |",
        "",
        "## Per Suite",
        "",
        "| Suite | Runs | Hits | Hit-rate |",
        "|---|---:|---:|---:|",
    ]
    for suite, row in payload["suites"].items():
        lines.append(
            f"| {suite} | {row['total_runs']} | {row['hits']} | {row['hit_rate'] * 100:.1f}% |"
        )

    lines.extend(
        [
            "",
            "## Per Target",
            "",
            "| Target | Runs | Hits | Hit-rate |",
            "|---|---:|---:|---:|",
        ]
    )
    for target, row in payload["targets"].items():
        lines.append(
            f"| {target} | {row['total_runs']} | {row['hits']} | {row['hit_rate'] * 100:.1f}% |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compute selector hit-rate from benchmark outcomes.json"
    )
    parser.add_argument("--outcomes", required=True, help="Path to benchmark outcomes.json")
    parser.add_argument(
        "--min-hit-rate",
        type=float,
        default=0.90,
        help="Minimum selector hit-rate threshold (default: 0.90)",
    )
    parser.add_argument(
        "--summary",
        help="Optional benchmark summary.json path; used for metadata only",
    )
    parser.add_argument("--json-out", help="Optional output path for JSON report")
    parser.add_argument("--md-out", help="Optional output path for Markdown report")
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Exit non-zero when hit-rate is below --min-hit-rate",
    )
    args = parser.parse_args()

    outcomes_path = Path(args.outcomes)
    if not outcomes_path.is_file():
        raise SystemExit(f"outcomes file not found: {outcomes_path}")

    outcomes = _load_json(outcomes_path)
    if not isinstance(outcomes, list):
        raise SystemExit(f"invalid outcomes schema (expected list): {outcomes_path}")

    metrics = _compute_selector_hit_metrics(outcomes)
    payload: dict[str, Any] = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "outcomes_path": str(outcomes_path),
        "summary_path": str(Path(args.summary)) if args.summary else None,
        **metrics,
    }
    payload["passes_threshold"] = payload["selector_hit_rate"] >= args.min_hit_rate

    print(
        "Selector hit-rate: "
        f"{payload['selector_hit_rate'] * 100:.1f}% "
        f"({payload['hits']}/{payload['total_runs']}) "
        f"threshold={args.min_hit_rate * 100:.1f}% "
        f"status={'PASS' if payload['passes_threshold'] else 'FAIL'}"
    )

    if args.json_out:
        json_out = Path(args.json_out)
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if args.md_out:
        md_out = Path(args.md_out)
        md_out.parent.mkdir(parents=True, exist_ok=True)
        md_out.write_text(_to_markdown(payload, args.min_hit_rate), encoding="utf-8")

    if args.enforce and not payload["passes_threshold"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
