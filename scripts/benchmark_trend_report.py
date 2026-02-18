#!/usr/bin/env python3
"""
Generate a compact nightly trend artifact from zk0d benchmark summaries.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional


def _latest_summary_path(benchmark_root: Path) -> Path:
    candidates = sorted(benchmark_root.glob("benchmark_*/summary.json"))
    if not candidates:
        raise FileNotFoundError(f"No summary.json found under {benchmark_root}")
    return candidates[-1]


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _pct(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    return f"{value * 100.0:.2f}%"


def _delta(curr: Optional[float], prev: Optional[float]) -> Optional[float]:
    if curr is None or prev is None:
        return None
    return curr - prev


def _format_delta(delta: Optional[float]) -> str:
    if delta is None:
        return "n/a"
    sign = "+" if delta >= 0 else ""
    return f"{sign}{delta * 100.0:.2f}pp"


def _last_history_entry(history_file: Path) -> Optional[Dict[str, Any]]:
    if not history_file.exists():
        return None
    lines = [line.strip() for line in history_file.read_text(encoding="utf-8").splitlines()]
    lines = [line for line in lines if line]
    if not lines:
        return None
    return json.loads(lines[-1])


def _extract_entry(summary: Dict[str, Any], summary_path: Path) -> Dict[str, Any]:
    return {
        "generated_utc": summary.get("generated_utc"),
        "summary_path": str(summary_path),
        "total_runs": int(summary.get("total_runs", 0)),
        "total_detected": int(summary.get("total_detected", 0)),
        "overall_completion_rate": float(summary.get("overall_completion_rate", 0.0)),
        "vulnerable_recall": float(summary.get("vulnerable_recall", 0.0)),
        "precision": float(summary.get("precision", 0.0)),
        "safe_false_positive_rate": float(summary.get("safe_false_positive_rate", 0.0)),
    }


def _write_markdown(path: Path, entry: Dict[str, Any], previous: Optional[Dict[str, Any]]) -> None:
    completion_delta = _delta(
        entry.get("overall_completion_rate"),
        previous.get("overall_completion_rate") if previous else None,
    )
    recall_delta = _delta(
        entry.get("vulnerable_recall"),
        previous.get("vulnerable_recall") if previous else None,
    )
    precision_delta = _delta(
        entry.get("precision"),
        previous.get("precision") if previous else None,
    )
    safe_fpr_delta = _delta(
        entry.get("safe_false_positive_rate"),
        previous.get("safe_false_positive_rate") if previous else None,
    )

    md = []
    md.append("# Benchmark Trend Report")
    md.append("")
    md.append(f"- Generated UTC: `{entry.get('generated_utc')}`")
    md.append(f"- Summary: `{entry.get('summary_path')}`")
    md.append("")
    md.append("| Metric | Current | Delta vs Previous |")
    md.append("|---|---:|---:|")
    md.append(
        f"| Completion rate | {_pct(entry.get('overall_completion_rate'))} | {_format_delta(completion_delta)} |"
    )
    md.append(
        f"| Vulnerable recall | {_pct(entry.get('vulnerable_recall'))} | {_format_delta(recall_delta)} |"
    )
    md.append(
        f"| Precision | {_pct(entry.get('precision'))} | {_format_delta(precision_delta)} |"
    )
    md.append(
        f"| Safe false-positive rate | {_pct(entry.get('safe_false_positive_rate'))} | {_format_delta(safe_fpr_delta)} |"
    )
    md.append("")
    md.append("| Count | Value |")
    md.append("|---|---:|")
    md.append(f"| Total runs | {entry.get('total_runs', 0)} |")
    md.append(f"| Total detected | {entry.get('total_detected', 0)} |")
    md.append("")

    if previous:
        md.append(f"- Previous generated UTC: `{previous.get('generated_utc')}`")
    else:
        md.append("- Previous generated UTC: `n/a`")
    md.append("")

    path.write_text("\n".join(md), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate benchmark trend artifacts.")
    parser.add_argument(
        "--benchmark-root",
        default="artifacts/benchmark_runs",
        help="Root directory containing benchmark_<timestamp>/summary.json",
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/benchmark_trends",
        help="Directory where trend artifacts are written",
    )
    parser.add_argument(
        "--history-file",
        default="artifacts/benchmark_trends/history.jsonl",
        help="JSONL file used to append trend entries",
    )
    args = parser.parse_args()

    benchmark_root = Path(args.benchmark_root)
    output_dir = Path(args.output_dir)
    history_file = Path(args.history_file)

    summary_path = _latest_summary_path(benchmark_root)
    summary = _load_json(summary_path)
    entry = _extract_entry(summary, summary_path)

    previous = _last_history_entry(history_file)

    output_dir.mkdir(parents=True, exist_ok=True)
    history_file.parent.mkdir(parents=True, exist_ok=True)

    (output_dir / "latest_trend.json").write_text(
        json.dumps(
            {
                "entry": entry,
                "previous": previous,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    _write_markdown(output_dir / "latest_trend.md", entry, previous)

    with history_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    print(f"Trend entry written: {output_dir / 'latest_trend.json'}")
    print(f"Trend report written: {output_dir / 'latest_trend.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

