#!/usr/bin/env python3
"""Generate manual exploitability label template from semantic report."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def find_default_report(search_root: Path) -> Optional[Path]:
    candidates = sorted(search_root.glob("**/semantic_track_report.json"))
    if not candidates:
        return None
    return candidates[-1]


def build_template(report: Dict[str, Any], source_report: str) -> Dict[str, Any]:
    run_id = str(report.get("run_id") or "").strip() or "unknown-run"
    labels: List[Dict[str, Any]] = []

    for violation in report.get("violations", []):
        if not isinstance(violation, dict):
            continue
        finding_id = str(violation.get("finding_id") or "").strip()
        if not finding_id:
            continue
        assessment = violation.get("assessment")
        predicted_exploitable = None
        if isinstance(assessment, dict) and isinstance(
            assessment.get("exploitable"), bool
        ):
            predicted_exploitable = assessment.get("exploitable")
        confidence = (
            int(assessment.get("confidence"))
            if isinstance(assessment, dict) and isinstance(assessment.get("confidence"), int)
            else None
        )
        labels.append(
            {
                "run_id": run_id,
                "finding_id": finding_id,
                "exploitable": None,
                "review_status": "pending",
                "review_notes": "",
                "predicted_exploitable": predicted_exploitable,
                "predicted_confidence": confidence,
                "detector": violation.get("detector"),
                "violation_summary": violation.get("violation_summary"),
            }
        )

    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source_report": source_report,
        "instructions": [
            "Set exploitable to true/false for each label after manual review.",
            "Set review_status to reviewed when completed.",
            "Leave predicted_* fields unchanged; they are model outputs for comparison.",
        ],
        "labels": labels,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate manual exploitability label template for semantic precision review."
    )
    parser.add_argument(
        "--search-root",
        default="artifacts/semantic_campaign",
        help="Root directory to locate semantic_track_report.json when --semantic-report is omitted",
    )
    parser.add_argument(
        "--semantic-report",
        default="",
        help="Optional explicit semantic_track_report.json path",
    )
    parser.add_argument(
        "--output",
        default="artifacts/semantic_exit/manual_labels_template.json",
        help="Output path for manual label template JSON",
    )
    args = parser.parse_args(argv)

    semantic_report_path: Optional[Path]
    if args.semantic_report:
        semantic_report_path = Path(args.semantic_report)
    else:
        semantic_report_path = find_default_report(Path(args.search_root))

    if semantic_report_path is None:
        print("no semantic report found")
        return 1

    report = load_json(semantic_report_path)
    template = build_template(report, str(semantic_report_path))

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(template, indent=2) + "\n", encoding="utf-8")
    print(
        "manual labels template:",
        f"report={semantic_report_path}",
        f"labels={len(template['labels'])}",
        f"output={output_path}",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
