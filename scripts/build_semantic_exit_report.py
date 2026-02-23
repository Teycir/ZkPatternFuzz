#!/usr/bin/env python3
"""Build semantic-track exit criteria report from emitted artifacts."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def discover_semantic_reports(search_root: Path) -> List[Path]:
    return sorted(
        path
        for path in search_root.glob("**/semantic_track_report.json")
        if path.is_file()
    )


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _extract_exploitable_predictions(report: Dict[str, Any]) -> Dict[str, bool]:
    predictions: Dict[str, bool] = {}
    for violation in report.get("violations", []):
        if not isinstance(violation, dict):
            continue
        finding_id = str(violation.get("finding_id") or "").strip()
        if not finding_id:
            continue
        assessment = violation.get("assessment")
        if isinstance(assessment, dict):
            predictions[finding_id] = bool(assessment.get("exploitable", False))
    return predictions


def _count_fix_suggestions(actionable_report: Optional[Dict[str, Any]]) -> int:
    if not isinstance(actionable_report, dict):
        return 0
    findings = actionable_report.get("findings")
    if not isinstance(findings, list):
        return 0
    count = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        suggestion = str(finding.get("fix_suggestion") or "").strip()
        if suggestion:
            count += 1
    return count


def parse_manual_labels(
    labels_payload: Dict[str, Any],
) -> List[Tuple[str, str, bool]]:
    labels = labels_payload.get("labels")
    if not isinstance(labels, list):
        return []
    parsed: List[Tuple[str, str, bool]] = []
    for item in labels:
        if not isinstance(item, dict):
            continue
        run_id = str(item.get("run_id") or "").strip()
        finding_id = str(item.get("finding_id") or "").strip()
        if not run_id or not finding_id:
            continue
        parsed.append((run_id, finding_id, bool(item.get("exploitable", False))))
    return parsed


def compute_manual_precision(
    manual_labels: Iterable[Tuple[str, str, bool]],
    predictions: Dict[Tuple[str, str], bool],
) -> Dict[str, Any]:
    matched = 0
    predicted_positive = 0
    true_positive = 0
    false_positive = 0

    for run_id, finding_id, expected_exploitable in manual_labels:
        key = (run_id, finding_id)
        if key not in predictions:
            continue
        matched += 1
        predicted = predictions[key]
        if not predicted:
            continue
        predicted_positive += 1
        if expected_exploitable:
            true_positive += 1
        else:
            false_positive += 1

    precision: Optional[float]
    if predicted_positive > 0:
        precision = true_positive / predicted_positive
    else:
        precision = None

    return {
        "matched_labels": matched,
        "predicted_positive": predicted_positive,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "precision": precision,
    }


def build_report(
    semantic_reports: List[Path],
    manual_labels_payload: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    run_rows: List[Dict[str, Any]] = []
    prediction_index: Dict[Tuple[str, str], bool] = {}

    total_intent_sources = 0
    total_semantic_violations = 0
    total_fix_suggestions = 0
    actionable_reports_with_suggestions = 0

    for report_path in semantic_reports:
        report = load_json(report_path)
        run_id = str(report.get("run_id") or report_path.parent.name)
        intents = int(report.get("extracted_intent_sources") or 0)
        violations = report.get("violations")
        violations_count = len(violations) if isinstance(violations, list) else 0

        actionable_path = report_path.parent / "semantic_actionable_report.json"
        actionable_report = load_json(actionable_path) if actionable_path.is_file() else None
        fix_suggestions = _count_fix_suggestions(actionable_report)

        predictions = _extract_exploitable_predictions(report)
        for finding_id, exploitable in predictions.items():
            prediction_index[(run_id, finding_id)] = exploitable

        total_intent_sources += intents
        total_semantic_violations += violations_count
        total_fix_suggestions += fix_suggestions
        if fix_suggestions > 0:
            actionable_reports_with_suggestions += 1

        run_rows.append(
            {
                "run_id": run_id,
                "report_path": str(report_path),
                "extracted_intent_sources": intents,
                "semantic_violations": violations_count,
                "fix_suggestions": fix_suggestions,
                "actionable_report_present": actionable_path.is_file(),
            }
        )

    manual_precision: Dict[str, Any]
    if manual_labels_payload is None:
        manual_precision = {
            "evaluated": False,
            "matched_labels": 0,
            "predicted_positive": 0,
            "true_positive": 0,
            "false_positive": 0,
            "precision": None,
        }
    else:
        labels = parse_manual_labels(manual_labels_payload)
        precision_stats = compute_manual_precision(labels, prediction_index)
        manual_precision = {"evaluated": True, **precision_stats}

    intents_target_met = total_intent_sources >= 20
    violations_target_met = total_semantic_violations >= 3
    actionable_target_met = actionable_reports_with_suggestions >= 1 and total_fix_suggestions >= 1
    precision_target_met = bool(
        manual_precision["evaluated"]
        and isinstance(manual_precision["precision"], float)
        and manual_precision["precision"] >= 0.8
    )

    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "semantic_runs": len(run_rows),
            "total_intent_sources": total_intent_sources,
            "total_semantic_violations": total_semantic_violations,
            "total_fix_suggestions": total_fix_suggestions,
            "actionable_reports_with_suggestions": actionable_reports_with_suggestions,
            "manual_precision": manual_precision,
        },
        "targets": {
            "intent_sources_ge_20": intents_target_met,
            "semantic_violations_ge_3": violations_target_met,
            "manual_precision_ge_0_80": precision_target_met,
            "actionable_reports_present": actionable_target_met,
            "overall_pass": intents_target_met
            and violations_target_met
            and actionable_target_met
            and (precision_target_met or not manual_precision["evaluated"]),
        },
        "runs": run_rows,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build semantic exit criteria report from semantic track artifacts."
    )
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument(
        "--search-root",
        default="artifacts",
        help="Directory to recursively scan for semantic_track_report.json",
    )
    parser.add_argument(
        "--manual-labels",
        default="",
        help="Optional JSON file with manual exploitability labels",
    )
    parser.add_argument(
        "--output",
        default="artifacts/semantic_exit/latest_report.json",
        help="Output JSON report path",
    )
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Exit non-zero if available targets are not met",
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    search_root = Path(args.search_root)
    if not search_root.is_absolute():
        search_root = (repo_root / search_root).resolve()

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = (repo_root / output_path).resolve()

    reports = discover_semantic_reports(search_root)
    manual_labels_payload: Optional[Dict[str, Any]] = None
    if args.manual_labels:
        labels_path = Path(args.manual_labels)
        if not labels_path.is_absolute():
            labels_path = (repo_root / labels_path).resolve()
        manual_labels_payload = load_json(labels_path)

    report = build_report(reports, manual_labels_payload)
    report["repo_root"] = str(repo_root)
    report["search_root"] = str(search_root)
    report["manual_labels_path"] = args.manual_labels or None

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    summary = report["summary"]
    targets = report["targets"]
    print(
        "semantic exit report:",
        f"runs={summary['semantic_runs']}",
        f"intent_sources={summary['total_intent_sources']}",
        f"semantic_violations={summary['total_semantic_violations']}",
        f"actionable_reports={summary['actionable_reports_with_suggestions']}",
        f"manual_precision={summary['manual_precision']['precision']}",
        f"overall_pass={targets['overall_pass']}",
        f"report={output_path}",
    )

    if args.enforce and not targets["overall_pass"]:
        print("enforce failed: semantic exit criteria are not met")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
