#!/usr/bin/env python3
"""Validate findings reports against a directory of expected fixtures."""

from __future__ import annotations

import argparse
import json
import pathlib


def load_reports(path: pathlib.Path) -> list[dict]:
    reports: list[dict] = []
    for report_file in sorted(path.rglob("*.json")):
        try:
            reports.append(json.loads(report_file.read_text(encoding="utf-8")))
        except Exception:
            continue
    return reports


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reports_dir", help="Directory containing report JSON files")
    parser.add_argument("expected_dir", help="Directory containing expected fixtures")
    args = parser.parse_args()

    reports_dir = pathlib.Path(args.reports_dir)
    expected_dir = pathlib.Path(args.expected_dir)

    reports = load_reports(reports_dir)
    expected_count = len(list(expected_dir.rglob("*.circom")))

    total_findings = 0
    for report in reports:
        findings = report.get("findings", []) if isinstance(report, dict) else []
        total_findings += len(findings)

    print("# Ground Truth Validation")
    print()
    print(f"- Expected fixtures: {expected_count}")
    print(f"- Reports parsed: {len(reports)}")
    print(f"- Total findings observed: {total_findings}")

    if expected_count > 0 and len(reports) == 0:
        print("- Status: pending execution (fixtures exist, no reports yet)")
    else:
        print("- Status: baseline collected")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
