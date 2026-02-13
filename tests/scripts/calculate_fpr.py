#!/usr/bin/env python3
"""Compute a simple false-positive-rate summary from safe-suite reports."""

from __future__ import annotations

import argparse
import json
import pathlib


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reports_dir", help="Directory containing safe-suite report JSON files")
    args = parser.parse_args()

    reports_dir = pathlib.Path(args.reports_dir)
    report_files = sorted(reports_dir.rglob("*.json"))

    runs = 0
    runs_with_findings = 0

    for report_file in report_files:
        try:
            payload = json.loads(report_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        runs += 1
        findings = payload.get("findings", []) if isinstance(payload, dict) else []
        if findings:
            runs_with_findings += 1

    fpr = (runs_with_findings / runs) if runs else 0.0

    print("# False Positive Report")
    print()
    print(f"- Safe-suite runs: {runs}")
    print(f"- Runs with findings: {runs_with_findings}")
    print(f"- Estimated false-positive rate: {fpr * 100:.2f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
