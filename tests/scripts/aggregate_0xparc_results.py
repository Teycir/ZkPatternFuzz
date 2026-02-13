#!/usr/bin/env python3
"""Aggregate 0xPARC validation JSON reports."""

from __future__ import annotations

import argparse
import json
import pathlib


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reports_dir", help="Directory containing 0xPARC report JSON files")
    args = parser.parse_args()

    reports_dir = pathlib.Path(args.reports_dir)
    report_files = sorted(reports_dir.rglob("*.json"))

    total_findings = 0
    for path in report_files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        total_findings += len(payload.get("findings", [])) if isinstance(payload, dict) else 0

    print("# 0xPARC Validation Summary")
    print()
    print(f"- Report files: {len(report_files)}")
    print(f"- Total findings: {total_findings}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
