#!/usr/bin/env python3
"""Combine validation markdown artifacts into a consolidated report."""

from __future__ import annotations

import argparse
import pathlib


SECTIONS = [
    ("0xPARC", "0xparc_summary.md"),
    ("False Positives", "false_positive_report.md"),
    ("Ground Truth", "ground_truth_report.md"),
    ("CVE", "cve_detection_report.md"),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reports_dir", help="Directory containing validation markdown files")
    args = parser.parse_args()

    root = pathlib.Path(args.reports_dir)
    print("# Validation Results")
    print()

    for title, file_name in SECTIONS:
        print(f"## {title}")
        path = root / file_name
        if path.exists():
            print(path.read_text(encoding="utf-8").strip())
        else:
            print("_No data yet._")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
