#!/usr/bin/env python3
"""Build mutator validity stress report."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


SUMMARY_PATTERN = re.compile(
    r"mutator_stress_summary\s+total=(\d+)\s+invalid=(\d+)\s+invalid_rate=([0-9.]+)"
)


def parse_stress_summary(output: str) -> Optional[Dict[str, Any]]:
    match = SUMMARY_PATTERN.search(output)
    if not match:
        return None
    total = int(match.group(1))
    invalid = int(match.group(2))
    invalid_rate = float(match.group(3))
    return {
        "total_mutations": total,
        "invalid_out_of_field": invalid,
        "invalid_rate": invalid_rate,
    }


def run_stress_lane(repo_root: Path, timeout_s: int) -> Dict[str, Any]:
    command = [
        "cargo",
        "test",
        "-q",
        "-p",
        "zk-fuzzer-core",
        "mutators::tests::test_mutate_field_element_stress_summary",
        "--",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]

    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            cwd=str(repo_root),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        duration_s = round(time.monotonic() - started, 3)
    except subprocess.TimeoutExpired as exc:
        duration_s = round(time.monotonic() - started, 3)
        return {
            "command": command,
            "status": "fail",
            "timed_out": True,
            "exit_code": None,
            "duration_s": duration_s,
            "summary": None,
            "stdout_tail": (exc.stdout or "")[-4000:],
            "stderr_tail": (exc.stderr or "")[-4000:],
        }

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    summary = parse_stress_summary(stdout + "\n" + stderr)

    return {
        "command": command,
        "status": "pass" if proc.returncode == 0 else "fail",
        "timed_out": False,
        "exit_code": proc.returncode,
        "duration_s": duration_s,
        "summary": summary,
        "stdout_tail": stdout[-4000:],
        "stderr_tail": stderr[-4000:],
    }


def build_summary(lane: Dict[str, Any]) -> Dict[str, Any]:
    lane_pass = lane.get("status") == "pass" and not lane.get("timed_out", False)
    parsed = lane.get("summary") or {}
    total = int(parsed.get("total_mutations", 0))
    invalid = int(parsed.get("invalid_out_of_field", 0))
    invalid_rate = float(parsed.get("invalid_rate", 1.0)) if parsed else 1.0
    parsed_ok = bool(parsed)

    return {
        "lane_pass": lane_pass,
        "summary_parsed": parsed_ok,
        "total_mutations": total,
        "invalid_out_of_field": invalid,
        "invalid_rate": invalid_rate,
        "overall_pass": lane_pass and parsed_ok and total > 0 and invalid == 0 and invalid_rate == 0.0,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build mutator validity report from stress lane output."
    )
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument(
        "--output",
        default="artifacts/mutator_validity/latest_report.json",
        help="Output JSON report path",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=300,
        help="Stress lane timeout in seconds",
    )
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Exit non-zero when invalid mutation rate is non-zero",
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = (repo_root / output_path).resolve()

    lane = run_stress_lane(repo_root, args.timeout_seconds)
    summary = build_summary(lane)

    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "repo_root": str(repo_root),
        "lane": lane,
        "summary": summary,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(
        "mutator validity:",
        f"lane_pass={summary['lane_pass']}",
        f"summary_parsed={summary['summary_parsed']}",
        f"total_mutations={summary['total_mutations']}",
        f"invalid_out_of_field={summary['invalid_out_of_field']}",
        f"invalid_rate={summary['invalid_rate']:.9f}",
        f"overall_pass={summary['overall_pass']}",
        f"report={output_path}",
    )

    if args.enforce and not summary["overall_pass"]:
        print("enforce failed: mutator validity stress checks are not fully green")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
