#!/usr/bin/env python3
"""Build a CVE portability report for clean-clone regression lanes."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def extract_circuit_paths(yaml_text: str) -> List[str]:
    paths: List[str] = []
    pattern = re.compile(r'^\s*circuit_path:\s*["\']?([^"\'#\n]+)')
    for line in yaml_text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        path = match.group(1).strip()
        if path:
            paths.append(path)
    return paths


def has_env_placeholder(path: str) -> bool:
    return "${" in path or bool(re.search(r"\$[A-Za-z_][A-Za-z0-9_]*", path))


def is_windows_absolute(path: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:[\\/]", path))


def is_unix_absolute(path: str) -> bool:
    return path.startswith("/")


def is_machine_specific_absolute(path: str) -> bool:
    if is_windows_absolute(path):
        return True
    if is_unix_absolute(path):
        return True
    return False


def classify_paths(paths: List[str], repo_root: Path) -> Dict[str, Any]:
    details: List[Dict[str, Any]] = []
    machine_specific_count = 0
    unresolved_placeholder_count = 0
    existing_relative_count = 0
    missing_relative_count = 0

    for path in paths:
        placeholder = has_env_placeholder(path)
        absolute = is_windows_absolute(path) or is_unix_absolute(path)
        machine_specific = is_machine_specific_absolute(path) if absolute else False

        if machine_specific:
            machine_specific_count += 1
        if placeholder:
            unresolved_placeholder_count += 1

        exists = False
        if not absolute and not placeholder:
            exists = (repo_root / path).exists()
            if exists:
                existing_relative_count += 1
            else:
                missing_relative_count += 1

        details.append(
            {
                "path": path,
                "has_env_placeholder": placeholder,
                "is_absolute": absolute,
                "is_machine_specific_absolute": machine_specific,
                "exists_if_repo_relative": exists,
            }
        )

    return {
        "total_paths": len(paths),
        "machine_specific_absolute_count": machine_specific_count,
        "env_placeholder_count": unresolved_placeholder_count,
        "existing_repo_relative_count": existing_relative_count,
        "missing_repo_relative_count": missing_relative_count,
        "paths": details,
    }


def run_lane(repo_root: Path, timeout_s: int) -> Dict[str, Any]:
    command = [
        "cargo",
        "test",
        "--test",
        "cve_regression_runner",
        "test_cve_regression_tests_execute",
        "--",
        "--exact",
        "--nocapture",
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
            "executed": 0,
            "skipped": 0,
            "total": 0,
            "stdout_tail": (exc.stdout or "")[-4000:],
            "stderr_tail": (exc.stderr or "")[-4000:],
        }

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    total = _extract_int(stdout, r"Total tests:\s*(\d+)")
    executed = _extract_int(stdout, r"Executed:\s*(\d+)")
    skipped = _extract_int(stdout, r"Skipped \(circuit not found\):\s*(\d+)")

    return {
        "command": command,
        "status": "pass" if proc.returncode == 0 else "fail",
        "timed_out": False,
        "exit_code": proc.returncode,
        "duration_s": duration_s,
        "total": total if total is not None else 0,
        "executed": executed if executed is not None else 0,
        "skipped": skipped if skipped is not None else 0,
        "stdout_tail": stdout[-4000:],
        "stderr_tail": stderr[-4000:],
    }


def _extract_int(text: str, pattern: str) -> Optional[int]:
    match = re.search(pattern, text)
    if not match:
        return None
    return int(match.group(1))


def build_summary(path_audit: Dict[str, Any], lane: Dict[str, Any]) -> Dict[str, Any]:
    lane_pass = lane.get("status") == "pass" and not lane.get("timed_out", False)
    has_machine_specific = path_audit["machine_specific_absolute_count"] > 0
    executed_count = int(lane.get("executed", 0))

    summary = {
        "lane_pass": lane_pass,
        "machine_specific_paths": has_machine_specific,
        "executed_regressions": executed_count,
        "overall_pass": lane_pass and not has_machine_specific and executed_count > 0,
    }
    return summary


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build clean-clone CVE portability report."
    )
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument(
        "--cve-db",
        default="templates/known_vulnerabilities.yaml",
        help="Path to known_vulnerabilities.yaml",
    )
    parser.add_argument(
        "--output",
        default="artifacts/portability/cve_portability_report.json",
        help="Output JSON report path",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=300,
        help="Lane command timeout in seconds",
    )
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Exit non-zero when portability checks fail",
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    cve_db_path = Path(args.cve_db)
    if not cve_db_path.is_absolute():
        cve_db_path = (repo_root / cve_db_path).resolve()

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = (repo_root / output_path).resolve()

    yaml_text = cve_db_path.read_text(encoding="utf-8")
    paths = extract_circuit_paths(yaml_text)
    path_audit = classify_paths(paths, repo_root)
    lane = run_lane(repo_root, args.timeout_seconds)
    summary = build_summary(path_audit, lane)

    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "repo_root": str(repo_root),
        "cve_database": str(cve_db_path),
        "path_audit": path_audit,
        "lane": lane,
        "summary": summary,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(
        "cve portability:",
        f"lane_pass={summary['lane_pass']}",
        f"machine_specific_paths={summary['machine_specific_paths']}",
        f"executed_regressions={summary['executed_regressions']}",
        f"overall_pass={summary['overall_pass']}",
        f"report={output_path}",
    )

    if args.enforce and not summary["overall_pass"]:
        print("enforce failed: CVE portability checks are not fully green")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
