#!/usr/bin/env python3
"""Build a strict Z3 compatibility matrix from local environment and build lanes."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore


def parse_z3_version(raw: str) -> Optional[str]:
    match = re.search(r"(\d+\.\d+\.\d+)", raw)
    if not match:
        return None
    return match.group(1)


def get_z3_binary_info() -> Dict[str, Any]:
    try:
        proc = subprocess.run(
            ["z3", "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return {
            "installed": False,
            "version_raw": "",
            "version": None,
            "exit_code": None,
        }

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    raw = stdout or stderr
    return {
        "installed": proc.returncode == 0,
        "version_raw": raw,
        "version": parse_z3_version(raw),
        "exit_code": proc.returncode,
    }


def get_lock_solver_versions(lock_path: Path) -> Dict[str, List[str]]:
    if not lock_path.exists():
        return {}
    doc = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = doc.get("package")
    if not isinstance(packages, list):
        return {}

    versions: Dict[str, set[str]] = {}
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        if isinstance(name, str) and name in {"z3", "z3-sys"} and isinstance(version, str):
            versions.setdefault(name, set()).add(version)

    return {name: sorted(vals) for name, vals in sorted(versions.items())}


def _run_lane(repo_root: Path, lane_id: str, description: str, command: List[str], timeout_s: int) -> Dict[str, Any]:
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
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - started
        stdout = (exc.stdout or "")
        stderr = (exc.stderr or "")
        return {
            "id": lane_id,
            "description": description,
            "command": command,
            "status": "fail",
            "timed_out": True,
            "exit_code": None,
            "duration_s": round(duration, 3),
            "stdout_tail": stdout[-2000:],
            "stderr_tail": stderr[-2000:],
        }

    duration = time.monotonic() - started
    stdout = (proc.stdout or "")
    stderr = (proc.stderr or "")
    return {
        "id": lane_id,
        "description": description,
        "command": command,
        "status": "pass" if proc.returncode == 0 else "fail",
        "timed_out": timed_out,
        "exit_code": proc.returncode,
        "duration_s": round(duration, 3),
        "stdout_tail": stdout[-2000:],
        "stderr_tail": stderr[-2000:],
    }


def assess_matrix(z3_info: Dict[str, Any], lanes: List[Dict[str, Any]]) -> Dict[str, Any]:
    failed_lanes = [lane["id"] for lane in lanes if lane.get("status") != "pass"]
    dynamic_lanes = [lane for lane in lanes if lane["id"].endswith("_dynamic")]
    static_lanes = [lane for lane in lanes if lane["id"].endswith("_static") or lane["id"].startswith("workspace_static")]

    summary = {
        "dynamic_pass": all(lane.get("status") == "pass" for lane in dynamic_lanes),
        "static_pass": all(lane.get("status") == "pass" for lane in static_lanes),
        "z3_binary_installed": bool(z3_info.get("installed")),
        "failed_lanes": failed_lanes,
    }
    summary["overall_pass"] = (
        summary["dynamic_pass"]
        and summary["static_pass"]
        and summary["z3_binary_installed"]
        and not failed_lanes
    )
    return summary


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build Z3 compatibility matrix using strict offline cargo check lanes."
    )
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument(
        "--output",
        default="artifacts/dependency_tracking/z3_compatibility_matrix.json",
        help="Output matrix JSON path",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=900,
        help="Per-lane timeout in seconds",
    )
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Exit non-zero when matrix is not fully compatible",
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = (repo_root / output_path).resolve()

    z3_info = get_z3_binary_info()
    lock_versions = get_lock_solver_versions(repo_root / "Cargo.lock")

    lanes_cfg = [
        (
            "zk_constraints_dynamic",
            "zk-constraints default linkage",
            ["cargo", "check", "-q", "-p", "zk-constraints", "--locked", "--offline"],
        ),
        (
            "zk_symbolic_dynamic",
            "zk-symbolic default linkage",
            ["cargo", "check", "-q", "-p", "zk-symbolic", "--locked", "--offline"],
        ),
        (
            "zk_constraints_static",
            "zk-constraints with z3-static feature",
            [
                "cargo",
                "check",
                "-q",
                "-p",
                "zk-constraints",
                "--features",
                "z3-static",
                "--locked",
                "--offline",
            ],
        ),
        (
            "zk_symbolic_static",
            "zk-symbolic with z3-static feature",
            [
                "cargo",
                "check",
                "-q",
                "-p",
                "zk-symbolic",
                "--features",
                "z3-static",
                "--locked",
                "--offline",
            ],
        ),
        (
            "workspace_static_feature",
            "workspace check with z3-static feature",
            ["cargo", "check", "-q", "--features", "z3-static", "--locked", "--offline"],
        ),
    ]

    lanes = [
        _run_lane(repo_root, lane_id, description, command, args.timeout_seconds)
        for lane_id, description, command in lanes_cfg
    ]
    summary = assess_matrix(z3_info, lanes)

    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "repo_root": str(repo_root),
        "z3_binary": z3_info,
        "lock_solver_versions": lock_versions,
        "lanes": lanes,
        "summary": summary,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(
        "z3 compatibility matrix:",
        f"z3_installed={summary['z3_binary_installed']}",
        f"dynamic_pass={summary['dynamic_pass']}",
        f"static_pass={summary['static_pass']}",
        f"overall_pass={summary['overall_pass']}",
        f"failed_lanes={len(summary['failed_lanes'])}",
        f"report={output_path}",
    )

    if args.enforce and not summary["overall_pass"]:
        print("enforce failed: z3 compatibility matrix not fully green")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
