#!/usr/bin/env python3
"""Analyze circom_compilation_failed outcomes and map them to circuits/includes."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _load_target_map(suites_yaml: Path) -> dict[str, str]:
    with suites_yaml.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    suites = data.get("suites", {})
    mapping: dict[str, str] = {}
    for suite in suites.values():
        targets = suite.get("targets", [])
        for target in targets:
            name = target.get("name")
            circuit = target.get("target_circuit")
            if isinstance(name, str) and isinstance(circuit, str):
                mapping[name] = circuit
    return mapping


def _extract_includes(circuit_path: Path) -> list[str]:
    if not circuit_path.is_file():
        return []
    include_pattern = re.compile(r'^\s*include\s+"([^"]+)"\s*;')
    includes: list[str] = []
    for line in circuit_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        match = include_pattern.match(line)
        if match:
            includes.append(match.group(1))
    return includes


def _analyze(
    outcomes: list[dict[str, Any]],
    target_map: dict[str, str],
    repo_root: Path,
) -> dict[str, Any]:
    failed_targets: Counter[str] = Counter()
    for row in outcomes:
        reason_counts = row.get("reason_counts", {})
        if int(reason_counts.get("circom_compilation_failed", 0)) > 0:
            failed_targets[str(row.get("target_name"))] += 1

    target_rows = []
    include_counter: Counter[str] = Counter()
    for target_name, fail_count in sorted(failed_targets.items()):
        circuit_rel = target_map.get(target_name)
        circuit_abs = repo_root.joinpath(circuit_rel) if circuit_rel else None
        includes = _extract_includes(circuit_abs) if circuit_abs else []
        for inc in includes:
            include_counter[inc] += fail_count
        target_rows.append(
            {
                "target_name": target_name,
                "failure_count": fail_count,
                "target_circuit": circuit_rel,
                "includes": includes,
            }
        )

    return {
        "failed_target_count": len(target_rows),
        "circom_compilation_failed_occurrences": int(sum(failed_targets.values())),
        "failed_targets": target_rows,
        "include_import_counts": dict(sorted(include_counter.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze circom_compilation_failed benchmark outcomes."
    )
    parser.add_argument("--outcomes", required=True, help="Path to outcomes.json")
    parser.add_argument("--summary", required=True, help="Path to summary.json")
    parser.add_argument("--repo-root", default=".", help="Repo root for circuit path resolution")
    parser.add_argument("--suites-yaml", help="Optional explicit suites YAML path")
    parser.add_argument("--json-out", help="Optional JSON output path")
    parser.add_argument("--md-out", help="Optional Markdown output path")
    args = parser.parse_args()

    outcomes_path = Path(args.outcomes)
    summary_path = Path(args.summary)
    repo_root = Path(args.repo_root).resolve()
    if not outcomes_path.is_file():
        raise SystemExit(f"outcomes file not found: {outcomes_path}")
    if not summary_path.is_file():
        raise SystemExit(f"summary file not found: {summary_path}")

    outcomes = _load_json(outcomes_path)
    if not isinstance(outcomes, list):
        raise SystemExit("outcomes schema invalid: expected list")
    summary = _load_json(summary_path)
    if not isinstance(summary, dict):
        raise SystemExit("summary schema invalid: expected object")

    suites_yaml_value = args.suites_yaml
    if suites_yaml_value is None:
        suites_yaml_value = str(summary.get("config", {}).get("suites_path", ""))
    suites_yaml_path = repo_root.joinpath(suites_yaml_value) if suites_yaml_value else None
    target_map = {}
    if suites_yaml_path and suites_yaml_path.is_file():
        target_map = _load_target_map(suites_yaml_path)

    result = _analyze(outcomes, target_map, repo_root)
    payload = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "outcomes_path": str(outcomes_path),
        "summary_path": str(summary_path),
        "suites_yaml_path": str(suites_yaml_path) if suites_yaml_path else None,
        **result,
    }

    print(
        "Circom compilation failure analysis: "
        f"occurrences={payload['circom_compilation_failed_occurrences']} "
        f"targets={payload['failed_target_count']}"
    )

    if args.json_out:
        json_out = Path(args.json_out)
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if args.md_out:
        md_out = Path(args.md_out)
        md_out.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# Circom Compilation Failure Analysis",
            "",
            f"Generated: `{payload['generated_utc']}`",
            "",
            f"- Occurrences: `{payload['circom_compilation_failed_occurrences']}`",
            f"- Failed targets: `{payload['failed_target_count']}`",
            "",
            "## Failed Targets",
            "",
        ]
        if payload["failed_targets"]:
            for row in payload["failed_targets"]:
                lines.append(
                    f"- `{row['target_name']}` failures=`{row['failure_count']}` "
                    f"circuit=`{row.get('target_circuit')}`"
                )
        else:
            lines.append("- (none)")
        lines.append("")
        md_out.write_text("\n".join(lines), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
