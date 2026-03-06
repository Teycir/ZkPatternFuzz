#!/usr/bin/env python3
"""Build a public validation corpus report from checked-in evidence."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_yaml(path: Path) -> Dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_manifest(path: Path) -> Dict[str, Any]:
    manifest = load_yaml(path)
    if not isinstance(manifest, dict):
        raise ValueError("validation corpus manifest must be a mapping")
    lanes = manifest.get("lanes")
    if not isinstance(lanes, list) or not lanes:
        raise ValueError("validation corpus manifest must define at least one lane")
    return manifest


def git_head(repo_root: Path) -> Optional[str]:
    try:
        return (
            subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                cwd=repo_root,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            .strip()
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def resolve(repo_root: Path, relative_path: str) -> Path:
    return repo_root / relative_path


def link_target(output_md: Path, repo_root: Path, relative_path: str) -> str:
    return os.path.relpath(resolve(repo_root, relative_path), start=output_md.parent)


def extract_markdown_conclusion(exploit_notes: Path) -> Optional[str]:
    capture = False
    for raw_line in exploit_notes.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line == "## Conclusion":
            capture = True
            continue
        if not capture:
            continue
        if not line:
            continue
        if line.startswith("#"):
            break
        return line.strip("`")
    return None


def summarize_benchmark_lane(lane: Dict[str, Any], repo_root: Path) -> Dict[str, Any]:
    evidence = lane["evidence_paths"]
    summary_path = resolve(repo_root, evidence["summary_json"])
    summary = load_json(summary_path)
    suites = summary.get("suites", [])
    positive_runs = sum(int(suite.get("runs_total", 0)) for suite in suites if suite.get("positive"))
    negative_runs = sum(
        int(suite.get("runs_total", 0)) for suite in suites if not suite.get("positive")
    )
    return {
        "status": "published_result",
        "positive_control_runs": positive_runs,
        "negative_control_runs": negative_runs,
        "total_runs": int(summary.get("total_runs", 0)),
        "vulnerable_recall": float(summary.get("vulnerable_recall", 0.0)),
        "vulnerable_high_confidence_recall": float(
            summary.get("vulnerable_high_confidence_recall", 0.0)
        ),
        "safe_false_positive_rate": float(summary.get("safe_false_positive_rate", 0.0)),
        "safe_high_confidence_false_positive_rate": float(
            summary.get("safe_high_confidence_false_positive_rate", 0.0)
        ),
        "overall_completion_rate": float(summary.get("overall_completion_rate", 0.0)),
        "suite_rows": [
            {
                "suite_name": suite.get("suite_name", ""),
                "positive": bool(suite.get("positive", False)),
                "runs_total": int(suite.get("runs_total", 0)),
                "detection_rate": float(suite.get("detection_rate", 0.0)),
                "high_confidence_detection_rate": float(
                    suite.get("high_confidence_detection_rate", 0.0)
                ),
            }
            for suite in suites
        ],
    }


def summarize_replay_lane(lane: Dict[str, Any], repo_root: Path) -> Dict[str, Any]:
    evidence = lane["evidence_paths"]
    exploit_notes = resolve(repo_root, evidence["exploit_notes"])
    replay_command = resolve(repo_root, evidence["replay_command"]).read_text(
        encoding="utf-8"
    ).strip()
    conclusion = extract_markdown_conclusion(exploit_notes) or "unknown"
    return {
        "status": "replay_bundle_present",
        "conclusion": conclusion,
        "replay_command": replay_command,
    }


def summarize_semantic_lane(lane: Dict[str, Any], repo_root: Path) -> Dict[str, Any]:
    evidence = lane["evidence_paths"]
    summary = load_json(resolve(repo_root, evidence["summary_json"]))
    semantic_summary = summary.get("summary", {})
    targets = summary.get("targets", {})
    return {
        "status": "pass" if targets.get("overall_pass") else "needs_review",
        "semantic_runs": int(semantic_summary.get("semantic_runs", 0)),
        "total_intent_sources": int(semantic_summary.get("total_intent_sources", 0)),
        "total_semantic_violations": int(
            semantic_summary.get("total_semantic_violations", 0)
        ),
        "total_fix_suggestions": int(semantic_summary.get("total_fix_suggestions", 0)),
        "overall_pass": bool(targets.get("overall_pass", False)),
    }


def summarize_cve_lane(lane: Dict[str, Any], repo_root: Path) -> Dict[str, Any]:
    evidence = lane["evidence_paths"]
    catalog = load_yaml(resolve(repo_root, evidence["catalog_yaml"]))
    vulnerabilities = catalog.get("vulnerabilities", [])
    fixture_dir = resolve(repo_root, evidence["fixtures_dir"])
    bundled_fixtures = sorted(
        path.name for path in fixture_dir.glob("*.circom") if path.is_file()
    )
    enabled_regressions = 0
    bundled_fixture_refs = 0
    for vulnerability in vulnerabilities:
        regression = vulnerability.get("regression_test", {})
        if regression.get("enabled"):
            enabled_regressions += 1
        circuit_path = str(regression.get("circuit_path", ""))
        if circuit_path.startswith("tests/cve_fixtures/"):
            bundled_fixture_refs += 1
    return {
        "status": "checked_in_regression_lane",
        "catalog_entries": len(vulnerabilities),
        "enabled_regressions": enabled_regressions,
        "bundled_fixture_refs": bundled_fixture_refs,
        "bundled_fixture_files": len(bundled_fixtures),
    }


def summarize_lane(lane: Dict[str, Any], repo_root: Path) -> Dict[str, Any]:
    evidence_paths = lane.get("evidence_paths", {})
    required_paths = {
        key: value for key, value in evidence_paths.items() if isinstance(value, str)
    }
    missing_paths = [
        relative_path
        for relative_path in required_paths.values()
        if not resolve(repo_root, relative_path).exists()
    ]
    kind = lane.get("kind")
    if kind == "benchmark_publication":
        details = summarize_benchmark_lane(lane, repo_root)
    elif kind == "deterministic_replay":
        details = summarize_replay_lane(lane, repo_root)
    elif kind == "semantic_validation":
        details = summarize_semantic_lane(lane, repo_root)
    elif kind == "cve_regression_lane":
        details = summarize_cve_lane(lane, repo_root)
    else:
        details = {"status": "unknown_lane_kind"}

    return {
        "id": lane.get("id", ""),
        "kind": kind,
        "title": lane.get("title", ""),
        "description": lane.get("description", ""),
        "rerun_command": lane.get("rerun_command", ""),
        "evidence_paths": required_paths,
        "missing_paths": missing_paths,
        "all_evidence_present": not missing_paths,
        "details": details,
    }


def build_summary(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    benchmark_rows = [row for row in rows if row["kind"] == "benchmark_publication"]
    replay_rows = [row for row in rows if row["kind"] == "deterministic_replay"]
    semantic_rows = [row for row in rows if row["kind"] == "semantic_validation"]
    cve_rows = [row for row in rows if row["kind"] == "cve_regression_lane"]

    return {
        "lane_count": len(rows),
        "lanes_with_all_evidence_present": sum(1 for row in rows if row["all_evidence_present"]),
        "published_benchmark_runs": sum(
            row["details"].get("total_runs", 0) for row in benchmark_rows
        ),
        "published_positive_control_runs": sum(
            row["details"].get("positive_control_runs", 0) for row in benchmark_rows
        ),
        "published_negative_control_runs": sum(
            row["details"].get("negative_control_runs", 0) for row in benchmark_rows
        ),
        "deterministic_replay_cases": len(replay_rows),
        "semantic_validation_runs": sum(
            row["details"].get("semantic_runs", 0) for row in semantic_rows
        ),
        "semantic_overall_pass_lanes": sum(
            1 for row in semantic_rows if row["details"].get("overall_pass")
        ),
        "cve_catalog_entries": sum(
            row["details"].get("catalog_entries", 0) for row in cve_rows
        ),
        "cve_enabled_regressions": sum(
            row["details"].get("enabled_regressions", 0) for row in cve_rows
        ),
        "bundled_cve_fixture_files": sum(
            row["details"].get("bundled_fixture_files", 0) for row in cve_rows
        ),
        "overall_evidence_present": all(row["all_evidence_present"] for row in rows),
    }


def build_report(manifest: Dict[str, Any], repo_root: Path) -> Dict[str, Any]:
    rows = [summarize_lane(lane, repo_root) for lane in manifest.get("lanes", [])]
    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "schema_version": manifest.get("schema_version", "1"),
        "title": manifest.get("title", "Validation Corpus"),
        "repo_commit": git_head(repo_root),
        "summary": build_summary(rows),
        "lanes": rows,
    }


def render_markdown(report: Dict[str, Any], repo_root: Path, output_md: Path) -> str:
    summary = report["summary"]
    lines: List[str] = []
    lines.append(f"# {report['title']}")
    lines.append("")
    lines.append(
        "This document is generated from the checked-in validation corpus manifest and points at the current public evidence lanes."
    )
    lines.append("")
    lines.append(f"- Generated: `{report['generated_utc']}`")
    if report.get("repo_commit"):
        lines.append(f"- Repo commit: `{report['repo_commit']}`")
    lines.append(f"- Registered lanes: `{summary['lane_count']}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(
        f"- Published benchmark coverage: `{summary['published_benchmark_runs']}` runs "
        f"(`{summary['published_positive_control_runs']}` vulnerable controls, "
        f"`{summary['published_negative_control_runs']}` safe controls)"
    )
    lines.append(
        f"- Deterministic replay cases: `{summary['deterministic_replay_cases']}`"
    )
    lines.append(
        f"- Semantic validation runs: `{summary['semantic_validation_runs']}` "
        f"across `{summary['semantic_overall_pass_lanes']}` passing semantic lanes"
    )
    lines.append(
        f"- CVE regression catalog: `{summary['cve_catalog_entries']}` entries, "
        f"`{summary['cve_enabled_regressions']}` enabled regression definitions, "
        f"`{summary['bundled_cve_fixture_files']}` bundled fixture files"
    )
    lines.append(
        f"- Evidence files present for all lanes: `{str(summary['overall_evidence_present']).lower()}`"
    )
    lines.append("")
    lines.append("## Registered Lanes")
    lines.append("")
    lines.append("| Lane | Kind | Status | Scope | Primary Evidence |")
    lines.append("| --- | --- | --- | --- | --- |")

    for row in report["lanes"]:
        details = row["details"]
        if row["kind"] == "benchmark_publication":
            scope = (
                f"{details['positive_control_runs']} vulnerable / "
                f"{details['negative_control_runs']} safe runs"
            )
            primary = row["evidence_paths"]["summary_json"]
        elif row["kind"] == "deterministic_replay":
            scope = details.get("conclusion", "unknown")
            primary = row["evidence_paths"]["replay_log"]
        elif row["kind"] == "semantic_validation":
            scope = (
                f"{details['semantic_runs']} run, "
                f"{details['total_semantic_violations']} violations"
            )
            primary = row["evidence_paths"]["summary_json"]
        else:
            scope = (
                f"{details['catalog_entries']} catalog entries / "
                f"{details['bundled_fixture_files']} fixtures"
            )
            primary = row["evidence_paths"]["catalog_yaml"]

        primary_link = f"[`{primary}`]({link_target(output_md, repo_root, primary)})"
        lines.append(
            f"| `{row['id']}` | `{row['kind']}` | `{details.get('status', 'unknown')}` | {scope} | {primary_link} |"
        )

    for row in report["lanes"]:
        details = row["details"]
        lines.append("")
        lines.append(f"## {row['title']}")
        lines.append("")
        lines.append(row["description"])
        lines.append("")
        lines.append(f"- Lane ID: `{row['id']}`")
        lines.append(f"- Kind: `{row['kind']}`")
        lines.append(f"- Status: `{details.get('status', 'unknown')}`")
        if row["missing_paths"]:
            lines.append(
                f"- Missing evidence paths: {', '.join(f'`{path}`' for path in row['missing_paths'])}"
            )
        else:
            lines.append("- Missing evidence paths: none")
        lines.append(f"- Rerun command: `{row['rerun_command']}`")

        if row["kind"] == "benchmark_publication":
            lines.append(
                f"- Current published recall: `{details['vulnerable_recall']:.1%}`"
            )
            lines.append(
                f"- Current published high-confidence recall: `{details['vulnerable_high_confidence_recall']:.1%}`"
            )
            lines.append(
                f"- Current published safe actionable false-positive rate: `{details['safe_false_positive_rate']:.1%}`"
            )
            lines.append(
                f"- Current published safe high-confidence false-positive rate: `{details['safe_high_confidence_false_positive_rate']:.1%}`"
            )
        elif row["kind"] == "deterministic_replay":
            lines.append(f"- Replay conclusion: `{details['conclusion']}`")
        elif row["kind"] == "semantic_validation":
            lines.append(
                f"- Intent sources extracted: `{details['total_intent_sources']}`"
            )
            lines.append(
                f"- Semantic violations: `{details['total_semantic_violations']}`"
            )
            lines.append(
                f"- Fix suggestions emitted: `{details['total_fix_suggestions']}`"
            )
            lines.append(f"- Overall pass: `{str(details['overall_pass']).lower()}`")
        elif row["kind"] == "cve_regression_lane":
            lines.append(
                f"- Catalog entries: `{details['catalog_entries']}`"
            )
            lines.append(
                f"- Enabled regression definitions: `{details['enabled_regressions']}`"
            )
            lines.append(
                f"- Bundled fixture references: `{details['bundled_fixture_refs']}`"
            )
            lines.append(
                f"- Bundled fixture files: `{details['bundled_fixture_files']}`"
            )

        lines.append("- Evidence paths:")
        for key, relative_path in row["evidence_paths"].items():
            lines.append(
                f"  - `{key}`: [`{relative_path}`]({link_target(output_md, repo_root, relative_path)})"
            )

    lines.append("")
    lines.append("## Source Of Truth")
    lines.append("")
    lines.append(
        f"- Manifest: [`docs/validation_corpus_manifest.yaml`]({link_target(output_md, repo_root, 'docs/validation_corpus_manifest.yaml')})"
    )
    lines.append(
        f"- Generator: [`scripts/build_validation_corpus_report.py`]({link_target(output_md, repo_root, 'scripts/build_validation_corpus_report.py')})"
    )
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a validation corpus report from checked-in evidence."
    )
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument(
        "--manifest",
        default="docs/validation_corpus_manifest.yaml",
        help="Validation corpus manifest path",
    )
    parser.add_argument(
        "--output-json",
        default="artifacts/validation/latest_report.json",
        help="Output JSON report path",
    )
    parser.add_argument(
        "--output-md",
        default="docs/VALIDATION_CORPUS.md",
        help="Output Markdown report path",
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    manifest_path = (repo_root / args.manifest).resolve()
    output_json = (repo_root / args.output_json).resolve()
    output_md = (repo_root / args.output_md).resolve()

    manifest = load_manifest(manifest_path)
    report = build_report(manifest, repo_root)

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(
        render_markdown(report, repo_root, output_md),
        encoding="utf-8",
    )

    print(
        "validation corpus report:",
        f"lanes={report['summary']['lane_count']}",
        f"benchmark_runs={report['summary']['published_benchmark_runs']}",
        f"replays={report['summary']['deterministic_replay_cases']}",
        f"semantic_runs={report['summary']['semantic_validation_runs']}",
        f"cve_entries={report['summary']['cve_catalog_entries']}",
        f"output_json={output_json}",
        f"output_md={output_md}",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
