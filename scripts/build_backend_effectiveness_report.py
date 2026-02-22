#!/usr/bin/env python3
"""Build a per-backend effectiveness report from benchmark artifacts."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


DEFAULT_REQUIRED_BACKENDS = ("circom", "noir", "cairo", "halo2")


def normalize_backend(raw: Any) -> str:
    text = str(raw or "").strip().lower()
    return text if text else "unknown"


def discover_latest_paths(benchmark_root: Path) -> Tuple[Path, Path]:
    candidates = sorted(benchmark_root.glob("benchmark_*/summary.json"))
    if not candidates:
        raise FileNotFoundError(f"No benchmark summary.json found under {benchmark_root}")

    summary_path = candidates[-1]
    outcomes_path = summary_path.with_name("outcomes.json")
    if not outcomes_path.is_file():
        raise FileNotFoundError(f"Missing outcomes.json at {outcomes_path}")

    return summary_path, outcomes_path


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _parse_bool(value: str, default: bool = True) -> bool:
    text = value.strip().lower()
    if text in {"true", "yes", "1"}:
        return True
    if text in {"false", "no", "0"}:
        return False
    return default


def parse_suite_targets(
    yaml_text: str,
    selected_suites: Optional[Iterable[str]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Parse target name -> metadata mapping from benchmark suites YAML text."""

    selected = {name.strip() for name in (selected_suites or []) if str(name).strip()}
    use_all = not selected

    suite_re = re.compile(r"^\s{2}([A-Za-z0-9_\-]+):\s*$")
    positive_re = re.compile(r"^\s{4}positive:\s*(true|false)\s*$", re.IGNORECASE)
    target_name_re = re.compile(r"^\s{6}-\s+name:\s*(.+?)\s*$")
    framework_re = re.compile(r"^\s{8}framework:\s*(.+?)\s*$")
    enabled_re = re.compile(r"^\s{8}enabled:\s*(.+?)\s*$")

    suite_name: Optional[str] = None
    suite_positive = False
    current_target: Optional[Dict[str, Any]] = None

    target_map: Dict[str, Dict[str, Any]] = {}

    def finalize_target() -> None:
        nonlocal current_target
        if current_target is None:
            return
        target_name = current_target.get("name")
        if target_name:
            include_suite = use_all or (suite_name in selected)
            if include_suite:
                target_map[str(target_name)] = {
                    "framework": normalize_backend(current_target.get("framework")),
                    "positive": bool(current_target.get("positive", False)),
                    "enabled": bool(current_target.get("enabled", True)),
                    "suite_name": suite_name or "",
                    "target_name": str(target_name),
                }
        current_target = None

    for raw_line in yaml_text.splitlines():
        line = raw_line.rstrip("\n")

        suite_match = suite_re.match(line)
        if suite_match:
            finalize_target()
            suite_name = suite_match.group(1).strip()
            suite_positive = False
            continue

        positive_match = positive_re.match(line)
        if positive_match:
            suite_positive = _parse_bool(positive_match.group(1), default=False)
            continue

        target_match = target_name_re.match(line)
        if target_match:
            finalize_target()
            current_target = {
                "name": _strip_quotes(target_match.group(1).strip()),
                "framework": "",
                "positive": suite_positive,
                "enabled": True,
            }
            continue

        if current_target is None:
            continue

        framework_match = framework_re.match(line)
        if framework_match:
            current_target["framework"] = _strip_quotes(framework_match.group(1).strip())
            continue

        enabled_match = enabled_re.match(line)
        if enabled_match:
            current_target["enabled"] = _parse_bool(enabled_match.group(1), default=True)
            continue

    finalize_target()
    return target_map


def load_suite_target_map(
    summary: Dict[str, Any],
    repo_root: Path,
) -> Dict[str, Any]:
    config = summary.get("config") if isinstance(summary.get("config"), dict) else {}
    suites_path_raw = config.get("suites_path")
    selected_suites = config.get("selected_suites")

    if not isinstance(suites_path_raw, str) or not suites_path_raw.strip():
        return {
            "source": "none",
            "suites_path": None,
            "selected_suites": [],
            "targets": {},
        }

    suites_path = Path(suites_path_raw)
    if not suites_path.is_absolute():
        suites_path = (repo_root / suites_path).resolve()

    if not suites_path.is_file():
        return {
            "source": "missing_file",
            "suites_path": str(suites_path),
            "selected_suites": selected_suites if isinstance(selected_suites, list) else [],
            "targets": {},
        }

    text = suites_path.read_text(encoding="utf-8")
    targets = parse_suite_targets(
        text,
        selected_suites if isinstance(selected_suites, list) else None,
    )

    return {
        "source": "parsed",
        "suites_path": str(suites_path),
        "selected_suites": selected_suites if isinstance(selected_suites, list) else [],
        "targets": targets,
    }


def _assign_backend(
    outcome: Dict[str, Any],
    target_map: Dict[str, Dict[str, Any]],
) -> Tuple[str, str]:
    framework = normalize_backend(outcome.get("framework"))
    if framework != "unknown":
        return framework, "outcome.framework"

    target_name = str(outcome.get("target_name") or "")
    target_info = target_map.get(target_name)
    if target_info:
        mapped = normalize_backend(target_info.get("framework"))
        if mapped != "unknown":
            return mapped, "suite_target_map"

    return "unknown", "unresolved"


def compute_backend_rows(
    outcomes: Sequence[Dict[str, Any]],
    target_map: Dict[str, Dict[str, Any]],
    required_backends: Sequence[str],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    required = [normalize_backend(item) for item in required_backends if normalize_backend(item) != "unknown"]
    rows: Dict[str, Dict[str, Any]] = {}

    for backend in required:
        rows[backend] = {
            "backend": backend,
            "target_counts": {
                "total": 0,
                "vulnerable": 0,
                "safe": 0,
            },
            "run_counts": {
                "total": 0,
                "vulnerable": 0,
                "safe": 0,
            },
            "detections": {
                "true_positives": 0,
                "false_positives": 0,
                "high_conf_true_positives": 0,
                "high_conf_false_positives": 0,
            },
            "metrics": {
                "recall": 0.0,
                "precision": 0.0,
                "high_conf_recall": 0.0,
                "high_conf_precision": 0.0,
                "true_positive_contribution_share": 0.0,
            },
        }

    for item in target_map.values():
        backend = normalize_backend(item.get("framework"))
        if backend not in rows:
            continue
        if not bool(item.get("enabled", True)):
            continue
        rows[backend]["target_counts"]["total"] += 1
        if bool(item.get("positive", False)):
            rows[backend]["target_counts"]["vulnerable"] += 1
        else:
            rows[backend]["target_counts"]["safe"] += 1

    assignment_counts: Dict[str, int] = {
        "outcome.framework": 0,
        "suite_target_map": 0,
        "unresolved": 0,
    }
    unresolved_runs = 0
    non_required_runs = 0

    for outcome in outcomes:
        backend, source = _assign_backend(outcome, target_map)
        assignment_counts[source] = assignment_counts.get(source, 0) + 1

        if backend not in rows:
            if backend == "unknown":
                unresolved_runs += 1
            else:
                non_required_runs += 1
            continue

        positive = bool(outcome.get("positive", False))
        detected = bool(outcome.get("detected", False))
        high_conf_detected = bool(outcome.get("high_confidence_detected", False))

        rows[backend]["run_counts"]["total"] += 1
        if positive:
            rows[backend]["run_counts"]["vulnerable"] += 1
            if detected:
                rows[backend]["detections"]["true_positives"] += 1
            if high_conf_detected:
                rows[backend]["detections"]["high_conf_true_positives"] += 1
        else:
            rows[backend]["run_counts"]["safe"] += 1
            if detected:
                rows[backend]["detections"]["false_positives"] += 1
            if high_conf_detected:
                rows[backend]["detections"]["high_conf_false_positives"] += 1

    total_tp = sum(rows[backend]["detections"]["true_positives"] for backend in required)
    total_high_conf_tp = sum(
        rows[backend]["detections"]["high_conf_true_positives"] for backend in required
    )

    for backend in required:
        row = rows[backend]
        vulnerable_runs = row["run_counts"]["vulnerable"]
        tp = row["detections"]["true_positives"]
        fp = row["detections"]["false_positives"]
        high_conf_tp = row["detections"]["high_conf_true_positives"]
        high_conf_fp = row["detections"]["high_conf_false_positives"]

        row["metrics"]["recall"] = round(tp / vulnerable_runs, 6) if vulnerable_runs else 0.0
        row["metrics"]["high_conf_recall"] = (
            round(high_conf_tp / vulnerable_runs, 6) if vulnerable_runs else 0.0
        )

        precision_denom = tp + fp
        high_conf_precision_denom = high_conf_tp + high_conf_fp
        row["metrics"]["precision"] = (
            round(tp / precision_denom, 6) if precision_denom else 0.0
        )
        row["metrics"]["high_conf_precision"] = (
            round(high_conf_tp / high_conf_precision_denom, 6)
            if high_conf_precision_denom
            else 0.0
        )

        row["metrics"]["true_positive_contribution_share"] = (
            round(tp / total_tp, 6) if total_tp else 0.0
        )
        row["metrics"]["high_conf_true_positive_contribution_share"] = (
            round(high_conf_tp / total_high_conf_tp, 6) if total_high_conf_tp else 0.0
        )

    ordered = [rows[backend] for backend in required]
    diagnostics = {
        "assignment_source_counts": assignment_counts,
        "unresolved_backend_runs": unresolved_runs,
        "non_required_backend_runs": non_required_runs,
        "total_true_positives": total_tp,
        "total_high_conf_true_positives": total_high_conf_tp,
    }
    return ordered, diagnostics


def build_summary(
    rows: Sequence[Dict[str, Any]],
    diagnostics: Dict[str, Any],
    required_backends: Sequence[str],
) -> Dict[str, Any]:
    required = [normalize_backend(item) for item in required_backends]
    present = [str(row.get("backend", "")) for row in rows]

    missing = [backend for backend in required if backend not in present]
    zero_run_backends = [
        str(row.get("backend", ""))
        for row in rows
        if int(((row.get("run_counts") or {}).get("total", 0)) == 0)
    ]

    total_runs = sum(int((row.get("run_counts") or {}).get("total", 0)) for row in rows)
    total_targets = sum(int((row.get("target_counts") or {}).get("total", 0)) for row in rows)

    max_share_backend = ""
    max_share = -1.0
    for row in rows:
        share = float(((row.get("metrics") or {}).get("true_positive_contribution_share", 0.0)))
        if share > max_share:
            max_share = share
            max_share_backend = str(row.get("backend", ""))

    unresolved_runs = int(diagnostics.get("unresolved_backend_runs", 0))

    return {
        "required_backends": required,
        "missing_required_backends": missing,
        "zero_run_backends": zero_run_backends,
        "total_runs_across_required_backends": total_runs,
        "total_targets_across_required_backends": total_targets,
        "dominant_true_positive_backend": max_share_backend if max_share >= 0.0 else "",
        "dominant_true_positive_share": round(max_share, 6) if max_share >= 0 else 0.0,
        "unresolved_backend_runs": unresolved_runs,
        "overall_pass": len(missing) == 0 and unresolved_runs == 0,
    }


def parse_required_backends(raw: str) -> List[str]:
    parts = [normalize_backend(item) for item in raw.split(",") if item.strip()]
    return [item for item in parts if item != "unknown"]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build per-backend effectiveness report from benchmark summary/outcomes."
    )
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument(
        "--benchmark-root",
        default="artifacts/benchmark_runs_fast",
        help="Benchmark root used for auto-discovery",
    )
    parser.add_argument("--summary", help="Explicit benchmark summary.json path")
    parser.add_argument("--outcomes", help="Explicit benchmark outcomes.json path")
    parser.add_argument(
        "--required-backends",
        default=",".join(DEFAULT_REQUIRED_BACKENDS),
        help="Comma-separated backend list",
    )
    parser.add_argument(
        "--output",
        default="artifacts/backend_effectiveness/latest_report.json",
        help="Output JSON report path",
    )
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Exit non-zero when report health checks fail",
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    benchmark_root = Path(args.benchmark_root)
    if not benchmark_root.is_absolute():
        benchmark_root = (repo_root / benchmark_root).resolve()

    summary_path = Path(args.summary).resolve() if args.summary else None
    outcomes_path = Path(args.outcomes).resolve() if args.outcomes else None

    if summary_path is None or outcomes_path is None:
        discovered_summary, discovered_outcomes = discover_latest_paths(benchmark_root)
        if summary_path is None:
            summary_path = discovered_summary
        if outcomes_path is None:
            outcomes_path = discovered_outcomes

    if summary_path is None or not summary_path.is_file():
        raise FileNotFoundError(f"Benchmark summary.json not found: {summary_path}")
    if outcomes_path is None or not outcomes_path.is_file():
        raise FileNotFoundError(f"Benchmark outcomes.json not found: {outcomes_path}")

    summary_payload = json.loads(summary_path.read_text(encoding="utf-8"))
    outcomes_payload = json.loads(outcomes_path.read_text(encoding="utf-8"))

    if not isinstance(outcomes_payload, list):
        raise ValueError(f"Outcomes payload must be a list: {outcomes_path}")

    required_backends = parse_required_backends(args.required_backends)
    if not required_backends:
        raise ValueError("--required-backends resolved to an empty list")

    suite_map_payload = load_suite_target_map(summary_payload, repo_root)
    target_map = suite_map_payload.get("targets")
    if not isinstance(target_map, dict):
        target_map = {}

    rows, diagnostics = compute_backend_rows(
        outcomes_payload,
        target_map,
        required_backends,
    )
    summary = build_summary(rows, diagnostics, required_backends)

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = (repo_root / output_path).resolve()

    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "repo_root": str(repo_root),
        "inputs": {
            "summary_path": str(summary_path),
            "outcomes_path": str(outcomes_path),
            "benchmark_root": str(benchmark_root),
            "required_backends": required_backends,
        },
        "suite_target_map": {
            "source": suite_map_payload.get("source"),
            "suites_path": suite_map_payload.get("suites_path"),
            "selected_suites": suite_map_payload.get("selected_suites"),
            "target_count": len(target_map),
        },
        "diagnostics": diagnostics,
        "backends": rows,
        "summary": summary,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(
        "backend effectiveness:",
        f"overall_pass={summary['overall_pass']}",
        f"missing_required={len(summary['missing_required_backends'])}",
        f"unresolved_backend_runs={summary['unresolved_backend_runs']}",
        f"zero_run_backends={','.join(summary['zero_run_backends']) if summary['zero_run_backends'] else '-'}",
        f"report={output_path}",
    )

    if args.enforce and not summary["overall_pass"]:
        print("enforce failed: per-backend effectiveness checks are not fully green")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
