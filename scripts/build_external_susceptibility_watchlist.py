#!/usr/bin/env python3
"""Build a zk external-repo susceptibility watchlist and candidate target matrix."""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

DEFAULT_SOURCE_ROOT = "/media/elements/Repos"
DEFAULT_CATALOG_PATH = "targets/external_repo_catalog_all_2026-02-25.json"
DEFAULT_EXTERNAL_ALL_MATRIX = "targets/zk0d_matrix_external_all.yaml"
DEFAULT_EXTERNAL_MANUAL_MATRIX = "targets/zk0d_matrix_external_manual.yaml"
DEFAULT_OUTPUT_JSON = "artifacts/external_targets/susceptibility_watchlist/latest_report.json"
DEFAULT_OUTPUT_MD = "artifacts/external_targets/susceptibility_watchlist/latest_report.md"
DEFAULT_OUTPUT_MATRIX = "targets/zk0d_matrix_external_susceptible.yaml"

SUPPORTED_FRAMEWORKS = {"circom", "noir", "cairo", "halo2"}

PATH_KEYWORD_WEIGHTS: Sequence[Tuple[str, int, str]] = (
    ("vuln", 30, "path includes vulnerability marker"),
    ("underconstrained", 24, "path includes underconstrained signal"),
    ("iszero", 12, "path includes IsZero family circuit"),
    ("lessthan", 12, "path includes LessThan family circuit"),
    ("montgomery", 10, "path includes Montgomery arithmetic circuit"),
    ("nullify", 8, "path includes nullifier logic"),
    ("authv3", 8, "path includes authV3 logic"),
    ("stateTransition", 8, "path includes state-transition logic"),
    ("query", 6, "path includes query-logic circuit"),
    ("email-wallet", 10, "path belongs to email-wallet privacy circuits"),
    ("semaphore", 8, "path belongs to semaphore privacy circuits"),
    ("tornado", 8, "path belongs to tornado privacy circuits"),
    ("verifier", 6, "path includes verifier logic"),
)

REPO_RISK_WEIGHTS = {
    "topk_avg": 0.6,
    "top_score": 0.3,
    "mean_score": 0.1,
}


def load_yaml(path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def load_json(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def discover_git_repos(source_root: Path, max_depth: int = 3) -> List[Path]:
    repos: List[Path] = []
    stack: List[Tuple[Path, int]] = [(source_root, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            continue
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue

        for entry in entries:
            if not entry.is_dir(follow_symlinks=False):
                continue
            child = Path(entry.path)
            git_path = child / ".git"
            if git_path.exists():
                repos.append(child.resolve())
                # Do not recurse into nested directories once repository root is found.
                continue
            if depth < max_depth:
                stack.append((child, depth + 1))

    return sorted(set(repos))


def is_zk_like_repo(path: Path) -> bool:
    lower = path.as_posix().lower()
    markers = (
        "zk",
        "circom",
        "halo2",
        "noir",
        "cairo",
        "plonk",
        "stark",
        "risc0",
        "sp1",
    )
    return any(marker in lower for marker in markers)


def classify_cargo_framework(cargo_toml_path: Path) -> Optional[str]:
    try:
        text = cargo_toml_path.read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        return None
    if "halo2" in text:
        return "halo2"
    if "plonky2" in text:
        return "plonky2"
    if re.search(r"\bsp1\b", text):
        return "sp1"
    if "risc0" in text:
        return "risc0"
    return None


def detect_new_repo_candidates(new_repo_paths: Sequence[Path]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for repo in new_repo_paths:
        # Root-level checks keep intake scans fast and deterministic on large monorepos.
        nargo_file = repo / "Nargo.toml"
        scarb_file = repo / "Scarb.toml"
        cargo_file = repo / "Cargo.toml"
        circom_file = next(repo.glob("*.circom"), None)
        cairo_file = next(repo.glob("*.cairo"), None)

        nargo_file = nargo_file if nargo_file.is_file() else None
        scarb_file = scarb_file if scarb_file.is_file() else None
        cargo_file = cargo_file if cargo_file.is_file() else None
        circom_file = circom_file if circom_file and circom_file.is_file() else None
        cairo_file = cairo_file if cairo_file and cairo_file.is_file() else None

        framework = ""
        entrypoint = ""
        support_status = "not_supported_by_current_executor"
        reason = "No supported Circom/Noir/Cairo/Halo2 entrypoint found"

        if circom_file:
            framework = "circom"
            entrypoint = circom_file.as_posix()
            support_status = "supported_by_current_executor"
            reason = "Direct .circom entrypoint discovered"
        elif nargo_file:
            framework = "noir"
            entrypoint = nargo_file.as_posix()
            support_status = "supported_by_current_executor"
            reason = "Noir Nargo.toml entrypoint discovered"
        elif scarb_file or cairo_file:
            framework = "cairo"
            entrypoint = (scarb_file or cairo_file).as_posix()
            support_status = "supported_by_current_executor"
            reason = "Cairo entrypoint discovered"
        elif cargo_file:
            detected = classify_cargo_framework(cargo_file)
            framework = detected or "rust-zk-unknown"
            entrypoint = cargo_file.as_posix()
            reason = "Cargo manifest discovered; framework classified from dependencies"
            if framework in SUPPORTED_FRAMEWORKS:
                support_status = "supported_by_current_executor"

        rows.append(
            {
                "repo_path": repo.as_posix(),
                "framework": framework or "unknown",
                "entrypoint": entrypoint or "",
                "support_status": support_status,
                "reason": reason,
            }
        )
    return rows


def resolve_repo_for_target(target_circuit: str, catalog_repo_paths: Sequence[str]) -> str:
    target_path = Path(target_circuit)
    best = ""
    for repo_path in catalog_repo_paths:
        repo = Path(repo_path)
        try:
            target_path.relative_to(repo)
        except ValueError:
            continue
        if len(repo_path) > len(best):
            best = repo_path
    return best


def score_candidate_target(row: Dict[str, Any]) -> Tuple[float, List[str]]:
    score = 0.0
    reasons: List[str] = []
    intel = row.get("intel", {}) if isinstance(row.get("intel"), dict) else {}
    framework_prior = (
        intel.get("framework_prior", {})
        if isinstance(intel.get("framework_prior"), dict)
        else {}
    )
    repo_prior = intel.get("repo_prior", {}) if isinstance(intel.get("repo_prior"), dict) else {}

    framework_issues = int(framework_prior.get("known_issue_count") or 0)
    if framework_issues:
        score += framework_issues
        reasons.append(f"framework_prior={framework_issues}")

    repo_issues = int(repo_prior.get("known_issue_count") or 0)
    if repo_issues:
        score += repo_issues
        reasons.append(f"repo_prior={repo_issues}")

    target_circuit = str(row.get("target_circuit") or "")
    lower = target_circuit.lower()
    for keyword, weight, explanation in PATH_KEYWORD_WEIGHTS:
        if keyword.lower() in lower:
            score += weight
            reasons.append(f"{keyword}(+{weight}): {explanation}")

    if "/test/" in lower:
        score -= 2
        reasons.append("test_path(-2): deprioritize pure unit-test fixtures")
    if "/node_modules/" in lower:
        score += 1
        reasons.append("node_modules(+1): third-party dependency surface")

    return score, reasons


def build_candidate_shortlist(
    external_all_rows: Sequence[Dict[str, Any]],
    manual_rows: Sequence[Dict[str, Any]],
    catalog_repo_paths: Sequence[str],
    limit: int = 24,
    per_repo_limit: int = 4,
) -> List[Dict[str, Any]]:
    manual_paths = {str(row.get("target_circuit") or "") for row in manual_rows}

    scored: List[Tuple[float, Dict[str, Any], List[str], str]] = []
    for row in external_all_rows:
        target_circuit = str(row.get("target_circuit") or "")
        if not target_circuit:
            continue
        if target_circuit in manual_paths:
            continue
        lower_target = target_circuit.lower()
        if "/node_modules/circomlib/test/circuits/" in lower_target:
            continue
        if lower_target.endswith("_test.circom"):
            continue
        framework = str(row.get("framework") or "")
        if framework not in SUPPORTED_FRAMEWORKS:
            continue
        score, reasons = score_candidate_target(row)
        if score <= 0:
            continue
        repo_path = resolve_repo_for_target(target_circuit, catalog_repo_paths)
        scored.append((score, row, reasons, repo_path))

    scored.sort(key=lambda item: (-item[0], str(item[1].get("target_circuit") or "")))
    chosen: List[Dict[str, Any]] = []
    per_repo_count: Dict[str, int] = {}
    for score, row, reasons, repo_path in scored:
        key = repo_path or "unknown_repo"
        if per_repo_count.get(key, 0) >= per_repo_limit:
            continue
        per_repo_count[key] = per_repo_count.get(key, 0) + 1
        chosen.append(
            {
                "name": str(row.get("name") or ""),
                "framework": str(row.get("framework") or ""),
                "target_circuit": str(row.get("target_circuit") or ""),
                "main_component": str(row.get("main_component") or "main"),
                "repo_path": repo_path,
                "score": round(score, 2),
                "reasons": reasons,
            }
        )
        if len(chosen) >= limit:
            break
    return chosen


def _is_eligible_candidate_row(row: Dict[str, Any], manual_paths: set[str]) -> bool:
    target_circuit = str(row.get("target_circuit") or "")
    if not target_circuit:
        return False
    if target_circuit in manual_paths:
        return False
    lower_target = target_circuit.lower()
    if "/node_modules/circomlib/test/circuits/" in lower_target:
        return False
    if lower_target.endswith("_test.circom"):
        return False
    framework = str(row.get("framework") or "")
    if framework not in SUPPORTED_FRAMEWORKS:
        return False
    return True


def build_repo_priority_ranking(
    external_all_rows: Sequence[Dict[str, Any]],
    manual_rows: Sequence[Dict[str, Any]],
    catalog_repo_paths: Sequence[str],
    topk: int = 4,
) -> List[Dict[str, Any]]:
    manual_paths = {str(row.get("target_circuit") or "") for row in manual_rows}
    scored_by_repo: Dict[str, List[Tuple[float, Dict[str, Any], List[str]]]] = {}

    for row in external_all_rows:
        if not _is_eligible_candidate_row(row, manual_paths):
            continue
        score, reasons = score_candidate_target(row)
        if score <= 0:
            continue
        target_circuit = str(row.get("target_circuit") or "")
        repo_path = resolve_repo_for_target(target_circuit, catalog_repo_paths) or "unknown_repo"
        scored_by_repo.setdefault(repo_path, []).append((score, row, reasons))

    ranking: List[Dict[str, Any]] = []
    for repo_path, items in scored_by_repo.items():
        sorted_items = sorted(
            items,
            key=lambda item: (-item[0], str(item[1].get("target_circuit") or "")),
        )
        top_items = sorted_items[: max(1, topk)]
        topk_avg = sum(item[0] for item in top_items) / len(top_items)
        top_score = sorted_items[0][0]
        mean_score = sum(item[0] for item in sorted_items) / len(sorted_items)
        risk_index = (
            REPO_RISK_WEIGHTS["topk_avg"] * topk_avg
            + REPO_RISK_WEIGHTS["top_score"] * top_score
            + REPO_RISK_WEIGHTS["mean_score"] * mean_score
        )
        ranking.append(
            {
                "repo_path": repo_path,
                "risk_index": round(risk_index, 2),
                "topk_avg_score": round(topk_avg, 2),
                "top_target_score": round(top_score, 2),
                "mean_score": round(mean_score, 2),
                "candidate_target_count": len(sorted_items),
                "top_target": str(sorted_items[0][1].get("target_circuit") or ""),
                "frameworks": sorted(
                    {
                        str(item[1].get("framework") or "")
                        for item in sorted_items
                        if str(item[1].get("framework") or "")
                    }
                ),
            }
        )

    ranking.sort(
        key=lambda row: (
            -float(row.get("risk_index") or 0.0),
            -float(row.get("top_target_score") or 0.0),
            str(row.get("repo_path") or ""),
        )
    )
    return ranking


def build_scan_roadmap(repo_ranking: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    roadmap: List[Dict[str, Any]] = []
    for index, row in enumerate(repo_ranking, start=1):
        if index <= 5:
            tier = "P0"
            phase = "Immediate"
        elif index <= 10:
            tier = "P1"
            phase = "High"
        elif index <= 14:
            tier = "P2"
            phase = "Medium"
        else:
            tier = "P3"
            phase = "Low"
        roadmap.append(
            {
                "rank": index,
                "tier": tier,
                "phase": phase,
                "repo_path": str(row.get("repo_path") or ""),
                "risk_index": float(row.get("risk_index") or 0.0),
                "candidate_target_count": int(row.get("candidate_target_count") or 0),
                "top_target": str(row.get("top_target") or ""),
                "frameworks": row.get("frameworks", []),
            }
        )
    return roadmap


def render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# External Susceptibility Watchlist",
        "",
        f"- generated_utc: `{report['generated_utc']}`",
        f"- source_root: `{report['source_root']}`",
        "",
        "## Summary",
        "",
        f"- zk_like_repos_discovered: `{report['summary']['zk_like_repos_discovered']}`",
        f"- catalog_repositories: `{report['summary']['catalog_repositories']}`",
        f"- new_zk_repos_not_in_catalog: `{report['summary']['new_zk_repos_not_in_catalog']}`",
        f"- shortlist_candidates: `{report['summary']['shortlist_candidates']}`",
        "",
        "## New Repos (Not In Catalog)",
        "",
        "| Repo | Framework | Entrypoint | Support Status | Reason |",
        "|---|---|---|---|---|",
    ]
    new_rows = report.get("new_repos_not_in_catalog", [])
    if not new_rows:
        lines.append("| `n/a` | `n/a` | `n/a` | `n/a` | `none` |")
    else:
        for row in new_rows:
            lines.append(
                f"| `{row['repo_path']}` | `{row['framework']}` | "
                f"`{row['entrypoint'] or 'n/a'}` | `{row['support_status']}` | {row['reason']} |"
            )

    lines.extend(
        [
            "",
            "## Candidate Target Shortlist",
            "",
            "| Rank | Score | Framework | Target Circuit | Repo |",
            "|---:|---:|---|---|---|",
        ]
    )
    shortlist = report.get("candidate_shortlist", [])
    if not shortlist:
        lines.append("| 1 | 0 | `n/a` | `n/a` | `n/a` |")
    else:
        for idx, row in enumerate(shortlist, start=1):
            lines.append(
                f"| {idx} | {row['score']} | `{row['framework']}` | "
                f"`{row['target_circuit']}` | `{row['repo_path'] or 'unknown'}` |"
            )

    lines.extend(
        [
            "",
            "## Repo Priority Ranking (Most Likely -> Least Likely)",
            "",
            "| Rank | Tier | Risk Index | Candidate Targets | Repo | Top Target |",
            "|---:|---|---:|---:|---|---|",
        ]
    )
    roadmap = report.get("scan_roadmap", [])
    if not roadmap:
        lines.append("| 1 | `n/a` | 0 | 0 | `n/a` | `n/a` |")
    else:
        for row in roadmap:
            lines.append(
                f"| {row['rank']} | `{row['tier']}` | {row['risk_index']:.2f} | "
                f"{row['candidate_target_count']} | `{row['repo_path']}` | "
                f"`{row['top_target'] or 'n/a'}` |"
            )
    lines.append("")
    return "\n".join(lines)


def build_matrix_yaml(shortlist: Sequence[Dict[str, Any]], generated_utc: str) -> str:
    targets: List[Dict[str, Any]] = []
    for row in shortlist:
        target = {
            "name": row["name"],
            "target_circuit": row["target_circuit"],
            "main_component": row.get("main_component") or "main",
            "framework": row["framework"],
            "alias": "always",
            "enabled": False,
            "intel": {
                "dataset": "zkbugs",
                "source_root": "/home/teycir/Documents/ZkDatasets",
                "synced_on": generated_utc[:10],
                "suspicion_score": row["score"],
                "rationale": row["reasons"],
            },
        }
        targets.append(target)

    payload = {
        "version": 1,
        "generated_utc": generated_utc,
        "note": "Auto-generated susceptibility watchlist targets. Keep disabled by default.",
        "targets": targets,
    }
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=False)


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build external susceptibility watchlist from /media/elements/Repos."
    )
    parser.add_argument("--source-root", default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--catalog-path", default=DEFAULT_CATALOG_PATH)
    parser.add_argument("--external-all-matrix", default=DEFAULT_EXTERNAL_ALL_MATRIX)
    parser.add_argument("--external-manual-matrix", default=DEFAULT_EXTERNAL_MANUAL_MATRIX)
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-md", default=DEFAULT_OUTPUT_MD)
    parser.add_argument("--output-matrix", default=DEFAULT_OUTPUT_MATRIX)
    parser.add_argument("--limit", type=int, default=24)
    parser.add_argument("--per-repo-limit", type=int, default=4)
    parser.add_argument("--repo-max-depth", type=int, default=3)
    return parser.parse_args()


def to_abs(repo_root: Path, path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    return (repo_root / path).resolve()


def main() -> int:
    args = parse_args()
    repo_root = Path(".").resolve()
    source_root = Path(args.source_root).resolve()
    catalog_path = to_abs(repo_root, args.catalog_path)
    external_all_matrix_path = to_abs(repo_root, args.external_all_matrix)
    external_manual_matrix_path = to_abs(repo_root, args.external_manual_matrix)
    output_json_path = to_abs(repo_root, args.output_json)
    output_md_path = to_abs(repo_root, args.output_md)
    output_matrix_path = to_abs(repo_root, args.output_matrix)

    catalog = load_json(catalog_path)
    catalog_repo_paths = [
        str(item.get("repo_path") or "")
        for item in catalog.get("repositories", [])
        if str(item.get("repo_path") or "").strip()
    ]
    catalog_repo_set = set(catalog_repo_paths)

    external_all = load_yaml(external_all_matrix_path)
    external_manual = load_yaml(external_manual_matrix_path)
    external_all_rows = external_all.get("targets", []) if isinstance(external_all.get("targets"), list) else []
    external_manual_rows = (
        external_manual.get("targets", []) if isinstance(external_manual.get("targets"), list) else []
    )

    discovered_repos = discover_git_repos(source_root=source_root, max_depth=args.repo_max_depth)
    zk_like_repos = [repo for repo in discovered_repos if is_zk_like_repo(repo)]
    new_repo_paths = [repo for repo in zk_like_repos if repo.as_posix() not in catalog_repo_set]
    new_repo_candidates = detect_new_repo_candidates(new_repo_paths)

    shortlist = build_candidate_shortlist(
        external_all_rows=external_all_rows,
        manual_rows=external_manual_rows,
        catalog_repo_paths=catalog_repo_paths,
        limit=max(1, args.limit),
        per_repo_limit=max(1, args.per_repo_limit),
    )
    repo_ranking = build_repo_priority_ranking(
        external_all_rows=external_all_rows,
        manual_rows=external_manual_rows,
        catalog_repo_paths=catalog_repo_paths,
        topk=max(1, args.per_repo_limit),
    )
    scan_roadmap = build_scan_roadmap(repo_ranking)

    generated_utc = datetime.now(timezone.utc).isoformat()
    report = {
        "generated_utc": generated_utc,
        "source_root": source_root.as_posix(),
        "inputs": {
            "catalog_path": catalog_path.as_posix(),
            "external_all_matrix": external_all_matrix_path.as_posix(),
            "external_manual_matrix": external_manual_matrix_path.as_posix(),
        },
        "summary": {
            "zk_like_repos_discovered": len(zk_like_repos),
            "catalog_repositories": len(catalog_repo_paths),
            "new_zk_repos_not_in_catalog": len(new_repo_candidates),
            "shortlist_candidates": len(shortlist),
        },
        "new_repos_not_in_catalog": new_repo_candidates,
        "candidate_shortlist": shortlist,
        "repo_priority_ranking": repo_ranking,
        "scan_roadmap": scan_roadmap,
    }

    markdown = render_markdown(report)
    matrix_yaml = build_matrix_yaml(shortlist, generated_utc)

    ensure_parent(output_json_path)
    ensure_parent(output_md_path)
    ensure_parent(output_matrix_path)
    output_json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    output_md_path.write_text(markdown, encoding="utf-8")
    output_matrix_path.write_text(matrix_yaml, encoding="utf-8")

    print(
        "external susceptibility watchlist:",
        f"zk_repos={report['summary']['zk_like_repos_discovered']}",
        f"new_not_in_catalog={report['summary']['new_zk_repos_not_in_catalog']}",
        f"shortlist={report['summary']['shortlist_candidates']}",
    )
    print(f"json={output_json_path.as_posix()}")
    print(f"markdown={output_md_path.as_posix()}")
    print(f"matrix={output_matrix_path.as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
