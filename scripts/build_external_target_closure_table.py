#!/usr/bin/env python3
"""Build a concise closure table for external targets with artifact links."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml


DEFAULT_MATRIX_PATH = "targets/zk0d_matrix_external_manual.yaml"
DEFAULT_ROADMAP_PATH = "ROADMAP.md"
DEFAULT_OUTPUT_JSON = "artifacts/external_targets/closure_table/latest_report.json"
DEFAULT_OUTPUT_MD = "artifacts/external_targets/closure_table/latest_table.md"

INTERESTING_FILENAMES = (
    "exploit_notes.md",
    "no_exploit_proof.md",
    "summary.json",
    "triage.md",
)


def normalize_target_id(raw_id: str) -> str:
    match = re.search(r"(\d{3})", str(raw_id))
    if not match:
        raise ValueError(f"Unable to normalize target id from '{raw_id}'")
    return f"EXT-{match.group(1)}"


def extract_target_id(text: str) -> Optional[str]:
    match = re.search(r"ext[-_]?(\d{3})", str(text), re.IGNORECASE)
    if not match:
        return None
    return f"EXT-{match.group(1)}"


def load_matrix_targets(matrix_path: Path) -> List[Dict[str, str]]:
    data = yaml.safe_load(matrix_path.read_text(encoding="utf-8")) or {}
    rows = data.get("targets", []) if isinstance(data, dict) else []

    parsed: Dict[str, Dict[str, str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        run_overrides_file = str(row.get("run_overrides_file") or "").strip()
        target_id = extract_target_id(name) or extract_target_id(run_overrides_file)
        if not target_id:
            continue
        if target_id not in parsed:
            parsed[target_id] = {
                "target_id": target_id,
                "target_name": name if name else target_id.lower(),
            }

    return sorted(parsed.values(), key=lambda item: item["target_id"])


def collect_artifact_index(artifacts_root: Path) -> Dict[str, Dict[str, List[Path]]]:
    index: Dict[str, Dict[str, List[Path]]] = {}
    for filename in INTERESTING_FILENAMES:
        for path in artifacts_root.rglob(filename):
            if not path.is_file():
                continue
            target_id = extract_target_id(path.as_posix())
            if not target_id:
                continue
            per_target = index.setdefault(target_id, {})
            per_target.setdefault(filename, []).append(path)
    return index


def latest_path(paths: Sequence[Path]) -> Optional[Path]:
    if not paths:
        return None
    return max(paths, key=lambda item: item.stat().st_mtime)


def classify_no_exploit_doc(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="replace").lower()
    if "pending_proof" in text:
        return "pending_proof"
    if "not_exploitable_within_bounds" in text:
        return "not_exploitable_within_bounds"
    if "not exploitable within checked bounds" in text:
        return "not_exploitable_within_bounds"
    if "not exploitable within bounds" in text:
        return "not_exploitable_within_bounds"
    if "result: **not exploitable" in text:
        return "not_exploitable_within_bounds"
    return "unknown"


def read_latest_summary(summary_paths: Sequence[Path]) -> Dict[str, Any]:
    summary_path = latest_path(summary_paths)
    if summary_path is None:
        return {}
    try:
        data = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"summary_path": summary_path.as_posix()}

    misc = (
        data.get("modes", {}).get("misc", {})
        if isinstance(data.get("modes"), dict)
        else {}
    )
    discovery = (
        misc.get("discovery_qualification", {})
        if isinstance(misc.get("discovery_qualification"), dict)
        else {}
    )
    return {
        "summary_path": summary_path.as_posix(),
        "status": str(misc.get("status") or ""),
        "stage": str(misc.get("stage") or ""),
        "reason_code": str(misc.get("reason_code") or ""),
        "proof_status": str(discovery.get("proof_status") or ""),
        "error": str(misc.get("error") or ""),
    }


def blocked_scope_from_summary(summary: Dict[str, Any]) -> str:
    status = str(summary.get("status") or "").lower()
    stage = str(summary.get("stage") or "").lower()
    proof_status = str(summary.get("proof_status") or "").lower()
    error = str(summary.get("error") or "").lower()

    if status == "completed_with_critical_findings":
        return "critical findings pending deterministic exploit/non-exploit bundle"
    if stage == "preflight_backend" or "preflight" in stage:
        return "backend/preflight instability prevents proof closure"
    if "backend preflight failed" in error:
        return "backend/preflight instability prevents proof closure"
    if proof_status == "pending_proof":
        return "proof bundle pending"
    return "proof bundle pending"


def count_open_ext005_findings(roadmap_text: str) -> int:
    return len(re.findall(r"^\s*-\s*\[ \]\s*`EXT-005-F\d+`", roadmap_text, re.MULTILINE))


def resolve_target_row(
    target_id: str,
    target_name: str,
    file_index: Dict[str, Dict[str, List[Path]]],
    ext005_open_findings: int,
) -> Dict[str, str]:
    files = file_index.get(target_id, {})
    exploit_notes = files.get("exploit_notes.md", [])
    no_exploit_docs = files.get("no_exploit_proof.md", [])
    triage_docs = files.get("triage.md", [])
    summaries = files.get("summary.json", [])

    no_exploit_closed: List[Path] = []
    no_exploit_pending: List[Path] = []
    for path in no_exploit_docs:
        classification = classify_no_exploit_doc(path)
        if classification == "not_exploitable_within_bounds":
            no_exploit_closed.append(path)
        elif classification == "pending_proof":
            no_exploit_pending.append(path)

    latest_summary = read_latest_summary(summaries)
    summary_link = latest_summary.get("summary_path", "")

    if exploit_notes:
        link = latest_path(exploit_notes)
        return {
            "target": target_id,
            "target_name": target_name,
            "closure_class": "exploitable",
            "current_scope": "target-level closed",
            "artifact_link": link.as_posix() if link else summary_link,
        }

    if target_id == "EXT-005" and ext005_open_findings > 0:
        link = latest_path(no_exploit_closed) or latest_path(no_exploit_pending) or latest_path(summaries)
        return {
            "target": target_id,
            "target_name": target_name,
            "closure_class": "blocked",
            "current_scope": (
                "partial closure (finding-level proofs exist; "
                f"{ext005_open_findings} finding(s) still open)"
            ),
            "artifact_link": link.as_posix() if link else "",
        }

    if no_exploit_closed:
        link = latest_path(no_exploit_closed)
        return {
            "target": target_id,
            "target_name": target_name,
            "closure_class": "not_exploitable_within_bounds",
            "current_scope": "target-level closed",
            "artifact_link": link.as_posix() if link else summary_link,
        }

    blocked_link = latest_path(no_exploit_pending) or latest_path(triage_docs) or latest_path(summaries)
    return {
        "target": target_id,
        "target_name": target_name,
        "closure_class": "blocked",
        "current_scope": blocked_scope_from_summary(latest_summary),
        "artifact_link": blocked_link.as_posix() if blocked_link else "",
    }


def build_rows(
    matrix_targets: Sequence[Dict[str, str]],
    file_index: Dict[str, Dict[str, List[Path]]],
    ext005_open_findings: int,
    selected_targets: Optional[Iterable[str]] = None,
) -> List[Dict[str, str]]:
    selected = {
        normalize_target_id(item)
        for item in (selected_targets or [])
        if str(item).strip()
    }
    use_all = not selected

    rows: List[Dict[str, str]] = []
    for item in matrix_targets:
        target_id = item["target_id"]
        if not use_all and target_id not in selected:
            continue
        rows.append(
            resolve_target_row(
                target_id=target_id,
                target_name=item["target_name"],
                file_index=file_index,
                ext005_open_findings=ext005_open_findings,
            )
        )
    return rows


def render_markdown(rows: Sequence[Dict[str, str]], generated_utc: str) -> str:
    lines = [
        "# External Target Closure Table",
        "",
        f"- generated_utc: `{generated_utc}`",
        "",
        "| Target | Closure Class | Current Scope | Artifact Link |",
        "|---|---|---|---|",
    ]
    for row in rows:
        artifact_link = row["artifact_link"]
        artifact_cell = f"`{artifact_link}`" if artifact_link else "`n/a`"
        lines.append(
            f"| `{row['target']}` | `{row['closure_class']}` | {row['current_scope']} | {artifact_cell} |"
        )
    lines.append("")
    return "\n".join(lines)


def write_outputs(output_json: Path, output_md: Path, payload: Dict[str, Any], markdown: str) -> None:
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    output_md.write_text(markdown, encoding="utf-8")


def build_report(
    repo_root: Path,
    matrix_path: Path,
    roadmap_path: Path,
    selected_targets: Optional[Iterable[str]] = None,
) -> Tuple[Dict[str, Any], str]:
    matrix_targets = load_matrix_targets(matrix_path)
    file_index = collect_artifact_index(repo_root / "artifacts")
    roadmap_text = roadmap_path.read_text(encoding="utf-8")
    ext005_open_findings = count_open_ext005_findings(roadmap_text)
    rows = build_rows(
        matrix_targets=matrix_targets,
        file_index=file_index,
        ext005_open_findings=ext005_open_findings,
        selected_targets=selected_targets,
    )

    generated_utc = datetime.now(timezone.utc).isoformat()
    summary = {
        "total_targets": len(rows),
        "counts_by_class": {
            "exploitable": sum(1 for row in rows if row["closure_class"] == "exploitable"),
            "not_exploitable_within_bounds": sum(
                1 for row in rows if row["closure_class"] == "not_exploitable_within_bounds"
            ),
            "blocked": sum(1 for row in rows if row["closure_class"] == "blocked"),
        },
        "ext005_open_findings": ext005_open_findings,
    }
    payload = {
        "generated_utc": generated_utc,
        "source": {
            "matrix_path": str(matrix_path),
            "roadmap_path": str(roadmap_path),
        },
        "summary": summary,
        "rows": rows,
    }
    markdown = render_markdown(rows, generated_utc)
    return payload, markdown


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build closure table for external target proof states."
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root path (default: current directory).",
    )
    parser.add_argument(
        "--matrix-path",
        default=DEFAULT_MATRIX_PATH,
        help=f"External target matrix YAML path (default: {DEFAULT_MATRIX_PATH}).",
    )
    parser.add_argument(
        "--roadmap-path",
        default=DEFAULT_ROADMAP_PATH,
        help=f"Roadmap path (default: {DEFAULT_ROADMAP_PATH}).",
    )
    parser.add_argument(
        "--output-json",
        default=DEFAULT_OUTPUT_JSON,
        help=f"JSON output path (default: {DEFAULT_OUTPUT_JSON}).",
    )
    parser.add_argument(
        "--output-md",
        default=DEFAULT_OUTPUT_MD,
        help=f"Markdown output path (default: {DEFAULT_OUTPUT_MD}).",
    )
    parser.add_argument(
        "--targets",
        default="",
        help="Optional comma-separated target IDs to include (example: EXT-003,EXT-005).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()

    matrix_path = Path(args.matrix_path)
    if not matrix_path.is_absolute():
        matrix_path = (repo_root / matrix_path).resolve()

    roadmap_path = Path(args.roadmap_path)
    if not roadmap_path.is_absolute():
        roadmap_path = (repo_root / roadmap_path).resolve()

    output_json = Path(args.output_json)
    if not output_json.is_absolute():
        output_json = (repo_root / output_json).resolve()

    output_md = Path(args.output_md)
    if not output_md.is_absolute():
        output_md = (repo_root / output_md).resolve()

    selected_targets = [
        item.strip()
        for item in args.targets.split(",")
        if item.strip()
    ]
    payload, markdown = build_report(
        repo_root=repo_root,
        matrix_path=matrix_path,
        roadmap_path=roadmap_path,
        selected_targets=selected_targets or None,
    )
    write_outputs(output_json, output_md, payload, markdown)

    counts = payload["summary"]["counts_by_class"]
    print(
        "external target closure table:",
        f"total={payload['summary']['total_targets']}",
        f"exploitable={counts['exploitable']}",
        f"not_exploitable_within_bounds={counts['not_exploitable_within_bounds']}",
        f"blocked={counts['blocked']}",
    )
    print(f"json={output_json}")
    print(f"markdown={output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
