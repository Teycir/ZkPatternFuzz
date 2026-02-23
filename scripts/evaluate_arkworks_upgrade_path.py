#!/usr/bin/env python3
"""Evaluate arkworks 0.5 migration path from current workspace manifests and lockfile."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python <3.11 recovery
    import tomli as tomllib  # type: ignore


SECTION_KEYS = ("dependencies", "dev-dependencies", "build-dependencies")


@dataclass(frozen=True)
class ArkDependency:
    manifest: str
    section: str
    name: str
    raw_spec: str
    parsed_track: Optional[Tuple[int, int]]


def infer_semver_track(raw_spec: str) -> Optional[Tuple[int, int]]:
    match = re.search(r"(\d+)\.(\d+)", raw_spec)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)))


def _stringify_spec(spec: Any) -> str:
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        parts = []
        if "version" in spec:
            parts.append(str(spec["version"]))
        if "path" in spec:
            parts.append(f"path={spec['path']}")
        if "git" in spec:
            parts.append(f"git={spec['git']}")
        if not parts:
            return json.dumps(spec, sort_keys=True)
        return ",".join(parts)
    return str(spec)


def _iter_dep_tables(manifest_doc: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    for section in SECTION_KEYS:
        table = manifest_doc.get(section)
        if isinstance(table, dict):
            yield section, table

    target_table = manifest_doc.get("target")
    if isinstance(target_table, dict):
        for target_name, target_cfg in target_table.items():
            if not isinstance(target_cfg, dict):
                continue
            for section in SECTION_KEYS:
                table = target_cfg.get(section)
                if isinstance(table, dict):
                    yield f"target.{target_name}.{section}", table


def _workspace_manifests(repo_root: Path) -> List[Path]:
    root_manifest = repo_root / "Cargo.toml"
    if not root_manifest.exists():
        raise FileNotFoundError(f"Missing workspace root Cargo.toml: {root_manifest}")

    root_doc = tomllib.loads(root_manifest.read_text(encoding="utf-8"))
    workspace_cfg = root_doc.get("workspace")
    members: List[str] = []
    if isinstance(workspace_cfg, dict):
        raw_members = workspace_cfg.get("members")
        if isinstance(raw_members, list):
            members = [str(item) for item in raw_members]

    manifests = [root_manifest]
    for member in members:
        member_path = (repo_root / member).resolve()
        member_manifest = member_path / "Cargo.toml"
        if member_manifest.exists():
            manifests.append(member_manifest)

    # Keep deterministic ordering and remove duplicates.
    seen = set()
    ordered: List[Path] = []
    for manifest in sorted(manifests):
        key = str(manifest)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(manifest)
    return ordered


def collect_direct_ark_dependencies(repo_root: Path) -> List[ArkDependency]:
    manifests = _workspace_manifests(repo_root)
    deps: List[ArkDependency] = []

    for manifest_path in manifests:
        if "target" in manifest_path.parts:
            continue
        doc = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        rel_manifest = str(manifest_path.relative_to(repo_root))

        for section_name, table in _iter_dep_tables(doc):
            for dep_name, dep_spec in table.items():
                if not dep_name.startswith("ark-"):
                    continue
                raw_spec = _stringify_spec(dep_spec)
                deps.append(
                    ArkDependency(
                        manifest=rel_manifest,
                        section=section_name,
                        name=dep_name,
                        raw_spec=raw_spec,
                        parsed_track=infer_semver_track(raw_spec),
                    )
                )

    deps.sort(key=lambda item: (item.manifest, item.section, item.name))
    return deps


def collect_lock_ark_versions(lock_path: Path) -> Dict[str, List[str]]:
    if not lock_path.exists():
        return {}

    doc = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    package_entries = doc.get("package")
    if not isinstance(package_entries, list):
        return {}

    versions: Dict[str, set[str]] = {}
    for entry in package_entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or not name.startswith("ark-"):
            continue
        if not isinstance(version, str):
            continue
        versions.setdefault(name, set()).add(version)

    return {name: sorted(vals) for name, vals in sorted(versions.items())}


def collect_usage_counts(repo_root: Path, dep_names: Iterable[str]) -> Dict[str, int]:
    dep_modules = {name: name.replace("-", "_") for name in dep_names}
    counts = {name: 0 for name in dep_modules}

    for rust_file in repo_root.glob("**/*.rs"):
        parts = rust_file.parts
        if "target" in parts:
            continue
        text = rust_file.read_text(encoding="utf-8", errors="ignore")
        for dep_name, module_name in dep_modules.items():
            if re.search(rf"\b{re.escape(module_name)}\b", text):
                counts[dep_name] += 1

    return counts


def _is_track(dep: ArkDependency, major: int, minor: int) -> bool:
    return dep.parsed_track == (major, minor)


def evaluate_upgrade_path(repo_root: Path) -> Dict[str, Any]:
    direct = collect_direct_ark_dependencies(repo_root)
    lock_versions = collect_lock_ark_versions(repo_root / "Cargo.lock")
    usage_counts = collect_usage_counts(repo_root, {d.name for d in direct})

    not_on_05 = [d for d in direct if not _is_track(d, 0, 5)]
    lock_has_non_05: Dict[str, List[str]] = {}
    for name, versions in lock_versions.items():
        non_05 = []
        for ver in versions:
            track = infer_semver_track(ver)
            if track != (0, 5):
                non_05.append(ver)
        if non_05:
            lock_has_non_05[name] = non_05

    direct_uses = {name: count for name, count in usage_counts.items() if count > 0}

    blockers: List[str] = []
    if not_on_05:
        blockers.append(
            f"{len(not_on_05)} direct ark dependencies are not pinned to 0.5"
        )
    if lock_has_non_05:
        blockers.append(
            f"Cargo.lock contains {len(lock_has_non_05)} ark crates not on 0.5"
        )

    migration_steps = [
        "Bump direct ark dependencies to 0.5 in root Cargo.toml",
        "Run cargo update for ark-* crates and resolve API breakage",
        "Run full workspace tests and backend readiness lanes",
    ]
    if not direct_uses:
        migration_steps.insert(
            1,
            "Optionally remove unused direct ark dependencies from root if no code path needs them",
        )
    else:
        migration_steps.insert(
            1,
            "Refactor ark API call sites reported in usage summary to 0.5 equivalents",
        )

    risk = "low" if not direct_uses else "medium"
    if len(not_on_05) >= 4 and direct_uses:
        risk = "high"

    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "repo_root": str(repo_root),
        "direct_ark_dependencies": [
            {
                "manifest": d.manifest,
                "section": d.section,
                "name": d.name,
                "raw_spec": d.raw_spec,
                "parsed_track": list(d.parsed_track) if d.parsed_track is not None else None,
                "usage_file_hits": usage_counts.get(d.name, 0),
            }
            for d in direct
        ],
        "lock_ark_versions": lock_versions,
        "not_on_05_direct": [
            {
                "manifest": d.manifest,
                "section": d.section,
                "name": d.name,
                "raw_spec": d.raw_spec,
            }
            for d in not_on_05
        ],
        "lock_non_05": lock_has_non_05,
        "usage_summary": usage_counts,
        "blockers": blockers,
        "migration_steps": migration_steps,
        "risk": risk,
        "ready_to_upgrade_now": len(not_on_05) == 0 and len(lock_has_non_05) == 0,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate arkworks 0.5 migration path using local manifests and lockfile."
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root containing Cargo.toml and Cargo.lock",
    )
    parser.add_argument(
        "--output",
        default="artifacts/dependency_tracking/arkworks_upgrade_path.json",
        help="Output report JSON path",
    )
    parser.add_argument(
        "--enforce-ready",
        action="store_true",
        help="Exit non-zero when upgrade prerequisites are not yet satisfied",
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    output = Path(args.output)
    if not output.is_absolute():
        output = (repo_root / output).resolve()

    report = evaluate_upgrade_path(repo_root)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(
        "arkworks upgrade evaluation:",
        f"direct_deps={len(report['direct_ark_dependencies'])}",
        f"not_on_05={len(report['not_on_05_direct'])}",
        f"lock_non_05_crates={len(report['lock_non_05'])}",
        f"risk={report['risk']}",
        f"ready_to_upgrade_now={report['ready_to_upgrade_now']}",
        f"report={output}",
    )

    if args.enforce_ready and not report["ready_to_upgrade_now"]:
        print("enforce-ready failed: arkworks migration prerequisites not satisfied", flush=True)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
