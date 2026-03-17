#!/usr/bin/env python3
"""Curate a clean shortlist of fuzzable targets under /home/teycir/ZkRepos.

This script keeps raw discovery separate from operator-focused curation. It
filters out framework source trees, workspace aggregates, tests/fixtures/docs,
and targets that do not expose a direct runnable entrypoint for the current
zkpatternfuzz execution model. It also reports concrete prerequisite and
dependency blockers for the surviving candidates.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

from discover_zkrepos_targets import DEFAULT_ROOT, TargetRecord, discover_targets


FRAMEWORK_INTERNAL_REPOS = {"cairo", "circomlib", "halo2"}
SKIP_SEGMENTS = {
    "test",
    "tests",
    "fixtures",
    "fixture",
    "mock",
    "mocks",
    "docs",
    "doc",
    "internal_test_programs",
    "macro_compilation_failure_tests",
    "noir-contracts-comp-failures",
}
EXAMPLE_SEGMENTS = {"example", "examples"}
MONOREPO_NOISE_REPOS = {"aztec-packages"}
PREFERRED_REPOS = {"circom-ecdsa", "tornado-core", "noir-examples", "zkevm-circuits"}


@dataclass(frozen=True)
class CuratedTarget:
    display_name: str
    repo_name: str
    framework: str
    main_component: str
    target_path: str
    source_kind: str
    category: str
    status: str
    skip_reason: str | None
    prerequisites: list[str]
    dependency_notes: list[str]
    verify_status: str
    verify_message: str | None


@dataclass(frozen=True)
class RepoSummary:
    repo_name: str
    status: str
    reason: str
    fit_targets: int
    skipped_targets: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Curate a clean, fuzzable target shortlist from a live ZkRepos checkout."
    )
    parser.add_argument(
        "--root",
        default=str(DEFAULT_ROOT),
        help="Root directory to scan (default: %(default)s)",
    )
    parser.add_argument(
        "--format",
        choices=("json", "tsv", "markdown"),
        default="markdown",
        help="Output format (default: %(default)s)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run lightweight readiness checks for curated candidates.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Per-check timeout in seconds when --verify is used (default: %(default)s)",
    )
    return parser.parse_args()


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        payload = tomllib.load(handle)
    if not isinstance(payload, dict):
        return {}
    return payload


def target_segments(record: TargetRecord) -> list[str]:
    return [segment.lower() for segment in Path(record.display_name).parts]


def repo_name_for(record: TargetRecord) -> str:
    return Path(record.display_name).parts[0]


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def discover_local_ptau(repo_root: Path) -> Path | None:
    preferred = repo_root / "bins" / "ptau" / "pot12_final.ptau"
    if preferred.is_file():
        return preferred
    ptau_dir = repo_root / "bins" / "ptau"
    if not ptau_dir.is_dir():
        return None
    for candidate in sorted(ptau_dir.iterdir()):
        if candidate.is_file() and candidate.suffix == ".ptau":
            return candidate
    return None


def parse_noir_manifest(manifest_path: Path) -> tuple[str | None, list[str]]:
    payload = load_toml(manifest_path)
    if "workspace" in payload and "package" not in payload:
        return ("workspace", [])

    package = payload.get("package")
    package_type = None
    if isinstance(package, dict):
        raw_type = package.get("type")
        if isinstance(raw_type, str):
            package_type = raw_type.strip() or None

    notes: list[str] = []
    dependencies = payload.get("dependencies")
    if isinstance(dependencies, dict):
        for name, spec in dependencies.items():
            if isinstance(spec, dict):
                dep_path = spec.get("path")
                dep_git = spec.get("git")
                if isinstance(dep_path, str):
                    resolved = (manifest_path.parent / dep_path).resolve()
                    state = "present" if resolved.exists() else "missing"
                    notes.append(f"{name}:path:{state}:{resolved}")
                elif isinstance(dep_git, str):
                    notes.append(f"{name}:git:{dep_git}")
                else:
                    notes.append(f"{name}:registry")
            else:
                notes.append(f"{name}:registry")
    return (package_type, notes)


def parse_halo2_manifest(manifest_path: Path) -> tuple[list[str], list[str]]:
    payload = load_toml(manifest_path)
    package = payload.get("package")
    bins: list[str] = []
    notes: list[str] = []

    if isinstance(package, dict):
        default_run = package.get("default-run")
        if isinstance(default_run, str) and default_run.strip():
            bins.append(default_run.strip())

    src_main = manifest_path.parent / "src" / "main.rs"
    if src_main.is_file():
        package_name = package.get("name") if isinstance(package, dict) else None
        if isinstance(package_name, str) and package_name.strip():
            bins.append(package_name.strip())
        else:
            bins.append("main")

    raw_bins = payload.get("bin")
    if isinstance(raw_bins, list):
        for item in raw_bins:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if isinstance(name, str) and name.strip():
                bins.append(name.strip())

    dependencies = payload.get("dependencies")
    if isinstance(dependencies, dict):
        for name, spec in dependencies.items():
            if isinstance(spec, dict):
                dep_path = spec.get("path")
                dep_git = spec.get("git")
                if isinstance(dep_path, str):
                    resolved = (manifest_path.parent / dep_path).resolve()
                    state = "present" if resolved.exists() else "missing"
                    notes.append(f"{name}:path:{state}:{resolved}")
                elif isinstance(dep_git, str):
                    notes.append(f"{name}:git:{dep_git}")

    deduped_bins: list[str] = []
    for item in bins:
        if item not in deduped_bins:
            deduped_bins.append(item)
    return (deduped_bins, notes)


def parse_circom_dependencies(target_path: Path) -> list[str]:
    notes: list[str] = []
    source = target_path.read_text(encoding="utf-8", errors="ignore")
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if not line.startswith("include "):
            continue
        quote = '"' if '"' in line else "'"
        parts = line.split(quote)
        if len(parts) < 3:
            continue
        include_value = parts[1].strip()
        include_path = Path(include_value)
        if include_path.is_absolute():
            resolved = include_path
        else:
            resolved = (target_path.parent / include_path).resolve()
        if resolved.exists():
            notes.append(f"include:present:{include_value}:{resolved}")
            continue
        if include_path.parts and include_path.parts[0] == "node_modules":
            notes.append(f"include:missing_node_modules:{include_value}")
        elif "/" not in include_value and "\\" not in include_value:
            notes.append(f"include:bare_symbol:{include_value}")
        else:
            notes.append(f"include:missing:{include_value}:{resolved}")
    return notes


def classify_target(record: TargetRecord) -> CuratedTarget:
    repo_name = repo_name_for(record)
    segments = target_segments(record)
    target_path = Path(record.target_path)

    prerequisites = ["cargo"]
    dependency_notes: list[str] = []
    category = "candidate"
    status = "candidate"
    skip_reason: str | None = None

    if repo_name in FRAMEWORK_INTERNAL_REPOS:
        return CuratedTarget(
            display_name=record.display_name,
            repo_name=repo_name,
            framework=record.framework,
            main_component=record.main_component,
            target_path=record.target_path,
            source_kind=record.source_kind,
            category="framework_internal",
            status="skip",
            skip_reason="framework_internal_repo",
            prerequisites=prerequisites,
            dependency_notes=dependency_notes,
            verify_status="not_run",
            verify_message=None,
        )

    if repo_name in MONOREPO_NOISE_REPOS:
        return CuratedTarget(
            display_name=record.display_name,
            repo_name=repo_name,
            framework=record.framework,
            main_component=record.main_component,
            target_path=record.target_path,
            source_kind=record.source_kind,
            category="monorepo_noise",
            status="skip",
            skip_reason="requires_targeted_monorepo_onboarding",
            prerequisites=prerequisites,
            dependency_notes=dependency_notes,
            verify_status="not_run",
            verify_message=None,
        )

    if any(segment in SKIP_SEGMENTS for segment in segments):
        matched = next(segment for segment in segments if segment in SKIP_SEGMENTS)
        return CuratedTarget(
            display_name=record.display_name,
            repo_name=repo_name,
            framework=record.framework,
            main_component=record.main_component,
            target_path=record.target_path,
            source_kind=record.source_kind,
            category="non_fit",
            status="skip",
            skip_reason=f"skip_segment:{matched}",
            prerequisites=prerequisites,
            dependency_notes=dependency_notes,
            verify_status="not_run",
            verify_message=None,
        )

    if record.framework == "circom":
        prerequisites.extend(["circom", "snarkjs", "ptau"])
        dependency_notes.extend(parse_circom_dependencies(target_path))
        if repo_name == "tornado-core":
            category = "production"
        elif any(segment in EXAMPLE_SEGMENTS for segment in segments):
            category = "example"
        elif repo_name in PREFERRED_REPOS:
            category = "candidate"
        else:
            category = "non_fit"
            status = "skip"
            skip_reason = "unprioritized_circom_repo"

    elif record.framework == "noir":
        prerequisites.append("nargo")
        package_type, noir_notes = parse_noir_manifest(target_path)
        dependency_notes.extend(noir_notes)
        if package_type == "workspace":
            status = "skip"
            category = "workspace"
            skip_reason = "workspace_manifest"
        elif package_type not in (None, "bin"):
            status = "skip"
            category = "non_fit"
            skip_reason = f"noir_package_type:{package_type}"
        elif repo_name == "noir-examples":
            category = "example"
        else:
            category = "candidate"

    elif record.framework == "halo2":
        bins, halo2_notes = parse_halo2_manifest(target_path)
        dependency_notes.extend(halo2_notes)
        if not bins:
            status = "skip"
            category = "non_fit"
            skip_reason = "halo2_no_runnable_bin"
        elif repo_name == "zkevm-circuits":
            category = "advanced"
        else:
            category = "candidate"

    elif record.framework == "cairo":
        prerequisites.extend(["scarb", "cairo-run"])
        category = "candidate"

    return CuratedTarget(
        display_name=record.display_name,
        repo_name=repo_name,
        framework=record.framework,
        main_component=record.main_component,
        target_path=record.target_path,
        source_kind=record.source_kind,
        category=category,
        status=status,
        skip_reason=skip_reason,
        prerequisites=dedupe(prerequisites),
        dependency_notes=dependency_notes,
        verify_status="not_run",
        verify_message=None,
    )


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def run_checked_command(args: list[str], timeout: int, cwd: Path) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            args,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return (False, f"timeout after {timeout}s")
    output = completed.stderr.strip() or completed.stdout.strip()
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    summary = " | ".join(lines[:6]) if lines else "ok"
    return (completed.returncode == 0, summary)


def verify_target(
    target: CuratedTarget, repo_root: Path, timeout: int
) -> tuple[str, str | None]:
    missing_tools = [tool for tool in target.prerequisites if tool != "ptau" and not command_exists(tool)]
    if missing_tools:
        return ("blocked", f"missing tools: {', '.join(missing_tools)}")

    if target.framework == "circom":
        ptau_path = discover_local_ptau(repo_root)
        if ptau_path is None:
            return ("blocked", "missing local ptau under bins/ptau")
        for note in target.dependency_notes:
            if note.startswith("include:missing"):
                return ("blocked", note)
            if note.startswith("include:bare_symbol"):
                return ("blocked", f"bare include requires extra include-path wiring: {note}")
        return ("ready", f"ptau={ptau_path}")

    if target.framework == "noir":
        project_dir = Path(target.target_path).parent
        ok, message = run_checked_command(
            ["nargo", "check", "--program-dir", str(project_dir)],
            timeout,
            project_dir,
        )
        return ("ready" if ok else "blocked", message)

    if target.framework == "halo2":
        manifest = Path(target.target_path)
        ok, message = run_checked_command(
            ["cargo", "fetch", "--manifest-path", str(manifest), "--offline"],
            timeout,
            manifest.parent,
        )
        return ("ready" if ok else "blocked", message)

    if target.framework == "cairo":
        manifest = Path(target.target_path)
        project_dir = manifest.parent
        ok, message = run_checked_command(["scarb", "metadata"], timeout, project_dir)
        return ("ready" if ok else "blocked", message)

    return ("not_run", None)


def build_repo_summaries(
    root: Path, curated_targets: list[CuratedTarget], raw_targets: list[TargetRecord]
) -> list[RepoSummary]:
    summaries: list[RepoSummary] = []
    all_repo_names = sorted(
        path.name
        for path in root.iterdir()
        if path.is_dir() and not path.name.startswith(".")
    )

    raw_by_repo: dict[str, int] = {}
    for record in raw_targets:
        repo = repo_name_for(record)
        raw_by_repo[repo] = raw_by_repo.get(repo, 0) + 1

    fit_by_repo: dict[str, int] = {}
    skipped_by_repo: dict[str, int] = {}
    for item in curated_targets:
        if item.status == "skip":
            skipped_by_repo[item.repo_name] = skipped_by_repo.get(item.repo_name, 0) + 1
        else:
            fit_by_repo[item.repo_name] = fit_by_repo.get(item.repo_name, 0) + 1

    for repo_name in all_repo_names:
        fit_count = fit_by_repo.get(repo_name, 0)
        skipped_count = skipped_by_repo.get(repo_name, 0)
        raw_count = raw_by_repo.get(repo_name, 0)

        if repo_name in FRAMEWORK_INTERNAL_REPOS:
            reason = "framework_internal_repo"
            status = "skip"
        elif repo_name in MONOREPO_NOISE_REPOS:
            reason = "requires_targeted_monorepo_onboarding"
            status = "skip"
        elif fit_count > 0:
            reason = "has_curated_targets"
            status = "fit"
        elif raw_count > 0:
            reason = "all_discovered_targets_filtered_out"
            status = "skip"
        else:
            reason = "no_direct_runnable_targets_discovered"
            status = "blocked"

        summaries.append(
            RepoSummary(
                repo_name=repo_name,
                status=status,
                reason=reason,
                fit_targets=fit_count,
                skipped_targets=skipped_count,
            )
        )
    return summaries


def render_tsv(targets: list[CuratedTarget]) -> str:
    lines = [
        "\t".join(
            [
                "display_name",
                "repo_name",
                "framework",
                "category",
                "status",
                "main_component",
                "target_path",
                "skip_reason",
                "verify_status",
            ]
        )
    ]
    for item in targets:
        lines.append(
            "\t".join(
                [
                    item.display_name,
                    item.repo_name,
                    item.framework,
                    item.category,
                    item.status,
                    item.main_component,
                    item.target_path,
                    item.skip_reason or "",
                    item.verify_status,
                ]
            )
        )
    return "\n".join(lines)


def render_markdown(
    fit_targets: list[CuratedTarget], skipped_targets: list[CuratedTarget], repo_summaries: list[RepoSummary]
) -> str:
    lines = ["# Curated ZkRepos Targets", ""]
    lines.append("## Fit Targets")
    if not fit_targets:
        lines.append("- none")
    for item in fit_targets:
        effective_status = item.verify_status if item.verify_status != "not_run" else item.status
        lines.append(
            f"- `{item.framework}` `{item.display_name}` [{item.category}] status=`{effective_status}`"
        )
        lines.append(f"  prerequisites: {', '.join(item.prerequisites)}")
        if item.dependency_notes:
            lines.append(f"  dependencies: {'; '.join(item.dependency_notes[:4])}")
        if item.verify_message:
            lines.append(f"  verify: {item.verify_message}")
    lines.append("")
    lines.append("## Skipped Targets")
    if not skipped_targets:
        lines.append("- none")
    for item in skipped_targets[:20]:
        lines.append(
            f"- `{item.framework}` `{item.display_name}` skip_reason=`{item.skip_reason}`"
        )
    if len(skipped_targets) > 20:
        lines.append(f"- ... {len(skipped_targets) - 20} more skipped targets")
    lines.append("")
    lines.append("## Repo Summary")
    for item in repo_summaries:
        lines.append(
            f"- `{item.repo_name}` status=`{item.status}` fit={item.fit_targets} skipped={item.skipped_targets} reason=`{item.reason}`"
        )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        raise SystemExit(f"Root directory does not exist: {root}")

    raw_targets = discover_targets(root)
    curated = [classify_target(record) for record in raw_targets]

    if args.verify:
        verified: list[CuratedTarget] = []
        repo_root = Path.cwd()
        for item in curated:
            if item.status == "skip":
                verified.append(item)
                continue
            verify_status, verify_message = verify_target(item, repo_root, args.timeout)
            verified.append(
                CuratedTarget(
                    display_name=item.display_name,
                    repo_name=item.repo_name,
                    framework=item.framework,
                    main_component=item.main_component,
                    target_path=item.target_path,
                    source_kind=item.source_kind,
                    category=item.category,
                    status=item.status,
                    skip_reason=item.skip_reason,
                    prerequisites=item.prerequisites,
                    dependency_notes=item.dependency_notes,
                    verify_status=verify_status,
                    verify_message=verify_message,
                )
            )
        curated = verified

    fit_targets = [item for item in curated if item.status != "skip"]
    skipped_targets = [item for item in curated if item.status == "skip"]
    repo_summaries = build_repo_summaries(root, curated, raw_targets)

    if args.format == "json":
        payload = {
            "fit_targets": [asdict(item) for item in fit_targets],
            "skipped_targets": [asdict(item) for item in skipped_targets],
            "repo_summaries": [asdict(item) for item in repo_summaries],
        }
        print(json.dumps(payload, indent=2))
    elif args.format == "tsv":
        print(render_tsv(curated))
    else:
        print(render_markdown(fit_targets, skipped_targets, repo_summaries))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
