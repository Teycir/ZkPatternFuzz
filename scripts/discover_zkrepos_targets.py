#!/usr/bin/env python3
"""Discover runnable ZK targets under a repo root.

This helper turns a live checkout such as /home/teycir/ZkRepos into direct
target paths that the existing zkpatternfuzz wrappers can consume.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore


DEFAULT_ROOT = Path("/home/teycir/ZkRepos")
SKIP_DIRS = {
    ".git",
    ".github",
    ".yarn",
    ".venv",
    "__pycache__",
    "artifacts",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
    "venv",
}


@dataclass(frozen=True)
class TargetRecord:
    display_name: str
    framework: str
    main_component: str
    target_path: str
    source_kind: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Discover runnable zkpatternfuzz targets under a live repo root."
    )
    parser.add_argument(
        "--root",
        default=str(DEFAULT_ROOT),
        help="Root directory to scan (default: %(default)s)",
    )
    parser.add_argument(
        "--format",
        choices=("tsv", "json", "env"),
        default="tsv",
        help="Output format (default: %(default)s)",
    )
    parser.add_argument(
        "--match",
        help="Filter to targets whose display name or path contains this case-insensitive text",
    )
    parser.add_argument(
        "--profile",
        choices=("smoke", "standard", "deep"),
        help="Required with --format env to emit ZKF_STD_TARGET_* bindings",
    )
    return parser.parse_args()


def iter_paths(root: Path) -> Iterable[Path]:
    for raw_root, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in SKIP_DIRS)
        current_root = Path(raw_root)
        for filename in sorted(filenames):
            yield current_root / filename


def relative_display_name(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def parse_circom_main_component(source: str) -> str | None:
    match = re.search(
        r"component\s+main(?:\s*\{[^}]*\})?\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        source,
    )
    if match:
        return match.group(1)
    return None


def parse_halo2_main_component(manifest_path: Path) -> str:
    with manifest_path.open("rb") as handle:
        manifest = tomllib.load(handle)

    package = manifest.get("package")
    if isinstance(package, dict):
        default_run = package.get("default-run")
        if isinstance(default_run, str) and default_run.strip():
            return default_run.strip()

    bins = manifest.get("bin")
    if isinstance(bins, list):
        for item in bins:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if isinstance(name, str) and name.strip():
                return name.strip()

    src_main = manifest_path.parent / "src" / "main.rs"
    if src_main.is_file():
        package_name = package.get("name") if isinstance(package, dict) else None
        if isinstance(package_name, str) and package_name.strip():
            return package_name.strip()
        return "main"

    return "main"


def cargo_manifest_looks_like_halo2(manifest_path: Path) -> bool:
    text = manifest_path.read_text(encoding="utf-8", errors="ignore").lower()
    if "halo2" not in text:
        return False
    return True


def discover_targets(root: Path) -> list[TargetRecord]:
    records: list[TargetRecord] = []
    seen_paths: set[str] = set()

    for path in iter_paths(root):
        if path.suffix == ".circom":
            target_path = str(path.resolve())
            if target_path in seen_paths:
                continue
            source = path.read_text(encoding="utf-8", errors="ignore")
            main_component = parse_circom_main_component(source)
            if main_component is None:
                continue
            records.append(
                TargetRecord(
                    display_name=relative_display_name(root, path),
                    framework="circom",
                    main_component=main_component,
                    target_path=target_path,
                    source_kind="circom_file",
                )
            )
            seen_paths.add(target_path)
            continue

        if path.name == "Nargo.toml":
            target_path = str(path.resolve())
            if target_path in seen_paths:
                continue
            records.append(
                TargetRecord(
                    display_name=relative_display_name(root, path),
                    framework="noir",
                    main_component="main",
                    target_path=target_path,
                    source_kind="nargo_manifest",
                )
            )
            seen_paths.add(target_path)
            continue

        if path.name == "Scarb.toml":
            target_path = str(path.resolve())
            if target_path in seen_paths:
                continue
            records.append(
                TargetRecord(
                    display_name=relative_display_name(root, path),
                    framework="cairo",
                    main_component="main",
                    target_path=target_path,
                    source_kind="scarb_manifest",
                )
            )
            seen_paths.add(target_path)
            continue

        if path.name == "Cargo.toml" and cargo_manifest_looks_like_halo2(path):
            target_path = str(path.resolve())
            if target_path in seen_paths:
                continue
            records.append(
                TargetRecord(
                    display_name=relative_display_name(root, path),
                    framework="halo2",
                    main_component=parse_halo2_main_component(path),
                    target_path=target_path,
                    source_kind="cargo_manifest",
                )
            )
            seen_paths.add(target_path)

    records.sort(key=lambda item: (item.framework, item.display_name))
    return records


def filter_records(records: list[TargetRecord], raw_match: str | None) -> list[TargetRecord]:
    if not raw_match:
        return records
    needle = raw_match.lower()
    return [
        item
        for item in records
        if needle in item.display_name.lower() or needle in item.target_path.lower()
    ]


def render_tsv(records: list[TargetRecord]) -> str:
    lines = ["display_name\tframework\tmain_component\ttarget_path\tsource_kind"]
    for item in records:
        lines.append(
            "\t".join(
                [
                    item.display_name,
                    item.framework,
                    item.main_component,
                    item.target_path,
                    item.source_kind,
                ]
            )
        )
    return "\n".join(lines)


def render_json(records: list[TargetRecord]) -> str:
    payload = [asdict(item) for item in records]
    return json.dumps(payload, indent=2)


def render_env(records: list[TargetRecord], profile: str | None) -> str:
    if not profile:
        raise SystemExit("--profile is required when --format env is used")
    if len(records) != 1:
        raise SystemExit(
            f"--format env requires exactly one matched target, found {len(records)}"
        )
    item = records[0]
    prefix = f"ZKF_STD_TARGET_{profile.upper()}"
    return "\n".join(
        [
            f"{prefix}={item.target_path}",
            f"{prefix}_FRAMEWORK={item.framework}",
            f"{prefix}_MAIN_COMPONENT={item.main_component}",
        ]
    )


def main() -> int:
    args = parse_args()
    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        print(f"Target root does not exist or is not a directory: {root}", file=sys.stderr)
        return 1

    records = filter_records(discover_targets(root), args.match)
    if args.format == "tsv":
        print(render_tsv(records))
        return 0
    if args.format == "json":
        print(render_json(records))
        return 0

    print(render_env(records, args.profile))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
