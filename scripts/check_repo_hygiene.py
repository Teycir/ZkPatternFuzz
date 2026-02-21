#!/usr/bin/env python3
"""Fail when blocked placeholder files exist at repository root."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

DEFAULT_BLOCKED_ROOT_FILES = ("new_file.txt",)


def parse_blocklist_file(path: Path) -> set[str]:
    blocked: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        blocked.add(line)
    return blocked


def blocked_root_files(repo_root: Path, blocked_names: Iterable[str]) -> list[str]:
    matches: list[str] = []
    for name in sorted(set(blocked_names)):
        if (repo_root / name).exists():
            matches.append(name)
    return matches


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check repository root for blocked placeholder files."
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root path (default: current directory).",
    )
    parser.add_argument(
        "--blocklist",
        help="Optional newline-delimited file of additional blocked root filenames.",
    )
    parser.add_argument(
        "--json-out",
        help="Optional path to write JSON report.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    blocked = set(DEFAULT_BLOCKED_ROOT_FILES)
    if args.blocklist:
        blocked.update(parse_blocklist_file(Path(args.blocklist)))

    matches = blocked_root_files(repo_root, blocked)
    report = {
        "repo_root": str(repo_root),
        "blocked_root_files": sorted(blocked),
        "matches": matches,
        "pass": not matches,
    }

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if matches:
        print("Repo hygiene check failed: blocked root files detected.")
        for name in matches:
            print(f"  - {name}")
        return 1

    print("Repo hygiene check passed: no blocked root placeholder files found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
