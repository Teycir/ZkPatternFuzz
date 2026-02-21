#!/usr/bin/env python3
"""Fail CI when new production panic-surface calls are introduced.

Tracks `.unwrap(` and `.expect(` occurrences in production Rust sources under
`src/` and `crates/`, excluding test files/dirs, and compares them against an
explicit allowlist.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Set

PANIC_PATTERN = re.compile(r"\.(unwrap|expect)\(")
DEFAULT_SEARCH_ROOTS = ("src", "crates")
EXCLUDED_DIR_NAMES = {"target", "tests", "benches", "examples"}


@dataclass(frozen=True)
class PanicMatch:
    path: str
    line: int
    code: str

    def key(self) -> str:
        return f"{self.path}|{self.code.strip()}"


def _is_excluded_path(path: Path) -> bool:
    name = path.name
    if name == "tests.rs" or name.endswith("_tests.rs") or name.startswith("test_"):
        return True
    return any(part in EXCLUDED_DIR_NAMES for part in path.parts)


def collect_panic_matches(repo_root: Path, search_roots: Iterable[str]) -> List[PanicMatch]:
    matches: List[PanicMatch] = []

    for root_name in search_roots:
        root = (repo_root / root_name).resolve()
        if not root.exists():
            continue
        for rust_file in root.rglob("*.rs"):
            rel = rust_file.relative_to(repo_root)
            if _is_excluded_path(rel):
                continue

            try:
                text = rust_file.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                text = rust_file.read_text(encoding="utf-8", errors="ignore")

            for idx, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.startswith("//"):
                    continue
                if PANIC_PATTERN.search(line) is None:
                    continue
                matches.append(PanicMatch(path=str(rel), line=idx, code=line.rstrip()))

    # Deterministic ordering
    matches.sort(key=lambda m: (m.path, m.line, m.code))
    return matches


def load_allowlist(path: Path) -> Set[str]:
    if not path.exists():
        return set()
    keys: Set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        keys.add(line)
    return keys


def write_allowlist(path: Path, keys: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sorted_keys = sorted(set(keys))
    content = "\n".join(sorted_keys) + ("\n" if sorted_keys else "")
    path.write_text(content, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check production panic-surface calls against an explicit allowlist."
    )
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument(
        "--allowlist",
        default="config/panic_surface_allowlist.txt",
        help="Allowlist file with entries in 'path|code' format",
    )
    parser.add_argument(
        "--search-roots",
        default=",".join(DEFAULT_SEARCH_ROOTS),
        help="Comma-separated roots to scan (default: src,crates)",
    )
    parser.add_argument(
        "--write-allowlist",
        action="store_true",
        help="Rewrite allowlist from current scan and exit 0",
    )
    parser.add_argument(
        "--fail-on-stale",
        action="store_true",
        help="Fail when allowlist contains entries no longer present",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    allowlist_path = Path(args.allowlist)
    if not allowlist_path.is_absolute():
        allowlist_path = (repo_root / allowlist_path).resolve()

    roots = [part.strip() for part in args.search_roots.split(",") if part.strip()]
    matches = collect_panic_matches(repo_root, roots)
    current_keys = {m.key() for m in matches}

    if args.write_allowlist:
        write_allowlist(allowlist_path, current_keys)
        print(
            f"panic-surface allowlist written: {allowlist_path} (entries={len(current_keys)})"
        )
        return 0

    allowed = load_allowlist(allowlist_path)
    unknown = sorted(current_keys - allowed)
    stale = sorted(allowed - current_keys)

    print(
        "panic-surface check:",
        f"matches={len(current_keys)}",
        f"allowlist={len(allowed)}",
        f"unknown={len(unknown)}",
        f"stale={len(stale)}",
    )

    if unknown:
        print("\nNew panic-surface entries not in allowlist:")
        for entry in unknown:
            print(f"  {entry}")
        print("\nUpdate allowlist intentionally via:")
        print("  python3 scripts/check_panic_surface.py --write-allowlist")
        return 1

    if args.fail_on_stale and stale:
        print("\nStale allowlist entries (no longer present):")
        for entry in stale:
            print(f"  {entry}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
