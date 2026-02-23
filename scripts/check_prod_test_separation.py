#!/usr/bin/env python3
"""Fail CI when production Rust sources mix in test-only modules/symbols."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

DEFAULT_SEARCH_ROOTS = ("src", "crates")
EXCLUDED_DIR_NAMES = {"target", "tests", "benches", "examples"}
MOD_DECL_PATTERN = re.compile(r"^\s*mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
PATH_ATTR_PATTERN = re.compile(r'^\s*#\[\s*path\s*=\s*"([^"]+)"\s*\]')
USE_TEST_SYMBOL_PATTERN = re.compile(
    r"\b(?:pub(?:\([^)]*\))?\s+)?use\s+[^;]*(?:\btests\b|_tests\b)"
)
TEST_ATTR_PATTERN = re.compile(r"^#!?\[(?:[A-Za-z_][A-Za-z0-9_]*::)*test(?:[(\]]|$)")


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    kind: str
    code: str


def _is_excluded_path(path: Path) -> bool:
    name = path.name
    if name == "tests.rs" or name.endswith("_tests.rs") or name.startswith("test_"):
        return True
    return any(part in EXCLUDED_DIR_NAMES for part in path.parts)


def _is_cfg_test_attr(raw_attr: str) -> bool:
    compact = re.sub(r"\s+", "", raw_attr)
    return compact.startswith("#[cfg(test)]")


def _path_attr_target(raw_attr: str) -> str | None:
    match = PATH_ATTR_PATTERN.match(raw_attr.strip())
    if not match:
        return None
    return match.group(1)


def _is_test_path(path_str: str) -> bool:
    norm = path_str.replace("\\", "/")
    name = norm.rsplit("/", 1)[-1]
    if name == "tests.rs" or name.endswith("_tests.rs") or name.startswith("test_"):
        return True
    return "/tests/" in f"/{norm}/"


def _is_test_attribute_line(raw_attr: str) -> bool:
    compact = re.sub(r"\s+", "", raw_attr)
    if compact.startswith("#[cfg(test)]") or compact.startswith("#![cfg(test)]"):
        return True
    if compact.startswith("#[cfg_attr(test,") or compact.startswith("#![cfg_attr(test,"):
        return True
    return TEST_ATTR_PATTERN.match(compact) is not None


def collect_violations(repo_root: Path, search_roots: Iterable[str]) -> List[Violation]:
    violations: List[Violation] = []

    for root_name in search_roots:
        root = (repo_root / root_name).resolve()
        if not root.exists():
            continue

        for rust_file in root.rglob("*.rs"):
            rel = rust_file.relative_to(repo_root)
            if _is_excluded_path(rel):
                continue

            try:
                lines = rust_file.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                lines = rust_file.read_text(encoding="utf-8", errors="ignore").splitlines()

            pending_attrs: List[str] = []
            for idx, raw_line in enumerate(lines, start=1):
                stripped = raw_line.strip()

                # Repository policy: root production tree (src/**) must not define test attributes.
                if rel.parts and rel.parts[0] == "src" and _is_test_attribute_line(stripped):
                    violations.append(
                        Violation(
                            path=str(rel),
                            line=idx,
                            kind="test_attribute_in_src",
                            code=raw_line.rstrip(),
                        )
                    )

                if stripped.startswith("#["):
                    pending_attrs.append(stripped)
                    continue

                if not stripped:
                    pending_attrs.clear()
                    continue

                if stripped.startswith("//"):
                    continue

                has_cfg_test = any(_is_cfg_test_attr(attr) for attr in pending_attrs)
                has_test_path_attr = any(
                    _is_test_path(path_target)
                    for path_target in (
                        _path_attr_target(attr) for attr in pending_attrs
                    )
                    if path_target is not None
                )

                if USE_TEST_SYMBOL_PATTERN.search(raw_line):
                    violations.append(
                        Violation(
                            path=str(rel),
                            line=idx,
                            kind="test_symbol_import_or_reexport",
                            code=raw_line.rstrip(),
                        )
                    )

                mod_match = MOD_DECL_PATTERN.match(raw_line)
                if mod_match:
                    module_name = mod_match.group(1)
                    if (module_name == "tests" or module_name.endswith("_tests")) and not has_cfg_test:
                        violations.append(
                            Violation(
                                path=str(rel),
                                line=idx,
                                kind="test_module_without_cfg_test",
                                code=raw_line.rstrip(),
                            )
                        )
                    if has_test_path_attr and not has_cfg_test:
                        violations.append(
                            Violation(
                                path=str(rel),
                                line=idx,
                                kind="test_path_module_without_cfg_test",
                                code=raw_line.rstrip(),
                            )
                        )
                elif has_test_path_attr and not has_cfg_test:
                    violations.append(
                        Violation(
                            path=str(rel),
                            line=idx,
                            kind="test_path_attr_without_cfg_test",
                            code=raw_line.rstrip(),
                        )
                    )

                pending_attrs.clear()

    violations.sort(key=lambda v: (v.path, v.line, v.kind, v.code))
    return violations


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check production Rust sources for prod/test separation violations."
    )
    parser.add_argument("--repo-root", default=".", help="Repository root path.")
    parser.add_argument(
        "--search-roots",
        default=",".join(DEFAULT_SEARCH_ROOTS),
        help="Comma-separated roots to scan (default: src,crates).",
    )
    parser.add_argument("--json-out", help="Optional JSON report output path.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    roots = [part.strip() for part in args.search_roots.split(",") if part.strip()]

    violations = collect_violations(repo_root, roots)
    report = {
        "repo_root": str(repo_root),
        "search_roots": roots,
        "violations": [v.__dict__ for v in violations],
        "pass": len(violations) == 0,
    }

    if args.json_out:
        out = Path(args.json_out)
        if not out.is_absolute():
            out = (repo_root / out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if not violations:
        print("Production/test separation check passed: no violations found.")
        return 0

    print("Production/test separation check failed:")
    for violation in violations:
        print(
            f"  - {violation.path}:{violation.line}: {violation.kind}: {violation.code.strip()}"
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
