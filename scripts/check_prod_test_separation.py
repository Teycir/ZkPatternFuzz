#!/usr/bin/env python3
"""Fail CI when production Rust sources mix in test-only modules/symbols."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

DEFAULT_SEARCH_ROOTS = ("src", "crates")
DEFAULT_BASELINE = "config/prod_test_separation_baseline.json"
EXCLUDED_DIR_NAMES = {"target", "tests", "benches", "examples"}
MOD_DECL_PATTERN = re.compile(r"^\s*mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
PATH_ATTR_PATTERN = re.compile(r'^\s*#\[\s*path\s*=\s*"([^"]+)"\s*\]')
USE_TEST_SYMBOL_PATTERN = re.compile(
    r"\b(?:pub(?:\([^)]*\))?\s+)?use\s+[^;]*(?:\btests\b|_tests\b)"
)
TEST_ATTR_PATTERN = re.compile(r"^#!?\[(?:[A-Za-z_][A-Za-z0-9_]*::)*test(?:[(\]]|$)")
TEST_WORD_PATTERN = re.compile(r"(?<![A-Za-z0-9_])test(?![A-Za-z0-9_])")


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    kind: str
    code: str

    def signature(self) -> tuple[str, str, str]:
        return (self.path, self.kind, self.code.strip())


def _is_test_like_filename(name: str) -> bool:
    return name == "tests.rs" or name.endswith("_tests.rs") or name.startswith("test_")


def _is_excluded_path(path: Path) -> bool:
    return any(part in EXCLUDED_DIR_NAMES for part in path.parts)


def _path_attr_target(raw_attr: str) -> str | None:
    match = PATH_ATTR_PATTERN.match(raw_attr.strip())
    if not match:
        return None
    return match.group(1)


def _is_test_path(path_str: str) -> bool:
    norm = path_str.replace("\\", "/")
    name = norm.rsplit("/", 1)[-1]
    if _is_test_like_filename(name):
        return True
    return "/tests/" in f"/{norm}/"


def _is_test_attribute_line(raw_attr: str) -> bool:
    compact = re.sub(r"\s+", "", raw_attr)
    if TEST_ATTR_PATTERN.match(compact) is not None:
        return True
    if compact.startswith("#[cfg(") or compact.startswith("#![cfg("):
        return TEST_WORD_PATTERN.search(compact) is not None
    if compact.startswith("#[cfg_attr(") or compact.startswith("#![cfg_attr("):
        return TEST_WORD_PATTERN.search(compact) is not None
    return False


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

            if _is_test_like_filename(rust_file.name):
                violations.append(
                    Violation(
                        path=str(rel),
                        line=1,
                        kind="test_file_in_production_tree",
                        code=rust_file.name,
                    )
                )

            try:
                lines = rust_file.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                lines = rust_file.read_text(encoding="utf-8", errors="ignore").splitlines()

            pending_attrs: List[str] = []
            for idx, raw_line in enumerate(lines, start=1):
                stripped = raw_line.strip()

                if _is_test_attribute_line(stripped):
                    violations.append(
                        Violation(
                            path=str(rel),
                            line=idx,
                            kind="test_attribute_in_production",
                            code=raw_line.rstrip(),
                        )
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

                if stripped.startswith("#["):
                    pending_attrs.append(stripped)
                    continue

                if not stripped:
                    pending_attrs.clear()
                    continue

                if stripped.startswith("//"):
                    continue

                has_test_path_attr = any(
                    _is_test_path(path_target)
                    for path_target in (
                        _path_attr_target(attr) for attr in pending_attrs
                    )
                    if path_target is not None
                )

                if has_test_path_attr:
                    violations.append(
                        Violation(
                            path=str(rel),
                            line=idx,
                            kind="test_path_attr_in_production",
                            code=raw_line.rstrip(),
                        )
                    )

                mod_match = MOD_DECL_PATTERN.match(raw_line)
                if mod_match:
                    module_name = mod_match.group(1)
                    if module_name == "tests" or module_name.endswith("_tests"):
                        violations.append(
                            Violation(
                                path=str(rel),
                                line=idx,
                                kind="test_module_decl_in_production",
                                code=raw_line.rstrip(),
                            )
                        )

                pending_attrs.clear()

    violations.sort(key=lambda v: (v.path, v.line, v.kind, v.code))
    return violations


def _load_baseline(baseline_path: Path) -> dict[tuple[str, str, str], int]:
    if not baseline_path.exists():
        return {}
    data = json.loads(baseline_path.read_text(encoding="utf-8"))
    entries = data.get("violations", [])
    signatures: dict[tuple[str, str, str], int] = {}
    for entry in entries:
        path = str(entry.get("path", "")).strip()
        kind = str(entry.get("kind", "")).strip()
        code = str(entry.get("code", "")).strip()
        count = int(entry.get("count", 1))
        if path and kind and code and count > 0:
            signatures[(path, kind, code)] = count
    return signatures


def _write_baseline(baseline_path: Path, violations: list[Violation]) -> None:
    counts = Counter(v.signature() for v in violations)
    unique = sorted(
        counts.items(),
        key=lambda item: (item[0][0], item[0][1], item[0][2]),
    )
    payload = {
        "format_version": 1,
        "description": "Known legacy prod/test separation violations; CI fails on any new entries.",
        "violations": [
            {"path": path, "kind": kind, "code": code, "count": count}
            for ((path, kind, code), count) in unique
        ],
    }
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


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
    parser.add_argument(
        "--baseline",
        default=DEFAULT_BASELINE,
        help="Baseline JSON path for known legacy violations.",
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Write/update baseline with current violations and exit success.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on any violation, ignoring baseline.",
    )
    parser.add_argument("--json-out", help="Optional JSON report output path.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    roots = [part.strip() for part in args.search_roots.split(",") if part.strip()]
    baseline_path = Path(args.baseline)
    if not baseline_path.is_absolute():
        baseline_path = (repo_root / baseline_path).resolve()

    violations = collect_violations(repo_root, roots)

    if args.write_baseline:
        _write_baseline(baseline_path, violations)
        print(
            f"Wrote prod/test separation baseline: {baseline_path} "
            f"({len({v.signature() for v in violations})} signatures, "
            f"{len(violations)} total violations)"
        )
        return 0

    baseline_counts = _load_baseline(baseline_path) if not args.strict else {}
    if args.strict:
        new_violations = violations
    else:
        seen_counts: dict[tuple[str, str, str], int] = {}
        new_violations = []
        for violation in violations:
            signature = violation.signature()
            seen = seen_counts.get(signature, 0) + 1
            seen_counts[signature] = seen
            if seen > baseline_counts.get(signature, 0):
                new_violations.append(violation)

    report = {
        "repo_root": str(repo_root),
        "search_roots": roots,
        "baseline_path": str(baseline_path),
        "strict": args.strict,
        "violation_count": len(violations),
        "legacy_violation_count": len(violations) - len(new_violations),
        "new_violation_count": len(new_violations),
        "baseline_signature_count": len(baseline_counts),
        "violations": [v.__dict__ for v in violations],
        "new_violations": [v.__dict__ for v in new_violations],
        "pass": len(new_violations) == 0,
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

    if args.strict:
        print("Production/test separation check failed (strict mode):")
        for violation in violations:
            print(
                f"  - {violation.path}:{violation.line}: {violation.kind}: "
                f"{violation.code.strip()}"
            )
        return 1

    if not baseline_path.exists():
        print(
            "Production/test separation check failed: baseline not found and violations exist."
        )
        print(f"Generate baseline with: python3 {Path(__file__).name} --write-baseline")
        return 1

    if not new_violations:
        print(
            "Production/test separation check passed: no new violations "
            f"(legacy baseline signatures matched: {len(baseline_counts)})."
        )
        return 0

    print("Production/test separation check failed: new violations detected.")
    for violation in new_violations:
        print(
            f"  - {violation.path}:{violation.line}: {violation.kind}: {violation.code.strip()}"
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
