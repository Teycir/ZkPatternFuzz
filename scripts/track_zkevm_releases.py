#!/usr/bin/env python3
"""Track local zkevm-circuits checkout against latest upstream stable release."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def _run_git(repo_path: Path, args: Iterable[str]) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_path), *list(args)],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        details = stderr or stdout or "git command failed"
        raise RuntimeError(f"git {' '.join(args)} failed: {details}")
    return proc.stdout.strip()


def _parse_iso8601(value: Optional[str]) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def select_latest_stable_release(releases: List[Dict[str, Any]]) -> Dict[str, Any]:
    stable = [r for r in releases if not r.get("draft") and not r.get("prerelease")]
    if not stable:
        raise ValueError("No stable release found (all releases are draft/prerelease)")

    # Sort by published_at first, with created_at as tie-breaker.
    stable.sort(
        key=lambda r: (
            _parse_iso8601(r.get("published_at")),
            _parse_iso8601(r.get("created_at")),
        ),
        reverse=True,
    )
    return stable[0]


def _fetch_releases(repo_slug: str, timeout_seconds: int) -> List[Dict[str, Any]]:
    url = f"https://api.github.com/repos/{repo_slug}/releases?per_page=50"
    req = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "zkpatternfuzz-zkevm-release-tracker",
        },
    )
    try:
        with urlopen(req, timeout=timeout_seconds) as response:
            payload = response.read().decode("utf-8")
    except HTTPError as exc:
        raise RuntimeError(f"GitHub releases API returned HTTP {exc.code} for {repo_slug}") from exc
    except URLError as exc:
        raise RuntimeError(f"Failed to reach GitHub releases API for {repo_slug}: {exc}") from exc

    data = json.loads(payload)
    if not isinstance(data, list):
        raise RuntimeError("Unexpected GitHub releases API payload: expected JSON list")
    return data


def _load_releases_from_file(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"Release file must contain a JSON list: {path}")
    return data


def _resolve_tag_commit(repo_path: Path, tag_name: str) -> str:
    if not tag_name:
        raise ValueError("Latest release is missing tag_name")

    raw = _run_git(
        repo_path,
        ["ls-remote", "--tags", "origin", f"refs/tags/{tag_name}", f"refs/tags/{tag_name}^{{}}"],
    )
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError(
            f"Release tag '{tag_name}' was not found on origin remote for {repo_path}"
        )

    # Prefer dereferenced annotated-tag commit (^{}), recovery to direct tag line.
    deref = [line for line in lines if line.endswith("^{}")]
    chosen = deref[0] if deref else lines[0]
    commit = chosen.split()[0]
    if len(commit) < 7:
        raise RuntimeError(f"Invalid commit hash resolved for tag {tag_name}: {commit!r}")
    return commit


def classify_relationship(repo_path: Path, local_sha: str, upstream_sha: str) -> str:
    if local_sha == upstream_sha:
        return "up_to_date"

    local_ancestor = subprocess.run(
        ["git", "-C", str(repo_path), "merge-base", "--is-ancestor", local_sha, upstream_sha],
        check=False,
    )
    if local_ancestor.returncode == 0:
        return "behind_latest_release"

    upstream_ancestor = subprocess.run(
        ["git", "-C", str(repo_path), "merge-base", "--is-ancestor", upstream_sha, local_sha],
        check=False,
    )
    if upstream_ancestor.returncode == 0:
        return "ahead_contains_latest_release"

    return "diverged"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Track local zkevm-circuits checkout against latest upstream stable release."
    )
    parser.add_argument(
        "--repo-path",
        default="circuits/zkevm-circuits",
        help="Local zkevm-circuits git checkout path",
    )
    parser.add_argument(
        "--repo-slug",
        default="scroll-tech/zkevm-circuits",
        help="GitHub repo slug used for release API (owner/repo)",
    )
    parser.add_argument(
        "--releases-json",
        default="",
        help="Optional local JSON file with GitHub releases payload (offline/testing)",
    )
    parser.add_argument(
        "--release-commit",
        default="",
        help=(
            "Optional explicit commit for latest release tag (strict offline mode). "
            "When set, skips origin tag lookup."
        ),
    )
    parser.add_argument(
        "--output",
        default="artifacts/dependency_tracking/zkevm_upstream_latest.json",
        help="Output report JSON path",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=15,
        help="Network timeout when querying releases API",
    )
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Exit non-zero unless local checkout contains latest stable release commit",
    )
    args = parser.parse_args(argv)

    root_dir = Path(__file__).resolve().parents[1]
    repo_path = Path(args.repo_path)
    if not repo_path.is_absolute():
        repo_path = (root_dir / repo_path).resolve()

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = (root_dir / output_path).resolve()

    if not repo_path.exists():
        raise FileNotFoundError(f"Local repo path not found: {repo_path}")
    if not (repo_path / ".git").exists():
        raise RuntimeError(f"Not a git repository (missing .git): {repo_path}")

    local_head = _run_git(repo_path, ["rev-parse", "HEAD"])
    origin_url = _run_git(repo_path, ["config", "--get", "remote.origin.url"])

    source = "github_api"
    if args.releases_json:
        releases_path = Path(args.releases_json)
        if not releases_path.is_absolute():
            releases_path = (root_dir / releases_path).resolve()
        releases = _load_releases_from_file(releases_path)
        source = f"file:{releases_path}"
    else:
        releases = _fetch_releases(args.repo_slug, args.timeout_seconds)

    latest = select_latest_stable_release(releases)
    tag_name = str(latest.get("tag_name") or "").strip()
    if args.release_commit:
        upstream_commit = args.release_commit.strip()
        if len(upstream_commit) < 7 or re.fullmatch(r"[0-9a-fA-F]+", upstream_commit) is None:
            raise ValueError(
                f"Invalid --release-commit value (expected git commit): {upstream_commit!r}"
            )
    else:
        upstream_commit = _resolve_tag_commit(repo_path, tag_name)

    relationship = classify_relationship(repo_path, local_head, upstream_commit)
    up_to_date = relationship in {"up_to_date", "ahead_contains_latest_release"}

    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "repo_path": str(repo_path),
        "origin_url": origin_url,
        "repo_slug": args.repo_slug,
        "source": source,
        "local_head": local_head,
        "local_head_short": local_head[:8],
        "latest_release": {
            "tag_name": tag_name,
            "name": latest.get("name"),
            "html_url": latest.get("html_url"),
            "published_at": latest.get("published_at"),
            "target_commitish": latest.get("target_commitish"),
            "draft": bool(latest.get("draft")),
            "prerelease": bool(latest.get("prerelease")),
            "commit": upstream_commit,
            "commit_short": upstream_commit[:8],
        },
        "status": relationship,
        "up_to_date": up_to_date,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(
        "zkevm release tracker:",
        f"status={relationship}",
        f"local={local_head[:8]}",
        f"release_tag={tag_name}",
        f"release_commit={upstream_commit[:8]}",
        f"report={output_path}",
    )

    if args.enforce and not up_to_date:
        print(
            "enforce failed: local checkout does not contain latest stable upstream release",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
