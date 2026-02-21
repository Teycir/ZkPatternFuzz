#!/usr/bin/env python3
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "track_zkevm_releases.py"
    spec = importlib.util.spec_from_file_location("track_zkevm_releases", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tracker = _load_module()


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


class TrackZkevmReleasesTests(unittest.TestCase):
    def test_select_latest_stable_release_skips_draft_and_prerelease(self):
        releases = [
            {
                "tag_name": "v0.4.0-rc1",
                "published_at": "2026-01-03T00:00:00Z",
                "draft": False,
                "prerelease": True,
            },
            {
                "tag_name": "v0.3.1",
                "published_at": "2026-01-02T00:00:00Z",
                "draft": False,
                "prerelease": False,
            },
            {
                "tag_name": "v0.4.0",
                "published_at": "2026-01-04T00:00:00Z",
                "draft": False,
                "prerelease": False,
            },
            {
                "tag_name": "v0.5.0",
                "published_at": "2026-01-05T00:00:00Z",
                "draft": True,
                "prerelease": False,
            },
        ]

        latest = tracker.select_latest_stable_release(releases)
        self.assertEqual(latest["tag_name"], "v0.4.0")

    def test_classify_relationship_states(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_zkevm_rel_") as tmpdir:
            repo = Path(tmpdir)
            _git(repo, "init")
            _git(repo, "config", "user.email", "tester@example.com")
            _git(repo, "config", "user.name", "Tester")

            file_path = repo / "state.txt"
            file_path.write_text("one\n", encoding="utf-8")
            _git(repo, "add", "state.txt")
            _git(repo, "commit", "-m", "c1")
            c1 = _git(repo, "rev-parse", "HEAD")

            file_path.write_text("two\n", encoding="utf-8")
            _git(repo, "commit", "-am", "c2")
            c2 = _git(repo, "rev-parse", "HEAD")

            self.assertEqual(tracker.classify_relationship(repo, c2, c2), "up_to_date")
            self.assertEqual(
                tracker.classify_relationship(repo, c1, c2), "behind_latest_release"
            )
            self.assertEqual(
                tracker.classify_relationship(repo, c2, c1), "ahead_contains_latest_release"
            )

    def test_main_writes_report_with_local_release_fixture(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_zkevm_main_") as tmpdir:
            root = Path(tmpdir)
            repo = root / "zkevm-circuits"
            repo.mkdir(parents=True, exist_ok=True)
            _git(repo, "init")
            _git(repo, "config", "user.email", "tester@example.com")
            _git(repo, "config", "user.name", "Tester")

            (repo / "state.txt").write_text("one\n", encoding="utf-8")
            _git(repo, "add", "state.txt")
            _git(repo, "commit", "-m", "initial")
            _git(repo, "tag", "v0.1.0")
            local_head = _git(repo, "rev-parse", "HEAD")

            # Create a bare remote and push so ls-remote origin works.
            remote_bare = root / "remote.git"
            _git(root, "init", "--bare", str(remote_bare))
            _git(repo, "remote", "add", "origin", str(remote_bare))
            _git(repo, "push", "origin", "HEAD")
            _git(repo, "push", "origin", "v0.1.0")

            releases = [
                {
                    "tag_name": "v0.1.0",
                    "published_at": "2026-01-01T00:00:00Z",
                    "draft": False,
                    "prerelease": False,
                    "name": "v0.1.0",
                    "html_url": "https://example.invalid/v0.1.0",
                    "target_commitish": "main",
                }
            ]
            releases_path = root / "releases.json"
            releases_path.write_text(json.dumps(releases), encoding="utf-8")

            output_path = root / "report.json"
            rc = tracker.main(
                [
                    "--repo-path",
                    str(repo),
                    "--repo-slug",
                    "scroll-tech/zkevm-circuits",
                    "--releases-json",
                    str(releases_path),
                    "--output",
                    str(output_path),
                    "--enforce",
                ]
            )
            self.assertEqual(rc, 0)
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "up_to_date")
            self.assertTrue(report["up_to_date"])
            self.assertEqual(report["local_head"], local_head)
            self.assertEqual(report["latest_release"]["tag_name"], "v0.1.0")


if __name__ == "__main__":
    unittest.main()
