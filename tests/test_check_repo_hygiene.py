#!/usr/bin/env python3
import importlib.util
import sys
import tempfile
from pathlib import Path
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "check_repo_hygiene.py"
    spec = importlib.util.spec_from_file_location("check_repo_hygiene", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


repo_hygiene = _load_module()


class CheckRepoHygieneTests(unittest.TestCase):
    def test_detects_default_blocked_root_file(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_repo_hygiene_") as tmpdir:
            root = Path(tmpdir)
            (root / "new_file.txt").write_text("", encoding="utf-8")
            matches = repo_hygiene.blocked_root_files(
                root, repo_hygiene.DEFAULT_BLOCKED_ROOT_FILES
            )
            self.assertEqual(matches, ["new_file.txt"])

    def test_parse_blocklist_file_ignores_comments(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_repo_hygiene_") as tmpdir:
            blocklist = Path(tmpdir) / "blocklist.txt"
            blocklist.write_text(
                "# comment\n\ncustom_placeholder.txt\n  extra.log  \n",
                encoding="utf-8",
            )
            blocked = repo_hygiene.parse_blocklist_file(blocklist)
            self.assertEqual(blocked, {"custom_placeholder.txt", "extra.log"})

    def test_main_passes_when_no_matches(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_repo_hygiene_") as tmpdir:
            root = Path(tmpdir)
            (root / "README.md").write_text("ok\n", encoding="utf-8")
            exit_code = repo_hygiene.main(["--repo-root", str(root)])
            self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
