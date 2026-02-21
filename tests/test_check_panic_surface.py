#!/usr/bin/env python3
import importlib.util
import sys
import tempfile
from pathlib import Path
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "check_panic_surface.py"
    spec = importlib.util.spec_from_file_location("check_panic_surface", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_module()


class PanicSurfaceCheckTests(unittest.TestCase):
    def test_is_excluded_path_filters_tests(self):
        self.assertTrue(checker._is_excluded_path(Path("src/foo/tests.rs")))
        self.assertTrue(checker._is_excluded_path(Path("src/foo/bar_tests.rs")))
        self.assertTrue(checker._is_excluded_path(Path("src/foo/test_utils.rs")))
        self.assertTrue(checker._is_excluded_path(Path("src/tests/mod.rs")))
        self.assertFalse(checker._is_excluded_path(Path("src/foo/mod.rs")))

    def test_collect_matches_ignores_comments_and_tests(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_panic_surface_") as tmpdir:
            root = Path(tmpdir)
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "main.rs").write_text(
                """
fn run() {
    let _x = maybe().unwrap();
    // let _ignored = maybe().expect("comment only");
}
""".strip()
                + "\n",
                encoding="utf-8",
            )
            (root / "src" / "tests.rs").write_text(
                "fn t() { let _ = maybe().unwrap(); }\n",
                encoding="utf-8",
            )
            (root / "crates" / "foo" / "src").mkdir(parents=True, exist_ok=True)
            (root / "crates" / "foo" / "src" / "lib.rs").write_text(
                "fn f() { let _ = maybe().expect(\"boom\"); }\n",
                encoding="utf-8",
            )

            matches = checker.collect_panic_matches(root, ["src", "crates"])
            keys = [m.key() for m in matches]
            self.assertEqual(len(keys), 2)
            self.assertTrue(any("src/main.rs" in k for k in keys))
            self.assertTrue(any("crates/foo/src/lib.rs" in k for k in keys))
            self.assertFalse(any("src/tests.rs" in k for k in keys))

    def test_allowlist_roundtrip(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_panic_allowlist_") as tmpdir:
            allowlist = Path(tmpdir) / "allow.txt"
            keys = {
                "src/main.rs|let _x = maybe().unwrap();",
                "crates/foo/src/lib.rs|let _ = maybe().expect(\"boom\");",
            }
            checker.write_allowlist(allowlist, keys)
            loaded = checker.load_allowlist(allowlist)
            self.assertEqual(loaded, keys)


if __name__ == "__main__":
    unittest.main()
