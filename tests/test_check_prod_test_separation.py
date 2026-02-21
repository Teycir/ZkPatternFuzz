#!/usr/bin/env python3
import importlib.util
import sys
import tempfile
from pathlib import Path
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "check_prod_test_separation.py"
    spec = importlib.util.spec_from_file_location(
        "check_prod_test_separation", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_module()


class ProdTestSeparationCheckTests(unittest.TestCase):
    def test_is_excluded_path_filters_test_files(self):
        self.assertTrue(checker._is_excluded_path(Path("src/foo/tests.rs")))
        self.assertTrue(checker._is_excluded_path(Path("src/foo/bar_tests.rs")))
        self.assertTrue(checker._is_excluded_path(Path("crates/x/src/test_helper.rs")))
        self.assertFalse(checker._is_excluded_path(Path("src/foo/mod.rs")))

    def test_detects_test_symbol_reexport(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_prod_test_sep_") as tmpdir:
            root = Path(tmpdir)
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "mod.rs").write_text(
                "pub(super) use super::attack_runner_tests::helper;\n",
                encoding="utf-8",
            )

            violations = checker.collect_violations(root, ["src"])
            self.assertEqual(len(violations), 1)
            self.assertEqual(violations[0].kind, "test_symbol_import_or_reexport")

    def test_allows_cfg_test_test_module(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_prod_test_sep_") as tmpdir:
            root = Path(tmpdir)
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "mod.rs").write_text(
                '#[cfg(test)]\n#[path = "mod_tests.rs"]\nmod tests;\n',
                encoding="utf-8",
            )

            violations = checker.collect_violations(root, ["src"])
            self.assertEqual(violations, [])

    def test_detects_test_module_without_cfg(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_prod_test_sep_") as tmpdir:
            root = Path(tmpdir)
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "mod.rs").write_text(
                '#[path = "mod_tests.rs"]\nmod tests;\n',
                encoding="utf-8",
            )

            violations = checker.collect_violations(root, ["src"])
            kinds = [v.kind for v in violations]
            self.assertIn("test_module_without_cfg_test", kinds)
            self.assertIn("test_path_module_without_cfg_test", kinds)

    def test_main_passes_on_clean_source(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_prod_test_sep_") as tmpdir:
            root = Path(tmpdir)
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "mod.rs").write_text("pub fn f() {}\n", encoding="utf-8")

            exit_code = checker.main(["--repo-root", str(root), "--search-roots", "src"])
            self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
