#!/usr/bin/env python3
import importlib.util
import json
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
    def test_test_like_filenames_are_detected(self):
        self.assertTrue(checker._is_test_like_filename("tests.rs"))
        self.assertTrue(checker._is_test_like_filename("foo_tests.rs"))
        self.assertTrue(checker._is_test_like_filename("test_helper.rs"))
        self.assertFalse(checker._is_test_like_filename("module.rs"))

    def test_detects_test_file_and_symbol_reexport(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_prod_test_sep_") as tmpdir:
            root = Path(tmpdir)
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "mod.rs").write_text(
                "pub(super) use super::attack_runner_tests::helper;\n",
                encoding="utf-8",
            )
            (root / "src" / "attack_runner_tests.rs").write_text(
                "pub fn helper() {}\n", encoding="utf-8"
            )

            violations = checker.collect_violations(root, ["src"])
            kinds = {v.kind for v in violations}
            self.assertIn("test_symbol_import_or_reexport", kinds)
            self.assertIn("test_file_in_production_tree", kinds)

    def test_cfg_test_is_not_allowed_in_production(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_prod_test_sep_") as tmpdir:
            root = Path(tmpdir)
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "mod.rs").write_text(
                '#[cfg(test)]\n#[path = "mod_tests.rs"]\nmod tests;\npub fn f() {}\n',
                encoding="utf-8",
            )

            violations = checker.collect_violations(root, ["src"])
            kinds = {v.kind for v in violations}
            self.assertIn("test_attribute_in_production", kinds)
            self.assertIn("test_path_attr_in_production", kinds)
            self.assertIn("test_module_decl_in_production", kinds)

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
            self.assertIn("test_module_decl_in_production", kinds)
            self.assertIn("test_path_attr_in_production", kinds)

    def test_main_passes_on_clean_source(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_prod_test_sep_") as tmpdir:
            root = Path(tmpdir)
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "mod.rs").write_text("pub fn f() {}\n", encoding="utf-8")

            exit_code = checker.main(["--repo-root", str(root), "--search-roots", "src"])
            self.assertEqual(exit_code, 0)

    def test_main_uses_baseline_and_rejects_new_violation(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_prod_test_sep_") as tmpdir:
            root = Path(tmpdir)
            (root / "src").mkdir(parents=True, exist_ok=True)
            baseline_path = root / "config" / "prod_test_separation_baseline.json"
            baseline_path.parent.mkdir(parents=True, exist_ok=True)

            (root / "src" / "legacy.rs").write_text(
                "#[cfg(test)]\npub fn legacy_only() {}\n", encoding="utf-8"
            )
            checker.main(
                [
                    "--repo-root",
                    str(root),
                    "--search-roots",
                    "src",
                    "--baseline",
                    str(baseline_path),
                    "--write-baseline",
                ]
            )

            # Baseline covers current state.
            exit_code = checker.main(
                [
                    "--repo-root",
                    str(root),
                    "--search-roots",
                    "src",
                    "--baseline",
                    str(baseline_path),
                ]
            )
            self.assertEqual(exit_code, 0)

            # Increase count for an existing signature (same file/kind/code).
            (root / "src" / "legacy.rs").write_text(
                "#[cfg(test)]\npub fn legacy_only() {}\n#[cfg(test)]\npub fn legacy_two() {}\n",
                encoding="utf-8",
            )
            exit_code = checker.main(
                [
                    "--repo-root",
                    str(root),
                    "--search-roots",
                    "src",
                    "--baseline",
                    str(baseline_path),
                ]
            )
            self.assertEqual(exit_code, 1)

            # Restore to baseline state before testing brand-new signature.
            (root / "src" / "legacy.rs").write_text(
                "#[cfg(test)]\npub fn legacy_only() {}\n", encoding="utf-8"
            )

            # Introduce new violation not present in baseline.
            (root / "src" / "new_bad.rs").write_text(
                "#[cfg(test)]\npub fn new_bad() {}\n", encoding="utf-8"
            )
            exit_code = checker.main(
                [
                    "--repo-root",
                    str(root),
                    "--search-roots",
                    "src",
                    "--baseline",
                    str(baseline_path),
                ]
            )
            self.assertEqual(exit_code, 1)

            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            self.assertTrue(baseline["violations"])


if __name__ == "__main__":
    unittest.main()
