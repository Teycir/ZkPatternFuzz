#!/usr/bin/env python3
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "evaluate_arkworks_upgrade_path.py"
    spec = importlib.util.spec_from_file_location("evaluate_arkworks_upgrade_path", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


evaluator = _load_module()


class EvaluateArkworksUpgradePathTests(unittest.TestCase):
    def test_infer_semver_track(self):
        self.assertEqual(evaluator.infer_semver_track("0.4"), (0, 4))
        self.assertEqual(evaluator.infer_semver_track("^0.5.1"), (0, 5))
        self.assertIsNone(evaluator.infer_semver_track("path=../foo"))

    def test_collect_lock_ark_versions(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_ark_lock_") as tmpdir:
            root = Path(tmpdir)
            lock = root / "Cargo.lock"
            lock.write_text(
                """
[[package]]
name = "ark-ff"
version = "0.4.2"

[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "ark-bn254"
version = "0.5.0"
""".strip()
                + "\n",
                encoding="utf-8",
            )

            versions = evaluator.collect_lock_ark_versions(lock)
            self.assertEqual(versions["ark-ff"], ["0.4.2"])
            self.assertEqual(versions["ark-bn254"], ["0.5.0"])
            self.assertNotIn("serde", versions)

    def test_evaluate_upgrade_path_detects_blockers(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_ark_eval_") as tmpdir:
            root = Path(tmpdir)
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "src" / "main.rs").write_text(
                "fn main() { let _x = 1; }\n",
                encoding="utf-8",
            )
            (root / "Cargo.toml").write_text(
                """
[package]
name = "sample"
version = "0.1.0"
edition = "2021"

[dependencies]
ark-ff = "0.4"
ark-bn254 = "0.4"
serde = "1"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            (root / "Cargo.lock").write_text(
                """
[[package]]
name = "ark-ff"
version = "0.4.2"

[[package]]
name = "ark-bn254"
version = "0.4.0"
""".strip()
                + "\n",
                encoding="utf-8",
            )

            report = evaluator.evaluate_upgrade_path(root)
            self.assertFalse(report["ready_to_upgrade_now"])
            self.assertEqual(len(report["not_on_05_direct"]), 2)
            self.assertIn("ark-ff", report["lock_non_05"])
            self.assertEqual(report["risk"], "low")

    def test_collect_direct_deps_uses_workspace_members_only(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_ark_workspace_") as tmpdir:
            root = Path(tmpdir)
            (root / "crate_a" / "src").mkdir(parents=True, exist_ok=True)
            (root / "vendor" / "src").mkdir(parents=True, exist_ok=True)

            (root / "Cargo.toml").write_text(
                """
[package]
name = "rootpkg"
version = "0.1.0"
edition = "2021"

[workspace]
members = [".", "crate_a"]

[dependencies]
ark-ff = "0.4"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            (root / "crate_a" / "Cargo.toml").write_text(
                """
[package]
name = "crate_a"
version = "0.1.0"
edition = "2021"

[dependencies]
ark-bn254 = "0.4"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            # This file should be ignored because it's not in [workspace].members.
            (root / "vendor" / "Cargo.toml").write_text(
                """
[package]
name = "vendor"
version = "0.1.0"
edition = "2021"

[dependencies]
ark-relations = "0.4"
""".strip()
                + "\n",
                encoding="utf-8",
            )

            deps = evaluator.collect_direct_ark_dependencies(root)
            names = sorted((d.manifest, d.name) for d in deps)
            self.assertEqual(
                names,
                [
                    ("Cargo.toml", "ark-ff"),
                    ("crate_a/Cargo.toml", "ark-bn254"),
                ],
            )


if __name__ == "__main__":
    unittest.main()
