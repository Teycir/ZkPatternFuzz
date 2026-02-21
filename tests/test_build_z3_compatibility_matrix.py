#!/usr/bin/env python3
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "build_z3_compatibility_matrix.py"
    spec = importlib.util.spec_from_file_location("build_z3_compatibility_matrix", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


matrix = _load_module()


class BuildZ3CompatibilityMatrixTests(unittest.TestCase):
    def test_parse_z3_version(self):
        self.assertEqual(matrix.parse_z3_version("Z3 version 4.13.3 - 64 bit"), "4.13.3")
        self.assertIsNone(matrix.parse_z3_version("unknown"))

    def test_get_lock_solver_versions(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_z3_lock_") as tmpdir:
            lock = Path(tmpdir) / "Cargo.lock"
            lock.write_text(
                """
[[package]]
name = "z3"
version = "0.12.1"

[[package]]
name = "z3-sys"
version = "0.8.1"

[[package]]
name = "serde"
version = "1.0.0"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            versions = matrix.get_lock_solver_versions(lock)
            self.assertEqual(versions["z3"], ["0.12.1"])
            self.assertEqual(versions["z3-sys"], ["0.8.1"])
            self.assertNotIn("serde", versions)

    def test_assess_matrix(self):
        z3_ok = {"installed": True}
        lanes_ok = [
            {"id": "zk_constraints_dynamic", "status": "pass"},
            {"id": "zk_symbolic_dynamic", "status": "pass"},
            {"id": "zk_constraints_static", "status": "pass"},
            {"id": "zk_symbolic_static", "status": "pass"},
            {"id": "workspace_static_feature", "status": "pass"},
        ]
        summary_ok = matrix.assess_matrix(z3_ok, lanes_ok)
        self.assertTrue(summary_ok["overall_pass"])

        z3_bad = {"installed": False}
        lanes_bad = [
            {"id": "zk_constraints_dynamic", "status": "pass"},
            {"id": "zk_constraints_static", "status": "fail"},
        ]
        summary_bad = matrix.assess_matrix(z3_bad, lanes_bad)
        self.assertFalse(summary_bad["overall_pass"])
        self.assertIn("zk_constraints_static", summary_bad["failed_lanes"])


if __name__ == "__main__":
    unittest.main()
