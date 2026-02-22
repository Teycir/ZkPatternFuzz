#!/usr/bin/env python3
import importlib.util
import sys
import tempfile
from pathlib import Path
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "build_cve_portability_report.py"
    spec = importlib.util.spec_from_file_location("build_cve_portability_report", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


reporter = _load_module()


class BuildCvePortabilityReportTests(unittest.TestCase):
    def test_extract_circuit_paths(self):
        sample = """
vulnerabilities:
  - id: ZK-CVE-1
    regression_test:
      circuit_path: "tests/halo2_specs/lookup.json"
  - id: ZK-CVE-2
    regression_test:
      circuit_path: ${ZK0D_BASE}/foo/bar.circom
"""
        paths = reporter.extract_circuit_paths(sample)
        self.assertEqual(
            paths,
            ["tests/halo2_specs/lookup.json", "${ZK0D_BASE}/foo/bar.circom"],
        )

    def test_classify_paths(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_cve_portability_") as tmpdir:
            root = Path(tmpdir)
            (root / "relative" / "ok.circom").parent.mkdir(parents=True, exist_ok=True)
            (root / "relative" / "ok.circom").write_text("template Main() {}\n")

            audit = reporter.classify_paths(
                [
                    "relative/ok.circom",
                    "relative/missing.circom",
                    "/media/elements/Repos/zk0d/circuit.circom",
                    "${ZK0D_BASE}/foo.circom",
                ],
                root,
            )

            self.assertEqual(audit["total_paths"], 4)
            self.assertEqual(audit["existing_repo_relative_count"], 1)
            self.assertEqual(audit["missing_repo_relative_count"], 1)
            self.assertEqual(audit["machine_specific_absolute_count"], 1)
            self.assertEqual(audit["env_placeholder_count"], 1)

    def test_build_summary(self):
        path_audit = {
            "machine_specific_absolute_count": 0,
        }
        lane = {
            "status": "pass",
            "timed_out": False,
            "executed": 2,
        }
        summary = reporter.build_summary(path_audit, lane)
        self.assertTrue(summary["overall_pass"])

        bad_lane = {
            "status": "fail",
            "timed_out": False,
            "executed": 2,
        }
        self.assertFalse(reporter.build_summary(path_audit, bad_lane)["overall_pass"])

        bad_paths = {"machine_specific_absolute_count": 1}
        self.assertFalse(reporter.build_summary(bad_paths, lane)["overall_pass"])

        zero_exec = {"status": "pass", "timed_out": False, "executed": 0}
        self.assertFalse(reporter.build_summary(path_audit, zero_exec)["overall_pass"])


if __name__ == "__main__":
    unittest.main()
