#!/usr/bin/env python3
import importlib.util
import sys
from pathlib import Path
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "build_mutator_validity_report.py"
    spec = importlib.util.spec_from_file_location("build_mutator_validity_report", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


reporter = _load_module()


class BuildMutatorValidityReportTests(unittest.TestCase):
    def test_parse_stress_summary(self):
        text = "mutator_stress_summary total=68000 invalid=0 invalid_rate=0.000000000\n"
        summary = reporter.parse_stress_summary(text)
        self.assertIsNotNone(summary)
        self.assertEqual(summary["total_mutations"], 68000)
        self.assertEqual(summary["invalid_out_of_field"], 0)
        self.assertEqual(summary["invalid_rate"], 0.0)

    def test_parse_stress_summary_missing(self):
        self.assertIsNone(reporter.parse_stress_summary("no summary here"))

    def test_build_summary(self):
        lane = {
            "status": "pass",
            "timed_out": False,
            "summary": {
                "total_mutations": 1000,
                "invalid_out_of_field": 0,
                "invalid_rate": 0.0,
            },
        }
        summary = reporter.build_summary(lane)
        self.assertTrue(summary["overall_pass"])

        bad_lane = {
            "status": "pass",
            "timed_out": False,
            "summary": {
                "total_mutations": 1000,
                "invalid_out_of_field": 1,
                "invalid_rate": 0.001,
            },
        }
        self.assertFalse(reporter.build_summary(bad_lane)["overall_pass"])


if __name__ == "__main__":
    unittest.main()
