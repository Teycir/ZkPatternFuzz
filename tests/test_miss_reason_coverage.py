#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import sys
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "validate_miss_reason_coverage.py"
    spec = importlib.util.spec_from_file_location(
        "validate_miss_reason_coverage", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


miss_reason_coverage = _load_module()


class MissReasonCoverageTests(unittest.TestCase):
    def test_passes_when_all_misses_have_reasons(self):
        outcomes = [
            {
                "positive": True,
                "detected": False,
                "suite_name": "vuln",
                "target_name": "a",
                "trial_idx": 1,
                "reason_counts": {"completed": 1},
            },
            {
                "positive": True,
                "detected": True,
                "reason_counts": {"critical_findings_detected": 1},
            },
            {
                "positive": False,
                "detected": False,
                "reason_counts": {"completed": 1},
            },
        ]

        result = miss_reason_coverage._misses_with_reason_coverage(outcomes)
        self.assertTrue(result["passes"])
        self.assertEqual(result["total_misses"], 1)
        self.assertEqual(result["covered_misses"], 1)
        self.assertEqual(result["uncovered_misses"], 0)

    def test_fails_when_miss_has_no_reason(self):
        outcomes = [
            {
                "positive": True,
                "detected": False,
                "suite_name": "vuln",
                "target_name": "a",
                "trial_idx": 1,
                "reason_counts": {},
            }
        ]
        result = miss_reason_coverage._misses_with_reason_coverage(outcomes)
        self.assertFalse(result["passes"])
        self.assertEqual(result["uncovered_misses"], 1)
        self.assertEqual(len(result["uncovered_rows"]), 1)


if __name__ == "__main__":
    unittest.main()
