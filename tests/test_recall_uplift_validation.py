#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import sys
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "validate_recall_uplift.py"
    spec = importlib.util.spec_from_file_location("validate_recall_uplift", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


recall_uplift = _load_module()


class RecallUpliftValidationTests(unittest.TestCase):
    def test_passes_on_sufficient_uplift_and_low_high_conf_fpr(self):
        baseline = {"vulnerable_recall": 0.1, "config": {"dry_run": False}}
        candidate = {
            "vulnerable_recall": 0.5,
            "safe_high_confidence_false_positive_rate": 0.0,
            "config": {"dry_run": False},
        }
        result = recall_uplift._validate_recall_uplift(
            baseline,
            candidate,
            min_uplift_pp=20.0,
            max_safe_high_conf_fpr=0.05,
            require_non_dry_run=True,
        )
        self.assertTrue(result["passes"])
        self.assertGreaterEqual(result["recall_uplift_pp"], 20.0)

    def test_fails_when_baseline_is_dry_run(self):
        baseline = {"vulnerable_recall": 0.1, "config": {"dry_run": True}}
        candidate = {
            "vulnerable_recall": 0.5,
            "safe_high_confidence_false_positive_rate": 0.0,
            "config": {"dry_run": False},
        }
        result = recall_uplift._validate_recall_uplift(
            baseline,
            candidate,
            min_uplift_pp=20.0,
            max_safe_high_conf_fpr=0.05,
            require_non_dry_run=True,
        )
        self.assertFalse(result["passes"])
        self.assertTrue(
            any("baseline summary is dry-run" in msg for msg in result["failures"])
        )


if __name__ == "__main__":
    unittest.main()
