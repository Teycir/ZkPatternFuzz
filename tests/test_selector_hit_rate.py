#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import sys
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "selector_hit_rate.py"
    spec = importlib.util.spec_from_file_location("selector_hit_rate", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


selector_hit_rate = _load_module()


class SelectorHitRateTests(unittest.TestCase):
    def test_compute_selector_hit_metrics(self):
        outcomes = [
            {
                "suite_name": "safe_regression",
                "target_name": "multiplier_safe",
                "attack_stage_reached": True,
            },
            {
                "suite_name": "safe_regression",
                "target_name": "multiplier_safe",
                "attack_stage_reached": False,
            },
            {
                "suite_name": "vulnerable_ground_truth",
                "target_name": "range_overflow",
                "attack_stage_reached": True,
            },
        ]

        metrics = selector_hit_rate._compute_selector_hit_metrics(outcomes)
        self.assertEqual(metrics["total_runs"], 3)
        self.assertEqual(metrics["hits"], 2)
        self.assertAlmostEqual(metrics["selector_hit_rate"], 2 / 3)
        self.assertAlmostEqual(metrics["suites"]["safe_regression"]["hit_rate"], 0.5)
        self.assertAlmostEqual(
            metrics["targets"]["safe_regression::multiplier_safe"]["hit_rate"], 0.5
        )

    def test_markdown_contains_status(self):
        payload = {
            "generated_utc": "2026-02-19T00:00:00Z",
            "total_runs": 2,
            "hits": 2,
            "selector_hit_rate": 1.0,
            "passes_threshold": True,
            "suites": {"safe": {"total_runs": 2, "hits": 2, "hit_rate": 1.0}},
            "targets": {"safe::a": {"total_runs": 2, "hits": 2, "hit_rate": 1.0}},
        }
        rendered = selector_hit_rate._to_markdown(payload, 0.9)
        self.assertIn("| Status | PASS |", rendered)
        self.assertIn("| safe::a | 2 | 2 | 100.0% |", rendered)


if __name__ == "__main__":
    unittest.main()
