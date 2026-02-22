#!/usr/bin/env python3
import importlib.util
import sys
from pathlib import Path
import unittest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "build_backend_effectiveness_report.py"
    spec = importlib.util.spec_from_file_location(
        "build_backend_effectiveness_report", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


reporter = _load_module()


class BuildBackendEffectivenessReportTests(unittest.TestCase):
    def test_parse_suite_targets_filters_selected_suites_and_enabled(self):
        sample = """
suites:
  vulnerable_ground_truth:
    positive: true
    targets:
      - name: vulnerable_circom
        framework: circom
      - name: vulnerable_disabled
        framework: noir
        enabled: false

  safe_regression:
    positive: false
    targets:
      - name: safe_halo2
        framework: halo2
"""
        target_map = reporter.parse_suite_targets(
            sample,
            selected_suites=["vulnerable_ground_truth"],
        )

        self.assertIn("vulnerable_circom", target_map)
        self.assertNotIn("safe_halo2", target_map)
        self.assertEqual(target_map["vulnerable_circom"]["framework"], "circom")
        self.assertTrue(target_map["vulnerable_circom"]["positive"])
        self.assertFalse(target_map["vulnerable_disabled"]["enabled"])

    def test_compute_backend_rows_uses_framework_or_target_map(self):
        outcomes = [
            {
                "framework": "circom",
                "target_name": "circom_vuln",
                "positive": True,
                "detected": True,
                "high_confidence_detected": True,
            },
            {
                "framework": "",
                "target_name": "noir_safe",
                "positive": False,
                "detected": True,
                "high_confidence_detected": False,
            },
            {
                "framework": "",
                "target_name": "noir_vuln",
                "positive": True,
                "detected": True,
                "high_confidence_detected": False,
            },
            {
                "framework": "",
                "target_name": "cairo_vuln",
                "positive": True,
                "detected": False,
                "high_confidence_detected": False,
            },
        ]

        target_map = {
            "noir_safe": {
                "framework": "noir",
                "positive": False,
                "enabled": True,
                "suite_name": "safe",
                "target_name": "noir_safe",
            },
            "noir_vuln": {
                "framework": "noir",
                "positive": True,
                "enabled": True,
                "suite_name": "vuln",
                "target_name": "noir_vuln",
            },
            "cairo_vuln": {
                "framework": "cairo",
                "positive": True,
                "enabled": True,
                "suite_name": "vuln",
                "target_name": "cairo_vuln",
            },
        }

        rows, diagnostics = reporter.compute_backend_rows(
            outcomes,
            target_map,
            ["circom", "noir", "cairo", "halo2"],
        )
        by_backend = {row["backend"]: row for row in rows}

        self.assertEqual(diagnostics["assignment_source_counts"]["outcome.framework"], 1)
        self.assertEqual(diagnostics["assignment_source_counts"]["suite_target_map"], 3)
        self.assertEqual(diagnostics["unresolved_backend_runs"], 0)

        circom = by_backend["circom"]
        self.assertEqual(circom["run_counts"]["total"], 1)
        self.assertEqual(circom["metrics"]["recall"], 1.0)
        self.assertEqual(circom["metrics"]["precision"], 1.0)

        noir = by_backend["noir"]
        self.assertEqual(noir["run_counts"]["total"], 2)
        self.assertEqual(noir["detections"]["true_positives"], 1)
        self.assertEqual(noir["detections"]["false_positives"], 1)
        self.assertEqual(noir["metrics"]["recall"], 1.0)
        self.assertEqual(noir["metrics"]["precision"], 0.5)

        cairo = by_backend["cairo"]
        self.assertEqual(cairo["run_counts"]["vulnerable"], 1)
        self.assertEqual(cairo["detections"]["true_positives"], 0)
        self.assertEqual(cairo["metrics"]["recall"], 0.0)
        self.assertEqual(cairo["metrics"]["true_positive_contribution_share"], 0.0)

        halo2 = by_backend["halo2"]
        self.assertEqual(halo2["run_counts"]["total"], 0)

    def test_build_summary_flags_unresolved_runs(self):
        rows = [
            {
                "backend": "circom",
                "run_counts": {"total": 2},
                "target_counts": {"total": 2},
                "metrics": {"true_positive_contribution_share": 1.0},
            },
            {
                "backend": "noir",
                "run_counts": {"total": 0},
                "target_counts": {"total": 0},
                "metrics": {"true_positive_contribution_share": 0.0},
            },
            {
                "backend": "cairo",
                "run_counts": {"total": 0},
                "target_counts": {"total": 0},
                "metrics": {"true_positive_contribution_share": 0.0},
            },
            {
                "backend": "halo2",
                "run_counts": {"total": 0},
                "target_counts": {"total": 0},
                "metrics": {"true_positive_contribution_share": 0.0},
            },
        ]
        diagnostics = {"unresolved_backend_runs": 1}

        summary = reporter.build_summary(
            rows,
            diagnostics,
            ["circom", "noir", "cairo", "halo2"],
        )

        self.assertFalse(summary["overall_pass"])
        self.assertEqual(summary["unresolved_backend_runs"], 1)
        self.assertEqual(summary["dominant_true_positive_backend"], "circom")
        self.assertIn("noir", summary["zero_run_backends"])


if __name__ == "__main__":
    unittest.main()
