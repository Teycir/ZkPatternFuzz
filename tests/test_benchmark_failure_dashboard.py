#!/usr/bin/env python3
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import unittest


def _load_dashboard_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "scripts" / "benchmark_failure_dashboard.py"
    spec = importlib.util.spec_from_file_location("benchmark_failure_dashboard", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dashboard = _load_dashboard_module()


@contextmanager
def _patched_env(overrides=None, clear=False):
    original = os.environ.copy()
    try:
        if clear:
            os.environ.clear()
        if overrides:
            os.environ.update(overrides)
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


class FailureDashboardThresholdTests(unittest.TestCase):
    def test_resolve_thresholds_defaults(self):
        with _patched_env({}, clear=True):
            resolved = dashboard._resolve_thresholds([])
        self.assertEqual(resolved, dashboard.CLASS_THRESHOLDS)

    def test_resolve_thresholds_env_override(self):
        with _patched_env({"ZKF_FAILURE_MAX_RATE_SETUP_TOOLING": "0.20"}, clear=True):
            resolved = dashboard._resolve_thresholds([])
        self.assertEqual(resolved["setup_tooling"], 0.20)
        self.assertEqual(resolved["timeouts"], dashboard.CLASS_THRESHOLDS["timeouts"])

    def test_resolve_thresholds_cli_overrides_env(self):
        with _patched_env({"ZKF_FAILURE_MAX_RATE_SETUP_TOOLING": "0.20"}, clear=True):
            resolved = dashboard._resolve_thresholds(["setup_tooling=0.25"])
        self.assertEqual(resolved["setup_tooling"], 0.25)

    def test_resolve_thresholds_invalid_env_value(self):
        with _patched_env({"ZKF_FAILURE_MAX_RATE_SETUP_TOOLING": "invalid"}, clear=True):
            with self.assertRaisesRegex(ValueError, r"\$ZKF_FAILURE_MAX_RATE_SETUP_TOOLING"):
                dashboard._resolve_thresholds([])

    def test_resolve_thresholds_invalid_cli_class(self):
        with _patched_env({}, clear=True):
            with self.assertRaisesRegex(ValueError, r"Unknown failure class"):
                dashboard._resolve_thresholds(["not_a_class=0.2"])

    def test_resolve_thresholds_invalid_cli_format(self):
        with _patched_env({}, clear=True):
            with self.assertRaisesRegex(ValueError, r"expected CLASS=RATE"):
                dashboard._resolve_thresholds(["setup_tooling"])

    def test_dashboard_output_schema_stable(self):
        summary = {"generated_utc": "2026-02-18T00:00:00Z", "total_runs": 10}
        outcomes = [{"reason_counts": {"none": 10}}]
        with _patched_env({}, clear=True):
            thresholds = dashboard._resolve_thresholds([])
        payload = dashboard._dashboard(
            summary,
            outcomes,
            Path("artifacts/benchmark_runs/benchmark_foo/summary.json"),
            Path("artifacts/benchmark_runs/benchmark_foo/outcomes.json"),
            thresholds,
        )

        self.assertEqual(
            set(payload.keys()),
            {
                "generated_utc",
                "summary_path",
                "outcomes_path",
                "total_runs",
                "overall_status",
                "class_rows",
                "reason_counts",
            },
        )
        self.assertEqual(payload["overall_status"], "PASS")
        self.assertEqual(len(payload["class_rows"]), 6)


if __name__ == "__main__":
    unittest.main()
