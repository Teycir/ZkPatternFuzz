#!/usr/bin/env python3
import json
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _script_path() -> Path:
    return _repo_root() / "scripts" / "backend_maturity_scorecard.sh"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class BackendMaturityScorecardTests(unittest.TestCase):
    def test_scorecard_enforce_passes_with_healthy_inputs(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_maturity_pass_") as tmpdir:
            root = Path(tmpdir)
            readiness_path = root / "backend_readiness.json"
            benchmark_summary = root / "benchmark_runs" / "benchmark_20260222_000000" / "summary.json"
            keygen_preflight = root / "keygen_preflight.json"
            output_path = root / "scorecard.json"

            _write_json(
                readiness_path,
                {
                    "thresholds": {
                        "min_selector_matching_total": 4,
                        "min_overall_completion_rate": 0.4,
                        "max_selector_mismatch_rate": 0.7,
                        "max_run_outcome_missing_rate": 0.05,
                    },
                    "backends": [
                        {
                            "backend": "noir",
                            "matrix_exit_code": 0,
                            "selector_matching_completion_rate": 1.0,
                            "selector_matching_total": 8,
                            "selector_mismatch_rate": 0.0,
                            "completion_rate": 1.0,
                            "runtime_error_count": 0,
                            "backend_preflight_failed_count": 0,
                            "run_outcome_missing_rate": 0.0,
                            "integration_statuses": ["pass", "pass"],
                            "gate_pass": True,
                        },
                        {
                            "backend": "cairo",
                            "matrix_exit_code": 0,
                            "selector_matching_completion_rate": 1.0,
                            "selector_matching_total": 8,
                            "selector_mismatch_rate": 0.0,
                            "completion_rate": 1.0,
                            "runtime_error_count": 0,
                            "backend_preflight_failed_count": 0,
                            "run_outcome_missing_rate": 0.0,
                            "integration_statuses": ["pass"],
                            "gate_pass": True,
                        },
                        {
                            "backend": "halo2",
                            "matrix_exit_code": 0,
                            "selector_matching_completion_rate": 1.0,
                            "selector_matching_total": 8,
                            "selector_mismatch_rate": 0.0,
                            "completion_rate": 1.0,
                            "runtime_error_count": 0,
                            "backend_preflight_failed_count": 0,
                            "run_outcome_missing_rate": 0.0,
                            "integration_statuses": ["pass", "pass"],
                            "gate_pass": True,
                        },
                    ],
                },
            )

            _write_json(
                benchmark_summary,
                {
                    "total_runs": 20,
                    "overall_completion_rate": 1.0,
                    "overall_attack_stage_reach_rate": 1.0,
                    "vulnerable_recall": 0.9,
                    "precision": 1.0,
                    "safe_false_positive_rate": 0.0,
                    "safe_high_confidence_false_positive_rate": 0.0,
                },
            )

            _write_json(
                keygen_preflight,
                {
                    "passed_targets": 5,
                    "total_targets": 5,
                    "passes": True,
                },
            )

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--readiness-dashboard",
                    str(readiness_path),
                    "--benchmark-root",
                    str(root / "benchmark_runs"),
                    "--keygen-preflight",
                    str(keygen_preflight),
                    "--output",
                    str(output_path),
                    "--required-backends",
                    "circom,noir,cairo,halo2",
                    "--min-score",
                    "4.5",
                    "--enforce",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(
                proc.returncode,
                0,
                msg=f"stdout={proc.stdout}\nstderr={proc.stderr}",
            )
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(payload["overall_pass"])
            backend_names = {entry["backend"] for entry in payload["backends"]}
            self.assertEqual(backend_names, {"circom", "noir", "cairo", "halo2"})
            self.assertEqual(payload["gate_failures"], [])
            self.assertIn("consecutive_gate", payload)
            self.assertFalse(payload["consecutive_gate"]["enabled"])
            noir_entry = next(
                entry for entry in payload["backends"] if entry["backend"] == "noir"
            )
            self.assertEqual(
                noir_entry["evidence"]["integration_tests_total"],
                2,
            )
            self.assertEqual(
                noir_entry["evidence"]["integration_tests_executed"],
                2,
            )
            self.assertEqual(
                noir_entry["evidence"]["integration_tests_skipped"],
                0,
            )
            self.assertEqual(
                noir_entry["evidence"]["integration_pass_ratio"],
                1.0,
            )

    def test_scorecard_enforce_fails_when_required_backend_below_threshold(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_maturity_fail_") as tmpdir:
            root = Path(tmpdir)
            readiness_path = root / "backend_readiness.json"
            output_path = root / "scorecard.json"

            _write_json(
                readiness_path,
                {
                    "thresholds": {
                        "min_selector_matching_total": 4,
                        "min_overall_completion_rate": 0.4,
                        "max_selector_mismatch_rate": 0.7,
                        "max_run_outcome_missing_rate": 0.05,
                    },
                    "backends": [
                        {
                            "backend": "halo2",
                            "matrix_exit_code": 1,
                            "selector_matching_completion_rate": 0.0,
                            "selector_matching_total": 1,
                            "selector_mismatch_rate": 1.0,
                            "completion_rate": 0.0,
                            "runtime_error_count": 5,
                            "backend_preflight_failed_count": 2,
                            "run_outcome_missing_rate": 0.8,
                            "integration_statuses": ["fail"],
                            "gate_pass": False,
                        }
                    ],
                },
            )

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--readiness-dashboard",
                    str(readiness_path),
                    "--benchmark-root",
                    str(root / "benchmark_runs"),
                    "--output",
                    str(output_path),
                    "--required-backends",
                    "halo2",
                    "--min-score",
                    "4.5",
                    "--enforce",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertFalse(payload["overall_pass"])
            self.assertTrue(any(msg.startswith("halo2: score") for msg in payload["gate_failures"]))

    def test_scorecard_enforce_passes_with_consecutive_day_streak(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_maturity_streak_pass_") as tmpdir:
            root = Path(tmpdir)
            readiness_path = root / "backend_readiness.json"
            output_path = root / "scorecard.json"
            history_path = root / "history.json"

            _write_json(
                readiness_path,
                {
                    "thresholds": {
                        "min_selector_matching_total": 4,
                        "min_overall_completion_rate": 0.4,
                        "max_selector_mismatch_rate": 0.7,
                        "max_run_outcome_missing_rate": 0.05,
                    },
                    "backends": [
                        {
                            "backend": "halo2",
                            "matrix_exit_code": 0,
                            "selector_matching_completion_rate": 1.0,
                            "selector_matching_total": 8,
                            "selector_mismatch_rate": 0.0,
                            "completion_rate": 1.0,
                            "runtime_error_count": 0,
                            "backend_preflight_failed_count": 0,
                            "run_outcome_missing_rate": 0.0,
                            "integration_statuses": ["pass", "pass"],
                            "gate_pass": True,
                        }
                    ],
                },
            )

            now = datetime.now(timezone.utc)
            _write_json(
                history_path,
                {
                    "history_version": 1,
                    "entries": [
                        {
                            "generated_utc": (now - timedelta(days=2)).isoformat(),
                            "backends": {
                                "halo2": {
                                    "score_total": 5.0,
                                    "runtime_error_count": 0,
                                }
                            },
                        },
                        {
                            "generated_utc": (now - timedelta(days=1)).isoformat(),
                            "backends": {
                                "halo2": {
                                    "score_total": 5.0,
                                    "runtime_error_count": 0,
                                }
                            },
                        },
                    ],
                },
            )

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--readiness-dashboard",
                    str(readiness_path),
                    "--benchmark-root",
                    str(root / "benchmark_runs"),
                    "--history-path",
                    str(history_path),
                    "--output",
                    str(output_path),
                    "--required-backends",
                    "halo2",
                    "--min-score",
                    "4.5",
                    "--consecutive-days",
                    "3",
                    "--consecutive-target-score",
                    "5.0",
                    "--consecutive-required-backends",
                    "halo2",
                    "--enforce",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(
                proc.returncode,
                0,
                msg=f"stdout={proc.stdout}\nstderr={proc.stderr}",
            )
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(payload["overall_pass"])
            self.assertTrue(payload["consecutive_gate"]["enabled"])
            self.assertTrue(payload["consecutive_gate"]["overall_pass"])
            backend_gate = payload["consecutive_gate"]["per_backend"]["halo2"]
            self.assertGreaterEqual(backend_gate["current_streak_days"], 3)
            self.assertEqual(backend_gate["required_streak_days"], 3)
            self.assertEqual(backend_gate["remaining_streak_days"], 0)
            self.assertIsInstance(backend_gate["projected_completion_day_utc"], str)
            self.assertTrue(backend_gate["projected_completion_day_utc"])

    def test_scorecard_enforce_fails_when_consecutive_day_streak_breaks(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_maturity_streak_fail_") as tmpdir:
            root = Path(tmpdir)
            readiness_path = root / "backend_readiness.json"
            output_path = root / "scorecard.json"
            history_path = root / "history.json"

            _write_json(
                readiness_path,
                {
                    "thresholds": {
                        "min_selector_matching_total": 4,
                        "min_overall_completion_rate": 0.4,
                        "max_selector_mismatch_rate": 0.7,
                        "max_run_outcome_missing_rate": 0.05,
                    },
                    "backends": [
                        {
                            "backend": "halo2",
                            "matrix_exit_code": 0,
                            "selector_matching_completion_rate": 1.0,
                            "selector_matching_total": 8,
                            "selector_mismatch_rate": 0.0,
                            "completion_rate": 1.0,
                            "runtime_error_count": 0,
                            "backend_preflight_failed_count": 0,
                            "run_outcome_missing_rate": 0.0,
                            "integration_statuses": ["pass", "pass"],
                            "gate_pass": True,
                        }
                    ],
                },
            )

            now = datetime.now(timezone.utc)
            _write_json(
                history_path,
                {
                    "history_version": 1,
                    "entries": [
                        {
                            "generated_utc": (now - timedelta(days=4)).isoformat(),
                            "backends": {
                                "halo2": {
                                    "score_total": 5.0,
                                    "runtime_error_count": 0,
                                }
                            },
                        },
                        {
                            "generated_utc": (now - timedelta(days=1)).isoformat(),
                            "backends": {
                                "halo2": {
                                    "score_total": 5.0,
                                    "runtime_error_count": 0,
                                }
                            },
                        },
                    ],
                },
            )

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--readiness-dashboard",
                    str(readiness_path),
                    "--benchmark-root",
                    str(root / "benchmark_runs"),
                    "--history-path",
                    str(history_path),
                    "--output",
                    str(output_path),
                    "--required-backends",
                    "halo2",
                    "--min-score",
                    "4.5",
                    "--consecutive-days",
                    "3",
                    "--consecutive-target-score",
                    "5.0",
                    "--consecutive-required-backends",
                    "halo2",
                    "--enforce",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertFalse(payload["overall_pass"])
            self.assertFalse(payload["consecutive_gate"]["overall_pass"])
            self.assertTrue(
                any(
                    msg.startswith("halo2: consecutive-day streak")
                    for msg in payload["gate_failures"]
                )
            )
            backend_gate = payload["consecutive_gate"]["per_backend"]["halo2"]
            self.assertEqual(backend_gate["required_streak_days"], 3)
            self.assertGreaterEqual(backend_gate["remaining_streak_days"], 1)
            self.assertIsInstance(backend_gate["projected_completion_day_utc"], str)
            self.assertTrue(backend_gate["projected_completion_day_utc"])

    def test_scorecard_treats_skipped_integration_as_non_executed(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_maturity_skipped_integration_") as tmpdir:
            root = Path(tmpdir)
            readiness_path = root / "backend_readiness.json"
            output_path = root / "scorecard.json"

            _write_json(
                readiness_path,
                {
                    "thresholds": {
                        "min_selector_matching_total": 4,
                        "min_overall_completion_rate": 0.4,
                        "max_selector_mismatch_rate": 0.7,
                        "max_run_outcome_missing_rate": 0.05,
                    },
                    "backends": [
                        {
                            "backend": "halo2",
                            "matrix_exit_code": 0,
                            "selector_matching_completion_rate": 1.0,
                            "selector_matching_total": 8,
                            "selector_mismatch_rate": 0.0,
                            "completion_rate": 1.0,
                            "runtime_error_count": 0,
                            "backend_preflight_failed_count": 0,
                            "run_outcome_missing_rate": 0.0,
                            "integration_statuses": ["skipped", "skipped"],
                            "gate_pass": True,
                        }
                    ],
                },
            )

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--readiness-dashboard",
                    str(readiness_path),
                    "--benchmark-root",
                    str(root / "benchmark_runs"),
                    "--output",
                    str(output_path),
                    "--required-backends",
                    "halo2",
                    "--min-score",
                    "4.5",
                    "--enforce",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(
                proc.returncode,
                0,
                msg=f"stdout={proc.stdout}\nstderr={proc.stderr}",
            )
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            halo2 = next(entry for entry in payload["backends"] if entry["backend"] == "halo2")
            self.assertEqual(halo2["score_total"], 5.0)
            self.assertEqual(halo2["evidence"]["integration_tests_total"], 2)
            self.assertEqual(halo2["evidence"]["integration_tests_executed"], 0)
            self.assertEqual(halo2["evidence"]["integration_tests_skipped"], 2)
            self.assertEqual(halo2["evidence"]["integration_tests_failed"], 0)
            self.assertEqual(halo2["evidence"]["integration_pass_ratio"], 1.0)


if __name__ == "__main__":
    unittest.main()
