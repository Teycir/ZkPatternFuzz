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
    return _repo_root() / "scripts" / "circom_flake_gate.sh"


def _write_passing_summary(path: Path) -> None:
    payload = {
        "total_runs": 5,
        "overall_completion_rate": 1.0,
        "vulnerable_recall": 1.0,
        "precision": 1.0,
        "safe_false_positive_rate": 0.0,
        "safe_high_confidence_false_positive_rate": 0.0,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _write_keygen_report(path: Path, passes: bool) -> None:
    payload = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "passes": passes,
        "total_targets": 5,
        "passed_targets": 5 if passes else 0,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class CircomFlakeGateTests(unittest.TestCase):
    def test_enforced_gate_passes_with_two_day_streak(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_circom_flake_pass_") as tmpdir:
            root = Path(tmpdir)
            bench_root = root / "bench"
            summary = bench_root / "benchmark_20260222_000000" / "summary.json"
            keygen = root / "keygen_preflight.json"
            history = root / "history.json"
            report = root / "report.json"

            _write_passing_summary(summary)
            _write_keygen_report(keygen, passes=True)

            yesterday = datetime.now(timezone.utc) - timedelta(days=1)
            history_payload = {
                "generated_utc": yesterday.isoformat(),
                "entries": [
                    {
                        "generated_utc": yesterday.isoformat(),
                        "day_utc": yesterday.date().isoformat(),
                        "lane_pass": True,
                        "keygen_setup_keys_pass": True,
                        "compile_prove_verify_pass": True,
                    }
                ],
            }
            history.write_text(
                json.dumps(history_payload, indent=2) + "\n", encoding="utf-8"
            )

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--benchmark-root",
                    str(bench_root),
                    "--benchmark-summary",
                    str(summary),
                    "--keygen-preflight",
                    str(keygen),
                    "--history-path",
                    str(history),
                    "--output",
                    str(report),
                    "--required-consecutive-days",
                    "2",
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
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertTrue(payload["overall_pass"])
            self.assertGreaterEqual(payload["current_streak_days"], 2)
            self.assertEqual(payload["remaining_streak_days"], 0)
            self.assertIsInstance(payload["projected_completion_day_utc"], str)
            self.assertTrue(payload["projected_completion_day_utc"])

    def test_enforced_gate_fails_when_latest_keygen_signal_fails(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_circom_flake_fail_") as tmpdir:
            root = Path(tmpdir)
            bench_root = root / "bench"
            summary = bench_root / "benchmark_20260222_000000" / "summary.json"
            keygen = root / "keygen_preflight.json"
            history = root / "history.json"
            report = root / "report.json"

            _write_passing_summary(summary)
            _write_keygen_report(keygen, passes=False)

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--benchmark-root",
                    str(bench_root),
                    "--benchmark-summary",
                    str(summary),
                    "--keygen-preflight",
                    str(keygen),
                    "--history-path",
                    str(history),
                    "--output",
                    str(report),
                    "--required-consecutive-days",
                    "1",
                    "--enforce",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertFalse(payload["overall_pass"])
            self.assertFalse(payload["latest_signals"]["keygen_setup_keys_pass"])
            self.assertEqual(payload["remaining_streak_days"], 1)
            self.assertIsNone(payload["projected_completion_day_utc"])


if __name__ == "__main__":
    unittest.main()
