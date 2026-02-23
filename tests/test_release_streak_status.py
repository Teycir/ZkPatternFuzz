#!/usr/bin/env python3
import json
import subprocess
import tempfile
from pathlib import Path
import unittest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _script_path() -> Path:
    return _repo_root() / "scripts" / "run_release_streak_status.sh"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class ReleaseStreakStatusTests(unittest.TestCase):
    def test_skip_refresh_reports_pass_from_fixture_inputs(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_release_streak_pass_") as tmpdir:
            root = Path(tmpdir)
            scorecard = root / "scorecard.json"
            flake = root / "flake.json"

            _write_json(
                scorecard,
                {
                    "generated_utc": "2026-02-23T15:00:00+00:00",
                    "consecutive_gate": {
                        "overall_pass": True,
                        "required_backends": ["circom", "noir"],
                        "per_backend": {
                            "circom": {
                                "current_streak_days": 14,
                                "required_streak_days": 14,
                                "remaining_streak_days": 0,
                                "projected_completion_day_utc": "2026-02-23",
                            },
                            "noir": {
                                "current_streak_days": 14,
                                "required_streak_days": 14,
                                "remaining_streak_days": 0,
                                "projected_completion_day_utc": "2026-02-23",
                            },
                        },
                    },
                },
            )
            _write_json(
                flake,
                {
                    "overall_pass": True,
                    "current_streak_days": 14,
                    "required_consecutive_days": 14,
                    "remaining_streak_days": 0,
                    "projected_completion_day_utc": "2026-02-23",
                },
            )

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--skip-refresh",
                    "--backend-scorecard-path",
                    str(scorecard),
                    "--circom-flake-path",
                    str(flake),
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
            self.assertIn("release_streak_status", proc.stdout)
            self.assertIn("backend=circom streak=14/14", proc.stdout)
            self.assertIn("circom_flake streak=14/14", proc.stdout)
            self.assertIn("overall_streak_status=PASS", proc.stdout)

    def test_skip_refresh_enforce_fails_when_fixture_gates_fail(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_release_streak_fail_") as tmpdir:
            root = Path(tmpdir)
            scorecard = root / "scorecard.json"
            flake = root / "flake.json"

            _write_json(
                scorecard,
                {
                    "generated_utc": "2026-02-23T15:00:00+00:00",
                    "consecutive_gate": {
                        "overall_pass": False,
                        "required_backends": ["circom"],
                        "per_backend": {
                            "circom": {
                                "current_streak_days": 2,
                                "required_streak_days": 14,
                                "remaining_streak_days": 12,
                                "projected_completion_day_utc": "2026-03-07",
                            }
                        },
                    },
                },
            )
            _write_json(
                flake,
                {
                    "overall_pass": False,
                    "current_streak_days": 2,
                    "required_consecutive_days": 14,
                    "remaining_streak_days": 12,
                    "projected_completion_day_utc": "2026-03-07",
                },
            )

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--skip-refresh",
                    "--backend-scorecard-path",
                    str(scorecard),
                    "--circom-flake-path",
                    str(flake),
                    "--enforce",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("overall_streak_status=FAIL", proc.stdout)

    def test_rejects_non_numeric_day_arguments(self):
        proc = subprocess.run(
            [str(_script_path()), "--backend-days", "abc"],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(proc.returncode, 2)
        self.assertIn("backend-days must be a non-negative integer", proc.stderr)


if __name__ == "__main__":
    unittest.main()
