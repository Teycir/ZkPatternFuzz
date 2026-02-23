#!/usr/bin/env python3
import json
import subprocess
import tempfile
from pathlib import Path
import unittest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _script_path() -> Path:
    return _repo_root() / "scripts" / "backend_readiness_dashboard.sh"


def _write_matrix(path: Path, enabled_targets: int = 5) -> None:
    lines = ["version: 1", "", "targets:"]
    for i in range(enabled_targets):
        lines.extend(
            [
                f"  - name: target_{i}",
                f"    target_circuit: tests/fixture_target_{i}",
                "    enabled: true",
            ]
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_backend_report(
    readiness_root: Path,
    backend: str,
    matrix_path: Path,
    reason_counts: dict,
) -> None:
    report = {
        "backend": backend,
        "matrix": {
            "path": str(matrix_path),
            "exit_code": 0,
            "reason_counts": reason_counts,
        },
        "integration_tests": [{"name": "fixture", "status": "pass"}],
    }
    report_path = readiness_root / backend / "latest_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


class BackendReadinessDashboardTests(unittest.TestCase):
    def test_per_backend_selector_threshold_fails_when_noir_below_25(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_readiness_fail_") as tmpdir:
            root = Path(tmpdir)
            readiness_root = root / "backend_readiness"
            output_path = readiness_root / "latest_report.json"

            matrix_noir = root / "matrices" / "noir.yaml"
            matrix_cairo = root / "matrices" / "cairo.yaml"
            matrix_halo2 = root / "matrices" / "halo2.yaml"
            _write_matrix(matrix_noir, enabled_targets=9)
            _write_matrix(matrix_cairo, enabled_targets=5)
            _write_matrix(matrix_halo2, enabled_targets=5)

            _write_backend_report(readiness_root, "noir", matrix_noir, {"completed": 24})
            _write_backend_report(readiness_root, "cairo", matrix_cairo, {"completed": 8})
            _write_backend_report(readiness_root, "halo2", matrix_halo2, {"completed": 8})

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--readiness-root",
                    str(readiness_root),
                    "--output",
                    str(output_path),
                    "--required-backends",
                    "noir,cairo,halo2",
                    "--min-selector-matching-total",
                    "4",
                    "--per-backend-min-selector-matching-total",
                    "noir=25,cairo=4,halo2=4",
                    "--enforce",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertFalse(payload["overall_pass"])
            thresholds = payload["thresholds"]["per_backend_min_selector_matching_total"]
            self.assertEqual(thresholds["noir"], 25)
            noir_entry = next(
                entry for entry in payload["backends"] if entry["backend"] == "noir"
            )
            self.assertFalse(noir_entry["gate_pass"])
            self.assertEqual(noir_entry["selector_matching_total_threshold"], 25)
            self.assertTrue(
                any(
                    "selector_matching_total 24 < 25" in failure
                    for failure in noir_entry["gate_failures"]
                )
            )

    def test_per_backend_selector_threshold_passes_when_noir_meets_25(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_readiness_pass_") as tmpdir:
            root = Path(tmpdir)
            readiness_root = root / "backend_readiness"
            output_path = readiness_root / "latest_report.json"

            matrix_noir = root / "matrices" / "noir.yaml"
            matrix_cairo = root / "matrices" / "cairo.yaml"
            matrix_halo2 = root / "matrices" / "halo2.yaml"
            _write_matrix(matrix_noir, enabled_targets=9)
            _write_matrix(matrix_cairo, enabled_targets=5)
            _write_matrix(matrix_halo2, enabled_targets=5)

            _write_backend_report(readiness_root, "noir", matrix_noir, {"completed": 27})
            _write_backend_report(readiness_root, "cairo", matrix_cairo, {"completed": 8})
            _write_backend_report(readiness_root, "halo2", matrix_halo2, {"completed": 8})

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--readiness-root",
                    str(readiness_root),
                    "--output",
                    str(output_path),
                    "--required-backends",
                    "noir,cairo,halo2",
                    "--min-selector-matching-total",
                    "4",
                    "--per-backend-min-selector-matching-total",
                    "noir=25,cairo=4,halo2=4",
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
            for entry in payload["backends"]:
                self.assertTrue(entry["gate_pass"], msg=f"{entry['backend']} failed unexpectedly")

    def test_invalid_per_backend_selector_threshold_format_errors(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_readiness_invalid_") as tmpdir:
            root = Path(tmpdir)
            readiness_root = root / "backend_readiness"
            output_path = readiness_root / "latest_report.json"

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--readiness-root",
                    str(readiness_root),
                    "--output",
                    str(output_path),
                    "--per-backend-min-selector-matching-total",
                    "noir:25",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 2)
            self.assertIn(
                "Invalid --per-backend-min-selector-matching-total",
                proc.stderr,
            )


if __name__ == "__main__":
    unittest.main()
