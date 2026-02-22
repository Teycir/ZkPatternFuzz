#!/usr/bin/env python3
import json
import subprocess
import tempfile
from pathlib import Path
import unittest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _script_path() -> Path:
    return _repo_root() / "scripts" / "backend_capacity_fitness_gate.sh"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _throughput_payload(noir: float, cairo: float, halo2: float, overall_pass: bool = True) -> dict:
    return {
        "generated_utc": "2026-02-22T00:00:00+00:00",
        "overall_pass": overall_pass,
        "backends": [
            {
                "backend": "noir",
                "overall_pass": True,
                "median_completed_per_sec": noir,
            },
            {
                "backend": "cairo",
                "overall_pass": True,
                "median_completed_per_sec": cairo,
            },
            {
                "backend": "halo2",
                "overall_pass": True,
                "median_completed_per_sec": halo2,
            },
        ],
    }


def _memory_payload(max_rss_values: list[int], overall_pass: bool = True) -> dict:
    frameworks = ["noir", "cairo", "halo2"]
    stats = []
    for framework, rss in zip(frameworks, max_rss_values):
        stats.append(
            {
                "framework": framework,
                "max_rss_kb": rss,
                "median_rss_kb": rss,
                "failed_runs": 0,
            }
        )
    return {
        "generated_utc": "2026-02-22T00:00:00+00:00",
        "overall_pass": overall_pass,
        "framework_stats": stats,
    }


class BackendCapacityFitnessGateTests(unittest.TestCase):
    def test_enforced_gate_passes_with_reports_above_thresholds(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_capacity_gate_pass_") as tmpdir:
            root = Path(tmpdir)
            throughput = root / "throughput.json"
            memory = root / "memory.json"
            report = root / "report.json"

            _write_json(throughput, _throughput_payload(noir=0.030, cairo=0.028, halo2=0.041))
            _write_json(memory, _memory_payload([68000, 74000, 62000]))

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--throughput-report",
                    str(throughput),
                    "--memory-report",
                    str(memory),
                    "--skip-throughput-run",
                    "--skip-memory-run",
                    "--min-median-completed-per-sec",
                    "0.020",
                    "--max-rss-kb",
                    "131072",
                    "--output",
                    str(report),
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
            self.assertEqual(payload["gate_failures"], [])

    def test_enforced_gate_fails_when_throughput_below_per_backend_threshold(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_capacity_gate_tp_fail_") as tmpdir:
            root = Path(tmpdir)
            throughput = root / "throughput.json"
            memory = root / "memory.json"
            report = root / "report.json"

            _write_json(throughput, _throughput_payload(noir=0.005, cairo=0.030, halo2=0.045))
            _write_json(memory, _memory_payload([68000, 74000, 62000]))

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--throughput-report",
                    str(throughput),
                    "--memory-report",
                    str(memory),
                    "--skip-throughput-run",
                    "--skip-memory-run",
                    "--per-backend-min-median-completed-per-sec",
                    "noir=0.010,cairo=0.020,halo2=0.020",
                    "--max-rss-kb",
                    "131072",
                    "--output",
                    str(report),
                    "--enforce",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertFalse(payload["overall_pass"])
            self.assertIn("throughput backend 'noir'", "\n".join(payload["gate_failures"]))

    def test_enforced_gate_fails_when_memory_exceeds_threshold(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_capacity_gate_mem_fail_") as tmpdir:
            root = Path(tmpdir)
            throughput = root / "throughput.json"
            memory = root / "memory.json"
            report = root / "report.json"

            _write_json(throughput, _throughput_payload(noir=0.030, cairo=0.028, halo2=0.041))
            _write_json(memory, _memory_payload([68000, 190000, 62000]))

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--throughput-report",
                    str(throughput),
                    "--memory-report",
                    str(memory),
                    "--skip-throughput-run",
                    "--skip-memory-run",
                    "--min-median-completed-per-sec",
                    "0.020",
                    "--max-rss-kb",
                    "131072",
                    "--output",
                    str(report),
                    "--enforce",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertFalse(payload["overall_pass"])
            self.assertIn("observed max_rss_kb", "\n".join(payload["gate_failures"]))


if __name__ == "__main__":
    unittest.main()
