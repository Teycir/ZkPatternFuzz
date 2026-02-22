#!/usr/bin/env python3
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path
import unittest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _script_path() -> Path:
    return _repo_root() / "scripts" / "release_candidate_gate.sh"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _make_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _write_stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body, encoding="utf-8")
    _make_executable(path)


def _write_stub_scripts(stub_dir: Path) -> None:
    stub_dir.mkdir(parents=True, exist_ok=True)

    _write_stub(
        stub_dir / "ci_benchmark_gate.sh",
        "exit 0\n",
    )

    _write_stub(
        stub_dir / "backend_readiness_dashboard.sh",
        """
output=""
enforce=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --enforce) enforce=1; shift ;;
    *) shift ;;
  esac
done
pass=true
if [[ "${FAIL_BACKEND_READINESS:-0}" == "1" ]]; then
  pass=false
fi
python3 - "$output" "$pass" <<'PY'
import json, os, sys
output, pass_raw = sys.argv[1:]
passed = pass_raw == "true"
payload = {
    "overall_pass": passed,
    "aggregate": {"gate_failures": []},
}
if passed:
    payload["backends"] = [
        {"backend": "noir", "gate_pass": True, "gate_failures": []},
        {"backend": "cairo", "gate_pass": True, "gate_failures": []},
        {"backend": "halo2", "gate_pass": True, "gate_failures": []},
    ]
else:
    payload["backends"] = [
        {"backend": "noir", "gate_pass": False, "gate_failures": ["selector_completion below threshold"]},
        {"backend": "cairo", "gate_pass": True, "gate_failures": []},
        {"backend": "halo2", "gate_pass": True, "gate_failures": []},
    ]
os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
with open(output, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
    handle.write("\\n")
PY
if [[ "$enforce" -eq 1 && "$pass" != "true" ]]; then
  exit 1
fi
""",
    )

    _write_stub(
        stub_dir / "backend_maturity_scorecard.sh",
        """
output=""
consecutive_days=0
consecutive_target=5.0
enforce=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --consecutive-days) consecutive_days="$2"; shift 2 ;;
    --consecutive-target-score) consecutive_target="$2"; shift 2 ;;
    --enforce) enforce=1; shift ;;
    *) shift ;;
  esac
done
pass=true
if [[ "${FAIL_BACKEND_MATURITY:-0}" == "1" ]]; then
  pass=false
fi
soft_blocker=0
if [[ "${MATURITY_SOFT_BACKEND_BLOCKER:-0}" == "1" ]]; then
  soft_blocker=1
fi
python3 - "$output" "$pass" "$consecutive_days" "$consecutive_target" "$soft_blocker" <<'PY'
import json, os, sys
output, pass_raw, days_raw, target_raw, soft_blocker_raw = sys.argv[1:]
passed = pass_raw == "true"
days = int(days_raw)
target = float(target_raw)
soft_blocker = soft_blocker_raw == "1"
payload = {
    "overall_pass": passed,
    "thresholds": {
        "consecutive_days": days,
        "consecutive_target_score": target,
    },
    "consecutive_gate": {
        "enabled": days > 0,
        "target_days": days,
        "target_score": target,
        "overall_pass": passed,
    },
    "gate_failures": [],
}
if not passed:
    payload["gate_failures"] = ["noir: score 4.200 < required 4.500"]
elif soft_blocker:
    payload["gate_failures"] = ["noir: unresolved release blocker marker"]
os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
with open(output, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
    handle.write("\\n")
PY
if [[ "$enforce" -eq 1 && "$pass" != "true" ]]; then
  exit 1
fi
""",
    )

    _write_stub(
        stub_dir / "circom_flake_gate.sh",
        """
output=""
required_days=0
enforce=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --required-consecutive-days) required_days="$2"; shift 2 ;;
    --enforce) enforce=1; shift ;;
    *) shift ;;
  esac
done
pass=true
if [[ "${FAIL_CIRCOM_FLAKE:-0}" == "1" ]]; then
  pass=false
fi
python3 - "$output" "$pass" "$required_days" <<'PY'
import json, os, sys
output, pass_raw, days_raw = sys.argv[1:]
passed = pass_raw == "true"
days = int(days_raw)
payload = {
    "overall_pass": passed,
    "required_consecutive_days": days,
    "required_gate_enabled": days > 0,
    "failures": [] if passed else [f"circom lane streak 3 < required {days} consecutive UTC days"],
}
os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
with open(output, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
    handle.write("\\n")
PY
if [[ "$enforce" -eq 1 && "$pass" != "true" ]]; then
  exit 1
fi
""",
    )

    _write_stub(
        stub_dir / "circom_hermetic_gate.sh",
        """
output=""
enforce=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --enforce) enforce=1; shift ;;
    *) shift ;;
  esac
done
pass=true
if [[ "${FAIL_CIRCOM_HERMETIC:-0}" == "1" ]]; then
  pass=false
fi
python3 - "$output" "$pass" <<'PY'
import json, os, sys
output, pass_raw = sys.argv[1:]
passed = pass_raw == "true"
payload = {
    "overall_pass": passed,
    "gate_failures": [] if passed else ["missing executable local circom binary"],
}
os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
with open(output, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
    handle.write("\\n")
PY
if [[ "$enforce" -eq 1 && "$pass" != "true" ]]; then
  exit 1
fi
""",
    )

    _write_stub(
        stub_dir / "backend_capacity_fitness_gate.sh",
        """
output=""
enforce=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --enforce) enforce=1; shift ;;
    *) shift ;;
  esac
done
pass=true
if [[ "${FAIL_BACKEND_CAPACITY_FITNESS:-0}" == "1" ]]; then
  pass=false
fi
python3 - "$output" "$pass" <<'PY'
import json, os, sys
output, pass_raw = sys.argv[1:]
passed = pass_raw == "true"
payload = {
    "overall_pass": passed,
    "gate_failures": [] if passed else ["throughput backend 'noir' reported overall_pass=false"],
}
os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
with open(output, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
    handle.write("\\n")
PY
if [[ "$enforce" -eq 1 && "$pass" != "true" ]]; then
  exit 1
fi
""",
    )

    _write_stub(
        stub_dir / "rollback_validate.sh",
        "exit 0\n",
    )


def _write_minimal_benchmark_summary(path: Path) -> None:
    _write_json(
        path,
        {
            "total_runs": 5,
            "overall_completion_rate": 1.0,
            "vulnerable_recall": 1.0,
            "precision": 1.0,
            "safe_false_positive_rate": 0.0,
            "safe_high_confidence_false_positive_rate": 0.0,
        },
    )


class ReleaseCandidateGateTests(unittest.TestCase):
    def test_release_gate_archives_5_of_5_evidence_bundles(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_release_gate_pass_") as tmpdir:
            root = Path(tmpdir)
            bench_root = root / "benchmark_runs"
            _write_minimal_benchmark_summary(
                bench_root / "benchmark_20260222_000000" / "summary.json"
            )
            _write_minimal_benchmark_summary(
                bench_root / "benchmark_20260222_000001" / "summary.json"
            )

            keygen_report = root / "keygen_preflight.json"
            release_report = root / "release_candidate_report.json"
            _write_json(keygen_report, {"passes": True, "total_targets": 5, "passed_targets": 5})
            _write_json(release_report, {"overall_pass": True})

            stub_dir = root / "stubs"
            _write_stub_scripts(stub_dir)

            readiness_report = root / "backend_readiness" / "latest_report.json"
            maturity_scorecard = root / "backend_maturity" / "latest_scorecard.json"
            maturity_history = root / "backend_maturity" / "history.json"
            flake_report = root / "circom_flake" / "latest_report.json"
            flake_history = root / "circom_flake" / "history.json"
            hermetic_report = root / "circom_hermetic" / "latest_report.json"
            capacity_report = root / "backend_capacity_fitness" / "latest_report.json"
            evidence_archive_root = root / "release_candidate_validation" / "evidence_bundles"
            evidence_manifest = (
                root / "release_candidate_validation" / "evidence_bundle_manifest.json"
            )
            blockers_report = (
                root / "release_candidate_validation" / "backend_release_blockers.json"
            )

            env = os.environ.copy()
            env["ZKFUZZ_RELEASE_GATE_SCRIPT_DIR"] = str(stub_dir)
            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--bench-root",
                    str(bench_root),
                    "--required-passes",
                    "2",
                    "--backend-readiness-dashboard",
                    str(readiness_report),
                    "--backend-maturity-scorecard",
                    str(maturity_scorecard),
                    "--backend-maturity-history",
                    str(maturity_history),
                    "--keygen-preflight-report",
                    str(keygen_report),
                    "--release-candidate-report",
                    str(release_report),
                    "--circom-flake-report",
                    str(flake_report),
                    "--circom-flake-history",
                    str(flake_history),
                    "--circom-flake-consecutive-days",
                    "14",
                    "--circom-hermetic-report",
                    str(hermetic_report),
                    "--backend-capacity-fitness-report",
                    str(capacity_report),
                    "--backend-maturity-consecutive-days",
                    "14",
                    "--backend-maturity-consecutive-target-score",
                    "5.0",
                    "--evidence-archive-root",
                    str(evidence_archive_root),
                    "--evidence-manifest",
                    str(evidence_manifest),
                    "--backend-blockers-report",
                    str(blockers_report),
                ],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )

            self.assertEqual(
                proc.returncode,
                0,
                msg=f"stdout={proc.stdout}\nstderr={proc.stderr}",
            )

            manifest = json.loads(evidence_manifest.read_text(encoding="utf-8"))
            blockers = json.loads(blockers_report.read_text(encoding="utf-8"))
            self.assertTrue(manifest["overall_pass"])
            self.assertEqual(manifest["required_bundle_total"], 5)
            self.assertEqual(manifest["required_bundle_passing"], 5)
            self.assertEqual(manifest["release_failures"], [])
            self.assertTrue(blockers["overall_pass"])
            self.assertEqual(blockers["unresolved_backend_blockers_count"], 0)

            archive_dir = Path(manifest["archive_dir"])
            self.assertTrue(archive_dir.is_dir())
            for bundle in manifest["bundles"]:
                archived = bundle["archived_path"]
                self.assertIsNotNone(archived)
                self.assertTrue(Path(archived).is_file(), msg=f"missing archive for {bundle}")

    def test_release_gate_fails_when_backend_blockers_exist(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_release_gate_fail_") as tmpdir:
            root = Path(tmpdir)
            bench_root = root / "benchmark_runs"
            _write_minimal_benchmark_summary(
                bench_root / "benchmark_20260222_000000" / "summary.json"
            )
            _write_minimal_benchmark_summary(
                bench_root / "benchmark_20260222_000001" / "summary.json"
            )

            keygen_report = root / "keygen_preflight.json"
            release_report = root / "release_candidate_report.json"
            _write_json(keygen_report, {"passes": True, "total_targets": 5, "passed_targets": 5})
            _write_json(release_report, {"overall_pass": True})

            stub_dir = root / "stubs"
            _write_stub_scripts(stub_dir)

            readiness_report = root / "backend_readiness" / "latest_report.json"
            maturity_scorecard = root / "backend_maturity" / "latest_scorecard.json"
            maturity_history = root / "backend_maturity" / "history.json"
            flake_report = root / "circom_flake" / "latest_report.json"
            flake_history = root / "circom_flake" / "history.json"
            hermetic_report = root / "circom_hermetic" / "latest_report.json"
            capacity_report = root / "backend_capacity_fitness" / "latest_report.json"
            evidence_archive_root = root / "release_candidate_validation" / "evidence_bundles"
            evidence_manifest = (
                root / "release_candidate_validation" / "evidence_bundle_manifest.json"
            )
            blockers_report = (
                root / "release_candidate_validation" / "backend_release_blockers.json"
            )

            env = os.environ.copy()
            env["ZKFUZZ_RELEASE_GATE_SCRIPT_DIR"] = str(stub_dir)
            env["MATURITY_SOFT_BACKEND_BLOCKER"] = "1"
            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--bench-root",
                    str(bench_root),
                    "--required-passes",
                    "2",
                    "--backend-readiness-dashboard",
                    str(readiness_report),
                    "--backend-maturity-scorecard",
                    str(maturity_scorecard),
                    "--backend-maturity-history",
                    str(maturity_history),
                    "--keygen-preflight-report",
                    str(keygen_report),
                    "--release-candidate-report",
                    str(release_report),
                    "--circom-flake-report",
                    str(flake_report),
                    "--circom-flake-history",
                    str(flake_history),
                    "--circom-flake-consecutive-days",
                    "14",
                    "--circom-hermetic-report",
                    str(hermetic_report),
                    "--backend-capacity-fitness-report",
                    str(capacity_report),
                    "--backend-maturity-consecutive-days",
                    "14",
                    "--backend-maturity-consecutive-target-score",
                    "5.0",
                    "--evidence-archive-root",
                    str(evidence_archive_root),
                    "--evidence-manifest",
                    str(evidence_manifest),
                    "--backend-blockers-report",
                    str(blockers_report),
                ],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )

            self.assertNotEqual(proc.returncode, 0, msg=f"stdout={proc.stdout}\nstderr={proc.stderr}")
            manifest = json.loads(evidence_manifest.read_text(encoding="utf-8"))
            blockers = json.loads(blockers_report.read_text(encoding="utf-8"))
            self.assertFalse(manifest["overall_pass"])
            self.assertEqual(manifest["required_bundle_passing"], 5)
            self.assertFalse(blockers["overall_pass"])
            self.assertGreater(blockers["unresolved_backend_blockers_count"], 0)
            noir_blockers = [
                row
                for row in blockers["unresolved_backend_blockers"]
                if row.get("backend") == "noir" and row.get("bundle") == "backend_maturity"
            ]
            self.assertTrue(noir_blockers, msg=f"blockers={blockers}")


if __name__ == "__main__":
    unittest.main()
