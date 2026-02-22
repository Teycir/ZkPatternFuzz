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
    return _repo_root() / "scripts" / "circom_hermetic_gate.sh"


def _make_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _prepare_local_bins(root: Path, include_circomlib_in_bins: bool = True) -> Path:
    bins = root / "bins"
    circom_bin = bins / "bin" / "circom"
    snarkjs_bin = bins / "bin" / "snarkjs"
    circomlib_dir = bins / "node_modules" / "circomlib" / "circuits"

    _make_executable(
        circom_bin,
        """#!/usr/bin/env bash
set -euo pipefail
src=""
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o)
      out="$2"
      shift 2
      ;;
    -*)
      shift
      ;;
    *)
      if [[ -z "$src" ]]; then
        src="$1"
      fi
      shift
      ;;
  esac
done
if [[ -z "$src" || -z "$out" ]]; then
  echo "missing src/out" >&2
  exit 2
fi
base="$(basename "$src" .circom)"
mkdir -p "$out/${base}_js"
touch "$out/${base}.r1cs"
touch "$out/${base}_js/${base}.wasm"
""",
    )

    _make_executable(
        snarkjs_bin,
        """#!/usr/bin/env bash
set -euo pipefail
echo "snarkjs stub"
""",
    )

    if include_circomlib_in_bins:
        circomlib_dir.mkdir(parents=True, exist_ok=True)
        (circomlib_dir / "poseidon.circom").write_text(
            "template Poseidon(n) { signal input inputs[n]; signal output out; out <== inputs[0]; }\n",
            encoding="utf-8",
        )
    return bins


class CircomHermeticGateTests(unittest.TestCase):
    def test_enforced_gate_passes_with_local_bins_and_include_smoke(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_circom_hermetic_pass_") as tmpdir:
            root = Path(tmpdir)
            bins = _prepare_local_bins(root)
            report = root / "report.json"

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--bins-dir",
                    str(bins),
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
            checks = {entry["name"]: entry["ok"] for entry in payload["checks"]}
            self.assertTrue(checks.get("circom_include_smoke_compile"))
            self.assertTrue(checks.get("circom_path_resolution_local"))
            self.assertTrue(checks.get("snarkjs_path_resolution_local"))

    def test_enforced_gate_fails_with_external_circom_include_env(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_circom_hermetic_env_fail_") as tmpdir:
            root = Path(tmpdir)
            bins = _prepare_local_bins(root)
            report = root / "report.json"

            env = dict(os.environ)
            env["CIRCOM_INCLUDE_PATHS"] = "/opt/global/circomlib"

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--bins-dir",
                    str(bins),
                    "--output",
                    str(report),
                    "--enforce",
                ],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertNotEqual(
                proc.returncode,
                0,
                msg=f"stdout={proc.stdout}\nstderr={proc.stderr}",
            )
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertFalse(payload["overall_pass"])
            self.assertTrue(payload["gate_failures"])
            self.assertIn(
                "outside repository root",
                "\n".join(payload["gate_failures"]),
            )

    def test_enforced_gate_uses_repo_node_modules_fallback_include_root(self):
        with tempfile.TemporaryDirectory(prefix="zkfuzz_circom_hermetic_root_fallback_") as tmpdir:
            root = Path(tmpdir)
            bins = _prepare_local_bins(root, include_circomlib_in_bins=False)
            report = root / "report.json"

            proc = subprocess.run(
                [
                    str(_script_path()),
                    "--bins-dir",
                    str(bins),
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
            self.assertEqual(
                Path(payload["selected_include_root"]).resolve(),
                (_repo_root() / "node_modules").resolve(),
            )
            checks = {entry["name"]: entry["ok"] for entry in payload["checks"]}
            self.assertTrue(checks.get("circom_include_smoke_compile"))


if __name__ == "__main__":
    unittest.main()
