#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINS_DIR="$ROOT_DIR/bins"
OUTPUT_PATH="$ROOT_DIR/artifacts/circom_hermetic/latest_report.json"
ENFORCE=0
ALLOW_EXTERNAL_INCLUDE_ENV=0

usage() {
  cat <<'USAGE'
Usage: scripts/circom_hermetic_gate.sh [options]

Validate deterministic, hermetic Circom include/toolchain resolution for release
lanes. This checks that release execution can resolve Circom + snarkjs from
repo-local bins and compile a circomlib include smoke circuit via local include
roots.

Options:
  --bins-dir <path>                    Local bins directory root (default: bins)
  --output <path>                      Output report path
                                       (default: artifacts/circom_hermetic/latest_report.json)
  --allow-external-circom-include-env  Allow CIRCOM_INCLUDE_PATHS entries outside repository root
  --enforce                            Exit non-zero if gate fails
  -h, --help                           Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bins-dir)
      BINS_DIR="$2"
      shift 2
      ;;
    --output)
      OUTPUT_PATH="$2"
      shift 2
      ;;
    --allow-external-circom-include-env)
      ALLOW_EXTERNAL_INCLUDE_ENV=1
      shift
      ;;
    --enforce)
      ENFORCE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "$(dirname "$OUTPUT_PATH")"

python3 - "$ROOT_DIR" "$BINS_DIR" "$OUTPUT_PATH" "$ENFORCE" "$ALLOW_EXTERNAL_INCLUDE_ENV" <<'PY'
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


def resolve_path(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except Exception:
        return path.absolute()


def looks_executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def add_check(results: List[Dict[str, object]], name: str, ok: bool, detail: str) -> None:
    results.append({"name": name, "ok": ok, "detail": detail})


def _safe_rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except Exception:
        return str(path)


def is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except Exception:
        return False


(
    root_dir_raw,
    bins_dir_raw,
    output_path_raw,
    enforce_raw,
    allow_external_include_env_raw,
) = sys.argv[1:]

root_dir = resolve_path(Path(root_dir_raw))
bins_dir = resolve_path(Path(bins_dir_raw))
output_path = Path(output_path_raw)
enforce = enforce_raw == "1"
allow_external_include_env = allow_external_include_env_raw == "1"

generated_utc = datetime.now(timezone.utc).isoformat()
checks: List[Dict[str, object]] = []
gate_failures: List[str] = []

circom_bin = bins_dir / "bin" / ("circom.exe" if os.name == "nt" else "circom")
snarkjs_candidates = [
    bins_dir / "bin" / ("snarkjs.cmd" if os.name == "nt" else "snarkjs"),
    bins_dir / "node_modules" / ".bin" / ("snarkjs.cmd" if os.name == "nt" else "snarkjs"),
]
include_root = bins_dir / "node_modules"
circomlib_root = include_root / "circomlib"
circomlib_circuits = circomlib_root / "circuits"

circom_ok = looks_executable(circom_bin)
add_check(
    checks,
    "local_circom_binary_present",
    circom_ok,
    f"expected executable at {_safe_rel(circom_bin, root_dir)}",
)
if not circom_ok:
    gate_failures.append(f"missing executable local circom binary: {circom_bin}")

snarkjs_path: Optional[Path] = None
for candidate in snarkjs_candidates:
    if looks_executable(candidate):
        snarkjs_path = candidate
        break
snarkjs_ok = snarkjs_path is not None
add_check(
    checks,
    "local_snarkjs_binary_present",
    snarkjs_ok,
    " or ".join(_safe_rel(path, root_dir) for path in snarkjs_candidates),
)
if not snarkjs_ok:
    gate_failures.append(
        "missing executable local snarkjs binary under bins/bin or bins/node_modules/.bin"
    )

include_root_ok = include_root.is_dir()
add_check(
    checks,
    "local_include_root_present",
    include_root_ok,
    f"expected directory at {_safe_rel(include_root, root_dir)}",
)
if not include_root_ok:
    gate_failures.append(f"missing local include root: {include_root}")

circomlib_ok = circomlib_circuits.is_dir()
add_check(
    checks,
    "circomlib_include_present",
    circomlib_ok,
    f"expected directory at {_safe_rel(circomlib_circuits, root_dir)}",
)
if not circomlib_ok:
    gate_failures.append(f"missing circomlib include directory: {circomlib_circuits}")

raw_include_env = os.environ.get("CIRCOM_INCLUDE_PATHS", "")
external_env_entries: List[str] = []
parsed_include_entries: List[str] = []
if raw_include_env.strip():
    for raw_entry in raw_include_env.split(os.pathsep):
        entry = raw_entry.strip()
        if not entry:
            continue
        parsed_include_entries.append(entry)
        candidate = Path(entry)
        if not candidate.is_absolute():
            candidate = root_dir / candidate
        resolved = resolve_path(candidate)
        if not is_within(resolved, root_dir):
            external_env_entries.append(str(resolved))

env_ok = allow_external_include_env or not external_env_entries
if allow_external_include_env:
    env_detail = "external CIRCOM_INCLUDE_PATHS entries allowed by flag"
elif not parsed_include_entries:
    env_detail = "CIRCOM_INCLUDE_PATHS not set"
else:
    env_detail = "all CIRCOM_INCLUDE_PATHS entries resolve under repository root"
add_check(checks, "circom_include_env_hermetic", env_ok, env_detail)
if not env_ok:
    gate_failures.append(
        "CIRCOM_INCLUDE_PATHS contains entries outside repository root: "
        + ", ".join(external_env_entries)
    )

path_probe_parts = [
    str(bins_dir),
    str(bins_dir / "bin"),
    str(bins_dir / "node_modules" / ".bin"),
    str(bins_dir / "node_modules"),
]
if os.environ.get("PATH"):
    path_probe_parts.append(os.environ["PATH"])
path_probe = os.pathsep.join(path_probe_parts)

detected_circom = shutil.which("circom", path=path_probe)
detected_circom_ok = False
if detected_circom and circom_ok:
    detected_circom_ok = resolve_path(Path(detected_circom)) == resolve_path(circom_bin)
add_check(
    checks,
    "circom_path_resolution_local",
    detected_circom_ok,
    f"detected={detected_circom or 'missing'} expected={circom_bin}",
)
if not detected_circom_ok:
    gate_failures.append(
        f"circom path resolution is not deterministic/local (detected: {detected_circom or 'missing'})"
    )

detected_snarkjs = shutil.which("snarkjs", path=path_probe)
detected_snarkjs_ok = False
if detected_snarkjs:
    detected_snarkjs_ok = is_within(resolve_path(Path(detected_snarkjs)), bins_dir)
add_check(
    checks,
    "snarkjs_path_resolution_local",
    detected_snarkjs_ok,
    f"detected={detected_snarkjs or 'missing'} expected_under={bins_dir}",
)
if not detected_snarkjs_ok:
    gate_failures.append(
        f"snarkjs path resolution is not deterministic/local (detected: {detected_snarkjs or 'missing'})"
    )

compile_smoke_ok = False
compile_smoke_detail = "skipped due to earlier gate failures"
compile_stdout = ""
compile_stderr = ""
if not gate_failures and circom_ok and include_root_ok and circomlib_ok:
    with tempfile.TemporaryDirectory(prefix="zkfuzz_circom_hermetic_") as tmpdir:
        tmp = Path(tmpdir)
        smoke_path = tmp / "smoke.circom"
        build_dir = tmp / "build"
        smoke_path.write_text(
            (
                "pragma circom 2.1.6;\n"
                'include "circomlib/circuits/poseidon.circom";\n'
                "template Smoke() {\n"
                "  signal input in;\n"
                "  signal output out;\n"
                "  component p = Poseidon(1);\n"
                "  p.inputs[0] <== in;\n"
                "  out <== p.out;\n"
                "}\n"
                "component main = Smoke();\n"
            ),
            encoding="utf-8",
        )
        cmd = [
            str(circom_bin),
            str(smoke_path),
            "--r1cs",
            "--wasm",
            "--sym",
            "--json",
            "-o",
            str(build_dir),
            "-l",
            str(include_root),
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "PATH": path_probe},
        )
        compile_stdout = proc.stdout[-2000:]
        compile_stderr = proc.stderr[-2000:]
        r1cs_exists = (build_dir / "smoke.r1cs").is_file()
        wasm_exists = (build_dir / "smoke_js" / "smoke.wasm").is_file()
        compile_smoke_ok = proc.returncode == 0 and r1cs_exists and wasm_exists
        if compile_smoke_ok:
            compile_smoke_detail = "circom include smoke compile succeeded via local bins/node_modules"
        else:
            compile_smoke_detail = (
                f"circom smoke compile failed (exit={proc.returncode}, "
                f"r1cs_exists={r1cs_exists}, wasm_exists={wasm_exists})"
            )
            stderr_snippet = compile_stderr.strip().splitlines()[-1] if compile_stderr.strip() else ""
            if stderr_snippet:
                compile_smoke_detail += f"; stderr_tail={stderr_snippet}"
            gate_failures.append("circom include smoke compile failed under hermetic local roots")

add_check(checks, "circom_include_smoke_compile", compile_smoke_ok, compile_smoke_detail)

overall_pass = len(gate_failures) == 0

report = {
    "generated_utc": generated_utc,
    "overall_pass": overall_pass,
    "root_dir": str(root_dir),
    "bins_dir": str(bins_dir),
    "output_path": str(output_path),
    "allow_external_circom_include_env": allow_external_include_env,
    "circom_include_paths_env": {
        "raw": raw_include_env,
        "parsed_entries": parsed_include_entries,
        "external_entries": external_env_entries,
    },
    "detected_paths": {
        "circom": detected_circom,
        "snarkjs": detected_snarkjs,
    },
    "checks": checks,
    "gate_failures": gate_failures,
    "compile_smoke": {
        "stdout_tail": compile_stdout,
        "stderr_tail": compile_stderr,
    },
}

output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

print(f"Circom hermetic include/toolchain gate: {'PASS' if overall_pass else 'FAIL'}")
print(f"Report: {output_path}")
for failure in gate_failures:
    print(f"- {failure}")

if enforce and not overall_pass:
    sys.exit(1)
PY
