import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "curate_zkrepos_targets.py"


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def test_curate_reports_ready_tornado_style_circom_target(tmp_path: Path) -> None:
    repo = tmp_path / "tornado-core"
    circuits = repo / "circuits"
    circuits.mkdir(parents=True)
    target = circuits / "withdraw.circom"
    target.write_text("template Withdraw() {}\ncomponent main = Withdraw();\n")

    result = run_script("--root", str(tmp_path), "--format", "json", "--verify")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)

    fit_targets = payload["fit_targets"]
    assert len(fit_targets) == 1
    assert fit_targets[0]["display_name"] == "tornado-core/circuits/withdraw.circom"
    assert fit_targets[0]["verify_status"] == "ready"


def test_curate_keeps_circom_ecdsa_as_blocked_candidate(tmp_path: Path) -> None:
    repo = tmp_path / "circom-ecdsa"
    scripts_dir = repo / "scripts" / "verify"
    scripts_dir.mkdir(parents=True)
    circuits_dir = repo / "circuits"
    circuits_dir.mkdir()
    (circuits_dir / "ecdsa.circom").write_text("template ECDSA() {}\n")
    (scripts_dir / "verify.circom").write_text(
        'include "../../node_modules/circomlib/circuits/bitify.circom";\n'
        'include "../../circuits/ecdsa.circom";\n'
        "component main {public [r, s]} = ECDSA();\n"
    )

    result = run_script("--root", str(tmp_path), "--format", "json", "--verify")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)

    fit_targets = payload["fit_targets"]
    assert len(fit_targets) == 1
    assert fit_targets[0]["repo_name"] == "circom-ecdsa"
    assert fit_targets[0]["status"] == "candidate"
    assert fit_targets[0]["verify_status"] == "blocked"
    assert "include:missing" in fit_targets[0]["verify_message"]


def test_curate_skips_noir_workspace_root(tmp_path: Path) -> None:
    repo = tmp_path / "noir-examples" / "lib_examples"
    repo.mkdir(parents=True)
    (repo / "Nargo.toml").write_text("[workspace]\nmembers = [\"demo\"]\n")

    result = run_script("--root", str(tmp_path), "--format", "json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)

    skipped = payload["skipped_targets"]
    assert len(skipped) == 1
    assert skipped[0]["skip_reason"] == "workspace_manifest"
