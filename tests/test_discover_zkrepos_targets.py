import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "discover_zkrepos_targets.py"


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def test_discovery_reports_framework_and_component(tmp_path: Path) -> None:
    circom = tmp_path / "semaphore.circom"
    circom.write_text("template Semaphore() {}\ncomponent main = Semaphore();\n")

    noir = tmp_path / "app"
    noir.mkdir()
    (noir / "Nargo.toml").write_text("[package]\nname = 'demo'\n")

    cairo = tmp_path / "cairo_proj"
    cairo.mkdir()
    (cairo / "Scarb.toml").write_text("[package]\nname = 'demo'\nversion = '0.1.0'\n")

    halo2 = tmp_path / "halo2_proj"
    (halo2 / "src").mkdir(parents=True)
    (halo2 / "src" / "main.rs").write_text("fn main() {}\n")
    (halo2 / "Cargo.toml").write_text(
        "\n".join(
            [
                "[package]",
                'name = "halo2-demo"',
                'version = "0.1.0"',
                'edition = "2021"',
                "",
                "[dependencies]",
                'halo2_proofs = "0.3"',
            ]
        )
    )

    result = run_script("--root", str(tmp_path), "--format", "json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)

    by_framework = {item["framework"]: item for item in payload}
    assert by_framework["circom"]["main_component"] == "Semaphore"
    assert by_framework["noir"]["target_path"].endswith("Nargo.toml")
    assert by_framework["cairo"]["target_path"].endswith("Scarb.toml")
    assert by_framework["halo2"]["main_component"] == "halo2-demo"


def test_discovery_skips_circom_templates_without_component_main(tmp_path: Path) -> None:
    library_circuit = tmp_path / "lib.circom"
    library_circuit.write_text('include "deps.circom";\ntemplate LibraryOnly() {}\n')

    runnable_circuit = tmp_path / "runnable.circom"
    runnable_circuit.write_text("template Runnable() {}\ncomponent main = Runnable();\n")

    result = run_script("--root", str(tmp_path), "--format", "json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)

    display_names = {item["display_name"] for item in payload}
    assert "runnable.circom" in display_names
    assert "lib.circom" not in display_names


def test_discovery_parses_public_main_component(tmp_path: Path) -> None:
    circom = tmp_path / "verify.circom"
    circom.write_text(
        "template ECDSA() {}\ncomponent main {public [r, s]} = ECDSA();\n"
    )

    result = run_script("--root", str(tmp_path), "--format", "json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)

    assert len(payload) == 1
    assert payload[0]["main_component"] == "ECDSA"


def test_env_output_requires_single_match(tmp_path: Path) -> None:
    first = tmp_path / "a.circom"
    second = tmp_path / "b.circom"
    first.write_text("template A() {}\ncomponent main = A();\n")
    second.write_text("template B() {}\ncomponent main = B();\n")

    result = run_script("--root", str(tmp_path), "--format", "env", "--profile", "deep")
    assert result.returncode != 0
    assert "exactly one matched target" in result.stderr


def test_env_output_renders_profile_bindings(tmp_path: Path) -> None:
    circom = tmp_path / "nested" / "demo.circom"
    circom.parent.mkdir(parents=True)
    circom.write_text("template Demo() {}\ncomponent main = Demo();\n")

    result = run_script(
        "--root",
        str(tmp_path),
        "--match",
        "demo.circom",
        "--format",
        "env",
        "--profile",
        "smoke",
    )
    assert result.returncode == 0, result.stderr
    assert "ZKF_STD_TARGET_SMOKE=" in result.stdout
    assert "ZKF_STD_TARGET_SMOKE_FRAMEWORK=circom" in result.stdout
    assert "ZKF_STD_TARGET_SMOKE_MAIN_COMPONENT=Demo" in result.stdout
