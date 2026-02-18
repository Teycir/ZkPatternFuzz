//! Noir Proof Generation for Evidence Bundles (Phase 0: Milestone 0.4)
//!
//! Generates verifiable proofs for Noir circuits using nargo.
//!
//! # Proof Generation Flow
//!
//! ```text
//! Finding → Generate Prover.toml → nargo prove → nargo verify
//!                                                      │
//!                                          ┌───────────┴───────────┐
//!                                          │                       │
//!                                      PASSES                   FAILS
//!                                          │                       │
//!                                CONFIRMED BUG            Not a real bug
//! ```

use super::evidence::VerificationResult;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use zk_core::Finding;

/// Generate Noir proof for a finding
///
/// # Arguments
/// * `finding_dir` - Directory containing witness.json
/// * `finding` - The finding to generate proof for
/// * `project_path` - Path to the Noir project (contains Nargo.toml)
///
/// # Returns
/// Tuple of (proof_path, verification_result)
pub fn generate_noir_proof(
    finding_dir: &Path,
    _finding: &Finding,
    project_path: &Path,
) -> anyhow::Result<(std::path::PathBuf, VerificationResult)> {
    let timeout = Duration::from_secs(120);
    let proof_path = finding_dir.join("proof.bin");
    let prover_toml = project_path.join("Prover.toml");
    let witness_json = finding_dir.join("witness.json");

    // Step 1: Convert witness.json to Prover.toml format
    if witness_json.exists() {
        if let Err(e) = convert_witness_to_prover_toml(&witness_json, &prover_toml) {
            return Ok((
                proof_path,
                VerificationResult::Skipped(format!("Failed to convert witness: {}", e)),
            ));
        }
    } else {
        return Ok((
            proof_path,
            VerificationResult::Skipped("witness.json not found".to_string()),
        ));
    }

    // Step 2: Check for nargo
    let nargo_check = super::command_timeout::run_with_timeout(
        Command::new("nargo").arg("--version"),
        Duration::from_secs(10),
    );

    let nargo_ok = matches!(nargo_check, Ok(output) if output.status.success());
    if !nargo_ok {
        return Ok((
            proof_path,
            VerificationResult::Skipped("nargo not found in PATH".to_string()),
        ));
    }

    // Step 3: Generate proof
    tracing::info!("Generating Noir proof for finding in {:?}", finding_dir);

    let prove_result = super::command_timeout::run_with_timeout(
        Command::new("nargo").arg("prove").current_dir(project_path),
        timeout,
    );

    match prove_result {
        Ok(output) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Noir proof generation failed: {}", stderr);
            return Ok((
                proof_path,
                VerificationResult::Failed(format!(
                    "proof generation failed: {}",
                    stderr.chars().take(200).collect::<String>()
                )),
            ));
        }
        Err(e) => {
            return Ok((
                proof_path,
                VerificationResult::Skipped(format!("nargo prove failed: {}", e)),
            ));
        }
        _ => {
            tracing::debug!("Noir proof generated successfully");
        }
    }

    // Copy proof to finding directory
    let noir_proof = project_path.join("proofs").join("noir.proof");
    if noir_proof.exists() {
        std::fs::copy(&noir_proof, &proof_path)?;
    }

    // Step 4: Verify proof
    let verify_result = super::command_timeout::run_with_timeout(
        Command::new("nargo")
            .arg("verify")
            .current_dir(project_path),
        timeout,
    );

    match verify_result {
        Ok(output) if output.status.success() => {
            tracing::info!("Noir proof verified - CONFIRMED BUG");
            Ok((proof_path, VerificationResult::Passed))
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::info!("Noir proof verification failed: {}", stderr);
            Ok((
                proof_path,
                VerificationResult::Failed(format!(
                    "verification failed: {}",
                    stderr.chars().take(200).collect::<String>()
                )),
            ))
        }
        Err(e) => Ok((
            proof_path,
            VerificationResult::Skipped(format!("nargo verify failed: {}", e)),
        )),
    }
}

/// Convert witness.json to Noir's Prover.toml format
fn convert_witness_to_prover_toml(witness_json: &Path, prover_toml: &Path) -> anyhow::Result<()> {
    let json_content = std::fs::read_to_string(witness_json)?;
    let witness: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&json_content)?;

    let mut toml_content = String::new();

    for (key, value) in witness {
        match value {
            serde_json::Value::String(s) => {
                toml_content.push_str(&format!("{} = \"{}\"\n", key, s));
            }
            serde_json::Value::Number(n) => {
                toml_content.push_str(&format!("{} = \"{}\"\n", key, n));
            }
            serde_json::Value::Array(arr) => {
                let values: Vec<String> = arr
                    .iter()
                    .map(|v| match v {
                        serde_json::Value::String(s) => format!("\"{}\"", s),
                        serde_json::Value::Number(n) => format!("\"{}\"", n),
                        _ => "\"0\"".to_string(),
                    })
                    .collect();
                toml_content.push_str(&format!("{} = [{}]\n", key, values.join(", ")));
            }
            _ => {}
        }
    }

    std::fs::write(prover_toml, toml_content)?;
    Ok(())
}

/// Generate Noir reproduction script
pub fn generate_noir_repro_script(
    path: &Path,
    finding: &Finding,
    project_path: &Path,
) -> anyhow::Result<String> {
    let script = format!(
        r#"#!/bin/bash
# Reproduction script for Noir finding: {:?}
# Generated by ZkPatternFuzz evidence mode
set -e

PROJECT_PATH="{}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Reproducing Noir finding: {} ==="
echo ""

# Step 1: Copy witness to Prover.toml
if [ -f "$SCRIPT_DIR/Prover.toml" ]; then
    cp "$SCRIPT_DIR/Prover.toml" "$PROJECT_PATH/Prover.toml"
fi

# Step 2: Generate proof
cd "$PROJECT_PATH"
nargo prove
echo "✓ Proof generated"

# Step 3: Verify proof
nargo verify
echo ""
echo "========================================"
echo "If verification SUCCEEDS, this is a CONFIRMED soundness bug."
echo "========================================"
"#,
        finding.attack_type,
        project_path.display(),
        finding.description.chars().take(50).collect::<String>(),
    );

    std::fs::write(path, &script)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms)?;
    }

    Ok(format!(
        "cd {} && ./repro.sh",
        path.parent().unwrap().display()
    ))
}

#[cfg(test)]
#[path = "evidence_noir_tests.rs"]
mod tests;
