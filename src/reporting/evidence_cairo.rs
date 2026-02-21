//! Cairo Proof Generation for Evidence Bundles (Phase 0: Milestone 0.4)
//!
//! Generates verifiable proofs for Cairo programs using stone-prover.
//!
//! # Proof Generation Flow
//!
//! ```text
//! Finding → Generate input.json → cairo-run → stone-prover → Verify
//!                                                              │
//!                                                  ┌───────────┴───────────┐
//!                                                  │                       │
//!                                              PASSES                   FAILS
//!                                                  │                       │
//!                                        CONFIRMED BUG            Not a real bug
//! ```

use super::evidence::VerificationResult;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use zk_core::Finding;

/// Generate Cairo proof for a finding
///
/// # Arguments
/// * `finding_dir` - Directory containing witness.json
/// * `finding` - The finding to generate proof for
/// * `program_path` - Path to the compiled Cairo program (program.json)
///
/// # Returns
/// Tuple of (proof_path, verification_result)
pub fn generate_cairo_proof(
    finding_dir: &Path,
    _finding: &Finding,
    program_path: &Path,
) -> anyhow::Result<(std::path::PathBuf, VerificationResult)> {
    let timeout = Duration::from_secs(300);
    let proof_path = finding_dir.join("cairo_proof.json");
    let trace_path = finding_dir.join("trace.bin");
    let memory_path = finding_dir.join("memory.bin");
    let air_public_input = finding_dir.join("air_public_input.json");
    let air_private_input = finding_dir.join("air_private_input.json");
    let witness_json = finding_dir.join("witness.json");

    if !witness_json.exists() {
        return Ok((
            proof_path,
            VerificationResult::Failed("witness.json not found".to_string()),
        ));
    }

    if !program_path.exists() {
        return Ok((
            proof_path,
            VerificationResult::Failed(format!(
                "Cairo program not found: {}",
                program_path.display()
            )),
        ));
    }

    // Convert witness.json to Cairo input format
    let input_path = finding_dir.join("input.json");
    if let Err(e) = convert_witness_to_cairo_input(&witness_json, &input_path) {
        return Ok((
            proof_path,
            VerificationResult::Failed(format!("Failed to convert witness: {}", e)),
        ));
    }

    // Check for cairo-run (Cairo 0) or scarb (Cairo 1)
    let has_cairo_run = matches!(
        super::command_timeout::run_with_timeout(
            Command::new("cairo-run").arg("--version"),
            Duration::from_secs(10),
        ),
        Ok(output) if output.status.success()
    );
    let has_scarb = matches!(
        super::command_timeout::run_with_timeout(
            Command::new("scarb").arg("--version"),
            Duration::from_secs(10),
        ),
        Ok(output) if output.status.success()
    );

    if !has_cairo_run && !has_scarb {
        return Ok((
            proof_path,
            VerificationResult::Failed("Neither cairo-run nor scarb found in PATH".to_string()),
        ));
    }

    tracing::info!("Generating Cairo proof for finding in {:?}", finding_dir);

    // Step 1: Run Cairo program to generate trace
    let run_result = if has_cairo_run {
        super::command_timeout::run_with_timeout(
            Command::new("cairo-run")
                .args([
                    "--program",
                    &program_path.display().to_string(),
                    "--print_output",
                    "--trace_file",
                    &trace_path.display().to_string(),
                    "--memory_file",
                    &memory_path.display().to_string(),
                    "--air_public_input",
                    &air_public_input.display().to_string(),
                    "--air_private_input",
                    &air_private_input.display().to_string(),
                ])
                .current_dir(finding_dir),
            timeout,
        )
    } else {
        // For Scarb-based projects, we need a different approach
        return Ok((
            proof_path,
            VerificationResult::Failed(
                "Scarb-based Cairo 1 proof generation not yet implemented".to_string(),
            ),
        ));
    };

    match run_result {
        Ok(output) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Cairo execution failed: {}", stderr);
            return Ok((
                proof_path,
                VerificationResult::Failed(format!(
                    "cairo-run failed: {}",
                    stderr.chars().take(200).collect::<String>()
                )),
            ));
        }
        Err(e) => {
            return Ok((
                proof_path,
                VerificationResult::Failed(format!("cairo-run error: {}", e)),
            ));
        }
        _ => {
            tracing::debug!("Cairo execution completed successfully");
        }
    }

    // Step 2: Generate STARK proof using stone-prover (if available)
    let has_stone_prover = matches!(
        super::command_timeout::run_with_timeout(
            Command::new("cpu_air_prover").arg("--version"),
            Duration::from_secs(10),
        ),
        Ok(output) if output.status.success()
    );

    if !has_stone_prover {
        return Ok((
            proof_path,
            VerificationResult::Failed(
                "stone-prover (cpu_air_prover) not found. Install from starkware-libs/stone-prover"
                    .to_string(),
            ),
        ));
    }

    // Generate proof
    let prove_result = super::command_timeout::run_with_timeout(
        Command::new("cpu_air_prover")
            .args([
                "--out_file",
                &proof_path.display().to_string(),
                "--public_input_file",
                &air_public_input.display().to_string(),
                "--private_input_file",
                &air_private_input.display().to_string(),
                "--prover_config_file",
                "cpu_air_prover_config.json", // Default config
            ])
            .current_dir(finding_dir),
        timeout,
    );

    match prove_result {
        Ok(output) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Stone prover failed: {}", stderr);
            return Ok((
                proof_path,
                VerificationResult::Failed(format!(
                    "Proof generation failed (trace exists): {}",
                    stderr.chars().take(200).collect::<String>()
                )),
            ));
        }
        Err(e) => {
            tracing::warn!("Stone prover error: {}", e);
            // Still return success if trace was generated
            if trace_path.exists() {
                return Ok((
                    proof_path,
                    VerificationResult::Failed(format!("Trace generated but proof failed: {}", e)),
                ));
            }
            return Ok((
                proof_path,
                VerificationResult::Failed(format!("stone prover error: {}", e)),
            ));
        }
        _ => {
            tracing::info!("Cairo STARK proof generated successfully");
        }
    }

    // Step 3: Verify proof
    let verify_result = super::command_timeout::run_with_timeout(
        Command::new("cpu_air_verifier")
            .args(["--in_file", &proof_path.display().to_string()])
            .current_dir(finding_dir),
        timeout,
    );

    match verify_result {
        Ok(output) if output.status.success() => {
            tracing::info!("Cairo proof verified - CONFIRMED BUG");
            Ok((proof_path, VerificationResult::Passed))
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::info!("Cairo proof verification failed: {}", stderr);
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
            VerificationResult::Failed(format!("cpu_air_verifier error: {}", e)),
        )),
    }
}

/// Convert witness.json to Cairo input format
fn convert_witness_to_cairo_input(witness_json: &Path, input_path: &Path) -> anyhow::Result<()> {
    let json_content = std::fs::read_to_string(witness_json)?;
    let witness: serde_json::Value = serde_json::from_str(&json_content)?;

    // Cairo expects a specific input format
    // For most cases, we can pass the witness directly
    std::fs::write(input_path, serde_json::to_string_pretty(&witness)?)?;
    Ok(())
}

/// Generate Cairo reproduction script
pub fn generate_cairo_repro_script(
    path: &Path,
    finding: &Finding,
    program_path: &Path,
) -> anyhow::Result<String> {
    let script = format!(
        r#"#!/bin/bash
# Reproduction script for Cairo finding: {:?}
# Generated by ZkPatternFuzz evidence mode
set -e

PROGRAM_PATH="{}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Reproducing Cairo finding: {} ==="
echo ""

# Step 1: Run Cairo program with trace generation
cairo-run \
    --program "$PROGRAM_PATH" \
    --print_output \
    --trace_file "$SCRIPT_DIR/trace.bin" \
    --memory_file "$SCRIPT_DIR/memory.bin" \
    --air_public_input "$SCRIPT_DIR/air_public_input.json" \
    --air_private_input "$SCRIPT_DIR/air_private_input.json"
echo "✓ Trace generated"

# Step 2: Generate STARK proof (requires stone-prover)
if command -v cpu_air_prover &> /dev/null; then
    cpu_air_prover \
        --out_file "$SCRIPT_DIR/proof.json" \
        --public_input_file "$SCRIPT_DIR/air_public_input.json" \
        --private_input_file "$SCRIPT_DIR/air_private_input.json"
    echo "✓ Proof generated"
    
    # Step 3: Verify
    cpu_air_verifier --in_file "$SCRIPT_DIR/proof.json"
    echo ""
    echo "========================================"
    echo "If verification SUCCEEDS, this is a CONFIRMED soundness bug."
    echo "========================================"
else
    echo "⚠ stone-prover not found - skipping proof generation"
    echo "Install from: https://github.com/starkware-libs/stone-prover"
fi
"#,
        finding.attack_type,
        program_path.display(),
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
#[path = "evidence_cairo_tests.rs"]
mod tests;
