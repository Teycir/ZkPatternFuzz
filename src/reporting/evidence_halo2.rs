//! Halo2 Proof Generation for Evidence Bundles (Phase 0: Milestone 0.4)
//!
//! Generates verifiable proofs for Halo2 circuits using the halo2_proofs crate.
//!
//! # Verification Flow
//!
//! We use `Halo2Target` directly so the evidence path stays backend-driven:
//!
//! ```text
//! Finding → Load Witness → Halo2Target::prove() → Halo2Target::verify()
//!                                                    │
//!                                        ┌───────────┴───────────┐
//!                                        │                       │
//!                                    PASSES                   FAILS
//!                                        │                       │
//!                              CONFIRMED BUG            Not a real bug
//! ```

use super::evidence::VerificationResult;
use std::path::Path;
use zk_core::{FieldElement, Finding};

/// Generate Halo2 proof verification for a finding
///
/// # Arguments
/// * `finding_dir` - Directory containing witness.json
/// * `finding` - The finding to generate proof for
/// * `circuit_spec_path` - Path to the Halo2 circuit specification JSON
///
/// # Returns
/// Tuple of (proof_path, verification_result)
pub fn generate_halo2_proof(
    finding_dir: &Path,
    _finding: &Finding,
    circuit_spec_path: Option<&Path>,
) -> anyhow::Result<(std::path::PathBuf, VerificationResult)> {
    let proof_path = finding_dir.join("halo2_proof.json");
    let witness_json = finding_dir.join("witness.json");

    if !witness_json.exists() {
        return Ok((
            proof_path,
            VerificationResult::Skipped("witness.json not found".to_string()),
        ));
    }

    // For Halo2, we need a circuit specification or compiled circuit
    let spec_path = match circuit_spec_path {
        Some(p) if p.exists() => p,
        _ => {
            return Ok((
                proof_path,
                VerificationResult::Skipped(
                    "Halo2 circuit specification not found. Set 'halo2_circuit_spec' in config."
                        .to_string(),
                ),
            ));
        }
    };

    tracing::info!(
        "Verifying Halo2 circuit with witness from {:?}",
        finding_dir
    );

    // Load witness
    let witness_content = std::fs::read_to_string(&witness_json)?;
    let witness: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&witness_content)?;

    let fallback_reason = match try_halo2_prove_and_verify(spec_path, &witness) {
        Ok((proof_bytes, verified)) => {
            std::fs::write(&proof_path, &proof_bytes)?;
            return Ok((
                proof_path,
                if verified {
                    VerificationResult::Passed
                } else {
                    VerificationResult::Failed("Halo2 proof verification failed".to_string())
                },
            ));
        }
        Err(e) => e.to_string(),
    };

    // Create verification result JSON
    let verification_result = serde_json::json!({
        "circuit_spec": spec_path.display().to_string(),
        "witness": witness,
        "prover_k": 10,  // Default circuit size parameter
        "status": "requires_local_halo2_runtime",
        "note": "Automatic proof generation failed in this environment. Use verify_halo2.rs for standalone verification with Halo2Target.",
        "fallback_reason": fallback_reason
    });

    std::fs::write(
        &proof_path,
        serde_json::to_string_pretty(&verification_result)?,
    )?;

    // Generate verification script
    let verify_script = finding_dir.join("verify_halo2.rs");
    generate_halo2_verify_script(&verify_script, spec_path, &witness_json)?;

    Ok((
        proof_path,
        VerificationResult::Skipped(
            "Automatic Halo2 verification unavailable here. Run verify_halo2.rs for standalone verification.".to_string(),
        ),
    ))
}

fn try_halo2_prove_and_verify(
    spec_path: &Path,
    witness: &serde_json::Map<String, serde_json::Value>,
) -> anyhow::Result<(Vec<u8>, bool)> {
    use crate::targets::Halo2Target;
    use crate::targets::TargetCircuit;

    let mut target = Halo2Target::new(spec_path.to_str().unwrap_or_default())?;
    target.setup()?;

    let inputs = parse_witness_inputs(witness)?;
    let public_len = target.num_public_inputs();
    let public_inputs = inputs.iter().take(public_len).cloned().collect::<Vec<_>>();

    let proof = target.prove(&inputs)?;
    let verified = target.verify(&proof, &public_inputs)?;
    Ok((proof, verified))
}

fn parse_witness_inputs(
    witness: &serde_json::Map<String, serde_json::Value>,
) -> anyhow::Result<Vec<FieldElement>> {
    let mut keys: Vec<&String> = witness.keys().collect();
    keys.sort();

    let mut inputs = Vec::new();
    for key in keys {
        if let Some(value) = witness.get(key) {
            flatten_json_value(value, &mut inputs)?;
        }
    }
    Ok(inputs)
}

fn flatten_json_value(
    value: &serde_json::Value,
    out: &mut Vec<FieldElement>,
) -> anyhow::Result<()> {
    match value {
        serde_json::Value::String(s) => {
            if let Ok(fe) = FieldElement::from_hex(s) {
                out.push(fe);
            } else if let Ok(num) = s.parse::<u64>() {
                out.push(FieldElement::from_u64(num));
            } else {
                anyhow::bail!("Unsupported witness string value: {}", s);
            }
        }
        serde_json::Value::Number(n) => {
            let num = n.as_u64().unwrap_or(0);
            out.push(FieldElement::from_u64(num));
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                flatten_json_value(item, out)?;
            }
        }
        serde_json::Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            for key in keys {
                if let Some(value) = obj.get(key) {
                    flatten_json_value(value, out)?;
                }
            }
        }
        _ => anyhow::bail!("Unsupported witness value type"),
    }
    Ok(())
}

/// Generate a Rust script for Halo2 verification
fn generate_halo2_verify_script(
    path: &Path,
    circuit_spec: &Path,
    witness_json: &Path,
) -> anyhow::Result<()> {
    let script = format!(
        r#"//! Halo2 Verification Script
//! Generated by ZkPatternFuzz
//!
//! This verifier uses `zk_backends::Halo2Target` directly and does not require
//! project-specific circuit glue code.
//!
//! To run this in a standalone Cargo project, add:
//!   anyhow = "1"
//!   serde_json = "1"
//!   zk-core = {{ path = "<repo>/crates/zk-core" }}
//!   zk-backends = {{ path = "<repo>/crates/zk-backends", features = ["halo2"] }}

use anyhow::Result;
use serde_json::{{Map, Value}};
use std::fs;
use zk_backends::{{Halo2Target, TargetCircuit}};
use zk_core::FieldElement;

fn main() -> Result<()> {{
    let circuit_spec_path = "{spec}";
    let witness_path = "{witness}";

    println!("Loading circuit spec from: {{}}", circuit_spec_path);
    println!("Loading witness from: {{}}", witness_path);

    let witness_content = fs::read_to_string(witness_path)
        .expect("Failed to read witness");
    let witness: Map<String, Value> =
        serde_json::from_str(&witness_content).expect("Failed to parse witness");

    let mut target = Halo2Target::new(circuit_spec_path)?;
    target.setup()?;

    let inputs = parse_witness_inputs(&witness)?;
    let public_len = target.num_public_inputs();
    let public_inputs = inputs.iter().take(public_len).cloned().collect::<Vec<_>>();

    let proof = target.prove(&inputs)?;
    let verified = target.verify(&proof, &public_inputs)?;

    if verified {{
        println!("✓ Verification PASSED – CONFIRMED BUG");
        std::process::exit(0);
    }} else {{
        println!("✗ Verification FAILED – witness rejected");
        std::process::exit(1);
    }}
}}

fn parse_witness_inputs(witness: &Map<String, Value>) -> Result<Vec<FieldElement>> {{
    let mut keys: Vec<&String> = witness.keys().collect();
    keys.sort();

    let mut inputs = Vec::new();
    for key in keys {{
        if let Some(value) = witness.get(key) {{
            flatten_json_value(value, &mut inputs)?;
        }}
    }}
    Ok(inputs)
}}

fn flatten_json_value(value: &Value, out: &mut Vec<FieldElement>) -> Result<()> {{
    match value {{
        Value::String(s) => {{
            if let Ok(fe) = FieldElement::from_hex(s) {{
                out.push(fe);
            }} else if let Ok(num) = s.parse::<u64>() {{
                out.push(FieldElement::from_u64(num));
            }} else {{
                anyhow::bail!("Unsupported witness string value: {{}}", s);
            }}
        }}
        Value::Number(n) => {{
            let num = n.as_u64().unwrap_or(0);
            out.push(FieldElement::from_u64(num));
        }}
        Value::Array(arr) => {{
            for item in arr {{
                flatten_json_value(item, out)?;
            }}
        }}
        Value::Object(obj) => {{
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            for key in keys {{
                if let Some(value) = obj.get(key) {{
                    flatten_json_value(value, out)?;
                }}
            }}
        }}
        _ => anyhow::bail!("Unsupported witness value type"),
    }}
    Ok(())
}}
"#,
        spec = circuit_spec.display(),
        witness = witness_json.display(),
    );

    std::fs::write(path, script)?;
    Ok(())
}

/// Generate Halo2 reproduction script (bash wrapper)
pub fn generate_halo2_repro_script(
    path: &Path,
    finding: &Finding,
    circuit_spec_path: Option<&Path>,
) -> anyhow::Result<String> {
    let spec_display = circuit_spec_path
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<circuit_spec>".to_string());

    let script = format!(
        r#"#!/bin/bash
# Reproduction script for Halo2 finding: {:?}
# Generated by ZkPatternFuzz evidence mode

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Reproducing Halo2 finding: {} ==="
echo ""

echo "Halo2 verification requires running Rust code."
echo ""
echo "Steps to verify:"
echo "1. Review the witness in: $SCRIPT_DIR/witness.json"
echo "2. Ensure circuit spec exists at: {}"
echo "3. Run verify_halo2.rs (it uses Halo2Target with no custom circuit glue)"
echo ""
echo "Example verification code is in: $SCRIPT_DIR/verify_halo2.rs"
echo ""
echo "If verify_halo2.rs prints 'Verification PASSED', this is a CONFIRMED bug."
"#,
        finding.attack_type,
        finding.description.chars().take(50).collect::<String>(),
        spec_display,
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
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_halo2_verify_script() {
        let temp_dir = TempDir::new().unwrap();
        let script_path = temp_dir.path().join("verify.rs");
        let spec_path = temp_dir.path().join("spec.json");
        let witness_path = temp_dir.path().join("witness.json");

        std::fs::write(&spec_path, "{}").unwrap();
        std::fs::write(&witness_path, "{}").unwrap();

        generate_halo2_verify_script(&script_path, &spec_path, &witness_path).unwrap();

        let content = std::fs::read_to_string(&script_path).unwrap();
        assert!(content.contains("Halo2Target"));
        assert!(content.contains("parse_witness_inputs"));
        assert!(!content.contains("YourCircuit"));
    }
}
