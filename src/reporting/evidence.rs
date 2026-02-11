//! Proof-Level Evidence Bundles (Phase 5)
//!
//! This module generates verifier-checked evidence bundles for confirmed findings.
//! Each bundle contains everything needed to independently reproduce and verify
//! a vulnerability finding.
//!
//! # Evidence Bundle Contents
//!
//! For Circom circuits:
//! - `witness.json` - Circom input format
//! - `witness.wtns` - Binary witness file
//! - `proof.json` - Groth16 proof
//! - `public.json` - Public inputs
//! - `repro.sh` - Reproduction script
//!
//! # Verification Flow
//!
//! ```text
//! Finding → Generate Witness → Compute Proof → Verify Proof
//!                                                   │
//!                                       ┌───────────┴───────────┐
//!                                       │                       │
//!                                   PASSES                   FAILS
//!                                       │                       │
//!                             CONFIRMED BUG            Not a real bug
//!                        (soundness violation)        (false positive)
//! ```

use crate::config::{Framework, FuzzConfig};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zk_core::{FieldElement, Finding};

/// Verification result from running proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationResult {
    /// Proof verification passed - this confirms a soundness bug
    Passed,
    /// Proof verification failed - not a real bug
    Failed(String),
    /// Could not run verification (missing tools, etc.)
    Skipped(String),
    /// Verification in progress
    Pending,
}

impl VerificationResult {
    pub fn is_confirmed(&self) -> bool {
        matches!(self, VerificationResult::Passed)
    }
}

/// Backend identity for provenance tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendIdentity {
    /// Framework name (circom, noir, halo2, cairo)
    pub framework: String,
    /// Backend version (e.g., "circom 2.1.8", "snarkjs 0.7.3")
    pub version: String,
    /// Hash of the circuit source/compiled artifacts
    pub circuit_hash: String,
    /// Whether this is a mock/fallback backend
    pub is_mock: bool,
}

impl BackendIdentity {
    pub fn mock() -> Self {
        Self {
            framework: "mock".to_string(),
            version: "synthetic".to_string(),
            circuit_hash: "0x0".to_string(),
            is_mock: true,
        }
    }

    pub fn from_framework(framework: Framework, is_mock: bool) -> Self {
        Self {
            framework: format!("{:?}", framework).to_lowercase(),
            version: "unknown".to_string(),
            circuit_hash: "unknown".to_string(),
            is_mock,
        }
    }
}

/// Complete evidence bundle for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// The original finding
    pub finding: Finding,
    /// Backend identity
    pub backend: BackendIdentity,
    /// Path to witness.json
    pub witness_json: Option<PathBuf>,
    /// Path to witness.wtns (if generated)
    pub witness_wtns: Option<PathBuf>,
    /// Path to proof.json (if generated)
    pub proof_json: Option<PathBuf>,
    /// Path to public.json (if generated)
    pub public_json: Option<PathBuf>,
    /// Verification result
    pub verification_result: VerificationResult,
    /// Reproduction command (copy-paste ready)
    pub repro_command: String,
    /// Path to reproduction script
    pub repro_script: Option<PathBuf>,
    /// Invariant name (if this is an invariant violation)
    pub invariant_name: Option<String>,
    /// Invariant relation (if this is an invariant violation)
    pub invariant_relation: Option<String>,
    /// Human-readable impact description
    pub impact_description: String,
    /// Timestamp of evidence generation
    pub generated_at: String,
}

impl EvidenceBundle {
    /// Create a new evidence bundle from a finding
    pub fn new(finding: Finding, backend: BackendIdentity) -> Self {
        Self {
            finding,
            backend,
            witness_json: None,
            witness_wtns: None,
            proof_json: None,
            public_json: None,
            verification_result: VerificationResult::Pending,
            repro_command: String::new(),
            repro_script: None,
            invariant_name: None,
            invariant_relation: None,
            impact_description: String::new(),
            generated_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Check if this bundle has complete evidence
    pub fn has_complete_evidence(&self) -> bool {
        self.witness_json.is_some() && self.verification_result.is_confirmed()
    }

    /// Check if this finding is confirmed (proof verification passed)
    pub fn is_confirmed(&self) -> bool {
        self.verification_result.is_confirmed()
    }
}

/// Evidence generator for creating proof-level bundles
pub struct EvidenceGenerator {
    /// Output directory for evidence files
    output_dir: PathBuf,
    /// Campaign configuration
    config: FuzzConfig,
    /// Path to snarkjs CLI (for Circom)
    snarkjs_path: Option<PathBuf>,
    /// Path to ptau file (for Circom setup) - reserved for future trusted setup
    #[allow(dead_code)]
    ptau_path: Option<PathBuf>,
    /// Path to circuit zkey file
    zkey_path: Option<PathBuf>,
    /// Path to verification key
    vkey_path: Option<PathBuf>,
    /// Path to compiled circuit WASM
    wasm_path: Option<PathBuf>,
}

impl EvidenceGenerator {
    /// Create a new evidence generator
    pub fn new(config: FuzzConfig, output_dir: PathBuf) -> Self {
        let additional = &config.campaign.parameters.additional;

        let snarkjs_path = additional
            .get("circom_snarkjs_path")
            .and_then(|v| v.as_str())
            .map(PathBuf::from);

        let ptau_path = additional
            .get("circom_ptau_path")
            .and_then(|v| v.as_str())
            .map(PathBuf::from);

        let zkey_path = additional
            .get("circom_zkey_path")
            .and_then(|v| v.as_str())
            .map(PathBuf::from);

        let vkey_path = additional
            .get("circom_vkey_path")
            .and_then(|v| v.as_str())
            .map(PathBuf::from);

        let wasm_path = additional
            .get("circom_wasm_path")
            .and_then(|v| v.as_str())
            .map(PathBuf::from);

        Self {
            output_dir,
            config,
            snarkjs_path,
            ptau_path,
            zkey_path,
            vkey_path,
            wasm_path,
        }
    }

    /// Set the zkey path (for Circom proving)
    pub fn with_zkey(mut self, path: PathBuf) -> Self {
        self.zkey_path = Some(path);
        self
    }

    /// Set the verification key path
    pub fn with_vkey(mut self, path: PathBuf) -> Self {
        self.vkey_path = Some(path);
        self
    }

    /// Set the circuit WASM path
    pub fn with_wasm(mut self, path: PathBuf) -> Self {
        self.wasm_path = Some(path);
        self
    }

    /// Resolve the snarkjs command to use
    fn resolve_snarkjs_cmd(&self) -> String {
        if let Some(ref path) = self.snarkjs_path {
            if path.exists() {
                return path.display().to_string();
            }
        }
        // Default to npx snarkjs which handles both global and local installs
        "npx snarkjs".to_string()
    }

    /// Auto-discover circuit artifacts from build directory
    fn discover_circuit_artifacts(&self) -> (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>) {
        let circuit_path = &self.config.campaign.target.circuit_path;
        let main_component = &self.config.campaign.target.main_component;
        
        // Try to find build directory
        let build_dir = self.config.campaign.parameters.additional
            .get("build_dir")
            .or_else(|| self.config.campaign.parameters.additional.get("circom_build_dir"))
            .and_then(|v| v.as_str())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                // Default: look for build dir next to circuit
                circuit_path.parent()
                    .map(|p| p.join("build"))
                    .unwrap_or_else(|| PathBuf::from("./build"))
            });

        let component_lower = main_component.to_lowercase();
        
        // Discover WASM
        let wasm = self.wasm_path.clone().or_else(|| {
            let wasm_dir = build_dir.join(format!("{}_js", component_lower));
            let wasm_file = wasm_dir.join(format!("{}.wasm", component_lower));
            if wasm_file.exists() {
                Some(wasm_file)
            } else {
                // Try alternative naming
                let alt_wasm = build_dir.join(format!("{}.wasm", component_lower));
                if alt_wasm.exists() { Some(alt_wasm) } else { None }
            }
        });

        // Discover zkey
        let zkey = self.zkey_path.clone().or_else(|| {
            let zkey_file = build_dir.join(format!("{}.zkey", component_lower));
            if zkey_file.exists() { Some(zkey_file) } else { None }
        });

        // Discover vkey
        let vkey = self.vkey_path.clone().or_else(|| {
            let vkey_file = build_dir.join("verification_key.json");
            if vkey_file.exists() { 
                Some(vkey_file) 
            } else {
                let alt_vkey = build_dir.join(format!("{}_vkey.json", component_lower));
                if alt_vkey.exists() { Some(alt_vkey) } else { None }
            }
        });

        (wasm, zkey, vkey)
    }

    /// Generate evidence bundle for a finding
    pub fn generate_bundle(
        &self,
        finding: &Finding,
        backend: BackendIdentity,
    ) -> anyhow::Result<EvidenceBundle> {
        let mut bundle = EvidenceBundle::new(finding.clone(), backend);

        // Create finding-specific directory
        let finding_id = self.generate_finding_id(finding);
        let finding_dir = self.output_dir.join(&finding_id);
        std::fs::create_dir_all(&finding_dir)?;

        // Generate witness.json
        let witness_json_path = finding_dir.join("witness.json");
        self.write_witness_json(&witness_json_path, &finding.poc.witness_a)?;
        bundle.witness_json = Some(witness_json_path);

        // Generate reproduction script
        let repro_script_path = finding_dir.join("repro.sh");
        let repro_command = self.generate_repro_script(&repro_script_path, finding)?;
        bundle.repro_script = Some(repro_script_path);
        bundle.repro_command = repro_command;

        // Generate impact description
        bundle.impact_description = self.generate_impact_description(finding);

        // Try to generate proof based on framework
        match self.config.campaign.target.framework {
            Framework::Circom => {
                match self.generate_circom_proof(&finding_dir, finding) {
                    Ok((proof_json, public_json, verification)) => {
                        bundle.proof_json = Some(proof_json);
                        bundle.public_json = Some(public_json);
                        bundle.verification_result = verification;
                    }
                    Err(e) => {
                        bundle.verification_result = VerificationResult::Skipped(e.to_string());
                    }
                }
            }
            Framework::Noir => {
                let project_path = self.config.campaign.target.circuit_path.parent()
                    .unwrap_or(Path::new("."));
                match super::evidence_noir::generate_noir_proof(&finding_dir, finding, project_path) {
                    Ok((proof_path, verification)) => {
                        bundle.proof_json = Some(proof_path);
                        bundle.verification_result = verification;
                    }
                    Err(e) => {
                        bundle.verification_result = VerificationResult::Skipped(e.to_string());
                    }
                }
            }
            Framework::Halo2 => {
                let circuit_spec = self.config.campaign.parameters.additional
                    .get("halo2_circuit_spec")
                    .and_then(|v| v.as_str())
                    .map(std::path::PathBuf::from);
                match super::evidence_halo2::generate_halo2_proof(
                    &finding_dir, 
                    finding, 
                    circuit_spec.as_deref()
                ) {
                    Ok((proof_path, verification)) => {
                        bundle.proof_json = Some(proof_path);
                        bundle.verification_result = verification;
                    }
                    Err(e) => {
                        bundle.verification_result = VerificationResult::Skipped(e.to_string());
                    }
                }
            }
            Framework::Cairo => {
                let program_path = &self.config.campaign.target.circuit_path;
                match super::evidence_cairo::generate_cairo_proof(&finding_dir, finding, program_path) {
                    Ok((proof_path, verification)) => {
                        bundle.proof_json = Some(proof_path);
                        bundle.verification_result = verification;
                    }
                    Err(e) => {
                        bundle.verification_result = VerificationResult::Skipped(e.to_string());
                    }
                }
            }
            Framework::Mock => {
                bundle.verification_result = VerificationResult::Skipped(
                    "Mock framework does not support proof generation".to_string()
                );
            }
        }

        // Write bundle metadata
        let bundle_path = finding_dir.join("bundle.json");
        std::fs::write(&bundle_path, serde_json::to_string_pretty(&bundle)?)?;

        Ok(bundle)
    }

    /// Generate a unique ID for a finding
    fn generate_finding_id(&self, finding: &Finding) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}", finding.attack_type));
        hasher.update(&finding.description);
        for fe in &finding.poc.witness_a {
            hasher.update(fe.0);
        }

        let hash = hasher.finalize();
        format!("finding_{}", hex::encode(&hash[..8]))
    }

    /// Write witness inputs to JSON format
    fn write_witness_json(&self, path: &Path, inputs: &[FieldElement]) -> anyhow::Result<()> {
        let mut witness_obj = serde_json::Map::new();

        for (i, input_spec) in self.config.inputs.iter().enumerate() {
            if let Some(fe) = inputs.get(i) {
                // Convert to decimal string (Circom format)
                let decimal = fe.to_decimal_string();
                witness_obj.insert(input_spec.name.clone(), serde_json::Value::String(decimal));
            }
        }

        let json = serde_json::Value::Object(witness_obj);
        std::fs::write(path, serde_json::to_string_pretty(&json)?)?;
        Ok(())
    }

    /// Generate reproduction script
    fn generate_repro_script(&self, path: &Path, finding: &Finding) -> anyhow::Result<String> {
        let circuit_path = self.config.campaign.target.circuit_path.display();
        let main_component = &self.config.campaign.target.main_component;

        let script = match self.config.campaign.target.framework {
            Framework::Circom => {
                format!(
                    r#"#!/bin/bash
# Reproduction script for finding: {:?}
# Generated by ZkPatternFuzz evidence mode
set -e

CIRCUIT_PATH="{}"
MAIN_COMPONENT="{}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

echo "=== Reproducing finding: {} ==="
echo ""

# Step 1: Compile circuit
mkdir -p "$BUILD_DIR"
circom "$CIRCUIT_PATH" --r1cs --wasm --sym -o "$BUILD_DIR"

# Step 2: Generate witness
cd "$BUILD_DIR/{}_js"
node generate_witness.js {}.wasm "$SCRIPT_DIR/witness.json" witness.wtns
echo "✓ Witness generated"

# Step 3: Generate proof (if zkey available)
if [ -f "$BUILD_DIR/{}.zkey" ]; then
    snarkjs groth16 prove "$BUILD_DIR/{}.zkey" witness.wtns proof.json public.json
    echo "✓ Proof generated"
    
    # Step 4: Verify proof
    snarkjs groth16 verify "$BUILD_DIR/verification_key.json" public.json proof.json
    echo ""
    echo "========================================"
    echo "If verification SUCCEEDS, this is a CONFIRMED soundness bug."
    echo "The circuit accepts an invalid witness."
    echo "========================================"
else
    echo "⚠ No zkey found - skipping proof generation"
    echo "To generate proof, run: snarkjs groth16 setup ... "
fi
"#,
                    finding.attack_type,
                    circuit_path,
                    main_component,
                    finding.description.chars().take(50).collect::<String>(),
                    main_component.to_lowercase(),
                    main_component.to_lowercase(),
                    main_component.to_lowercase(),
                    main_component.to_lowercase(),
                )
            }
            _ => {
                format!(
                    r#"#!/bin/bash
# Reproduction script for finding: {:?}
# Generated by ZkPatternFuzz evidence mode

echo "Manual reproduction required for {:?} framework"
echo ""
echo "Witness inputs are in witness.json"
echo "Finding description: {}"
"#,
                    finding.attack_type, self.config.campaign.target.framework, finding.description,
                )
            }
        };

        std::fs::write(path, &script)?;

        // Make executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(path, perms)?;
        }

        // Return the key command
        Ok(format!(
            "cd {} && ./repro.sh",
            path.parent().unwrap().display()
        ))
    }

    /// Generate Circom proof and verify it
    /// 
    /// This shells out to snarkjs to:
    /// 1. Calculate witness: snarkjs wtns calculate circuit.wasm witness.json witness.wtns
    /// 2. Generate proof: snarkjs groth16 prove circuit.zkey witness.wtns proof.json public.json
    /// 3. Verify proof: snarkjs groth16 verify vkey.json public.json proof.json
    fn generate_circom_proof(
        &self,
        finding_dir: &Path,
        _finding: &Finding,
    ) -> anyhow::Result<(PathBuf, PathBuf, VerificationResult)> {
        use std::process::Command;
        use std::time::Duration;

        let timeout = Duration::from_secs(120); // 2 minute timeout per command
        let proof_json = finding_dir.join("proof.json");
        let public_json = finding_dir.join("public.json");
        let witness_wtns = finding_dir.join("witness.wtns");
        let witness_json = finding_dir.join("witness.json");

        if !witness_json.exists() {
            return Err(anyhow::anyhow!("witness.json not found"));
        }

        // Auto-discover artifacts if not explicitly set
        let (wasm_path, zkey_path, vkey_path) = self.discover_circuit_artifacts();

        let wasm = match wasm_path {
            Some(p) if p.exists() => p,
            _ => {
                return Ok((
                    proof_json,
                    public_json,
                    VerificationResult::Skipped("circuit WASM not found - compile circuit first".to_string()),
                ));
            }
        };

        let zkey = match zkey_path {
            Some(p) if p.exists() => p,
            _ => {
                return Ok((
                    proof_json,
                    public_json,
                    VerificationResult::Skipped("zkey not found - run trusted setup first".to_string()),
                ));
            }
        };

        let vkey = match vkey_path {
            Some(p) if p.exists() => p,
            _ => {
                return Ok((
                    proof_json,
                    public_json,
                    VerificationResult::Skipped("verification key not found".to_string()),
                ));
            }
        };

        let snarkjs_cmd = self.resolve_snarkjs_cmd();
        tracing::info!("Generating proof with snarkjs for finding in {:?}", finding_dir);

        // Step 1: Calculate witness (wasm -> wtns)
        // snarkjs wtns calculate circuit.wasm witness.json witness.wtns
        let wtns_result = if snarkjs_cmd.starts_with("npx") {
            super::command_timeout::run_with_timeout(
                Command::new("npx")
                    .args(["--yes", "snarkjs", "wtns", "calculate"])  // --yes prevents prompts
                    .arg(&wasm)
                    .arg(&witness_json)
                    .arg(&witness_wtns)
                    .current_dir(finding_dir),
                timeout,
            )
        } else {
            super::command_timeout::run_with_timeout(
                Command::new(&snarkjs_cmd)
                    .args(["wtns", "calculate"])
                    .arg(&wasm)
                    .arg(&witness_json)
                    .arg(&witness_wtns)
                    .current_dir(finding_dir),
                timeout,
            )
        };

        match wtns_result {
            Ok(output) if !output.status.success() => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::warn!("Witness calculation failed: {}", stderr);
                return Ok((
                    proof_json,
                    public_json,
                    VerificationResult::Failed(format!("witness calculation failed: {}", stderr.chars().take(200).collect::<String>())),
                ));
            }
            Err(e) => {
                return Ok((
                    proof_json,
                    public_json,
                    VerificationResult::Skipped(format!("snarkjs not available: {}", e)),
                ));
            }
            _ => {
                tracing::debug!("Witness calculated successfully");
            }
        }

        // Step 2: Generate proof
        // snarkjs groth16 prove circuit.zkey witness.wtns proof.json public.json
        let prove_result = if snarkjs_cmd.starts_with("npx") {
            super::command_timeout::run_with_timeout(
                Command::new("npx")
                    .args(["--yes", "snarkjs", "groth16", "prove"])
                    .arg(&zkey)
                    .arg(&witness_wtns)
                    .arg(&proof_json)
                    .arg(&public_json)
                    .current_dir(finding_dir),
                timeout,
            )
        } else {
            super::command_timeout::run_with_timeout(
                Command::new(&snarkjs_cmd)
                    .args(["groth16", "prove"])
                    .arg(&zkey)
                    .arg(&witness_wtns)
                    .arg(&proof_json)
                    .arg(&public_json)
                    .current_dir(finding_dir),
                timeout,
            )
        };

        match prove_result {
            Ok(output) if !output.status.success() => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::warn!("Proof generation failed: {}", stderr);
                return Ok((
                    proof_json,
                    public_json,
                    VerificationResult::Failed(format!("proof generation failed: {}", stderr.chars().take(200).collect::<String>())),
                ));
            }
            Err(e) => {
                return Ok((
                    proof_json,
                    public_json,
                    VerificationResult::Skipped(format!("snarkjs prove failed: {}", e)),
                ));
            }
            _ => {
                tracing::debug!("Proof generated successfully");
            }
        }

        // Step 3: Verify proof
        // snarkjs groth16 verify vkey.json public.json proof.json
        let verify_result = if snarkjs_cmd.starts_with("npx") {
            super::command_timeout::run_with_timeout(
                Command::new("npx")
                    .args(["--yes", "snarkjs", "groth16", "verify"])
                    .arg(&vkey)
                    .arg(&public_json)
                    .arg(&proof_json)
                    .current_dir(finding_dir),
                timeout,
            )
        } else {
            super::command_timeout::run_with_timeout(
                Command::new(&snarkjs_cmd)
                    .args(["groth16", "verify"])
                    .arg(&vkey)
                    .arg(&public_json)
                    .arg(&proof_json)
                    .current_dir(finding_dir),
                timeout,
            )
        };

        match verify_result {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                
                if output.status.success() {
                    // Check if snarkjs output indicates success
                    // snarkjs outputs "OK!" or similar on successful verification
                    let combined = format!("{}{}", stdout, stderr).to_lowercase();
                    if combined.contains("ok") || combined.contains("valid") || combined.contains("true") {
                        tracing::info!("✓ PROOF VERIFIED - CONFIRMED soundness bug!");
                        Ok((proof_json, public_json, VerificationResult::Passed))
                    } else {
                        // Exit code 0 but no explicit OK - treat as passed
                        tracing::info!("✓ Proof verification succeeded (exit 0)");
                        Ok((proof_json, public_json, VerificationResult::Passed))
                    }
                } else {
                    // Verification failed - this means the witness is NOT a valid proof
                    // This is actually the expected behavior for a non-buggy circuit
                    let reason = if stderr.is_empty() { stdout.to_string() } else { stderr.to_string() };
                    tracing::info!("✗ Proof verification failed - not a real bug");
                    Ok((
                        proof_json,
                        public_json,
                        VerificationResult::Failed(format!("proof verification failed: {}", reason.chars().take(200).collect::<String>())),
                    ))
                }
            }
            Err(e) => {
                Ok((
                    proof_json,
                    public_json,
                    VerificationResult::Skipped(format!("snarkjs verify failed: {}", e)),
                ))
            }
        }
    }

    /// Generate impact description for a finding
    fn generate_impact_description(&self, finding: &Finding) -> String {
        match finding.attack_type {
            zk_core::AttackType::Soundness => {
                "CRITICAL: Soundness violation detected. An attacker can generate valid proofs \
                for false statements, completely breaking the security of the proving system."
                    .to_string()
            }
            zk_core::AttackType::Underconstrained => {
                "HIGH: Underconstrained circuit detected. Multiple different private inputs \
                produce the same public output, potentially leaking private information or \
                allowing unauthorized actions."
                    .to_string()
            }
            zk_core::AttackType::ArithmeticOverflow => {
                "MEDIUM: Arithmetic overflow detected. Field arithmetic may wrap around \
                unexpectedly, potentially allowing attackers to bypass range checks."
                    .to_string()
            }
            _ => format!(
                "Finding of type {:?} detected. Review witness for details.",
                finding.attack_type
            ),
        }
    }

    /// Generate evidence bundles for all findings
    pub fn generate_all_bundles(
        &self,
        findings: &[Finding],
        backend: BackendIdentity,
    ) -> Vec<EvidenceBundle> {
        findings
            .iter()
            .filter_map(|f| self.generate_bundle(f, backend.clone()).ok())
            .collect()
    }
}

/// Format evidence bundle as markdown report section
pub fn format_bundle_markdown(bundle: &EvidenceBundle) -> String {
    let mut md = String::new();

    md.push_str(&format!("## Finding: {:?}\n\n", bundle.finding.attack_type));
    md.push_str(&format!("**Severity**: {:?}\n\n", bundle.finding.severity));
    md.push_str(&format!(
        "**Description**: {}\n\n",
        bundle.finding.description
    ));

    if let Some(ref name) = bundle.invariant_name {
        md.push_str(&format!("**Invariant Violated**: {}\n\n", name));
    }
    if let Some(ref relation) = bundle.invariant_relation {
        md.push_str(&format!("**Relation**: `{}`\n\n", relation));
    }

    md.push_str("### Witness Inputs\n\n```json\n");
    for (i, fe) in bundle.finding.poc.witness_a.iter().enumerate() {
        md.push_str(&format!("  input[{}]: {}\n", i, fe.to_hex()));
    }
    md.push_str("```\n\n");

    md.push_str("### Verification Result\n\n");
    match &bundle.verification_result {
        VerificationResult::Passed => {
            md.push_str(
                "✅ **CONFIRMED**: Proof verification PASSED - this is a real soundness bug.\n\n",
            );
        }
        VerificationResult::Failed(reason) => {
            md.push_str(&format!(
                "❌ **NOT CONFIRMED**: Proof verification failed - {}\n\n",
                reason
            ));
        }
        VerificationResult::Skipped(reason) => {
            md.push_str(&format!("⏭ **SKIPPED**: {}\n\n", reason));
        }
        VerificationResult::Pending => {
            md.push_str("⏳ **PENDING**: Verification not yet run.\n\n");
        }
    }

    md.push_str("### Reproduction Command\n\n```bash\n");
    md.push_str(&bundle.repro_command);
    md.push_str("\n```\n\n");

    md.push_str("### Impact\n\n");
    md.push_str(&bundle.impact_description);
    md.push_str("\n\n");

    md.push_str("### Backend\n\n");
    md.push_str(&format!("- Framework: {}\n", bundle.backend.framework));
    md.push_str(&format!("- Version: {}\n", bundle.backend.version));
    md.push_str(&format!(
        "- Circuit Hash: {}\n",
        bundle.backend.circuit_hash
    ));
    if bundle.backend.is_mock {
        md.push_str("- ⚠️ **WARNING**: This is a MOCK backend - findings are SYNTHETIC\n");
    }
    md.push_str("\n---\n\n");

    md
}
