//! Proof Forgery Detection and Verification
//!
//! This module provides end-to-end underconstrained exploit detection:
//! 1. Parse R1CS from compiled circuit
//! 2. Generate valid witness via circuit execution
//! 3. Find alternative witness via Z3
//! 4. Generate proof with alternative witness
//! 5. Verify forged proof against real verifier
//!
//! If step 5 succeeds, the circuit is confirmed underconstrained.

use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::alt_witness_solver::{
    find_alternative_witness, find_multiple_alternatives, R1CSMatrices,
};
use super::r1cs_parser::R1CS;
use zk_core::FieldElement;

/// Complete proof forgery detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofForgeryResult {
    /// Whether the circuit is confirmed underconstrained
    pub is_underconstrained: bool,
    /// Whether proof forgery was successful
    pub forgery_verified: bool,
    /// Original public inputs
    pub original_public_inputs: Vec<String>,
    /// Original public outputs
    pub original_public_outputs: Vec<String>,
    /// Alternative witness found (private inputs only)
    pub alternative_private_inputs: Option<Vec<String>>,
    /// Proof verification result
    pub verification_result: Option<VerificationResult>,
    /// Statistics and metadata
    pub stats: ForgeryStats,
    /// Error message if any step failed
    pub error: Option<String>,
}

/// Verification result from snarkjs/bb
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Verifier used (snarkjs, bb, etc.)
    pub verifier: String,
    /// Whether verification passed
    pub passed: bool,
    /// Verifier output
    pub output: String,
}

/// Statistics for the forgery detection process
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForgeryStats {
    /// R1CS parsing time (ms)
    pub r1cs_parse_time_ms: u64,
    /// Witness generation time (ms)
    pub witness_gen_time_ms: u64,
    /// Z3 solving time (ms)
    pub z3_solve_time_ms: u64,
    /// Proof generation time (ms)
    pub proof_gen_time_ms: u64,
    /// Verification time (ms)
    pub verification_time_ms: u64,
    /// Total time (ms)
    pub total_time_ms: u64,
    /// Number of constraints
    pub num_constraints: usize,
    /// Number of wires
    pub num_wires: usize,
    /// Number of alternative witnesses found
    pub num_alternatives: usize,
}

/// Proof forgery detector
pub struct ProofForgeryDetector {
    /// R1CS parsed from circuit
    r1cs: R1CS,
    /// Proving key path (.zkey)
    zkey_path: Option<String>,
    /// Verification key path
    vkey_path: Option<String>,
    /// WASM path for witness generation
    wasm_path: Option<String>,
    /// Solver timeout in milliseconds
    solver_timeout_ms: u32,
}

impl ProofForgeryDetector {
    /// Create detector from R1CS file path
    pub fn from_r1cs_file(r1cs_path: &str) -> Result<Self> {
        let r1cs = R1CS::from_file(r1cs_path)?;

        let path = Path::new(r1cs_path);
        let build_dir = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("R1CS path has no parent directory: '{}'", r1cs_path))?
            .to_string_lossy()
            .to_string();

        let stem = path.file_stem().and_then(|s| s.to_str()).ok_or_else(|| {
            anyhow::anyhow!("R1CS file stem is missing or non-UTF8: '{}'", r1cs_path)
        })?;

        // Look for related artifacts
        let zkey_path = format!("{}/{}.zkey", build_dir, stem);
        let vkey_path = format!("{}/{}_vkey.json", build_dir, stem);
        let wasm_path = format!("{}/{}_js/{}.wasm", build_dir, stem, stem);

        Ok(Self {
            r1cs,
            zkey_path: if Path::new(&zkey_path).exists() {
                Some(zkey_path)
            } else {
                None
            },
            vkey_path: if Path::new(&vkey_path).exists() {
                Some(vkey_path)
            } else {
                None
            },
            wasm_path: if Path::new(&wasm_path).exists() {
                Some(wasm_path)
            } else {
                None
            },
            solver_timeout_ms: 30000,
        })
    }

    /// Create detector from R1CS struct
    pub fn from_r1cs(r1cs: R1CS, _build_dir: &str) -> Self {
        Self {
            r1cs,
            zkey_path: None,
            vkey_path: None,
            wasm_path: None,
            solver_timeout_ms: 30000,
        }
    }

    /// Set proving key path
    pub fn with_zkey(mut self, path: &str) -> Self {
        self.zkey_path = Some(path.to_string());
        self
    }

    /// Set verification key path
    pub fn with_vkey(mut self, path: &str) -> Self {
        self.vkey_path = Some(path.to_string());
        self
    }

    /// Set WASM path for witness generation
    pub fn with_wasm(mut self, path: &str) -> Self {
        self.wasm_path = Some(path.to_string());
        self
    }

    /// Set solver timeout
    pub fn with_timeout(mut self, timeout_ms: u32) -> Self {
        self.solver_timeout_ms = timeout_ms;
        self
    }

    /// Get R1CS matrices for analysis
    pub fn get_matrices(&self) -> R1CSMatrices {
        R1CSMatrices::from_r1cs(&self.r1cs)
    }

    /// Detect if circuit is underconstrained using provided witness
    pub fn detect_with_witness(&self, witness: &[FieldElement]) -> ProofForgeryResult {
        let start = std::time::Instant::now();
        let mut stats = ForgeryStats {
            num_constraints: self.r1cs.constraints.len(),
            num_wires: self.r1cs.num_wires,
            ..Default::default()
        };

        // Step 1: Find alternative witness
        let z3_start = std::time::Instant::now();
        let alt_result = find_alternative_witness(&self.r1cs, witness, self.solver_timeout_ms);
        stats.z3_solve_time_ms = z3_start.elapsed().as_millis() as u64;

        if !alt_result.found {
            stats.total_time_ms = start.elapsed().as_millis() as u64;
            return ProofForgeryResult {
                is_underconstrained: false,
                forgery_verified: false,
                original_public_inputs: self.extract_public_inputs(witness),
                original_public_outputs: self.extract_public_outputs(witness),
                alternative_private_inputs: None,
                verification_result: None,
                stats,
                error: None,
            };
        }

        stats.num_alternatives = 1;

        let alt_witness = alt_result.alternative_witness.as_ref().unwrap();
        let alt_private = self.extract_private_inputs(alt_witness);

        // Step 2: If we have proving infrastructure, generate and verify proof
        let verification_result =
            if matches!((&self.zkey_path, &self.vkey_path), (Some(_), Some(_))) {
                match self.verify_forged_proof(alt_witness) {
                    Ok(result) => Some(result),
                    Err(e) => {
                        stats.total_time_ms = start.elapsed().as_millis() as u64;
                        return ProofForgeryResult {
                            is_underconstrained: true, // Still underconstrained even if proof fails
                            forgery_verified: false,
                            original_public_inputs: self.extract_public_inputs(witness),
                            original_public_outputs: self.extract_public_outputs(witness),
                            alternative_private_inputs: Some(alt_private),
                            verification_result: None,
                            stats,
                            error: Some(format!("Proof verification failed: {}", e)),
                        };
                    }
                }
            } else {
                None
            };

        let forgery_verified: bool = verification_result
            .as_ref()
            .map(|r| r.passed)
            .unwrap_or_default();

        stats.total_time_ms = start.elapsed().as_millis() as u64;

        ProofForgeryResult {
            is_underconstrained: true,
            forgery_verified,
            original_public_inputs: self.extract_public_inputs(witness),
            original_public_outputs: self.extract_public_outputs(witness),
            alternative_private_inputs: Some(alt_private),
            verification_result,
            stats,
            error: None,
        }
    }

    /// Detect with multiple alternative witnesses
    pub fn detect_multiple(
        &self,
        witness: &[FieldElement],
        max_alternatives: usize,
    ) -> Vec<ProofForgeryResult> {
        let alternatives = find_multiple_alternatives(
            &self.r1cs,
            witness,
            max_alternatives,
            self.solver_timeout_ms,
        );

        alternatives
            .into_iter()
            .filter(|alt| alt.found)
            .filter_map(|alt| {
                alt.alternative_witness
                    .as_ref()
                    .map(|w| self.verify_single_alternative(witness, w))
            })
            .collect()
    }

    fn verify_single_alternative(
        &self,
        original: &[FieldElement],
        alternative: &[FieldElement],
    ) -> ProofForgeryResult {
        let start = std::time::Instant::now();
        let mut stats = ForgeryStats {
            num_constraints: self.r1cs.constraints.len(),
            num_wires: self.r1cs.num_wires,
            num_alternatives: 1,
            ..Default::default()
        };

        let alt_private = self.extract_private_inputs(alternative);

        let verification_result =
            if matches!((&self.zkey_path, &self.vkey_path), (Some(_), Some(_))) {
                match self.verify_forged_proof(alternative) {
                    Ok(result) => Some(result),
                    Err(err) => {
                        tracing::warn!("Forged proof verification errored: {}", err);
                        None
                    }
                }
            } else {
                None
            };

        let forgery_verified: bool = verification_result
            .as_ref()
            .map(|r| r.passed)
            .unwrap_or_default();

        stats.total_time_ms = start.elapsed().as_millis() as u64;

        ProofForgeryResult {
            is_underconstrained: true,
            forgery_verified,
            original_public_inputs: self.extract_public_inputs(original),
            original_public_outputs: self.extract_public_outputs(original),
            alternative_private_inputs: Some(alt_private),
            verification_result,
            stats,
            error: None,
        }
    }

    /// Generate and verify proof using snarkjs
    fn verify_forged_proof(&self, witness: &[FieldElement]) -> Result<VerificationResult> {
        let zkey = self
            .zkey_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No proving key available"))?;
        let vkey = self
            .vkey_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No verification key available"))?;

        // Create temp directory for artifacts
        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir.path();

        let witness_path = temp_path.join("witness.json");
        let proof_path = temp_path.join("proof.json");
        let public_path = temp_path.join("public.json");
        let wtns_path = temp_path.join("witness.wtns");
        let witness_path_str = witness_path.to_string_lossy().to_string();
        let proof_path_str = proof_path.to_string_lossy().to_string();
        let public_path_str = public_path.to_string_lossy().to_string();
        let wtns_path_str = wtns_path.to_string_lossy().to_string();

        // Write witness as JSON array
        let witness_values: Vec<String> = witness.iter().map(|fe| fe.to_decimal_string()).collect();
        let witness_json = serde_json::to_string(&witness_values)?;
        std::fs::write(&witness_path, &witness_json)?;

        // Strategy: prefer importing the full Z3 witness directly.
        // WASM wtns calculate would recompute the witness from inputs,
        // erasing the Z3-found degrees of freedom that prove underconstraint.
        let mut import_cmd = Command::new("npx");
        import_cmd.args([
            "snarkjs",
            "wtns",
            "import",
            &witness_path_str,
            &wtns_path_str,
        ]);
        let import_output = Self::run_command_with_timeout(
            import_cmd,
            Duration::from_millis(self.solver_timeout_ms as u64),
            "snarkjs wtns import",
        )
        .context("Failed to run snarkjs wtns import")?;
        if !import_output.status.success() {
            let stderr = String::from_utf8_lossy(&import_output.stderr);
            anyhow::bail!("wtns import failed: {}", stderr);
        }

        // Generate proof
        let mut prove_cmd = Command::new("npx");
        prove_cmd.args([
            "snarkjs",
            "groth16",
            "prove",
            zkey,
            &wtns_path_str,
            &proof_path_str,
            &public_path_str,
        ]);
        let output = Self::run_command_with_timeout(
            prove_cmd,
            Duration::from_millis(self.solver_timeout_ms as u64),
            "snarkjs groth16 prove",
        )
        .context("Failed to generate proof")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Ok(VerificationResult {
                verifier: "snarkjs".to_string(),
                passed: false,
                output: format!("Proof generation failed: {}", stderr),
            });
        }

        // Verify proof
        let mut verify_cmd = Command::new("npx");
        verify_cmd.args([
            "snarkjs",
            "groth16",
            "verify",
            vkey,
            &public_path_str,
            &proof_path_str,
        ]);
        let output = Self::run_command_with_timeout(
            verify_cmd,
            Duration::from_millis(self.solver_timeout_ms as u64),
            "snarkjs groth16 verify",
        )
        .context("Failed to verify proof")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let passed = output.status.success() && stdout.contains("OK");

        Ok(VerificationResult {
            verifier: "snarkjs".to_string(),
            passed,
            output: stdout.to_string(),
        })
    }

    fn run_command_with_timeout(
        mut command: Command,
        timeout: Duration,
        label: &str,
    ) -> Result<std::process::Output> {
        let poll_interval = Duration::from_millis(50);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .with_context(|| format!("Failed to spawn {}", label))?;
        let deadline = Instant::now() + timeout;

        loop {
            match child
                .try_wait()
                .with_context(|| format!("Failed while waiting for {}", label))?
            {
                Some(_status) => {
                    return child
                        .wait_with_output()
                        .with_context(|| format!("Failed to collect output for {}", label));
                }
                None => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let output = child.wait_with_output().ok();
                        let stderr_preview = output
                            .as_ref()
                            .map(|o| {
                                String::from_utf8_lossy(&o.stderr)
                                    .chars()
                                    .take(200)
                                    .collect::<String>()
                            })
                            .unwrap_or_default();
                        anyhow::bail!(
                            "{} timed out after {} ms{}",
                            label,
                            timeout.as_millis(),
                            if stderr_preview.is_empty() {
                                "".to_string()
                            } else {
                                format!(" (stderr: {})", stderr_preview)
                            }
                        );
                    }
                    std::thread::sleep(poll_interval);
                }
            }
        }
    }

    fn extract_public_inputs(&self, witness: &[FieldElement]) -> Vec<String> {
        let start = 1 + self.r1cs.num_public_outputs;
        let end = start + self.r1cs.num_public_inputs;
        witness[start.min(witness.len())..end.min(witness.len())]
            .iter()
            .map(|fe| fe.to_decimal_string())
            .collect()
    }

    fn extract_public_outputs(&self, witness: &[FieldElement]) -> Vec<String> {
        let start = 1;
        let end = 1 + self.r1cs.num_public_outputs;
        witness[start.min(witness.len())..end.min(witness.len())]
            .iter()
            .map(|fe| fe.to_decimal_string())
            .collect()
    }

    fn extract_private_inputs(&self, witness: &[FieldElement]) -> Vec<String> {
        let start = 1 + self.r1cs.num_public_outputs + self.r1cs.num_public_inputs;
        let end = start + self.r1cs.num_private_inputs;
        witness[start.min(witness.len())..end.min(witness.len())]
            .iter()
            .map(|fe| fe.to_decimal_string())
            .collect()
    }
}

/// Quick check if a circuit is likely underconstrained
pub fn quick_underconstrained_check(r1cs: &R1CS) -> bool {
    // Heuristic: more signals than constraints often indicates underconstraint
    let total_signals = r1cs.num_wires;
    let constraints = r1cs.constraints.len();

    if constraints == 0 {
        return true;
    }

    // Very rough heuristic
    let ratio = total_signals as f64 / constraints as f64;
    ratio > 2.0
}

#[cfg(test)]
#[path = "proof_forgery_tests.rs"]
mod tests;
