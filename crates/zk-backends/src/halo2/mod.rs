//! Halo2 circuit target implementation
//!
//! Provides integration with the Halo2 proving system:
//! - Direct Rust API integration (circuits defined in Rust)
//! - Support for PSE's halo2 fork (halo2_proofs)
//! - PLONK-based constraint system

use crate::TargetCircuit;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use zk_constraints::{
    ConstraintChecker, ConstraintParser, ParsedConstraintSet, UnknownLookupPolicy,
};
use zk_core::FieldElement;
use zk_core::Framework;

fn halo2_external_command_timeout() -> std::time::Duration {
    crate::util::timeout_from_env("ZK_FUZZER_HALO2_EXTERNAL_TIMEOUT_SECS", 120)
}

fn halo2_cargo_toolchain_from_env() -> Option<String> {
    for key in ["ZK_FUZZER_HALO2_CARGO_TOOLCHAIN", "RUSTUP_TOOLCHAIN"] {
        if let Ok(value) = std::env::var(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn halo2_lockfile_requires_nightly(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("lock file version 4 requires")
        || lower.contains("requires `-znext-lockfile-bump`")
        || lower.contains("requires -znext-lockfile-bump")
}

/// Halo2 circuit target
///
/// Unlike Circom and Noir which use external CLIs, Halo2 circuits are Rust code
/// that must be compiled and linked. This target supports:
/// 1. Compiled Rust library circuits (via dynamic loading)
/// 2. Standalone circuit binaries (via subprocess execution)
pub struct Halo2Target {
    /// Path to the circuit (can be a Rust project, compiled binary, or circuit spec)
    circuit_path: PathBuf,
    /// Circuit name
    name: String,
    /// Compiled metadata
    metadata: Option<Halo2Metadata>,
    /// Build directory
    build_dir: PathBuf,
    /// Circuit configuration
    config: Halo2Config,
    /// Optional cargo toolchain suffix (e.g. nightly).
    cargo_toolchain: Option<String>,
    /// Cached PLONK constraints and lookup tables (if available)
    plonk_constraints: OnceLock<ParsedConstraintSet>,
}

/// Halo2 circuit metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Halo2Metadata {
    /// Circuit name
    pub name: String,
    /// Number of rows (degree = 2^k)
    pub k: u32,
    /// Number of advice columns
    pub num_advice_columns: usize,
    /// Number of fixed columns
    pub num_fixed_columns: usize,
    /// Number of instance columns (public inputs)
    pub num_instance_columns: usize,
    /// Estimated number of constraints
    pub num_constraints: usize,
    /// Number of private inputs
    pub num_private_inputs: usize,
    /// Number of public inputs
    pub num_public_inputs: usize,
    /// Number of lookups
    pub num_lookups: usize,
}

/// Halo2 circuit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Halo2Config {
    /// Degree of the circuit (2^k rows)
    pub k: u32,
    /// Field to use
    pub field: Halo2Field,
    /// Whether to use KZG or IPA commitment
    pub commitment: CommitmentScheme,
}

impl Default for Halo2Config {
    fn default() -> Self {
        Self {
            k: 10,
            field: Halo2Field::Bn254,
            commitment: CommitmentScheme::Kzg,
        }
    }
}

/// Supported field types for Halo2
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Halo2Field {
    /// BN254 (used in zkEVM, PSE circuits)
    Bn254,
    /// Pasta curves (Pallas/Vesta, used in Zcash)
    Pasta,
    /// BLS12-381
    Bls12_381,
}

/// Commitment scheme
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CommitmentScheme {
    /// Kate-Zaverucha-Goldberg (trusted setup)
    Kzg,
    /// Inner Product Argument (no trusted setup)
    Ipa,
}

impl Halo2Target {
    /// Get the field name used by this circuit configuration
    pub fn field_name(&self) -> &str {
        match self.config.field {
            Halo2Field::Bn254 => "bn254",
            Halo2Field::Pasta => "pasta",
            Halo2Field::Bls12_381 => "bls12-381",
        }
    }

    /// Create a new Halo2 target from a circuit path
    pub fn new(circuit_path: &str) -> Result<Self> {
        let path = PathBuf::from(circuit_path);
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid Halo2 circuit path '{}'", path.display()))?
            .to_string();

        let build_dir = path
            .parent()
            .ok_or_else(|| {
                anyhow::anyhow!("Halo2 circuit path has no parent: '{}'", path.display())
            })?
            .join("target")
            .join("halo2_build");

        Ok(Self {
            circuit_path: path,
            name,
            metadata: None,
            build_dir,
            config: Halo2Config::default(),
            cargo_toolchain: halo2_cargo_toolchain_from_env(),
            plonk_constraints: OnceLock::new(),
        })
    }

    /// Override the build directory for compiled artifacts.
    pub fn with_build_dir(mut self, build_dir: PathBuf) -> Self {
        self.build_dir = build_dir;
        self
    }

    /// Create with custom configuration
    pub fn with_config(mut self, config: Halo2Config) -> Self {
        self.config = config;
        self
    }

    fn cargo_command_with_toolchain(&self, toolchain: Option<&str>) -> Command {
        let mut command = Command::new("cargo");
        if let Some(toolchain) = toolchain {
            let trimmed = toolchain.trim();
            if !trimmed.is_empty() {
                command.arg(format!("+{trimmed}"));
            }
        }
        command.env("CARGO_TARGET_DIR", &self.build_dir);
        command
    }

    fn cargo_command(&self) -> Command {
        self.cargo_command_with_toolchain(self.cargo_toolchain.as_deref())
    }

    fn run_cargo_build(
        &self,
        project_dir: &Path,
        toolchain: Option<&str>,
    ) -> Result<std::process::Output> {
        let mut cmd = self.cargo_command_with_toolchain(toolchain);
        cmd.args(["build", "--release"]).current_dir(project_dir);
        crate::util::run_with_timeout(&mut cmd, halo2_external_command_timeout())
            .context("Failed to build Halo2 circuit")
    }

    /// Load and configure the circuit
    pub fn setup(&mut self) -> Result<()> {
        tracing::info!("Setting up Halo2 circuit: {:?}", self.circuit_path);

        std::fs::create_dir_all(&self.build_dir)?;

        // Check if this is a Rust project with Cargo.toml
        let cargo_path = if self.circuit_path.is_dir() {
            self.circuit_path.join("Cargo.toml")
        } else {
            self.circuit_path
                .parent()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Halo2 circuit path has no parent: '{}'",
                        self.circuit_path.display()
                    )
                })?
                .join("Cargo.toml")
        };

        if cargo_path.exists() {
            self.setup_rust_circuit(&cargo_path)?;
        } else if self.circuit_path.extension().is_some_and(|e| e == "json") {
            self.setup_from_json()?;
        } else {
            anyhow::bail!(
                "Could not determine Halo2 circuit type. Provide a Rust project or JSON constraint spec."
            );
        }

        Ok(())
    }

    /// Setup from a Rust project
    fn setup_rust_circuit(&mut self, cargo_path: &Path) -> Result<()> {
        let project_dir = cargo_path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "Halo2 Cargo.toml path has no parent directory: '{}'",
                cargo_path.display()
            )
        })?;

        // Build the project
        tracing::info!("Building Halo2 Rust project...");
        let mut output = self.run_cargo_build(project_dir, self.cargo_toolchain.as_deref())?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if self.cargo_toolchain.is_none() && halo2_lockfile_requires_nightly(&stderr) {
                tracing::warn!(
                    "Halo2 build hit lockfile-version/toolchain incompatibility; retrying with cargo +nightly"
                );
                self.cargo_toolchain = Some("nightly".to_string());
                output = self.run_cargo_build(project_dir, self.cargo_toolchain.as_deref())?;
                if !output.status.success() {
                    let fallback_stderr = String::from_utf8_lossy(&output.stderr);
                    anyhow::bail!("Failed to build Halo2 circuit: {}", fallback_stderr);
                }
            } else {
                anyhow::bail!("Failed to build Halo2 circuit: {}", stderr);
            }
        }

        // Try to run the circuit's info command if it has one
        let info = self.get_circuit_info_from_binary(project_dir);

        self.metadata = Some(info);
        Ok(())
    }

    /// Get circuit info by running the binary
    fn get_circuit_info_from_binary(&self, project_dir: &Path) -> Halo2Metadata {
        // Try to run with --info flag
        let output = {
            let mut cmd = self.cargo_command();
            cmd.args(["run", "--release", "--", "--info"])
                .current_dir(project_dir);
            match crate::util::run_with_timeout(&mut cmd, halo2_external_command_timeout()) {
                Ok(output) => Some(output),
                Err(err) => {
                    tracing::warn!(
                        "Failed to run Halo2 --info command in '{}': {}",
                        project_dir.display(),
                        err
                    );
                    None
                }
            }
        };

        if let Some(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(info) = serde_json::from_str(&stdout) {
                    return info;
                }
            }
        }

        // Return default if we can't get info
        Halo2Metadata {
            name: self.name.clone(),
            k: self.config.k,
            num_advice_columns: 0,
            num_fixed_columns: 0,
            num_instance_columns: 0,
            num_constraints: 0,
            num_private_inputs: 0,
            num_public_inputs: 0,
            num_lookups: 0,
        }
    }

    /// Setup from a JSON circuit specification
    fn setup_from_json(&mut self) -> Result<()> {
        let content = std::fs::read_to_string(&self.circuit_path)?;
        let spec: serde_json::Value = serde_json::from_str(&content)?;

        let required_u64 = |key: &str| -> Result<u64> {
            spec.get(key)
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow::anyhow!("Halo2 JSON spec missing required '{}' field", key))
        };
        let required_usize = |key: &str| -> Result<usize> { Ok(required_u64(key)? as usize) };
        let lookup_count = || -> Result<usize> {
            // Accept either:
            // - numeric `lookups: <count>`
            // - array `lookups: [ ... ]` (count inferred from length)
            match spec.get("lookups") {
                Some(value) if value.is_u64() => Ok(value.as_u64().unwrap_or(0) as usize),
                Some(value) if value.is_array() => {
                    Ok(value.as_array().map(|a| a.len()).unwrap_or(0))
                }
                _ => Err(anyhow::anyhow!(
                    "Halo2 JSON spec missing required 'lookups' field"
                )),
            }
        };
        let name = spec
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Halo2 JSON spec missing required 'name' field"))?
            .to_string();
        let k = required_u64("k")? as u32;

        self.config.k = k;
        self.metadata = Some(Halo2Metadata {
            name,
            k,
            num_advice_columns: required_usize("advice_columns")?,
            num_fixed_columns: required_usize("fixed_columns")?,
            num_instance_columns: required_usize("instance_columns")?,
            num_constraints: required_usize("constraints")?,
            num_private_inputs: required_usize("private_inputs")?,
            num_public_inputs: required_usize("public_inputs")?,
            num_lookups: lookup_count()?,
        });

        let parsed = ConstraintParser::parse_plonk_with_tables(&content);
        if self.plonk_constraints.set(parsed).is_err() {
            tracing::warn!("PLONK constraint cache already initialized during setup_from_json");
        }

        Ok(())
    }

    /// Load PLONK constraints and lookup tables if available
    pub fn load_plonk_constraints(&self) -> ParsedConstraintSet {
        if let Some(existing) = self.plonk_constraints.get() {
            return existing.clone();
        }

        if self.circuit_path.extension().is_some_and(|e| e == "json") {
            if let Ok(content) = std::fs::read_to_string(&self.circuit_path) {
                let parsed = ConstraintParser::parse_plonk_with_tables(&content);
                if self.plonk_constraints.set(parsed.clone()).is_err() {
                    tracing::warn!(
                        "PLONK constraint cache already initialized while loading JSON constraints"
                    );
                }
                return parsed;
            }
        }

        let project_dir = if self.circuit_path.is_dir() {
            self.circuit_path.clone()
        } else {
            self.circuit_path
                .parent()
                .expect("Halo2 circuit path must have parent directory")
                .to_path_buf()
        };

        if let Some(parsed) = self.try_extract_constraints_from_binary(&project_dir) {
            if self.plonk_constraints.set(parsed.clone()).is_err() {
                tracing::warn!(
                    "PLONK constraint cache already initialized while loading binary constraints"
                );
            }
            return parsed;
        }

        ParsedConstraintSet::default()
    }

    fn try_extract_constraints_from_binary(
        &self,
        project_dir: &Path,
    ) -> Option<ParsedConstraintSet> {
        let output = {
            let mut cmd = self.cargo_command();
            cmd.args(["run", "--release", "--", "--constraints"])
                .current_dir(project_dir);
            match crate::util::run_with_timeout(&mut cmd, halo2_external_command_timeout()) {
                Ok(output) => output,
                Err(err) => {
                    tracing::warn!(
                        "Failed to extract Halo2 constraints via binary run in '{}': {}",
                        project_dir.display(),
                        err
                    );
                    return None;
                }
            }
        };

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed = ConstraintParser::parse_plonk_with_tables(&stdout);
        if parsed.constraints.is_empty() {
            None
        } else {
            Some(parsed)
        }
    }

    /// Generate keys using the PSE ceremony parameters (for KZG)
    pub fn setup_keys(&mut self) -> Result<()> {
        tracing::info!("Generating Halo2 proving/verification keys...");

        // For real implementation, would need to:
        // 1. Load or generate trusted setup parameters (for KZG)
        // 2. Synthesize the circuit
        // 3. Generate proving and verification keys

        anyhow::bail!(
            "Halo2 key generation not implemented. Provide a circuit binary that handles keygen."
        )
    }

    /// Execute circuit with real execution
    fn execute_circuit(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        // For real execution, we would need to:
        // 1. Create the circuit with the given inputs as witnesses
        // 2. Synthesize to get the outputs
        // 3. Return the instance (public) values

        // Try to run the circuit binary with inputs
        let input_json = serde_json::to_string(
            &inputs
                .iter()
                .map(|fe| format!("0x{}", hex::encode(fe.0)))
                .collect::<Vec<_>>(),
        )?;

        let project_dir = if self.circuit_path.is_dir() {
            self.circuit_path.as_path()
        } else {
            self.circuit_path
                .parent()
                .expect("Halo2 circuit path must have parent directory")
        };

        let output = {
            let mut cmd = self.cargo_command();
            cmd.args(["run", "--release", "--", "--execute", &input_json])
                .current_dir(project_dir);
            match crate::util::run_with_timeout(&mut cmd, halo2_external_command_timeout()) {
                Ok(output) => Some(output),
                Err(err) => {
                    tracing::warn!(
                        "Failed to run Halo2 execute command in '{}': {}",
                        project_dir.display(),
                        err
                    );
                    None
                }
            }
        };

        if let Some(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(values) = serde_json::from_str::<Vec<String>>(&stdout) {
                    return values.iter().map(|s| FieldElement::from_hex(s)).collect();
                }
            }
        }

        anyhow::bail!("Halo2 execution failed. Provide a circuit binary that supports --execute.")
    }

    fn execute_from_json_spec(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        let parsed = self.load_plonk_constraints();
        if parsed.constraints.is_empty() {
            // Metadata-only JSON specs are used in lightweight tests and can still
            // project public inputs even without explicit constraints.
            let public = self.num_public_inputs();
            return if public > 0 {
                Ok(inputs.iter().take(public).cloned().collect())
            } else {
                Ok(vec![FieldElement::one()])
            };
        }

        let mut wire_values: HashMap<usize, FieldElement> = inputs
            .iter()
            .enumerate()
            .map(|(idx, value)| (idx, value.clone()))
            .collect();
        // Common convention: wire 0 is constant 1.
        wire_values.insert(0, FieldElement::one());

        let mut checker =
            ConstraintChecker::new().with_unknown_lookup_policy(UnknownLookupPolicy::FailClosed);
        for (id, table) in parsed.lookup_tables {
            checker.add_table(id, table);
        }

        for (idx, constraint) in parsed.constraints.iter().enumerate() {
            let eval = checker.evaluate(constraint, &wire_values);
            if !eval.satisfied {
                anyhow::bail!(
                    "Halo2 JSON spec constraint {} unsatisfied (lhs={}, rhs={})",
                    idx,
                    eval.lhs.to_decimal_string(),
                    eval.rhs.to_decimal_string()
                );
            }
        }

        let public = self.num_public_inputs();
        if public > 0 {
            Ok(inputs.iter().take(public).cloned().collect())
        } else {
            Ok(vec![FieldElement::one()])
        }
    }
}

impl TargetCircuit for Halo2Target {
    fn framework(&self) -> Framework {
        Framework::Halo2
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn field_modulus(&self) -> [u8; 32] {
        let hex_str = match self.config.field {
            Halo2Field::Bn254 => "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
            Halo2Field::Pasta => {
                // Pallas scalar field
                "40000000000000000000000000000000224698fc094cf91b992d30ed00000001"
            }
            Halo2Field::Bls12_381 => {
                "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
            }
        };
        let mut modulus = [0u8; 32];
        if let Ok(decoded) = hex::decode(hex_str) {
            modulus.copy_from_slice(&decoded);
        }
        modulus
    }

    fn field_name(&self) -> &str {
        match self.config.field {
            Halo2Field::Bn254 => "bn254",
            Halo2Field::Pasta => "pasta",
            Halo2Field::Bls12_381 => "bls12-381",
        }
    }

    fn num_constraints(&self) -> usize {
        self.metadata
            .as_ref()
            .map(|m| m.num_constraints)
            .expect("Halo2 metadata unavailable; call setup() before querying num_constraints")
    }

    fn num_private_inputs(&self) -> usize {
        self.metadata
            .as_ref()
            .map(|m| m.num_private_inputs)
            .expect("Halo2 metadata unavailable; call setup() before querying num_private_inputs")
    }

    fn num_public_inputs(&self) -> usize {
        self.metadata
            .as_ref()
            .map(|m| m.num_public_inputs)
            .expect("Halo2 metadata unavailable; call setup() before querying num_public_inputs")
    }

    fn execute(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        if self.circuit_path.extension().is_some_and(|e| e == "json") {
            self.execute_from_json_spec(inputs)
        } else {
            self.execute_circuit(inputs)
        }
    }

    fn prove(&self, witness: &[FieldElement]) -> Result<Vec<u8>> {
        // For real proving, need to use halo2_proofs crate
        // This would require the circuit to be compiled into this binary

        // Try running the circuit binary with prove command
        let witness_json = serde_json::to_string(
            &witness
                .iter()
                .map(|fe| format!("0x{}", hex::encode(fe.0)))
                .collect::<Vec<_>>(),
        )?;

        let project_dir = if self.circuit_path.is_dir() {
            self.circuit_path.as_path()
        } else {
            self.circuit_path
                .parent()
                .expect("Halo2 circuit path must have parent directory")
        };

        let output = {
            let mut cmd = self.cargo_command();
            cmd.args(["run", "--release", "--", "--prove", &witness_json])
                .current_dir(project_dir);
            match crate::util::run_with_timeout(&mut cmd, halo2_external_command_timeout()) {
                Ok(output) => Some(output),
                Err(err) => {
                    tracing::warn!(
                        "Failed to run Halo2 prove command in '{}': {}",
                        project_dir.display(),
                        err
                    );
                    None
                }
            }
        };

        if let Some(output) = output {
            if output.status.success() {
                return Ok(output.stdout);
            }
        }

        anyhow::bail!("Halo2 prove failed. Provide a circuit binary that supports --prove.")
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> Result<bool> {
        // Try running verify command
        let proof_hex = hex::encode(proof);
        let inputs_json = serde_json::to_string(
            &public_inputs
                .iter()
                .map(|fe| format!("0x{}", hex::encode(fe.0)))
                .collect::<Vec<_>>(),
        )?;

        let project_dir = if self.circuit_path.is_dir() {
            self.circuit_path.as_path()
        } else {
            self.circuit_path
                .parent()
                .expect("Halo2 circuit path must have parent directory")
        };

        let output = {
            let mut cmd = self.cargo_command();
            cmd.args([
                "run",
                "--release",
                "--",
                "--verify",
                &proof_hex,
                &inputs_json,
            ])
            .current_dir(project_dir);
            match crate::util::run_with_timeout(&mut cmd, halo2_external_command_timeout()) {
                Ok(output) => Some(output),
                Err(err) => {
                    tracing::warn!(
                        "Failed to run Halo2 verify command in '{}': {}",
                        project_dir.display(),
                        err
                    );
                    None
                }
            }
        };

        if let Some(output) = output {
            return Ok(output.status.success());
        }

        anyhow::bail!("Halo2 verify failed. Provide a circuit binary that supports --verify.")
    }
}

/// Halo2-specific analysis utilities
pub mod analysis {

    /// Analyze a Halo2 circuit for common issues
    pub fn analyze_circuit(source: &str) -> Vec<Halo2Issue> {
        let mut issues = Vec::new();

        // Check for unused columns
        issues.extend(check_unused_columns(source));

        // Check for missing copy constraints
        issues.extend(check_copy_constraints(source));

        // Check for unsafe range checks
        issues.extend(check_range_checks(source));

        issues
    }

    /// Check for potentially unused columns
    pub fn check_unused_columns(source: &str) -> Vec<Halo2Issue> {
        let mut issues = Vec::new();

        // Look for column declarations vs usage
        let advice_decl = source.matches("advice_column").count();
        let advice_use = source.matches(".query_advice").count();

        if advice_decl > advice_use {
            issues.push(Halo2Issue {
                gate_type: "column".to_string(),
                description: format!(
                    "Declared {} advice columns but only {} are queried - potential unused columns",
                    advice_decl, advice_use
                ),
                severity: "warning".to_string(),
            });
        }

        issues
    }

    /// Check for potentially missing copy constraints
    pub fn check_copy_constraints(source: &str) -> Vec<Halo2Issue> {
        let mut issues = Vec::new();

        // Look for assignments without copy constraints
        let assigns =
            source.matches("assign_advice").count() + source.matches("assign_fixed").count();
        let copies =
            source.matches("copy_advice").count() + source.matches("enable_equality").count();

        if assigns > copies * 3 {
            issues.push(Halo2Issue {
                gate_type: "copy_constraint".to_string(),
                description: format!(
                    "Found {} assignments but only {} copy-related operations - values may not be properly constrained",
                    assigns, copies
                ),
                severity: "warning".to_string(),
            });
        }

        issues
    }

    /// Check for range check issues
    pub fn check_range_checks(source: &str) -> Vec<Halo2Issue> {
        let mut issues = Vec::new();

        // Check for bit decomposition without proper range checks
        if source.contains("bit") && !source.contains("range_check") && !source.contains("lookup") {
            issues.push(Halo2Issue {
                gate_type: "range".to_string(),
                description: "Bit operations detected without explicit range checks or lookups"
                    .to_string(),
                severity: "info".to_string(),
            });
        }

        issues
    }

    /// A detected issue in Halo2 circuit
    #[derive(Debug, Clone)]
    pub struct Halo2Issue {
        pub gate_type: String,
        pub description: String,
        pub severity: String,
    }

    /// Constraint type in Halo2
    #[derive(Debug, Clone, PartialEq)]
    pub enum ConstraintType {
        /// Custom gate constraint
        Gate,
        /// Lookup table constraint
        Lookup,
        /// Shuffle constraint
        Shuffle,
        /// Permutation (copy) constraint
        Permutation,
    }

    /// Circuit statistics
    #[derive(Debug, Clone, Default)]
    pub struct CircuitStats {
        pub num_gates: usize,
        pub num_lookups: usize,
        pub num_permutations: usize,
        pub num_rows: usize,
        pub num_columns: usize,
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
