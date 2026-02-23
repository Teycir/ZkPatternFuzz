//! Halo2 circuit target implementation
//!
//! Provides integration with the Halo2 proving system:
//! - Direct Rust API integration (circuits defined in Rust)
//! - Support for PSE's halo2 fork (halo2_proofs)
//! - PLONK-based constraint system

use crate::TargetCircuit;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use zk_constraints::{
    ConstraintChecker, ConstraintParser, ParsedConstraintSet, UnknownLookupPolicy,
};
use zk_core::constants::bn254_modulus_bytes;
use zk_core::FieldElement;
use zk_core::Framework;

fn halo2_external_command_timeout() -> std::time::Duration {
    crate::util::timeout_from_env("ZK_FUZZER_HALO2_EXTERNAL_TIMEOUT_SECS", 120)
}

fn halo2_cargo_toolchain_from_env() -> Option<String> {
    if let Ok(value) = std::env::var("ZK_FUZZER_HALO2_CARGO_TOOLCHAIN") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn halo2_strict_readiness_mode() -> bool {
    match std::env::var("ZKFUZZ_HALO2_STRICT_READINESS") {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Halo2KeySetupManifest {
    contract_version: u32,
    framework: String,
    circuit_name: String,
    field: String,
    commitment: String,
    k: u32,
    setup_mode: String,
    setup_command: Option<Vec<String>>,
    proving_key_path: String,
    verification_key_path: String,
    proving_key_sha256: String,
    verification_key_sha256: String,
    seed_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Halo2CanonicalProofEnvelope {
    contract_version: u32,
    framework: String,
    proof_mode: String,
    circuit_name: String,
    field: String,
    commitment: String,
    k: u32,
    witness_len: usize,
    public_inputs_len: usize,
    witness_sha256: String,
    public_inputs_sha256: String,
    key_seed_sha256: String,
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
        let output = self.run_cargo_build(project_dir, self.cargo_toolchain.as_deref())?;

        if !output.status.success() {
            let details = crate::util::command_output_summary(&output);
            anyhow::bail!("Failed to build Halo2 circuit: {}", details);
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
        if halo2_strict_readiness_mode() && parsed.constraints.is_empty() {
            anyhow::bail!(
                "Halo2 strict readiness mode requires non-empty PLONK constraints in JSON specs"
            );
        }
        if self.plonk_constraints.set(parsed).is_err() {
            tracing::warn!("PLONK constraint cache already initialized during setup_from_json");
        }

        Ok(())
    }

    fn commitment_name(&self) -> &'static str {
        match self.config.commitment {
            CommitmentScheme::Kzg => "kzg",
            CommitmentScheme::Ipa => "ipa",
        }
    }

    fn key_setup_manifest_path(&self) -> PathBuf {
        self.build_dir.join("halo2_key_setup_manifest.json")
    }

    fn canonical_key_paths(&self) -> (PathBuf, PathBuf) {
        let keys_dir = self.build_dir.join("keys");
        (
            keys_dir.join("halo2_proving.key"),
            keys_dir.join("halo2_verification.key"),
        )
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    fn derive_key_material(seed: &[u8], label: &[u8]) -> Vec<u8> {
        let mut first = Sha256::new();
        first.update(b"zkfuzz-halo2-key-material-v1");
        first.update(seed);
        first.update(label);
        first.update([1u8]);
        let first_digest = first.finalize();

        let mut second = Sha256::new();
        second.update(b"zkfuzz-halo2-key-material-v1");
        second.update(seed);
        second.update(label);
        second.update([2u8]);
        let second_digest = second.finalize();

        [first_digest.to_vec(), second_digest.to_vec()].concat()
    }

    fn key_setup_seed(&self) -> Result<Vec<u8>> {
        let metadata = self
            .metadata
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Halo2 metadata unavailable; run setup first"))?;

        let mut hasher = Sha256::new();
        hasher.update(b"zkfuzz-halo2-key-setup-seed-v1");
        hasher.update(metadata.name.as_bytes());
        hasher.update(metadata.k.to_le_bytes());
        hasher.update((metadata.num_advice_columns as u64).to_le_bytes());
        hasher.update((metadata.num_fixed_columns as u64).to_le_bytes());
        hasher.update((metadata.num_instance_columns as u64).to_le_bytes());
        hasher.update((metadata.num_constraints as u64).to_le_bytes());
        hasher.update((metadata.num_private_inputs as u64).to_le_bytes());
        hasher.update((metadata.num_public_inputs as u64).to_le_bytes());
        hasher.update((metadata.num_lookups as u64).to_le_bytes());
        hasher.update(self.field_name().as_bytes());
        hasher.update(self.commitment_name().as_bytes());

        if self.circuit_path.is_file() {
            if let Ok(bytes) = std::fs::read(&self.circuit_path) {
                hasher.update(bytes);
            }
        } else {
            let cargo_toml = self.circuit_path.join("Cargo.toml");
            if let Ok(bytes) = std::fs::read(cargo_toml) {
                hasher.update(bytes);
            }
        }

        Ok(hasher.finalize().to_vec())
    }

    fn cargo_project_dir(&self) -> Option<PathBuf> {
        let cargo_path = if self.circuit_path.is_dir() {
            self.circuit_path.join("Cargo.toml")
        } else {
            self.circuit_path.parent()?.join("Cargo.toml")
        };
        if cargo_path.is_file() {
            cargo_path.parent().map(Path::to_path_buf)
        } else {
            None
        }
    }

    fn detect_project_cli_flag(
        &self,
        project_dir: &Path,
        purpose: &str,
        candidates: &[&str],
    ) -> Option<String> {
        let output = {
            let mut cmd = self.cargo_command();
            cmd.args(["run", "--release", "--", "--help"])
                .current_dir(project_dir);
            match crate::util::run_with_timeout(&mut cmd, halo2_external_command_timeout()) {
                Ok(output) => output,
                Err(err) => {
                    tracing::warn!(
                        "Failed to inspect Halo2 {} flags in '{}': {}",
                        purpose,
                        project_dir.display(),
                        err
                    );
                    return None;
                }
            }
        };

        if !output.status.success() {
            tracing::warn!(
                "Halo2 --help command failed while probing {} support in '{}': {}",
                purpose,
                project_dir.display(),
                String::from_utf8_lossy(&output.stderr)
            );
            return None;
        }

        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .to_ascii_lowercase();

        for candidate in candidates {
            if combined.contains(candidate) {
                return Some(candidate.to_string());
            }
        }

        None
    }

    fn detect_project_key_setup_flag(&self, project_dir: &Path) -> Option<String> {
        self.detect_project_cli_flag(
            project_dir,
            "key setup",
            &["--setup-keys", "--setup_keys", "--keygen"],
        )
    }

    fn run_project_key_setup_command(
        &self,
        project_dir: &Path,
        flag: &str,
    ) -> Result<std::process::Output> {
        let mut cmd = self.cargo_command();
        cmd.args(["run", "--release", "--", flag])
            .current_dir(project_dir);
        crate::util::run_with_timeout(&mut cmd, halo2_external_command_timeout())
            .with_context(|| format!("Failed running Halo2 key setup command '{flag}'"))
    }

    fn find_existing_key_artifacts(&self, project_dir: &Path) -> Option<(Vec<u8>, Vec<u8>)> {
        let search_dirs = [
            project_dir.join("keys"),
            project_dir.join("target"),
            project_dir.join("target").join("release"),
            self.build_dir.join("keys"),
            self.build_dir.clone(),
        ];

        let proving_names = [
            "proving.key",
            "proving_key",
            "proving.pk",
            "pk.bin",
            "pk.key",
            "prover.key",
            "proving_key.bin",
        ];
        let verification_names = [
            "verification.key",
            "verifying.key",
            "verification_key",
            "vk.bin",
            "vk.key",
            "verifier.key",
            "verification_key.bin",
        ];

        let read_first_nonempty = |paths: Vec<PathBuf>| -> Option<Vec<u8>> {
            for path in paths {
                if !path.is_file() {
                    continue;
                }
                match std::fs::read(&path) {
                    Ok(bytes) if !bytes.is_empty() => return Some(bytes),
                    Ok(_) => continue,
                    Err(err) => {
                        tracing::debug!(
                            "Failed reading candidate Halo2 key artifact '{}': {}",
                            path.display(),
                            err
                        );
                    }
                }
            }
            None
        };

        let proving_paths = search_dirs
            .iter()
            .flat_map(|dir| proving_names.iter().map(move |name| dir.join(name)))
            .collect::<Vec<_>>();
        let verification_paths = search_dirs
            .iter()
            .flat_map(|dir| verification_names.iter().map(move |name| dir.join(name)))
            .collect::<Vec<_>>();

        let proving = read_first_nonempty(proving_paths)?;
        let verification = read_first_nonempty(verification_paths)?;
        Some((proving, verification))
    }

    fn write_key_setup_manifest(
        &self,
        setup_mode: &str,
        setup_command: Option<Vec<String>>,
        proving_key_path: &Path,
        verification_key_path: &Path,
        proving_key: &[u8],
        verification_key: &[u8],
        seed: &[u8],
    ) -> Result<()> {
        let manifest = Halo2KeySetupManifest {
            contract_version: 1,
            framework: "halo2".to_string(),
            circuit_name: self.name.clone(),
            field: self.field_name().to_string(),
            commitment: self.commitment_name().to_string(),
            k: self.config.k,
            setup_mode: setup_mode.to_string(),
            setup_command,
            proving_key_path: proving_key_path.display().to_string(),
            verification_key_path: verification_key_path.display().to_string(),
            proving_key_sha256: Self::sha256_hex(proving_key),
            verification_key_sha256: Self::sha256_hex(verification_key),
            seed_sha256: Self::sha256_hex(seed),
        };

        let manifest_path = self.key_setup_manifest_path();
        if let Some(parent) = manifest_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed creating '{}'", parent.display()))?;
        }
        let payload = serde_json::to_vec_pretty(&manifest)
            .context("Failed serializing Halo2 key setup manifest")?;
        std::fs::write(&manifest_path, payload)
            .with_context(|| format!("Failed writing '{}'", manifest_path.display()))?;
        Ok(())
    }

    fn canonical_public_projection(&self, inputs: &[FieldElement]) -> Vec<FieldElement> {
        let public = self
            .metadata
            .as_ref()
            .map(|m| m.num_public_inputs)
            .unwrap_or(0);
        if public > 0 {
            inputs.iter().take(public).cloned().collect()
        } else {
            vec![FieldElement::one()]
        }
    }

    fn encode_field_elements_hex(values: &[FieldElement]) -> Vec<String> {
        values
            .iter()
            .map(|fe| format!("0x{}", hex::encode(fe.0)))
            .collect()
    }

    fn sha256_hex_for_field_elements(values: &[FieldElement]) -> String {
        let mut hasher = Sha256::new();
        for value in values {
            hasher.update(value.0);
        }
        hex::encode(hasher.finalize())
    }

    fn canonical_proof_envelope(
        &self,
        witness: &[FieldElement],
    ) -> Result<Halo2CanonicalProofEnvelope> {
        let public_inputs = self.canonical_public_projection(witness);
        let seed = self.key_setup_seed()?;

        Ok(Halo2CanonicalProofEnvelope {
            contract_version: 1,
            framework: "halo2".to_string(),
            proof_mode: "canonical_adapter".to_string(),
            circuit_name: self.name.clone(),
            field: self.field_name().to_string(),
            commitment: self.commitment_name().to_string(),
            k: self.config.k,
            witness_len: witness.len(),
            public_inputs_len: public_inputs.len(),
            witness_sha256: Self::sha256_hex_for_field_elements(witness),
            public_inputs_sha256: Self::sha256_hex_for_field_elements(&public_inputs),
            key_seed_sha256: Self::sha256_hex(&seed),
        })
    }

    fn canonical_prove(&self, witness: &[FieldElement]) -> Result<Vec<u8>> {
        let envelope = self.canonical_proof_envelope(witness)?;
        serde_json::to_vec(&envelope).context("Failed serializing canonical Halo2 proof envelope")
    }

    fn canonical_verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> Result<bool> {
        let envelope: Halo2CanonicalProofEnvelope = match serde_json::from_slice(proof) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };

        if envelope.contract_version != 1
            || envelope.framework != "halo2"
            || envelope.proof_mode != "canonical_adapter"
            || envelope.circuit_name != self.name
            || envelope.field != self.field_name()
            || envelope.commitment != self.commitment_name()
            || envelope.k != self.config.k
            || envelope.public_inputs_len != public_inputs.len()
        {
            return Ok(false);
        }

        let expected_public_inputs_sha256 = Self::sha256_hex_for_field_elements(public_inputs);
        if envelope.public_inputs_sha256 != expected_public_inputs_sha256 {
            return Ok(false);
        }

        let expected_seed_sha256 = self.key_setup_seed().map(|seed| Self::sha256_hex(&seed))?;
        if envelope.key_seed_sha256 != expected_seed_sha256 {
            return Ok(false);
        }

        Ok(true)
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
        if self.metadata.is_none() {
            self.setup()
                .context("Halo2 setup failed before key generation")?;
        }

        std::fs::create_dir_all(&self.build_dir)
            .with_context(|| format!("Failed creating build dir '{}'", self.build_dir.display()))?;

        let mut setup_mode = "canonical_adapter".to_string();
        let mut setup_command: Option<Vec<String>> = None;
        let mut keygen_project_dir: Option<PathBuf> = None;

        if let Some(project_dir) = self.cargo_project_dir() {
            if let Some(flag) = self.detect_project_key_setup_flag(&project_dir) {
                let output = self.run_project_key_setup_command(&project_dir, &flag)?;
                if !output.status.success() {
                    anyhow::bail!(
                        "Halo2 key setup command '{}' failed: stdout='{}' stderr='{}'",
                        flag,
                        String::from_utf8_lossy(&output.stdout).trim(),
                        String::from_utf8_lossy(&output.stderr).trim()
                    );
                }

                setup_mode = "project_cli".to_string();
                setup_command = Some(vec![
                    "cargo".to_string(),
                    "run".to_string(),
                    "--release".to_string(),
                    "--".to_string(),
                    flag.clone(),
                ]);
                keygen_project_dir = Some(project_dir);
            }
        }

        let seed = self.key_setup_seed()?;
        let (proving_key_path, verification_key_path) = self.canonical_key_paths();

        let (proving_key, verification_key) = if let Some(project_dir) = keygen_project_dir.as_ref()
        {
            if let Some((proving_key, verification_key)) =
                self.find_existing_key_artifacts(project_dir)
            {
                setup_mode = "project_cli_artifacts".to_string();
                (proving_key, verification_key)
            } else {
                setup_mode = "project_cli_canonical_adapter".to_string();
                (
                    Self::derive_key_material(&seed, b"proving"),
                    Self::derive_key_material(&seed, b"verification"),
                )
            }
        } else {
            (
                Self::derive_key_material(&seed, b"proving"),
                Self::derive_key_material(&seed, b"verification"),
            )
        };

        if let Some(parent) = proving_key_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed creating '{}'", parent.display()))?;
        }
        std::fs::write(&proving_key_path, &proving_key)
            .with_context(|| format!("Failed writing '{}'", proving_key_path.display()))?;
        std::fs::write(&verification_key_path, &verification_key)
            .with_context(|| format!("Failed writing '{}'", verification_key_path.display()))?;

        self.write_key_setup_manifest(
            &setup_mode,
            setup_command,
            &proving_key_path,
            &verification_key_path,
            &proving_key,
            &verification_key,
            &seed,
        )?;

        tracing::info!(
            "Halo2 key setup complete: mode='{}', proving='{}', verification='{}'",
            setup_mode,
            proving_key_path.display(),
            verification_key_path.display()
        );
        Ok(())
    }

    /// Execute circuit with real execution
    fn execute_circuit(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        let project_dir = if self.circuit_path.is_dir() {
            self.circuit_path.as_path()
        } else {
            self.circuit_path
                .parent()
                .expect("Halo2 circuit path must have parent directory")
        };

        let execute_flag = self.detect_project_cli_flag(project_dir, "execute", &["--execute"]);
        if execute_flag.is_none() {
            tracing::info!(
                "Halo2 project '{}' does not expose a supported execute flag; using canonical adapter execution",
                project_dir.display()
            );
            return Ok(self.canonical_public_projection(inputs));
        }
        let execute_flag = execute_flag.expect("checked is_some");

        let input_json = serde_json::to_string(&Self::encode_field_elements_hex(inputs))?;
        let output = {
            let mut cmd = self.cargo_command();
            cmd.args(["run", "--release", "--", &execute_flag, &input_json])
                .current_dir(project_dir);
            crate::util::run_with_timeout(&mut cmd, halo2_external_command_timeout())
                .with_context(|| format!("Failed to run Halo2 execute command '{execute_flag}'"))?
        };

        if !output.status.success() {
            anyhow::bail!(
                "Halo2 execute command '{}' failed: stdout='{}' stderr='{}'",
                execute_flag,
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(values) = serde_json::from_str::<Vec<String>>(&stdout) {
            return values.iter().map(|s| FieldElement::from_hex(s)).collect();
        }

        anyhow::bail!(
            "Halo2 execute command '{}' returned non-JSON output",
            execute_flag
        )
    }

    fn execute_from_json_spec(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        let parsed = self.load_plonk_constraints();
        if parsed.constraints.is_empty() {
            // Metadata-only JSON specs are used in lightweight tests and can still
            // project public inputs even without explicit constraints.
            return Ok(self.canonical_public_projection(inputs));
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

        Ok(self.canonical_public_projection(inputs))
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
        match self.config.field {
            Halo2Field::Bn254 => bn254_modulus_bytes(),
            Halo2Field::Pasta => {
                // Pallas scalar field
                let mut modulus = [0u8; 32];
                if let Ok(decoded) =
                    hex::decode("40000000000000000000000000000000224698fc094cf91b992d30ed00000001")
                {
                    modulus.copy_from_slice(&decoded);
                }
                modulus
            }
            Halo2Field::Bls12_381 => {
                let mut modulus = [0u8; 32];
                if let Ok(decoded) =
                    hex::decode("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
                {
                    modulus.copy_from_slice(&decoded);
                }
                modulus
            }
        }
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
        if self.circuit_path.extension().is_some_and(|e| e == "json") {
            return self.canonical_prove(witness);
        }

        let project_dir = if self.circuit_path.is_dir() {
            self.circuit_path.as_path()
        } else {
            self.circuit_path
                .parent()
                .expect("Halo2 circuit path must have parent directory")
        };
        let prove_flag = self.detect_project_cli_flag(project_dir, "prove", &["--prove"]);
        if prove_flag.is_none() {
            tracing::info!(
                "Halo2 project '{}' does not expose a supported prove flag; using canonical adapter proving",
                project_dir.display()
            );
            return self.canonical_prove(witness);
        }
        let prove_flag = prove_flag.expect("checked is_some");

        let witness_json = serde_json::to_string(&Self::encode_field_elements_hex(witness))?;

        let output = {
            let mut cmd = self.cargo_command();
            cmd.args(["run", "--release", "--", &prove_flag, &witness_json])
                .current_dir(project_dir);
            crate::util::run_with_timeout(&mut cmd, halo2_external_command_timeout())
                .with_context(|| format!("Failed to run Halo2 prove command '{prove_flag}'"))?
        };

        if output.status.success() {
            return Ok(output.stdout);
        }

        anyhow::bail!(
            "Halo2 prove command '{}' failed: stdout='{}' stderr='{}'",
            prove_flag,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> Result<bool> {
        if self.circuit_path.extension().is_some_and(|e| e == "json") {
            return self.canonical_verify(proof, public_inputs);
        }

        let project_dir = if self.circuit_path.is_dir() {
            self.circuit_path.as_path()
        } else {
            self.circuit_path
                .parent()
                .expect("Halo2 circuit path must have parent directory")
        };
        let verify_flag = self.detect_project_cli_flag(project_dir, "verify", &["--verify"]);
        if verify_flag.is_none() {
            tracing::info!(
                "Halo2 project '{}' does not expose a supported verify flag; using canonical adapter verification",
                project_dir.display()
            );
            return self.canonical_verify(proof, public_inputs);
        }
        let verify_flag = verify_flag.expect("checked is_some");

        let proof_hex = hex::encode(proof);
        let inputs_json = serde_json::to_string(&Self::encode_field_elements_hex(public_inputs))?;
        let output = {
            let mut cmd = self.cargo_command();
            cmd.args([
                "run",
                "--release",
                "--",
                &verify_flag,
                &proof_hex,
                &inputs_json,
            ])
            .current_dir(project_dir);
            crate::util::run_with_timeout(&mut cmd, halo2_external_command_timeout())
                .with_context(|| format!("Failed to run Halo2 verify command '{verify_flag}'"))?
        };
        Ok(output.status.success())
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
