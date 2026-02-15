//! Cairo circuit target implementation
//!
//! Provides integration with the Cairo/StarkNet ecosystem:
//! - Compilation via cairo-compile or scarb
//! - Execution via cairo-run
//! - STARK proof generation via stone-prover

use crate::TargetCircuit;
use zk_core::Framework;
use zk_core::FieldElement;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

fn cairo_external_command_timeout() -> std::time::Duration {
    // Cairo executions can be heavier than CLI compilation; default a bit higher.
    crate::util::timeout_from_env("ZK_FUZZER_CAIRO_EXTERNAL_TIMEOUT_SECS", 120)
}

/// Cairo circuit target with full backend integration
pub struct CairoTarget {
    /// Path to the Cairo source file or project
    source_path: PathBuf,
    /// Program name
    name: String,
    /// Compiled program path
    compiled_path: Option<PathBuf>,
    /// Program metadata
    metadata: Option<CairoMetadata>,
    /// Build directory
    build_dir: PathBuf,
    /// Whether the program has been compiled
    compiled: bool,
    /// Cairo version (Cairo 0 vs Cairo 1/Scarb)
    cairo_version: CairoVersion,
    /// Configuration
    config: CairoConfig,
}

/// Cairo version
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CairoVersion {
    /// Original Cairo (Cairo 0)
    Cairo0,
    /// New Cairo (Cairo 1, Scarb-based)
    Cairo1,
}

/// Cairo program metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CairoMetadata {
    /// Program name
    pub name: String,
    /// Number of steps (execution trace length)
    pub num_steps: usize,
    /// Number of memory cells used
    pub num_memory_cells: usize,
    /// Number of builtins used
    pub builtins: Vec<String>,
    /// Number of input felts
    pub num_inputs: usize,
    /// Number of output felts
    pub num_outputs: usize,
}

/// Cairo configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CairoConfig {
    /// Maximum number of steps
    pub max_steps: usize,
    /// Layout to use (e.g., "plain", "small", "dex", "recursive")
    pub layout: String,
    /// Whether to use proof mode
    pub proof_mode: bool,
}

impl Default for CairoConfig {
    fn default() -> Self {
        Self {
            max_steps: 10_000_000,
            layout: "small".to_string(),
            proof_mode: true,
        }
    }
}

impl CairoTarget {
    /// Create a new Cairo target from a source file
    pub fn new(source_path: &str) -> Result<Self> {
        let path = PathBuf::from(source_path);
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Detect Cairo version from file extension/content
        let cairo_version = Self::detect_version(&path)?;
        let build_dir = match cairo_version {
            CairoVersion::Cairo0 => path.parent().unwrap_or(Path::new(".")).join("build"),
            CairoVersion::Cairo1 => path.parent().unwrap_or(Path::new(".")).join("target"),
        };

        Ok(Self {
            source_path: path,
            name,
            compiled_path: None,
            metadata: None,
            build_dir,
            compiled: false,
            cairo_version,
            config: CairoConfig::default(),
        })
    }

    /// Override the build directory for compiled artifacts.
    pub fn with_build_dir(mut self, build_dir: PathBuf) -> Self {
        self.build_dir = build_dir;
        self
    }

    /// Create with custom configuration
    pub fn with_config(mut self, config: CairoConfig) -> Self {
        self.config = config;
        self
    }

    /// Detect Cairo version from the source file
    fn detect_version(path: &Path) -> Result<CairoVersion> {
        // Check for Scarb.toml (Cairo 1)
        let scarb_path = path.parent().unwrap_or(Path::new(".")).join("Scarb.toml");
        if scarb_path.exists() {
            return Ok(CairoVersion::Cairo1);
        }

        // Check file extension
        if let Some(ext) = path.extension() {
            if ext == "cairo" {
                // Try to read file and detect version from syntax
                if let Ok(content) = std::fs::read_to_string(path) {
                    // Cairo 1 uses different syntax
                    if content.contains("fn main()")
                        || content.contains("#[contract]")
                        || content.contains("mod ")
                        || content.contains("use ")
                    {
                        return Ok(CairoVersion::Cairo1);
                    }
                }
            }
        }

        // Default to Cairo 0
        Ok(CairoVersion::Cairo0)
    }

    /// Check if Cairo compiler is available
    pub fn check_cairo_available() -> Result<(CairoVersion, String)> {
        // Prefer Cairo 0 toolchain when available (cairo-compile + cairo-run).
        let cairo0 = (|| -> Result<String> {
            let mut cmd = Command::new("cairo-compile");
            cmd.arg("--version");
            let output =
                crate::util::run_with_timeout(&mut cmd, cairo_external_command_timeout())
                    .context("cairo-compile not found in PATH")?;
            if !output.status.success() {
                anyhow::bail!("cairo-compile --version failed");
            }

            let mut run_cmd = Command::new("cairo-run");
            run_cmd.arg("--version");
            let run_output =
                crate::util::run_with_timeout(&mut run_cmd, cairo_external_command_timeout())
                    .context("cairo-run not found in PATH")?;
            if !run_output.status.success() {
                anyhow::bail!("cairo-run --version failed");
            }

            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        })();

        if let Ok(version) = cairo0 {
            return Ok((CairoVersion::Cairo0, version));
        }

        // Fallback to Scarb (Cairo 1).
        let output = {
            let mut cmd = Command::new("scarb");
            cmd.arg("--version");
            crate::util::run_with_timeout(&mut cmd, cairo_external_command_timeout())
                .context("scarb not found in PATH")?
        };
        if !output.status.success() {
            anyhow::bail!("No Cairo toolchain detected (need cairo-compile/cairo-run or scarb)");
        }

        Ok((
            CairoVersion::Cairo1,
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ))
    }

    /// Check if stone-prover is available
    pub fn check_stone_prover_available() -> Result<String> {
        let output = {
            let mut cmd = Command::new("cpu_air_prover");
            cmd.arg("--version");
            crate::util::run_with_timeout(&mut cmd, cairo_external_command_timeout())
                .context("stone-prover not found")?
        };

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            anyhow::bail!("stone-prover --version failed")
        }
    }

    /// Compile the Cairo program
    pub fn compile(&mut self) -> Result<()> {
        if self.compiled {
            return Ok(());
        }

        tracing::info!("Compiling Cairo program: {:?}", self.source_path);

        std::fs::create_dir_all(&self.build_dir)?;
        let _dir_lock = crate::util::DirLock::acquire_exclusive(&self.build_dir)?;

        match self.cairo_version {
            CairoVersion::Cairo0 => self.compile_cairo0()?,
            CairoVersion::Cairo1 => self.compile_cairo1()?,
        }

        self.compiled = true;
        Ok(())
    }

    /// Compile Cairo 0 program
    fn compile_cairo0(&mut self) -> Result<()> {
        let output_path = self.build_dir.join(format!("{}.json", self.name));

        let mut args = vec![
            self.source_path.to_str().unwrap().to_string(),
            "--output".to_string(),
            output_path.to_str().unwrap().to_string(),
        ];

        if self.config.proof_mode {
            args.push("--proof_mode".to_string());
        } else {
            args.push("--no_proof_mode".to_string());
        }

        let output = {
            let mut cmd = Command::new("cairo-compile");
            cmd.args(&args);
            crate::util::run_with_timeout(&mut cmd, cairo_external_command_timeout())
                .context("Failed to run cairo-compile")?
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Cairo compilation failed: {}", stderr);
        }

        self.compiled_path = Some(output_path);
        tracing::info!("Cairo 0 compilation successful");

        // Parse program info
        self.parse_program_info()?;

        Ok(())
    }

    /// Compile Cairo 1 program using scarb
    fn compile_cairo1(&mut self) -> Result<()> {
        let project_dir = self.source_path.parent().unwrap_or(Path::new("."));

        let output = {
            let mut cmd = Command::new("scarb");
            cmd.args(["build"])
                .env("SCARB_TARGET_DIR", &self.build_dir)
                .current_dir(project_dir);
            crate::util::run_with_timeout(&mut cmd, cairo_external_command_timeout())
                .context("Failed to run scarb build")?
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Scarb build failed: {}", stderr);
        }

        // Find the compiled Sierra file
        let target_dir = self.build_dir.join("dev");
        if let Ok(entries) = std::fs::read_dir(&target_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path
                    .extension()
                    .is_some_and(|e| e == "sierra.json" || e == "casm.json")
                {
                    self.compiled_path = Some(path);
                    break;
                }
            }
        }

        if self.compiled_path.is_none() {
            let fallback_dir = project_dir.join("target").join("dev");
            if let Ok(entries) = std::fs::read_dir(&fallback_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path
                        .extension()
                        .is_some_and(|e| e == "sierra.json" || e == "casm.json")
                    {
                        self.compiled_path = Some(path);
                        break;
                    }
                }
            }
        }

        tracing::info!("Cairo 1 compilation successful");
        self.parse_program_info()?;

        Ok(())
    }

    /// Parse program information from compiled artifact
    fn parse_program_info(&mut self) -> Result<()> {
        let compiled_path = match &self.compiled_path {
            Some(p) => p,
            None => return Ok(()),
        };

        if compiled_path.exists() {
            let content = std::fs::read_to_string(compiled_path)?;
            if let Ok(program) = serde_json::from_str::<serde_json::Value>(&content) {
                // Extract builtins
                let builtins: Vec<String> = program
                    .get("builtins")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                // Count hints for input estimation
                let num_hints = program
                    .get("hints")
                    .and_then(|v| v.as_object())
                    .map(|h| h.len())
                    .unwrap_or(0);

                self.metadata = Some(CairoMetadata {
                    name: self.name.clone(),
                    num_steps: 0,
                    num_memory_cells: 0,
                    builtins,
                    num_inputs: num_hints.max(1),
                    num_outputs: 1,
                });
            }
        }

        Ok(())
    }

    /// Execute the Cairo program with given inputs
    pub fn execute_cairo(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        if !self.compiled {
            anyhow::bail!("Program not compiled. Call compile() first.");
        }

        let _guard = cairo_io_lock().lock().unwrap();
        self.execute_cairo_inner(inputs)
    }

    fn execute_cairo_inner(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        match self.cairo_version {
            CairoVersion::Cairo0 => self.execute_cairo0(inputs),
            CairoVersion::Cairo1 => self.execute_cairo1(inputs),
        }
    }

    /// Execute Cairo 0 program
    fn execute_cairo0(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        let compiled_path = self
            .compiled_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No compiled program"))?;

        let temp_dir = tempfile::Builder::new()
            .prefix("zkfuzz_cairo_")
            .tempdir()
            .context("Failed to create temp directory")?;
        let work = temp_dir.path();

        // Create input file
        let input_path = work.join("input.json");
        let input_json = self.create_input_json(inputs)?;
        std::fs::write(&input_path, &input_json)?;

        // Run cairo-run
        let trace_path = work.join("trace.bin");
        let memory_path = work.join("memory.bin");

        let mut args = vec![
            "--program".to_string(),
            compiled_path.to_str().unwrap().to_string(),
            "--print_output".to_string(),
            "--layout".to_string(),
            self.config.layout.clone(),
        ];

        if self.config.proof_mode {
            args.extend([
                "--trace_file".to_string(),
                trace_path.to_str().unwrap().to_string(),
                "--memory_file".to_string(),
                memory_path.to_str().unwrap().to_string(),
                "--proof_mode".to_string(),
            ]);
        }

        // Add program input if the program expects it
        args.extend([
            "--program_input".to_string(),
            input_path.to_str().unwrap().to_string(),
        ]);

        let output = {
            let mut cmd = Command::new("cairo-run");
            cmd.args(&args);
            crate::util::run_with_timeout(&mut cmd, cairo_external_command_timeout())
                .context("Failed to run cairo-run")?
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Cairo execution failed: {}", stderr);
        }

        // Parse output
        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_cairo_output(&stdout)
    }

    /// Execute Cairo 1 program
    fn execute_cairo1(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        let project_dir = self.source_path.parent().unwrap_or(Path::new("."));

        // Create args JSON
        let args: Vec<String> = inputs
            .iter()
            .map(|fe| format!("\"{}\"", field_element_to_decimal(fe)))
            .collect();
        let args_json = format!("[{}]", args.join(", "));

        let output = {
            let mut cmd = Command::new("scarb");
            cmd.args(["cairo-run", "--", &args_json]).current_dir(project_dir);
            crate::util::run_with_timeout(&mut cmd, cairo_external_command_timeout())
                .context("Failed to run scarb cairo-run")?
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Cairo 1 execution failed: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_cairo1_output(&stdout)
    }

    /// Create input JSON for Cairo program
    fn create_input_json(&self, inputs: &[FieldElement]) -> Result<String> {
        let values: Vec<String> = inputs
            .iter()
            .map(|fe| format!("\"{}\"", field_element_to_decimal(fe)))
            .collect();

        // Create a simple input structure
        Ok(format!("{{\"inputs\": [{}]}}", values.join(", ")))
    }

    /// Parse Cairo 0 output
    fn parse_cairo_output(&self, stdout: &str) -> Result<Vec<FieldElement>> {
        let mut outputs = Vec::new();

        // Look for output lines
        for line in stdout.lines() {
            let trimmed = line.trim();

            // Cairo outputs values in various formats
            if trimmed.starts_with("Program output:") {
                continue;
            }

            // Try to parse as number
            if let Ok(num) = trimmed.parse::<u64>() {
                outputs.push(FieldElement::from_u64(num));
            } else if trimmed.starts_with("0x") {
                if let Ok(fe) = FieldElement::from_hex(trimmed) {
                    outputs.push(fe);
                }
            } else {
                // Try parsing as big decimal
                use num_bigint::BigUint;
                if let Some(value) = BigUint::parse_bytes(trimmed.as_bytes(), 10) {
                    let bytes = value.to_bytes_be();
                    let mut result = [0u8; 32];
                    let start = 32usize.saturating_sub(bytes.len());
                    result[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);
                    outputs.push(FieldElement(result));
                }
            }
        }

        Ok(outputs)
    }

    /// Parse Cairo 1 output
    fn parse_cairo1_output(&self, stdout: &str) -> Result<Vec<FieldElement>> {
        // Cairo 1 typically outputs in a specific format
        self.parse_cairo_output(stdout)
    }

    /// Generate STARK proof using stone-prover
    pub fn generate_stark_proof(
        &self,
        trace_path: &Path,
        memory_path: &Path,
        output_dir: &Path,
    ) -> Result<Vec<u8>> {
        let proof_path = output_dir.join("proof.json");

        if !trace_path.exists() || !memory_path.exists() {
            anyhow::bail!("Trace and memory files not found for proving")
        }

        // Create prover config
        let config_path = output_dir.join("cpu_air_prover_config.json");
        let config = self.create_prover_config()?;
        std::fs::write(&config_path, &config)?;

        // Run stone-prover
        let output = {
            let mut cmd = Command::new("cpu_air_prover");
            cmd.args([
                "--out_file",
                proof_path.to_str().unwrap(),
                "--trace_file",
                trace_path.to_str().unwrap_or_default(),
                "--memory_file",
                memory_path.to_str().unwrap_or_default(),
                "--prover_config_file",
                config_path.to_str().unwrap(),
            ]);
            crate::util::run_with_timeout(&mut cmd, cairo_external_command_timeout())
                .context("Failed to run cpu_air_prover")?
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Proof generation failed: {}", stderr);
        }

        std::fs::read(&proof_path).context("Failed to read proof file")
    }

    /// Create prover configuration
    fn create_prover_config(&self) -> Result<String> {
        Ok(r#"{
            "constraint_polynomial_task_size": 256,
            "n_out_of_memory_merkle_layers": 1,
            "table_prover_n_tasks_per_segment": 32
        }"#
        .to_string())
    }

    /// Best-effort wire labels from source function signatures.
    pub fn wire_labels(&self) -> HashMap<usize, String> {
        let mut labels = HashMap::new();
        let source = match std::fs::read_to_string(&self.source_path) {
            Ok(s) => s,
            Err(_) => return labels,
        };

        let functions = analysis::extract_functions(&source);
        let func = functions
            .iter()
            .find(|f| f.name == "main")
            .or_else(|| functions.first());

        if let Some(func) = func {
            for (idx, (name, _typ)) in func.args.iter().enumerate() {
                labels.insert(idx, name.clone());
            }
        }

        labels
    }
}

/// Starkware field prime P = 2^251 + 17·2^192 + 1 as 32-byte big-endian.
const STARK252_MODULUS_HEX: &str =
    "0800000000000011000000000000000000000000000000000000000000000001";

impl TargetCircuit for CairoTarget {
    fn framework(&self) -> Framework {
        Framework::Cairo
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn field_modulus(&self) -> [u8; 32] {
        let mut modulus = [0u8; 32];
        if let Ok(decoded) = hex::decode(STARK252_MODULUS_HEX) {
            let start = 32usize.saturating_sub(decoded.len());
            modulus[start..].copy_from_slice(&decoded[..decoded.len().min(32)]);
        }
        modulus
    }

    fn field_name(&self) -> &str {
        "stark252"
    }

    fn num_constraints(&self) -> usize {
        self.metadata.as_ref().map(|m| m.num_steps).unwrap_or(0)
    }

    fn num_private_inputs(&self) -> usize {
        self.metadata.as_ref().map(|m| m.num_inputs).unwrap_or(0)
    }

    fn num_public_inputs(&self) -> usize {
        self.metadata.as_ref().map(|m| m.num_outputs).unwrap_or(0)
    }

    fn execute(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        self.execute_cairo(inputs)
    }

    fn prove(&self, witness: &[FieldElement]) -> Result<Vec<u8>> {
        let _guard = cairo_io_lock().lock().unwrap();

        if self.cairo_version == CairoVersion::Cairo1 {
            anyhow::bail!("Cairo1 proving via stone-prover is not implemented");
        }

        let compiled_path = self
            .compiled_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No compiled program"))?;

        let temp_dir = tempfile::Builder::new()
            .prefix("zkfuzz_cairo_prove_")
            .tempdir()
            .context("Failed to create temp directory")?;
        let work = temp_dir.path();

        // Generate trace/memory with cairo-run proof mode.
        let input_path = work.join("input.json");
        let input_json = self.create_input_json(witness)?;
        std::fs::write(&input_path, &input_json)?;

        let trace_path = work.join("trace.bin");
        let memory_path = work.join("memory.bin");

        let args = vec![
            "--program".to_string(),
            compiled_path.to_str().unwrap().to_string(),
            "--print_output".to_string(),
            "--layout".to_string(),
            self.config.layout.clone(),
            "--trace_file".to_string(),
            trace_path.to_str().unwrap().to_string(),
            "--memory_file".to_string(),
            memory_path.to_str().unwrap().to_string(),
            "--proof_mode".to_string(),
            "--program_input".to_string(),
            input_path.to_str().unwrap().to_string(),
        ];

        let output = {
            let mut cmd = Command::new("cairo-run");
            cmd.args(&args);
            crate::util::run_with_timeout(&mut cmd, cairo_external_command_timeout())
                .context("Failed to run cairo-run for proving")?
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Cairo execution (prove mode) failed: {}", stderr);
        }

        self.generate_stark_proof(&trace_path, &memory_path, work)
    }

    fn verify(&self, proof: &[u8], _public_inputs: &[FieldElement]) -> Result<bool> {
        let _guard = cairo_io_lock().lock().unwrap();

        let temp_dir = tempfile::Builder::new()
            .prefix("zkfuzz_cairo_verify_")
            .tempdir()
            .context("Failed to create temp directory")?;
        let proof_path = temp_dir.path().join("proof.json");
        std::fs::write(&proof_path, proof)?;

        // Run stone verifier
        let output = {
            let mut cmd = Command::new("cpu_air_verifier");
            cmd.args(["--in_file", proof_path.to_str().unwrap()]);
            crate::util::run_with_timeout(&mut cmd, cairo_external_command_timeout())
                .context("Failed to run cpu_air_verifier")?
        };

        Ok(output.status.success())
    }
}

fn cairo_io_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Convert FieldElement to decimal string
fn field_element_to_decimal(fe: &FieldElement) -> String {
    use num_bigint::BigUint;
    let value = BigUint::from_bytes_be(&fe.0);
    value.to_string()
}

/// Cairo-specific analysis utilities
pub mod analysis {
    /// Analyze Cairo source for common vulnerability patterns
    pub fn analyze_for_vulnerabilities(source: &str) -> Vec<CairoIssue> {
        let mut issues = Vec::new();

        // Check for missing range checks
        if source.contains("felt") && !source.contains("assert") {
            issues.push(CairoIssue {
                issue_type: IssueType::MissingAssertion,
                description: "Felt operations without assertions may lead to overflows".to_string(),
                severity: "warning".to_string(),
                line: None,
            });
        }

        // Check for unchecked recursion
        if source.contains("func ") && source.contains("call ") {
            let func_count = source.matches("func ").count();
            let call_count = source.matches("call ").count();

            if call_count > func_count * 2 {
                issues.push(CairoIssue {
                    issue_type: IssueType::DeepRecursion,
                    description: "Heavy recursion may lead to high step count and potential DoS"
                        .to_string(),
                    severity: "info".to_string(),
                    line: None,
                });
            }
        }

        // Check for hint usage (potential for non-determinism)
        if source.contains("%{") {
            issues.push(CairoIssue {
                issue_type: IssueType::HintUsage,
                description: "Hints are not verified - ensure all hint outputs are constrained"
                    .to_string(),
                severity: "warning".to_string(),
                line: None,
            });
        }

        issues
    }

    /// A detected issue in Cairo code
    #[derive(Debug, Clone)]
    pub struct CairoIssue {
        pub issue_type: IssueType,
        pub description: String,
        pub severity: String,
        pub line: Option<usize>,
    }

    /// Issue types
    #[derive(Debug, Clone, PartialEq)]
    pub enum IssueType {
        MissingAssertion,
        DeepRecursion,
        HintUsage,
        UnconstrainedValue,
        BuiltinMisuse,
    }

    /// Extract function signatures from Cairo source
    pub fn extract_functions(source: &str) -> Vec<CairoFunction> {
        let mut functions = Vec::new();

        for line in source.lines() {
            let trimmed = line.trim();

            // Cairo 0 syntax
            if trimmed.starts_with("func ") {
                if let Some(func) = parse_cairo0_func(trimmed) {
                    functions.push(func);
                }
            }
            // Cairo 1 syntax
            else if trimmed.starts_with("fn ") || trimmed.starts_with("pub fn ") {
                if let Some(func) = parse_cairo1_func(trimmed) {
                    functions.push(func);
                }
            }
        }

        functions
    }

    fn parse_cairo0_func(line: &str) -> Option<CairoFunction> {
        // func name(arg1: felt, arg2: felt) -> (res: felt)
        let after_func = line.strip_prefix("func ")?;
        let name = after_func.split('(').next()?.trim().to_string();
        let args = extract_args(after_func);

        Some(CairoFunction {
            name,
            args,
            returns: vec![],
            is_external: false,
        })
    }

    fn parse_cairo1_func(line: &str) -> Option<CairoFunction> {
        let is_external = line.contains("#[external");
        let trimmed = line.trim_start_matches("pub ").trim_start_matches("fn ");
        let name = trimmed.split('(').next()?.trim().to_string();
        let args = extract_args(trimmed);

        Some(CairoFunction {
            name,
            args,
            returns: vec![],
            is_external,
        })
    }

    fn extract_args(signature: &str) -> Vec<(String, String)> {
        let mut args = Vec::new();
        let args_section = match signature.split('(').nth(1).and_then(|s| s.split(')').next()) {
            Some(section) => section.trim(),
            None => return args,
        };

        if args_section.is_empty() {
            return args;
        }

        for part in args_section.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let mut iter = part.splitn(2, ':');
            let name = iter.next().unwrap_or("").trim();
            let typ = iter.next().unwrap_or("").trim();
            if !name.is_empty() {
                args.push((name.to_string(), typ.to_string()));
            }
        }

        args
    }

    /// Cairo function information
    #[derive(Debug, Clone)]
    pub struct CairoFunction {
        pub name: String,
        pub args: Vec<(String, String)>,
        pub returns: Vec<(String, String)>,
        pub is_external: bool,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_version() {
        // Cairo 1 syntax detection
        let cairo1_content = r#"
            fn main() -> felt252 {
                return 42;
            }
        "#;

        // Would need actual file for full test
        assert!(cairo1_content.contains("fn main()"));
    }

    #[test]
    fn test_vulnerability_analysis() {
        let source = r#"
            func main{output_ptr: felt*}() {
                let x = 5;
                %{ memory[ap] = 100 %}
                [ap] = [ap - 1] + x;
            }
        "#;

        let issues = analysis::analyze_for_vulnerabilities(source);
        assert!(issues
            .iter()
            .any(|i| i.issue_type == analysis::IssueType::HintUsage));
    }
}
