//! Circom circuit target implementation
//!
//! Provides full integration with the Circom ecosystem:
//! - Compilation via circom CLI
//! - Witness generation via generated WASM
//! - Proof generation/verification via snarkjs-compatible format

use crate::TargetCircuit;
use zk_core::Framework;
use zk_core::ConstraintEquation;
use zk_core::FieldElement;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use tempfile::Builder;

/// Circom circuit target with full backend integration
pub struct CircomTarget {
    /// Path to the circom source file
    circuit_path: PathBuf,
    /// Main component name
    main_component: String,
    /// Compiled circuit metadata
    metadata: Option<CircomMetadata>,
    /// Build directory for compiled artifacts
    build_dir: PathBuf,
    /// Whether the circuit has been compiled
    compiled: bool,
    /// Cached witness calculator (WASM instance)
    witness_calculator: Option<WitnessCalculator>,
    /// Proving key path
    proving_key_path: Option<PathBuf>,
    /// Verification key path
    verification_key_path: Option<PathBuf>,
    /// Extra include paths for circom (-l)
    include_paths: Vec<PathBuf>,
    /// Optional override path for powers of tau
    ptau_path_override: Option<PathBuf>,
    /// Optional override path for snarkjs CLI
    snarkjs_path_override: Option<PathBuf>,
    /// If true, reuse existing build artifacts instead of recompiling
    skip_compile_if_artifacts: bool,
}

/// Metadata extracted from compiled Circom circuit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircomMetadata {
    /// Number of constraints in the R1CS
    pub num_constraints: usize,
    /// Number of private inputs
    pub num_private_inputs: usize,
    /// Number of public inputs
    pub num_public_inputs: usize,
    /// Number of outputs
    pub num_outputs: usize,
    /// Signal names and their indices
    pub signals: HashMap<String, usize>,
    /// Input signal names
    pub input_signals: Vec<String>,
    /// Input signal array sizes (None for scalar inputs)
    #[serde(default)]
    pub input_signal_sizes: HashMap<String, Option<usize>>,
    /// Input signal indices (ordered, public first)
    pub input_signal_indices: Vec<usize>,
    /// Public input signal indices
    pub public_input_indices: Vec<usize>,
    /// Private input signal indices
    pub private_input_indices: Vec<usize>,
    /// Output signal names
    pub output_signals: Vec<String>,
    /// Output signal indices
    pub output_signal_indices: Vec<usize>,
    /// Prime field used
    pub prime: String,
}

#[derive(Default)]
struct CircomIoInfo {
    input_signals: Vec<analysis::SignalInfo>,
    output_signals: Vec<analysis::SignalInfo>,
    public_inputs: Vec<String>,
}

#[derive(Debug)]
struct BuildDirLock {
    #[allow(dead_code)]
    path: PathBuf,
    file: File,
}

impl BuildDirLock {
    fn acquire(build_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(build_dir)?;
        let path = build_dir.join(".zkfuzz_build.lock");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .with_context(|| format!("Failed to open build lock file: {}", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("Failed to lock build dir: {}", build_dir.display()));
            }
        }

        // Helpful metadata for humans. Not required for correctness.
        let _ = file.set_len(0);
        let _ = writeln!(file, "pid={}", std::process::id());
        let _ = file.sync_all();

        Ok(Self { path, file })
    }
}

impl Drop for BuildDirLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

fn map_signal_index(signals: &HashMap<String, usize>, name: &str) -> Option<usize> {
    let with_main = format!("main.{}", name);
    signals
        .get(&with_main)
        .or_else(|| signals.get(name))
        .copied()
}

fn infer_array_size(signals: &HashMap<String, usize>, name: &str) -> Option<usize> {
    let prefixes = [format!("main.{}[", name), format!("{}[", name)];

    let mut max_index: Option<usize> = None;
    for key in signals.keys() {
        for prefix in &prefixes {
            if let Some(rest) = key.strip_prefix(prefix) {
                if let Some(close_idx) = rest.find(']') {
                    if let Ok(idx) = rest[..close_idx].parse::<usize>() {
                        max_index = Some(max_index.map(|v| v.max(idx)).unwrap_or(idx));
                    }
                }
            }
        }
    }

    max_index.map(|idx| idx + 1)
}

fn split_array_index(name: &str) -> Option<(&str, usize)> {
    let open = name.rfind('[')?;
    let close = name.rfind(']')?;
    if close <= open {
        return None;
    }
    let idx_str = &name[open + 1..close];
    if idx_str.is_empty() {
        return None;
    }
    let idx = idx_str.parse::<usize>().ok()?;
    Some((&name[..open], idx))
}

fn infer_io_from_symbols(
    sym_list: &[(usize, String)],
    num_outputs: usize,
    num_public_inputs: usize,
    num_private_inputs: usize,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let total = num_outputs
        .saturating_add(num_public_inputs)
        .saturating_add(num_private_inputs);
    if total == 0 {
        return (Vec::new(), Vec::new(), Vec::new());
    }

    let mut top_level = Vec::new();
    for (_, name) in sym_list {
        let Some(rest) = name.strip_prefix("main.") else {
            continue;
        };
        if rest.contains('.') {
            continue;
        }
        top_level.push(rest.to_string());
        if top_level.len() >= total {
            break;
        }
    }

    if top_level.is_empty() {
        return (Vec::new(), Vec::new(), Vec::new());
    }

    let outputs_end = num_outputs.min(top_level.len());
    let public_end = outputs_end.saturating_add(num_public_inputs).min(top_level.len());

    let outputs = top_level[..outputs_end].to_vec();
    let public_inputs = top_level[outputs_end..public_end].to_vec();
    let private_inputs = top_level[public_end..].to_vec();

    (outputs, public_inputs, private_inputs)
}

/// Witness calculator using compiled WASM
struct WitnessCalculator {
    /// Path to the WASM file
    wasm_path: PathBuf,
    /// Optional override path for snarkjs CLI
    snarkjs_path: Option<PathBuf>,
}

fn create_temp_dir() -> Result<tempfile::TempDir> {
    Builder::new()
        .prefix("zkfuzzer_")
        .tempdir()
        .context("Failed to create temp directory")
}

fn maybe_prepare_circom2_source(
    source: &str,
    circuit_path: &Path,
    main_component: &str,
) -> Result<(PathBuf, Option<tempfile::TempDir>)> {
    let mut has_pragma = false;
    let mut pragma_legacy = false;
    let mut needs_semicolon_fix = false;

    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("pragma circom") {
            has_pragma = true;
            if trimmed.contains("pragma circom 1") {
                pragma_legacy = true;
            }
        }
        if (trimmed.contains("===") || trimmed.contains("<==")) && !trimmed.ends_with(';') {
            needs_semicolon_fix = true;
        }
    }

    let has_private_inputs = source.contains("signal private input");
    let needs_rewrite = has_private_inputs || !has_pragma || pragma_legacy || needs_semicolon_fix;

    if !needs_rewrite {
        return Ok((circuit_path.to_path_buf(), None));
    }

    let mut public_inputs = Vec::new();
    for signal in analysis::extract_signals(source) {
        if matches!(signal.direction, analysis::SignalDirection::Input) && signal.is_public {
            public_inputs.push(signal.name);
        }
    }
    public_inputs.sort();
    public_inputs.dedup();

    let temp_dir = create_temp_dir()?;
    let mut cache = HashMap::new();
    let converted_path = convert_circom_file(
        circuit_path,
        &temp_dir,
        &mut cache,
        main_component,
        Some(&public_inputs),
        true,
    )?;

    tracing::info!(
        "Using circom2-compat source for {}",
        circuit_path.display()
    );

    Ok((converted_path, Some(temp_dir)))
}

fn convert_circom_file(
    path: &Path,
    temp_dir: &tempfile::TempDir,
    cache: &mut HashMap<PathBuf, PathBuf>,
    main_component: &str,
    public_inputs: Option<&[String]>,
    is_root: bool,
) -> Result<PathBuf> {
    if let Some(existing) = cache.get(path) {
        return Ok(existing.clone());
    }

    let filename = if is_root {
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_else(|| main_component)
            .to_string()
    } else {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("circom");
        let hash = hash_path(path);
        format!("{stem}_{hash}.circom")
    };

    let temp_path = temp_dir.path().join(filename);
    cache.insert(path.to_path_buf(), temp_path.clone());

    let source = std::fs::read_to_string(path)?;
    let mut out_lines = Vec::new();

    let mut has_pragma = false;
    for line in source.lines() {
        if line.trim().starts_with("pragma circom") {
            has_pragma = true;
            break;
        }
    }
    if is_root && !has_pragma {
        out_lines.push("pragma circom 2.0.0;".to_string());
    }

    let mut main_rewritten = false;
    let source_dir = path.parent().unwrap_or(Path::new("."));

    for line in source.lines() {
        let trimmed = line.trim();
        if is_root && trimmed.starts_with("pragma circom") {
            out_lines.push("pragma circom 2.0.0;".to_string());
            continue;
        }

        let mut updated = line.replace("signal private input", "signal input");
        updated = updated.replace("MiMCSponge(2, 1)", "MiMCSponge(2, 220, 1)");
        updated = updated.replace("MiMCSponge(2,1)", "MiMCSponge(2,220,1)");
        let mut updated_trimmed = updated.trim_start().to_string();

        if updated_trimmed.starts_with("include ") {
            if let Some((path_str, quote)) = extract_include_path(&updated_trimmed) {
                let include_path = Path::new(&path_str);
                let resolved = if include_path.is_relative() {
                    source_dir.join(include_path)
                } else {
                    include_path.to_path_buf()
                };
                let converted = convert_circom_file(
                    &resolved,
                    temp_dir,
                    cache,
                    main_component,
                    None,
                    false,
                )?;
                let converted_str = converted.to_string_lossy();
                let needle = format!("{quote}{path_str}{quote}");
                let replacement = format!("{quote}{converted_str}{quote}");
                updated = updated.replace(&needle, &replacement);
                updated_trimmed = updated.trim_start().to_string();
            }
        }

        if is_root
            && !main_rewritten
            && updated_trimmed.starts_with("component main")
            && !updated_trimmed.contains("public")
        {
            if let Some(public_inputs) = public_inputs {
                if !public_inputs.is_empty() {
                    if let Some((lhs, rhs)) = updated.split_once('=') {
                        let indent = lhs
                            .chars()
                            .take_while(|c| c.is_whitespace())
                            .collect::<String>();
                        let rhs_trimmed = rhs.trim().trim_end_matches(';');
                        let list = public_inputs.join(", ");
                        updated = format!(
                            "{indent}component main {{ public [{list}] }} = {rhs_trimmed};"
                        );
                        main_rewritten = true;
                    }
                }
            }
        }

        if needs_semicolon(&updated_trimmed) {
            updated.push(';');
        }

        out_lines.push(updated);
    }

    std::fs::write(&temp_path, out_lines.join("\n"))?;

    Ok(temp_path)
}

fn needs_semicolon(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("/*") {
        return false;
    }
    if trimmed.ends_with(';') || trimmed.ends_with('{') || trimmed.ends_with('}') {
        return false;
    }
    if trimmed.ends_with('+')
        || trimmed.ends_with('-')
        || trimmed.ends_with('*')
        || trimmed.ends_with('/')
        || trimmed.ends_with('(')
        || trimmed.ends_with(',')
    {
        return false;
    }
    trimmed.contains("===") || trimmed.contains("<==")
}

fn hash_path(path: &Path) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    path.to_string_lossy().hash(&mut hasher);
    hasher.finish()
}

fn extract_include_path(line: &str) -> Option<(String, char)> {
    let quote = if line.contains('\"') { '\"' } else { '\'' };
    let start = line.find(quote)? + 1;
    let rest = &line[start..];
    let end = rest.find(quote)?;
    Some((rest[..end].to_string(), quote))
}

fn is_js_cli(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("js") | Some("cjs") | Some("mjs")
    )
}

fn snarkjs_command_for(path: Option<&Path>) -> Command {
    match path {
        Some(path) if is_js_cli(path) => {
            let mut cmd = Command::new("node");
            cmd.arg(path);
            cmd
        }
        Some(path) => Command::new(path),
        None => {
            let mut cmd = Command::new("npx");
            cmd.arg("snarkjs");
            cmd
        }
    }
}

fn circom_io_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

impl WitnessCalculator {
    fn new(wasm_path: PathBuf, snarkjs_path: Option<PathBuf>) -> Self {
        Self {
            wasm_path,
            snarkjs_path,
        }
    }

    /// Calculate witness using node.js and snarkjs
    fn calculate(&self, inputs: &HashMap<String, Vec<String>>) -> Result<Vec<FieldElement>> {
        // Create temporary input file
        let temp_dir = create_temp_dir()?;
        let temp_path = temp_dir.path();

        let input_path = temp_path.join("input.json");
        let witness_path = temp_path.join("witness.wtns");
        let witness_json_path = temp_path.join("witness.json");

        // Write inputs to JSON
        let input_json = serde_json::to_string(inputs)?;
        std::fs::write(&input_path, &input_json)?;

        // Prefer the generated witness_calculator.js when available to avoid snarkjs CLI hangs.
        // This uses the same WASM witness calculator generated by circom.
        if let Some(wasm_dir) = self.wasm_path.parent() {
            let witness_calculator_path = wasm_dir.join("witness_calculator.js");
            if witness_calculator_path.exists() {
                let script_path = temp_path.join("calc_witness.js");
                let input_js = serde_json::to_string(
                    input_path.to_str().unwrap_or_default()
                )?;
                let wasm_js = serde_json::to_string(
                    self.wasm_path.to_str().unwrap_or_default()
                )?;
                let wc_js = serde_json::to_string(
                    witness_calculator_path.to_str().unwrap_or_default()
                )?;
                let out_js = serde_json::to_string(
                    witness_json_path.to_str().unwrap_or_default()
                )?;

                let script = format!(
                    "const wc = require({wc_js});\n\
const fs = require('fs');\n\
const input = JSON.parse(fs.readFileSync({input_js}, 'utf8'));\n\
const wasm = fs.readFileSync({wasm_js});\n\
wc(wasm).then(async (calc) => {{\n\
  const witness = await calc.calculateWitness(input, 0);\n\
  const witnessStr = witness.map((v) => v.toString());\n\
  fs.writeFileSync({out_js}, JSON.stringify(witnessStr));\n\
}}).catch((err) => {{\n\
  console.error(err);\n\
  process.exit(1);\n\
}});\n"
                );
                std::fs::write(&script_path, script)?;

                let output = Command::new("node")
                    .arg(&script_path)
                    .output()
                    .context("Failed to run witness calculator")?;

                if output.status.success() && witness_json_path.exists() {
                    let witness_json = std::fs::read_to_string(&witness_json_path)?;
                    let witness_values: Vec<String> = serde_json::from_str(&witness_json)?;
                    let witness: Vec<FieldElement> = witness_values
                        .iter()
                        .map(|v| parse_decimal_to_field_element(v))
                        .collect::<Result<Vec<_>>>()?;
                    return Ok(witness);
                }
            }
        }

        // Run witness generation using snarkjs
        let output = snarkjs_command_for(self.snarkjs_path.as_deref())
            .args([
                "wtns",
                "calculate",
                self.wasm_path.to_str().unwrap(),
                input_path.to_str().unwrap(),
                witness_path.to_str().unwrap(),
            ])
            .output()
            .context("Failed to run snarkjs witness calculation")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Witness calculation failed: {}", stderr);
        }

        // Export witness to JSON for parsing
        let output = snarkjs_command_for(self.snarkjs_path.as_deref())
            .args([
                "wtns",
                "export",
                "json",
                witness_path.to_str().unwrap(),
                witness_json_path.to_str().unwrap(),
            ])
            .output()
            .context("Failed to export witness to JSON")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Witness export failed: {}", stderr);
        }

        // Parse witness JSON
        let witness_json = std::fs::read_to_string(&witness_json_path)?;
        let witness_values: Vec<String> = serde_json::from_str(&witness_json)?;

        // Convert to FieldElements
        let witness: Vec<FieldElement> = witness_values
            .iter()
            .map(|v| parse_decimal_to_field_element(v))
            .collect::<Result<Vec<_>>>()?;

        Ok(witness)
    }
}

impl CircomTarget {
    /// Create a new Circom target from a circuit file
    pub fn new(circuit_path: &str, main_component: &str) -> Result<Self> {
        let path = PathBuf::from(circuit_path);

        // Create build directory next to the circuit
        // Note: circom outputs files based on source filename, not template name
        let build_dir = path.parent().unwrap_or(Path::new(".")).join("build");

        Ok(Self {
            circuit_path: path,
            main_component: main_component.to_string(),
            metadata: None,
            build_dir,
            compiled: false,
            witness_calculator: None,
            proving_key_path: None,
            verification_key_path: None,
            include_paths: Vec::new(),
            ptau_path_override: None,
            snarkjs_path_override: None,
            skip_compile_if_artifacts: false,
        })
    }

    /// Get the base name for output files (derived from source filename)
    fn output_basename(&self) -> String {
        self.circuit_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(&self.main_component)
            .to_string()
    }

    /// Create with custom build directory
    pub fn with_build_dir(mut self, build_dir: PathBuf) -> Self {
        self.build_dir = build_dir;
        self
    }

    /// Reuse existing build artifacts (r1cs/wasm) when present
    pub fn with_skip_compile_if_artifacts(mut self, skip: bool) -> Self {
        self.skip_compile_if_artifacts = skip;
        self
    }

    /// Add include paths for circom compilation (-l)
    pub fn with_include_paths(mut self, include_paths: Vec<PathBuf>) -> Self {
        self.include_paths = include_paths;
        self
    }

    /// Override the powers of tau file location for Groth16 setup
    pub fn with_ptau_path(mut self, ptau_path: PathBuf) -> Self {
        self.ptau_path_override = Some(ptau_path);
        self
    }

    /// Override the snarkjs CLI location (binary or JS file)
    pub fn with_snarkjs_path(mut self, snarkjs_path: PathBuf) -> Self {
        self.snarkjs_path_override = Some(snarkjs_path);
        self
    }

    /// Check if circom is available
    pub fn check_circom_available() -> Result<String> {
        let output = Command::new("circom")
            .arg("--version")
            .output()
            .context("circom not found in PATH")?;

        if !output.status.success() {
            anyhow::bail!("circom --version failed");
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Check if snarkjs is available
    pub fn check_snarkjs_available() -> Result<String> {
        let output = snarkjs_command_for(None)
            .arg("--version")
            .output()
            .context("snarkjs not found")?;

        // snarkjs may return version on stdout or stderr
        let version = if output.status.success() {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        } else {
            String::from_utf8_lossy(&output.stderr).trim().to_string()
        };

        Ok(version)
    }

    /// Compile the circuit to R1CS and generate WASM witness calculator
    pub fn compile(&mut self) -> Result<()> {
        if self.compiled {
            return Ok(());
        }

        // Ensure build dir exists and prevent cross-process artifact races/collisions.
        // This allows running multiple zk-fuzzer processes in parallel as long as they
        // do not intentionally share the same build dir for different circuits.
        let _build_lock = BuildDirLock::acquire(&self.build_dir)?;

        // In-process IO lock to avoid concurrent circom/snarkjs calls stepping on each other.
        let _guard = circom_io_lock().lock().unwrap();

        let basename = self.output_basename();
        let r1cs_path = self.build_dir.join(format!("{}.r1cs", basename));
        let wasm_path = self
            .build_dir
            .join(format!("{}_js", basename))
            .join(format!("{}.wasm", basename));

        if self.skip_compile_if_artifacts && r1cs_path.exists() && wasm_path.exists() {
            tracing::info!(
                "Skipping circom compile; using existing artifacts in {:?}",
                self.build_dir
            );
            self.parse_r1cs_info()?;
            self.witness_calculator = Some(WitnessCalculator::new(
                wasm_path,
                self.snarkjs_path_override.clone(),
            ));
            self.compiled = true;
            return Ok(());
        }

        tracing::info!("Compiling Circom circuit: {:?}", self.circuit_path);

        // Check circom is available
        let circom_version = Self::check_circom_available()?;
        tracing::debug!("Using circom: {}", circom_version);

        let source = std::fs::read_to_string(&self.circuit_path)?;
        let (compile_path, _temp_dir) = maybe_prepare_circom2_source(
            &source,
            &self.circuit_path,
            &self.main_component,
        )?;

        // Compile circuit
        let mut cmd = Command::new("circom");
        for include in &self.include_paths {
            cmd.arg("-l").arg(include);
        }
        let output = cmd
            .args([
                compile_path.to_str().unwrap(),
                "--r1cs",
                "--wasm",
                "--sym",
                "--json",
                "-o",
                self.build_dir.to_str().unwrap(),
            ])
            .output()
            .context("Failed to run circom compiler")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Circom compilation failed: {}", stderr);
        }

        tracing::info!("Circom compilation successful");

        // Parse R1CS info to get metadata
        self.parse_r1cs_info()?;

        // Setup witness calculator
        // circom outputs: {basename}_js/{basename}.wasm
        let wasm_path = self
            .build_dir
            .join(format!("{}_js", basename))
            .join(format!("{}.wasm", basename));

        if wasm_path.exists() {
            self.witness_calculator = Some(WitnessCalculator::new(
                wasm_path,
                self.snarkjs_path_override.clone(),
            ));
        } else {
            tracing::warn!(
                "WASM file not found at expected path {:?}, witness calculation may fail",
                wasm_path
            );
        }

        self.compiled = true;
        Ok(())
    }

    /// Parse IO information from the source file
    fn parse_io_info(&self) -> Result<CircomIoInfo> {
        let source = std::fs::read_to_string(&self.circuit_path)?;
        let signals = analysis::extract_signals(&source);

        let mut input_signals = Vec::new();
        let mut output_signals = Vec::new();

        for signal in signals {
            match signal.direction {
                analysis::SignalDirection::Input => input_signals.push(signal),
                analysis::SignalDirection::Output => output_signals.push(signal),
                analysis::SignalDirection::Intermediate => {}
            }
        }

        let public_inputs = analysis::extract_public_inputs(&source);

        Ok(CircomIoInfo {
            input_signals,
            output_signals,
            public_inputs,
        })
    }

    /// Parse R1CS info to extract metadata
    fn parse_r1cs_info(&mut self) -> Result<()> {
        let basename = self.output_basename();
        let r1cs_path = self.build_dir.join(format!("{}.r1cs", basename));

        if !r1cs_path.exists() {
            tracing::warn!("R1CS file not found: {:?}", r1cs_path);
            return Ok(());
        }

        // Use snarkjs to get R1CS info
        let output = snarkjs_command_for(self.snarkjs_path_override.as_deref())
            .args(["r1cs", "info", r1cs_path.to_str().unwrap()])
            .output()
            .context("Failed to get R1CS info")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Failed to parse R1CS info: {}", stderr);
            return Ok(());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse the output to extract constraint count
        let mut num_constraints = 0;
        let mut num_private_inputs = 0;
        let mut num_public_inputs = 0;
        let mut num_outputs = 0;

        // Parse the snarkjs output which looks like:
        // [INFO]  snarkJS: # of Constraints: 1
        // [INFO]  snarkJS: # of Private Inputs: 2
        // We need to extract the last colon-separated value
        for line in stdout.lines() {
            // Get the value after the last colon
            if let Some(last_colon_idx) = line.rfind(':') {
                let value_str = line[last_colon_idx + 1..].trim();

                if line.contains("Constraints") {
                    num_constraints = value_str.parse().unwrap_or(0);
                } else if line.contains("Private Inputs") {
                    num_private_inputs = value_str.parse().unwrap_or(0);
                } else if line.contains("Public Inputs") {
                    num_public_inputs = value_str.parse().unwrap_or(0);
                } else if line.contains("Outputs")
                    && !line.contains("Public")
                    && !line.contains("Private")
                {
                    num_outputs = value_str.parse().unwrap_or(0);
                }
            }
        }

        // Also parse the symbols file for signal names
        let sym_path = self.build_dir.join(format!("{}.sym", basename));
        let (signals, sym_list) = if sym_path.exists() {
            (
                self.parse_symbols_file(&sym_path)?,
                self.parse_symbols_list(&sym_path)?,
            )
        } else {
            (HashMap::new(), Vec::new())
        };

        let io_info = self.parse_io_info().unwrap_or_else(|e| {
            tracing::warn!("Failed to parse Circom IO metadata: {}", e);
            CircomIoInfo::default()
        });

        let mut input_names: Vec<String> = io_info
            .input_signals
            .iter()
            .map(|s| s.name.clone())
            .collect();
        let mut output_names: Vec<String> = io_info
            .output_signals
            .iter()
            .map(|s| s.name.clone())
            .collect();

        let mut public_inputs: Vec<String> = io_info.public_inputs;
        let mut inferred_io: Option<(Vec<String>, Vec<String>, Vec<String>)> = None;

        if !sym_list.is_empty() {
            let (sym_outputs, sym_public, sym_private) = infer_io_from_symbols(
                &sym_list,
                num_outputs,
                num_public_inputs,
                num_private_inputs,
            );
            let sym_counts_match = sym_public.len() == num_public_inputs
                && sym_private.len() == num_private_inputs;

            if sym_counts_match || input_names.is_empty() {
                if !sym_outputs.is_empty() {
                    output_names = sym_outputs;
                }
                if !sym_public.is_empty() {
                    public_inputs = sym_public.clone();
                }
                input_names = sym_public
                    .iter()
                    .chain(sym_private.iter())
                    .cloned()
                    .collect();
                inferred_io = Some((output_names.clone(), public_inputs.clone(), sym_private));
            }
        }
        let public_set: HashSet<String> = public_inputs.iter().cloned().collect();

        let mut ordered_inputs = Vec::new();
        if let Some((_, pub_inputs, priv_inputs)) = inferred_io {
            ordered_inputs.extend(pub_inputs);
            ordered_inputs.extend(priv_inputs);
        } else {
            for name in &public_inputs {
                if input_names.contains(name) {
                    ordered_inputs.push(name.clone());
                }
            }
            for name in &input_names {
                if !public_set.contains(name) {
                    ordered_inputs.push(name.clone());
                }
            }
        }

        let input_signal_indices: Vec<usize> = ordered_inputs
            .iter()
            .filter_map(|name| map_signal_index(&signals, name))
            .collect();
        let public_input_indices: Vec<usize> = public_inputs
            .iter()
            .filter_map(|name| map_signal_index(&signals, name))
            .collect();
        let private_input_indices: Vec<usize> = ordered_inputs
            .iter()
            .filter(|name| !public_set.contains(*name))
            .filter_map(|name| map_signal_index(&signals, name))
            .collect();
        let output_signal_indices: Vec<usize> = output_names
            .iter()
            .filter_map(|name| map_signal_index(&signals, name))
            .collect();

        let mut input_signal_sizes = HashMap::new();
        if io_info.input_signals.is_empty() {
            for name in &ordered_inputs {
                let inferred = infer_array_size(&signals, name);
                input_signal_sizes.insert(name.clone(), inferred);
            }
        } else {
            for signal in &io_info.input_signals {
                let inferred = infer_array_size(&signals, &signal.name);
                let size = signal.array_size.or(inferred);
                input_signal_sizes.insert(signal.name.clone(), size);
            }
        }

        self.metadata = Some(CircomMetadata {
            num_constraints,
            num_private_inputs,
            num_public_inputs: public_input_indices.len(),
            num_outputs: output_signal_indices.len().max(num_outputs),
            signals,
            input_signals: ordered_inputs,
            input_signal_sizes,
            input_signal_indices,
            public_input_indices,
            private_input_indices,
            output_signals: output_names,
            output_signal_indices,
            prime: "bn128".to_string(),
        });

        tracing::info!(
            "Circuit has {} constraints, {} private inputs, {} public inputs",
            num_constraints,
            num_private_inputs,
            num_public_inputs
        );

        Ok(())
    }

    /// Parse the symbols file to get signal names
    fn parse_symbols_file(&self, path: &Path) -> Result<HashMap<String, usize>> {
        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut signals = HashMap::new();

        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 4 {
                let index: usize = parts[0].parse().unwrap_or(0);
                let name = parts[3].to_string();
                signals.insert(name, index);
            }
        }

        Ok(signals)
    }

    fn parse_symbols_list(&self, path: &Path) -> Result<Vec<(usize, String)>> {
        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 4 {
                let index: usize = parts[0].parse().unwrap_or(0);
                let name = parts[3].to_string();
                entries.push((index, name));
            }
        }

        entries.sort_by_key(|(idx, _)| *idx);
        Ok(entries)
    }

    /// Setup proving and verification keys using Groth16
    pub fn setup_keys(&mut self) -> Result<()> {
        // Prevent cross-process writes to the same build dir (zkey/vkey/ptau).
        let _build_lock = BuildDirLock::acquire(&self.build_dir)?;
        let _guard = circom_io_lock().lock().unwrap();
        let basename = self.output_basename();
        let r1cs_path = self.build_dir.join(format!("{}.r1cs", basename));
        let ptau_path = self.find_or_download_ptau()?;

        let zkey_path = self.build_dir.join(format!("{}.zkey", basename));
        let vkey_path = self.build_dir.join(format!("{}_vkey.json", basename));

        // Generate zkey (proving key)
        tracing::info!("Generating proving key...");
        let output = snarkjs_command_for(self.snarkjs_path_override.as_deref())
            .args([
                "groth16",
                "setup",
                r1cs_path.to_str().unwrap(),
                ptau_path.to_str().unwrap(),
                zkey_path.to_str().unwrap(),
            ])
            .output()
            .context("Failed to generate proving key")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Key generation failed: {}", stderr);
        }

        // Export verification key
        tracing::info!("Exporting verification key...");
        let output = snarkjs_command_for(self.snarkjs_path_override.as_deref())
            .args([
                "zkey",
                "export",
                "verificationkey",
                zkey_path.to_str().unwrap(),
                vkey_path.to_str().unwrap(),
            ])
            .output()
            .context("Failed to export verification key")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Verification key export failed: {}", stderr);
        }

        self.proving_key_path = Some(zkey_path);
        self.verification_key_path = Some(vkey_path);

        tracing::info!("Key setup complete");
        Ok(())
    }

    /// Find existing powers of tau file or download a small one
    fn find_or_download_ptau(&self) -> Result<PathBuf> {
        if let Some(path) = &self.ptau_path_override {
            if path.exists() {
                return Ok(path.clone());
            }
            anyhow::bail!("Configured ptau file not found: {:?}", path);
        }
        // Check for existing ptau files
        let ptau_dirs = vec![
            self.build_dir.clone(),
            PathBuf::from("."),
            dirs::home_dir().unwrap_or_default().join(".snarkjs"),
        ];

        for dir in &ptau_dirs {
            for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "ptau") {
                    tracing::info!("Found existing ptau file: {:?}", path);
                    return Ok(path);
                }
            }
        }

        // Download a small ptau file for testing
        let ptau_path = self.build_dir.join("pot12_final.ptau");
        if !ptau_path.exists() {
            tracing::info!("Downloading powers of tau file...");
            let output = Command::new("curl")
                .args([
                    "-L",
                    "-o",
                    ptau_path.to_str().unwrap(),
                    "https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau",
                ])
                .output()
                .context("Failed to download ptau file")?;

            if !output.status.success() {
                anyhow::bail!("Failed to download powers of tau file");
            }
        }

        Ok(ptau_path)
    }

    /// Calculate witness for given inputs
    pub fn calculate_witness(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        let _guard = circom_io_lock().lock().unwrap();
        let calculator = self
            .witness_calculator
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Witness calculator not initialized"))?;

        // Convert inputs to named map based on metadata
        let input_map = self.inputs_to_map(inputs)?;

        calculator.calculate(&input_map)
    }

    /// Convert input array to named signal map
    fn inputs_to_map(&self, inputs: &[FieldElement]) -> Result<HashMap<String, Vec<String>>> {
        let mut map = HashMap::new();

        if let Some(metadata) = &self.metadata {
            static INPUT_MAP_LOG_ONCE: OnceLock<()> = OnceLock::new();
            if INPUT_MAP_LOG_ONCE.set(()).is_ok() {
                tracing::info!(
                    "Circom input mapping: {} values, {} signals (public {}, private {})",
                    inputs.len(),
                    metadata.input_signals.len(),
                    metadata.num_public_inputs,
                    metadata.num_private_inputs
                );
                for name in &metadata.input_signals {
                    let size = metadata
                        .input_signal_sizes
                        .get(name)
                        .copied()
                        .flatten()
                        .unwrap_or(1);
                    tracing::info!("  input '{}' size {}", name, size);
                }
            }

            let mut cursor = 0usize;
            for (i, name) in metadata.input_signals.iter().enumerate() {
                let clean_name = name.strip_prefix("main.").unwrap_or(name).to_string();

                if let Some((base, idx)) = split_array_index(&clean_name) {
                    if cursor >= inputs.len() {
                        anyhow::bail!(
                            "Not enough inputs for signal '{}' (expected {}, got {})",
                            name,
                            idx + 1,
                            inputs.len().saturating_sub(cursor)
                        );
                    }
                    let value = field_element_to_decimal(&inputs[cursor]);
                    let entry = map.entry(base.to_string()).or_insert_with(Vec::new);
                    if entry.len() <= idx {
                        entry.resize(idx + 1, "0".to_string());
                    }
                    entry[idx] = value;
                    cursor += 1;
                    if i == metadata.input_signals.len() - 1 && cursor < inputs.len() {
                        tracing::warn!(
                            "Unused inputs provided: {} extra values",
                            inputs.len().saturating_sub(cursor)
                        );
                    }
                    continue;
                }

                let size = metadata
                    .input_signal_sizes
                    .get(name)
                    .copied()
                    .flatten()
                    .unwrap_or(1);

                if cursor + size > inputs.len() {
                    anyhow::bail!(
                        "Not enough inputs for signal '{}' (expected {}, got {})",
                        name,
                        size,
                        inputs.len().saturating_sub(cursor)
                    );
                }

                let values = inputs[cursor..cursor + size]
                    .iter()
                    .map(field_element_to_decimal)
                    .collect::<Vec<_>>();
                map.insert(clean_name, values);

                cursor += size;
                if i == metadata.input_signals.len() - 1 && cursor < inputs.len() {
                    tracing::warn!(
                        "Unused inputs provided: {} extra values",
                        inputs.len().saturating_sub(cursor)
                    );
                }
            }
        } else {
            // No metadata, use generic names
            for (i, input) in inputs.iter().enumerate() {
                let value = field_element_to_decimal(input);
                map.insert(format!("in{}", i), vec![value]);
            }
        }

        Ok(map)
    }

    fn constraints_json_path(&self) -> PathBuf {
        let basename = self.output_basename();
        self.build_dir
            .join(format!("{}_constraints.json", basename))
    }

    /// Load constraint equations from Circom-generated JSON
    pub fn load_constraints(&self) -> Result<Vec<ConstraintEquation>> {
        let mut constraints_path = self.constraints_json_path();
        let basename = self.output_basename();

        if !constraints_path.exists() {
            let r1cs_path = self.build_dir.join(format!("{}.r1cs", basename));
            if !r1cs_path.exists() {
                return Ok(Vec::new());
            }

            let temp_dir = create_temp_dir()?;
            let temp_path = temp_dir.path().join("constraints.json");

            let output = snarkjs_command_for(self.snarkjs_path_override.as_deref())
                .args([
                    "r1cs",
                    "export",
                    "json",
                    r1cs_path.to_str().unwrap(),
                    temp_path.to_str().unwrap(),
                ])
                .output()
                .context("Failed to export R1CS constraints")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("Constraint export failed: {}", stderr);
            }

            constraints_path = temp_path;
        }

        let contents = std::fs::read_to_string(&constraints_path)?;
        let json: serde_json::Value = serde_json::from_str(&contents)?;
        let constraints = json
            .get("constraints")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow::anyhow!("Invalid constraints JSON format"))?;

        let mut equations = Vec::new();

        for (id, constraint) in constraints.iter().enumerate() {
            let parts = constraint
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("Constraint entry is not an array"))?;
            if parts.len() != 3 {
                continue;
            }

            let a_terms = parse_constraint_terms(&parts[0])?;
            let b_terms = parse_constraint_terms(&parts[1])?;
            let c_terms = parse_constraint_terms(&parts[2])?;

            equations.push(ConstraintEquation {
                id,
                a_terms,
                b_terms,
                c_terms,
                description: Some("circom r1cs".to_string()),
            });
        }

        Ok(equations)
    }

    pub fn public_input_indices(&self) -> Vec<usize> {
        self.metadata
            .as_ref()
            .map(|m| m.public_input_indices.clone())
            .unwrap_or_default()
    }

    pub fn private_input_indices(&self) -> Vec<usize> {
        self.metadata
            .as_ref()
            .map(|m| m.private_input_indices.clone())
            .unwrap_or_default()
    }

    pub fn output_signal_indices(&self) -> Vec<usize> {
        self.metadata
            .as_ref()
            .map(|m| m.output_signal_indices.clone())
            .unwrap_or_default()
    }

    /// Extract outputs from a full witness using metadata when available.
    pub fn outputs_from_witness(&self, witness: &[FieldElement]) -> Vec<FieldElement> {
        if let Some(metadata) = &self.metadata {
            if !metadata.output_signal_indices.is_empty() {
                let mut outputs = Vec::new();
                for idx in &metadata.output_signal_indices {
                    if let Some(value) = witness.get(*idx) {
                        outputs.push(value.clone());
                    }
                }
                if !outputs.is_empty() {
                    return outputs;
                }
            }

            let num_public = metadata.num_public_inputs;
            let num_outputs = metadata.num_outputs.max(1);

            if witness.len() > 1 + num_public + num_outputs {
                return witness[1..1 + num_outputs].to_vec();
            }
        }

        if !witness.is_empty() {
            vec![witness[witness.len() - 1].clone()]
        } else {
            Vec::new()
        }
    }

    /// Get the field name/prime used by this circuit (e.g., bn128/bn254)
    pub fn field_name(&self) -> &str {
        self.metadata
            .as_ref()
            .map(|m| m.prime.as_str())
            .unwrap_or("bn128")
    }

    /// Get wire labels when available (index -> name)
    pub fn wire_labels(&self) -> HashMap<usize, String> {
        let mut labels = HashMap::new();
        if let Some(metadata) = &self.metadata {
            for (name, idx) in &metadata.signals {
                labels.entry(*idx).or_insert_with(|| name.clone());
            }
        }
        labels
    }
}

impl TargetCircuit for CircomTarget {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn name(&self) -> &str {
        &self.main_component
    }

    fn num_constraints(&self) -> usize {
        self.metadata
            .as_ref()
            .map(|m| m.num_constraints)
            .unwrap_or(0)
    }

    fn num_private_inputs(&self) -> usize {
        self.metadata
            .as_ref()
            .map(|m| m.num_private_inputs)
            .unwrap_or(0)
    }

    fn num_public_inputs(&self) -> usize {
        self.metadata
            .as_ref()
            .map(|m| m.num_public_inputs)
            .unwrap_or(0)
    }

    fn execute(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        if !self.compiled {
            anyhow::bail!("Circuit not compiled. Call compile() first.");
        }

        let witness = self.calculate_witness(inputs)?;
        Ok(self.outputs_from_witness(&witness))
    }

    fn prove(&self, witness: &[FieldElement]) -> Result<Vec<u8>> {
        let _guard = circom_io_lock().lock().unwrap();
        let zkey_path = self
            .proving_key_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Proving key not set. Call setup_keys() first."))?;

        let temp_dir = create_temp_dir()?;
        let temp_path = temp_dir.path();

        let witness_path = temp_path.join("witness.wtns");
        let proof_path = temp_path.join("proof.json");
        let public_path = temp_path.join("public.json");

        // First need to create witness file
        // For now, use the WASM-based approach
        let input_map = self.inputs_to_map(witness)?;
        let input_json = serde_json::to_string(&input_map)?;
        let input_path = temp_path.join("input.json");
        std::fs::write(&input_path, &input_json)?;

        if let Some(calc) = &self.witness_calculator {
            let output = snarkjs_command_for(self.snarkjs_path_override.as_deref())
                .args([
                    "wtns",
                    "calculate",
                    calc.wasm_path.to_str().unwrap(),
                    input_path.to_str().unwrap(),
                    witness_path.to_str().unwrap(),
                ])
                .output()
                .context("Failed to calculate witness for proof")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("Witness calculation failed: {}", stderr);
            }
        }

        // Generate proof
        let output = snarkjs_command_for(self.snarkjs_path_override.as_deref())
            .args([
                "groth16",
                "prove",
                zkey_path.to_str().unwrap(),
                witness_path.to_str().unwrap(),
                proof_path.to_str().unwrap(),
                public_path.to_str().unwrap(),
            ])
            .output()
            .context("Failed to generate proof")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Proof generation failed: {}", stderr);
        }

        // Read proof JSON
        let proof_json = std::fs::read_to_string(&proof_path)?;

        Ok(proof_json.into_bytes())
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> Result<bool> {
        let _guard = circom_io_lock().lock().unwrap();
        let vkey_path = self
            .verification_key_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Verification key not set."))?;

        let temp_dir = create_temp_dir()?;
        let temp_path = temp_dir.path();

        let proof_path = temp_path.join("proof.json");
        let public_path = temp_path.join("public.json");

        // Write proof
        std::fs::write(&proof_path, proof)?;

        // Write public inputs
        let public_values: Vec<String> =
            public_inputs.iter().map(field_element_to_decimal).collect();
        let public_json = serde_json::to_string(&public_values)?;
        std::fs::write(&public_path, &public_json)?;

        // Verify
        let output = snarkjs_command_for(self.snarkjs_path_override.as_deref())
            .args([
                "groth16",
                "verify",
                vkey_path.to_str().unwrap(),
                public_path.to_str().unwrap(),
                proof_path.to_str().unwrap(),
            ])
            .output()
            .context("Failed to verify proof")?;

        // snarkjs outputs "OK!" on success
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(output.status.success() && stdout.contains("OK"))
    }
}

fn parse_constraint_terms(value: &serde_json::Value) -> Result<Vec<(usize, FieldElement)>> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Constraint term is not an object"))?;

    let mut terms = Vec::new();
    for (key, val) in obj {
        let idx: usize = key.parse().unwrap_or(0);
        let coeff = match val {
            serde_json::Value::String(s) => parse_decimal_to_field_element(s)?,
            serde_json::Value::Number(n) => parse_decimal_to_field_element(&n.to_string())?,
            _ => parse_decimal_to_field_element("0")?,
        };
        terms.push((idx, coeff));
    }

    terms.sort_by_key(|(idx, _)| *idx);
    Ok(terms)
}

/// Parse a decimal string to FieldElement
fn parse_decimal_to_field_element(s: &str) -> Result<FieldElement> {
    use num_bigint::BigUint;

    let clean = s.trim().trim_matches('"');
    let value = BigUint::parse_bytes(clean.as_bytes(), 10)
        .ok_or_else(|| anyhow::anyhow!("Invalid decimal: {}", s))?;

    let bytes = value.to_bytes_be();
    let mut result = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    let copy_len = bytes.len().min(32);
    result[start..start + copy_len].copy_from_slice(&bytes[..copy_len]);

    Ok(FieldElement(result))
}

/// Convert FieldElement to decimal string
fn field_element_to_decimal(fe: &FieldElement) -> String {
    use num_bigint::BigUint;

    let value = BigUint::from_bytes_be(&fe.0);
    value.to_string()
}

/// Circom-specific analysis utilities
pub mod analysis {
    use super::*;

    /// Extract signal names from a Circom source file
    pub fn extract_signals(source: &str) -> Vec<SignalInfo> {
        let mut signals = Vec::new();

        for line in source.lines() {
            let trimmed = line.trim();

            // Look for signal declarations
            if trimmed.starts_with("signal") {
                if let Some(info) = parse_signal_declaration(trimmed) {
                    signals.push(info);
                }
            }
        }

        signals
    }

    /// Parse a signal declaration line
    fn parse_signal_declaration(line: &str) -> Option<SignalInfo> {
        // signal input x;
        // signal output y;
        // signal private input z;

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }

        let mut direction = SignalDirection::Intermediate;
        let mut is_public = true;
        let mut name_idx = 1;

        for (i, part) in parts.iter().enumerate().skip(1) {
            match *part {
                "input" => {
                    direction = SignalDirection::Input;
                    name_idx = i + 1;
                }
                "output" => {
                    direction = SignalDirection::Output;
                    name_idx = i + 1;
                }
                "private" => {
                    is_public = false;
                }
                _ => {}
            }
        }

        let raw_name = parts.get(name_idx)?.trim_end_matches(';').to_string();

        let (name, array_size) = if let Some(open_idx) = raw_name.find('[') {
            if let Some(close_idx) = raw_name.find(']') {
                let size_str = &raw_name[open_idx + 1..close_idx];
                let size = size_str.parse::<usize>().ok();
                (raw_name[..open_idx].to_string(), size)
            } else {
                (raw_name.clone(), None)
            }
        } else {
            (raw_name, None)
        };

        Some(SignalInfo {
            name,
            direction,
            is_public,
            array_size,
        })
    }

    /// Signal information extracted from source
    #[derive(Debug, Clone)]
    pub struct SignalInfo {
        pub name: String,
        pub direction: SignalDirection,
        pub is_public: bool,
        pub array_size: Option<usize>,
    }

    /// Signal direction
    #[derive(Debug, Clone, PartialEq)]
    pub enum SignalDirection {
        Input,
        Output,
        Intermediate,
    }

    /// Extract public input list from the main component declaration
    pub fn extract_public_inputs(source: &str) -> Vec<String> {
        let mut inputs = Vec::new();
        let mut cursor = 0usize;

        while let Some(pos) = source[cursor..].find("public") {
            let start = cursor + pos + "public".len();
            let rest = &source[start..];
            let open = match rest.find('[') {
                Some(idx) => start + idx,
                None => {
                    cursor = start;
                    continue;
                }
            };
            let close = match source[open..].find(']') {
                Some(idx) => open + idx,
                None => break,
            };

            let list = &source[open + 1..close];
            for item in list.split(',') {
                let name = item.trim();
                if !name.is_empty() {
                    inputs.push(name.to_string());
                }
            }
            break;
        }

        inputs
    }

    /// Extract constraints from compiled R1CS (placeholder - requires binary parsing)
    pub fn extract_constraints(_r1cs_path: &str) -> Result<Vec<Constraint>> {
        // R1CS is a binary format, would need full parser
        // For now, return empty
        Ok(vec![])
    }

    /// Representation of an R1CS constraint
    #[derive(Debug, Clone)]
    pub struct Constraint {
        pub a: Vec<(usize, FieldElement)>,
        pub b: Vec<(usize, FieldElement)>,
        pub c: Vec<(usize, FieldElement)>,
    }

    /// Analyze circuit for common vulnerability patterns
    pub fn analyze_for_vulnerabilities(source: &str) -> Vec<VulnerabilityHint> {
        let mut hints = Vec::new();

        // Check for missing constraints
        if source.contains("===") {
            let constraint_count = source.matches("===").count();
            let signal_count = extract_signals(source).len();

            if signal_count > constraint_count * 2 {
                hints.push(VulnerabilityHint {
                    hint_type: VulnerabilityType::Underconstrained,
                    description: format!(
                        "Circuit has {} signals but only {} constraints - may be underconstrained",
                        signal_count, constraint_count
                    ),
                    line: None,
                });
            }
        }

        // Check for unsafe comparisons (== instead of ===)
        for (line_num, line) in source.lines().enumerate() {
            if line.contains(" == ") && !line.contains("===") && !line.trim().starts_with("//") {
                hints.push(VulnerabilityHint {
                    hint_type: VulnerabilityType::UnsafeComparison,
                    description: "Using == instead of === may not add constraints".to_string(),
                    line: Some(line_num + 1),
                });
            }
        }

        hints
    }

    /// Vulnerability hint from static analysis
    #[derive(Debug, Clone)]
    pub struct VulnerabilityHint {
        pub hint_type: VulnerabilityType,
        pub description: String,
        pub line: Option<usize>,
    }

    /// Types of potential vulnerabilities
    #[derive(Debug, Clone, PartialEq)]
    pub enum VulnerabilityType {
        Underconstrained,
        UnsafeComparison,
        MissingRangeCheck,
        UnusedSignal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn find_test_circuits_dir() -> PathBuf {
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for _ in 0..6 {
            let candidate = dir.join("tests").join("circuits");
            if candidate.exists() {
                return candidate;
            }
            if !dir.pop() {
                break;
            }
        }
        panic!("tests/circuits directory not found from CARGO_MANIFEST_DIR");
    }

    #[test]
    fn test_field_element_conversion() {
        let fe = FieldElement::from_u64(12345);
        let decimal = field_element_to_decimal(&fe);
        let parsed = parse_decimal_to_field_element(&decimal).unwrap();
        assert_eq!(fe, parsed);
    }

    #[test]
    fn test_signal_extraction() {
        let source = r#"
            signal input a;
            signal input b;
            signal output c;
            signal private input d;
        "#;

        let signals = analysis::extract_signals(source);
        assert_eq!(signals.len(), 4);
        assert_eq!(signals[0].name, "a");
        assert_eq!(signals[0].direction, analysis::SignalDirection::Input);
    }

    #[test]
    fn test_constraint_parsing() {
        let circuits_dir = find_test_circuits_dir();
        let circuit_path = circuits_dir.join("multiplier.circom");
        let build_dir = circuits_dir.join("build");

        let target = CircomTarget::new(circuit_path.to_str().unwrap(), "Multiplier")
            .unwrap()
            .with_build_dir(build_dir);

        let constraints = target.load_constraints().unwrap();
        assert!(!constraints.is_empty());
    }
}
