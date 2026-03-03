//! Circom circuit target implementation
//!
//! Provides full integration with the Circom ecosystem:
//! - Compilation via circom CLI
//! - Witness generation via generated WASM
//! - Proof generation/verification via snarkjs-compatible format

use crate::TargetCircuit;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};
use tempfile::Builder;
use zk_core::constants::bn254_modulus_bytes;
use zk_core::ConstraintEquation;
use zk_core::FieldElement;
use zk_core::Framework;

fn circom_external_command_timeout() -> std::time::Duration {
    // Default chosen to prevent pathological hangs without being too aggressive for large circuits.
    // Override with e.g. `ZK_FUZZER_CIRCOM_EXTERNAL_TIMEOUT_SECS=300` for slower machines/circuits.
    crate::util::timeout_from_env("ZK_FUZZER_CIRCOM_EXTERNAL_TIMEOUT_SECS", 60)
}

const CIRCOM_BIN_CANDIDATES_ENV: &str = "ZK_FUZZER_CIRCOM_BIN_CANDIDATES";
const CIRCOM_VERSION_CANDIDATES_ENV: &str = "ZK_FUZZER_CIRCOM_VERSION_CANDIDATES";
const SNARKJS_PATH_CANDIDATES_ENV: &str = "ZK_FUZZER_SNARKJS_PATH_CANDIDATES";
const CIRCOM_PTAU_SEARCH_PATHS_ENV: &str = "ZK_FUZZER_CIRCOM_PTAU_SEARCH_PATHS";
const CIRCOM_PTAU_PATH_ENV: &str = "ZKF_PTAU_PATH";

fn circom_command_candidates(preferred: Option<&str>) -> Vec<String> {
    let bin_candidates_raw = std::env::var(CIRCOM_BIN_CANDIDATES_ENV).ok();
    let version_candidates_raw = std::env::var(CIRCOM_VERSION_CANDIDATES_ENV).ok();

    crate::util::build_command_candidates(
        preferred,
        bin_candidates_raw.as_deref(),
        version_candidates_raw.as_deref(),
        "circom",
    )
}

fn run_circom_with_fallback<F>(
    candidates: &[String],
    context: &str,
    mut configure: F,
) -> Result<(Output, String)>
where
    F: FnMut(&mut Command),
{
    crate::util::run_command_with_fallback(
        candidates,
        circom_external_command_timeout(),
        context,
        |cmd| {
            apply_local_bins_path(cmd);
            configure(cmd);
        },
    )
}

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
    /// If true, enable witness "sanity check" when generating witnesses.
    ///
    /// This makes witness generation fail-fast when constraints are not satisfied,
    /// matching the semantics expected by fuzzing engines that treat a successful
    /// execution as "the circuit accepted the witness".
    ///
    /// Implemented via the circom-generated witness_calculator.js API:
    ///   calculateWitness(input, sanityCheck)
    /// where sanityCheck=1 enforces constraints.
    witness_sanity_check: bool,
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

const CIRCOM_METADATA_CACHE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedCircomMetadata {
    version: u32,
    metadata: CircomMetadata,
}

#[derive(Default)]
struct CircomIoInfo {
    input_signals: Vec<analysis::SignalInfo>,
    output_signals: Vec<analysis::SignalInfo>,
    public_inputs: Vec<String>,
}

#[derive(Debug)]
struct BuildDirLock {
    path: PathBuf,
    file: File,
}

impl BuildDirLock {
    fn open_lock_file(build_dir: &Path) -> Result<(PathBuf, File)> {
        std::fs::create_dir_all(build_dir)?;
        let path = build_dir.join(".zkfuzz_build.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("Failed to open build lock file: {}", path.display()))?;
        Ok((path, file))
    }

    fn acquire_exclusive(build_dir: &Path) -> Result<Self> {
        let (path, mut file) = Self::open_lock_file(build_dir)?;

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
        if let Err(e) = file.set_len(0) {
            tracing::warn!("Failed to truncate build lock {}: {}", path.display(), e);
        }
        if let Err(e) = writeln!(file, "pid={}", std::process::id()) {
            tracing::warn!(
                "Failed to write build lock metadata {}: {}",
                path.display(),
                e
            );
        }
        if let Err(e) = file.sync_all() {
            tracing::warn!("Failed to sync build lock {}: {}", path.display(), e);
        }

        Ok(Self { path, file })
    }

    fn acquire_shared(build_dir: &Path) -> Result<Self> {
        let (path, file) = Self::open_lock_file(build_dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("Failed to lock build dir: {}", build_dir.display()));
            }
        }

        Ok(Self { path, file })
    }
}

impl Drop for BuildDirLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let rc = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                tracing::warn!(
                    "Failed to unlock build dir lock {}: {}",
                    self.path.display(),
                    err
                );
            }
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
                        max_index = Some(match max_index {
                            Some(current) => current.max(idx),
                            None => idx,
                        });
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
    let idx = match idx_str.parse::<usize>() {
        Ok(idx) => idx,
        Err(err) => {
            tracing::debug!("Invalid array index '{}': {}", idx_str, err);
            return None;
        }
    };
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
    let public_end = outputs_end
        .saturating_add(num_public_inputs)
        .min(top_level.len());

    let outputs = top_level[..outputs_end].to_vec();
    let public_inputs = top_level[outputs_end..public_end].to_vec();
    let private_inputs = top_level[public_end..].to_vec();

    (outputs, public_inputs, private_inputs)
}

/// Witness calculator using compiled WASM
struct WitnessCalculator {
    /// Path to the WASM file
    wasm_path: PathBuf,
    /// If true, ask the witness calculator to verify constraints while building the witness.
    sanity_check: bool,
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
    let mut needs_param_signal_compat_fix = false;

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
        if is_param_signal_assignment_compat_line(trimmed) {
            needs_param_signal_compat_fix = true;
        }
    }

    // Modern Circom 2 sources should compile as-is. The compatibility rewrite
    // pass is intended for missing/legacy pragma and legacy syntax conversion,
    // and can over-transform valid Circom 2 templates.
    if has_pragma && !pragma_legacy {
        return Ok((circuit_path.to_path_buf(), None));
    }

    let mut visited = HashSet::new();
    let needs_include_param_signal_compat_fix =
        has_param_signal_compat_issue_recursive(circuit_path, &mut visited);

    let needs_rewrite = !has_pragma
        || pragma_legacy
        || needs_semicolon_fix
        || needs_param_signal_compat_fix
        || needs_include_param_signal_compat_fix;

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

    tracing::info!("Using circom2-compat source for {}", circuit_path.display());

    Ok((converted_path, Some(temp_dir)))
}

fn has_param_signal_compat_issue_recursive(path: &Path, visited: &mut HashSet<PathBuf>) -> bool {
    let canonical = match std::fs::canonicalize(path) {
        Ok(canonical) => canonical,
        Err(e) => {
            tracing::warn!(
                "Failed to canonicalize Circom path '{}' while checking compat issues: {}",
                path.display(),
                e
            );
            return false;
        }
    };
    if !visited.insert(canonical) {
        return false;
    }

    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "Failed reading Circom file '{}' while checking compat issues: {}",
                path.display(),
                e
            );
            return false;
        }
    };

    let source_dir = match path.parent() {
        Some(parent) => parent,
        None => {
            tracing::warn!(
                "Circom file '{}' has no parent directory for include resolution",
                path.display()
            );
            return false;
        }
    };
    for line in source.lines() {
        let trimmed = line.trim();
        if is_param_signal_assignment_compat_line(trimmed) {
            return true;
        }

        if trimmed.starts_with("include ") {
            if let Some((path_str, _quote)) = extract_include_path(trimmed) {
                let include_path = Path::new(&path_str);
                let resolved = if include_path.is_relative() {
                    source_dir.join(include_path)
                } else {
                    include_path.to_path_buf()
                };
                if has_param_signal_compat_issue_recursive(&resolved, visited) {
                    return true;
                }
            }
        }
    }

    false
}

fn convert_circom_file(
    path: &Path,
    temp_dir: &tempfile::TempDir,
    cache: &mut HashMap<PathBuf, PathBuf>,
    _main_component: &str,
    public_inputs: Option<&[String]>,
    is_root: bool,
) -> Result<PathBuf> {
    if let Some(existing) = cache.get(path) {
        return Ok(existing.clone());
    }

    let filename = if is_root {
        path.file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Invalid root Circom filename (non-UTF8 or missing): '{}'",
                    path.display()
                )
            })?
            .to_string()
    } else {
        let stem = path.file_stem().and_then(|s| s.to_str()).ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid Circom filename stem (non-UTF8 or missing): '{}'",
                path.display()
            )
        })?;
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
    let source_dir = path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "Circom source path has no parent directory: '{}'",
            path.display()
        )
    })?;

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

        if is_param_signal_assignment_compat_line(&updated_trimmed) {
            // External dataset snapshots sometimes wire `.p[...]` like a signal even
            // when `p` is a template parameter in the callee; drop the stale wiring.
            continue;
        }

        if updated_trimmed.starts_with("include ") {
            if let Some((path_str, quote)) = extract_include_path(&updated_trimmed) {
                let include_path = Path::new(&path_str);
                let resolved = if include_path.is_relative() {
                    source_dir.join(include_path)
                } else {
                    include_path.to_path_buf()
                };
                let converted =
                    convert_circom_file(&resolved, temp_dir, cache, _main_component, None, false)?;
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

fn circom_missing_main_error(stderr: &str) -> bool {
    let lowered = stderr.to_ascii_lowercase();
    lowered.contains("error[p1001]") && lowered.contains("no main specified")
}

fn template_param_count_from_decl_suffix(raw_suffix: &str) -> Option<usize> {
    let open = raw_suffix.find('(')?;
    let close = raw_suffix[open + 1..].find(')')?;
    let params = &raw_suffix[open + 1..open + 1 + close];
    let count = params
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .count();
    Some(count)
}

fn extract_template_declarations(source: &str) -> Vec<(String, usize)> {
    let mut templates = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim_start();
        let Some(after_prefix) = trimmed.strip_prefix("template ") else {
            continue;
        };
        let name: String = after_prefix
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let suffix = &after_prefix[name.len()..];
        let Some(param_count) = template_param_count_from_decl_suffix(suffix) else {
            continue;
        };
        if templates.iter().any(|(existing, _)| existing == &name) {
            continue;
        }
        templates.push((name, param_count));
    }
    templates
}

fn parse_component_main_rhs_candidates(source: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    for line in source.lines() {
        let mut normalized = line.trim();
        if normalized.starts_with("//") {
            normalized = normalized.trim_start_matches('/').trim_start();
        }
        if !normalized.contains("component main") {
            continue;
        }
        let Some((_, rhs)) = normalized.split_once('=') else {
            continue;
        };
        let rhs = rhs.split(';').next().unwrap_or_default().trim();
        if rhs.is_empty() {
            continue;
        }
        if candidates.iter().any(|existing| existing == rhs) {
            continue;
        }
        candidates.push(rhs.to_string());
    }
    candidates
}

fn build_template_invocation(name: &str, param_count: usize, value: usize) -> String {
    if param_count == 0 {
        return format!("{name}()");
    }
    let args = std::iter::repeat_n(value.to_string(), param_count).collect::<Vec<_>>();
    format!("{name}({})", args.join(", "))
}

fn synthetic_main_candidates(
    source: &str,
    compile_path: &Path,
    configured_main_component: &str,
) -> Vec<String> {
    let mut candidates = parse_component_main_rhs_candidates(source);
    let declarations = extract_template_declarations(source);

    let mut known_param_counts = HashMap::<String, usize>::new();
    for (name, param_count) in &declarations {
        known_param_counts.insert(name.clone(), *param_count);
    }

    let configured = configured_main_component.trim();
    if !configured.is_empty() && !configured.eq_ignore_ascii_case("main") {
        if let Some(param_count) = known_param_counts.get(configured).copied() {
            for seed in [1usize, 5usize] {
                let candidate = build_template_invocation(configured, param_count, seed);
                if !candidates.iter().any(|existing| existing == &candidate) {
                    candidates.push(candidate);
                }
            }
        } else {
            let candidate = format!("{configured}()");
            if !candidates.iter().any(|existing| existing == &candidate) {
                candidates.push(candidate);
            }
        }
    }

    if let Some(stem) = compile_path.file_stem().and_then(|value| value.to_str()) {
        if let Some(param_count) = known_param_counts.get(stem).copied() {
            for seed in [1usize, 5usize] {
                let candidate = build_template_invocation(stem, param_count, seed);
                if !candidates.iter().any(|existing| existing == &candidate) {
                    candidates.push(candidate);
                }
            }
        }
    }

    for (name, param_count) in declarations {
        for seed in [1usize, 5usize] {
            let candidate = build_template_invocation(&name, param_count, seed);
            if !candidates.iter().any(|existing| existing == &candidate) {
                candidates.push(candidate);
            }
            if param_count == 0 {
                break;
            }
        }
    }

    candidates
}

fn synthetic_main_wrapper_source(include_path: &Path, main_rhs: &str) -> String {
    format!(
        "pragma circom 2.0.0;\ninclude \"{}\";\ncomponent main = {};\n",
        include_path.display(),
        main_rhs
    )
}

fn has_explicit_component_main(source: &str) -> bool {
    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }
        if trimmed.contains("component main") {
            return true;
        }
    }
    false
}

fn try_compile_with_synthetic_main(
    compile_path: &Path,
    build_dir_str: &str,
    include_paths: &[PathBuf],
    candidates: &[String],
    configured_main_component: &str,
) -> Result<Option<String>> {
    let source = std::fs::read_to_string(compile_path).with_context(|| {
        format!(
            "Failed reading Circom source '{}' for synthetic-main recovery",
            compile_path.display()
        )
    })?;
    let synth_candidates =
        synthetic_main_candidates(&source, compile_path, configured_main_component);
    if synth_candidates.is_empty() {
        return Ok(None);
    }

    let temp_dir = create_temp_dir()?;
    let wrapper_name = compile_path
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.to_string())
        .unwrap_or_else(|| "main_wrapper.circom".to_string());
    let wrapper_path = temp_dir.path().join(wrapper_name);
    let include_abs = std::fs::canonicalize(compile_path).with_context(|| {
        format!(
            "Failed canonicalizing Circom source path '{}' for synthetic-main recovery",
            compile_path.display()
        )
    })?;

    let mut fallback_errors = Vec::new();
    for main_rhs in synth_candidates {
        let wrapper_source = synthetic_main_wrapper_source(&include_abs, &main_rhs);
        std::fs::write(&wrapper_path, wrapper_source).with_context(|| {
            format!(
                "Failed writing synthetic-main wrapper '{}'",
                wrapper_path.display()
            )
        })?;
        let wrapper_path_str = wrapper_path.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "Non-UTF8 synthetic-main wrapper path: {}",
                wrapper_path.display()
            )
        })?;

        match run_circom_with_fallback(
            candidates,
            "Circom synthetic-main fallback compile failed",
            |cmd| {
                for include in include_paths {
                    cmd.arg("-l").arg(include);
                }
                cmd.args([
                    wrapper_path_str,
                    "--r1cs",
                    "--wasm",
                    "--sym",
                    "--json",
                    "-o",
                    build_dir_str,
                ]);
            },
        ) {
            Ok((output, selected_candidate)) if output.status.success() => {
                tracing::info!(
                    "Circom synthetic-main fallback succeeded with '{}': component main = {}",
                    selected_candidate,
                    main_rhs
                );
                return Ok(Some(selected_candidate));
            }
            Ok((output, _)) => {
                fallback_errors.push(crate::util::command_failure_summary(&output));
            }
            Err(err) => fallback_errors.push(err.to_string()),
        }
    }

    if !fallback_errors.is_empty() {
        tracing::warn!(
            "Circom synthetic-main fallback exhausted for '{}': {}",
            compile_path.display(),
            fallback_errors.join(" || ")
        );
    }
    Ok(None)
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

fn is_param_signal_assignment_compat_line(trimmed: &str) -> bool {
    let compact = trimmed.replace(' ', "");
    compact.contains(".p[") && compact.contains("<==p[")
}

fn is_js_cli(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("js") | Some("cjs") | Some("mjs")
    )
}

fn local_bins_search_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        paths.push(cwd.join("bins"));
        paths.push(cwd.join("bins").join("bin"));
        paths.push(cwd.join("bins").join("node_modules").join(".bin"));
        paths.push(cwd.join("bins").join("node_modules"));
    }
    paths
}

fn apply_local_bins_path(cmd: &mut Command) {
    let separator = if cfg!(windows) { ';' } else { ':' };
    let mut prepend = Vec::new();
    for candidate in local_bins_search_paths() {
        if candidate.exists() {
            prepend.push(candidate.to_string_lossy().to_string());
        }
    }
    if prepend.is_empty() {
        return;
    }

    let current = std::env::var("PATH").unwrap_or_default();
    let mut path_parts = prepend;
    if !current.is_empty() {
        path_parts.push(current);
    }
    cmd.env("PATH", path_parts.join(&separator.to_string()));
}

fn snarkjs_command_for(path: Option<&Path>) -> Command {
    let mut cmd = match path {
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
    };
    apply_local_bins_path(&mut cmd);
    cmd
}

#[derive(Debug, Clone)]
enum SnarkjsCommandCandidate {
    Explicit(PathBuf),
    Npx,
}

fn snarkjs_command_candidates(preferred: Option<&Path>) -> Vec<SnarkjsCommandCandidate> {
    let mut candidates = Vec::new();

    if let Some(path) = preferred {
        candidates.push(SnarkjsCommandCandidate::Explicit(path.to_path_buf()));
    }

    let env_candidates_raw = std::env::var(SNARKJS_PATH_CANDIDATES_ENV).ok();
    for candidate in crate::util::parse_command_candidates(env_candidates_raw.as_deref()) {
        let path = PathBuf::from(candidate);
        if candidates.iter().any(|existing| {
            matches!(
                existing,
                SnarkjsCommandCandidate::Explicit(existing_path) if existing_path == &path
            )
        }) {
            continue;
        }
        candidates.push(SnarkjsCommandCandidate::Explicit(path));
    }

    candidates.push(SnarkjsCommandCandidate::Npx);
    candidates
}

fn run_snarkjs_with_fallback<F>(
    preferred: Option<&Path>,
    context: &str,
    mut configure: F,
) -> Result<(Output, String)>
where
    F: FnMut(&mut Command),
{
    let candidates = snarkjs_command_candidates(preferred);
    crate::util::run_candidate_commands_with_fallback(
        &candidates,
        circom_external_command_timeout(),
        context,
        |candidate| match candidate {
            SnarkjsCommandCandidate::Explicit(path) => path.display().to_string(),
            SnarkjsCommandCandidate::Npx => "npx snarkjs".to_string(),
        },
        |candidate| {
            let mut cmd = match candidate {
                SnarkjsCommandCandidate::Explicit(path) => {
                    snarkjs_command_for(Some(path.as_path()))
                }
                SnarkjsCommandCandidate::Npx => snarkjs_command_for(None),
            };
            configure(&mut cmd);
            Ok(cmd)
        },
    )
}

fn run_snarkjs_with_fallback_capture<F>(
    preferred: Option<&Path>,
    context: &str,
    mut configure: F,
) -> Result<(Output, String)>
where
    F: FnMut(&mut Command),
{
    let candidates = snarkjs_command_candidates(preferred);
    let mut failures = Vec::new();
    let mut labels_seen = Vec::new();

    for candidate in candidates {
        let (candidate_label, mut cmd) = match candidate {
            SnarkjsCommandCandidate::Explicit(path) => {
                (path.display().to_string(), snarkjs_command_for(Some(&path)))
            }
            SnarkjsCommandCandidate::Npx => ("npx snarkjs".to_string(), snarkjs_command_for(None)),
        };
        labels_seen.push(candidate_label.clone());
        configure(&mut cmd);
        match crate::util::run_with_timeout(&mut cmd, circom_external_command_timeout()) {
            Ok(output) => return Ok((output, candidate_label)),
            Err(err) => failures.push(format!("{candidate_label}: {err}")),
        }
    }

    anyhow::bail!(
        "{context}. Candidates tried: {}. Last errors: {}",
        labels_seen.join(", "),
        failures.join(" || ")
    )
}

fn circom_io_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn circom_io_guard(op: &str) -> Result<std::sync::MutexGuard<'static, ()>> {
    circom_io_lock()
        .lock()
        .map_err(|err| anyhow::anyhow!("circom IO lock poisoned during {}: {}", op, err))
}

impl WitnessCalculator {
    fn new(wasm_path: PathBuf, sanity_check: bool) -> Self {
        Self {
            wasm_path,
            sanity_check,
        }
    }

    /// Calculate witness using node.js and snarkjs
    fn calculate(&self, inputs: &HashMap<String, Vec<String>>) -> Result<Vec<FieldElement>> {
        // Create temporary input file
        let temp_dir = create_temp_dir()?;
        let temp_path = temp_dir.path();

        let input_path = temp_path.join("input.json");
        let witness_json_path = temp_path.join("witness.json");
        let cmd_timeout = circom_external_command_timeout();

        // Write inputs to JSON
        let input_json = serde_json::to_string(inputs)?;
        std::fs::write(&input_path, &input_json)?;

        // Strict mode policy: witness generation must use circom's generated
        // witness_calculator.js, and must fail hard on any error.
        let wasm_dir = self
            .wasm_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("WASM path has no parent directory"))?;
        let witness_calculator_path = wasm_dir.join("witness_calculator.js");
        if !witness_calculator_path.exists() {
            anyhow::bail!(
                "witness_calculator.js not found at {}",
                witness_calculator_path.display()
            );
        }

        let script_path = temp_path.join("calc_witness.js");
        let input_path_str = input_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 input path: {}", input_path.display()))?;
        let input_js = serde_json::to_string(input_path_str)?;
        // Use absolute paths since the script runs from a temp dir (relative paths
        // would be resolved relative to that temp dir and fail).
        let wasm_abs = std::fs::canonicalize(&self.wasm_path).with_context(|| {
            format!(
                "Failed to canonicalize wasm path '{}'",
                self.wasm_path.display()
            )
        })?;
        let wc_abs = std::fs::canonicalize(&witness_calculator_path).with_context(|| {
            format!(
                "Failed to canonicalize witness_calculator path '{}'",
                witness_calculator_path.display()
            )
        })?;

        let wasm_abs_str = wasm_abs
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 wasm path: {}", wasm_abs.display()))?;
        let wc_abs_str = wc_abs.to_str().ok_or_else(|| {
            anyhow::anyhow!("Non-UTF8 witness calculator path: {}", wc_abs.display())
        })?;
        let witness_json_path_str = witness_json_path.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "Non-UTF8 witness output path: {}",
                witness_json_path.display()
            )
        })?;

        let wasm_js = serde_json::to_string(wasm_abs_str)?;
        let wc_js = serde_json::to_string(wc_abs_str)?;
        let out_js = serde_json::to_string(witness_json_path_str)?;
        let sanity = if self.sanity_check { 1 } else { 0 };

        let script = format!(
            "const wc = require({wc_js});\n\
const fs = require('fs');\n\
const input = JSON.parse(fs.readFileSync({input_js}, 'utf8'));\n\
const wasm = fs.readFileSync({wasm_js});\n\
wc(wasm).then(async (calc) => {{\n\
  const witness = await calc.calculateWitness(input, {sanity});\n\
  const witnessStr = witness.map((v) => v.toString());\n\
  fs.writeFileSync({out_js}, JSON.stringify(witnessStr));\n\
}}).catch((err) => {{\n\
  console.error(err);\n\
  process.exit(1);\n\
}});\n"
        );
        std::fs::write(&script_path, script)?;

        let output = {
            let mut cmd = Command::new("node");
            cmd.arg(&script_path);
            crate::util::run_with_timeout(&mut cmd, cmd_timeout)
        }
        .context("Failed to run witness calculator")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "witness_calculator.js failed for '{}': {}",
                self.wasm_path.display(),
                stderr.chars().take(200).collect::<String>()
            );
        }
        if !witness_json_path.exists() {
            anyhow::bail!(
                "witness_calculator.js succeeded but did not produce witness JSON at {}",
                witness_json_path.display()
            );
        }

        let witness_json = std::fs::read_to_string(&witness_json_path)?;
        let witness_values: Vec<String> = serde_json::from_str(&witness_json)?;
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
        let build_dir = path
            .parent()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Circom circuit path has no parent directory: '{}'",
                    path.display()
                )
            })?
            .join("build");

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
            witness_sanity_check: false,
        })
    }

    /// Get the base name for output files (derived from source filename)
    fn output_basename(&self) -> Result<String> {
        let stem = self
            .circuit_path
            .file_stem()
            .ok_or_else(|| anyhow::anyhow!("Circuit path has no file stem"))?;
        let basename = stem.to_string_lossy().trim().to_string();
        if basename.is_empty() {
            anyhow::bail!(
                "Circuit path has an empty file stem for output basename: {}",
                self.circuit_path.display()
            );
        }
        Ok(basename)
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

    /// Enable/disable witness sanity checks (constraint checking during witness generation).
    pub fn with_witness_sanity_check(mut self, enabled: bool) -> Self {
        self.witness_sanity_check = enabled;
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
        let candidates = circom_command_candidates(None);
        let (output, _candidate) =
            run_circom_with_fallback(&candidates, "circom not found in PATH", |cmd| {
                cmd.arg("--version");
            })?;

        if !output.status.success() {
            anyhow::bail!(
                "circom --version failed: {}",
                crate::util::command_failure_summary(&output)
            );
        }

        crate::util::command_version_line(&output).ok_or_else(|| {
            anyhow::anyhow!(
                "circom --version returned empty output: {}",
                crate::util::command_failure_summary(&output)
            )
        })
    }

    /// Check if snarkjs is available
    pub fn check_snarkjs_available() -> Result<String> {
        let (output, _candidate) = run_snarkjs_with_fallback(None, "snarkjs not found", |cmd| {
            cmd.arg("--version");
        })?;

        crate::util::command_version_line(&output).ok_or_else(|| {
            anyhow::anyhow!(
                "snarkjs --version returned empty output: {}",
                crate::util::command_failure_summary(&output)
            )
        })
    }

    /// Compile the circuit to R1CS and generate WASM witness calculator
    pub fn compile(&mut self) -> Result<()> {
        if self.compiled {
            return Ok(());
        }

        let basename = self.output_basename()?;
        let r1cs_path = self.build_dir.join(format!("{}.r1cs", basename));
        let wasm_path = self
            .build_dir
            .join(format!("{}_js", basename))
            .join(format!("{}.wasm", basename));

        if self.skip_compile_if_artifacts && r1cs_path.exists() && wasm_path.exists() {
            // Shared lock is enough when reusing existing artifacts. This avoids serializing
            // per-exec isolation workers on a single exclusive build lock.
            let _build_lock = BuildDirLock::acquire_shared(&self.build_dir)?;
            tracing::info!(
                "Skipping circom compile; using existing artifacts in {:?}",
                self.build_dir
            );
            self.parse_r1cs_info()?;
            self.witness_calculator =
                Some(WitnessCalculator::new(wasm_path, self.witness_sanity_check));
            self.compiled = true;
            return Ok(());
        }

        // Prevent cross-process artifact races/collisions (compilation/emit).
        let _build_lock = BuildDirLock::acquire_exclusive(&self.build_dir)?;

        // Another process may have finished compilation while we waited for the exclusive lock.
        if self.skip_compile_if_artifacts && r1cs_path.exists() && wasm_path.exists() {
            tracing::info!(
                "Skipping circom compile; using existing artifacts in {:?}",
                self.build_dir
            );
            self.parse_r1cs_info()?;
            self.witness_calculator =
                Some(WitnessCalculator::new(wasm_path, self.witness_sanity_check));
            self.compiled = true;
            return Ok(());
        }

        // In-process IO lock to avoid concurrent circom/snarkjs calls stepping on each other.
        let _guard = circom_io_guard("compile")?;

        tracing::info!("Compiling Circom circuit: {:?}", self.circuit_path);

        // Check circom is available
        let circom_version = Self::check_circom_available()?;
        tracing::debug!("Using circom: {}", circom_version);

        let source = std::fs::read_to_string(&self.circuit_path)?;
        let (compile_path, _temp_dir) =
            maybe_prepare_circom2_source(&source, &self.circuit_path, &self.main_component)?;

        // Compile circuit
        let candidates = circom_command_candidates(None);
        let compile_path_str = compile_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 compile path: {}", compile_path.display()))?;
        let build_dir_str = self
            .build_dir
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 build dir: {}", self.build_dir.display()))?;
        let compile_context = format!(
            "Failed to run circom compiler for '{}'",
            compile_path.display()
        );
        let compile_source = std::fs::read_to_string(&compile_path).with_context(|| {
            format!(
                "Failed reading Circom source '{}' before compile",
                compile_path.display()
            )
        })?;

        let mut selected_candidate: Option<String> = None;
        if !has_explicit_component_main(&compile_source) {
            selected_candidate = try_compile_with_synthetic_main(
                &compile_path,
                build_dir_str,
                &self.include_paths,
                &candidates,
                &self.main_component,
            )?;
        }

        if selected_candidate.is_none() {
            match run_circom_with_fallback(&candidates, &compile_context, |cmd| {
                for include in &self.include_paths {
                    cmd.arg("-l").arg(include);
                }
                cmd.args([
                    compile_path_str,
                    "--r1cs",
                    "--wasm",
                    "--sym",
                    "--json",
                    "-o",
                    build_dir_str,
                ]);
            }) {
                Ok((output, candidate)) => {
                    if !output.status.success() {
                        anyhow::bail!(
                            "Circom compilation failed for '{}': {}",
                            compile_path.display(),
                            crate::util::command_failure_summary(&output)
                        );
                    }
                    selected_candidate = Some(candidate);
                }
                Err(err) => {
                    if circom_missing_main_error(&err.to_string()) {
                        selected_candidate = try_compile_with_synthetic_main(
                            &compile_path,
                            build_dir_str,
                            &self.include_paths,
                            &candidates,
                            &self.main_component,
                        )?;
                        if selected_candidate.is_none() {
                            return Err(err);
                        }
                    } else {
                        return Err(err);
                    }
                }
            }
        }

        let selected_candidate =
            selected_candidate.unwrap_or_else(|| "unknown_circom_candidate".to_string());

        tracing::info!(
            "Circom compilation successful (command candidate: {})",
            selected_candidate
        );

        // Parse R1CS info to get metadata
        self.parse_r1cs_info()?;

        // Setup witness calculator
        // circom outputs: {basename}_js/{basename}.wasm
        let wasm_path = self
            .build_dir
            .join(format!("{}_js", basename))
            .join(format!("{}.wasm", basename));

        if wasm_path.exists() {
            self.witness_calculator =
                Some(WitnessCalculator::new(wasm_path, self.witness_sanity_check));
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
        let basename = self.output_basename()?;
        let r1cs_path = self.build_dir.join(format!("{}.r1cs", basename));
        let sym_path = self.build_dir.join(format!("{}.sym", basename));
        let metadata_cache_path = self.metadata_cache_path()?;

        if !r1cs_path.exists() {
            tracing::warn!("R1CS file not found: {:?}", r1cs_path);
            return Ok(());
        }

        if self.try_load_cached_metadata(&metadata_cache_path, &r1cs_path, &sym_path)? {
            return Ok(());
        }

        // Strict mode: require snarkjs metadata extraction to succeed.
        let r1cs_path_str = r1cs_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 r1cs path: {}", r1cs_path.display()))?;
        let (output, _candidate) = run_snarkjs_with_fallback(
            self.snarkjs_path_override.as_deref(),
            "Failed to run snarkjs r1cs info",
            |cmd| {
                cmd.args(["r1cs", "info", r1cs_path_str]);
            },
        )?;
        if !output.status.success() {
            anyhow::bail!(
                "snarkjs r1cs info failed for '{}': {}",
                r1cs_path.display(),
                crate::util::command_failure_summary(&output)
            );
        }
        let (num_constraints, num_private_inputs, num_public_inputs, num_outputs) =
            Self::parse_snarkjs_r1cs_info_stdout(&String::from_utf8_lossy(&output.stdout))
                .with_context(|| {
                    format!(
                        "Failed to parse snarkjs r1cs info output for '{}'",
                        r1cs_path.display()
                    )
                })?;

        // Also parse the symbols file for signal names
        let (signals, sym_list) = if sym_path.exists() {
            (
                self.parse_symbols_file(&sym_path)?,
                self.parse_symbols_list(&sym_path)?,
            )
        } else {
            (HashMap::new(), Vec::new())
        };

        let io_info = self
            .parse_io_info()
            .context("Failed to parse Circom IO metadata")?;

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
            let sym_counts_match =
                sym_public.len() == num_public_inputs && sym_private.len() == num_private_inputs;

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
                let size = inferred.or(Some(1));
                input_signal_sizes.insert(name.clone(), size);
            }
        } else {
            for signal in &io_info.input_signals {
                let inferred = infer_array_size(&signals, &signal.name);
                let size = signal.array_size.or(inferred).or(Some(1));
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
        if let Err(err) = self.persist_metadata_cache(&metadata_cache_path) {
            tracing::warn!(
                "Failed to persist Circom metadata cache '{}': {}",
                metadata_cache_path.display(),
                err
            );
        }

        Ok(())
    }

    fn parse_snarkjs_r1cs_info_stdout(stdout: &str) -> Result<(usize, usize, usize, usize)> {
        let mut num_constraints = None;
        let mut num_private_inputs = None;
        let mut num_public_inputs = None;
        let mut num_outputs = None;

        for line in stdout.lines() {
            if let Some(last_colon_idx) = line.rfind(':') {
                let value_str = line[last_colon_idx + 1..].trim();
                if line.contains("Constraints") {
                    num_constraints = Some(value_str.parse().with_context(|| {
                        format!("Failed parsing constraint count from '{}'", line)
                    })?);
                } else if line.contains("Private Inputs") {
                    num_private_inputs = Some(value_str.parse().with_context(|| {
                        format!("Failed parsing private input count from '{}'", line)
                    })?);
                } else if line.contains("Public Inputs") {
                    num_public_inputs = Some(value_str.parse().with_context(|| {
                        format!("Failed parsing public input count from '{}'", line)
                    })?);
                } else if line.contains("Outputs")
                    && !line.contains("Public")
                    && !line.contains("Private")
                {
                    num_outputs =
                        Some(value_str.parse().with_context(|| {
                            format!("Failed parsing output count from '{}'", line)
                        })?);
                }
            }
        }

        let constraints = num_constraints
            .ok_or_else(|| anyhow::anyhow!("Missing constraint count in snarkjs output"))?;
        let private_inputs = num_private_inputs
            .ok_or_else(|| anyhow::anyhow!("Missing private input count in snarkjs output"))?;
        let public_inputs = num_public_inputs
            .ok_or_else(|| anyhow::anyhow!("Missing public input count in snarkjs output"))?;
        let outputs = num_outputs.unwrap_or(0);

        Ok((constraints, private_inputs, public_inputs, outputs))
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
                let index: usize = parts[0].parse().with_context(|| {
                    format!(
                        "Failed to parse symbol index '{}' in {}",
                        parts[0],
                        path.display()
                    )
                })?;
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
                let index: usize = parts[0].parse().with_context(|| {
                    format!(
                        "Failed to parse symbol index '{}' in {}",
                        parts[0],
                        path.display()
                    )
                })?;
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
        let _build_lock = BuildDirLock::acquire_exclusive(&self.build_dir)?;
        let _guard = circom_io_guard("setup_keys")?;
        let basename = self.output_basename()?;
        let r1cs_path = self.build_dir.join(format!("{}.r1cs", basename));
        let ptau_path = self.find_ptau()?;

        let zkey_path = self.build_dir.join(format!("{}.zkey", basename));
        let vkey_path = self.build_dir.join(format!("{}_vkey.json", basename));
        let r1cs_path_str = r1cs_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 r1cs path: {}", r1cs_path.display()))?;
        let ptau_path_str = ptau_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 ptau path: {}", ptau_path.display()))?;
        let zkey_path_str = zkey_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 zkey path: {}", zkey_path.display()))?;
        let vkey_path_str = vkey_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 vkey path: {}", vkey_path.display()))?;

        let zkey_ready = is_valid_zkey_file(&zkey_path)?;
        let vkey_ready = is_valid_json_file(&vkey_path)?;
        if zkey_ready && vkey_ready {
            tracing::info!(
                "Reusing existing proving/verification keys in '{}'",
                self.build_dir.display()
            );
            self.proving_key_path = Some(zkey_path);
            self.verification_key_path = Some(vkey_path);
            return Ok(());
        }

        if zkey_path.exists() {
            tracing::warn!(
                "Removing stale/incomplete proving key before regeneration: {}",
                zkey_path.display()
            );
            if let Err(err) = std::fs::remove_file(&zkey_path) {
                tracing::warn!(
                    "Failed to remove stale proving key '{}': {}",
                    zkey_path.display(),
                    err
                );
            }
        }
        if vkey_path.exists() {
            tracing::warn!(
                "Removing stale/incomplete verification key before regeneration: {}",
                vkey_path.display()
            );
            if let Err(err) = std::fs::remove_file(&vkey_path) {
                tracing::warn!(
                    "Failed to remove stale verification key '{}': {}",
                    vkey_path.display(),
                    err
                );
            }
        }

        // Generate zkey (proving key)
        tracing::info!("Generating proving key...");
        let (output, _candidate) = run_snarkjs_with_fallback(
            self.snarkjs_path_override.as_deref(),
            "Failed to generate proving key",
            |cmd| {
                cmd.args([
                    "groth16",
                    "setup",
                    r1cs_path_str,
                    ptau_path_str,
                    zkey_path_str,
                ]);
            },
        )?;

        if !output.status.success() || snarkjs_output_reports_error(&output) {
            anyhow::bail!(
                "Key generation failed: {}",
                crate::util::command_failure_summary(&output)
            );
        }
        if !is_valid_zkey_file(&zkey_path)? {
            anyhow::bail!(
                "Generated proving key is invalid (bad header): {}. {}",
                zkey_path.display(),
                crate::util::command_failure_summary(&output)
            );
        }

        // Export verification key
        tracing::info!("Exporting verification key...");
        let (output, _candidate) = run_snarkjs_with_fallback(
            self.snarkjs_path_override.as_deref(),
            "Failed to export verification key",
            |cmd| {
                cmd.args([
                    "zkey",
                    "export",
                    "verificationkey",
                    zkey_path_str,
                    vkey_path_str,
                ]);
            },
        )?;

        if !output.status.success() || snarkjs_output_reports_error(&output) {
            anyhow::bail!(
                "Verification key export failed: {}",
                crate::util::command_failure_summary(&output)
            );
        }
        if !is_valid_json_file(&vkey_path)? {
            anyhow::bail!(
                "Generated verification key is invalid JSON: {}",
                vkey_path.display()
            );
        }

        self.proving_key_path = Some(zkey_path);
        self.verification_key_path = Some(vkey_path);

        tracing::info!("Key setup complete");
        Ok(())
    }

    /// Find existing powers of tau file.
    fn find_ptau(&self) -> Result<PathBuf> {
        fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
            if paths.iter().any(|existing| existing == &path) {
                return;
            }
            paths.push(path);
        }

        if let Some(path) = &self.ptau_path_override {
            if is_valid_ptau_file(path)? {
                return Ok(path.clone());
            }
            anyhow::bail!(
                "Configured ptau file is missing or invalid (bad header/size): {}",
                path.display()
            );
        }

        if let Some(raw) = std::env::var_os(CIRCOM_PTAU_PATH_ENV) {
            let path = PathBuf::from(raw);
            if path.as_os_str().is_empty() {
                anyhow::bail!("{} is set but empty", CIRCOM_PTAU_PATH_ENV);
            }
            if is_valid_ptau_file(&path)? {
                tracing::info!("Using ptau file from {}: {:?}", CIRCOM_PTAU_PATH_ENV, path);
                return Ok(path);
            }
            anyhow::bail!(
                "Configured ptau file from {} is missing or invalid (bad header/size): {}",
                CIRCOM_PTAU_PATH_ENV,
                path.display()
            );
        }

        let mut ptau_dirs = Vec::<PathBuf>::new();
        let mut direct_ptau_candidates = Vec::<PathBuf>::new();
        push_unique_path(&mut ptau_dirs, self.build_dir.clone());
        push_unique_path(&mut ptau_dirs, PathBuf::from("."));

        if let Ok(cwd) = std::env::current_dir() {
            // Standard local bootstrap locations used by this repository.
            push_unique_path(&mut ptau_dirs, cwd.join("bins").join("ptau"));
            push_unique_path(
                &mut ptau_dirs,
                cwd.join("tests").join("circuits").join("build"),
            );
        }

        if let Some(raw) = std::env::var_os(CIRCOM_PTAU_SEARCH_PATHS_ENV) {
            for candidate in std::env::split_paths(&raw) {
                if candidate.extension().is_some_and(|ext| ext == "ptau") {
                    push_unique_path(&mut direct_ptau_candidates, candidate);
                } else {
                    push_unique_path(&mut ptau_dirs, candidate);
                }
            }
        }

        for candidate in direct_ptau_candidates {
            if is_valid_ptau_file(&candidate)? {
                tracing::info!("Found existing valid ptau file: {:?}", candidate);
                return Ok(candidate);
            }
            tracing::warn!(
                "Ignoring invalid ptau candidate (bad header/size): {}",
                candidate.display()
            );
        }

        if let Some(home) = dirs::home_dir() {
            ptau_dirs.push(home.join(".snarkjs"));
        } else {
            tracing::warn!("HOME directory not found; skipping ~/.snarkjs ptau search path");
        }

        for dir in &ptau_dirs {
            let entries = match std::fs::read_dir(dir) {
                Ok(entries) => entries,
                Err(e) => {
                    tracing::warn!("Failed reading ptau directory '{}': {}", dir.display(), e);
                    continue;
                }
            };
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => {
                        tracing::warn!(
                            "Failed reading an entry in ptau directory '{}': {}",
                            dir.display(),
                            e
                        );
                        continue;
                    }
                };
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "ptau") {
                    if is_valid_ptau_file(&path)? {
                        tracing::info!("Found existing valid ptau file: {:?}", path);
                        return Ok(path);
                    }
                    tracing::warn!(
                        "Ignoring invalid ptau candidate (bad header/size): {}",
                        path.display()
                    );
                }
            }
        }

        anyhow::bail!(
            "No valid ptau file found. Configure an explicit ptau path via executor options/target settings."
        )
    }

    /// Calculate witness for given inputs
    pub fn calculate_witness(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        let _guard = circom_io_guard("witness calculation")?;
        let calculator = self
            .witness_calculator
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Witness calculator not initialized"))?;

        // Convert inputs to named map based on metadata
        let input_map = self.inputs_to_map(inputs)?;
        calculator
            .calculate(&input_map)
            .with_context(|| self.input_map_debug_context(inputs.len(), &input_map))
    }

    /// Convert input array to named signal map
    fn inputs_to_map(&self, inputs: &[FieldElement]) -> Result<HashMap<String, Vec<String>>> {
        let mut map = HashMap::new();

        if let Some(metadata) = &self.metadata {
            static INPUT_MAP_LOG_ONCE: OnceLock<()> = OnceLock::new();
            if INPUT_MAP_LOG_ONCE.set(()).is_ok() {
                // This is extremely verbose for large circuits and becomes catastrophic when
                // process isolation spawns a fresh exec-worker per execution. Keep it at DEBUG.
                tracing::debug!(
                    "Circom input mapping: {} values, {} signals (public {}, private {})",
                    inputs.len(),
                    metadata.input_signals.len(),
                    metadata.num_public_inputs,
                    metadata.num_private_inputs
                );
                if tracing::enabled!(tracing::Level::DEBUG) {
                    for name in &metadata.input_signals {
                        let size = metadata
                            .input_signal_sizes
                            .get(name)
                            .copied()
                            .flatten()
                            .ok_or_else(|| {
                                anyhow::anyhow!("Missing input size metadata for signal '{}'", name)
                            })?;
                        tracing::debug!("  input '{}' size {}", name, size);
                    }
                }
            }

            let mut cursor = 0usize;
            for (i, name) in metadata.input_signals.iter().enumerate() {
                let clean_name = match name.strip_prefix("main.") {
                    Some(trimmed) => trimmed.to_string(),
                    None => name.to_string(),
                };

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
                    .ok_or_else(|| {
                        anyhow::anyhow!("Missing input size metadata for signal '{}'", name)
                    })?;

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

        self.validate_input_map_against_metadata(&map)?;
        Ok(map)
    }

    fn input_map_signal_present(map: &HashMap<String, Vec<String>>, signal: &str) -> bool {
        if let Some((base, idx)) = split_array_index(signal) {
            if map
                .get(base)
                .and_then(|values| values.get(idx))
                .is_some_and(|value| !value.trim().is_empty())
            {
                return true;
            }
            if map
                .get(signal)
                .and_then(|values| values.first())
                .is_some_and(|value| !value.trim().is_empty())
            {
                return true;
            }
            return false;
        }

        map.get(signal)
            .and_then(|values| values.first())
            .is_some_and(|value| !value.trim().is_empty())
    }

    fn validate_input_map_against_metadata(
        &self,
        map: &HashMap<String, Vec<String>>,
    ) -> Result<()> {
        let Some(metadata) = &self.metadata else {
            return Ok(());
        };
        if metadata.input_signals.is_empty() {
            return Ok(());
        }

        let mut missing = Vec::new();
        for raw_name in &metadata.input_signals {
            let clean_name = raw_name.strip_prefix("main.").unwrap_or(raw_name);
            if !Self::input_map_signal_present(map, clean_name) {
                missing.push(clean_name.to_string());
            }
        }

        if !missing.is_empty() {
            let preview = missing
                .iter()
                .take(10)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "Input map is missing {} required Circom signals (first: {})",
                missing.len(),
                preview
            );
        }

        Ok(())
    }

    fn input_map_debug_context(
        &self,
        provided_input_values: usize,
        map: &HashMap<String, Vec<String>>,
    ) -> String {
        let mut map_keys = map
            .iter()
            .map(|(name, values)| format!("{}[{}]", name, values.len()))
            .collect::<Vec<_>>();
        map_keys.sort();

        if let Some(metadata) = &self.metadata {
            let expected_preview = metadata
                .input_signals
                .iter()
                .map(|name| name.strip_prefix("main.").unwrap_or(name).to_string())
                .take(16)
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "Circom witness input context: provided_values={}, expected_signals={} (public={}, private={}), expected_preview=[{}], provided_map_keys=[{}]",
                provided_input_values,
                metadata.input_signals.len(),
                metadata.num_public_inputs,
                metadata.num_private_inputs,
                expected_preview,
                map_keys.join(", ")
            )
        } else {
            format!(
                "Circom witness input context: provided_values={}, metadata=missing, provided_map_keys=[{}]",
                provided_input_values,
                map_keys.join(", ")
            )
        }
    }

    fn constraints_json_path(&self) -> Result<PathBuf> {
        let basename = self.output_basename()?;
        Ok(self
            .build_dir
            .join(format!("{}_constraints.json", basename)))
    }

    fn metadata_cache_path(&self) -> Result<PathBuf> {
        let basename = self.output_basename()?;
        Ok(self.build_dir.join(format!("{}_metadata.json", basename)))
    }

    fn try_load_cached_metadata(
        &mut self,
        cache_path: &Path,
        r1cs_path: &Path,
        sym_path: &Path,
    ) -> Result<bool> {
        if !cache_path.exists() {
            return Ok(false);
        }
        if !Self::is_cache_fresh(
            cache_path,
            &[r1cs_path, &self.circuit_path],
            if sym_path.exists() {
                Some(sym_path)
            } else {
                None
            },
        ) {
            return Ok(false);
        }

        let raw = match std::fs::read_to_string(cache_path) {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(
                    "Failed reading Circom metadata cache '{}': {}",
                    cache_path.display(),
                    err
                );
                return Ok(false);
            }
        };

        let cached: CachedCircomMetadata = match serde_json::from_str(&raw) {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(
                    "Failed parsing Circom metadata cache '{}': {}",
                    cache_path.display(),
                    err
                );
                return Ok(false);
            }
        };

        if cached.version != CIRCOM_METADATA_CACHE_VERSION {
            tracing::debug!(
                "Ignoring Circom metadata cache '{}' with unsupported version {}",
                cache_path.display(),
                cached.version
            );
            return Ok(false);
        }

        let metadata = cached.metadata;
        tracing::info!(
            "Loaded cached Circom metadata from '{}' (constraints={}, private_inputs={}, public_inputs={})",
            cache_path.display(),
            metadata.num_constraints,
            metadata.num_private_inputs,
            metadata.num_public_inputs
        );
        self.metadata = Some(metadata);
        Ok(true)
    }

    fn persist_metadata_cache(&self, cache_path: &Path) -> Result<()> {
        let Some(metadata) = &self.metadata else {
            return Ok(());
        };

        let payload = CachedCircomMetadata {
            version: CIRCOM_METADATA_CACHE_VERSION,
            metadata: metadata.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&payload)?;
        let tmp_path = cache_path.with_extension(format!(
            "tmp.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));

        if let Some(parent) = cache_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&tmp_path, bytes)?;
        match std::fs::rename(&tmp_path, cache_path) {
            Ok(_) => Ok(()),
            Err(err) => {
                if cache_path.exists() {
                    let _ = std::fs::remove_file(&tmp_path);
                    Ok(())
                } else {
                    Err(err).context(format!(
                        "Failed to atomically publish metadata cache '{}'",
                        cache_path.display()
                    ))
                }
            }
        }
    }

    fn is_cache_fresh(
        cache_path: &Path,
        mandatory_deps: &[&Path],
        optional_dep: Option<&Path>,
    ) -> bool {
        let cache_mtime = match std::fs::metadata(cache_path).and_then(|m| m.modified()) {
            Ok(time) => time,
            Err(_) => return false,
        };

        for dep in mandatory_deps {
            let dep_mtime = match std::fs::metadata(dep).and_then(|m| m.modified()) {
                Ok(time) => time,
                Err(_) => return false,
            };
            if dep_mtime > cache_mtime {
                return false;
            }
        }

        if let Some(dep) = optional_dep {
            if let Ok(dep_mtime) = std::fs::metadata(dep).and_then(|m| m.modified()) {
                if dep_mtime > cache_mtime {
                    return false;
                }
            }
        }

        true
    }

    /// Load constraint equations from Circom-generated JSON
    pub fn load_constraints(&self) -> Result<Vec<ConstraintEquation>> {
        let constraints_path = self.constraints_json_path()?;
        let basename = self.output_basename()?;

        if !constraints_path.exists() {
            let r1cs_path = self.build_dir.join(format!("{}.r1cs", basename));
            if !r1cs_path.exists() {
                anyhow::bail!(
                    "Circom constraints unavailable: missing R1CS artifact '{}' (expected constraints JSON '{}')",
                    r1cs_path.display(),
                    constraints_path.display()
                );
            }

            if let Some(parent) = constraints_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let temp_path = constraints_path.with_extension(format!(
                "json.tmp.{}.{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            let r1cs_path_str = r1cs_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Non-UTF8 r1cs path: {}", r1cs_path.display()))?;
            let temp_path_str = temp_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Non-UTF8 temp path: {}", temp_path.display()))?;

            let (output, _candidate) = run_snarkjs_with_fallback(
                self.snarkjs_path_override.as_deref(),
                "Failed to export R1CS constraints",
                |cmd| {
                    cmd.args(["r1cs", "export", "json", r1cs_path_str, temp_path_str]);
                },
            )?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let _ = std::fs::remove_file(&temp_path);
                anyhow::bail!("Constraint export failed: {}", stderr);
            }
            match std::fs::rename(&temp_path, &constraints_path) {
                Ok(_) => {}
                Err(err) => {
                    if constraints_path.exists() {
                        let _ = std::fs::remove_file(&temp_path);
                    } else {
                        return Err(err).context(format!(
                            "Failed to persist exported constraints at '{}'",
                            constraints_path.display()
                        ));
                    }
                }
            }
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
            .expect("Circom metadata missing; call compile() before querying public_input_indices")
            .public_input_indices
            .clone()
    }

    pub fn private_input_indices(&self) -> Vec<usize> {
        self.metadata
            .as_ref()
            .expect("Circom metadata missing; call compile() before querying private_input_indices")
            .private_input_indices
            .clone()
    }

    pub fn output_signal_indices(&self) -> Vec<usize> {
        self.metadata
            .as_ref()
            .expect("Circom metadata missing; call compile() before querying output_signal_indices")
            .output_signal_indices
            .clone()
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
            .expect("Circom metadata missing; call compile() before querying field_name")
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

/// Resolve a Circom field/prime string to a 32-byte modulus.
///
/// Handles:
///  - Aliases:  `bn128`, `bn254`, `alt_bn128`, `altbn128` → BN254 scalar field
///  - `bls12381`, `bls12-381` → BLS12-381 scalar field
///  - `goldilocks` → Goldilocks prime
///  - Numeric decimal string (the raw prime)
///  - Hex string with `0x` prefix
///
/// Returns `None` on unrecognised / unparseable input (fail-closed).
fn resolve_circom_prime(prime: &str) -> Option<[u8; 32]> {
    let normalised: String = prime
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && *c != '-')
        .collect();

    // Well-known aliases
    match normalised.as_str() {
        "bn128" | "bn254" | "altbn128" | "altbn128_" => {
            return Some(bn254_modulus_bytes());
        }
        "bls12381" => {
            return hex_to_modulus(
                "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
            );
        }
        "goldilocks" => {
            return hex_to_modulus(
                "000000000000000000000000000000000000000000000000ffffffff00000001",
            );
        }
        _ => {}
    }

    // Try hex with 0x prefix
    if let Some(hex_str) = normalised.strip_prefix("0x") {
        return hex_to_modulus(hex_str);
    }

    // Try decimal
    use num_bigint::BigUint;
    if let Some(value) = BigUint::parse_bytes(normalised.as_bytes(), 10) {
        let bytes = value.to_bytes_be();
        if bytes.len() <= 32 {
            let mut result = [0u8; 32];
            let start = 32 - bytes.len();
            result[start..].copy_from_slice(&bytes);
            return Some(result);
        }
    }

    // Fail closed – unknown prime
    tracing::warn!("Unknown Circom prime '{}', cannot resolve modulus", prime);
    None
}

fn hex_to_modulus(hex_str: &str) -> Option<[u8; 32]> {
    let decoded = match hex::decode(hex_str) {
        Ok(decoded) => decoded,
        Err(err) => {
            tracing::debug!("Failed to decode hex modulus '{}': {}", hex_str, err);
            return None;
        }
    };
    if decoded.len() > 32 {
        return None;
    }
    let mut result = [0u8; 32];
    let start = 32 - decoded.len();
    result[start..].copy_from_slice(&decoded);
    Some(result)
}

impl TargetCircuit for CircomTarget {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn name(&self) -> &str {
        &self.main_component
    }

    fn field_modulus(&self) -> [u8; 32] {
        let prime = self.field_name();
        match resolve_circom_prime(prime) {
            Some(modulus) => modulus,
            None => panic!(
                "Unknown Circom prime '{}'; cannot resolve field modulus",
                prime
            ),
        }
    }

    fn field_name(&self) -> &str {
        self.metadata
            .as_ref()
            .map(|m| m.prime.as_str())
            .expect("Circom metadata missing; call compile() before querying field_name")
    }

    fn num_constraints(&self) -> usize {
        self.metadata
            .as_ref()
            .map(|m| m.num_constraints)
            .expect("Circom metadata missing; call compile() before querying num_constraints")
    }

    fn num_private_inputs(&self) -> usize {
        self.metadata
            .as_ref()
            .map(|m| m.num_private_inputs)
            .expect("Circom metadata missing; call compile() before querying num_private_inputs")
    }

    fn num_public_inputs(&self) -> usize {
        self.metadata
            .as_ref()
            .map(|m| m.num_public_inputs)
            .expect("Circom metadata missing; call compile() before querying num_public_inputs")
    }

    fn execute(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        if !self.compiled {
            anyhow::bail!("Circuit not compiled. Call compile() first.");
        }

        let witness = self.calculate_witness(inputs)?;
        Ok(self.outputs_from_witness(&witness))
    }

    fn prove(&self, witness: &[FieldElement]) -> Result<Vec<u8>> {
        let _guard = circom_io_guard("prove")?;
        let zkey_path = self
            .proving_key_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Proving key not set. Call setup_keys() first."))?;

        let temp_dir = create_temp_dir()?;
        let temp_path = temp_dir.path();

        let witness_path = temp_path.join("witness.wtns");
        let proof_path = temp_path.join("proof.json");
        let public_path = temp_path.join("public.json");
        let zkey_path_str = zkey_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 zkey path: {}", zkey_path.display()))?;
        let witness_path_str = witness_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 witness path: {}", witness_path.display()))?;
        let proof_path_str = proof_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 proof path: {}", proof_path.display()))?;
        let public_path_str = public_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 public path: {}", public_path.display()))?;

        // First need to create witness file
        // For now, use the WASM-based approach
        let input_map = self.inputs_to_map(witness)?;
        let input_json = serde_json::to_string(&input_map)?;
        let input_path = temp_path.join("input.json");
        std::fs::write(&input_path, &input_json)?;

        if let Some(calc) = &self.witness_calculator {
            let calc_wasm_path_str = calc.wasm_path.to_str().ok_or_else(|| {
                anyhow::anyhow!("Non-UTF8 wasm path: {}", calc.wasm_path.display())
            })?;
            let input_path_str = input_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Non-UTF8 input path: {}", input_path.display()))?;
            let (output, _candidate) = run_snarkjs_with_fallback(
                self.snarkjs_path_override.as_deref(),
                "Failed to calculate witness for proof",
                |cmd| {
                    cmd.args([
                        "wtns",
                        "calculate",
                        calc_wasm_path_str,
                        input_path_str,
                        witness_path_str,
                    ]);
                },
            )?;

            if !output.status.success() {
                anyhow::bail!(
                    "Witness calculation failed: {}",
                    crate::util::command_failure_summary(&output)
                );
            }
        }

        // Generate proof
        let (output, _candidate) = run_snarkjs_with_fallback(
            self.snarkjs_path_override.as_deref(),
            "Failed to generate proof",
            |cmd| {
                cmd.args([
                    "groth16",
                    "prove",
                    zkey_path_str,
                    witness_path_str,
                    proof_path_str,
                    public_path_str,
                ]);
            },
        )?;

        if !output.status.success() {
            anyhow::bail!(
                "Proof generation failed: {}",
                crate::util::command_failure_summary(&output)
            );
        }

        // Read proof JSON
        let proof_json = std::fs::read_to_string(&proof_path)?;

        Ok(proof_json.into_bytes())
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> Result<bool> {
        let _guard = circom_io_guard("verify")?;
        let vkey_path = self
            .verification_key_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Verification key not set."))?;

        let temp_dir = create_temp_dir()?;
        let temp_path = temp_dir.path();

        let proof_path = temp_path.join("proof.json");
        let public_path = temp_path.join("public.json");
        let vkey_path_str = vkey_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 vkey path: {}", vkey_path.display()))?;
        let public_path_str = public_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 public path: {}", public_path.display()))?;
        let proof_path_str = proof_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 proof path: {}", proof_path.display()))?;

        // Write proof
        std::fs::write(&proof_path, proof)?;

        // Write public inputs
        let public_values: Vec<String> =
            public_inputs.iter().map(field_element_to_decimal).collect();
        let public_json = serde_json::to_string(&public_values)?;
        std::fs::write(&public_path, &public_json)?;

        // Verify
        let (output, _candidate) = run_snarkjs_with_fallback_capture(
            self.snarkjs_path_override.as_deref(),
            "Failed to verify proof",
            |cmd| {
                cmd.args([
                    "groth16",
                    "verify",
                    vkey_path_str,
                    public_path_str,
                    proof_path_str,
                ]);
            },
        )?;

        // snarkjs prints "OK!" on success; invalid proofs commonly return non-zero exit.
        let stdout = String::from_utf8_lossy(&output.stdout);
        if output.status.success() && stdout.contains("OK") {
            return Ok(true);
        }
        if snarkjs_output_is_invalid_proof(&output) {
            return Ok(false);
        }
        if output.status.success() {
            return Ok(false);
        }
        anyhow::bail!(
            "Proof verification command failed: {}",
            crate::util::command_failure_summary(&output)
        )
    }
}

fn parse_constraint_terms(value: &serde_json::Value) -> Result<Vec<(usize, FieldElement)>> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Constraint term is not an object"))?;

    let mut terms = Vec::new();
    for (key, val) in obj {
        let idx: usize = key
            .parse()
            .with_context(|| format!("Invalid constraint wire index '{}'", key))?;
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

fn file_has_nonzero_size(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to read metadata for '{}'", path.display()))?;
    Ok(metadata.is_file() && metadata.len() > 0)
}

// Powers of Tau files smaller than this are almost certainly truncated/corrupt.
const MIN_PTAU_BYTES: u64 = 1_000_000;

fn has_bin_magic(path: &Path, magic: &[u8; 4]) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }

    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to read metadata for '{}'", path.display()))?;
    if !metadata.is_file() || metadata.len() < 4 {
        return Ok(false);
    }

    let mut file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open file '{}'", path.display()))?;
    let mut header = [0u8; 4];
    file.read_exact(&mut header)
        .with_context(|| format!("Failed to read header '{}'", path.display()))?;

    Ok(&header == magic)
}

fn is_valid_ptau_file(path: &Path) -> Result<bool> {
    if !has_bin_magic(path, b"ptau")? {
        return Ok(false);
    }
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to read metadata for '{}'", path.display()))?;
    Ok(metadata.is_file() && metadata.len() >= MIN_PTAU_BYTES)
}

fn is_valid_zkey_file(path: &Path) -> Result<bool> {
    has_bin_magic(path, b"zkey")
}

fn is_valid_json_file(path: &Path) -> Result<bool> {
    if !file_has_nonzero_size(path)? {
        return Ok(false);
    }

    let raw = std::fs::read(path)
        .with_context(|| format!("Failed to read json file '{}'", path.display()))?;
    Ok(serde_json::from_slice::<serde_json::Value>(&raw).is_ok())
}

fn snarkjs_output_reports_error(output: &Output) -> bool {
    fn contains_error_marker(bytes: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bytes).to_lowercase();
        text.contains("[error]") || text.contains("snarkjs: error")
    }

    contains_error_marker(&output.stdout) || contains_error_marker(&output.stderr)
}

fn snarkjs_output_is_invalid_proof(output: &Output) -> bool {
    let stdout = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    stdout.contains("invalid proof")
        || stderr.contains("invalid proof")
        || stdout.contains("proof is not valid")
        || stderr.contains("proof is not valid")
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
                let size = match size_str.parse::<usize>() {
                    Ok(size) => Some(size),
                    Err(err) => {
                        tracing::warn!(
                            "Invalid array size '{}' in signal declaration '{}': {}",
                            size_str,
                            raw_name,
                            err
                        );
                        None
                    }
                };
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

    /// Legacy analysis entrypoint retained for API compatibility.
    /// Use `CircomTarget::load_constraints()` on a compiled target instead.
    pub fn extract_constraints(_r1cs_path: &str) -> Result<Vec<Constraint>> {
        anyhow::bail!(
            "analysis::extract_constraints is not implemented; use load_constraints() on a compiled target instead"
        )
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
#[path = "mod_tests.rs"]
mod tests;
