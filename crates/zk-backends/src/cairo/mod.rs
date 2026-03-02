//! Cairo circuit target implementation
//!
//! Provides integration with the Cairo/StarkNet ecosystem:
//! - Compilation via cairo-compile or scarb
//! - Execution via cairo-run
//! - STARK proof generation via stone-prover

use crate::TargetCircuit;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use zk_core::FieldElement;
use zk_core::Framework;

fn cairo_external_command_timeout() -> std::time::Duration {
    // Cairo executions can be heavier than CLI compilation; default a bit higher.
    crate::util::timeout_from_env("ZK_FUZZER_CAIRO_EXTERNAL_TIMEOUT_SECS", 120)
}

const SCARB_BIN_CANDIDATES_ENV: &str = "ZK_FUZZER_SCARB_BIN_CANDIDATES";
const SCARB_VERSION_CANDIDATES_ENV: &str = "ZK_FUZZER_SCARB_VERSION_CANDIDATES";
const SCARB_TOOLCHAIN_DIR_ENV: &str = "ZK_FUZZER_SCARB_TOOLCHAIN_DIR";
const SCARB_ARCHIVE_DIR_ENV: &str = "ZK_FUZZER_SCARB_ARCHIVE_DIR";
const SCARB_CACHE_ENV: &str = "SCARB_CACHE";
const SCARB_CONFIG_ENV: &str = "SCARB_CONFIG";
const SCARB_OFFLINE_ENV: &str = "SCARB_OFFLINE";
const SCARB_HOME_CACHE_SEED_ENV: &str = "ZK_FUZZER_SCARB_HOME_CACHE_SEED";
const SCARB_VERSION_CASCADE_LIMIT_ENV: &str = "ZK_FUZZER_SCARB_VERSION_CASCADE_LIMIT";

fn scarb_download_timeout() -> std::time::Duration {
    crate::util::timeout_from_env("ZK_FUZZER_SCARB_DOWNLOAD_TIMEOUT_SECS", 240)
}

fn push_unique_candidate(candidates: &mut Vec<String>, candidate: impl Into<String>) {
    let candidate = candidate.into();
    if candidate.trim().is_empty() {
        return;
    }
    if candidates.iter().any(|existing| existing == &candidate) {
        return;
    }
    candidates.push(candidate);
}

fn parse_semver_part(raw: &str) -> Option<u64> {
    let digits: String = raw.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<u64>().ok()
}

fn parse_semver_triplet(raw: &str) -> Option<(u64, u64, u64)> {
    let trimmed = raw.trim().trim_start_matches('v');
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.split('.');
    let major = parse_semver_part(parts.next()?)?;
    let minor = parse_semver_part(parts.next()?)?;
    let patch = match parts.next() {
        Some(raw_patch) => parse_semver_part(raw_patch)?,
        None => 0,
    };
    Some((major, minor, patch))
}

fn scarb_version_cascade_limit() -> usize {
    let default_limit = 10usize;
    let parsed = std::env::var(SCARB_VERSION_CASCADE_LIMIT_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(default_limit);
    parsed.clamp(1, 64)
}

fn discover_scarb_versions_from_path() -> Vec<String> {
    let mut versions = Vec::new();
    let Some(path_os) = std::env::var_os("PATH") else {
        return versions;
    };

    for dir in std::env::split_paths(&path_os) {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(version) = name.strip_prefix("scarb-") else {
                continue;
            };
            if parse_semver_triplet(version).is_none() {
                continue;
            }
            push_unique_candidate(&mut versions, version.to_string());
        }
    }

    versions
}

fn discover_scarb_versions_from_toolchain_dir() -> Vec<String> {
    let mut versions = Vec::new();
    let toolchain_root = resolve_scarb_toolchain_dir();
    let Ok(entries) = fs::read_dir(&toolchain_root) else {
        return versions;
    };

    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }

        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(after_prefix) = name.strip_prefix("scarb-v") else {
            continue;
        };
        let Some((version, _rest)) = after_prefix.split_once('-') else {
            continue;
        };
        if parse_semver_triplet(version).is_none() {
            continue;
        }
        if !entry.path().join("bin").join("scarb").is_file() {
            continue;
        }
        push_unique_candidate(&mut versions, version.to_string());
    }

    versions
}

fn resolve_versioned_scarb_binary_on_path(version: &str) -> Option<String> {
    let trimmed = version.trim();
    if trimmed.is_empty() {
        return None;
    }
    let binary_name = format!("scarb-{trimmed}");
    let path_os = std::env::var_os("PATH")?;

    for dir in std::env::split_paths(&path_os) {
        let candidate = dir.join(&binary_name);
        if candidate.is_file() {
            return Some(candidate.display().to_string());
        }
    }
    None
}

fn collect_scarb_version_cascade(version_hint: Option<&str>) -> Vec<String> {
    let hint_parsed = version_hint.and_then(parse_semver_triplet);
    let mut versions = Vec::<String>::new();

    if let Some(hint) = version_hint
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        push_unique_candidate(&mut versions, hint.to_string());
    }

    let env_versions = std::env::var(SCARB_VERSION_CANDIDATES_ENV).ok();
    for version in crate::util::parse_command_candidates(env_versions.as_deref()) {
        if parse_semver_triplet(&version).is_none() {
            continue;
        }
        push_unique_candidate(&mut versions, version);
    }
    for version in discover_scarb_versions_from_path() {
        push_unique_candidate(&mut versions, version);
    }
    for version in discover_scarb_versions_from_toolchain_dir() {
        push_unique_candidate(&mut versions, version);
    }

    if let Some(hint_key) = hint_parsed {
        versions.sort_by(|left, right| {
            let left_key = parse_semver_triplet(left);
            let right_key = parse_semver_triplet(right);
            let left_score = left_key.map(|(major, minor, patch)| {
                let tier = if major == hint_key.0 && minor == hint_key.1 {
                    0u8
                } else if major == hint_key.0 {
                    1u8
                } else {
                    2u8
                };
                (
                    tier,
                    major.abs_diff(hint_key.0),
                    minor.abs_diff(hint_key.1),
                    patch.abs_diff(hint_key.2),
                )
            });
            let right_score = right_key.map(|(major, minor, patch)| {
                let tier = if major == hint_key.0 && minor == hint_key.1 {
                    0u8
                } else if major == hint_key.0 {
                    1u8
                } else {
                    2u8
                };
                (
                    tier,
                    major.abs_diff(hint_key.0),
                    minor.abs_diff(hint_key.1),
                    patch.abs_diff(hint_key.2),
                )
            });

            left_score.cmp(&right_score).then_with(|| left.cmp(right))
        });
    } else {
        versions.sort_by(|left, right| {
            let left_key = parse_semver_triplet(left);
            let right_key = parse_semver_triplet(right);
            right_key.cmp(&left_key).then_with(|| left.cmp(right))
        });
    }

    let limit = scarb_version_cascade_limit();
    if versions.len() > limit {
        versions.truncate(limit);
    }
    versions
}

fn scarb_command_candidates(
    preferred: Option<&str>,
    extra_bin_candidates: &[String],
    extra_version_candidates: &[String],
) -> Vec<String> {
    let bin_candidates_raw = std::env::var(SCARB_BIN_CANDIDATES_ENV).ok();
    let version_candidates_raw = std::env::var(SCARB_VERSION_CANDIDATES_ENV).ok();

    let mut candidates = crate::util::build_command_candidates(
        preferred,
        bin_candidates_raw.as_deref(),
        version_candidates_raw.as_deref(),
        "scarb",
    );

    for candidate in extra_bin_candidates {
        if candidate.trim().is_empty() {
            continue;
        }
        if candidates.iter().any(|existing| existing == candidate) {
            continue;
        }
        candidates.insert(0, candidate.clone());
    }
    for version in extra_version_candidates {
        let parsed = version.trim();
        if parsed.is_empty() {
            continue;
        }
        let candidate = format!("scarb-{parsed}");
        if candidates.iter().any(|existing| existing == &candidate) {
            continue;
        }
        candidates.insert(0, candidate);
    }

    candidates
}

fn run_scarb_with_fallback<F>(
    candidates: &[String],
    context: &str,
    configure: F,
) -> Result<(std::process::Output, String)>
where
    F: FnMut(&mut Command),
{
    crate::util::run_command_with_fallback(
        candidates,
        cairo_external_command_timeout(),
        context,
        configure,
    )
}

fn detect_host_scarb_asset_triples() -> Vec<&'static str> {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("x86_64", "linux") => vec!["x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"],
        ("aarch64", "linux") => vec!["aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl"],
        ("x86_64", "macos") => vec!["x86_64-apple-darwin"],
        ("aarch64", "macos") => vec!["aarch64-apple-darwin"],
        _ => Vec::new(),
    }
}

fn resolve_scarb_toolchain_dir() -> PathBuf {
    if let Some(raw) = std::env::var_os(SCARB_TOOLCHAIN_DIR_ENV) {
        if !raw.is_empty() {
            return PathBuf::from(raw);
        }
    }
    std::env::temp_dir().join("zkfuzz_toolchains")
}

fn run_toolchain_setup_command(
    program: &str,
    args: &[String],
    context: &str,
) -> Result<std::process::Output> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    let output = crate::util::run_with_timeout(&mut cmd, scarb_download_timeout())
        .with_context(|| format!("Failed to run {}", program))?;
    if !output.status.success() {
        anyhow::bail!(
            "{}: {}",
            context,
            crate::util::command_failure_summary(&output)
        );
    }
    Ok(output)
}

fn ensure_versioned_scarb_binary(version: &str) -> Option<String> {
    let parsed = version.trim();
    if parsed.is_empty() {
        return None;
    }

    let toolchain_root = resolve_scarb_toolchain_dir();
    let triples = detect_host_scarb_asset_triples();
    if triples.is_empty() {
        return None;
    }

    for triple in &triples {
        let candidate = toolchain_root
            .join(format!("scarb-v{parsed}-{triple}"))
            .join("bin")
            .join("scarb");
        if candidate.exists() {
            return Some(candidate.display().to_string());
        }
    }

    if let Err(err) = fs::create_dir_all(&toolchain_root) {
        tracing::warn!(
            "Failed to create Scarb toolchain directory '{}': {}",
            toolchain_root.display(),
            err
        );
        return None;
    }

    let local_archive_dir = std::env::var_os(SCARB_ARCHIVE_DIR_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);

    for triple in triples {
        let archive_name = format!("scarb-v{parsed}-{triple}.tar.gz");
        let archive_path = toolchain_root.join(&archive_name);
        let mut archive_ready = archive_path.is_file();

        if !archive_ready {
            if let Some(local_dir) = local_archive_dir.as_ref() {
                let local_archive = local_dir.join(&archive_name);
                if local_archive.is_file() {
                    if let Err(err) = fs::copy(&local_archive, &archive_path) {
                        tracing::warn!(
                            "Skipping local Scarb archive candidate '{}': failed copying '{}' -> '{}': {}",
                            triple,
                            local_archive.display(),
                            archive_path.display(),
                            err
                        );
                        continue;
                    }
                    archive_ready = true;
                }
            }
        }

        if !archive_ready {
            tracing::debug!(
                "Skipping scarb toolchain candidate version {} ({}) because local archive '{}' is unavailable and remote auto-download is disabled",
                parsed,
                triple,
                archive_name
            );
            continue;
        }

        let tar_args = vec![
            "-xzf".to_string(),
            archive_path.display().to_string(),
            "-C".to_string(),
            toolchain_root.display().to_string(),
        ];
        if let Err(err) =
            run_toolchain_setup_command("tar", &tar_args, "Failed extracting scarb toolchain")
        {
            tracing::warn!(
                "Skipping extracted scarb toolchain version {} ({}) due to extraction error: {}",
                parsed,
                triple,
                err
            );
            continue;
        }

        let candidate = toolchain_root
            .join(format!("scarb-v{parsed}-{triple}"))
            .join("bin")
            .join("scarb");
        if candidate.exists() {
            return Some(candidate.display().to_string());
        }
    }

    None
}

fn find_scarb_manifest(start_dir: &Path) -> Option<PathBuf> {
    let mut current = Some(start_dir);
    while let Some(dir) = current {
        let candidate = dir.join("Scarb.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        current = dir.parent();
    }
    None
}

fn parse_cairo_version_from_manifest(manifest_path: &Path) -> Option<String> {
    let raw = fs::read_to_string(manifest_path).ok()?;
    let mut in_package = false;

    for raw_line in raw.lines() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            in_package = line == "[package]";
            continue;
        }

        if !in_package {
            continue;
        }

        let Some(after_key) = line.strip_prefix("cairo-version") else {
            continue;
        };
        let Some(after_eq) = after_key.trim().strip_prefix('=') else {
            continue;
        };
        let parsed = after_eq.trim().trim_matches('"').trim_matches('\'').trim();
        if parsed.is_empty() {
            return None;
        }
        return Some(parsed.to_string());
    }

    None
}

fn should_skip_scarb_project_entry(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".github" | ".vscode" | ".idea" | ".scarb" | "target" | "node_modules"
    )
}

fn copy_scarb_project_tree(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)
        .with_context(|| format!("Failed to create Scarb project mirror '{}'", dst.display()))?;

    for entry in fs::read_dir(src)
        .with_context(|| format!("Failed to read Scarb project dir '{}'", src.display()))?
    {
        let entry = entry.with_context(|| {
            format!(
                "Failed reading Scarb project entry under '{}'",
                src.display()
            )
        })?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        if should_skip_scarb_project_entry(&file_name) {
            continue;
        }

        let file_type = entry.file_type().with_context(|| {
            format!(
                "Failed reading file type for Scarb project entry '{}'",
                src_path.display()
            )
        })?;
        if file_type.is_symlink() {
            tracing::debug!(
                "Skipping symlink while mirroring Scarb project '{}'",
                src_path.display()
            );
            continue;
        }

        if file_type.is_dir() {
            copy_scarb_project_tree(&src_path, &dst_path)?;
            continue;
        }

        if let Some(parent) = dst_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed creating Scarb project mirror parent '{}'",
                    parent.display()
                )
            })?;
        }
        fs::copy(&src_path, &dst_path).with_context(|| {
            format!(
                "Failed mirroring Scarb project file '{}' -> '{}'",
                src_path.display(),
                dst_path.display()
            )
        })?;
    }

    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    if !src.exists() {
        return Ok(());
    }
    fs::create_dir_all(dst)
        .with_context(|| format!("Failed to create cache dir '{}'", dst.display()))?;

    for entry in fs::read_dir(src)
        .with_context(|| format!("Failed to read cache dir '{}'", src.display()))?
    {
        let entry =
            entry.with_context(|| format!("Failed reading entry under '{}'", src.display()))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
            continue;
        }

        if dst_path.exists() {
            continue;
        }
        fs::copy(&src_path, &dst_path).with_context(|| {
            format!(
                "Failed copying cache seed '{}' -> '{}'",
                src_path.display(),
                dst_path.display()
            )
        })?;
    }

    Ok(())
}

fn cache_has_registry_entries(cache_dir: &Path) -> bool {
    let registry_dir = cache_dir.join("registry").join("git");
    for rel in ["db", "checkouts"] {
        let dir = registry_dir.join(rel);
        let Ok(mut entries) = fs::read_dir(&dir) else {
            continue;
        };
        if entries.next().is_some() {
            return true;
        }
    }
    false
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
    /// Last runtime-backed coverage sample captured during execution.
    runtime_coverage_sample: Mutex<Option<CairoRuntimeCoverageSample>>,
    /// Most recent Scarb binary candidate that worked for this target.
    selected_scarb_binary: Mutex<Option<String>>,
    /// Writable mirror of the Scarb project used for build/run commands.
    prepared_scarb_project_dir: OnceLock<PathBuf>,
}

/// Cairo version
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CairoVersion {
    /// Original Cairo (Cairo 0)
    Cairo0,
    /// New Cairo (Cairo 1, Scarb-based)
    Cairo1,
}

#[derive(Debug, Clone)]
pub struct CairoRuntimeCoverageSample {
    pub source: String,
    pub trace_bytes: u64,
    pub memory_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Cairo1ProofArtifact {
    contract_version: u32,
    framework: String,
    backend: String,
    proof_transport: String,
    execution_id: String,
    witness_count: usize,
    witness_args_json: String,
    witness_sha256: String,
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
            .ok_or_else(|| anyhow::anyhow!("Invalid Cairo source path '{}'", path.display()))?
            .to_string();

        // Detect Cairo version from file extension/content
        let cairo_version = Self::detect_version(&path)?;
        let build_dir = match cairo_version {
            CairoVersion::Cairo0 => path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("Cairo source path has no parent"))?
                .join("build"),
            CairoVersion::Cairo1 => path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("Cairo source path has no parent"))?
                .join("target"),
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
            runtime_coverage_sample: Mutex::new(None),
            selected_scarb_binary: Mutex::new(None),
            prepared_scarb_project_dir: OnceLock::new(),
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

    pub fn cairo_version(&self) -> CairoVersion {
        self.cairo_version
    }

    pub fn is_cairo1(&self) -> bool {
        self.cairo_version == CairoVersion::Cairo1
    }

    pub fn latest_runtime_coverage_sample(&self) -> Option<CairoRuntimeCoverageSample> {
        match self.runtime_coverage_sample.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => {
                tracing::warn!(
                    "cairo runtime coverage sample lock poisoned; returning recovered sample"
                );
                poisoned.into_inner().clone()
            }
        }
    }

    fn store_runtime_coverage_sample(&self, sample: Option<CairoRuntimeCoverageSample>) {
        let mut guard = match self.runtime_coverage_sample.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!(
                    "cairo runtime coverage sample lock poisoned; storing recovered sample"
                );
                poisoned.into_inner()
            }
        };
        *guard = sample;
    }

    fn selected_scarb_binary(&self) -> Option<String> {
        match self.selected_scarb_binary.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => {
                tracing::warn!("selected_scarb_binary lock poisoned; returning recovered value");
                poisoned.into_inner().clone()
            }
        }
    }

    fn remember_selected_scarb_binary(&self, candidate: &str) {
        let mut guard = match self.selected_scarb_binary.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("selected_scarb_binary lock poisoned; storing recovered value");
                poisoned.into_inner()
            }
        };
        if guard.as_deref() != Some(candidate) {
            tracing::info!("Using Scarb candidate '{}'", candidate);
            *guard = Some(candidate.to_string());
        }
    }

    fn cairo_version_hint(&self, project_dir: &Path) -> Option<String> {
        let manifest = find_scarb_manifest(project_dir)?;
        parse_cairo_version_from_manifest(&manifest)
    }

    fn source_scarb_project_dir(&self) -> Result<PathBuf> {
        let start_dir = if self.source_path.is_dir() {
            self.source_path.as_path()
        } else if self
            .source_path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("Scarb.toml"))
        {
            self.source_path.parent().ok_or_else(|| {
                anyhow::anyhow!(
                    "Scarb manifest path has no parent directory: '{}'",
                    self.source_path.display()
                )
            })?
        } else {
            self.source_path.parent().ok_or_else(|| {
                anyhow::anyhow!(
                    "Cairo source path has no parent directory: '{}'",
                    self.source_path.display()
                )
            })?
        };

        let manifest = find_scarb_manifest(start_dir).ok_or_else(|| {
            anyhow::anyhow!(
                "Could not locate Scarb.toml for Cairo target '{}'",
                self.source_path.display()
            )
        })?;
        manifest
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| anyhow::anyhow!("Scarb.toml has no parent directory"))
    }

    fn ensure_prepared_scarb_project_dir(&self) -> Result<PathBuf> {
        if let Some(existing) = self.prepared_scarb_project_dir.get() {
            let manifest = existing.join("Scarb.toml");
            if manifest.exists() {
                return Ok(existing.clone());
            }
            tracing::warn!(
                "Prepared Scarb project dir '{}' is stale (missing Scarb.toml); rebuilding mirror",
                existing.display()
            );
        }

        let source_project_dir = self.source_scarb_project_dir()?;
        let prepared_dir = self.build_dir.join("_scarb_project");
        if prepared_dir.exists() {
            fs::remove_dir_all(&prepared_dir).with_context(|| {
                format!(
                    "Failed to clear stale Scarb project mirror '{}'",
                    prepared_dir.display()
                )
            })?;
        }
        copy_scarb_project_tree(&source_project_dir, &prepared_dir)?;

        let _ = self.prepared_scarb_project_dir.set(prepared_dir.clone());
        Ok(self
            .prepared_scarb_project_dir
            .get()
            .cloned()
            .unwrap_or(prepared_dir))
    }

    fn warm_cache_from_home_if_available(&self, cache_dir: &Path) -> bool {
        let marker = cache_dir.join(".zkfuzz_seeded_from_home");
        if marker.exists() {
            return cache_has_registry_entries(cache_dir);
        }

        let explicit_home_seed = std::env::var_os(SCARB_HOME_CACHE_SEED_ENV)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let default_home_seed = dirs::home_dir().map(|home| home.join(".cache").join("scarb"));
        let Some(home_seed) = explicit_home_seed.or(default_home_seed) else {
            return false;
        };
        if !home_seed.exists() {
            return false;
        }

        let mut copied_any = false;
        for rel in ["registry/git/db", "registry/git/checkouts"] {
            let src = home_seed.join(rel);
            let dst = cache_dir.join(rel);
            if !src.exists() {
                continue;
            }
            if let Err(err) = copy_dir_recursive(&src, &dst) {
                tracing::warn!(
                    "Failed warming Scarb cache from '{}' into '{}': {}",
                    src.display(),
                    dst.display(),
                    err
                );
                continue;
            }
            copied_any = true;
        }

        if copied_any {
            let _ = fs::write(&marker, "seeded-from-home-cache\n");
        }
        copied_any
    }

    fn configure_scarb_command_env(&self, cmd: &mut Command, project_dir: &Path) {
        cmd.env("SCARB_TARGET_DIR", &self.build_dir);

        let explicit_cache = std::env::var_os(SCARB_CACHE_ENV).filter(|value| !value.is_empty());
        if explicit_cache.is_none() {
            let local_cache = self.build_dir.join("_scarb_cache");
            if let Err(err) = fs::create_dir_all(&local_cache) {
                tracing::warn!(
                    "Failed creating local Scarb cache dir '{}': {}",
                    local_cache.display(),
                    err
                );
            } else {
                cmd.env(SCARB_CACHE_ENV, &local_cache);
                let _ = self.warm_cache_from_home_if_available(&local_cache);
                if std::env::var_os(SCARB_OFFLINE_ENV)
                    .filter(|value| !value.is_empty())
                    .is_none()
                    && cache_has_registry_entries(&local_cache)
                {
                    // Prefer cache-only dependency resolution when a local cache exists.
                    cmd.env(SCARB_OFFLINE_ENV, "true");
                }
            }
        }

        if std::env::var_os(SCARB_CONFIG_ENV)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            let local_config = self.build_dir.join("_scarb_config");
            if let Err(err) = fs::create_dir_all(&local_config) {
                tracing::warn!(
                    "Failed creating local Scarb config dir '{}': {}",
                    local_config.display(),
                    err
                );
            } else {
                cmd.env(SCARB_CONFIG_ENV, &local_config);
            }
        }

        cmd.current_dir(project_dir);
    }

    fn run_scarb_command_with_fallback<F>(
        &self,
        context: &str,
        project_dir: &Path,
        mut configure: F,
    ) -> Result<std::process::Output>
    where
        F: FnMut(&mut Command),
    {
        let preferred = self.selected_scarb_binary();
        let mut extra_bin_candidates = Vec::new();
        let mut extra_version_candidates = Vec::new();

        let version_hint = self.cairo_version_hint(project_dir);
        let version_cascade = collect_scarb_version_cascade(version_hint.as_deref());
        for version in &version_cascade {
            push_unique_candidate(&mut extra_version_candidates, version.clone());
            if let Some(binary_path) = resolve_versioned_scarb_binary_on_path(version) {
                push_unique_candidate(&mut extra_bin_candidates, binary_path);
            }
        }

        // Provision all semver-compatible cascade candidates so fallback can use locally
        // materialized versioned binaries even when only `scarb` is present on PATH.
        for version in &version_cascade {
            if let Some(versioned_binary) = ensure_versioned_scarb_binary(version) {
                push_unique_candidate(&mut extra_bin_candidates, versioned_binary);
            }
        }

        let candidates = scarb_command_candidates(
            preferred.as_deref(),
            &extra_bin_candidates,
            &extra_version_candidates,
        );
        let (output, candidate) =
            run_scarb_with_fallback(&candidates, context, |cmd| {
                self.configure_scarb_command_env(cmd, project_dir);
                configure(cmd);
            })
            .with_context(|| {
                format!(
                    "Toolchain cascade exhausted; set {} with explicit versions (comma-separated) to force a known-good Scarb toolchain",
                    SCARB_VERSION_CANDIDATES_ENV
                )
            })?;
        self.remember_selected_scarb_binary(&candidate);
        Ok(output)
    }

    /// Detect Cairo version from the source file
    fn detect_version(path: &Path) -> Result<CairoVersion> {
        // Check for Scarb.toml (Cairo 1)
        let scarb_path = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Cairo source path has no parent"))?
            .join("Scarb.toml");
        if scarb_path.exists() {
            return Ok(CairoVersion::Cairo1);
        }

        // Check file extension
        if path.extension().is_none_or(|ext| ext != "cairo") {
            anyhow::bail!(
                "Unsupported Cairo source extension for '{}'; expected .cairo",
                path.display()
            );
        }
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read Cairo source '{}'", path.display()))?;
        // Cairo 1 uses different syntax
        if content.contains("fn main()")
            || content.contains("#[contract]")
            || content.contains("mod ")
            || content.contains("use ")
        {
            return Ok(CairoVersion::Cairo1);
        }
        Ok(CairoVersion::Cairo0)
    }

    /// Check if Cairo compiler is available
    pub fn check_cairo_available() -> Result<(CairoVersion, String)> {
        // Prefer Cairo 0 toolchain when available (cairo-compile + cairo-run).
        let cairo0 = (|| -> Result<String> {
            let mut cmd = Command::new("cairo-compile");
            cmd.arg("--version");
            let output = crate::util::run_with_timeout(&mut cmd, cairo_external_command_timeout())
                .context("cairo-compile not found in PATH")?;
            if !output.status.success() {
                anyhow::bail!(
                    "cairo-compile --version failed: {}",
                    crate::util::command_failure_summary(&output)
                );
            }

            let mut run_cmd = Command::new("cairo-run");
            run_cmd.arg("--version");
            let run_output =
                crate::util::run_with_timeout(&mut run_cmd, cairo_external_command_timeout())
                    .context("cairo-run not found in PATH")?;
            if !run_output.status.success() {
                anyhow::bail!(
                    "cairo-run --version failed: {}",
                    crate::util::command_failure_summary(&run_output)
                );
            }

            crate::util::command_version_line(&output).ok_or_else(|| {
                anyhow::anyhow!(
                    "cairo-compile --version returned empty output: {}",
                    crate::util::command_failure_summary(&output)
                )
            })
        })();

        let cairo0_error = match cairo0 {
            Ok(version) => return Ok((CairoVersion::Cairo0, version)),
            Err(e) => e,
        };

        // Try Scarb (Cairo 1 toolchain), including configured fallback candidates.
        let candidates = scarb_command_candidates(None, &[], &[]);
        let (output, candidate) = run_scarb_with_fallback(
            &candidates,
            "No working Scarb candidate found for Cairo1 toolchain detection",
            |cmd| {
                cmd.arg("--version");
            },
        )
        .with_context(|| {
            format!("No Cairo toolchain detected. Cairo0 check failed: {cairo0_error}")
        })?;

        if candidate != "scarb" {
            tracing::info!(
                "Cairo toolchain detection selected fallback Scarb '{}'",
                candidate
            );
        }

        let version = crate::util::command_version_line(&output).ok_or_else(|| {
            anyhow::anyhow!(
                "scarb --version returned empty output: {}",
                crate::util::command_failure_summary(&output)
            )
        })?;

        Ok((CairoVersion::Cairo1, version))
    }

    /// Check if stone-prover is available
    pub fn check_stone_prover_available() -> Result<String> {
        let output = {
            let mut cmd = Command::new("cpu_air_prover");
            cmd.arg("--version");
            crate::util::run_with_timeout(&mut cmd, cairo_external_command_timeout())
                .context("stone-prover not found")?
        };

        if !output.status.success() {
            anyhow::bail!(
                "stone-prover --version failed: {}",
                crate::util::command_failure_summary(&output)
            );
        }

        crate::util::command_version_line(&output).ok_or_else(|| {
            anyhow::anyhow!(
                "stone-prover --version returned empty output: {}",
                crate::util::command_failure_summary(&output)
            )
        })
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
        let source_path_str = self.source_path.to_str().ok_or_else(|| {
            anyhow::anyhow!("Non-UTF8 Cairo source path: {}", self.source_path.display())
        })?;
        let output_path_str = output_path.to_str().ok_or_else(|| {
            anyhow::anyhow!("Non-UTF8 Cairo output path: {}", output_path.display())
        })?;

        let mut args = vec![
            source_path_str.to_string(),
            "--output".to_string(),
            output_path_str.to_string(),
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
        let project_dir = self.ensure_prepared_scarb_project_dir()?;

        self.run_scarb_command_with_fallback(
            "Scarb build failed for all configured candidates",
            &project_dir,
            |cmd| {
                cmd.args(["build"]);
            },
        )?;

        // Find the compiled Sierra file
        let target_dir = self.build_dir.join("dev");
        let entries = std::fs::read_dir(&target_dir)
            .with_context(|| format!("Failed to read target dir '{}'", target_dir.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| {
                format!(
                    "Failed reading an entry in target dir '{}'",
                    target_dir.display()
                )
            })?;
            let path = entry.path();
            let file_name = path.file_name().and_then(|value| value.to_str());
            let is_compiled_artifact = file_name.is_some_and(|name| {
                name.ends_with(".sierra.json")
                    || name.ends_with(".casm.json")
                    || name.ends_with(".sierra")
                    || name.ends_with(".casm")
            });
            if is_compiled_artifact {
                self.compiled_path = Some(path);
                break;
            }
        }

        if self.compiled_path.is_none() {
            anyhow::bail!(
                "Scarb build succeeded but no compiled artifact (.sierra.json/.casm.json) was found in {}",
                target_dir.display()
            );
        }

        tracing::info!("Cairo 1 compilation successful");
        self.parse_program_info()?;

        Ok(())
    }

    /// Parse program information from compiled artifact
    fn parse_program_info(&mut self) -> Result<()> {
        let compiled_path = match &self.compiled_path {
            Some(p) => p,
            None => anyhow::bail!("No compiled Cairo artifact available"),
        };

        if compiled_path.exists() {
            let content = std::fs::read_to_string(compiled_path)?;
            let program: serde_json::Value = serde_json::from_str(&content).with_context(|| {
                format!(
                    "Failed parsing compiled Cairo artifact '{}'",
                    compiled_path.display()
                )
            })?;

            // Extract builtins
            let builtins: Vec<String> = match program.get("builtins") {
                Some(v) => {
                    let arr = v
                        .as_array()
                        .ok_or_else(|| anyhow::anyhow!("'builtins' field is not an array"))?;
                    let mut parsed = Vec::with_capacity(arr.len());
                    for item in arr {
                        let item_str = item
                            .as_str()
                            .ok_or_else(|| anyhow::anyhow!("Builtins entry is not a string"))?;
                        parsed.push(item_str.to_string());
                    }
                    parsed
                }
                None => Vec::new(),
            };

            // Count hints for input estimation
            let num_hints = program
                .get("hints")
                .and_then(|v| v.as_object())
                .map(|h| h.len());
            let num_hints = num_hints.unwrap_or_default();

            self.metadata = Some(CairoMetadata {
                name: self.name.clone(),
                num_steps: 0,
                num_memory_cells: 0,
                builtins,
                num_inputs: num_hints.max(1),
                num_outputs: 1,
            });
        }

        Ok(())
    }

    /// Execute the Cairo program with given inputs
    pub fn execute_cairo(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        if !self.compiled {
            anyhow::bail!("Program not compiled. Call compile() first.");
        }

        let _guard = match cairo_io_lock().lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!(
                    "cairo IO lock poisoned during execute; continuing with recovered lock"
                );
                poisoned.into_inner()
            }
        };
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
        self.store_runtime_coverage_sample(None);
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
            compiled_path
                .to_str()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Non-UTF8 compiled program path: {}",
                        compiled_path.display()
                    )
                })?
                .to_string(),
            "--print_output".to_string(),
            "--layout".to_string(),
            self.config.layout.clone(),
        ];

        if self.config.proof_mode {
            args.extend([
                "--trace_file".to_string(),
                trace_path
                    .to_str()
                    .ok_or_else(|| {
                        anyhow::anyhow!("Non-UTF8 trace path: {}", trace_path.display())
                    })?
                    .to_string(),
                "--memory_file".to_string(),
                memory_path
                    .to_str()
                    .ok_or_else(|| {
                        anyhow::anyhow!("Non-UTF8 memory path: {}", memory_path.display())
                    })?
                    .to_string(),
                "--proof_mode".to_string(),
            ]);
        }

        // Add program input if the program expects it
        args.extend([
            "--program_input".to_string(),
            input_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Non-UTF8 input path: {}", input_path.display()))?
                .to_string(),
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
        let outputs = self.parse_cairo_output(&stdout)?;

        if self.config.proof_mode && trace_path.exists() && memory_path.exists() {
            let trace_bytes = std::fs::metadata(&trace_path)
                .map(|m| m.len())
                .unwrap_or_default();
            let memory_bytes = std::fs::metadata(&memory_path)
                .map(|m| m.len())
                .unwrap_or_default();
            self.store_runtime_coverage_sample(Some(CairoRuntimeCoverageSample {
                source: "cairo0_trace".to_string(),
                trace_bytes,
                memory_bytes,
            }));
        }

        Ok(outputs)
    }

    /// Execute Cairo 1 program
    fn execute_cairo1(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        self.store_runtime_coverage_sample(None);
        let project_dir = self.ensure_prepared_scarb_project_dir()?;

        // Create args JSON
        let args: Vec<String> = inputs
            .iter()
            .map(|fe| format!("\"{}\"", field_element_to_decimal(fe)))
            .collect();
        let args_json = format!("[{}]", args.join(", "));

        let output = self.run_scarb_command_with_fallback(
            "Failed to run scarb cairo-run across configured candidates",
            &project_dir,
            |cmd| {
                cmd.args(["cairo-run", "--", &args_json]);
            },
        )?;

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

    fn cairo1_arguments_json(inputs: &[FieldElement]) -> String {
        let args: Vec<String> = inputs.iter().map(field_element_to_decimal).collect();
        format!("[{}]", args.join(", "))
    }

    fn cairo1_arguments_cli(inputs: &[FieldElement]) -> String {
        inputs
            .iter()
            .map(field_element_to_decimal)
            .collect::<Vec<_>>()
            .join(",")
    }

    fn cairo1_witness_digest_hex(inputs: &[FieldElement]) -> String {
        let mut hasher = Sha256::new();
        for value in inputs {
            hasher.update(value.0);
        }
        hex::encode(hasher.finalize())
    }

    fn build_cairo1_proof_artifact(
        execution_id: &str,
        witness: &[FieldElement],
        witness_args_json: String,
    ) -> Cairo1ProofArtifact {
        Cairo1ProofArtifact {
            contract_version: 1,
            framework: "cairo".to_string(),
            backend: "scarb".to_string(),
            proof_transport: "execution_id".to_string(),
            execution_id: execution_id.to_string(),
            witness_count: witness.len(),
            witness_args_json,
            witness_sha256: Self::cairo1_witness_digest_hex(witness),
        }
    }

    fn cairo1_proof_contract_path(&self) -> PathBuf {
        self.build_dir.join("cairo1_proof_contract.json")
    }

    fn serialize_cairo1_proof_artifact(artifact: &Cairo1ProofArtifact) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(artifact)
            .context("Failed serializing Cairo1 proof artifact contract")
    }

    fn parse_cairo1_proof_artifact(proof: &[u8]) -> Result<Cairo1ProofArtifact> {
        let artifact: Cairo1ProofArtifact =
            serde_json::from_slice(proof).context("Invalid Cairo1 proof artifact format")?;

        if artifact.contract_version != 1 {
            anyhow::bail!(
                "Unsupported Cairo1 proof contract version {}; expected 1",
                artifact.contract_version
            );
        }
        if artifact.framework != "cairo" {
            anyhow::bail!(
                "Invalid Cairo1 proof contract framework '{}'; expected 'cairo'",
                artifact.framework
            );
        }
        if artifact.backend != "scarb" {
            anyhow::bail!(
                "Invalid Cairo1 proof contract backend '{}'; expected 'scarb'",
                artifact.backend
            );
        }
        if artifact.proof_transport != "execution_id" {
            anyhow::bail!(
                "Invalid Cairo1 proof transport '{}'; expected 'execution_id'",
                artifact.proof_transport
            );
        }
        if artifact.execution_id.trim().is_empty() {
            anyhow::bail!("Cairo1 proof contract has empty execution_id");
        }
        let parsed_args: serde_json::Value = serde_json::from_str(&artifact.witness_args_json)
            .context("Cairo1 proof contract witness_args_json is not valid JSON")?;
        if !parsed_args.is_array() {
            anyhow::bail!("Cairo1 proof contract witness_args_json must be a JSON array");
        }

        Ok(artifact)
    }

    fn write_cairo1_proof_artifact(&self, artifact: &Cairo1ProofArtifact) -> Result<PathBuf> {
        let contract_path = self.cairo1_proof_contract_path();
        if let Some(parent) = contract_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed creating Cairo1 proof contract directory '{}'",
                    parent.display()
                )
            })?;
        }
        let payload = Self::serialize_cairo1_proof_artifact(artifact)?;
        std::fs::write(&contract_path, payload).with_context(|| {
            format!(
                "Failed writing Cairo1 proof contract '{}'",
                contract_path.display()
            )
        })?;
        Ok(contract_path)
    }

    fn parse_cairo1_execution_id(output: &str) -> Option<String> {
        for line in output.lines() {
            let lowered = line.to_ascii_lowercase();
            if !lowered.contains("execution id") {
                continue;
            }

            let candidate = line
                .split(':')
                .nth(1)
                .unwrap_or(line)
                .split_whitespace()
                .find_map(|token| {
                    let trimmed = token
                        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
                        .trim();
                    if trimmed.is_empty() {
                        return None;
                    }
                    let valid = trimmed
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
                    if valid {
                        Some(trimmed.to_string())
                    } else {
                        None
                    }
                });
            if candidate.is_some() {
                return candidate;
            }
        }
        None
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
        let trace_path_str = trace_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 trace path: {}", trace_path.display()))?;
        let memory_path_str = memory_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 memory path: {}", memory_path.display()))?;
        let output = {
            let proof_path_str = proof_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Non-UTF8 proof path: {}", proof_path.display()))?;
            let config_path_str = config_path.to_str().ok_or_else(|| {
                anyhow::anyhow!("Non-UTF8 prover config path: {}", config_path.display())
            })?;
            let mut cmd = Command::new("cpu_air_prover");
            cmd.args([
                "--out_file",
                proof_path_str,
                "--trace_file",
                trace_path_str,
                "--memory_file",
                memory_path_str,
                "--prover_config_file",
                config_path_str,
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
            Err(e) => {
                tracing::warn!(
                    "Failed reading Cairo source '{}' while collecting wire labels: {}",
                    self.source_path.display(),
                    e
                );
                return labels;
            }
        };

        let functions = analysis::extract_functions(&source);
        let func = functions.iter().find(|f| f.name == "main");

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
        let decoded = match hex::decode(STARK252_MODULUS_HEX) {
            Ok(decoded) => decoded,
            Err(err) => {
                tracing::error!("Failed to decode STARK252 modulus constant: {}", err);
                Vec::new()
            }
        };
        let mut modulus = [0u8; 32];
        let start = 32usize.saturating_sub(decoded.len());
        modulus[start..].copy_from_slice(&decoded[..decoded.len().min(32)]);
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
        let _guard = match cairo_io_lock().lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!(
                    "cairo IO lock poisoned during prove; continuing with recovered lock"
                );
                poisoned.into_inner()
            }
        };

        if self.cairo_version == CairoVersion::Cairo1 {
            let project_dir = self.ensure_prepared_scarb_project_dir()?;

            let args_json = Self::cairo1_arguments_json(witness);
            let args_cli = Self::cairo1_arguments_cli(witness);
            let output = self.run_scarb_command_with_fallback(
                "Failed to run scarb prove --execute across configured candidates",
                &project_dir,
                |cmd| {
                    cmd.args(["prove", "--execute", "--output", "standard"]);
                    if !witness.is_empty() {
                        cmd.args(["--arguments", &args_cli]);
                    }
                },
            )?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            let execution_id = Self::parse_cairo1_execution_id(&stdout).ok_or_else(|| {
                anyhow::anyhow!(
                    "Cairo1 proof generation succeeded but execution id was not found in scarb output"
                )
            })?;
            let artifact = Self::build_cairo1_proof_artifact(&execution_id, witness, args_json);
            let _contract_path = self.write_cairo1_proof_artifact(&artifact)?;
            return Self::serialize_cairo1_proof_artifact(&artifact);
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
            compiled_path
                .to_str()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Non-UTF8 compiled program path: {}",
                        compiled_path.display()
                    )
                })?
                .to_string(),
            "--print_output".to_string(),
            "--layout".to_string(),
            self.config.layout.clone(),
            "--trace_file".to_string(),
            trace_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Non-UTF8 trace path: {}", trace_path.display()))?
                .to_string(),
            "--memory_file".to_string(),
            memory_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Non-UTF8 memory path: {}", memory_path.display()))?
                .to_string(),
            "--proof_mode".to_string(),
            "--program_input".to_string(),
            input_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Non-UTF8 input path: {}", input_path.display()))?
                .to_string(),
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
        let _guard = match cairo_io_lock().lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!(
                    "cairo IO lock poisoned during verify; continuing with recovered lock"
                );
                poisoned.into_inner()
            }
        };

        if self.cairo_version == CairoVersion::Cairo1 {
            let project_dir = self.ensure_prepared_scarb_project_dir()?;

            let artifact = Self::parse_cairo1_proof_artifact(proof)
                .context("Cairo1 verify requires structured proof artifact contract")?;

            let output = self.run_scarb_command_with_fallback(
                "Failed to run scarb verify across configured candidates",
                &project_dir,
                |cmd| {
                    cmd.args(["verify", "--execution-id", &artifact.execution_id]);
                },
            )?;
            return Ok(output.status.success());
        }

        let temp_dir = tempfile::Builder::new()
            .prefix("zkfuzz_cairo_verify_")
            .tempdir()
            .context("Failed to create temp directory")?;
        let proof_path = temp_dir.path().join("proof.json");
        std::fs::write(&proof_path, proof)?;

        // Run stone verifier
        let output = {
            let proof_path_str = proof_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Non-UTF8 proof path: {}", proof_path.display()))?;
            let mut cmd = Command::new("cpu_air_verifier");
            cmd.args(["--in_file", proof_path_str]);
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
        let args_section = match signature
            .split('(')
            .nth(1)
            .and_then(|s| s.split(')').next())
        {
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
            let name = match iter.next() {
                Some(name) => name.trim(),
                None => continue,
            };
            let typ = match iter.next() {
                Some(t) => t.trim(),
                None => "",
            };
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
#[path = "mod_tests.rs"]
mod tests;
