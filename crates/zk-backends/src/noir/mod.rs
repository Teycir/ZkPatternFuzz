//! Noir circuit target implementation
//!
//! Provides full integration with the Noir ecosystem:
//! - Compilation via nargo CLI
//! - Witness generation and proving via Barretenberg
//! - Support for Noir's ACIR format

use crate::TargetCircuit;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use zk_core::ConstraintEquation;
use zk_core::FieldElement;
use zk_core::Framework;

fn noir_external_command_timeout() -> std::time::Duration {
    crate::util::timeout_from_env("ZK_FUZZER_NOIR_EXTERNAL_TIMEOUT_SECS", 60)
}

struct ScopedFileOverwrite {
    path: PathBuf,
    original: Option<Vec<u8>>,
}

impl ScopedFileOverwrite {
    fn overwrite(path: PathBuf, contents: &[u8]) -> Result<Self> {
        let original = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => return Err(err).context("Failed reading original file"),
        };
        fs::write(&path, contents).with_context(|| format!("Failed writing {}", path.display()))?;
        Ok(Self { path, original })
    }
}

impl Drop for ScopedFileOverwrite {
    fn drop(&mut self) {
        match self.original.take() {
            Some(bytes) => {
                if let Err(err) = fs::write(&self.path, bytes) {
                    tracing::warn!("Failed restoring '{}': {}", self.path.display(), err);
                }
            }
            None => {
                if let Err(err) = fs::remove_file(&self.path) {
                    if err.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!("Failed removing '{}': {}", self.path.display(), err);
                    }
                }
            }
        }
    }
}

/// Noir circuit target with full backend integration
pub struct NoirTarget {
    /// Path to the Noir project directory (containing Nargo.toml)
    project_path: PathBuf,
    /// Optional project path override used when isolating nested-workspace projects.
    project_path_override: Option<PathBuf>,
    /// Compiled circuit metadata
    metadata: Option<NoirMetadata>,
    /// Build directory for artifacts
    build_dir: PathBuf,
    /// Whether the circuit has been compiled
    compiled: bool,
    /// Cached proving key
    proving_key: Option<Vec<u8>>,
    /// Cached verification key
    verification_key: Option<Vec<u8>>,
    /// Cached ACIR constraint info
    acir_info: OnceLock<NoirAcirInfo>,
}

/// Metadata extracted from compiled Noir circuit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirMetadata {
    /// Circuit name from Nargo.toml
    pub name: String,
    /// Number of ACIR opcodes (roughly equivalent to constraints)
    pub num_opcodes: usize,
    /// Number of witnesses (private inputs)
    pub num_witnesses: usize,
    /// Number of public inputs
    pub num_public_inputs: usize,
    /// Number of return values
    pub num_return_values: usize,
    /// ABI information
    pub abi: NoirAbi,
}

#[derive(Debug, Clone)]
struct NoirAcirInfo {
    constraints: Vec<ConstraintEquation>,
    public_indices: Vec<usize>,
    private_indices: Vec<usize>,
    return_indices: Vec<usize>,
}

/// Noir ABI (Application Binary Interface)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NoirAbi {
    /// Parameter definitions
    pub parameters: Vec<NoirParameter>,
    /// Return type info
    pub return_type: Option<serde_json::Value>,
}

/// Noir function parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirParameter {
    pub name: String,
    #[serde(rename = "type")]
    pub typ: NoirType,
    pub visibility: Visibility,
}

/// Noir type representation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum NoirType {
    #[serde(rename = "field")]
    Field,
    #[serde(rename = "integer")]
    Integer { sign: String, width: u32 },
    #[serde(rename = "boolean")]
    Boolean,
    #[serde(rename = "array")]
    Array { length: usize, typ: Box<NoirType> },
    #[serde(rename = "string")]
    String { length: usize },
    #[serde(rename = "struct")]
    Struct {
        path: String,
        fields: Vec<(String, NoirType)>,
    },
}

/// Parameter visibility
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Visibility {
    #[default]
    Private,
    Public,
}

impl NoirTarget {
    fn active_project_path(&self) -> &Path {
        self.project_path_override
            .as_deref()
            .unwrap_or(self.project_path.as_path())
    }

    /// Get the field name used by this circuit (default Noir field)
    pub fn field_name(&self) -> &str {
        // Noir currently uses the native field (typically BN254 in Barretenberg)
        // Override here if/when project metadata exposes a different field.
        "bn254"
    }

    /// Get wire labels for inputs/outputs when available
    pub fn wire_labels(&self) -> HashMap<usize, String> {
        let mut labels = HashMap::new();

        let metadata = match &self.metadata {
            Some(m) => m,
            None => return labels,
        };

        let mut public_iter = self.public_input_indices().into_iter();
        let mut private_iter = self.private_input_indices().into_iter();

        for param in &metadata.abi.parameters {
            let idx = if param.visibility == Visibility::Public {
                public_iter.next()
            } else {
                private_iter.next()
            };

            if let Some(wire_idx) = idx {
                labels.insert(wire_idx, param.name.clone());
            }
        }

        for (i, wire_idx) in self.output_signal_indices().into_iter().enumerate() {
            labels
                .entry(wire_idx)
                .or_insert_with(|| format!("return_{}", i));
        }

        labels
    }

    fn nargo_home_dir(&self) -> PathBuf {
        self.build_dir.join("nargo_home")
    }

    fn nargo_command(&self) -> Result<Command> {
        std::fs::create_dir_all(&self.build_dir)?;
        let nargo_home = self.nargo_home_dir();
        std::fs::create_dir_all(&nargo_home)?;

        let cargo_home = nargo_home.join("cargo");
        std::fs::create_dir_all(&cargo_home)?;

        let mut command = Command::new("nargo");
        command
            .current_dir(self.active_project_path())
            .env("HOME", &nargo_home)
            .env("NARGO_HOME", &nargo_home)
            .env("CARGO_HOME", &cargo_home)
            .env("NARGO_TARGET_DIR", &self.build_dir)
            .env("CARGO_TARGET_DIR", &self.build_dir);

        Ok(command)
    }

    fn proof_file_candidates(&self) -> Vec<PathBuf> {
        let proof_dir = self.active_project_path().join("proofs");
        let mut candidates = Vec::new();
        let mut seen = HashSet::new();
        for stem in [self.name().to_string(), "main".to_string()] {
            let candidate = proof_dir.join(format!("{}.proof", stem));
            if seen.insert(candidate.clone()) {
                candidates.push(candidate);
            }
        }
        candidates
    }

    /// Create a new Noir target from a project path
    pub fn new(project_path: &str) -> Result<Self> {
        let path = PathBuf::from(project_path);

        // Determine if this is a project dir or a file
        let project_path = if path.is_file() {
            path.parent()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Noir source file path has no parent directory: '{}'",
                        path.display()
                    )
                })?
                .to_path_buf()
        } else {
            path
        };

        let build_dir = project_path.join("target");

        Ok(Self {
            project_path,
            project_path_override: None,
            metadata: None,
            build_dir,
            compiled: false,
            proving_key: None,
            verification_key: None,
            acir_info: OnceLock::new(),
        })
    }

    /// Override the build directory for compiled artifacts.
    pub fn with_build_dir(mut self, build_dir: PathBuf) -> Self {
        self.build_dir = build_dir;
        self
    }

    /// Check if nargo is available
    pub fn check_nargo_available() -> Result<String> {
        let output = Command::new("nargo")
            .arg("--version")
            .output()
            .context("nargo not found in PATH")?;

        if !output.status.success() {
            anyhow::bail!("nargo --version failed");
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Check if bb (Barretenberg) is available
    pub fn check_bb_available() -> Result<String> {
        let output = Command::new("bb")
            .arg("--version")
            .output()
            .context("Failed to run bb --version")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("bb --version failed: {}", stderr.trim());
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Compile the Noir project
    pub fn compile(&mut self) -> Result<()> {
        if self.compiled {
            return Ok(());
        }

        tracing::info!("Compiling Noir project: {:?}", self.active_project_path());

        // Check nargo is available
        let nargo_version = Self::check_nargo_available()?;
        tracing::debug!("Using nargo: {}", nargo_version);

        let _guard = noir_io_lock()
            .lock()
            .expect("noir IO lock poisoned during compile");
        let _dir_lock = crate::util::DirLock::acquire_exclusive(&self.build_dir)?;

        let compile_project = |this: &Self| -> Result<std::process::Output> {
            let mut cmd = this.nargo_command()?;
            cmd.args(["compile"]);
            Ok(
                crate::util::run_with_timeout(&mut cmd, noir_external_command_timeout())
                    .context("Failed to run nargo compile")?,
            )
        };

        // Compile the project
        let mut output = compile_project(self)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if Self::is_missing_selected_package(&stderr)
                && self.enable_isolated_project_mode().with_context(|| {
                    format!(
                        "Failed preparing isolated Noir project from '{}'",
                        self.project_path.display()
                    )
                })?
            {
                tracing::warn!(
                    "Noir package resolution failed in parent workspace; retrying compile in isolated project copy '{}'",
                    self.active_project_path().display()
                );
                output = compile_project(self)?;
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Nargo compilation failed: {}", stderr);
        }

        tracing::info!("Noir compilation successful");

        // Parse circuit info
        self.parse_circuit_info()?;

        self.compiled = true;
        Ok(())
    }

    /// Parse circuit information from compiled artifacts
    fn parse_circuit_info(&mut self) -> Result<()> {
        // Get project name from Nargo.toml
        let nargo_toml_path = self.active_project_path().join("Nargo.toml");
        if !nargo_toml_path.exists() {
            anyhow::bail!(
                "Noir project is missing Nargo.toml at '{}'",
                nargo_toml_path.display()
            );
        }
        let content = std::fs::read_to_string(&nargo_toml_path)?;
        let name = self.parse_project_name(&content)?;

        // Get circuit info using nargo info
        let output = {
            let mut command = self.nargo_command()?;
            command.args(["info", "--json"]);
            crate::util::run_with_timeout(&mut command, noir_external_command_timeout())
                .context("Failed to run nargo info --json")?
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("nargo info --json failed: {}", stderr);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let (num_opcodes, num_witnesses, num_public_inputs) = self.parse_nargo_info(&stdout)?;

        // Parse ABI from compiled artifact
        let abi = self.parse_abi()?;

        self.metadata = Some(NoirMetadata {
            name,
            num_opcodes,
            num_witnesses,
            num_public_inputs,
            num_return_values: 0,
            abi,
        });

        Ok(())
    }

    /// Parse project name from Nargo.toml
    fn parse_project_name(&self, content: &str) -> Result<String> {
        for line in content.lines() {
            if line.trim().starts_with("name") {
                if let Some(value) = line.split('=').nth(1) {
                    let parsed = value.trim().trim_matches('"').to_string();
                    if parsed.is_empty() {
                        anyhow::bail!("Noir project name in Nargo.toml is empty");
                    }
                    return Ok(parsed);
                }
            }
        }
        anyhow::bail!("Missing 'name' entry in Nargo.toml")
    }

    /// Parse nargo info output
    fn parse_nargo_info(&self, output: &str) -> Result<(usize, usize, usize)> {
        let info: serde_json::Value =
            serde_json::from_str(output).context("Invalid JSON from nargo info --json")?;
        let scalar = |key: &str| {
            info.get(key)
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .unwrap_or(0)
        };

        // Legacy schema:
        //   {"opcodes": X, "witnesses": Y, "public_inputs": Z}
        //
        // Newer schema (observed in modern nargo):
        //   {"programs":[{"functions":[{"opcodes": X}, ...], ...}], ...}
        let opcodes = if let Some(v) = info.get("opcodes").and_then(|v| v.as_u64()) {
            v as usize
        } else if let Some(programs) = info.get("programs").and_then(|v| v.as_array()) {
            programs
                .iter()
                .flat_map(|program| {
                    program
                        .get("functions")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default()
                })
                .filter_map(|func| func.get("opcodes").and_then(|v| v.as_u64()))
                .map(|v| v as usize)
                .sum()
        } else {
            0
        };

        if opcodes == 0 {
            anyhow::bail!("Missing 'opcodes' in nargo info output");
        }

        let witnesses = scalar("witnesses");
        let public = scalar("public_inputs");
        Ok((opcodes, witnesses, public))
    }

    /// Parse ABI from compiled artifact
    fn parse_abi(&self) -> Result<NoirAbi> {
        let candidates = self.candidate_artifact_paths()?;

        for json_path in candidates {
            if !json_path.exists() {
                continue;
            }
            let content = std::fs::read_to_string(&json_path)?;
            match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(artifact) => {
                    if let Some(abi) = artifact.get("abi") {
                        return Ok(serde_json::from_value(abi.clone())?);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed parsing Noir artifact JSON '{}': {}",
                        json_path.display(),
                        e
                    );
                }
            }
        }

        anyhow::bail!(
            "Failed to locate ABI in Noir artifacts (build_dir='{}', project_target='{}')",
            self.build_dir.display(),
            self.active_project_path().join("target").display()
        )
    }

    fn candidate_artifact_paths(&self) -> Result<Vec<PathBuf>> {
        use std::collections::HashSet;

        let mut candidates = Vec::new();
        let mut seen = HashSet::new();

        if let Some(metadata) = &self.metadata {
            let path = self.build_dir.join(format!("{}.json", metadata.name));
            if seen.insert(path.clone()) {
                candidates.push(path);
            }
        }

        let nargo_toml_path = self.active_project_path().join("Nargo.toml");
        if nargo_toml_path.exists() {
            let content = std::fs::read_to_string(&nargo_toml_path)
                .with_context(|| format!("Failed reading '{}'", nargo_toml_path.display()))?;
            let name = self.parse_project_name(&content)?;
            let path = self.build_dir.join(format!("{}.json", name));
            if seen.insert(path.clone()) {
                candidates.push(path);
            }
            let project_target_named = self
                .active_project_path()
                .join("target")
                .join(format!("{}.json", name));
            if seen.insert(project_target_named.clone()) {
                candidates.push(project_target_named);
            }
        }

        for stem in ["program", "main"] {
            let project_target_default = self
                .active_project_path()
                .join("target")
                .join(format!("{stem}.json"));
            if seen.insert(project_target_default.clone()) {
                candidates.push(project_target_default);
            }
        }

        self.collect_json_candidates(self.build_dir.as_path(), 3, &mut candidates, &mut seen)?;
        let project_target_dir = self.active_project_path().join("target");
        self.collect_json_candidates(project_target_dir.as_path(), 2, &mut candidates, &mut seen)?;

        Ok(candidates)
    }

    fn collect_json_candidates(
        &self,
        root: &Path,
        max_depth: usize,
        candidates: &mut Vec<PathBuf>,
        seen: &mut HashSet<PathBuf>,
    ) -> Result<()> {
        if !root.exists() {
            return Ok(());
        }

        let mut stack = vec![(root.to_path_buf(), 0usize)];
        while let Some((dir, depth)) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(err) => {
                    tracing::debug!(
                        "Failed reading Noir artifact directory '{}': {}",
                        dir.display(),
                        err
                    );
                    continue;
                }
            };

            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(err) => {
                        tracing::debug!(
                            "Failed reading Noir artifact entry in '{}': {}",
                            dir.display(),
                            err
                        );
                        continue;
                    }
                };
                let path = entry.path();
                let file_type = match entry.file_type() {
                    Ok(file_type) => file_type,
                    Err(err) => {
                        tracing::debug!(
                            "Failed reading Noir artifact file type '{}': {}",
                            path.display(),
                            err
                        );
                        continue;
                    }
                };

                if file_type.is_file()
                    && path
                        .extension()
                        .is_some_and(|extension| extension == "json")
                    && seen.insert(path.clone())
                {
                    candidates.push(path);
                } else if file_type.is_dir() && depth < max_depth {
                    stack.push((path, depth + 1));
                }
            }
        }

        Ok(())
    }

    fn is_missing_selected_package(stderr: &str) -> bool {
        stderr.contains("Selected package `") && stderr.contains("was not found")
    }

    fn enable_isolated_project_mode(&mut self) -> Result<bool> {
        if self.project_path_override.is_some() {
            return Ok(false);
        }

        let manifest_path = self.project_path.join("Nargo.toml");
        let manifest_content = fs::read_to_string(&manifest_path)
            .with_context(|| format!("Failed reading '{}'", manifest_path.display()))?;

        // Path dependencies commonly rely on sibling-relative paths. Keep original
        // layout in that case instead of copying into an isolated directory.
        if manifest_content
            .lines()
            .any(|line| !line.trim_start().starts_with('#') && line.contains("path ="))
        {
            tracing::warn!(
                "Skipping Noir isolated-project fallback for '{}' because manifest uses path dependencies",
                manifest_path.display()
            );
            return Ok(false);
        }

        let isolated_root = self.build_dir.join("isolated_project");
        if isolated_root.exists() {
            fs::remove_dir_all(&isolated_root).with_context(|| {
                format!(
                    "Failed removing stale isolated directory '{}'",
                    isolated_root.display()
                )
            })?;
        }
        self.copy_project_tree(self.project_path.as_path(), isolated_root.as_path())?;
        self.project_path_override = Some(isolated_root);
        Ok(true)
    }

    fn copy_project_tree(&self, src: &Path, dst: &Path) -> Result<()> {
        fs::create_dir_all(dst).with_context(|| format!("Failed creating '{}'", dst.display()))?;

        for entry in
            fs::read_dir(src).with_context(|| format!("Failed reading '{}'", src.display()))?
        {
            let entry =
                entry.with_context(|| format!("Failed reading entry in '{}'", src.display()))?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());
            let file_type = entry.file_type().with_context(|| {
                format!("Failed reading file type for '{}'", src_path.display())
            })?;

            if file_type.is_symlink() {
                continue;
            }

            if file_type.is_dir() {
                let skip = src_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| matches!(name, "target" | "proofs" | ".git"));
                if skip {
                    continue;
                }
                self.copy_project_tree(src_path.as_path(), dst_path.as_path())?;
                continue;
            }

            if file_type.is_file() {
                fs::copy(&src_path, &dst_path).with_context(|| {
                    format!(
                        "Failed copying Noir project file '{}' to '{}'",
                        src_path.display(),
                        dst_path.display()
                    )
                })?;
            }
        }

        Ok(())
    }

    /// Load the compiled ACIR artifact (JSON) when available.
    pub fn load_acir_artifact(&self) -> Option<Vec<u8>> {
        let candidates = match self.candidate_artifact_paths() {
            Ok(candidates) => candidates,
            Err(err) => {
                tracing::warn!("Failed resolving Noir artifact candidates: {}", err);
                return None;
            }
        };
        for json_path in candidates {
            if !json_path.exists() {
                continue;
            }

            let bytes = match std::fs::read(&json_path) {
                Ok(bytes) => bytes,
                Err(err) => {
                    tracing::warn!(
                        "Failed reading Noir artifact '{}': {}",
                        json_path.display(),
                        err
                    );
                    continue;
                }
            };
            match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(artifact) => {
                    if artifact.get("opcodes").is_some()
                        || artifact.get("program").is_some()
                        || artifact.get("functions").is_some()
                        || artifact.get("constraints").is_some()
                        || artifact.get("bytecode").is_some()
                    {
                        return Some(bytes);
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        "Failed parsing Noir artifact bytes '{}': {}",
                        json_path.display(),
                        err
                    );
                }
            }
        }

        None
    }

    /// Load ACIR text via `nargo compile --print-acir` when available.
    pub fn load_acir_text(&self) -> Option<String> {
        let _guard = noir_io_lock()
            .lock()
            .expect("noir IO lock poisoned while loading ACIR text");
        let _dir_lock = match crate::util::DirLock::acquire_shared(&self.build_dir) {
            Ok(lock) => lock,
            Err(err) => {
                tracing::warn!(
                    "Failed to acquire Noir shared build lock '{}': {}",
                    self.build_dir.display(),
                    err
                );
                return None;
            }
        };

        let output = {
            let mut cmd = match self.nargo_command() {
                Ok(cmd) => cmd,
                Err(err) => {
                    tracing::warn!("Failed building nargo command: {}", err);
                    return None;
                }
            };
            cmd.args(["compile", "--print-acir"]);
            match crate::util::run_with_timeout(&mut cmd, noir_external_command_timeout()) {
                Ok(output) => output,
                Err(err) => {
                    tracing::warn!("Failed running 'nargo compile --print-acir': {}", err);
                    return None;
                }
            }
        };

        if !output.status.success() {
            tracing::warn!(
                "nargo compile --print-acir failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return None;
        }

        Some(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn acir_info(&self) -> Result<&NoirAcirInfo> {
        if self.acir_info.get().is_none() {
            let info = self.build_acir_info()?;
            if self.acir_info.set(info).is_err() {
                anyhow::bail!("Failed to initialize ACIR info cache");
            }
        }

        self.acir_info
            .get()
            .ok_or_else(|| anyhow::anyhow!("ACIR info unavailable"))
    }

    fn build_acir_info(&self) -> Result<NoirAcirInfo> {
        let _guard = noir_io_lock()
            .lock()
            .expect("noir IO lock poisoned while building ACIR info");
        let _dir_lock = crate::util::DirLock::acquire_shared(&self.build_dir)?;

        let output = {
            let mut cmd = self.nargo_command()?;
            cmd.args(["compile", "--print-acir"]);
            crate::util::run_with_timeout(&mut cmd, noir_external_command_timeout())
                .context("Failed to run nargo compile --print-acir")?
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Nargo ACIR print failed: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_acir_output(&stdout))
    }

    pub fn load_constraints(&self) -> Result<Vec<ConstraintEquation>> {
        Ok(self.acir_info()?.constraints.clone())
    }

    pub fn public_input_indices(&self) -> Vec<usize> {
        match self.acir_info() {
            Ok(info) => info.public_indices.clone(),
            Err(err) => {
                tracing::warn!("Failed reading Noir public input indices: {}", err);
                Vec::new()
            }
        }
    }

    pub fn private_input_indices(&self) -> Vec<usize> {
        match self.acir_info() {
            Ok(info) => info.private_indices.clone(),
            Err(err) => {
                tracing::warn!("Failed reading Noir private input indices: {}", err);
                Vec::new()
            }
        }
    }

    pub fn output_signal_indices(&self) -> Vec<usize> {
        match self.acir_info() {
            Ok(info) => info.return_indices.clone(),
            Err(err) => {
                tracing::warn!("Failed reading Noir output indices: {}", err);
                Vec::new()
            }
        }
    }

    /// Execute circuit with given inputs
    pub fn execute_noir(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        if !self.compiled {
            anyhow::bail!("Circuit not compiled. Call compile() first.");
        }

        let _guard = noir_io_lock()
            .lock()
            .expect("noir IO lock poisoned during execute");
        let _dir_lock = crate::util::DirLock::acquire_exclusive(self.active_project_path())?;

        // Create Prover.toml with inputs
        let prover_toml = self.create_prover_toml(inputs)?;
        let prover_path = self.active_project_path().join("Prover.toml");
        let _prover_guard = ScopedFileOverwrite::overwrite(prover_path, prover_toml.as_bytes())?;

        // Execute using nargo execute (JSON output is version-dependent)
        let output = {
            let mut cmd = self.nargo_command()?;
            cmd.args(["execute", "--json"]);
            crate::util::run_with_timeout(&mut cmd, noir_external_command_timeout())
                .context("Failed to execute Noir circuit")?
        };

        let output = if output.status.success() {
            output
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("unexpected argument '--json'") {
                let mut cmd = self.nargo_command()?;
                cmd.args(["execute"]);
                crate::util::run_with_timeout(&mut cmd, noir_external_command_timeout())
                    .context("Failed to execute Noir circuit without --json")?
            } else {
                anyhow::bail!("Noir execution failed: {}", stderr);
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Noir execution failed: {}", stderr);
        }

        // Parse output
        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_execution_output(&stdout)
    }

    /// Create Prover.toml content from inputs
    fn create_prover_toml(&self, inputs: &[FieldElement]) -> Result<String> {
        let mut toml = String::new();

        if let Some(metadata) = &self.metadata {
            let mut public_params = Vec::new();
            let mut private_params = Vec::new();

            for param in &metadata.abi.parameters {
                if param.visibility == Visibility::Public {
                    public_params.push(param);
                } else {
                    private_params.push(param);
                }
            }

            let mut idx = 0usize;
            for param in public_params.into_iter().chain(private_params.into_iter()) {
                if idx < inputs.len() {
                    let value = field_element_to_noir_value(&inputs[idx]);
                    toml.push_str(&format!("{} = {}\n", param.name, value));
                    idx += 1;
                }
            }
        } else {
            // Default parameter names
            for (i, input) in inputs.iter().enumerate() {
                let value = field_element_to_noir_value(input);
                toml.push_str(&format!("x{} = {}\n", i, value));
            }
        }

        Ok(toml)
    }

    /// Parse execution output
    fn parse_execution_output(&self, output: &str) -> Result<Vec<FieldElement>> {
        // Try to parse JSON output
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
            if let Some(return_value) = json.get("return_value") {
                return self.parse_noir_value(return_value);
            }
        }

        for line in output.lines() {
            if let Some(idx) = line.find("Circuit output:") {
                let value_str = line[idx + "Circuit output:".len()..].trim();
                if value_str.starts_with('[') && value_str.ends_with(']') {
                    let inner = &value_str[1..value_str.len().saturating_sub(1)];
                    let mut results = Vec::new();
                    for part in inner.split(',') {
                        let part = part.trim();
                        if part.is_empty() {
                            continue;
                        }
                        results.push(parse_noir_field(part)?);
                    }
                    return Ok(results);
                }
                return Ok(vec![parse_noir_field(value_str)?]);
            }
        }

        // If no return value, return empty
        Ok(vec![])
    }

    /// Parse a Noir value to FieldElements
    fn parse_noir_value(&self, value: &serde_json::Value) -> Result<Vec<FieldElement>> {
        Self::parse_value_internal(value)
    }

    fn parse_value_internal(value: &serde_json::Value) -> Result<Vec<FieldElement>> {
        match value {
            serde_json::Value::String(s) => Ok(vec![parse_noir_field(s)?]),
            serde_json::Value::Number(n) => {
                let num = n.as_u64().ok_or_else(|| {
                    anyhow::anyhow!("Unsupported non-u64 Noir JSON number: {}", n)
                })?;
                Ok(vec![FieldElement::from_u64(num)])
            }
            serde_json::Value::Array(arr) => {
                let mut results = Vec::new();
                for item in arr {
                    results.extend(Self::parse_value_internal(item)?);
                }
                Ok(results)
            }
            serde_json::Value::Object(obj) => {
                // Struct - flatten fields
                let mut results = Vec::new();
                for (_, v) in obj {
                    results.extend(Self::parse_value_internal(v)?);
                }
                Ok(results)
            }
            _ => anyhow::bail!(
                "Unsupported Noir JSON value type for witness input: {}",
                value
            ),
        }
    }

    /// Generate proving and verification keys
    pub fn setup_keys(&mut self) -> Result<()> {
        if !self.compiled {
            self.compile()?;
        }

        tracing::warn!(
            "Noir backend does not expose explicit key generation; \
             nargo prove/verify handles keys internally. setup_keys is a no-op."
        );

        self.proving_key = None;
        self.verification_key = None;

        Ok(())
    }
}

fn noir_io_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

impl TargetCircuit for NoirTarget {
    fn framework(&self) -> Framework {
        Framework::Noir
    }

    fn field_modulus(&self) -> [u8; 32] {
        // Noir uses BN254 (Barretenberg backend)
        let hex_str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
        let decoded = hex::decode(hex_str).expect("Noir BN254 modulus constant must be valid hex");
        let mut modulus = [0u8; 32];
        modulus.copy_from_slice(&decoded);
        modulus
    }

    fn field_name(&self) -> &str {
        "bn254"
    }

    fn name(&self) -> &str {
        self.metadata
            .as_ref()
            .map(|m| m.name.as_str())
            .expect("Noir metadata unavailable; call compile() before querying name")
    }

    fn num_constraints(&self) -> usize {
        self.metadata
            .as_ref()
            .map(|m| m.num_opcodes)
            .expect("Noir metadata unavailable; call compile() before querying num_constraints")
    }

    fn num_private_inputs(&self) -> usize {
        let metadata = self
            .metadata
            .as_ref()
            .expect("Noir metadata unavailable; call compile() before querying num_private_inputs");
        if !metadata.abi.parameters.is_empty() {
            return metadata
                .abi
                .parameters
                .iter()
                .filter(|p| p.visibility != Visibility::Public)
                .count();
        }
        metadata.num_witnesses
    }

    fn num_public_inputs(&self) -> usize {
        let metadata = self
            .metadata
            .as_ref()
            .expect("Noir metadata unavailable; call compile() before querying num_public_inputs");
        let public = metadata
            .abi
            .parameters
            .iter()
            .filter(|p| p.visibility == Visibility::Public)
            .count();
        if public > 0 {
            return public;
        }
        metadata.num_public_inputs
    }

    fn execute(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        self.execute_noir(inputs)
    }

    fn prove(&self, witness: &[FieldElement]) -> Result<Vec<u8>> {
        if !self.compiled {
            anyhow::bail!("Circuit not compiled. Call compile() first.");
        }

        let _guard = noir_io_lock()
            .lock()
            .expect("noir IO lock poisoned during prove");
        let _dir_lock = crate::util::DirLock::acquire_exclusive(self.active_project_path())?;

        // Create Prover.toml
        let prover_toml = self.create_prover_toml(witness)?;
        let prover_path = self.active_project_path().join("Prover.toml");
        let _prover_guard = ScopedFileOverwrite::overwrite(prover_path, prover_toml.as_bytes())?;

        // Generate proof using nargo
        let output = {
            let mut cmd = self.nargo_command()?;
            cmd.args(["prove"]);
            crate::util::run_with_timeout(&mut cmd, noir_external_command_timeout())
                .context("Failed to generate Noir proof")?
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Noir proof generation failed: {}", stderr);
        }

        // Read generated proof from known nargo output locations.
        for proof_path in self.proof_file_candidates() {
            if proof_path.exists() {
                return Ok(std::fs::read(&proof_path)?);
            }
        }
        anyhow::bail!("Proof file not found")
    }

    fn verify(&self, proof: &[u8], _public_inputs: &[FieldElement]) -> Result<bool> {
        if !self.compiled {
            anyhow::bail!("Circuit not compiled. Call compile() first.");
        }

        let _guard = noir_io_lock()
            .lock()
            .expect("noir IO lock poisoned during verify");
        let _dir_lock = crate::util::DirLock::acquire_exclusive(self.active_project_path())?;

        // Write proof to all known nargo lookup paths for compatibility across noir versions.
        let mut _proof_guards = Vec::new();
        for proof_path in self.proof_file_candidates() {
            if let Some(parent) = proof_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            _proof_guards.push(ScopedFileOverwrite::overwrite(proof_path, proof)?);
        }

        // Verify using nargo
        let output = {
            let mut cmd = self.nargo_command()?;
            cmd.args(["verify"]);
            crate::util::run_with_timeout(&mut cmd, noir_external_command_timeout())
                .context("Failed to verify Noir proof")?
        };

        Ok(output.status.success())
    }
}

fn extract_witness_indices(text: &str) -> Vec<usize> {
    let mut indices = Vec::new();
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == 'w' {
            let mut digits = String::new();
            while let Some(next) = chars.peek() {
                if next.is_ascii_digit() {
                    digits.push(*next);
                    chars.next();
                } else {
                    break;
                }
            }
            if !digits.is_empty() {
                match digits.parse::<usize>() {
                    Ok(idx) => indices.push(idx),
                    Err(e) => {
                        tracing::warn!("Failed to parse ACIR witness index '{}': {}", digits, e);
                    }
                }
            }
        }
    }

    indices
}

fn parse_acir_output(output: &str) -> NoirAcirInfo {
    let mut public_indices = Vec::new();
    let mut private_indices = Vec::new();
    let mut return_indices = Vec::new();
    let mut constraints = Vec::new();
    let mut id = 0usize;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("private parameters:") {
            private_indices = extract_witness_indices(trimmed);
            continue;
        }
        if trimmed.starts_with("public parameters:") {
            public_indices = extract_witness_indices(trimmed);
            continue;
        }
        if trimmed.starts_with("return values:") {
            return_indices = extract_witness_indices(trimmed);
            continue;
        }
        if trimmed.starts_with("ASSERT") {
            let (output_idx, input_indices, rhs_text) =
                if let Some((lhs, rhs)) = trimmed.split_once('=') {
                    let lhs_indices = extract_witness_indices(lhs);
                    let rhs_indices = extract_witness_indices(rhs);
                    (
                        lhs_indices.into_iter().next(),
                        rhs_indices,
                        Some(rhs.trim()),
                    )
                } else {
                    let all_indices = extract_witness_indices(trimmed);
                    if all_indices.len() >= 2 {
                        (Some(all_indices[0]), all_indices[1..].to_vec(), None)
                    } else {
                        (None, Vec::new(), None)
                    }
                };

            if let Some(out_idx) = output_idx {
                let is_multiplication = match rhs_text {
                    Some(rhs) => rhs.contains('*'),
                    None => false,
                };
                if is_multiplication && input_indices.len() >= 2 {
                    constraints.push(ConstraintEquation {
                        id,
                        a_terms: vec![(input_indices[0], FieldElement::one())],
                        b_terms: vec![(input_indices[1], FieldElement::one())],
                        c_terms: vec![(out_idx, FieldElement::one())],
                        description: Some("noir acir mul".to_string()),
                    });
                } else {
                    let a_terms = input_indices
                        .into_iter()
                        .map(|idx| (idx, FieldElement::one()))
                        .collect();

                    constraints.push(ConstraintEquation {
                        id,
                        a_terms,
                        b_terms: vec![(0, FieldElement::one())],
                        c_terms: vec![(out_idx, FieldElement::one())],
                        description: Some("noir acir".to_string()),
                    });
                }
                id += 1;
            }
        }
    }

    NoirAcirInfo {
        constraints,
        public_indices,
        private_indices,
        return_indices,
    }
}

/// Parse a Noir field element string
fn parse_noir_field(s: &str) -> Result<FieldElement> {
    let clean = s.trim().trim_matches('"');

    if clean.starts_with("0x") || clean.starts_with("0X") {
        FieldElement::from_hex(clean)
    } else {
        // Decimal
        use num_bigint::BigUint;
        let value = BigUint::parse_bytes(clean.as_bytes(), 10)
            .ok_or_else(|| anyhow::anyhow!("Invalid decimal: {}", s))?;

        let bytes = value.to_bytes_be();
        let mut result = [0u8; 32];
        let start = 32usize.saturating_sub(bytes.len());
        result[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);

        Ok(FieldElement(result))
    }
}

/// Convert FieldElement to Noir TOML value format
fn field_element_to_noir_value(fe: &FieldElement) -> String {
    use num_bigint::BigUint;
    let value = BigUint::from_bytes_be(&fe.0);
    format!("\"{}\"", value)
}

/// Noir-specific analysis utilities
pub mod analysis {
    /// Extract function signatures from Noir source
    pub fn extract_functions(source: &str) -> Vec<NoirFunction> {
        let mut functions = Vec::new();

        for line in source.lines() {
            let trimmed = line.trim();

            // Look for function declarations
            if trimmed.starts_with("fn ") || trimmed.starts_with("pub fn ") {
                if let Some(func) = parse_function_signature(trimmed) {
                    functions.push(func);
                }
            }
        }

        functions
    }

    /// Parse a function signature
    fn parse_function_signature(line: &str) -> Option<NoirFunction> {
        // fn main(x: Field, y: pub Field) -> Field
        let is_main = line.contains("fn main");

        // Extract name
        let after_fn = line.split("fn ").nth(1)?;
        let name = after_fn.split('(').next()?.trim().to_string();

        // Extract parameters
        let params_str = after_fn.split('(').nth(1)?.split(')').next()?;
        let params: Vec<(String, String)> = params_str
            .split(',')
            .filter_map(|p| {
                let parts: Vec<&str> = p.trim().split(':').collect();
                if parts.len() >= 2 {
                    Some((
                        parts[0].trim().trim_start_matches("pub ").to_string(),
                        parts[1].trim().to_string(),
                    ))
                } else {
                    None
                }
            })
            .collect();

        // Extract return type
        let return_type = if line.contains("->") {
            line.split("->")
                .nth(1)
                .map(|s| s.trim().trim_end_matches('{').trim().to_string())
        } else {
            None
        };

        Some(NoirFunction {
            name,
            params,
            return_type,
            is_main,
        })
    }

    /// Noir function information
    #[derive(Debug, Clone)]
    pub struct NoirFunction {
        pub name: String,
        pub params: Vec<(String, String)>,
        pub return_type: Option<String>,
        pub is_main: bool,
    }

    /// Analyze Noir source for common issues
    pub fn analyze_for_vulnerabilities(source: &str) -> Vec<VulnerabilityHint> {
        let mut hints = Vec::new();

        // Check for unconstrained functions that might leak private data
        if source.contains("unconstrained") {
            hints.push(VulnerabilityHint {
                hint_type: VulnerabilityType::UnconstrainedFunction,
                description:
                    "Contains unconstrained functions - ensure they don't leak private data"
                        .to_string(),
                line: None,
            });
        }

        // Check for missing assertions
        let assert_count = source.matches("assert").count();
        let fn_count = source.matches("fn ").count();

        if fn_count > assert_count {
            hints.push(VulnerabilityHint {
                hint_type: VulnerabilityType::MissingAssertions,
                description: format!(
                    "Found {} functions but only {} assertions - some constraints may be missing",
                    fn_count, assert_count
                ),
                line: None,
            });
        }

        hints
    }

    /// Vulnerability hint
    #[derive(Debug, Clone)]
    pub struct VulnerabilityHint {
        pub hint_type: VulnerabilityType,
        pub description: String,
        pub line: Option<usize>,
    }

    /// Vulnerability types
    #[derive(Debug, Clone, PartialEq)]
    pub enum VulnerabilityType {
        UnconstrainedFunction,
        MissingAssertions,
        UnsafeArithmetic,
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
