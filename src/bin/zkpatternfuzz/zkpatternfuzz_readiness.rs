use anyhow::Context;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn find_binary_on_path(name: &str) -> bool {
    let Some(path_os) = std::env::var_os("PATH") else {
        return false;
    };
    let has_extension = Path::new(name).extension().is_some();

    std::env::split_paths(&path_os).any(|dir| {
        if dir.join(name).is_file() {
            return true;
        }
        if cfg!(windows) && !has_extension {
            let exts = std::env::var_os("PATHEXT")
                .map(|raw| raw.to_string_lossy().to_string())
                .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string());
            for ext in exts.split(';').filter(|ext| !ext.trim().is_empty()) {
                let candidate = dir.join(format!("{}{}", name, ext.trim()));
                if candidate.is_file() {
                    return true;
                }
            }
        }
        false
    })
}

fn require_binary_on_path(binary: &str, reason: &str) -> anyhow::Result<()> {
    if find_binary_on_path(binary) {
        return Ok(());
    }
    anyhow::bail!("Missing required local tool '{}' ({})", binary, reason)
}

fn summarize_command_failure(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let source = if stderr.trim().is_empty() {
        stdout
    } else {
        stderr
    };
    let mut lines = source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .take(6)
        .collect::<Vec<String>>();
    if lines.is_empty() {
        return "no output".to_string();
    }
    if lines.len() == 6 {
        lines.push("...".to_string());
    }
    lines.join(" | ")
}

pub fn preflight_template_paths<F>(
    template_paths: &[PathBuf],
    validate_pattern_only_yaml: F,
) -> anyhow::Result<()>
where
    F: Fn(&Path) -> anyhow::Result<()>,
{
    for path in template_paths {
        if !path.exists() {
            anyhow::bail!("Template is missing at '{}'", path.display());
        }
        validate_pattern_only_yaml(path).with_context(|| {
            format!(
                "Template '{}' failed pattern-only validation",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn resolve_halo2_manifest_path(target_circuit_path: &Path) -> anyhow::Result<PathBuf> {
    let manifest_path = if target_circuit_path.is_dir() {
        target_circuit_path.join("Cargo.toml")
    } else {
        target_circuit_path.to_path_buf()
    };

    if manifest_path.file_name().and_then(|v| v.to_str()) != Some("Cargo.toml") {
        anyhow::bail!(
            "Halo2 target must point to Cargo.toml or a directory containing Cargo.toml. Got '{}'",
            target_circuit_path.display()
        );
    }
    if !manifest_path.is_file() {
        anyhow::bail!("Halo2 manifest not found at '{}'", manifest_path.display());
    }
    Ok(manifest_path)
}

fn paths_equivalent(lhs: &Path, rhs: &Path) -> bool {
    if lhs == rhs {
        return true;
    }
    match (lhs.canonicalize(), rhs.canonicalize()) {
        (Ok(lhs), Ok(rhs)) => lhs == rhs,
        _ => false,
    }
}

fn halo2_bin_readiness_from_metadata(
    metadata: &serde_json::Value,
    manifest_path: &Path,
) -> anyhow::Result<(Vec<String>, Option<String>)> {
    let packages = metadata
        .get("packages")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("cargo metadata output missing 'packages'"))?;

    let package = packages
        .iter()
        .find(|pkg| {
            pkg.get("manifest_path")
                .and_then(|v| v.as_str())
                .map(|path| paths_equivalent(Path::new(path), manifest_path))
                .unwrap_or(false)
        })
        .or_else(|| {
            if packages.len() == 1 {
                packages.first()
            } else {
                None
            }
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Failed to match Cargo package for manifest '{}'",
                manifest_path.display()
            )
        })?;

    let targets = package
        .get("targets")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("cargo metadata output missing package targets"))?;

    let mut bins = BTreeSet::<String>::new();
    for target in targets {
        let Some(name) = target.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let has_bin_kind = target
            .get("kind")
            .and_then(|v| v.as_array())
            .map(|kinds| {
                kinds
                    .iter()
                    .filter_map(|v| v.as_str())
                    .any(|kind| kind == "bin")
            })
            .unwrap_or(false);
        if has_bin_kind {
            bins.insert(name.to_string());
        }
    }

    let default_run = package
        .get("default_run")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());

    Ok((bins.into_iter().collect(), default_run))
}

fn ensure_halo2_runnable_bin(
    manifest_path: &Path,
    requested_bin: Option<&str>,
) -> anyhow::Result<()> {
    let output = Command::new("cargo")
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--no-deps")
        .arg("--manifest-path")
        .arg(manifest_path)
        .arg("--offline")
        .output()
        .with_context(|| {
            format!(
                "Failed to run cargo metadata for Halo2 target '{}'",
                manifest_path.display()
            )
        })?;

    if !output.status.success() {
        anyhow::bail!(
            "Local Halo2 metadata preflight failed for '{}': {}",
            manifest_path.display(),
            summarize_command_failure(&output)
        );
    }

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).with_context(|| {
            format!(
                "Failed to parse cargo metadata JSON for '{}'",
                manifest_path.display()
            )
        })?;
    let (bins, default_run) = halo2_bin_readiness_from_metadata(&metadata, manifest_path)?;

    if bins.is_empty() {
        anyhow::bail!(
            "Halo2 target '{}' has no runnable Cargo bin target. Provide a manifest with a bin (src/main.rs or [[bin]])",
            manifest_path.display()
        );
    }

    if let Some(ref default_run) = default_run {
        if !bins.iter().any(|bin| bin == default_run) {
            anyhow::bail!(
                "Halo2 target '{}' declares default-run='{}' but available bins are [{}]",
                manifest_path.display(),
                default_run,
                bins.join(", ")
            );
        }
    }

    if let Some(requested_bin) = requested_bin
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !bins.iter().any(|bin| bin == requested_bin) {
            anyhow::bail!(
                "Halo2 target '{}' does not expose requested bin '{}' (available: [{}])",
                manifest_path.display(),
                requested_bin,
                bins.join(", ")
            );
        }
        return Ok(());
    }

    if bins.len() > 1 && default_run.is_none() {
        anyhow::bail!(
            "Halo2 target '{}' has multiple bins ({}) but no default-run. Set default-run or pass --main-component <bin> for deterministic selection",
            manifest_path.display(),
            bins.join(", ")
        );
    }

    Ok(())
}

fn find_cargo_lock_for_manifest(manifest_path: &Path) -> Option<PathBuf> {
    let mut current = manifest_path.parent();
    while let Some(dir) = current {
        let candidate = dir.join("Cargo.lock");
        if candidate.is_file() {
            return Some(candidate);
        }
        current = dir.parent();
    }
    None
}

fn ensure_halo2_dependencies_available_offline(manifest_path: &Path) -> anyhow::Result<()> {
    let lock_path = find_cargo_lock_for_manifest(manifest_path);
    let mut cmd = Command::new("cargo");
    cmd.arg("fetch")
        .arg("--manifest-path")
        .arg(manifest_path)
        .arg("--offline");
    if lock_path.is_some() {
        cmd.arg("--locked");
    }

    let output = cmd.output().with_context(|| {
        format!(
            "Failed to run cargo fetch preflight for '{}'",
            manifest_path.display()
        )
    })?;
    if output.status.success() {
        return Ok(());
    }

    let lock_hint = lock_path
        .map(|p| format!(" using lockfile '{}'", p.display()))
        .unwrap_or_else(|| " (no Cargo.lock found in parent tree)".to_string());
    anyhow::bail!(
        "Missing local Halo2 dependencies for '{}': {}{}. \
Use a fully local cache/vendor setup before running.",
        manifest_path.display(),
        summarize_command_failure(&output),
        lock_hint
    )
}

fn ensure_circom_target_shape(target_circuit_path: &Path) -> anyhow::Result<()> {
    if !target_circuit_path.is_file() {
        anyhow::bail!(
            "Circom target must be a .circom file. Got '{}'",
            target_circuit_path.display()
        );
    }
    if target_circuit_path.extension().and_then(|v| v.to_str()) != Some("circom") {
        anyhow::bail!(
            "Circom target must end with '.circom'. Got '{}'",
            target_circuit_path.display()
        );
    }
    Ok(())
}

fn ensure_cairo_target_shape(target_circuit_path: &Path) -> anyhow::Result<()> {
    if target_circuit_path.is_dir() {
        let manifest = target_circuit_path.join("Scarb.toml");
        if !manifest.is_file() {
            anyhow::bail!(
                "Cairo directory target '{}' is missing Scarb.toml",
                target_circuit_path.display()
            );
        }
        return Ok(());
    }

    if !target_circuit_path.is_file() {
        anyhow::bail!(
            "Cairo target must be a .cairo file or Scarb.toml. Got '{}'",
            target_circuit_path.display()
        );
    }

    let file_name = target_circuit_path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or_default();
    if file_name == "Scarb.toml" {
        return Ok(());
    }
    if target_circuit_path.extension().and_then(|v| v.to_str()) == Some("cairo") {
        return Ok(());
    }

    anyhow::bail!(
        "Cairo target must be .cairo or Scarb.toml. Got '{}'",
        target_circuit_path.display()
    );
}

fn ensure_noir_target_shape(target_circuit_path: &Path) -> anyhow::Result<()> {
    if target_circuit_path.is_dir() {
        let manifest = target_circuit_path.join("Nargo.toml");
        if !manifest.is_file() {
            anyhow::bail!(
                "Noir directory target '{}' is missing Nargo.toml",
                target_circuit_path.display()
            );
        }
        return Ok(());
    }

    if !target_circuit_path.is_file() {
        anyhow::bail!(
            "Noir target must be a .nr file or Nargo.toml. Got '{}'",
            target_circuit_path.display()
        );
    }

    let file_name = target_circuit_path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or_default();
    if file_name == "Nargo.toml" {
        return Ok(());
    }
    if target_circuit_path.extension().and_then(|v| v.to_str()) == Some("nr") {
        return Ok(());
    }

    anyhow::bail!(
        "Noir target must be .nr or Nargo.toml. Got '{}'",
        target_circuit_path.display()
    );
}

fn discover_local_ptau() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    let preferred = cwd.join("bins").join("ptau").join("pot12_final.ptau");
    if preferred.is_file() {
        return Some(preferred);
    }

    let ptau_dir = cwd.join("bins").join("ptau");
    let entries = fs::read_dir(ptau_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|v| v.to_str()) == Some("ptau") && path.is_file() {
            return Some(path);
        }
    }
    None
}

fn ensure_circom_ptau_available() -> anyhow::Result<()> {
    if let Ok(raw) = std::env::var("ZKF_PTAU_PATH") {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            anyhow::bail!("ZKF_PTAU_PATH is set but empty");
        }
        let path = PathBuf::from(trimmed);
        if !path.is_file() {
            anyhow::bail!("ZKF_PTAU_PATH points to missing file '{}'", path.display());
        }
        return Ok(());
    }

    if discover_local_ptau().is_some() {
        return Ok(());
    }

    anyhow::bail!(
        "Missing Circom ptau setup. Set ZKF_PTAU_PATH to a local .ptau file or provide one under bins/ptau/"
    )
}

struct LocalReadinessContext<'a> {
    framework: &'a str,
    target_circuit: &'a str,
    target_circuit_path: &'a Path,
    main_component: &'a str,
}

#[derive(Default)]
struct BaseReadinessChecker;

impl BaseReadinessChecker {
    fn validate_common(&self, ctx: &LocalReadinessContext<'_>) -> anyhow::Result<()> {
        require_binary_on_path(
            "cargo",
            "zkpatternfuzz requires cargo to build/launch zk-fuzzer",
        )?;

        if !ctx.target_circuit_path.exists() {
            anyhow::bail!(
                "target_circuit not found '{}' (resolved from '{}')",
                ctx.target_circuit_path.display(),
                ctx.target_circuit
            );
        }
        Ok(())
    }
}

trait FrameworkReadinessChecker {
    fn base(&self) -> &BaseReadinessChecker;
    fn validate_framework(&self, ctx: &LocalReadinessContext<'_>) -> anyhow::Result<()>;

    fn validate(&self, ctx: &LocalReadinessContext<'_>) -> anyhow::Result<()> {
        self.base().validate_common(ctx)?;
        self.validate_framework(ctx)
    }
}

#[derive(Default)]
struct CircomReadinessChecker {
    base: BaseReadinessChecker,
}

impl FrameworkReadinessChecker for CircomReadinessChecker {
    fn base(&self) -> &BaseReadinessChecker {
        &self.base
    }

    fn validate_framework(&self, ctx: &LocalReadinessContext<'_>) -> anyhow::Result<()> {
        require_binary_on_path("circom", "required for circom target execution")?;
        require_binary_on_path("snarkjs", "required for circom proving/verification")?;
        ensure_circom_target_shape(ctx.target_circuit_path)?;
        ensure_circom_ptau_available()?;
        Ok(())
    }
}

#[derive(Default)]
struct CairoReadinessChecker {
    base: BaseReadinessChecker,
}

impl FrameworkReadinessChecker for CairoReadinessChecker {
    fn base(&self) -> &BaseReadinessChecker {
        &self.base
    }

    fn validate_framework(&self, ctx: &LocalReadinessContext<'_>) -> anyhow::Result<()> {
        require_binary_on_path("scarb", "required for cairo target builds")?;
        require_binary_on_path("cairo-run", "required for cairo execution/proof flow")?;
        ensure_cairo_target_shape(ctx.target_circuit_path)?;
        Ok(())
    }
}

#[derive(Default)]
struct NoirReadinessChecker {
    base: BaseReadinessChecker,
}

impl FrameworkReadinessChecker for NoirReadinessChecker {
    fn base(&self) -> &BaseReadinessChecker {
        &self.base
    }

    fn validate_framework(&self, ctx: &LocalReadinessContext<'_>) -> anyhow::Result<()> {
        require_binary_on_path("nargo", "required for noir target execution")?;
        ensure_noir_target_shape(ctx.target_circuit_path)?;
        Ok(())
    }
}

#[derive(Default)]
struct Halo2ReadinessChecker {
    base: BaseReadinessChecker,
}

impl FrameworkReadinessChecker for Halo2ReadinessChecker {
    fn base(&self) -> &BaseReadinessChecker {
        &self.base
    }

    fn validate_framework(&self, ctx: &LocalReadinessContext<'_>) -> anyhow::Result<()> {
        let manifest_path = resolve_halo2_manifest_path(ctx.target_circuit_path)?;
        ensure_halo2_runnable_bin(&manifest_path, Some(ctx.main_component))?;
        ensure_halo2_dependencies_available_offline(&manifest_path)?;
        Ok(())
    }
}

#[derive(Default)]
struct PassthroughReadinessChecker {
    base: BaseReadinessChecker,
}

impl FrameworkReadinessChecker for PassthroughReadinessChecker {
    fn base(&self) -> &BaseReadinessChecker {
        &self.base
    }

    fn validate_framework(&self, _ctx: &LocalReadinessContext<'_>) -> anyhow::Result<()> {
        Ok(())
    }
}

fn make_framework_readiness_checker(framework: &str) -> Box<dyn FrameworkReadinessChecker> {
    match framework.to_ascii_lowercase().as_str() {
        "circom" => Box::new(CircomReadinessChecker::default()),
        "cairo" => Box::new(CairoReadinessChecker::default()),
        "noir" => Box::new(NoirReadinessChecker::default()),
        "halo2" => Box::new(Halo2ReadinessChecker::default()),
        _ => Box::new(PassthroughReadinessChecker::default()),
    }
}

pub fn ensure_local_runtime_requirements(
    framework: &str,
    target_circuit: &str,
    target_circuit_path: &Path,
    main_component: &str,
) -> anyhow::Result<()> {
    let ctx = LocalReadinessContext {
        framework,
        target_circuit,
        target_circuit_path,
        main_component,
    };
    make_framework_readiness_checker(ctx.framework).validate(&ctx)
}
