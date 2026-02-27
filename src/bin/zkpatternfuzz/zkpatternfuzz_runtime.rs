use anyhow::Context;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::Ordering;

use super::{resolve_build_cache_dir, RUN_ROOT_NONCE};

fn ensure_writable_dir(path: &Path, label: &str) -> anyhow::Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("Failed to create {} '{}'", label, path.display()))?;

    let probe_name = format!(
        ".zkpatternfuzz_probe_{}_{}",
        std::process::id(),
        RUN_ROOT_NONCE.fetch_add(1, Ordering::Relaxed)
    );
    let probe_path = path.join(probe_name);
    fs::write(&probe_path, b"probe")
        .with_context(|| format!("{} is not writable at '{}'", label, path.display()))?;
    let _ = fs::remove_file(&probe_path);
    Ok(())
}

pub(super) fn preflight_runtime_paths(results_root: &Path) -> anyhow::Result<(PathBuf, PathBuf)> {
    ensure_writable_dir(results_root, "results root")?;
    let run_signal_dir = results_root.join("run_signals");
    ensure_writable_dir(&run_signal_dir, "run signal dir")?;
    let build_cache_dir = resolve_build_cache_dir(results_root);
    ensure_writable_dir(&build_cache_dir, "build cache dir")?;
    Ok((run_signal_dir, build_cache_dir))
}

pub(super) fn push_unique_nonempty(values: &mut Vec<String>, candidate: impl Into<String>) {
    let candidate = candidate.into();
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return;
    }
    if values.iter().any(|existing| existing == trimmed) {
        return;
    }
    values.push(trimmed.to_string());
}

pub(super) fn parse_rustup_toolchain_names(raw: &str) -> Vec<String> {
    let mut parsed = Vec::new();
    for line in raw.lines() {
        let first = line.split_whitespace().next().unwrap_or_default().trim();
        if first.is_empty() || first.starts_with("info:") || first.starts_with("error:") {
            continue;
        }
        push_unique_nonempty(&mut parsed, first.trim_end_matches(','));
    }
    parsed
}

fn rustup_stdout(args: &[&str]) -> Option<String> {
    let output = Command::new("rustup").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

pub(super) fn auto_halo2_toolchain_candidates() -> Vec<String> {
    let mut candidates = Vec::<String>::new();

    if let Some(active) = rustup_stdout(&["show", "active-toolchain"]) {
        if let Some(toolchain) = active.split_whitespace().next() {
            push_unique_nonempty(&mut candidates, toolchain);
        }
    }

    let installed = rustup_stdout(&["toolchain", "list"])
        .map(|raw| parse_rustup_toolchain_names(&raw))
        .unwrap_or_default();
    let installed_set = installed.iter().cloned().collect::<BTreeSet<String>>();

    for preferred in [
        "nightly-x86_64-unknown-linux-gnu",
        "nightly",
        "stable-x86_64-unknown-linux-gnu",
        "stable",
    ] {
        if installed_set.contains(preferred) {
            push_unique_nonempty(&mut candidates, preferred);
        }
    }

    for name in &installed {
        if name.starts_with("nightly-") {
            push_unique_nonempty(&mut candidates, name);
        }
    }
    for name in &installed {
        if name.starts_with("stable-") {
            push_unique_nonempty(&mut candidates, name);
        }
    }
    for name in &installed {
        push_unique_nonempty(&mut candidates, name);
    }

    const MAX_AUTO_TOOLCHAINS: usize = 6;
    if candidates.len() > MAX_AUTO_TOOLCHAINS {
        candidates.truncate(MAX_AUTO_TOOLCHAINS);
    }
    candidates
}

pub(super) fn is_external_target(target_circuit: &str) -> bool {
    let target_path = Path::new(target_circuit);
    if !target_path.is_absolute() {
        return false;
    }

    let Ok(workspace_root) = std::env::current_dir() else {
        return false;
    };
    !target_path.starts_with(&workspace_root)
}

fn resolve_halo2_manifest_path(target_circuit: &str) -> anyhow::Result<PathBuf> {
    let candidate = PathBuf::from(target_circuit);
    if candidate.is_file() {
        let is_manifest = candidate
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name == "Cargo.toml")
            .unwrap_or(false);
        if is_manifest {
            return Ok(candidate);
        }
        anyhow::bail!(
            "Halo2 target '{}' must be Cargo.toml or a directory containing Cargo.toml",
            target_circuit
        );
    }

    if candidate.is_dir() {
        let manifest = candidate.join("Cargo.toml");
        if manifest.is_file() {
            return Ok(manifest);
        }
        anyhow::bail!(
            "Halo2 target directory '{}' does not contain Cargo.toml",
            target_circuit
        );
    }

    anyhow::bail!(
        "Halo2 target '{}' does not exist or is not a file/directory",
        target_circuit
    );
}

pub(super) fn prepare_target_for_framework(
    framework: &str,
    target_circuit: &str,
) -> anyhow::Result<bool> {
    if !framework.eq_ignore_ascii_case("halo2") {
        return Ok(false);
    }

    let manifest = resolve_halo2_manifest_path(target_circuit)?;
    let status = Command::new("cargo")
        .args(["build", "--release", "--manifest-path"])
        .arg(&manifest)
        .status()
        .with_context(|| {
            format!(
                "Failed to execute cargo build for Halo2 target '{}'",
                manifest.display()
            )
        })?;

    if !status.success() {
        anyhow::bail!(
            "Halo2 target prepare failed: cargo build --release --manifest-path '{}' exited with non-zero status",
            manifest.display()
        );
    }

    Ok(true)
}

pub(super) fn resolved_release_bin_path(binary_name: &str) -> PathBuf {
    if let Some(target_dir) = std::env::var_os("CARGO_TARGET_DIR") {
        PathBuf::from(target_dir).join("release").join(binary_name)
    } else {
        PathBuf::from("target").join("release").join(binary_name)
    }
}
