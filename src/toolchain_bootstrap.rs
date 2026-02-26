use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_PTAU_FIXTURE_REL: &str = "tests/circuits/build/pot12_final.ptau";
const DEFAULT_PTAU_FIXTURE_SHA256: &str =
    "7ffca1fa4a9a4b432075d353311c44bb6ffcf42def5ae41353ac7b15c81ef49c";

#[derive(Debug, Clone)]
pub struct BinsBootstrapOptions {
    pub bins_dir: PathBuf,
    pub circom_version: String,
    pub snarkjs_version: String,
    pub ptau_file_name: String,
    pub ptau_url: Option<String>,
    pub ptau_sha256: Option<String>,
    pub skip_circom: bool,
    pub skip_snarkjs: bool,
    pub skip_ptau: bool,
    pub force: bool,
    pub dry_run: bool,
}

pub fn run_bins_bootstrap(options: &BinsBootstrapOptions) -> Result<()> {
    if options.skip_circom && options.skip_snarkjs && options.skip_ptau {
        anyhow::bail!(
            "All bootstrap targets are skipped. Remove at least one of --skip-circom/--skip-snarkjs/--skip-ptau."
        );
    }

    let bins_dir = options.bins_dir.clone();
    let bin_dir = bins_dir.join("bin");
    let ptau_dir = bins_dir.join("ptau");

    println!("BOOTSTRAP START");
    println!("bins dir: {}", bins_dir.display());

    if options.dry_run {
        println!("[DRY RUN] mkdir -p {}", bin_dir.display());
        println!("[DRY RUN] mkdir -p {}", ptau_dir.display());
    } else {
        fs::create_dir_all(&bin_dir)
            .with_context(|| format!("Failed to create bins directory '{}'", bin_dir.display()))?;
        fs::create_dir_all(&ptau_dir)
            .with_context(|| format!("Failed to create ptau directory '{}'", ptau_dir.display()))?;
    }

    if !options.skip_circom {
        bootstrap_circom(options, &bin_dir)?;
    }
    if !options.skip_snarkjs {
        bootstrap_snarkjs(options, &bin_dir)?;
    }
    if !options.skip_ptau {
        bootstrap_ptau(options, &ptau_dir)?;
    }

    println!("BOOTSTRAP END");
    Ok(())
}

fn bootstrap_circom(options: &BinsBootstrapOptions, bin_dir: &Path) -> Result<()> {
    let circom_name = if cfg!(windows) {
        "circom.exe"
    } else {
        "circom"
    };
    let circom_path = bin_dir.join(circom_name);
    if circom_path.exists() && !options.force {
        println!(
            "circom: using existing local binary at '{}' (use --force to refresh)",
            circom_path.display()
        );
        return Ok(());
    }

    let requested_tag = normalize_circom_tag(&options.circom_version);
    let source = find_executable_in_path("circom").ok_or_else(|| {
        anyhow::anyhow!(
            "circom bootstrap is local-only. Install circom in PATH or place '{}' manually under '{}'. Requested version '{}'.",
            circom_name,
            bin_dir.display(),
            requested_tag
        )
    })?;

    if options.dry_run {
        println!(
            "[DRY RUN] link/copy local circom '{}' -> '{}'",
            source.display(),
            circom_path.display()
        );
        return Ok(());
    }

    if !paths_equivalent(&source, &circom_path) {
        replace_with_link_or_copy(&source, &circom_path)?;
        make_executable(&circom_path)?;
    }

    let version = probe_command_output(&circom_path, &["--version"])
        .unwrap_or_else(|_| "version probe failed".to_string());
    if !version_matches_request(&version, &requested_tag) {
        println!(
            "circom: staged local binary version '{}' which does not match requested '{}'",
            version.trim(),
            requested_tag
        );
    }
    println!(
        "circom: staged '{}' from local '{}' ({})",
        circom_path.display(),
        source.display(),
        version.trim()
    );
    Ok(())
}

fn bootstrap_snarkjs(options: &BinsBootstrapOptions, bin_dir: &Path) -> Result<()> {
    let snarkjs_link_name = if cfg!(windows) {
        "snarkjs.cmd"
    } else {
        "snarkjs"
    };
    let snarkjs_path = bin_dir.join(snarkjs_link_name);
    if snarkjs_path.exists() && !options.force {
        println!(
            "snarkjs: using existing local binary at '{}' (use --force to refresh)",
            snarkjs_path.display()
        );
        return Ok(());
    }

    let source = find_executable_in_path("snarkjs").ok_or_else(|| {
        anyhow::anyhow!(
            "snarkjs bootstrap is local-only. Install snarkjs in PATH or place '{}' manually under '{}'. Requested version '{}'.",
            snarkjs_link_name,
            bin_dir.display(),
            options.snarkjs_version.trim()
        )
    })?;

    if options.dry_run {
        println!(
            "[DRY RUN] link/copy local snarkjs '{}' -> '{}'",
            source.display(),
            snarkjs_path.display()
        );
        return Ok(());
    }

    if !paths_equivalent(&source, &snarkjs_path) {
        replace_with_link_or_copy(&source, &snarkjs_path)?;
    }
    let version =
        probe_snarkjs_version(&snarkjs_path).unwrap_or_else(|_| "version probe failed".to_string());
    if !version_matches_request(&version, options.snarkjs_version.trim()) {
        println!(
            "snarkjs: staged local binary version '{}' which does not match requested '{}'",
            version.trim(),
            options.snarkjs_version.trim()
        );
    }
    println!(
        "snarkjs: staged '{}' from local '{}' ({})",
        snarkjs_path.display(),
        source.display(),
        version.trim()
    );
    Ok(())
}

fn bootstrap_ptau(options: &BinsBootstrapOptions, ptau_dir: &Path) -> Result<()> {
    if options.ptau_url.is_some() {
        anyhow::bail!(
            "Remote ptau download is disabled. Remove --ptau-url and stage ptau locally."
        );
    }

    let file_name = options.ptau_file_name.trim();
    if file_name.is_empty() {
        anyhow::bail!("--ptau-file cannot be empty");
    }

    let ptau_dest = ptau_dir.join(file_name);
    let expected_sha = if let Some(sha) = options.ptau_sha256.as_deref() {
        normalize_sha256_hex(sha)?
    } else {
        DEFAULT_PTAU_FIXTURE_SHA256.to_string()
    };

    if ptau_dest.exists() && !options.force {
        verify_sha256_file(&ptau_dest, &expected_sha)?;
        verify_ptau_magic(&ptau_dest)?;
        println!(
            "ptau: using existing local file '{}' (use --force to refresh)",
            ptau_dest.display()
        );
        return Ok(());
    }

    if options.dry_run {
        println!(
            "[DRY RUN] copy default ptau fixture '{}' to '{}'",
            DEFAULT_PTAU_FIXTURE_REL,
            ptau_dest.display()
        );
        return Ok(());
    }

    let fixture = PathBuf::from(DEFAULT_PTAU_FIXTURE_REL);
    if !fixture.exists() {
        anyhow::bail!(
            "Default ptau fixture '{}' not found. Stage the file locally before bootstrap.",
            fixture.display()
        );
    }
    verify_sha256_file(&fixture, &expected_sha)?;
    verify_ptau_magic(&fixture)?;
    fs::copy(&fixture, &ptau_dest).with_context(|| {
        format!(
            "Failed to copy ptau fixture '{}' to '{}'",
            fixture.display(),
            ptau_dest.display()
        )
    })?;
    verify_sha256_file(&ptau_dest, &expected_sha)?;

    println!("ptau: installed '{}'", ptau_dest.display());
    Ok(())
}

fn normalize_circom_tag(version: &str) -> String {
    let trimmed = version.trim();
    if trimmed.starts_with('v') {
        trimmed.to_string()
    } else {
        format!("v{}", trimmed)
    }
}

fn find_executable_in_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    #[cfg(not(windows))]
    let names = vec![program.to_string()];
    #[cfg(windows)]
    let mut names = vec![program.to_string()];

    #[cfg(windows)]
    {
        use std::ffi::OsString;
        if Path::new(program).extension().is_none() {
            let pathext = std::env::var_os("PATHEXT")
                .unwrap_or_else(|| OsString::from(".EXE;.CMD;.BAT;.COM"));
            for ext in pathext.to_string_lossy().split(';') {
                let ext = ext.trim();
                if ext.is_empty() {
                    continue;
                }
                names.push(format!("{program}{ext}"));
            }
        }
    }

    for dir in std::env::split_paths(&path) {
        for name in &names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
}

fn paths_equivalent(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn version_matches_request(observed: &str, requested: &str) -> bool {
    let requested = requested.trim().trim_start_matches('v');
    if requested.is_empty() {
        return true;
    }
    observed.contains(requested) || observed.contains(&format!("v{requested}"))
}

fn probe_command_output(program: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute '{}'", program.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "Command '{}' failed with status {}",
            program.display(),
            output.status
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let merged = if !stdout.trim().is_empty() {
        stdout.to_string()
    } else {
        stderr.to_string()
    };
    Ok(merged)
}

fn probe_snarkjs_version(program: &Path) -> Result<String> {
    let output = Command::new(program)
        .arg("--version")
        .output()
        .with_context(|| format!("Failed to execute '{} --version'", program.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let merged = if !stdout.trim().is_empty() {
        stdout.to_string()
    } else {
        stderr.to_string()
    };
    if !merged.trim().is_empty() {
        let first = merged
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("snarkjs");
        return Ok(first.to_string());
    }

    let help = Command::new(program)
        .arg("--help")
        .output()
        .with_context(|| format!("Failed to execute '{} --help'", program.display()))?;
    let text = String::from_utf8_lossy(&help.stdout);
    let first = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("snarkjs");
    Ok(first.to_string())
}

fn replace_with_link_or_copy(source: &Path, dest: &Path) -> Result<()> {
    if fs::symlink_metadata(dest).is_ok() {
        fs::remove_file(dest)
            .or_else(|_| fs::remove_dir_all(dest))
            .with_context(|| format!("Failed to remove existing '{}'", dest.display()))?;
    }
    let source_for_link = source
        .canonicalize()
        .unwrap_or_else(|_| source.to_path_buf());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&source_for_link, dest).with_context(|| {
            format!(
                "Failed to create symlink '{}' -> '{}'",
                dest.display(),
                source_for_link.display()
            )
        })?;
    }
    #[cfg(not(unix))]
    {
        fs::copy(&source_for_link, dest).with_context(|| {
            format!(
                "Failed to copy executable '{}' to '{}'",
                source_for_link.display(),
                dest.display()
            )
        })?;
    }
    Ok(())
}

fn make_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .with_context(|| format!("Failed reading metadata for '{}'", path.display()))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)
            .with_context(|| format!("Failed setting executable bit on '{}'", path.display()))?;
    }
    Ok(())
}

fn normalize_sha256_hex(input: &str) -> Result<String> {
    let trimmed = input.trim();
    let value = trimmed.strip_prefix("sha256:").unwrap_or(trimmed);
    if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!(
            "Invalid SHA-256 '{}': expected 64 hex characters (optionally prefixed with 'sha256:')",
            input
        );
    }
    Ok(value.to_ascii_lowercase())
}

fn verify_sha256_file(path: &Path, expected: &str) -> Result<()> {
    let expected = normalize_sha256_hex(expected)?;
    let actual = file_sha256_hex(path)?;
    if actual != expected {
        anyhow::bail!(
            "Checksum mismatch for '{}': expected {}, got {}",
            path.display(),
            expected,
            actual
        );
    }
    Ok(())
}

fn file_sha256_hex(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("Failed to open file for hashing '{}'", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let read = file
            .read(&mut buf)
            .with_context(|| format!("Failed reading '{}'", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    let digest = hasher.finalize();
    Ok(format!("{digest:x}"))
}

fn verify_ptau_magic(path: &Path) -> Result<()> {
    let mut file =
        fs::File::open(path).with_context(|| format!("Failed to open '{}'", path.display()))?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .with_context(|| format!("Failed reading ptau magic from '{}'", path.display()))?;
    if &magic != b"ptau" {
        anyhow::bail!(
            "Invalid ptau header in '{}': expected magic 'ptau'",
            path.display()
        );
    }
    Ok(())
}
