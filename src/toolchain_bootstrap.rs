use anyhow::{Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const DEFAULT_PTAU_FIXTURE_REL: &str = "tests/circuits/build/pot12_final.ptau";
const DEFAULT_PTAU_FIXTURE_SHA256: &str =
    "7ffca1fa4a9a4b432075d353311c44bb6ffcf42def5ae41353ac7b15c81ef49c";
const CIRCOM_RELEASES_BY_TAG_URL: &str = "https://api.github.com/repos/iden3/circom/releases/tags";

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

#[derive(Debug, Deserialize)]
struct CircomRelease {
    tag_name: String,
    assets: Vec<CircomReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct CircomReleaseAsset {
    name: String,
    digest: Option<String>,
    browser_download_url: String,
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
        bootstrap_snarkjs(options, &bins_dir, &bin_dir)?;
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
    if options.dry_run {
        println!(
            "[DRY RUN] download circom {} to '{}'",
            requested_tag,
            circom_path.display()
        );
        return Ok(());
    }

    let release = fetch_circom_release(&requested_tag)?;
    let asset = select_circom_asset_for_platform(&release)?;
    let expected_sha = asset
        .digest
        .as_deref()
        .and_then(|value| value.strip_prefix("sha256:"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Circom release asset '{}' has no sha256 digest in GitHub metadata",
                asset.name
            )
        })?;

    let tmp_path = circom_path.with_extension("download");
    download_with_curl(&asset.browser_download_url, &tmp_path).with_context(|| {
        format!(
            "Failed downloading circom asset '{}' from {}",
            asset.name, asset.browser_download_url
        )
    })?;
    verify_sha256_file(&tmp_path, expected_sha)?;
    install_file_atomically(&tmp_path, &circom_path)?;
    make_executable(&circom_path)?;

    let version = probe_command_output(&circom_path, &["--version"])
        .unwrap_or_else(|_| "version probe failed".to_string());
    println!(
        "circom: installed '{}' ({})",
        circom_path.display(),
        version.trim()
    );
    Ok(())
}

fn bootstrap_snarkjs(
    options: &BinsBootstrapOptions,
    bins_dir: &Path,
    bin_dir: &Path,
) -> Result<()> {
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

    let npm_package = format!("snarkjs@{}", options.snarkjs_version.trim());
    if options.dry_run {
        println!(
            "[DRY RUN] npm --prefix '{}' install --no-audit --no-fund --save-exact {}",
            bins_dir.display(),
            npm_package
        );
        println!(
            "[DRY RUN] link '{}' -> '{}'",
            snarkjs_path.display(),
            bins_dir
                .join("node_modules")
                .join(".bin")
                .join(snarkjs_link_name)
                .display()
        );
        return Ok(());
    }

    run_command(
        Command::new("npm")
            .arg("--prefix")
            .arg(bins_dir)
            .arg("install")
            .arg("--no-audit")
            .arg("--no-fund")
            .arg("--save-exact")
            .arg(npm_package),
        "npm install snarkjs",
    )?;

    let source = bins_dir
        .join("node_modules")
        .join(".bin")
        .join(snarkjs_link_name);
    if !source.exists() {
        anyhow::bail!(
            "Expected snarkjs executable '{}' after npm install, but it was not found",
            source.display()
        );
    }

    replace_with_link_or_copy(&source, &snarkjs_path)?;
    let version =
        probe_snarkjs_version(&snarkjs_path).unwrap_or_else(|_| "version probe failed".to_string());
    println!(
        "snarkjs: installed '{}' ({})",
        snarkjs_path.display(),
        version.trim()
    );
    Ok(())
}

fn bootstrap_ptau(options: &BinsBootstrapOptions, ptau_dir: &Path) -> Result<()> {
    let file_name = options.ptau_file_name.trim();
    if file_name.is_empty() {
        anyhow::bail!("--ptau-file cannot be empty");
    }

    let ptau_dest = ptau_dir.join(file_name);
    let expected_sha = if let Some(sha) = options.ptau_sha256.as_deref() {
        Some(normalize_sha256_hex(sha)?)
    } else if options.ptau_url.is_none() {
        Some(DEFAULT_PTAU_FIXTURE_SHA256.to_string())
    } else {
        None
    };

    if ptau_dest.exists() && !options.force {
        if let Some(expected) = expected_sha.as_deref() {
            verify_sha256_file(&ptau_dest, expected)?;
        }
        verify_ptau_magic(&ptau_dest)?;
        println!(
            "ptau: using existing local file '{}' (use --force to refresh)",
            ptau_dest.display()
        );
        return Ok(());
    }

    if options.dry_run {
        if let Some(url) = options.ptau_url.as_deref() {
            println!(
                "[DRY RUN] download ptau from '{}' to '{}'",
                url,
                ptau_dest.display()
            );
        } else {
            println!(
                "[DRY RUN] copy default ptau fixture '{}' to '{}'",
                DEFAULT_PTAU_FIXTURE_REL,
                ptau_dest.display()
            );
        }
        return Ok(());
    }

    if let Some(url) = options.ptau_url.as_deref() {
        let Some(expected) = expected_sha.as_deref() else {
            anyhow::bail!(
                "When --ptau-url is used, --ptau-sha256 is required for checksum verification"
            );
        };
        let tmp = ptau_dest.with_extension("download");
        download_with_curl(url, &tmp)
            .with_context(|| format!("Failed to download ptau from '{}'", url))?;
        verify_sha256_file(&tmp, expected)?;
        verify_ptau_magic(&tmp)?;
        install_file_atomically(&tmp, &ptau_dest)?;
    } else {
        let fixture = PathBuf::from(DEFAULT_PTAU_FIXTURE_REL);
        if !fixture.exists() {
            anyhow::bail!(
                "Default ptau fixture '{}' not found. Either add it or pass --ptau-url and --ptau-sha256.",
                fixture.display()
            );
        }
        let expected = expected_sha
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Missing expected checksum for default ptau fixture"))?;
        verify_sha256_file(&fixture, expected)?;
        verify_ptau_magic(&fixture)?;
        fs::copy(&fixture, &ptau_dest).with_context(|| {
            format!(
                "Failed to copy ptau fixture '{}' to '{}'",
                fixture.display(),
                ptau_dest.display()
            )
        })?;
        verify_sha256_file(&ptau_dest, expected)?;
    }

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

fn fetch_circom_release(tag: &str) -> Result<CircomRelease> {
    let url = format!("{}/{}", CIRCOM_RELEASES_BY_TAG_URL, tag);
    let output = run_command_capture(
        Command::new("curl")
            .arg("-fsSL")
            .arg("-H")
            .arg("Accept: application/vnd.github+json")
            .arg("-H")
            .arg("User-Agent: zk-fuzzer-bootstrap")
            .arg(url),
        "curl circom release metadata",
    )?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Failed to fetch circom release metadata for '{}': {}",
            tag,
            stderr.trim()
        );
    }

    let release: CircomRelease = serde_json::from_slice(&output.stdout)
        .context("Failed to parse circom GitHub release metadata")?;
    Ok(release)
}

fn select_circom_asset_for_platform(release: &CircomRelease) -> Result<&CircomReleaseAsset> {
    let names = circom_asset_candidates()?;
    for candidate in &names {
        if let Some(asset) = release.assets.iter().find(|asset| asset.name == *candidate) {
            return Ok(asset);
        }
    }

    let available = release
        .assets
        .iter()
        .map(|asset| asset.name.clone())
        .collect::<Vec<_>>();
    anyhow::bail!(
        "No circom asset for current platform in release '{}'. Wanted one of [{}], available [{}]",
        release.tag_name,
        names.join(", "),
        available.join(", ")
    );
}

fn circom_asset_candidates() -> Result<Vec<&'static str>> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    let candidates = match (os, arch) {
        ("linux", "x86_64") => vec!["circom-linux-amd64"],
        ("linux", "aarch64") => vec!["circom-linux-arm64", "circom-linux-aarch64"],
        ("macos", "x86_64") => vec!["circom-macos-amd64"],
        ("macos", "aarch64") => vec!["circom-macos-arm64", "circom-macos-aarch64"],
        ("windows", "x86_64") => vec!["circom-windows-amd64.exe"],
        _ => {
            anyhow::bail!(
                "Unsupported platform for automatic circom bootstrap: os='{}' arch='{}'",
                os,
                arch
            )
        }
    };

    Ok(candidates)
}

fn download_with_curl(url: &str, output_path: &Path) -> Result<()> {
    run_command(
        Command::new("curl")
            .arg("-fL")
            .arg("--retry")
            .arg("3")
            .arg("--connect-timeout")
            .arg("15")
            .arg("--max-time")
            .arg("1800")
            .arg("-o")
            .arg(output_path)
            .arg(url),
        &format!("curl download {}", url),
    )
}

fn install_file_atomically(from: &Path, to: &Path) -> Result<()> {
    if to.exists() {
        fs::remove_file(to)
            .with_context(|| format!("Failed to remove old file '{}'", to.display()))?;
    }
    fs::rename(from, to).with_context(|| {
        format!(
            "Failed to move downloaded file '{}' to '{}'",
            from.display(),
            to.display()
        )
    })?;
    Ok(())
}

fn run_command(cmd: &mut Command, label: &str) -> Result<()> {
    let output = run_command_capture(cmd, label)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{} failed: {}", label, stderr.trim());
    }
    Ok(())
}

fn run_command_capture(cmd: &mut Command, label: &str) -> Result<Output> {
    cmd.output()
        .with_context(|| format!("Failed to execute {}", label))
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

#[cfg(test)]
#[path = "toolchain_bootstrap_tests.rs"]
mod tests;
