use anyhow::Context;
use chrono::Utc;
use std::path::Path;
use std::time::Duration;
use zk_fuzzer::config::FuzzConfig;

pub(crate) fn apply_scan_output_suffix_if_present(config: &mut FuzzConfig) -> anyhow::Result<()> {
    let Some(raw_suffix) = config
        .campaign
        .parameters
        .additional
        .get_string("scan_output_suffix")
    else {
        return Ok(());
    };

    let trimmed = raw_suffix.trim();
    if trimmed.is_empty() {
        anyhow::bail!("`campaign.parameters.scan_output_suffix` cannot be empty");
    }

    let slug = crate::sanitize_slug(trimmed);
    let run_root = if let Some(v) = crate::read_optional_env("ZKF_SCAN_RUN_ROOT") {
        let candidate = v.trim();
        if candidate.is_empty() {
            anyhow::bail!("ZKF_SCAN_RUN_ROOT is set but empty");
        }
        if !candidate.starts_with("scan_run") {
            anyhow::bail!(
                "ZKF_SCAN_RUN_ROOT must start with 'scan_run' (got '{}')",
                candidate
            );
        }
        if !candidate
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            anyhow::bail!(
                "ZKF_SCAN_RUN_ROOT contains invalid characters: '{}'",
                candidate
            );
        }
        candidate.to_string()
    } else {
        reserve_scan_run_root(&config.reporting.output_dir)?
    };
    let public_root = config.reporting.output_dir.join(&run_root);
    let artifacts_root = config
        .reporting
        .output_dir
        .join(".scan_run_artifacts")
        .join(&run_root);
    config.reporting.output_dir = config
        .reporting
        .output_dir
        .join(".scan_run_artifacts")
        .join(&run_root)
        .join(&slug);
    let _ = std::fs::create_dir_all(&public_root);
    let _ = std::fs::create_dir_all(artifacts_root);
    write_scan_pattern_summary_if_present(config, &public_root, &slug);
    tracing::info!(
        "Scan output isolation enabled: {}",
        config.reporting.output_dir.display()
    );
    Ok(())
}

fn reserve_scan_run_root(output_root: &Path) -> anyhow::Result<String> {
    let artifacts_base = output_root.join(".scan_run_artifacts");
    std::fs::create_dir_all(&artifacts_base).with_context(|| {
        format!(
            "Failed to create scan artifacts base '{}'",
            artifacts_base.display()
        )
    })?;

    // Keep the existing run-root format (`scan_runYYYYmmdd_HHMMSS`) for compatibility
    // while making allocation collision-safe across concurrent scan processes.
    for _ in 0..120 {
        let ts = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let candidate = format!("scan_run{}", ts);
        let reservation = artifacts_base.join(&candidate);
        match std::fs::create_dir(&reservation) {
            Ok(_) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                std::thread::sleep(Duration::from_millis(1100));
                continue;
            }
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "Failed to reserve scan run root '{}' under '{}': {}",
                    candidate,
                    artifacts_base.display(),
                    err
                ));
            }
        }
    }

    anyhow::bail!(
        "Failed to allocate unique scan run root after repeated collisions under '{}'",
        artifacts_base.display()
    )
}

fn write_scan_pattern_summary_if_present(config: &FuzzConfig, public_root: &Path, slug: &str) {
    let summary_text = config
        .campaign
        .parameters
        .additional
        .get_string("scan_pattern_summary_text");

    let summary_path = public_root.join("summary.txt");
    if let Some(summary_text) = summary_text {
        for line in summary_text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            best_effort_append_text_line(&summary_path, &format!("{}: {}", slug, trimmed));
        }
    } else {
        best_effort_append_text_line(
            &summary_path,
            &format!("{}: pattern {} found in lines []", slug, slug),
        );
    }
}

fn best_effort_append_text_line(path: &Path, line: &str) {
    if let Some(parent) = path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            tracing::warn!(
                "Failed to create parent directory for '{}': {}",
                path.display(),
                err
            );
            return;
        }
    }
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(mut file) => {
            use std::io::Write as _;
            if let Err(err) = writeln!(file, "{}", line) {
                tracing::warn!(
                    "Failed to append text line to '{}': {}",
                    path.display(),
                    err
                );
            }
        }
        Err(err) => {
            tracing::warn!("Failed to open '{}' for append: {}", path.display(), err);
        }
    }
}
