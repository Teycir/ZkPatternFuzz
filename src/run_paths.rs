use chrono::{DateTime, Utc};
use std::path::PathBuf;
use zk_fuzzer::config::FuzzConfig;

use crate::run_identity::sanitize_slug;

pub(crate) fn read_optional_env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(e) => {
            eprintln!("[zk-fuzzer] ERROR: invalid {} value: {}", name, e);
            std::process::exit(2);
        }
    }
}

pub(crate) fn run_signal_dir() -> PathBuf {
    // Base folder where "easy to find" run folders are written.
    //
    // Default matches your requested structure:
    //   /home/<user>/ZkFuzz/report_<epoch>/
    //
    // Override with:
    //   ZKF_RUN_SIGNAL_DIR=/some/other/base
    //
    // If writing outside the repo is not allowed in your environment, set it back to:
    //   ZKF_RUN_SIGNAL_DIR=reports/_run_signals
    let path = if let Some(v) = read_optional_env("ZKF_RUN_SIGNAL_DIR") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            PathBuf::from(trimmed)
        } else {
            eprintln!("[zk-fuzzer] ERROR: ZKF_RUN_SIGNAL_DIR is set but empty");
            std::process::exit(2);
        }
    } else if let Some(home) = read_optional_env("HOME") {
        let home = home.trim();
        if !home.is_empty() {
            PathBuf::from(home).join("ZkFuzz")
        } else {
            eprintln!("[zk-fuzzer] ERROR: HOME is set but empty");
            std::process::exit(2);
        }
    } else {
        eprintln!("[zk-fuzzer] ERROR: neither ZKF_RUN_SIGNAL_DIR nor HOME is available");
        std::process::exit(2);
    };

    if let Err(err) = std::fs::create_dir_all(&path) {
        eprintln!(
            "[zk-fuzzer] ERROR: cannot create run-signal dir '{}': {}",
            path.display(),
            err
        );
        std::process::exit(2);
    }
    path
}

fn build_cache_dir() -> PathBuf {
    // Build artifacts are large and should not live inside engagement report folders.
    // Default:
    //   /home/<user>/ZkFuzz/_build_cache/
    //
    // Override with:
    //   ZKF_BUILD_CACHE_DIR=/some/other/path
    if let Some(v) = read_optional_env("ZKF_BUILD_CACHE_DIR") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            if let Err(err) = std::fs::create_dir_all(&path) {
                eprintln!(
                    "[zk-fuzzer] ERROR: cannot create build cache dir '{}': {}",
                    path.display(),
                    err
                );
                std::process::exit(2);
            }
            return path;
        }
    }

    let path = run_signal_dir().join("_build_cache");
    if let Err(err) = std::fs::create_dir_all(&path) {
        eprintln!(
            "[zk-fuzzer] ERROR: cannot create build cache dir '{}': {}",
            path.display(),
            err
        );
        std::process::exit(2);
    }
    path
}

pub(crate) fn normalize_build_paths(config: &mut FuzzConfig, run_id: &str) {
    let report_dir = engagement_root_dir(run_id);
    let cache = build_cache_dir();
    let additional = &mut config.campaign.parameters.additional;

    // Remove any explicit build paths that point inside the engagement folder, then force
    // build_dir_base to the cache root.
    let keys = [
        "build_dir_base",
        "build_dir",
        "circom_build_dir",
        "noir_build_dir",
        "halo2_build_dir",
        "cairo_build_dir",
    ];

    let mut had_in_report = false;
    for key in keys {
        if let Some(v) = additional.get(key).and_then(|v| v.as_str()) {
            let p = PathBuf::from(v);
            if p.starts_with(&report_dir) {
                had_in_report = true;
                additional.remove(key);
            }
        }
    }

    // If build_dir_base is missing, set it. If it existed but pointed into the report dir, replace it.
    if had_in_report || additional.get("build_dir_base").is_none() {
        additional.insert(
            "build_dir_base".to_string(),
            serde_yaml::Value::String(cache.display().to_string()),
        );
        if had_in_report {
            tracing::info!(
                "Build artifacts redirected to cache dir {:?} (were inside engagement folder {:?})",
                cache,
                report_dir
            );
        }
    }
}

pub(crate) fn run_id_epoch_dir(run_id: &str) -> Option<String> {
    // run_id prefix is make_run_id(): "%Y%m%d_%H%M%S_..."
    if run_id.len() < 15 {
        return None;
    }
    let ts = &run_id[..15];
    let naive = match chrono::NaiveDateTime::parse_from_str(ts, "%Y%m%d_%H%M%S") {
        Ok(naive) => naive,
        Err(err) => {
            tracing::warn!("Invalid run_id timestamp prefix '{}': {}", ts, err);
            return None;
        }
    };
    let started_utc = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
    Some(format!("report_{}", started_utc.timestamp()))
}

pub(crate) fn engagement_dir_name(run_id: &str) -> String {
    // Allow grouping multiple processes (scan/chains/misc) into the same report folder.
    //
    // Example:
    //   export ZKF_ENGAGEMENT_EPOCH=176963063
    //   ... run scan and chains ...
    //   => /home/<user>/ZkFuzz/report_176963063/
    if let Some(epoch) = read_optional_env("ZKF_ENGAGEMENT_EPOCH") {
        let trimmed = epoch.trim();
        if !trimmed.is_empty() {
            return format!("report_{}", trimmed);
        }
    }

    if let Some(name) = read_optional_env("ZKF_ENGAGEMENT_NAME") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    match run_id_epoch_dir(run_id) {
        Some(dir_name) => dir_name,
        None => {
            let fallback = format!("report_{}", sanitize_slug(run_id));
            tracing::warn!(
                "Run id '{}' does not contain a valid timestamp prefix; using fallback engagement dir '{}'",
                run_id,
                fallback
            );
            fallback
        }
    }
}

pub(crate) fn engagement_root_dir(run_id: &str) -> PathBuf {
    // If ZKF_ENGAGEMENT_DIR is set, use it as the full report folder.
    if let Some(dir) = read_optional_env("ZKF_ENGAGEMENT_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    run_signal_dir().join(engagement_dir_name(run_id))
}
