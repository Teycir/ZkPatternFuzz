use anyhow::Context;
use std::path::{Path, PathBuf};

use super::{
    env_var, MemoryGuardConfig, StageTimeoutConfig, BUILD_CACHE_DIR_ENV,
    DEFAULT_BATCH_TIMEOUT_SECS, DEFAULT_HALO2_BATCH_TIMEOUT_SECS,
    DEFAULT_HIGH_CONFIDENCE_MIN_ORACLES, DEFAULT_MEMORY_GUARD_LAUNCH_FLOOR_MB,
    DEFAULT_MEMORY_GUARD_MB_PER_TEMPLATE, DEFAULT_MEMORY_GUARD_MB_PER_WORKER,
    DEFAULT_MEMORY_GUARD_POLL_MS, DEFAULT_MEMORY_GUARD_RESERVED_MB, DEFAULT_MEMORY_GUARD_WAIT_SECS,
    DEFAULT_STUCK_STEP_WARN_SECS, DETECTION_STAGE_TIMEOUT_ENV, HALO2_DEFAULT_BATCH_TIMEOUT_ENV,
    HALO2_MIN_EXTERNAL_TIMEOUT_ENV, HIGH_CONFIDENCE_MIN_ORACLES_ENV, MEMORY_GUARD_ENABLED_ENV,
    MEMORY_GUARD_LAUNCH_FLOOR_MB_ENV, MEMORY_GUARD_MB_PER_TEMPLATE_ENV,
    MEMORY_GUARD_MB_PER_WORKER_ENV, MEMORY_GUARD_POLL_MS_ENV, MEMORY_GUARD_RESERVED_MB_ENV,
    MEMORY_GUARD_WAIT_SECS_ENV, PROOF_STAGE_TIMEOUT_ENV, SCAN_OUTPUT_ROOT_ENV,
    SHARED_BUILD_CACHE_DIR_ENV, STUCK_STEP_WARN_SECS_ENV,
};

pub(super) fn high_confidence_min_oracles_from_env() -> usize {
    env_var(HIGH_CONFIDENCE_MIN_ORACLES_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_HIGH_CONFIDENCE_MIN_ORACLES)
}

fn env_bool_with_default(name: &str, default: bool) -> anyhow::Result<bool> {
    let Ok(raw) = env_var(name) else {
        return Ok(default);
    };
    let trimmed = raw.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!(
            "Invalid {}='{}'. Use one of: 1/0, true/false, yes/no, on/off",
            name,
            raw
        ),
    }
}

fn env_u64_with_default(name: &str, default: u64, min: u64) -> anyhow::Result<u64> {
    let Ok(raw) = env_var(name) else {
        return Ok(default.max(min));
    };
    let trimmed = raw.trim();
    let parsed = trimmed
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("Invalid {}='{}'. Expected an unsigned integer", name, raw))?;
    if parsed < min {
        anyhow::bail!("Invalid {}={}: must be >= {}", name, parsed, min);
    }
    Ok(parsed)
}

pub(super) fn load_memory_guard_config() -> anyhow::Result<MemoryGuardConfig> {
    Ok(MemoryGuardConfig {
        enabled: env_bool_with_default(MEMORY_GUARD_ENABLED_ENV, true)?,
        reserved_mb: env_u64_with_default(
            MEMORY_GUARD_RESERVED_MB_ENV,
            DEFAULT_MEMORY_GUARD_RESERVED_MB,
            0,
        )?,
        mb_per_template: env_u64_with_default(
            MEMORY_GUARD_MB_PER_TEMPLATE_ENV,
            DEFAULT_MEMORY_GUARD_MB_PER_TEMPLATE,
            1,
        )?,
        mb_per_worker: env_u64_with_default(
            MEMORY_GUARD_MB_PER_WORKER_ENV,
            DEFAULT_MEMORY_GUARD_MB_PER_WORKER,
            1,
        )?,
        launch_floor_mb: env_u64_with_default(
            MEMORY_GUARD_LAUNCH_FLOOR_MB_ENV,
            DEFAULT_MEMORY_GUARD_LAUNCH_FLOOR_MB,
            1,
        )?,
        wait_secs: env_u64_with_default(
            MEMORY_GUARD_WAIT_SECS_ENV,
            DEFAULT_MEMORY_GUARD_WAIT_SECS,
            1,
        )?,
        poll_ms: env_u64_with_default(MEMORY_GUARD_POLL_MS_ENV, DEFAULT_MEMORY_GUARD_POLL_MS, 50)?,
    })
}

pub(super) fn load_stage_timeout_config(
    default_timeout_secs: u64,
) -> anyhow::Result<StageTimeoutConfig> {
    Ok(StageTimeoutConfig {
        detection_timeout_secs: env_u64_with_default(
            DETECTION_STAGE_TIMEOUT_ENV,
            default_timeout_secs,
            1,
        )?,
        proof_timeout_secs: env_u64_with_default(PROOF_STAGE_TIMEOUT_ENV, default_timeout_secs, 1)?,
        stuck_step_warn_secs: env_u64_with_default(
            STUCK_STEP_WARN_SECS_ENV,
            DEFAULT_STUCK_STEP_WARN_SECS,
            1,
        )?,
    })
}

pub(super) fn resolve_build_cache_dir(results_root: &Path) -> PathBuf {
    for env_name in [BUILD_CACHE_DIR_ENV, SHARED_BUILD_CACHE_DIR_ENV] {
        if let Ok(raw) = env_var(env_name) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed);
            }
        }
    }
    results_root.join("_build_cache")
}

pub(super) fn halo2_effective_external_timeout_secs(
    framework: &str,
    requested_timeout: u64,
) -> u64 {
    if !framework.eq_ignore_ascii_case("halo2") {
        return requested_timeout;
    }

    let floor = env_var(HALO2_MIN_EXTERNAL_TIMEOUT_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(180);

    requested_timeout.max(floor)
}

pub(super) fn effective_batch_timeout_secs(framework: &str, requested_timeout: u64) -> u64 {
    if requested_timeout != DEFAULT_BATCH_TIMEOUT_SECS {
        return requested_timeout;
    }
    if !framework.eq_ignore_ascii_case("halo2") {
        return requested_timeout;
    }

    let halo2_default = env_var(HALO2_DEFAULT_BATCH_TIMEOUT_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_HALO2_BATCH_TIMEOUT_SECS);

    requested_timeout.max(halo2_default)
}

pub(super) fn resolve_results_root() -> anyhow::Result<PathBuf> {
    let raw = env_var(SCAN_OUTPUT_ROOT_ENV).with_context(|| {
        format!(
            "{} is required (output path is env-only)",
            SCAN_OUTPUT_ROOT_ENV
        )
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!(
            "{} is set but empty; provide a writable output root",
            SCAN_OUTPUT_ROOT_ENV
        );
    }
    Ok(PathBuf::from(trimmed))
}
