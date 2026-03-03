use anyhow::Context;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::{
    env_var, Args, BatchFileConfig, EffectiveFileConfig, MemoryGuardConfig, StageTimeoutConfig,
    BUILD_CACHE_DIR_ENV, DEFAULT_BATCH_TIMEOUT_SECS, DEFAULT_HALO2_BATCH_TIMEOUT_SECS,
    DEFAULT_HIGH_CONFIDENCE_MIN_ORACLES, DEFAULT_MEMORY_GUARD_LAUNCH_FLOOR_MB,
    DEFAULT_MEMORY_GUARD_MB_PER_TEMPLATE, DEFAULT_MEMORY_GUARD_MB_PER_WORKER,
    DEFAULT_MEMORY_GUARD_POLL_MS, DEFAULT_MEMORY_GUARD_RESERVED_MB, DEFAULT_MEMORY_GUARD_WAIT_SECS,
    DEFAULT_STUCK_STEP_WARN_SECS, DEFAULT_TARGET_OVERRIDES_INDEX_PATH, DETECTION_STAGE_TIMEOUT_ENV,
    HALO2_DEFAULT_BATCH_TIMEOUT_ENV, HALO2_MIN_EXTERNAL_TIMEOUT_ENV,
    HIGH_CONFIDENCE_MIN_ORACLES_ENV, MEMORY_GUARD_ENABLED_ENV, MEMORY_GUARD_LAUNCH_FLOOR_MB_ENV,
    MEMORY_GUARD_MB_PER_TEMPLATE_ENV, MEMORY_GUARD_MB_PER_WORKER_ENV, MEMORY_GUARD_POLL_MS_ENV,
    MEMORY_GUARD_RESERVED_MB_ENV, MEMORY_GUARD_WAIT_SECS_ENV, PROOF_STAGE_TIMEOUT_ENV,
    SCAN_OUTPUT_ROOT_ENV, SHARED_BUILD_CACHE_DIR_ENV, STUCK_STEP_WARN_SECS_ENV,
};
use super::{expand_env_placeholders, has_unresolved_env_placeholder};
use zk_fuzzer::target_overrides::{collect_target_override_env, resolve_target_run_overrides};

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

fn yaml_key(name: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(name.to_string())
}

fn env_value_to_string(value: &serde_yaml::Value) -> anyhow::Result<Option<String>> {
    let rendered = match value {
        serde_yaml::Value::Null => return Ok(None),
        serde_yaml::Value::Bool(v) => {
            if *v {
                "1".to_string()
            } else {
                "0".to_string()
            }
        }
        serde_yaml::Value::Number(v) => v.to_string(),
        serde_yaml::Value::String(v) => v.clone(),
        other => anyhow::bail!(
            "Unsupported env override value type: {:?}. Use scalar string/number/bool.",
            other
        ),
    };
    Ok(Some(rendered))
}

pub(super) fn load_batch_file_config(raw_path: &str) -> anyhow::Result<BatchFileConfig> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        anyhow::bail!("--config-json cannot be empty");
    }
    let path = PathBuf::from(trimmed);
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config file '{}'", path.display()))?;
    let mut parsed: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed to parse config file '{}'", path.display()))?;

    if let Some(map) = parsed.as_mapping_mut() {
        if let Some(inner) = map.get(yaml_key("run_overrides")) {
            parsed = inner.clone();
        } else if let Some(inner) = map.get(yaml_key("run")) {
            parsed = inner.clone();
        } else if let Some(inner) = map.get(yaml_key("config")) {
            parsed = inner.clone();
        }
    }

    if let Some(map) = parsed.as_mapping() {
        if map.contains_key(yaml_key("output_root")) {
            anyhow::bail!(
                "Invalid config '{}': output_root is no longer supported; set {} in your env config file",
                path.display(),
                SCAN_OUTPUT_ROOT_ENV
            );
        }
    }

    serde_yaml::from_value(parsed).with_context(|| {
        format!(
            "Failed to decode config file '{}'. Expected keys such as pattern_yaml/target_circuit/workers/iterations/timeout/env.",
            path.display()
        )
    })
}

pub(super) fn apply_file_config(
    args: &mut Args,
    cfg: BatchFileConfig,
) -> anyhow::Result<EffectiveFileConfig> {
    if args.target_circuit.is_none() {
        args.target_circuit = cfg.target_circuit;
    }
    if args.collection.is_none() {
        args.collection = cfg.collection;
    }
    if args.alias.is_none() {
        args.alias = cfg.alias;
    }
    if args.template.is_none() {
        args.template = cfg.template;
    }
    if args.pattern_yaml.is_none() {
        args.pattern_yaml = cfg.pattern_yaml;
    }
    if let Some(value) = cfg.main_component {
        args.main_component = value;
    }
    if let Some(value) = cfg.framework {
        args.framework = value;
    }
    if let Some(value) = cfg.family {
        args.family = value;
    }
    if let Some(value) = cfg.jobs {
        if value == 0 {
            anyhow::bail!("Invalid config: jobs cannot be zero");
        }
        args.jobs = value;
    }
    if let Some(value) = cfg.workers {
        if value == 0 {
            anyhow::bail!("Invalid config: workers cannot be zero");
        }
        args.workers = value;
    }
    if let Some(value) = cfg.seed {
        args.seed = value;
    }
    if let Some(value) = cfg.iterations {
        args.iterations = value;
    }
    if let Some(value) = cfg.timeout {
        if value == 0 {
            anyhow::bail!("Invalid config: timeout cannot be zero");
        }
        args.timeout = value;
    }
    if let Some(value) = cfg.prepare_target {
        args.prepare_target = value;
    }

    let mut env = BTreeMap::new();
    for (key, value) in cfg.env {
        if key.trim().is_empty() {
            anyhow::bail!("Invalid config: env key cannot be empty");
        }
        if let Some(rendered) = env_value_to_string(&value)? {
            env.insert(key, rendered);
        }
    }

    Ok(EffectiveFileConfig {
        env,
        extra_args: cfg.extra_args,
    })
}

pub(super) fn apply_target_run_overrides(
    args: &mut Args,
    effective_file_cfg: &mut EffectiveFileConfig,
) -> anyhow::Result<Option<String>> {
    if args.disable_target_overrides {
        return Ok(None);
    }

    let Some(target_raw) = args.target_circuit.as_deref() else {
        return Ok(None);
    };
    let target_resolved = expand_env_placeholders(target_raw).with_context(|| {
        format!(
            "Failed expanding target_circuit env placeholders in '{}'",
            target_raw
        )
    })?;
    if has_unresolved_env_placeholder(&target_resolved) {
        anyhow::bail!(
            "Unresolved env placeholder in target_circuit '{}'. Set required environment variables.",
            target_raw
        );
    }

    let index_path_raw = args
        .target_overrides_index
        .clone()
        .unwrap_or_else(|| DEFAULT_TARGET_OVERRIDES_INDEX_PATH.to_string());
    let index_path = PathBuf::from(&index_path_raw);

    if !index_path.exists() {
        if args.target_overrides_index.is_some() {
            anyhow::bail!(
                "Target overrides index not found: '{}'",
                index_path.display()
            );
        }
        return Ok(None);
    }

    let target_path = PathBuf::from(&target_resolved);
    let Some(resolved) = resolve_target_run_overrides(&index_path, &target_path, &args.framework)?
    else {
        return Ok(None);
    };

    if let Some(value) = resolved.overrides.batch_jobs {
        if value == 0 {
            anyhow::bail!(
                "Invalid batch_jobs=0 in target run overrides '{}'",
                resolved.overrides_path.display()
            );
        }
        args.jobs = value;
    }
    if let Some(value) = resolved.overrides.workers {
        if value == 0 {
            anyhow::bail!(
                "Invalid workers=0 in target run overrides '{}'",
                resolved.overrides_path.display()
            );
        }
        args.workers = value;
    }
    if let Some(value) = resolved.overrides.iterations {
        args.iterations = value;
    }
    if let Some(value) = resolved.overrides.timeout {
        if value == 0 {
            anyhow::bail!(
                "Invalid timeout=0 in target run overrides '{}'",
                resolved.overrides_path.display()
            );
        }
        args.timeout = value;
    }

    let target_env = collect_target_override_env(&resolved.overrides)?;
    for (key, value) in target_env {
        // Explicit file config should win over auto target defaults.
        effective_file_cfg.env.entry(key).or_insert(value);
    }

    let env_keys = if effective_file_cfg.env.is_empty() {
        "<none>".to_string()
    } else {
        effective_file_cfg
            .env
            .keys()
            .cloned()
            .collect::<Vec<String>>()
            .join(",")
    };
    Ok(Some(format!(
        "Target overrides applied: target='{}' matrix_target='{}' file='{}' jobs={} workers={} iterations={} timeout={} env_keys={}",
        resolved.target_name,
        resolved.target_circuit.display(),
        resolved.overrides_path.display(),
        args.jobs,
        args.workers,
        args.iterations,
        args.timeout,
        env_keys
    )))
}
