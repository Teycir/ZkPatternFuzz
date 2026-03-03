use anyhow::{bail, Context};
use regex::Regex;
use serde_json::Value;
use std::env;
use std::path::{Path, PathBuf};

pub const ENV_MIN_COMPLETION_RATE: &str = "MIN_COMPLETION_RATE";
pub const ENV_MIN_VULNERABLE_RECALL: &str = "MIN_VULNERABLE_RECALL";
pub const ENV_MIN_PRECISION: &str = "MIN_PRECISION";
pub const ENV_MAX_SAFE_FPR: &str = "MAX_SAFE_FPR";
pub const ENV_MAX_SAFE_HIGH_CONF_FPR: &str = "MAX_SAFE_HIGH_CONF_FPR";

pub const DEFAULT_MIN_COMPLETION_RATE: f64 = 0.95;
pub const DEFAULT_MIN_VULNERABLE_RECALL: f64 = 0.20;
pub const DEFAULT_MIN_PRECISION: f64 = 0.20;
pub const DEFAULT_MAX_SAFE_FPR: f64 = 0.20;
pub const DEFAULT_MAX_SAFE_HIGH_CONF_FPR: f64 = 0.05;

#[derive(Debug, Clone, Copy, Default)]
pub struct RegressionThresholdOverrides {
    pub min_completion_rate: Option<f64>,
    pub min_vulnerable_recall: Option<f64>,
    pub min_precision: Option<f64>,
    pub max_safe_fpr: Option<f64>,
    pub max_safe_high_conf_fpr: Option<f64>,
}

#[derive(Debug, Clone, Copy)]
pub struct RegressionThresholds {
    pub min_completion_rate: f64,
    pub min_vulnerable_recall: f64,
    pub min_precision: f64,
    pub max_safe_fpr: f64,
    pub max_safe_high_conf_fpr: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct RegressionMetrics {
    pub total_runs: usize,
    pub total_detected: usize,
    pub completion: f64,
    pub vulnerable_recall: f64,
    pub precision: f64,
    pub safe_fpr: f64,
    pub safe_high_conf_fpr: f64,
}

#[derive(Debug, Clone)]
pub struct RegressionEvaluation {
    pub metrics: RegressionMetrics,
    pub failures: Vec<String>,
}

fn parse_rate(raw: &str, source: &str) -> anyhow::Result<f64> {
    let value: f64 = raw
        .parse()
        .with_context(|| format!("Invalid threshold value from {source}: {raw:?}"))?;
    if !(0.0..=1.0).contains(&value) {
        bail!("Threshold from {source} must be between 0.0 and 1.0, got {value}");
    }
    Ok(value)
}

fn resolve_rate(cli: Option<f64>, env_key: &str, default: f64) -> anyhow::Result<f64> {
    if let Some(value) = cli {
        return parse_rate(&value.to_string(), &format!("--{}", env_key.to_lowercase()));
    }
    let value = match env::var(env_key) {
        Ok(raw) if !raw.trim().is_empty() => parse_rate(raw.trim(), &format!("${env_key}"))?,
        _ => default,
    };
    Ok(value)
}

pub fn resolve_thresholds(
    overrides: RegressionThresholdOverrides,
) -> anyhow::Result<RegressionThresholds> {
    Ok(RegressionThresholds {
        min_completion_rate: resolve_rate(
            overrides.min_completion_rate,
            ENV_MIN_COMPLETION_RATE,
            DEFAULT_MIN_COMPLETION_RATE,
        )?,
        min_vulnerable_recall: resolve_rate(
            overrides.min_vulnerable_recall,
            ENV_MIN_VULNERABLE_RECALL,
            DEFAULT_MIN_VULNERABLE_RECALL,
        )?,
        min_precision: resolve_rate(
            overrides.min_precision,
            ENV_MIN_PRECISION,
            DEFAULT_MIN_PRECISION,
        )?,
        max_safe_fpr: resolve_rate(
            overrides.max_safe_fpr,
            ENV_MAX_SAFE_FPR,
            DEFAULT_MAX_SAFE_FPR,
        )?,
        max_safe_high_conf_fpr: resolve_rate(
            overrides.max_safe_high_conf_fpr,
            ENV_MAX_SAFE_HIGH_CONF_FPR,
            DEFAULT_MAX_SAFE_HIGH_CONF_FPR,
        )?,
    })
}

pub fn latest_summary_path(benchmark_root: &Path) -> anyhow::Result<PathBuf> {
    let bench_name_re =
        Regex::new(r"^benchmark_[0-9]{8}_[0-9]{6}$").with_context(|| "Invalid benchmark regex")?;
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(benchmark_root)
        .with_context(|| format!("Failed to read '{}'", benchmark_root.display()))?
    {
        let entry = match entry {
            Ok(value) => value,
            Err(_) => continue,
        };
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !bench_name_re.is_match(name) {
            continue;
        }
        let summary = path.join("summary.json");
        if summary.is_file() {
            candidates.push(summary);
        }
    }
    candidates.sort();
    candidates
        .into_iter()
        .next_back()
        .ok_or_else(|| anyhow::anyhow!("No benchmark summary.json found"))
}

pub fn load_summary(path: &Path) -> anyhow::Result<Value> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read benchmark summary '{}'", path.display()))?;
    let value: Value = serde_json::from_str(&raw)
        .with_context(|| format!("Failed to parse benchmark summary '{}'", path.display()))?;
    if !value.is_object() {
        bail!(
            "Expected JSON object in benchmark summary '{}'",
            path.display()
        );
    }
    Ok(value)
}

fn value_to_f64(value: &Value) -> Option<f64> {
    if let Some(number) = value.as_f64() {
        return Some(number);
    }
    value.as_str().and_then(|raw| raw.parse::<f64>().ok())
}

fn value_to_usize(value: &Value) -> Option<usize> {
    if let Some(number) = value.as_u64() {
        return usize::try_from(number).ok();
    }
    if let Some(number) = value.as_i64() {
        if number < 0 {
            return None;
        }
        return usize::try_from(number as u64).ok();
    }
    value.as_str().and_then(|raw| raw.parse::<usize>().ok())
}

fn get_f64(summary: &Value, key: &str, default: f64) -> f64 {
    summary.get(key).and_then(value_to_f64).unwrap_or(default)
}

fn get_usize(summary: &Value, key: &str, default: usize) -> usize {
    summary.get(key).and_then(value_to_usize).unwrap_or(default)
}

pub fn evaluate_summary(
    summary: &Value,
    thresholds: &RegressionThresholds,
) -> RegressionEvaluation {
    let metrics = RegressionMetrics {
        completion: get_f64(summary, "overall_completion_rate", 0.0),
        vulnerable_recall: get_f64(summary, "vulnerable_recall", 0.0),
        precision: get_f64(summary, "precision", 0.0),
        safe_fpr: get_f64(summary, "safe_false_positive_rate", 1.0),
        safe_high_conf_fpr: get_f64(summary, "safe_high_confidence_false_positive_rate", 1.0),
        total_runs: get_usize(summary, "total_runs", 0),
        total_detected: get_usize(summary, "total_detected", 0),
    };

    let mut failures = Vec::new();
    if metrics.total_runs == 0 {
        failures.push("total_runs must be > 0".to_string());
    }
    if metrics.completion < thresholds.min_completion_rate {
        failures.push(format!(
            "overall_completion_rate {:.4} < {:.4}",
            metrics.completion, thresholds.min_completion_rate
        ));
    }
    if metrics.vulnerable_recall < thresholds.min_vulnerable_recall {
        failures.push(format!(
            "vulnerable_recall {:.4} < {:.4}",
            metrics.vulnerable_recall, thresholds.min_vulnerable_recall
        ));
    }
    if metrics.precision < thresholds.min_precision {
        failures.push(format!(
            "precision {:.4} < {:.4}",
            metrics.precision, thresholds.min_precision
        ));
    }
    if metrics.safe_fpr > thresholds.max_safe_fpr {
        failures.push(format!(
            "safe_false_positive_rate {:.4} > {:.4}",
            metrics.safe_fpr, thresholds.max_safe_fpr
        ));
    }
    if metrics.safe_high_conf_fpr > thresholds.max_safe_high_conf_fpr {
        failures.push(format!(
            "safe_high_confidence_false_positive_rate {:.4} > {:.4}",
            metrics.safe_high_conf_fpr, thresholds.max_safe_high_conf_fpr
        ));
    }

    RegressionEvaluation { metrics, failures }
}
