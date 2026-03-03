use anyhow::{bail, Context};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::path::{Path, PathBuf};

pub const SUCCESS_REASONS: &[&str] = &["none", "completed", "critical_findings_detected"];

pub const FAILURE_CLASSES: &[&str] = &[
    "lock_contention",
    "setup_tooling",
    "timeouts",
    "stability_runtime",
    "contract_or_config",
    "other_failure",
];

pub const FAILURE_CLASS_RULES: &[(&str, &[&str])] = &[
    ("lock_contention", &["output_dir_locked"]),
    (
        "setup_tooling",
        &[
            "backend_tooling_missing",
            "backend_preflight_failed",
            "circom_compilation_failed",
            "key_generation_failed",
            "missing_invariants",
            "readiness_failed",
            "filesystem_permission_denied",
        ],
    ),
    ("timeouts", &["wall_clock_timeout"]),
    (
        "stability_runtime",
        &[
            "runtime_error",
            "panic",
            "artifact_mirror_panic_missing_command",
            "run_outcome_missing",
            "run_outcome_unreadable",
            "run_outcome_invalid_json",
            "unknown",
            "stale_interrupted",
        ],
    ),
    (
        "contract_or_config",
        &["engagement_contract_failed", "missing_chains_definition"],
    ),
];

pub fn default_thresholds() -> BTreeMap<String, f64> {
    BTreeMap::from([
        ("lock_contention".to_string(), 0.05),
        ("setup_tooling".to_string(), 0.15),
        ("timeouts".to_string(), 0.10),
        ("stability_runtime".to_string(), 0.05),
        ("contract_or_config".to_string(), 0.10),
        ("other_failure".to_string(), 0.05),
    ])
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureClassRow {
    pub class: String,
    pub count: usize,
    pub rate: f64,
    pub max_rate: f64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureDashboardPayload {
    pub generated_utc: Option<String>,
    pub summary_path: String,
    pub outcomes_path: String,
    pub total_runs: usize,
    pub overall_status: String,
    pub class_rows: Vec<FailureClassRow>,
    pub reason_counts: BTreeMap<String, usize>,
}

pub fn latest_benchmark_dir(benchmark_root: &Path) -> anyhow::Result<PathBuf> {
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
        if path.join("summary.json").is_file() && path.join("outcomes.json").is_file() {
            candidates.push(path);
        }
    }
    candidates.sort();
    candidates.into_iter().next_back().ok_or_else(|| {
        anyhow::anyhow!(
            "No benchmark_<timestamp> directory with summary/outcomes found under {}",
            benchmark_root.display()
        )
    })
}

pub fn load_json(path: &Path) -> anyhow::Result<Value> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read '{}'", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("Failed to parse '{}'", path.display()))
}

fn value_to_i64(value: &Value) -> Option<i64> {
    if let Some(number) = value.as_i64() {
        return Some(number);
    }
    if let Some(number) = value.as_u64() {
        return i64::try_from(number).ok();
    }
    if let Some(number) = value.as_f64() {
        return Some(number as i64);
    }
    value.as_str().and_then(|raw| raw.parse::<i64>().ok())
}

fn value_to_usize(value: &Value) -> Option<usize> {
    value_to_i64(value).and_then(|number| {
        if number < 0 {
            None
        } else {
            usize::try_from(number as u64).ok()
        }
    })
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

pub fn env_key_for_class(class_name: &str) -> String {
    format!("ZKF_FAILURE_MAX_RATE_{}", class_name.to_ascii_uppercase())
}

pub fn resolve_thresholds(cli_overrides: &[String]) -> anyhow::Result<BTreeMap<String, f64>> {
    let mut thresholds = default_thresholds();

    for class_name in FAILURE_CLASSES {
        let env_key = env_key_for_class(class_name);
        let raw_env = match env::var(&env_key) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if raw_env.trim().is_empty() {
            continue;
        }
        let parsed = parse_rate(raw_env.trim(), &format!("${env_key}"))?;
        thresholds.insert((*class_name).to_string(), parsed);
    }

    let known_classes: BTreeSet<String> = thresholds.keys().cloned().collect();
    for override_value in cli_overrides {
        let Some((raw_class, raw_rate)) = override_value.split_once('=') else {
            bail!("Invalid --threshold {override_value:?}; expected CLASS=RATE");
        };
        let class_name = raw_class.trim().to_ascii_lowercase();
        if !known_classes.contains(&class_name) {
            let valid = FAILURE_CLASSES.join(", ");
            bail!("Unknown failure class {class_name:?}; valid classes: {valid}");
        }
        let source = format!("--threshold {}={}", raw_class.trim(), raw_rate.trim());
        let parsed = parse_rate(raw_rate.trim(), &source)?;
        thresholds.insert(class_name, parsed);
    }
    Ok(thresholds)
}

pub fn classify_reason(reason: &str) -> &'static str {
    if SUCCESS_REASONS.contains(&reason) {
        return "success";
    }
    for (class_name, reasons) in FAILURE_CLASS_RULES {
        if reasons.contains(&reason) {
            return class_name;
        }
    }
    "other_failure"
}

pub fn sum_reason_counts(outcomes: &[Value]) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for item in outcomes {
        let Some(reason_counts) = item.get("reason_counts").and_then(Value::as_object) else {
            continue;
        };
        for (reason, raw_count) in reason_counts {
            let Some(parsed_count) = value_to_i64(raw_count) else {
                continue;
            };
            let non_negative = usize::try_from(parsed_count.max(0) as u64).unwrap_or(0);
            let entry = counts.entry(reason.clone()).or_insert(0);
            *entry = (*entry).saturating_add(non_negative);
        }
    }
    counts
}

pub fn dashboard(
    summary: &Value,
    outcomes: &[Value],
    summary_path: &Path,
    outcomes_path: &Path,
    class_thresholds: &BTreeMap<String, f64>,
) -> anyhow::Result<FailureDashboardPayload> {
    let generated_utc = summary
        .get("generated_utc")
        .and_then(Value::as_str)
        .map(str::to_string);

    let mut total_runs = summary
        .get("total_runs")
        .and_then(value_to_usize)
        .unwrap_or(outcomes.len());
    if total_runs == 0 {
        total_runs = outcomes.len();
    }

    let reason_counts = sum_reason_counts(outcomes);
    let mut class_counts: BTreeMap<String, usize> = BTreeMap::new();
    for (reason, count) in &reason_counts {
        let class_name = classify_reason(reason).to_string();
        let entry = class_counts.entry(class_name).or_insert(0);
        *entry = (*entry).saturating_add(*count);
    }

    let mut class_rows = Vec::new();
    for class_name in FAILURE_CLASSES {
        let count = class_counts.get(*class_name).copied().unwrap_or(0);
        let threshold = class_thresholds.get(*class_name).copied().ok_or_else(|| {
            anyhow::anyhow!("Missing threshold for failure class '{}'", class_name)
        })?;
        let rate = if total_runs > 0 {
            count as f64 / total_runs as f64
        } else {
            0.0
        };
        let status = if rate <= threshold { "PASS" } else { "FAIL" };
        class_rows.push(FailureClassRow {
            class: (*class_name).to_string(),
            count,
            rate,
            max_rate: threshold,
            status: status.to_string(),
        });
    }

    let overall_status = if class_rows.iter().any(|row| row.status == "FAIL") {
        "FAIL"
    } else {
        "PASS"
    };

    Ok(FailureDashboardPayload {
        generated_utc,
        summary_path: summary_path.display().to_string(),
        outcomes_path: outcomes_path.display().to_string(),
        total_runs,
        overall_status: overall_status.to_string(),
        class_rows,
        reason_counts,
    })
}

fn pct(value: f64) -> String {
    format!("{:.2}%", value * 100.0)
}

pub fn write_markdown(path: &Path, payload: &FailureDashboardPayload) -> anyhow::Result<()> {
    let mut lines = Vec::new();
    lines.push("# Benchmark Failure-Class Dashboard".to_string());
    lines.push(String::new());
    lines.push(format!(
        "- Generated UTC: `{}`",
        payload.generated_utc.as_deref().unwrap_or("n/a")
    ));
    lines.push(format!("- Summary: `{}`", payload.summary_path));
    lines.push(format!("- Outcomes: `{}`", payload.outcomes_path));
    lines.push(format!("- Overall status: `{}`", payload.overall_status));
    lines.push(format!("- Total runs: `{}`", payload.total_runs));
    lines.push(String::new());
    lines.push("| Failure Class | Count | Rate | Max Allowed | Status |".to_string());
    lines.push("|---|---:|---:|---:|---|".to_string());
    for row in &payload.class_rows {
        lines.push(format!(
            "| {} | {} | {} | {} | {} |",
            row.class,
            row.count,
            pct(row.rate),
            pct(row.max_rate),
            row.status
        ));
    }
    lines.push(String::new());
    lines.push("## Reason Counts".to_string());
    lines.push(String::new());
    lines.push("| Reason Code | Count |".to_string());
    lines.push("|---|---:|".to_string());
    for (reason, count) in &payload.reason_counts {
        lines.push(format!("| {} | {} |", reason, count));
    }
    lines.push(String::new());

    std::fs::write(path, lines.join("\n")).with_context(|| {
        format!(
            "Failed writing failure dashboard markdown '{}'",
            path.display()
        )
    })?;
    Ok(())
}
