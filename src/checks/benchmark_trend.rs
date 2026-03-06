use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendEntry {
    pub generated_utc: Option<String>,
    pub summary_path: String,
    pub total_runs: usize,
    pub total_detected: usize,
    pub overall_completion_rate: f64,
    pub vulnerable_recall: f64,
    pub precision: f64,
    pub safe_false_positive_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendPayload {
    pub entry: TrendEntry,
    pub previous: Option<Value>,
}

pub fn latest_summary_path(benchmark_root: &Path) -> anyhow::Result<PathBuf> {
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
        if !name.starts_with("benchmark_") {
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
        .ok_or_else(|| anyhow::anyhow!("No summary.json found under {}", benchmark_root.display()))
}

pub fn load_json(path: &Path) -> anyhow::Result<Value> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read '{}'", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("Failed to parse '{}'", path.display()))
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

pub fn extract_entry(summary: &Value, summary_path: &Path) -> TrendEntry {
    let generated_utc = summary
        .get("generated_utc")
        .and_then(Value::as_str)
        .map(str::to_string);
    TrendEntry {
        generated_utc,
        summary_path: summary_path.display().to_string(),
        total_runs: get_usize(summary, "total_runs", 0),
        total_detected: get_usize(summary, "total_detected", 0),
        overall_completion_rate: get_f64(summary, "overall_completion_rate", 0.0),
        vulnerable_recall: get_f64(summary, "vulnerable_recall", 0.0),
        precision: get_f64(summary, "precision", 0.0),
        safe_false_positive_rate: get_f64(summary, "safe_false_positive_rate", 0.0),
    }
}

pub fn last_history_entry(history_file: &Path) -> anyhow::Result<Option<Value>> {
    if !history_file.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(history_file)
        .with_context(|| format!("Failed to read '{}'", history_file.display()))?;
    let Some(last_non_empty) = raw.lines().map(str::trim).rfind(|line| !line.is_empty()) else {
        return Ok(None);
    };
    let value: Value = serde_json::from_str(last_non_empty).with_context(|| {
        format!(
            "Failed to parse last JSONL history entry in '{}'",
            history_file.display()
        )
    })?;
    Ok(Some(value))
}

fn pct(value: Option<f64>) -> String {
    match value {
        Some(v) => format!("{:.2}%", v * 100.0),
        None => "n/a".to_string(),
    }
}

fn delta(curr: Option<f64>, prev: Option<f64>) -> Option<f64> {
    match (curr, prev) {
        (Some(curr), Some(prev)) => Some(curr - prev),
        _ => None,
    }
}

fn format_delta(value: Option<f64>) -> String {
    match value {
        Some(v) if v >= 0.0 => format!("+{:.2}pp", v * 100.0),
        Some(v) => format!("{:.2}pp", v * 100.0),
        None => "n/a".to_string(),
    }
}

fn previous_metric(previous: Option<&Value>, key: &str) -> Option<f64> {
    previous
        .and_then(|value| value.get(key))
        .and_then(value_to_f64)
}

pub fn write_markdown(
    path: &Path,
    entry: &TrendEntry,
    previous: Option<&Value>,
) -> anyhow::Result<()> {
    let completion_delta = delta(
        Some(entry.overall_completion_rate),
        previous_metric(previous, "overall_completion_rate"),
    );
    let recall_delta = delta(
        Some(entry.vulnerable_recall),
        previous_metric(previous, "vulnerable_recall"),
    );
    let precision_delta = delta(
        Some(entry.precision),
        previous_metric(previous, "precision"),
    );
    let safe_fpr_delta = delta(
        Some(entry.safe_false_positive_rate),
        previous_metric(previous, "safe_false_positive_rate"),
    );
    let previous_generated_utc = previous
        .and_then(|value| value.get("generated_utc"))
        .and_then(Value::as_str)
        .unwrap_or("n/a");

    let mut lines = Vec::new();
    lines.push("# Benchmark Trend Report".to_string());
    lines.push(String::new());
    lines.push(format!(
        "- Generated UTC: `{}`",
        entry.generated_utc.as_deref().unwrap_or("n/a")
    ));
    lines.push(format!("- Summary: `{}`", entry.summary_path));
    lines.push(String::new());
    lines.push("| Metric | Current | Delta vs Previous |".to_string());
    lines.push("|---|---:|---:|".to_string());
    lines.push(format!(
        "| Completion rate | {} | {} |",
        pct(Some(entry.overall_completion_rate)),
        format_delta(completion_delta)
    ));
    lines.push(format!(
        "| Vulnerable recall | {} | {} |",
        pct(Some(entry.vulnerable_recall)),
        format_delta(recall_delta)
    ));
    lines.push(format!(
        "| Precision | {} | {} |",
        pct(Some(entry.precision)),
        format_delta(precision_delta)
    ));
    lines.push(format!(
        "| Safe false-positive rate | {} | {} |",
        pct(Some(entry.safe_false_positive_rate)),
        format_delta(safe_fpr_delta)
    ));
    lines.push(String::new());
    lines.push("| Count | Value |".to_string());
    lines.push("|---|---:|".to_string());
    lines.push(format!("| Total runs | {} |", entry.total_runs));
    lines.push(format!("| Total detected | {} |", entry.total_detected));
    lines.push(String::new());
    lines.push(format!(
        "- Previous generated UTC: `{previous_generated_utc}`"
    ));
    lines.push(String::new());

    std::fs::write(path, lines.join("\n"))
        .with_context(|| format!("Failed writing markdown trend report '{}'", path.display()))?;
    Ok(())
}

pub fn write_payload_json(path: &Path, payload: &TrendPayload) -> anyhow::Result<()> {
    let raw = serde_json::to_string_pretty(payload)
        .with_context(|| "Failed serializing trend payload")?;
    std::fs::write(path, raw)
        .with_context(|| format!("Failed writing trend payload '{}'", path.display()))?;
    Ok(())
}

pub fn append_history(history_file: &Path, entry: &TrendEntry) -> anyhow::Result<()> {
    let parent = history_file.parent().ok_or_else(|| {
        anyhow::anyhow!("History file has no parent: '{}'", history_file.display())
    })?;
    if !parent.exists() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed creating '{}'", parent.display()))?;
    }
    let line =
        serde_json::to_string(entry).with_context(|| "Failed serializing trend history entry")?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(history_file)
        .with_context(|| format!("Failed opening history file '{}'", history_file.display()))?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("Failed writing history file '{}'", history_file.display()))?;
    file.write_all(b"\n").with_context(|| {
        format!(
            "Failed writing history newline '{}'",
            history_file.display()
        )
    })?;
    Ok(())
}

pub fn ensure_output_dir(path: &Path) -> anyhow::Result<()> {
    if path.as_os_str().is_empty() {
        bail!("Output directory cannot be empty");
    }
    std::fs::create_dir_all(path)
        .with_context(|| format!("Failed creating output dir '{}'", path.display()))
}
