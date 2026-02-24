use crate::cli::ScanFamily;
use anyhow::Context;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ScanFindingsSummary {
    pub(crate) findings_total: u64,
}

pub(crate) fn scan_default_output_dir() -> PathBuf {
    let raw = std::env::var("ZKF_SCAN_OUTPUT_ROOT").unwrap_or_else(|err| {
        eprintln!(
            "[zk-fuzzer] ERROR: ZKF_SCAN_OUTPUT_ROOT is required for scan output: {}",
            err
        );
        std::process::exit(2);
    });
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        eprintln!("[zk-fuzzer] ERROR: ZKF_SCAN_OUTPUT_ROOT is set but empty");
        std::process::exit(2);
    }

    let path = PathBuf::from(trimmed);
    let resolved = if path.is_absolute() {
        path
    } else {
        let cwd = std::env::current_dir().unwrap_or_else(|err| {
            eprintln!(
                "[zk-fuzzer] ERROR: cannot resolve current directory for ZKF_SCAN_OUTPUT_ROOT '{}': {}",
                path.display(),
                err
            );
            std::process::exit(2);
        });
        cwd.join(path)
    };

    std::fs::create_dir_all(&resolved)
        .with_context(|| {
            format!(
                "cannot create output root '{}'",
                resolved.display()
            )
        })
        .unwrap_or_else(|err| {
            eprintln!(
                "[zk-fuzzer] ERROR: cannot initialize ZKF_SCAN_OUTPUT_ROOT '{}': {}",
                resolved.display(),
                err
            );
            std::process::exit(2);
        });
    resolved
}

fn read_scan_progress_step_fraction(progress_path: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(progress_path).ok()?;
    let doc: serde_json::Value = serde_json::from_str(&raw).ok()?;
    doc.get("progress")
        .and_then(|v| v.get("step_fraction"))
        .and_then(|v| v.as_str())
        .map(|value| value.to_string())
}

pub(crate) fn read_scan_findings_summary_since(
    output_dir: &Path,
    phase_started_at: std::time::SystemTime,
) -> Option<ScanFindingsSummary> {
    let run_outcome_path = output_dir.join("run_outcome.json");
    let modified = std::fs::metadata(&run_outcome_path).ok()?.modified().ok()?;
    if modified < phase_started_at {
        return None;
    }
    let raw = std::fs::read_to_string(run_outcome_path).ok()?;
    let doc: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let metrics = doc.get("metrics")?;

    let findings_total = metrics
        .get("findings_total")
        .and_then(|v| v.as_u64())
        .or_else(|| metrics.get("chain_findings_total").and_then(|v| v.as_u64()))
        .or_else(|| metrics.get("total_findings").and_then(|v| v.as_u64()))
        .unwrap_or(0);
    Some(ScanFindingsSummary { findings_total })
}

pub(crate) async fn run_scan_phase_with_progress<F>(
    phase_label: &str,
    output_dir: &Path,
    phase_future: F,
) -> anyhow::Result<()>
where
    F: std::future::Future<Output = anyhow::Result<()>>,
{
    let progress_path = output_dir.join("progress.json");
    let mut last_fraction: Option<String> = read_scan_progress_step_fraction(&progress_path);
    let mut phase_future = std::pin::pin!(phase_future);

    loop {
        tokio::select! {
            result = &mut phase_future => return result,
            _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                let fraction = read_scan_progress_step_fraction(&progress_path);
                if let Some(fraction) = fraction {
                    let changed = match &last_fraction {
                        Some(prev) => prev != &fraction,
                        None => true,
                    };
                    if changed {
                        println!("{} {}", phase_label, fraction);
                        last_fraction = Some(fraction);
                    }
                }
            }
        }
    }
}

pub(crate) async fn run_scan_mode_with_progress<F>(
    mode_label: &str,
    output_dir: &Path,
    phase_future: F,
) -> anyhow::Result<()>
where
    F: std::future::Future<Output = anyhow::Result<()>>,
{
    tracing::info!("Scan (yaml {} run)", mode_label);
    println!("\nSCAN START");
    let started_at = std::time::SystemTime::now();
    let run_result = run_scan_phase_with_progress("scan", output_dir, phase_future).await;
    let summary = read_scan_findings_summary_since(output_dir, started_at).unwrap_or_default();
    println!("SCAN END");
    println!("scan findings: {}", summary.findings_total);
    run_result
}

pub(crate) async fn dispatch_scan_family_run<MkMono, MkMulti, MonoFut, MultiFut>(
    family: ScanFamily,
    output_dir: &Path,
    mono_has_explicit_corpus_dir: bool,
    mono_run: MkMono,
    multi_run: MkMulti,
) -> anyhow::Result<()>
where
    MkMono: FnOnce() -> MonoFut,
    MkMulti: FnOnce() -> MultiFut,
    MonoFut: std::future::Future<Output = anyhow::Result<()>>,
    MultiFut: std::future::Future<Output = anyhow::Result<()>>,
{
    match family {
        ScanFamily::Mono => run_scan_mode_with_progress("mono", output_dir, mono_run()).await,
        ScanFamily::Multi => {
            if mono_has_explicit_corpus_dir {
                anyhow::bail!(
                    "--corpus-dir is mono-only. Multi/chain scans use chain corpus under ZKF_SCAN_OUTPUT_ROOT."
                );
            }
            run_scan_mode_with_progress("multi", output_dir, multi_run()).await
        }
        ScanFamily::Auto => unreachable!("auto resolved before scan run dispatch"),
    }
}
