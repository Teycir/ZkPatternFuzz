use anyhow::Context;
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use super::{
    Args, Family, MemoryGuardConfig, ScanRunConfig, TemplateInfo, MEMORY_GUARD_ENABLED_ENV,
    MEMORY_GUARD_RESERVED_MB_ENV, RUN_ROOT_NONCE,
};

pub(super) struct TemplateProgressUpdate {
    pub(super) dedupe_key: String,
    pub(super) rendered_line: String,
    pub(super) stage: String,
    pub(super) step_fraction: String,
}

pub(super) struct BatchProgress {
    total: usize,
    started_at: Instant,
    completed: AtomicUsize,
    template_errors: AtomicUsize,
}

impl BatchProgress {
    pub(super) fn new(total: usize) -> Self {
        Self {
            total,
            started_at: Instant::now(),
            completed: AtomicUsize::new(0),
            template_errors: AtomicUsize::new(0),
        }
    }

    pub(super) fn record(&self, template_file: &str, success: bool) -> String {
        let completed = self.completed.fetch_add(1, Ordering::SeqCst) + 1;
        let template_errors = if success {
            self.template_errors.load(Ordering::SeqCst)
        } else {
            self.template_errors.fetch_add(1, Ordering::SeqCst) + 1
        };
        let succeeded = completed.saturating_sub(template_errors);
        let elapsed_secs = self.started_at.elapsed().as_secs_f64();

        format_batch_progress_line(
            completed,
            self.total,
            succeeded,
            template_errors,
            elapsed_secs,
            template_file,
            success,
        )
    }
}

fn format_batch_progress_line(
    completed: usize,
    total: usize,
    succeeded: usize,
    template_errors: usize,
    elapsed_secs: f64,
    template_file: &str,
    success: bool,
) -> String {
    let percent = if total == 0 {
        100.0
    } else {
        (completed as f64 * 100.0) / total as f64
    };
    let elapsed = elapsed_secs.max(0.001);
    let rate = completed as f64 / elapsed;
    let remaining = total.saturating_sub(completed);
    let eta_secs = if rate > 0.0 {
        remaining as f64 / rate
    } else {
        0.0
    };
    let result = if success { "ok" } else { "template_error" };

    format!(
        "[BATCH PROGRESS] {}/{} ({:.1}%) ok={} template_errors={} elapsed={:.1}s rate={:.2}/s eta={:.1}s last={} result={}",
        completed,
        total,
        percent,
        succeeded,
        template_errors,
        elapsed,
        rate,
        eta_secs,
        template_file,
        result
    )
}

pub(super) fn template_progress_path(run_cfg: ScanRunConfig<'_>, output_suffix: &str) -> PathBuf {
    if let Some(run_root) = run_cfg.scan_run_root {
        run_cfg
            .artifacts_root
            .join(run_root)
            .join(output_suffix)
            .join("progress.json")
    } else {
        run_cfg
            .results_root
            .join(output_suffix)
            .join("progress.json")
    }
}

pub(super) fn read_template_progress_update(
    template_file: &str,
    progress_path: &Path,
) -> Option<TemplateProgressUpdate> {
    let raw = fs::read_to_string(progress_path).ok()?;
    let doc: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let progress = doc.get("progress")?;
    let step_fraction = progress
        .get("step_fraction")
        .and_then(|v| v.as_str())
        .unwrap_or("?/??");
    let stage = doc
        .get("stage")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let details = doc.get("details");
    let attack_type = details
        .and_then(|d| d.get("attack_type"))
        .and_then(|v| v.as_str());
    let elapsed_seconds = details
        .and_then(|d| d.get("elapsed_seconds"))
        .and_then(|v| v.as_u64());
    let findings_total = details
        .and_then(|d| d.get("findings_total"))
        .and_then(|v| v.as_u64());

    let mut rendered = format!(
        "[TEMPLATE STEP] {} step={} stage={}",
        template_file, step_fraction, stage
    );
    if let Some(attack_type) = attack_type {
        rendered.push_str(&format!(" attack={}", attack_type));
    }
    if let Some(elapsed_seconds) = elapsed_seconds {
        rendered.push_str(&format!(" elapsed={}s", elapsed_seconds));
    }
    if stage == "completed" {
        if let Some(findings_total) = findings_total {
            rendered.push_str(&format!(" detected_patterns={}", findings_total));
        }
    }

    let dedupe_key = format!(
        "{}|{}|{}|{}|{}",
        step_fraction,
        stage,
        attack_type.unwrap_or_default(),
        elapsed_seconds.unwrap_or(0),
        findings_total.unwrap_or(0)
    );

    Some(TemplateProgressUpdate {
        dedupe_key,
        rendered_line: rendered,
        stage: stage.to_string(),
        step_fraction: step_fraction.to_string(),
    })
}

pub(super) fn progress_stage_is_proof(stage: &str) -> bool {
    let normalized = stage.trim().to_ascii_lowercase();
    normalized == "reporting"
        || normalized == "completed"
        || normalized.contains("proof")
        || normalized.contains("report")
        || normalized.contains("evidence")
}

pub(super) fn format_stuck_step_warning_line(
    template_file: &str,
    stage: &str,
    step_fraction: &str,
    stagnant_secs: u64,
    window_secs: u64,
) -> String {
    format!(
        "[TEMPLATE WARNING] {} warning=stuck_step stage={} step={} no_progress_for={}s window={}s",
        template_file, stage, step_fraction, stagnant_secs, window_secs
    )
}

pub(super) fn parse_mem_available_kib(meminfo: &str) -> Option<u64> {
    let mut mem_available_kib: Option<u64> = None;
    let mut mem_total_kib: Option<u64> = None;

    for line in meminfo.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(raw_value) = parts.next() else {
            continue;
        };
        let Ok(value) = raw_value.parse::<u64>() else {
            continue;
        };
        match key {
            "MemAvailable:" => mem_available_kib = Some(value),
            "MemTotal:" => mem_total_kib = Some(value),
            _ => {}
        }
    }

    mem_available_kib.or(mem_total_kib)
}

pub(super) fn host_available_memory_mb() -> Option<u64> {
    let raw = fs::read_to_string("/proc/meminfo").ok()?;
    let kib = parse_mem_available_kib(&raw)?;
    Some((kib / 1024).max(1))
}

pub(super) fn estimated_batch_memory_mb(
    jobs: usize,
    workers: usize,
    guard: MemoryGuardConfig,
) -> u64 {
    let jobs_u64 = jobs as u64;
    let workers_u64 = workers as u64;
    jobs_u64.saturating_mul(
        guard
            .mb_per_template
            .saturating_add(workers_u64.saturating_mul(guard.mb_per_worker)),
    )
}

pub(super) fn apply_memory_parallelism_guardrails_with_available(
    args: &mut Args,
    guard: MemoryGuardConfig,
    available_mb: Option<u64>,
) -> anyhow::Result<()> {
    if !guard.enabled {
        anyhow::bail!(
            "Unsafe proof-stage memory settings: {}=false disables launch guardrails. \
             Keep memory guard enabled for proof-stage runs.",
            MEMORY_GUARD_ENABLED_ENV
        );
    }
    if guard.reserved_mb == 0 {
        anyhow::bail!(
            "Unsafe proof-stage memory settings: {}=0 removes host safety reserve. \
             Set {} to a positive value.",
            MEMORY_GUARD_RESERVED_MB_ENV,
            MEMORY_GUARD_RESERVED_MB_ENV
        );
    }

    let Some(available_mb) = available_mb else {
        eprintln!(
            "Memory guard: unable to read /proc/meminfo; skipping automatic jobs/workers throttling"
        );
        return Ok(());
    };

    let budget_mb = available_mb.saturating_sub(guard.reserved_mb);
    if budget_mb == 0 {
        anyhow::bail!(
            "Memory guard blocked run: MemAvailable={}MB <= reserved={}MB. \
             Lower {} or free memory.",
            available_mb,
            guard.reserved_mb,
            MEMORY_GUARD_RESERVED_MB_ENV
        );
    }

    let requested_jobs = args.jobs.max(1);
    let requested_workers = args.workers.max(1);
    let requested_estimate = estimated_batch_memory_mb(requested_jobs, requested_workers, guard);

    let mut safe_jobs = requested_jobs;
    let mut safe_workers = requested_workers;
    while safe_jobs > 1 && estimated_batch_memory_mb(safe_jobs, safe_workers, guard) > budget_mb {
        safe_jobs -= 1;
    }
    while safe_workers > 1 && estimated_batch_memory_mb(safe_jobs, safe_workers, guard) > budget_mb
    {
        safe_workers -= 1;
    }

    let safe_estimate = estimated_batch_memory_mb(safe_jobs, safe_workers, guard);
    if safe_estimate > budget_mb {
        anyhow::bail!(
            "Memory guard blocked run: requested jobs={} workers={} (~{}MB) exceeds budget {}MB \
             and cannot be safely reduced below jobs=1 workers=1 under current guardrail settings.",
            requested_jobs,
            requested_workers,
            requested_estimate,
            budget_mb
        );
    }

    if safe_jobs != requested_jobs || safe_workers != requested_workers {
        eprintln!(
            "Memory guard throttled parallelism: jobs {} -> {}, workers {} -> {} \
             (MemAvailable={}MB, reserve={}MB, budget={}MB, estimated={}MB)",
            requested_jobs,
            safe_jobs,
            requested_workers,
            safe_workers,
            available_mb,
            guard.reserved_mb,
            budget_mb,
            safe_estimate
        );
        args.jobs = safe_jobs;
        args.workers = safe_workers;
    }

    Ok(())
}

pub(super) fn apply_memory_parallelism_guardrails(
    args: &mut Args,
    guard: MemoryGuardConfig,
) -> anyhow::Result<()> {
    apply_memory_parallelism_guardrails_with_available(args, guard, host_available_memory_mb())
}

fn effective_family(template_family: Family, family_override: Family) -> Family {
    match family_override {
        Family::Auto => template_family,
        Family::Mono => Family::Mono,
        Family::Multi => Family::Multi,
    }
}

pub(super) fn validate_template_compatibility(
    template: &TemplateInfo,
    family_override: Family,
) -> anyhow::Result<Family> {
    if template.family != Family::Auto
        && family_override != Family::Auto
        && template.family != family_override
    {
        anyhow::bail!(
            "Template '{}' family '{}' is incompatible with override '{}'",
            template.file_name,
            template.family.as_str(),
            family_override.as_str()
        );
    }
    let effective = effective_family(template.family, family_override);
    Ok(effective)
}

pub(super) fn reserve_batch_scan_run_root(artifacts_root: &Path) -> anyhow::Result<String> {
    std::fs::create_dir_all(artifacts_root).with_context(|| {
        format!(
            "Failed to create scan artifacts root '{}'",
            artifacts_root.display()
        )
    })?;

    // Process-safe reservation via atomic create_dir; candidate includes pid + monotonic nonce.
    for _ in 0..512 {
        let ts = Utc::now().format("%Y%m%d_%H%M%S_%3f").to_string();
        let nonce = RUN_ROOT_NONCE.fetch_add(1, Ordering::Relaxed);
        let candidate = format!("scan_run{}_p{}_n{}", ts, std::process::id(), nonce);
        let reservation = artifacts_root.join(&candidate);
        match std::fs::create_dir(&reservation) {
            Ok(_) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "Failed to reserve batch scan run root '{}' under '{}': {}",
                    candidate,
                    artifacts_root.display(),
                    err
                ));
            }
        }
    }

    anyhow::bail!(
        "Failed to allocate unique batch scan run root after repeated collisions under '{}'",
        artifacts_root.display()
    )
}
