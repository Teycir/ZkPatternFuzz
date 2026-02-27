use anyhow::Context;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::{
    auto_halo2_toolchain_candidates, classify_run_reason_code, env_is_set,
    format_stuck_step_warning_line, halo2_effective_external_timeout_secs,
    host_available_memory_mb, is_external_target, progress_stage_is_proof,
    read_template_progress_update, template_progress_path, validate_pattern_only_yaml, Family,
    HardTimeoutStage, MemoryGuardConfig, ScanRunConfig, ScanRunResult, StageTimeoutConfig,
    TemplateInfo, BUILD_CACHE_DIR_ENV, CAIRO_EXTERNAL_TIMEOUT_ENV, HALO2_CARGO_RUN_BIN_ENV,
    HALO2_CARGO_TOOLCHAIN_CANDIDATES_ENV, HALO2_EXTERNAL_TIMEOUT_ENV,
    HALO2_TOOLCHAIN_CASCADE_LIMIT_ENV, HALO2_USE_HOST_CARGO_HOME_ENV, MAX_PIPE_CAPTURE_BYTES,
    PIPE_CAPTURE_TRUNCATED_NOTICE, RUN_SIGNAL_DIR_ENV, SCAN_OUTPUT_ROOT_ENV, SCAN_RUN_ROOT_ENV,
    SCARB_DOWNLOAD_TIMEOUT_ENV,
};

#[cfg(unix)]
fn prepare_child_process_group(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // Place child in its own process group so timeout kills can terminate descendants.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn prepare_child_process_group(_cmd: &mut Command) {}

#[cfg(unix)]
fn kill_child_tree(child: &mut Child) -> std::io::Result<()> {
    let pgid = child.id() as i32;
    let rc = unsafe { libc::killpg(pgid, libc::SIGKILL) };
    if rc == 0 {
        return Ok(());
    }
    child.kill()
}

#[cfg(not(unix))]
fn kill_child_tree(child: &mut Child) -> std::io::Result<()> {
    child.kill()
}

#[derive(Debug)]
pub(super) struct PipeCapture {
    pub(super) bytes: Vec<u8>,
    pub(super) truncated: bool,
}

fn read_pipe_with_cap<R: Read>(mut reader: R) -> anyhow::Result<PipeCapture> {
    let mut bytes = Vec::new();
    let mut scratch = [0u8; 8192];
    let mut truncated = false;

    loop {
        let read = reader.read(&mut scratch)?;
        if read == 0 {
            break;
        }

        let remaining = MAX_PIPE_CAPTURE_BYTES.saturating_sub(bytes.len());
        if remaining > 0 {
            let keep = remaining.min(read);
            bytes.extend_from_slice(&scratch[..keep]);
            if keep < read {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }

    Ok(PipeCapture { bytes, truncated })
}

pub(super) fn spawn_pipe_reader<R>(reader: R) -> JoinHandle<anyhow::Result<PipeCapture>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || read_pipe_with_cap(reader))
}

pub(super) fn join_pipe_reader(
    handle: Option<JoinHandle<anyhow::Result<PipeCapture>>>,
) -> anyhow::Result<PipeCapture> {
    match handle {
        Some(handle) => {
            let result = handle
                .join()
                .map_err(|_| anyhow::anyhow!("failed to join command output reader thread"))?;
            result
        }
        None => Ok(PipeCapture {
            bytes: Vec::new(),
            truncated: false,
        }),
    }
}

pub(super) fn finalize_pipe_capture(
    stdout: PipeCapture,
    mut stderr: PipeCapture,
) -> (Vec<u8>, Vec<u8>) {
    if stdout.truncated || stderr.truncated {
        stderr
            .bytes
            .extend_from_slice(PIPE_CAPTURE_TRUNCATED_NOTICE.as_bytes());
    }
    (stdout.bytes, stderr.bytes)
}

fn memory_headroom_launch_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn wait_for_memory_headroom(guard: MemoryGuardConfig) -> anyhow::Result<()> {
    if !guard.enabled {
        return Ok(());
    }

    let Some(initial_available_mb) = host_available_memory_mb() else {
        return Ok(());
    };
    if initial_available_mb >= guard.launch_floor_mb {
        return Ok(());
    }

    let deadline = Instant::now() + Duration::from_secs(guard.wait_secs);
    let mut last_seen_mb = initial_available_mb;
    let mut warned = false;

    loop {
        if let Some(available_mb) = host_available_memory_mb() {
            last_seen_mb = available_mb;
            if available_mb >= guard.launch_floor_mb {
                return Ok(());
            }
            if !warned {
                eprintln!(
                    "Memory guard waiting: MemAvailable={}MB below launch floor {}MB \
                     (wait up to {}s)",
                    available_mb, guard.launch_floor_mb, guard.wait_secs
                );
                warned = true;
            }
        }

        if Instant::now() >= deadline {
            anyhow::bail!(
                "Memory guard timeout: MemAvailable={}MB stayed below launch floor {}MB \
                 for {}s",
                last_seen_mb,
                guard.launch_floor_mb,
                guard.wait_secs
            );
        }

        std::thread::sleep(Duration::from_millis(guard.poll_ms));
    }
}

fn run_command_with_stage_timeouts(
    cmd: &mut Command,
    template_file: &str,
    progress_path: &Path,
    stage_timeouts: StageTimeoutConfig,
    memory_guard: MemoryGuardConfig,
) -> anyhow::Result<(Output, Option<HardTimeoutStage>)> {
    let launch_guard = memory_headroom_launch_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    wait_for_memory_headroom(memory_guard).with_context(|| {
        format!(
            "Template '{}' launch blocked by memory guard",
            template_file
        )
    })?;

    prepare_child_process_group(cmd);
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    drop(launch_guard);

    let stdout_reader = child.stdout.take().map(spawn_pipe_reader);
    let stderr_reader = child.stderr.take().map(spawn_pipe_reader);

    let started = Instant::now();
    let detection_timeout = Duration::from_secs(stage_timeouts.detection_timeout_secs.max(1));
    let proof_timeout = Duration::from_secs(stage_timeouts.proof_timeout_secs.max(1));
    let stuck_warn_window = Duration::from_secs(stage_timeouts.stuck_step_warn_secs.max(1));
    let mut proof_stage_started: Option<Instant> = None;
    let mut last_progress_dedupe_key: Option<String> = None;
    let mut last_progress_change_at = started;
    let mut next_stuck_warning_at = started + stuck_warn_window;
    let mut last_stage_label = "unknown".to_string();
    let mut last_step_fraction = "?/??".to_string();

    loop {
        if let Some(status) = child.try_wait()? {
            if let Some(update) = read_template_progress_update(template_file, progress_path) {
                let changed = match &last_progress_dedupe_key {
                    Some(prev) => prev != &update.dedupe_key,
                    None => true,
                };
                if changed {
                    println!("{}", update.rendered_line);
                }
            }
            let stdout_capture = join_pipe_reader(stdout_reader)?;
            let stderr_capture = join_pipe_reader(stderr_reader)?;
            let (stdout, stderr) = finalize_pipe_capture(stdout_capture, stderr_capture);
            return Ok((
                Output {
                    status,
                    stdout,
                    stderr,
                },
                None,
            ));
        }

        if let Some(update) = read_template_progress_update(template_file, progress_path) {
            let changed = match &last_progress_dedupe_key {
                Some(prev) => prev != &update.dedupe_key,
                None => true,
            };
            last_stage_label = update.stage.clone();
            last_step_fraction = update.step_fraction.clone();
            if changed {
                println!("{}", update.rendered_line);
                last_progress_dedupe_key = Some(update.dedupe_key.clone());
                last_progress_change_at = Instant::now();
                next_stuck_warning_at = last_progress_change_at + stuck_warn_window;
            }
            if proof_stage_started.is_none() && progress_stage_is_proof(&update.stage) {
                proof_stage_started = Some(Instant::now());
            }
        }

        let now = Instant::now();
        if now >= next_stuck_warning_at {
            let stagnant_secs = now.duration_since(last_progress_change_at).as_secs();
            eprintln!(
                "{}",
                format_stuck_step_warning_line(
                    template_file,
                    &last_stage_label,
                    &last_step_fraction,
                    stagnant_secs,
                    stage_timeouts.stuck_step_warn_secs,
                )
            );
            next_stuck_warning_at = now + stuck_warn_window;
        }
        let timeout_stage = if let Some(proof_started_at) = proof_stage_started {
            if now.duration_since(proof_started_at) >= proof_timeout {
                Some(HardTimeoutStage::Proving)
            } else {
                None
            }
        } else if now.duration_since(started) >= detection_timeout {
            Some(HardTimeoutStage::Detecting)
        } else {
            None
        };

        if let Some(stage) = timeout_stage {
            let _ = kill_child_tree(&mut child);
            let status = child.wait()?;
            let stdout_capture = join_pipe_reader(stdout_reader)?;
            let stderr_capture = join_pipe_reader(stderr_reader)?;
            let (stdout, mut stderr) = finalize_pipe_capture(stdout_capture, stderr_capture);
            let (stage_label, stage_budget) = match stage {
                HardTimeoutStage::Detecting => ("detection", stage_timeouts.detection_timeout_secs),
                HardTimeoutStage::Proving => ("proof", stage_timeouts.proof_timeout_secs),
            };
            stderr.extend_from_slice(
                format!(
                    "\nPer-template hard wall-clock timeout reached during {} stage (budget={}s)\n",
                    stage_label, stage_budget
                )
                .as_bytes(),
            );
            return Ok((
                Output {
                    status,
                    stdout,
                    stderr,
                },
                Some(stage),
            ));
        }

        thread::sleep(Duration::from_millis(200));
    }
}

pub(super) fn run_scan(
    run_cfg: ScanRunConfig<'_>,
    template: &TemplateInfo,
    family: Family,
    validate_only: bool,
    output_suffix: &str,
) -> anyhow::Result<ScanRunResult> {
    let family_str = family.as_str();
    let mut cmd = Command::new(run_cfg.bin_path);
    cmd.env(SCAN_OUTPUT_ROOT_ENV, run_cfg.results_root)
        .env(RUN_SIGNAL_DIR_ENV, run_cfg.run_signal_dir)
        .env(BUILD_CACHE_DIR_ENV, run_cfg.build_cache_dir);
    for (key, value) in run_cfg.env_overrides {
        cmd.env(key, value);
    }
    if !env_is_set(HALO2_EXTERNAL_TIMEOUT_ENV) {
        cmd.env(
            HALO2_EXTERNAL_TIMEOUT_ENV,
            halo2_effective_external_timeout_secs(run_cfg.framework, run_cfg.timeout).to_string(),
        );
    }
    if !env_is_set(CAIRO_EXTERNAL_TIMEOUT_ENV) {
        cmd.env(CAIRO_EXTERNAL_TIMEOUT_ENV, run_cfg.timeout.to_string());
    }
    if !env_is_set(SCARB_DOWNLOAD_TIMEOUT_ENV) {
        cmd.env(SCARB_DOWNLOAD_TIMEOUT_ENV, run_cfg.timeout.to_string());
    }
    if let Some(run_root) = run_cfg.scan_run_root {
        cmd.env(SCAN_RUN_ROOT_ENV, run_root);
    }
    if run_cfg.framework.eq_ignore_ascii_case("halo2") {
        let selected_bin = run_cfg.main_component.trim();
        if !selected_bin.is_empty() {
            cmd.env(HALO2_CARGO_RUN_BIN_ENV, selected_bin);
        }
    }
    if is_external_target(run_cfg.target_circuit) && run_cfg.framework.eq_ignore_ascii_case("halo2")
    {
        let auto_candidates = auto_halo2_toolchain_candidates();

        // External targets often live outside the writable workspace; keep Halo2 Cargo state
        // local and avoid broad toolchain cascades that trigger rustup network fetches.
        if !env_is_set(HALO2_USE_HOST_CARGO_HOME_ENV) {
            cmd.env(HALO2_USE_HOST_CARGO_HOME_ENV, "0");
        }
        if !env_is_set(HALO2_CARGO_TOOLCHAIN_CANDIDATES_ENV) && !auto_candidates.is_empty() {
            cmd.env(
                HALO2_CARGO_TOOLCHAIN_CANDIDATES_ENV,
                auto_candidates.join(","),
            );
        }
        if !env_is_set(HALO2_TOOLCHAIN_CASCADE_LIMIT_ENV) {
            let cascade_limit = auto_candidates.len().clamp(1, 8);
            cmd.env(HALO2_TOOLCHAIN_CASCADE_LIMIT_ENV, cascade_limit.to_string());
        }
    }
    cmd.arg("scan")
        .arg(&template.path)
        .arg("--family")
        .arg(family_str)
        .arg("--target-circuit")
        .arg(run_cfg.target_circuit)
        .arg("--main-component")
        .arg(run_cfg.main_component)
        .arg("--framework")
        .arg(run_cfg.framework)
        .arg("--workers")
        .arg(run_cfg.workers.to_string())
        .arg("--seed")
        .arg(run_cfg.seed.to_string())
        .arg("--iterations")
        .arg(run_cfg.iterations.to_string())
        .arg("--timeout")
        .arg(run_cfg.timeout.to_string())
        .arg("--simple-progress");
    if !run_cfg.extra_args.is_empty() {
        cmd.args(run_cfg.extra_args);
    }

    if !validate_only {
        cmd.arg("--output-suffix").arg(output_suffix);
    }

    if validate_only {
        cmd.arg("--dry-run");
    }

    if run_cfg.dry_run {
        let suffix_arg = if !validate_only {
            format!(" --output-suffix {}", output_suffix)
        } else {
            String::new()
        };
        let extra_args = if run_cfg.extra_args.is_empty() {
            String::new()
        } else {
            format!(" {}", run_cfg.extra_args.join(" "))
        };
        println!(
            "[DRY RUN] {}={} {}={} {}={} {} scan {} --family {} --target-circuit {} --main-component {} --framework {} --workers {} --seed {} --iterations {} --timeout {} --simple-progress{}{}{}",
            SCAN_OUTPUT_ROOT_ENV,
            run_cfg.results_root.display(),
            RUN_SIGNAL_DIR_ENV,
            run_cfg.run_signal_dir.display(),
            BUILD_CACHE_DIR_ENV,
            run_cfg.build_cache_dir.display(),
            run_cfg.bin_path.display(),
            template.path.display(),
            family_str,
            run_cfg.target_circuit,
            run_cfg.main_component,
            run_cfg.framework,
            run_cfg.workers,
            run_cfg.seed,
            run_cfg.iterations,
            run_cfg.timeout,
            extra_args,
            suffix_arg,
            if validate_only { " --dry-run" } else { "" }
        );
        return Ok(ScanRunResult {
            success: true,
            stdout: String::new(),
            stderr: String::new(),
        });
    }

    let progress_path = template_progress_path(run_cfg, output_suffix);
    let (output, timeout_stage_hit) = if !validate_only {
        run_command_with_stage_timeouts(
            &mut cmd,
            &template.file_name,
            &progress_path,
            run_cfg.stage_timeouts,
            run_cfg.memory_guard,
        )?
    } else {
        (cmd.output()?, None)
    };
    if let Some(stage) = timeout_stage_hit {
        let stage_budget_secs = match stage {
            HardTimeoutStage::Detecting => run_cfg.stage_timeouts.detection_timeout_secs,
            HardTimeoutStage::Proving => run_cfg.stage_timeouts.proof_timeout_secs,
        };
        if let Err(err) = write_stage_timeout_outcome(
            run_cfg.artifacts_root,
            run_cfg.scan_run_root,
            output_suffix,
            stage,
            stage_budget_secs,
        ) {
            eprintln!(
                "Failed to write hard-timeout run outcome for '{}' [{}]: {:#}",
                template.file_name, output_suffix, err
            );
        }
    }
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        if !stdout.is_empty() {
            print!("{}", stdout);
        }
        if !stderr.is_empty() {
            eprint!("{}", stderr);
        }
    }

    Ok(ScanRunResult {
        success: output.status.success(),
        stdout,
        stderr,
    })
}

pub(super) fn run_template(
    run_cfg: ScanRunConfig<'_>,
    template: &TemplateInfo,
    family: Family,
    skip_validate: bool,
    output_suffix: &str,
) -> anyhow::Result<bool> {
    if !template.path.exists() {
        eprintln!(
            "Template '{}' failed: file not found '{}'",
            template.file_name,
            template.path.display()
        );
        return Ok(false);
    }

    if let Err(err) = validate_pattern_only_yaml(&template.path) {
        eprintln!(
            "Template '{}' failed: invalid pattern YAML '{}': {}",
            template.file_name,
            template.path.display(),
            err
        );
        return Ok(false);
    }

    if !skip_validate {
        let validate = run_scan(run_cfg, template, family, true, output_suffix)?;
        if !validate.success {
            if is_selector_mismatch_validation(&validate.stdout, &validate.stderr)
                && write_selector_mismatch_outcome(
                    run_cfg.artifacts_root,
                    run_cfg.scan_run_root,
                    output_suffix,
                )
                .is_ok()
            {
                eprintln!(
                    "Template '{}' selector mismatch recorded as synthetic preflight outcome",
                    template.file_name
                );
                return Ok(true);
            }
            eprintln!("Template '{}' failed validation", template.file_name);
            return Ok(false);
        }
    }

    println!("[TEMPLATE STAGE] {} stage=detecting", template.file_name);
    println!("[TEMPLATE STAGE] {} stage=proving", template.file_name);
    let scan_result = run_scan(run_cfg, template, family, false, output_suffix)?;
    if !scan_result.success {
        let reason_code = read_template_reason_code(run_cfg, output_suffix)
            .unwrap_or_else(|| "unknown".to_string());
        if reason_code == "critical_findings_detected" {
            let proof_status = read_template_proof_status(run_cfg, output_suffix)
                .unwrap_or_else(|| "unknown".to_string());
            println!(
                "[TEMPLATE STAGE] {} stage=proof_done proof_status={}",
                template.file_name, proof_status
            );
            println!(
                "[TEMPLATE STAGE] {} stage=completed_with_critical_findings",
                template.file_name
            );
            return Ok(true);
        }
        eprintln!(
            "Template '{}' failed (reason_code={})",
            template.file_name, reason_code
        );
        return Ok(false);
    }
    let proof_status =
        read_template_proof_status(run_cfg, output_suffix).unwrap_or_else(|| "unknown".to_string());
    println!(
        "[TEMPLATE STAGE] {} stage=proof_done proof_status={}",
        template.file_name, proof_status
    );

    Ok(true)
}

pub(super) fn scan_output_suffix(template: &TemplateInfo, family: Family) -> String {
    let stem = template
        .file_name
        .strip_suffix(".yaml")
        .unwrap_or(template.file_name.as_str());
    let mut normalized = String::with_capacity(stem.len() + 8);
    for ch in stem.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            normalized.push(ch);
        } else {
            normalized.push('_');
        }
    }
    if normalized.is_empty() {
        normalized = "pattern".to_string();
    }
    format!("{}__{}", family.as_str(), normalized)
}

fn is_selector_mismatch_validation(stdout: &str, stderr: &str) -> bool {
    let combined = format!("{}\n{}", stdout, stderr).to_ascii_lowercase();
    combined.contains("selectors did not match target circuit")
}

fn write_selector_mismatch_outcome(
    artifacts_root: &Path,
    run_root: Option<&str>,
    output_suffix: &str,
) -> anyhow::Result<()> {
    let Some(run_root) = run_root else {
        anyhow::bail!("scan_run_root is unavailable for selector mismatch outcome");
    };

    let template_dir = artifacts_root.join(run_root).join(output_suffix);
    fs::create_dir_all(&template_dir).with_context(|| {
        format!(
            "Failed creating selector-mismatch artifact dir '{}'",
            template_dir.display()
        )
    })?;

    let run_outcome_path = template_dir.join("run_outcome.json");
    let payload = serde_json::json!({
        "status": "failed",
        "stage": "preflight_selector",
        "reason": "selector_mismatch",
        "error": "Pattern selectors did not match target circuit",
    });
    let serialized = serde_json::to_string_pretty(&payload)?;
    fs::write(&run_outcome_path, serialized).with_context(|| {
        format!(
            "Failed writing selector-mismatch run outcome '{}'",
            run_outcome_path.display()
        )
    })?;

    Ok(())
}

pub(super) fn write_stage_timeout_outcome(
    artifacts_root: &Path,
    run_root: Option<&str>,
    output_suffix: &str,
    stage: HardTimeoutStage,
    stage_budget_secs: u64,
) -> anyhow::Result<()> {
    let Some(run_root) = run_root else {
        anyhow::bail!("scan_run_root is unavailable for hard-timeout outcome");
    };

    let template_dir = artifacts_root.join(run_root).join(output_suffix);
    fs::create_dir_all(&template_dir).with_context(|| {
        format!(
            "Failed creating hard-timeout artifact dir '{}'",
            template_dir.display()
        )
    })?;

    let stage_name = match stage {
        HardTimeoutStage::Detecting => "detecting",
        HardTimeoutStage::Proving => "proof",
    };
    let run_outcome_stage = match stage {
        HardTimeoutStage::Detecting => "detection_timeout",
        HardTimeoutStage::Proving => "proof_timeout",
    };

    let run_outcome_path = template_dir.join("run_outcome.json");
    let payload = serde_json::json!({
        "status": "failed",
        "stage": run_outcome_stage,
        "reason_code": "wall_clock_timeout",
        "reason": "wall_clock_timeout",
        "error": format!(
            "Per-template hard wall-clock timeout reached during {} stage (budget={}s)",
            stage_name,
            stage_budget_secs
        ),
        "discovery_qualification": {
            "proof_status": "proof_failed"
        },
    });
    let serialized = serde_json::to_string_pretty(&payload)?;
    fs::write(&run_outcome_path, serialized).with_context(|| {
        format!(
            "Failed writing hard-timeout run outcome '{}'",
            run_outcome_path.display()
        )
    })?;

    Ok(())
}

fn template_run_outcome_path(run_cfg: ScanRunConfig<'_>, output_suffix: &str) -> Option<PathBuf> {
    let run_root = run_cfg.scan_run_root?;
    Some(
        run_cfg
            .artifacts_root
            .join(run_root)
            .join(output_suffix)
            .join("run_outcome.json"),
    )
}

pub(super) fn proof_status_from_run_outcome_doc(doc: &serde_json::Value) -> Option<String> {
    doc.get("discovery_qualification")
        .and_then(|v| v.get("proof_status"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn reason_code_from_run_outcome_doc(doc: &serde_json::Value) -> Option<String> {
    doc.get("reason_code")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn read_template_run_outcome_doc(
    run_cfg: ScanRunConfig<'_>,
    output_suffix: &str,
) -> Option<serde_json::Value> {
    let run_outcome_path = template_run_outcome_path(run_cfg, output_suffix)?;
    let raw = fs::read_to_string(run_outcome_path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn read_template_reason_code(run_cfg: ScanRunConfig<'_>, output_suffix: &str) -> Option<String> {
    let parsed = read_template_run_outcome_doc(run_cfg, output_suffix)?;
    reason_code_from_run_outcome_doc(&parsed)
        .or_else(|| Some(classify_run_reason_code(&parsed).to_string()))
}

fn read_template_proof_status(run_cfg: ScanRunConfig<'_>, output_suffix: &str) -> Option<String> {
    let parsed = read_template_run_outcome_doc(run_cfg, output_suffix)?;
    proof_status_from_run_outcome_doc(&parsed)
}
