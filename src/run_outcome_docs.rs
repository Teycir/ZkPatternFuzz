use chrono::{DateTime, Duration as ChronoDuration, Local, Utc};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub(crate) struct RunOutcomeDocContext<'a> {
    pub command: &'a str,
    pub run_id: &'a str,
    pub stage: &'a str,
    pub config_path: &'a str,
    pub campaign_name: &'a str,
    pub output_dir: &'a Path,
    pub started_utc: &'a DateTime<Utc>,
    pub timeout_seconds: Option<u64>,
}

pub(crate) fn add_run_window_fields(
    doc: &mut serde_json::Value,
    started_utc: DateTime<Utc>,
    timeout_seconds: Option<u64>,
    timeout_semantics: &'static str,
) {
    let started_local = started_utc.with_timezone(&Local);
    let expected_end_utc = timeout_seconds
        .and_then(|s| match i64::try_from(s) {
            Ok(seconds) => Some(seconds),
            Err(err) => {
                tracing::warn!("Timeout seconds value '{}' exceeds i64: {}", s, err);
                None
            }
        })
        .map(|s| started_utc + ChronoDuration::seconds(s));
    let expected_end_local = expected_end_utc.map(|dt| dt.with_timezone(&Local));

    if let Some(obj) = doc.as_object_mut() {
        obj.insert(
            "run_window".to_string(),
            serde_json::json!({
                "started_utc": started_utc.to_rfc3339(),
                "started_local": started_local.to_rfc3339(),
                "timeout_seconds": timeout_seconds,
                "timeout_semantics": timeout_semantics,
                "expected_latest_end_utc": expected_end_utc.map(|dt| dt.to_rfc3339()),
                "expected_latest_end_local": expected_end_local.map(|dt| dt.to_rfc3339()),
                "note": match timeout_semantics {
                    "wall_clock" => "For this command, --timeout is enforced as a total wall-clock budget for the run.",
                    _ => "",
                },
            }),
        );
    }
}

pub(crate) fn classify_run_reason_code(doc: &serde_json::Value) -> Option<&'static str> {
    let obj = doc.as_object()?;
    let status = obj
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let stage = obj
        .get("stage")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let error_lc = obj
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let reason_lc = obj
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let panic_message_lc = obj
        .get("panic")
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    let is_dependency_resolution_failure = |message: &str| -> bool {
        message.contains("failed to load source for dependency")
            || message.contains("failed to get `")
            || message.contains("failed to update")
            || message.contains("unable to update")
            || message.contains("could not clone")
            || message.contains("failed to clone")
            || message.contains("failed to fetch into")
            || message.contains("couldn't find remote ref")
            || message.contains("network failure seems to have happened")
            || message.contains("spurious network error")
            || message.contains("index-pack failed")
            || message.contains("failed to download")
            || message.contains("checksum failed")
    };
    let is_input_contract_mismatch = |message: &str| -> bool {
        message.contains("not all inputs have been set")
            || message.contains("input map is missing")
            || message.contains("missing required circom signals")
    };
    let is_circom_compilation_failure = |message: &str| -> bool {
        message.contains("circom compilation failed")
            || message.contains("failed to run circom compiler")
            || (message.contains("out of bounds exception") && message.contains(".circom"))
    };
    let is_backend_toolchain_mismatch = |message: &str| -> bool {
        let cascade_exhausted = message.contains("toolchain cascade exhausted")
            || message.contains("scarb build failed for all configured candidates")
            || message.contains("no working scarb candidate found");
        let scarb_compile_mismatch = message.contains("scarb build failed")
            && message.contains("could not compile `")
            && (message.contains("error[e")
                || message.contains("identifier not found")
                || message.contains("type annotations needed")
                || message.contains("unsupported"));
        let rust_toolchain_mismatch = message.contains("requires rustc")
            || message.contains("the package requires")
            || message.contains("is not supported by this compiler")
            || message.contains("cargo-features");
        cascade_exhausted || scarb_compile_mismatch || rust_toolchain_mismatch
    };

    if status == "completed_with_critical_findings" {
        return Some("critical_findings_detected");
    }
    if status == "completed" {
        return Some("completed");
    }
    if status == "failed_engagement_contract" {
        return Some("engagement_contract_failed");
    }
    if status == "stale_interrupted" {
        return Some("stale_interrupted");
    }
    if status == "panic" {
        if panic_message_lc.contains("missing required 'command' in run document") {
            return Some("artifact_mirror_panic_missing_command");
        }
        return Some("panic");
    }
    if status == "running" {
        return None;
    }
    if error_lc.contains("permission denied") {
        return Some("filesystem_permission_denied");
    }
    if stage == "preflight_backend"
        && (error_lc.contains("backend required but not available")
            || error_lc.contains("not found in path")
            || error_lc.contains("snarkjs not found")
            || error_lc.contains("circom not found")
            || error_lc.contains("install circom"))
    {
        return Some("backend_tooling_missing");
    }
    if stage == "preflight_backend" && is_dependency_resolution_failure(&error_lc) {
        return Some("backend_dependency_resolution_failed");
    }
    if stage == "preflight_backend" && is_backend_toolchain_mismatch(&error_lc) {
        return Some("backend_toolchain_mismatch");
    }
    if is_circom_compilation_failure(&error_lc) {
        return Some("circom_compilation_failed");
    }
    if error_lc.contains("key generation failed")
        || error_lc.contains("key setup failed")
        || error_lc.contains("proving key")
    {
        return Some("key_generation_failed");
    }
    if error_lc.contains("wall-clock timeout") || reason_lc.contains("wall-clock timeout") {
        return Some("wall_clock_timeout");
    }
    if stage == "acquire_output_lock" {
        return Some("output_dir_locked");
    }
    if is_input_contract_mismatch(&error_lc) {
        return Some("backend_input_contract_mismatch");
    }
    if stage == "preflight_backend" {
        return Some("backend_preflight_failed");
    }
    if stage == "preflight_invariants" {
        return Some("missing_invariants");
    }
    if stage == "preflight_readiness" {
        return Some("readiness_failed");
    }
    if stage == "preflight_selector" {
        return Some("selector_mismatch");
    }
    if stage == "parse_chains" && reason_lc.contains("requires chains") {
        return Some("missing_chains_definition");
    }
    if status == "failed" {
        return Some("runtime_error");
    }
    None
}

pub(crate) fn log_run_reason_code(doc: &serde_json::Value) {
    if doc
        .get("status")
        .and_then(|v| v.as_str())
        .map(|s| s == "running")
        .unwrap_or(false)
    {
        return;
    }
    let code = doc
        .get("reason_code")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .or_else(|| classify_run_reason_code(doc).map(|value| value.to_string()));
    let Some(code) = code else {
        return;
    };
    let status = doc
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let stage = doc
        .get("stage")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    // Logging should never crash the run lifecycle (e.g., broken stderr pipe in parent process).
    let _ = std::panic::catch_unwind(|| {
        tracing::info!(
            "run_outcome_classified: reason_code={} status={} stage={}",
            code.as_str(),
            status,
            stage
        );
    });
}

fn reason_code_from_doc_or_classification(doc: &serde_json::Value) -> String {
    if let Some(code) = doc
        .get("reason_code")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return code.to_string();
    }

    if let Some(code) = classify_run_reason_code(doc) {
        return code.to_string();
    }

    match doc
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
    {
        "running" => "running".to_string(),
        _ => "unknown".to_string(),
    }
}

fn status_family(status: &str) -> &'static str {
    match status {
        "running" => "running",
        "completed" | "completed_with_critical_findings" => "completed",
        "failed" | "failed_engagement_contract" | "stale_interrupted" | "panic" => "failed",
        _ => "unknown",
    }
}

fn is_terminal(status: &str) -> bool {
    !matches!(status, "running")
}

fn findings_total_from_doc(doc: &serde_json::Value) -> u64 {
    let Some(metrics) = doc.get("metrics") else {
        return 0;
    };
    metrics
        .get("findings_total")
        .and_then(|v| v.as_u64())
        .or_else(|| metrics.get("chain_findings_total").and_then(|v| v.as_u64()))
        .or_else(|| metrics.get("total_findings").and_then(|v| v.as_u64()))
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, Default)]
struct EvidenceProofStats {
    bundles_total: u64,
    passed: u64,
    failed: u64,
    skipped: u64,
    pending: u64,
    unknown: u64,
    complete_proof_packs: u64,
    passed_with_complete_pack: u64,
    failed_with_complete_pack: u64,
    missing_required_artifacts: u64,
}

impl EvidenceProofStats {
    fn has_unresolved(&self) -> bool {
        self.pending > 0 || self.unknown > 0
    }
}

fn classify_bundle_verification_result(bundle: &serde_json::Value) -> &'static str {
    let Some(result) = bundle.get("verification_result") else {
        return "unknown";
    };

    match result {
        serde_json::Value::String(value) => {
            let lc = value.to_ascii_lowercase();
            if lc == "passed" {
                "passed"
            } else if lc == "failed" {
                "failed"
            } else if lc == "skipped" {
                "skipped"
            } else if lc == "pending" {
                "pending"
            } else {
                "unknown"
            }
        }
        serde_json::Value::Object(map) => {
            if map.contains_key("Failed") {
                "failed"
            } else if map.contains_key("Skipped") {
                "skipped"
            } else {
                "unknown"
            }
        }
        _ => "unknown",
    }
}

fn has_required_proof_artifacts(bundle_path: &Path) -> bool {
    let Some(bundle_dir) = bundle_path.parent() else {
        return false;
    };

    let has_replay_command = bundle_dir.join("replay_command.txt").exists();
    let has_notes = bundle_dir.join("exploit_notes.md").exists()
        || bundle_dir.join("no_exploit_proof.md").exists();
    let has_impact = bundle_dir.join("impact.md").exists();
    let has_log = std::fs::read_dir(bundle_dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .any(|name| name.ends_with(".log"));

    has_replay_command && has_notes && has_impact && has_log
}

fn evidence_bundle_paths(output_dir: &str) -> Vec<PathBuf> {
    let evidence_dir = Path::new(output_dir).join("evidence");
    let entries = match std::fs::read_dir(&evidence_dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("bundle.json"))
        .filter(|path| path.exists())
        .collect()
}

fn collect_evidence_proof_stats(output_dir: Option<&str>) -> Option<EvidenceProofStats> {
    let output_dir = output_dir
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let mut stats = EvidenceProofStats::default();

    for bundle_path in evidence_bundle_paths(output_dir) {
        stats.bundles_total += 1;
        let has_required_artifacts = has_required_proof_artifacts(&bundle_path);
        if has_required_artifacts {
            stats.complete_proof_packs += 1;
        } else {
            stats.missing_required_artifacts += 1;
        }
        let raw = match std::fs::read_to_string(&bundle_path) {
            Ok(raw) => raw,
            Err(_) => {
                stats.unknown += 1;
                continue;
            }
        };
        let parsed: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(value) => value,
            Err(_) => {
                stats.unknown += 1;
                continue;
            }
        };
        match classify_bundle_verification_result(&parsed) {
            "passed" => {
                stats.passed += 1;
                if has_required_artifacts {
                    stats.passed_with_complete_pack += 1;
                }
            }
            "failed" => {
                stats.failed += 1;
                if has_required_artifacts {
                    stats.failed_with_complete_pack += 1;
                }
            }
            "skipped" => stats.skipped += 1,
            "pending" => stats.pending += 1,
            _ => stats.unknown += 1,
        }
    }

    Some(stats)
}

fn critical_findings_from_doc(doc: &serde_json::Value) -> bool {
    if let Some(metrics) = doc.get("metrics") {
        if let Some(value) = metrics.get("critical_findings").and_then(|v| v.as_bool()) {
            return value;
        }
    }
    matches!(
        doc.get("status").and_then(|v| v.as_str()),
        Some("completed_with_critical_findings")
    )
}

fn discovery_state(status: &str, findings_total: u64, critical_findings: bool) -> &'static str {
    match status {
        "running" => "in_progress",
        "completed_with_critical_findings" => "candidate_vulnerability",
        "completed" => {
            if critical_findings || findings_total > 0 {
                "candidate_vulnerability"
            } else {
                "no_vulnerability_observed"
            }
        }
        "failed_engagement_contract" => "engagement_contract_failed",
        "stale_interrupted" => "stale_interrupted",
        "failed" | "panic" => "run_failed",
        _ => "unknown",
    }
}

fn proof_status(
    reason_code: &str,
    stage: &str,
    discovery_state: &str,
    findings_total: u64,
    proof_stats: Option<EvidenceProofStats>,
) -> &'static str {
    match discovery_state {
        "candidate_vulnerability" => {
            let Some(stats) = proof_stats else {
                return "proof_failed";
            };
            if stats.passed_with_complete_pack > 0 {
                return "exploitable";
            }
            // Every finding produced a verifier-rejected proof artifact.
            if findings_total > 0
                && stats.bundles_total >= findings_total
                && stats.failed >= findings_total
                && stats.failed_with_complete_pack >= findings_total
                && stats.skipped == 0
                && !stats.has_unresolved()
            {
                return "not_exploitable_within_bounds";
            }
            "proof_failed"
        }
        "run_failed" | "stale_interrupted" => {
            if reason_code == "wall_clock_timeout" || stage.contains("proof") {
                "proof_failed"
            } else {
                "not_ready"
            }
        }
        "no_vulnerability_observed" => "proof_skipped_by_policy",
        _ => "not_ready",
    }
}

fn analysis_priority(discovery_state: &str) -> &'static str {
    match discovery_state {
        "candidate_vulnerability" => "high",
        "run_failed" | "engagement_contract_failed" | "stale_interrupted" => "high",
        "no_vulnerability_observed" => "medium",
        "in_progress" => "low",
        _ => "medium",
    }
}

fn next_step(discovery_state: &str, proof_status: &str) -> &'static str {
    match proof_status {
        "exploitable" => "Exploit proof completed. Fix root cause, then run post-fix replay.",
        "not_exploitable_within_bounds" => {
            "Bounded non-exploit proof completed. Keep bounds and assumptions in the evidence pack."
        }
        "proof_failed" => {
            "Proof stage failed or incomplete. Fix proof inputs/tooling and rerun detection+proof."
        }
        "proof_skipped_by_policy" => "No detection signal required proof in this run.",
        _ => match discovery_state {
            "run_failed" => {
                "Fix root cause from stage/error, rerun campaign, then re-qualify discovery outcome."
            }
            "engagement_contract_failed" => {
                "Fix engagement contract and readiness failures, then rerun strict evidence mode."
            }
            "stale_interrupted" => {
                "Inspect logs for interruption cause (OOM/SIGKILL/external stop) and rerun deterministically."
            }
            "in_progress" => "Wait for terminal status before vulnerability qualification.",
            _ => "Inspect run artifact manually and assign qualification state.",
        },
    }
}

fn analysis_input_path(output_dir: Option<&str>, rel: &str) -> Option<String> {
    output_dir.map(|root| {
        let trimmed = root.trim_end_matches('/');
        format!("{}/{}", trimmed, rel)
    })
}

pub(crate) fn standardize_run_outcome_doc(doc: &serde_json::Value) -> serde_json::Value {
    let status = doc
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let reason_code = reason_code_from_doc_or_classification(doc);
    let status_family = status_family(status);
    let terminal = is_terminal(status);
    let stage = doc
        .get("stage")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let findings_total = findings_total_from_doc(doc);
    let critical_findings = critical_findings_from_doc(doc);
    let discovery_state = discovery_state(status, findings_total, critical_findings);
    let output_dir = doc.get("output_dir").and_then(|v| v.as_str());
    let proof_stats = collect_evidence_proof_stats(output_dir);
    let proof_status = proof_status(
        &reason_code,
        stage,
        discovery_state,
        findings_total,
        proof_stats,
    );
    let analysis_priority = analysis_priority(discovery_state);

    let mut normalized = match doc.as_object() {
        Some(_) => doc.clone(),
        None => serde_json::json!({ "raw": doc }),
    };

    if let Some(obj) = normalized.as_object_mut() {
        obj.insert(
            "artifact_schema".to_string(),
            serde_json::json!({
                "name": "zkfuzz.run_outcome",
                "version": "1.0.0",
            }),
        );
        obj.insert(
            "reason_code".to_string(),
            serde_json::Value::String(reason_code),
        );
        obj.insert(
            "status_family".to_string(),
            serde_json::Value::String(status_family.to_string()),
        );
        obj.insert("terminal".to_string(), serde_json::Value::Bool(terminal));
        obj.insert(
            "discovery_qualification".to_string(),
            serde_json::json!({
                "discovery_state": discovery_state,
                "proof_status": proof_status,
                "analysis_priority": analysis_priority,
                "findings_total": findings_total,
                "critical_findings": critical_findings,
                "next_step": next_step(discovery_state, proof_status),
                "ready_for_followup": terminal,
                "triage_source": "auto_inferred",
                "proof_artifacts": {
                    "bundles_total": proof_stats.map(|stats| stats.bundles_total).unwrap_or(0),
                    "passed": proof_stats.map(|stats| stats.passed).unwrap_or(0),
                    "failed": proof_stats.map(|stats| stats.failed).unwrap_or(0),
                    "skipped": proof_stats.map(|stats| stats.skipped).unwrap_or(0),
                    "pending": proof_stats.map(|stats| stats.pending).unwrap_or(0),
                    "unknown": proof_stats.map(|stats| stats.unknown).unwrap_or(0),
                    "complete_proof_packs": proof_stats.map(|stats| stats.complete_proof_packs).unwrap_or(0),
                    "passed_with_complete_pack": proof_stats.map(|stats| stats.passed_with_complete_pack).unwrap_or(0),
                    "failed_with_complete_pack": proof_stats.map(|stats| stats.failed_with_complete_pack).unwrap_or(0),
                    "missing_required_artifacts": proof_stats.map(|stats| stats.missing_required_artifacts).unwrap_or(0),
                },
                "analysis_inputs": {
                    "run_outcome_json": analysis_input_path(output_dir, "run_outcome.json"),
                    "report_json": analysis_input_path(output_dir, "report.json"),
                    "chain_report_json": analysis_input_path(output_dir, "chain_report.json"),
                    "evidence_summary_json": analysis_input_path(output_dir, "evidence/summary.json"),
                },
            }),
        );
    }

    normalized
}

pub(crate) fn running_run_doc_with_window(ctx: RunOutcomeDocContext<'_>) -> serde_json::Value {
    let mut doc = serde_json::json!({
        "status": "running",
        "command": ctx.command,
        "run_id": ctx.run_id,
        "stage": ctx.stage,
        "pid": std::process::id(),
        "campaign_path": ctx.config_path,
        "campaign_name": ctx.campaign_name,
        "output_dir": ctx.output_dir.display().to_string(),
        "started_utc": ctx.started_utc.to_rfc3339(),
    });
    add_run_window_fields(
        &mut doc,
        ctx.started_utc.to_owned(),
        ctx.timeout_seconds,
        "wall_clock",
    );
    doc
}

pub(crate) fn completed_run_doc_with_window(
    status: &str,
    ctx: RunOutcomeDocContext<'_>,
) -> serde_json::Value {
    let ended_utc = Utc::now();
    let mut doc = serde_json::json!({
        "status": status,
        "command": ctx.command,
        "run_id": ctx.run_id,
        "stage": ctx.stage,
        "pid": std::process::id(),
        "campaign_path": ctx.config_path,
        "campaign_name": ctx.campaign_name,
        "output_dir": ctx.output_dir.display().to_string(),
        "started_utc": ctx.started_utc.to_rfc3339(),
        "ended_utc": ended_utc.to_rfc3339(),
        "duration_seconds": (ended_utc - ctx.started_utc.to_owned()).num_seconds().max(0),
    });
    add_run_window_fields(
        &mut doc,
        ctx.started_utc.to_owned(),
        ctx.timeout_seconds,
        "wall_clock",
    );
    doc
}

pub(crate) fn failed_run_doc_with_window(ctx: RunOutcomeDocContext<'_>) -> serde_json::Value {
    let ended_utc = Utc::now();
    let mut doc = serde_json::json!({
        "status": "failed",
        "command": ctx.command,
        "run_id": ctx.run_id,
        "stage": ctx.stage,
        "pid": std::process::id(),
        "campaign_path": ctx.config_path,
        "campaign_name": ctx.campaign_name,
        "output_dir": ctx.output_dir.display().to_string(),
        "started_utc": ctx.started_utc.to_rfc3339(),
        "ended_utc": ended_utc.to_rfc3339(),
        "duration_seconds": (ended_utc - ctx.started_utc.to_owned()).num_seconds().max(0),
    });
    add_run_window_fields(
        &mut doc,
        ctx.started_utc.to_owned(),
        ctx.timeout_seconds,
        "wall_clock",
    );
    doc
}
