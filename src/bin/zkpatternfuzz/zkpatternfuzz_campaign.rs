use anyhow::Context;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use super::{
    high_confidence_min_oracles_from_env, proof_status_from_run_outcome_doc, scan_output_suffix,
    Family, TemplateInfo, TemplateOutcomeReason, PROOF_STAGE_NOT_STARTED_REASON_CODE,
};

fn report_has_high_confidence_finding(report_path: &Path) -> bool {
    report_has_high_confidence_finding_with_min_oracles(
        report_path,
        high_confidence_min_oracles_from_env(),
    )
}

fn report_detected_pattern_count(report_path: &Path) -> usize {
    let raw = match fs::read_to_string(report_path) {
        Ok(raw) => raw,
        Err(_) => return 0,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(_) => return 0,
    };
    parsed
        .get("findings")
        .and_then(|v| v.as_array())
        .map(|entries| entries.len())
        .unwrap_or(0)
}

pub(super) fn parse_correlation_confidence(description: &str) -> Option<String> {
    let marker = "correlation:";
    let description_lc = description.to_ascii_lowercase();
    let start = description_lc.find(marker)?;
    let tail = description_lc.get(start + marker.len()..)?.trim_start();
    let token = tail
        .split_whitespace()
        .next()?
        .trim_matches(|ch: char| ch == '(' || ch == ')' || ch == ',' || ch == ';' || ch == '.');
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

pub(super) fn parse_correlation_oracle_count(description: &str) -> Option<usize> {
    let marker = "oracles=";
    let start = description.find(marker)?;
    let tail = description.get(start + marker.len()..)?;
    let digits: String = tail.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<usize>().ok()
}

fn report_has_high_confidence_finding_with_min_oracles(
    report_path: &Path,
    min_oracles: usize,
) -> bool {
    let raw = match fs::read_to_string(report_path) {
        Ok(raw) => raw,
        Err(_) => return false,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    let Some(findings) = parsed.get("findings").and_then(|v| v.as_array()) else {
        return false;
    };
    findings.iter().any(|finding| {
        let description = finding
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let Some(confidence) = parse_correlation_confidence(description) else {
            return false;
        };
        if confidence == "critical" {
            return true;
        }
        if confidence != "high" {
            return false;
        }
        match parse_correlation_oracle_count(description) {
            Some(oracles) => oracles >= min_oracles,
            None => true,
        }
    })
}

pub(super) fn list_scan_run_roots(artifacts_root: &Path) -> anyhow::Result<BTreeSet<String>> {
    if !artifacts_root.exists() {
        return Ok(BTreeSet::new());
    }

    let mut roots = BTreeSet::new();
    for entry in fs::read_dir(artifacts_root).with_context(|| {
        format!(
            "Failed to read artifacts root '{}'",
            artifacts_root.display()
        )
    })? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("scan_run") {
            continue;
        }
        if entry.file_type()?.is_dir() {
            roots.insert(name.to_string());
        }
    }

    Ok(roots)
}

pub(super) fn collect_observed_suffixes_for_roots(
    artifacts_root: &Path,
    run_roots: &BTreeSet<String>,
) -> anyhow::Result<BTreeSet<String>> {
    let mut observed = BTreeSet::new();
    for run_root in run_roots {
        let run_root_path = artifacts_root.join(run_root);
        if !run_root_path.exists() {
            continue;
        }
        for entry in fs::read_dir(&run_root_path).with_context(|| {
            format!(
                "Failed to read run artifact root '{}'",
                run_root_path.display()
            )
        })? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            observed.insert(name.to_string());
        }
    }
    Ok(observed)
}

pub(super) fn classify_run_reason_code(doc: &serde_json::Value) -> &'static str {
    let Some(obj) = doc.as_object() else {
        return "invalid_run_outcome_json";
    };
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
        return "critical_findings_detected";
    }
    if status == "completed" {
        return "completed";
    }
    if status == "failed_engagement_contract" {
        return "engagement_contract_failed";
    }
    if status == "stale_interrupted" {
        return "stale_interrupted";
    }
    if status == "panic" {
        if panic_message_lc.contains("missing required 'command' in run document") {
            return "artifact_mirror_panic_missing_command";
        }
        return "panic";
    }
    if status == "running" {
        return "running";
    }
    if error_lc.contains("permission denied") {
        return "filesystem_permission_denied";
    }
    if stage == "preflight_backend"
        && (error_lc.contains("backend required but not available")
            || error_lc.contains("not found in path")
            || error_lc.contains("snarkjs not found")
            || error_lc.contains("circom not found")
            || error_lc.contains("install circom"))
    {
        return "backend_tooling_missing";
    }
    if stage == "preflight_backend" && is_dependency_resolution_failure(&error_lc) {
        return "backend_dependency_resolution_failed";
    }
    if stage == "preflight_backend" && is_backend_toolchain_mismatch(&error_lc) {
        return "backend_toolchain_mismatch";
    }
    if is_circom_compilation_failure(&error_lc) {
        return "circom_compilation_failed";
    }
    if error_lc.contains("key generation failed")
        || error_lc.contains("key setup failed")
        || error_lc.contains("proving key")
    {
        return "key_generation_failed";
    }
    if error_lc.contains("wall-clock timeout") || reason_lc.contains("wall-clock timeout") {
        return "wall_clock_timeout";
    }
    if stage == "acquire_output_lock" {
        return "output_dir_locked";
    }
    if is_input_contract_mismatch(&error_lc) {
        return "backend_input_contract_mismatch";
    }
    if stage == "preflight_backend" {
        return "backend_preflight_failed";
    }
    if stage == "preflight_selector" {
        return "selector_mismatch";
    }
    if stage == "preflight_invariants" {
        return "missing_invariants";
    }
    if stage == "preflight_readiness" {
        return "readiness_failed";
    }
    if stage == "parse_chains" && reason_lc.contains("requires chains") {
        return "missing_chains_definition";
    }
    if status == "failed" {
        return "runtime_error";
    }

    "unknown"
}

pub(super) fn collect_template_outcome_reasons(
    artifacts_root: &Path,
    run_root: Option<&str>,
    selected_with_family: &[(TemplateInfo, Family)],
) -> Vec<TemplateOutcomeReason> {
    let Some(run_root) = run_root else {
        return Vec::new();
    };

    selected_with_family
        .iter()
        .map(|(template, family)| {
            let suffix = scan_output_suffix(template, *family);
            let run_outcome_path = artifacts_root
                .join(run_root)
                .join(&suffix)
                .join("run_outcome.json");

            if !run_outcome_path.exists() {
                return TemplateOutcomeReason {
                    template_file: template.file_name.clone(),
                    template_path: template.path.display().to_string(),
                    suffix,
                    status: None,
                    stage: None,
                    proof_status: None,
                    reason_code: "run_outcome_missing".to_string(),
                    high_confidence_detected: false,
                    detected_pattern_count: 0,
                };
            }

            let raw = match fs::read_to_string(&run_outcome_path) {
                Ok(raw) => raw,
                Err(_) => {
                    return TemplateOutcomeReason {
                        template_file: template.file_name.clone(),
                        template_path: template.path.display().to_string(),
                        suffix,
                        status: None,
                        stage: None,
                        proof_status: None,
                        reason_code: "run_outcome_unreadable".to_string(),
                        high_confidence_detected: false,
                        detected_pattern_count: 0,
                    };
                }
            };

            let parsed: serde_json::Value = match serde_json::from_str(&raw) {
                Ok(parsed) => parsed,
                Err(_) => {
                    return TemplateOutcomeReason {
                        template_file: template.file_name.clone(),
                        template_path: template.path.display().to_string(),
                        suffix,
                        status: None,
                        stage: None,
                        proof_status: None,
                        reason_code: "run_outcome_invalid_json".to_string(),
                        high_confidence_detected: false,
                        detected_pattern_count: 0,
                    };
                }
            };

            let status = parsed
                .get("status")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let stage = parsed
                .get("stage")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let report_path = artifacts_root
                .join(run_root)
                .join(&suffix)
                .join("report.json");

            let mut reason = TemplateOutcomeReason {
                template_file: template.file_name.clone(),
                template_path: template.path.display().to_string(),
                suffix,
                status,
                stage,
                proof_status: proof_status_from_run_outcome_doc(&parsed),
                reason_code: parsed
                    .get("reason_code")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| classify_run_reason_code(&parsed).to_string()),
                high_confidence_detected: report_has_high_confidence_finding(&report_path),
                detected_pattern_count: report_detected_pattern_count(&report_path),
            };
            enforce_detected_pattern_proof_contract(&mut reason);
            reason
        })
        .collect()
}

fn proof_stage_started_for_status(proof_status: Option<&str>) -> bool {
    matches!(
        proof_status,
        Some("exploitable" | "not_exploitable_within_bounds" | "proof_failed")
    )
}

fn enforce_detected_pattern_proof_contract(reason: &mut TemplateOutcomeReason) {
    if reason.detected_pattern_count == 0
        || proof_stage_started_for_status(reason.proof_status.as_deref())
    {
        return;
    }
    reason.proof_status = Some("proof_failed".to_string());
    if matches!(
        reason.reason_code.as_str(),
        "completed" | "critical_findings_detected"
    ) {
        reason.reason_code = PROOF_STAGE_NOT_STARTED_REASON_CODE.to_string();
    }
}

pub(super) fn print_reason_summary(reasons: &[TemplateOutcomeReason]) {
    if reasons.is_empty() {
        return;
    }

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for reason in reasons {
        *counts.entry(reason.reason_code.clone()).or_insert(0) += 1;
    }

    let summary_line = counts
        .iter()
        .map(|(code, count)| format!("{}={}", code, count))
        .collect::<Vec<_>>()
        .join(", ");

    println!("Reason code summary: {}", summary_line);

    for reason in reasons {
        if (reason.reason_code == "completed" || reason.reason_code == "critical_findings_detected")
            && reason.proof_status.as_deref() != Some("proof_failed")
        {
            continue;
        }
        println!(
            "  - {} [{}]: reason_code={} status={} stage={} proof_status={}",
            reason.template_file,
            reason.suffix,
            reason.reason_code,
            reason.status.as_deref().unwrap_or("unknown"),
            reason.stage.as_deref().unwrap_or("unknown"),
            reason.proof_status.as_deref().unwrap_or("unknown"),
        );
    }
}
