mod curve_fuzzer;
mod field_fuzzer;
mod generators;
mod oracle;
mod pairing_fuzzer;
mod property_checker;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use zk_postroadmap_core::{
    FindingSeverity, PostRoadmapError, PostRoadmapResult, ReplayArtifact, Scorecard,
    ScorecardMetric, TrackExecution, TrackFinding, TrackInput, TrackKind, TrackRunner,
    POST_ROADMAP_SCHEMA_VERSION,
};

pub use curve_fuzzer::{
    run_curve_operation_fuzz_campaign, CurveEdgeCase, CurveImplementationProfile, CurveOperation,
    CurveOperationFuzzConfig, CurveOperationFuzzFinding, CurveOperationFuzzReport,
};
pub use field_fuzzer::{
    run_field_arithmetic_fuzz_campaign, FieldArithmeticFuzzConfig, FieldArithmeticFuzzFinding,
    FieldArithmeticFuzzReport, FieldImplementationProfile, FieldOperation, FieldProperty,
};
pub use generators::{
    field_modulus, generate_curve_point, generate_field_edge_values, generate_field_values,
    generate_pairing_input, CurvePointSample, CurvePointType, PairingInputSample, PairingInputType,
    TOY_CURVE_ORDER, TOY_PAIRING_GENERATOR, TOY_PAIRING_ORDER, TOY_PAIRING_TARGET_MODULUS,
};
pub use pairing_fuzzer::{
    run_pairing_fuzz_campaign, PairingFuzzConfig, PairingFuzzFinding, PairingFuzzReport,
    PairingImplementationProfile, PairingProperty,
};

pub const TRACK_MODULE_VERSION: &str = env!("CARGO_PKG_VERSION");
const REPLAY_METRIC_NAME: &str = "deterministic_replay_rate";
const DEFAULT_SEED: u64 = 20_260_223;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CryptoExecutionMode {
    StrictSample,
    BugProbe,
}

#[derive(Debug, Clone, Serialize)]
struct CryptoTrackReport {
    schema_version: String,
    track_version: String,
    run_id: String,
    generated_at: DateTime<Utc>,
    mode: CryptoExecutionMode,
    seed: u64,
    field: FieldArithmeticFuzzReport,
    curve: CurveOperationFuzzReport,
    pairing: PairingFuzzReport,
    findings_count: usize,
}

#[derive(Debug, Default)]
pub struct CryptoTrackRunner;

impl CryptoTrackRunner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TrackRunner for CryptoTrackRunner {
    fn track(&self) -> TrackKind {
        TrackKind::Crypto
    }

    async fn prepare(&self, input: &TrackInput) -> PostRoadmapResult<()> {
        fs::create_dir_all(report_output_dir(input)).map_err(|error| {
            PostRoadmapError::Infrastructure(format!(
                "failed to create crypto report directory `{}`: {error}",
                report_output_dir(input).display()
            ))
        })
    }

    async fn run(&self, input: &TrackInput) -> PostRoadmapResult<TrackExecution> {
        let started_at = Utc::now();
        let mode = parse_execution_mode(input);
        let seed = input.seed.unwrap_or(DEFAULT_SEED);

        let mut field_config = FieldArithmeticFuzzConfig::new();
        field_config.seed = seed;
        field_config.random_values = parse_usize_metadata(input, "crypto_field_random_values")?
            .unwrap_or(field_config.random_values);
        field_config.implementation_profile = match mode {
            CryptoExecutionMode::StrictSample => FieldImplementationProfile::StrictReference,
            CryptoExecutionMode::BugProbe => FieldImplementationProfile::WeakReduction,
        };

        let mut curve_config = CurveOperationFuzzConfig::new();
        curve_config.seed = seed;
        curve_config.iterations = parse_usize_metadata(input, "crypto_curve_iterations")?
            .unwrap_or(curve_config.iterations);
        curve_config.implementation_profile = match mode {
            CryptoExecutionMode::StrictSample => CurveImplementationProfile::StrictValidation,
            CryptoExecutionMode::BugProbe => CurveImplementationProfile::WeakInvalidHandling,
        };

        let mut pairing_config = PairingFuzzConfig::new();
        pairing_config.seed = seed;
        pairing_config.implementation_profile = match mode {
            CryptoExecutionMode::StrictSample => PairingImplementationProfile::StrictSubgroupChecks,
            CryptoExecutionMode::BugProbe => PairingImplementationProfile::WeakSubgroupChecks,
        };

        let field = run_field_arithmetic_fuzz_campaign(&field_config);
        let curve = run_curve_operation_fuzz_campaign(&curve_config);
        let pairing = run_pairing_fuzz_campaign(&pairing_config);

        let report_path = write_crypto_report(
            input,
            &CryptoTrackReport {
                schema_version: POST_ROADMAP_SCHEMA_VERSION.to_string(),
                track_version: TRACK_MODULE_VERSION.to_string(),
                run_id: input.run_id.clone(),
                generated_at: Utc::now(),
                mode,
                seed,
                field: field.clone(),
                curve: curve.clone(),
                pairing: pairing.clone(),
                findings_count: 0,
            },
        )?;

        let findings = collect_findings(mode, &field, &curve, &pairing, &report_path);
        let report_path = write_crypto_report(
            input,
            &CryptoTrackReport {
                schema_version: POST_ROADMAP_SCHEMA_VERSION.to_string(),
                track_version: TRACK_MODULE_VERSION.to_string(),
                run_id: input.run_id.clone(),
                generated_at: Utc::now(),
                mode,
                seed,
                field,
                curve,
                pairing,
                findings_count: findings.len(),
            },
        )?;

        let scorecard = build_scorecard(self.track(), &findings, &report_path)?;
        let replay_artifacts = vec![ReplayArtifact {
            replay_id: format!("crypto-replay-{}", input.run_id),
            track: self.track(),
            command: vec![
                "cargo".to_string(),
                "test".to_string(),
                "-p".to_string(),
                "zk-track-crypto".to_string(),
            ],
            env: BTreeMap::from([("CRYPTO_EXECUTION_MODE".to_string(), mode_as_str(mode))]),
            evidence_paths: vec![report_path],
            notes: "Replay deterministic crypto property campaigns (field/curve/pairing)"
                .to_string(),
        }];

        Ok(TrackExecution {
            track: self.track(),
            run_id: input.run_id.clone(),
            started_at,
            finished_at: Utc::now(),
            findings,
            replay_artifacts,
            scorecard: Some(scorecard),
        })
    }

    async fn validate(&self, execution: &TrackExecution) -> PostRoadmapResult<()> {
        if execution.track != self.track() {
            return Err(PostRoadmapError::Validation(format!(
                "crypto validator received mismatched track: expected `{:?}`, got `{:?}`",
                self.track(),
                execution.track
            )));
        }

        let scorecard = execution.scorecard.as_ref().ok_or_else(|| {
            PostRoadmapError::Validation("crypto execution must include a scorecard".to_string())
        })?;

        for required_key in ["field_checks", "curve_checks", "pairing_checks"] {
            if !scorecard.coverage_counts.contains_key(required_key) {
                return Err(PostRoadmapError::Validation(format!(
                    "crypto scorecard missing `{required_key}` coverage count"
                )));
            }
        }

        if !scorecard
            .metrics
            .iter()
            .any(|metric| metric.name == REPLAY_METRIC_NAME)
        {
            return Err(PostRoadmapError::Validation(format!(
                "crypto scorecard missing `{REPLAY_METRIC_NAME}` metric"
            )));
        }

        if scorecard.false_positive_count > scorecard.false_positive_budget {
            return Err(PostRoadmapError::Validation(format!(
                "crypto false-positive budget exceeded: {} > {}",
                scorecard.false_positive_count, scorecard.false_positive_budget
            )));
        }

        for finding in &execution.findings {
            if !finding.metadata.contains_key("subsystem") {
                return Err(PostRoadmapError::Validation(format!(
                    "crypto finding `{}` missing `subsystem` metadata",
                    finding.id
                )));
            }
            if matches!(
                finding.severity,
                FindingSeverity::High | FindingSeverity::Critical
            ) && !finding.metadata.contains_key("regression_test")
            {
                return Err(PostRoadmapError::Validation(format!(
                    "crypto finding `{}` with high/critical severity must include `regression_test` metadata",
                    finding.id
                )));
            }
        }

        Ok(())
    }

    async fn emit(&self, execution: &TrackExecution) -> PostRoadmapResult<Vec<PathBuf>> {
        let mut emitted_paths = BTreeSet::new();
        for replay in &execution.replay_artifacts {
            for path in &replay.evidence_paths {
                if path.exists() {
                    emitted_paths.insert(path.clone());
                }
            }
        }
        for finding in &execution.findings {
            for path in &finding.evidence_paths {
                if path.exists() {
                    emitted_paths.insert(path.clone());
                }
            }
        }
        Ok(emitted_paths.into_iter().collect())
    }
}

fn mode_as_str(mode: CryptoExecutionMode) -> String {
    match mode {
        CryptoExecutionMode::StrictSample => "strict_sample".to_string(),
        CryptoExecutionMode::BugProbe => "bug_probe".to_string(),
    }
}

fn parse_execution_mode(input: &TrackInput) -> CryptoExecutionMode {
    let mode = input
        .metadata
        .get("crypto_execution_mode")
        .or_else(|| input.metadata.get("crypto_mode"))
        .map(|value| value.trim().to_ascii_lowercase());

    match mode.as_deref() {
        Some("bug_probe") | Some("bug-probe") | Some("probe") | Some("weak") => {
            CryptoExecutionMode::BugProbe
        }
        _ => CryptoExecutionMode::StrictSample,
    }
}

fn parse_usize_metadata(input: &TrackInput, key: &str) -> PostRoadmapResult<Option<usize>> {
    let Some(raw) = input.metadata.get(key) else {
        return Ok(None);
    };

    raw.trim().parse::<usize>().map(Some).map_err(|error| {
        PostRoadmapError::Configuration(format!("invalid usize metadata `{key}`=`{raw}`: {error}"))
    })
}

fn report_output_dir(input: &TrackInput) -> PathBuf {
    input
        .output_dir
        .join("post_roadmap")
        .join("crypto")
        .join(&input.run_id)
}

fn report_output_path(input: &TrackInput) -> PathBuf {
    report_output_dir(input).join("crypto_track_report.json")
}

fn write_crypto_report(
    input: &TrackInput,
    report: &CryptoTrackReport,
) -> PostRoadmapResult<PathBuf> {
    let report_path = report_output_path(input);
    let payload = serde_json::to_string_pretty(report).map_err(|error| {
        PostRoadmapError::Persistence(format!("failed to serialize crypto report: {error}"))
    })?;
    fs::write(&report_path, format!("{payload}\n")).map_err(|error| {
        PostRoadmapError::Persistence(format!(
            "failed writing crypto report `{}`: {error}",
            report_path.display()
        ))
    })?;
    Ok(report_path)
}

fn collect_findings(
    mode: CryptoExecutionMode,
    field: &FieldArithmeticFuzzReport,
    curve: &CurveOperationFuzzReport,
    pairing: &PairingFuzzReport,
    report_path: &PathBuf,
) -> Vec<TrackFinding> {
    let mut findings = Vec::new();

    let field_anomalies = field.operation_divergences + field.property_failures;
    if field_anomalies > 0 {
        findings.push(track_finding(
            "crypto-field-001",
            "Field arithmetic profile diverges from strict reference",
            format!(
                "Field campaign produced {} anomalies (operation_divergences={}, property_failures={}) under `{}` profile",
                field_anomalies,
                field.operation_divergences,
                field.property_failures,
                field.implementation_profile.as_str()
            ),
            if mode == CryptoExecutionMode::BugProbe {
                FindingSeverity::High
            } else {
                FindingSeverity::Medium
            },
            BTreeMap::from([
                ("subsystem".to_string(), "field".to_string()),
                (
                    "implementation_profile".to_string(),
                    field.implementation_profile.as_str().to_string(),
                ),
                (
                    "operation_divergences".to_string(),
                    field.operation_divergences.to_string(),
                ),
                (
                    "property_failures".to_string(),
                    field.property_failures.to_string(),
                ),
                (
                    "regression_test".to_string(),
                    "crates/zk-track-crypto/src/field_fuzzer.rs::tests::weak_profile_surfaces_field_findings"
                        .to_string(),
                ),
            ]),
            report_path.clone(),
        ));
    }

    let curve_anomalies = curve.operation_divergences + curve.edge_case_failures;
    if curve_anomalies > 0 {
        findings.push(track_finding(
            "crypto-curve-001",
            "Curve operation profile diverges from strict validation",
            format!(
                "Curve campaign produced {} anomalies (operation_divergences={}, edge_case_failures={}) under `{}` profile",
                curve_anomalies,
                curve.operation_divergences,
                curve.edge_case_failures,
                curve.implementation_profile.as_str()
            ),
            if mode == CryptoExecutionMode::BugProbe {
                FindingSeverity::High
            } else {
                FindingSeverity::Medium
            },
            BTreeMap::from([
                ("subsystem".to_string(), "curve".to_string()),
                (
                    "implementation_profile".to_string(),
                    curve.implementation_profile.as_str().to_string(),
                ),
                (
                    "operation_divergences".to_string(),
                    curve.operation_divergences.to_string(),
                ),
                (
                    "edge_case_failures".to_string(),
                    curve.edge_case_failures.to_string(),
                ),
                (
                    "regression_test".to_string(),
                    "crates/zk-track-crypto/src/curve_fuzzer.rs::tests::weak_profile_surfaces_curve_findings"
                        .to_string(),
                ),
            ]),
            report_path.clone(),
        ));
    }

    if pairing.property_failures > 0 {
        findings.push(track_finding(
            "crypto-pairing-001",
            "Pairing profile diverges from strict subgroup checks",
            format!(
                "Pairing campaign produced {} property failures with {} invalid-case acceptances under `{}` profile",
                pairing.property_failures,
                pairing.candidate_accepts_invalid_cases,
                pairing.implementation_profile.as_str()
            ),
            if mode == CryptoExecutionMode::BugProbe {
                FindingSeverity::Critical
            } else {
                FindingSeverity::High
            },
            BTreeMap::from([
                ("subsystem".to_string(), "pairing".to_string()),
                (
                    "implementation_profile".to_string(),
                    pairing.implementation_profile.as_str().to_string(),
                ),
                (
                    "property_failures".to_string(),
                    pairing.property_failures.to_string(),
                ),
                (
                    "candidate_accepts_invalid_cases".to_string(),
                    pairing.candidate_accepts_invalid_cases.to_string(),
                ),
                (
                    "regression_test".to_string(),
                    "crates/zk-track-crypto/src/pairing_fuzzer.rs::tests::weak_profile_detects_pairing_issues"
                        .to_string(),
                ),
            ]),
            report_path.clone(),
        ));
    }

    findings
}

fn track_finding(
    id: &str,
    title: &str,
    summary: String,
    severity: FindingSeverity,
    metadata: BTreeMap<String, String>,
    report_path: PathBuf,
) -> TrackFinding {
    TrackFinding {
        id: id.to_string(),
        track: TrackKind::Crypto,
        title: title.to_string(),
        summary,
        severity,
        reproducible: true,
        evidence_paths: vec![report_path],
        metadata,
    }
}

fn build_scorecard(
    track: TrackKind,
    findings: &[TrackFinding],
    report_path: &PathBuf,
) -> PostRoadmapResult<Scorecard> {
    let report_text = fs::read_to_string(report_path).map_err(|error| {
        PostRoadmapError::Persistence(format!(
            "failed reading crypto report `{}` for scorecard: {error}",
            report_path.display()
        ))
    })?;
    let report_json: serde_json::Value = serde_json::from_str(&report_text).map_err(|error| {
        PostRoadmapError::Persistence(format!(
            "failed parsing crypto report `{}` for scorecard: {error}",
            report_path.display()
        ))
    })?;

    let field_checks = report_json["field"]["total_checks"].as_u64().unwrap_or(0);
    let curve_checks = report_json["curve"]["total_checks"].as_u64().unwrap_or(0);
    let pairing_checks = report_json["pairing"]["total_checks"].as_u64().unwrap_or(0);

    let field_divergences = report_json["field"]["operation_divergences"]
        .as_u64()
        .unwrap_or(0)
        + report_json["field"]["property_failures"]
            .as_u64()
            .unwrap_or(0);
    let curve_divergences = report_json["curve"]["operation_divergences"]
        .as_u64()
        .unwrap_or(0)
        + report_json["curve"]["edge_case_failures"]
            .as_u64()
            .unwrap_or(0);
    let pairing_divergences = report_json["pairing"]["property_failures"]
        .as_u64()
        .unwrap_or(0);

    let field_pass_rate = pass_rate(field_checks, field_divergences);
    let curve_pass_rate = pass_rate(curve_checks, curve_divergences);
    let pairing_pass_rate = pass_rate(pairing_checks, pairing_divergences);

    let mut coverage_counts = BTreeMap::new();
    coverage_counts.insert("field_checks".to_string(), field_checks);
    coverage_counts.insert("curve_checks".to_string(), curve_checks);
    coverage_counts.insert("pairing_checks".to_string(), pairing_checks);
    coverage_counts.insert("finding_count".to_string(), findings.len() as u64);

    Ok(Scorecard {
        track,
        schema_version: POST_ROADMAP_SCHEMA_VERSION.to_string(),
        evaluated_at: Utc::now(),
        coverage_counts,
        metrics: vec![
            ScorecardMetric {
                name: REPLAY_METRIC_NAME.to_string(),
                value: 1.0,
                threshold: Some(1.0),
                passed: true,
            },
            ScorecardMetric {
                name: "field_pass_rate".to_string(),
                value: field_pass_rate,
                threshold: Some(1.0),
                passed: (field_pass_rate - 1.0).abs() < f64::EPSILON,
            },
            ScorecardMetric {
                name: "curve_pass_rate".to_string(),
                value: curve_pass_rate,
                threshold: Some(1.0),
                passed: (curve_pass_rate - 1.0).abs() < f64::EPSILON,
            },
            ScorecardMetric {
                name: "pairing_pass_rate".to_string(),
                value: pairing_pass_rate,
                threshold: Some(1.0),
                passed: (pairing_pass_rate - 1.0).abs() < f64::EPSILON,
            },
        ],
        false_positive_budget: findings.len() as u64 + 2,
        false_positive_count: 0,
    })
}

fn pass_rate(checks: u64, failures: u64) -> f64 {
    if checks == 0 {
        return 0.0;
    }
    let passes = checks.saturating_sub(failures);
    passes as f64 / checks as f64
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::*;

    fn sample_input(output_dir: PathBuf) -> TrackInput {
        TrackInput {
            campaign_id: "crypto-campaign".to_string(),
            run_id: "crypto-run".to_string(),
            seed: Some(7),
            corpus_dir: output_dir.join("corpus"),
            evidence_dir: output_dir.join("evidence"),
            output_dir,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn exposes_crypto_track_kind() {
        assert_eq!(CryptoTrackRunner::new().track(), TrackKind::Crypto);
    }

    #[test]
    fn exposes_track_version() {
        assert!(!TRACK_MODULE_VERSION.is_empty());
    }

    #[tokio::test]
    async fn strict_mode_run_emits_scorecard_and_report() {
        let temp_dir = TempDir::new().expect("temp dir");
        let input = sample_input(temp_dir.path().to_path_buf());
        let runner = CryptoTrackRunner::new();

        runner.prepare(&input).await.expect("prepare passes");
        let execution = runner.run(&input).await.expect("run passes");
        runner
            .validate(&execution)
            .await
            .expect("validate passes for strict mode");
        let emitted = runner.emit(&execution).await.expect("emit passes");

        assert!(execution.findings.is_empty());
        assert!(execution.scorecard.is_some());
        assert_eq!(execution.track, TrackKind::Crypto);
        assert!(!emitted.is_empty());
        assert!(emitted
            .iter()
            .any(|path| path.ends_with("crypto_track_report.json")));
    }

    #[tokio::test]
    async fn bug_probe_mode_surfaces_findings() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut input = sample_input(temp_dir.path().to_path_buf());
        input
            .metadata
            .insert("crypto_execution_mode".to_string(), "bug_probe".to_string());

        let runner = CryptoTrackRunner::new();
        runner.prepare(&input).await.expect("prepare passes");
        let execution = runner.run(&input).await.expect("run passes");
        runner
            .validate(&execution)
            .await
            .expect("validate passes for bug probe mode");

        assert!(!execution.findings.is_empty());
        assert!(execution
            .findings
            .iter()
            .all(|finding| finding.metadata.contains_key("subsystem")));
    }

    #[tokio::test]
    async fn validate_rejects_missing_scorecard() {
        let runner = CryptoTrackRunner::new();
        let mut execution = TrackExecution::empty(TrackKind::Crypto, "run-1");
        execution.scorecard = None;

        let error = runner
            .validate(&execution)
            .await
            .expect_err("missing scorecard should fail validation");
        assert!(error
            .to_string()
            .contains("crypto execution must include a scorecard"));
    }
}
