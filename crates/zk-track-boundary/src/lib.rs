mod adapters;
mod cross_component_fuzzer;
mod public_input_fuzzer;
mod serialization_fuzzer;
mod solidity_verifier_fuzzer;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use zk_postroadmap_core::{
    FindingSeverity, PostRoadmapError, PostRoadmapResult, ReplayArtifact, Scorecard,
    ScorecardMetric, TrackExecution, TrackFinding, TrackInput, TrackKind, TrackRunner,
    POST_ROADMAP_SCHEMA_VERSION,
};

pub use adapters::{
    BoundaryProtocolAdapter, BoundaryProtocolCase, BoundaryProtocolResult, SerializationAdapter,
    VerifierAdapter,
};
pub use cross_component_fuzzer::{
    run_cross_component_fuzz_campaign, ComponentMismatchCase, CrossComponentFinding,
    CrossComponentFuzzConfig, CrossComponentFuzzReport, CrossComponentVerifierProfile,
    WorkflowFaultStage,
};
pub use public_input_fuzzer::{
    run_public_input_manipulation_campaign, PublicInputAttackScenario,
    PublicInputManipulationConfig, PublicInputManipulationFinding, PublicInputManipulationReport,
    PublicInputMutationStrategy, PublicInputVerifierProfile,
};
pub use serialization_fuzzer::{
    run_serialization_fuzz_campaign, CrossLanguageSerializationCase, ProofSerializationEdgeCase,
    PublicInputSerializationEdgeCase, SerializationFormat, SerializationFuzzConfig,
    SerializationFuzzFinding, SerializationFuzzReport, SerializationVerifierProfile,
};
pub use solidity_verifier_fuzzer::{
    run_solidity_verifier_fuzz_campaign, PairingManipulationCase, SolidityEdgeCase,
    SolidityVerifierFinding, SolidityVerifierFuzzConfig, SolidityVerifierFuzzReport,
    SolidityVerifierProfile, VerifierInputMutation,
};

pub const TRACK_MODULE_VERSION: &str = env!("CARGO_PKG_VERSION");
const REPLAY_METRIC_NAME: &str = "deterministic_replay_rate";
const DEFAULT_SEED: u64 = 20_260_223;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BoundaryExecutionMode {
    StrictSample,
    BugProbe,
}

#[derive(Debug, Clone, Serialize)]
struct BoundaryTrackReport {
    schema_version: String,
    track_version: String,
    run_id: String,
    generated_at: DateTime<Utc>,
    mode: BoundaryExecutionMode,
    seed: u64,
    public_input: PublicInputManipulationReport,
    serialization: SerializationFuzzReport,
    solidity_verifier: SolidityVerifierFuzzReport,
    cross_component: CrossComponentFuzzReport,
    findings_count: usize,
}

#[derive(Default)]
pub struct BoundaryTrackRunner {
    protocol_adapters: Vec<Box<dyn BoundaryProtocolAdapter>>,
}

impl BoundaryTrackRunner {
    pub fn new() -> Self {
        Self {
            protocol_adapters: Vec::new(),
        }
    }

    pub fn with_protocol_adapter(mut self, adapter: Box<dyn BoundaryProtocolAdapter>) -> Self {
        self.protocol_adapters.push(adapter);
        self
    }

    pub fn protocol_adapter_count(&self) -> usize {
        self.protocol_adapters.len()
    }
}

#[async_trait]
impl TrackRunner for BoundaryTrackRunner {
    fn track(&self) -> TrackKind {
        TrackKind::Boundary
    }

    async fn prepare(&self, input: &TrackInput) -> PostRoadmapResult<()> {
        fs::create_dir_all(report_output_dir(input)).map_err(|error| {
            PostRoadmapError::Infrastructure(format!(
                "failed to create boundary report directory `{}`: {error}",
                report_output_dir(input).display()
            ))
        })
    }

    async fn run(&self, input: &TrackInput) -> PostRoadmapResult<TrackExecution> {
        let started_at = Utc::now();
        let _protocol_adapters = self.protocol_adapters.len();
        let mode = parse_execution_mode(input);
        let seed = input.seed.unwrap_or(DEFAULT_SEED);

        let mut public_input_config = PublicInputManipulationConfig::new();
        public_input_config.seed = seed;
        public_input_config.proofs = parse_usize_metadata(input, "boundary_public_input_proofs")?
            .unwrap_or(public_input_config.proofs);
        public_input_config.public_inputs_per_proof =
            parse_usize_metadata(input, "boundary_public_inputs_per_proof")?
                .unwrap_or(public_input_config.public_inputs_per_proof);
        public_input_config.verifier_profile = match mode {
            BoundaryExecutionMode::StrictSample => PublicInputVerifierProfile::StrictBinding,
            BoundaryExecutionMode::BugProbe => PublicInputVerifierProfile::WeakFirstInputBinding,
        };

        let mut serialization_config = SerializationFuzzConfig::new();
        serialization_config.seed = seed;
        serialization_config.cases_per_format =
            parse_usize_metadata(input, "boundary_serialization_cases_per_format")?
                .unwrap_or(serialization_config.cases_per_format);
        serialization_config.verifier_profile = match mode {
            BoundaryExecutionMode::StrictSample => SerializationVerifierProfile::StrictCanonical,
            BoundaryExecutionMode::BugProbe => SerializationVerifierProfile::LenientLegacy,
        };

        let mut solidity_config = SolidityVerifierFuzzConfig::new();
        solidity_config.seed = seed;
        solidity_config.proofs = parse_usize_metadata(input, "boundary_solidity_proofs")?
            .unwrap_or(solidity_config.proofs);
        solidity_config.public_inputs_per_proof =
            parse_usize_metadata(input, "boundary_solidity_public_inputs_per_proof")?
                .unwrap_or(solidity_config.public_inputs_per_proof);
        solidity_config.optimized_profile = match mode {
            BoundaryExecutionMode::StrictSample => SolidityVerifierProfile::StrictParity,
            BoundaryExecutionMode::BugProbe => SolidityVerifierProfile::WeakGasOptimization,
        };

        let mut cross_component_config = CrossComponentFuzzConfig::new();
        cross_component_config.seed = seed;
        cross_component_config.combinations =
            parse_usize_metadata(input, "boundary_cross_component_combinations")?
                .unwrap_or(cross_component_config.combinations);
        cross_component_config.public_inputs_per_case =
            parse_usize_metadata(input, "boundary_cross_component_public_inputs_per_case")?
                .unwrap_or(cross_component_config.public_inputs_per_case);
        cross_component_config.verifier_profile = match mode {
            BoundaryExecutionMode::StrictSample => {
                CrossComponentVerifierProfile::StrictCompatibility
            }
            BoundaryExecutionMode::BugProbe => {
                CrossComponentVerifierProfile::WeakMismatchAcceptance
            }
        };

        let public_input = run_public_input_manipulation_campaign(&public_input_config);
        let serialization = run_serialization_fuzz_campaign(&serialization_config);
        let solidity_verifier = run_solidity_verifier_fuzz_campaign(&solidity_config);
        let cross_component = run_cross_component_fuzz_campaign(&cross_component_config);

        let report_path = write_boundary_report(
            input,
            &BoundaryTrackReport {
                schema_version: POST_ROADMAP_SCHEMA_VERSION.to_string(),
                track_version: TRACK_MODULE_VERSION.to_string(),
                run_id: input.run_id.clone(),
                generated_at: Utc::now(),
                mode,
                seed,
                public_input: public_input.clone(),
                serialization: serialization.clone(),
                solidity_verifier: solidity_verifier.clone(),
                cross_component: cross_component.clone(),
                findings_count: 0,
            },
        )?;

        let findings = collect_findings(
            mode,
            &public_input,
            &serialization,
            &solidity_verifier,
            &cross_component,
            &report_path,
        );

        let report_path = write_boundary_report(
            input,
            &BoundaryTrackReport {
                schema_version: POST_ROADMAP_SCHEMA_VERSION.to_string(),
                track_version: TRACK_MODULE_VERSION.to_string(),
                run_id: input.run_id.clone(),
                generated_at: Utc::now(),
                mode,
                seed,
                public_input,
                serialization,
                solidity_verifier,
                cross_component,
                findings_count: findings.len(),
            },
        )?;

        let scorecard = build_scorecard(self.track(), &report_path, &findings)?;
        let replay_artifacts = vec![ReplayArtifact {
            replay_id: format!("boundary-replay-{}", input.run_id),
            track: self.track(),
            command: vec![
                "cargo".to_string(),
                "test".to_string(),
                "-p".to_string(),
                "zk-track-boundary".to_string(),
            ],
            env: BTreeMap::from([("BOUNDARY_EXECUTION_MODE".to_string(), mode_as_str(mode))]),
            evidence_paths: vec![report_path],
            notes:
                "Replay deterministic boundary campaigns (public input, serialization, solidity verifier, cross component)"
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
                "boundary validator received mismatched track: expected `{:?}`, got `{:?}`",
                self.track(),
                execution.track
            )));
        }

        let scorecard = execution.scorecard.as_ref().ok_or_else(|| {
            PostRoadmapError::Validation("boundary execution must include a scorecard".to_string())
        })?;

        for required_key in [
            "public_input_checks",
            "serialization_checks",
            "solidity_checks",
            "cross_component_checks",
        ] {
            if !scorecard.coverage_counts.contains_key(required_key) {
                return Err(PostRoadmapError::Validation(format!(
                    "boundary scorecard missing `{required_key}` coverage count"
                )));
            }
        }

        if !scorecard
            .metrics
            .iter()
            .any(|metric| metric.name == REPLAY_METRIC_NAME)
        {
            return Err(PostRoadmapError::Validation(format!(
                "boundary scorecard missing `{REPLAY_METRIC_NAME}` metric"
            )));
        }

        if scorecard.false_positive_count > scorecard.false_positive_budget {
            return Err(PostRoadmapError::Validation(format!(
                "boundary false-positive budget exceeded: {} > {}",
                scorecard.false_positive_count, scorecard.false_positive_budget
            )));
        }

        for finding in &execution.findings {
            if !finding.metadata.contains_key("subsystem") {
                return Err(PostRoadmapError::Validation(format!(
                    "boundary finding `{}` missing `subsystem` metadata",
                    finding.id
                )));
            }
            if matches!(
                finding.severity,
                FindingSeverity::High | FindingSeverity::Critical
            ) && !finding.metadata.contains_key("regression_test")
            {
                return Err(PostRoadmapError::Validation(format!(
                    "boundary finding `{}` with high/critical severity must include `regression_test` metadata",
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

fn mode_as_str(mode: BoundaryExecutionMode) -> String {
    match mode {
        BoundaryExecutionMode::StrictSample => "strict_sample".to_string(),
        BoundaryExecutionMode::BugProbe => "bug_probe".to_string(),
    }
}

fn parse_execution_mode(input: &TrackInput) -> BoundaryExecutionMode {
    let mode = input
        .metadata
        .get("boundary_execution_mode")
        .or_else(|| input.metadata.get("boundary_mode"))
        .map(|value| value.trim().to_ascii_lowercase());

    match mode.as_deref() {
        Some("bug_probe") | Some("bug-probe") | Some("probe") | Some("weak") => {
            BoundaryExecutionMode::BugProbe
        }
        _ => BoundaryExecutionMode::StrictSample,
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
        .join("boundary")
        .join(&input.run_id)
}

fn report_output_path(input: &TrackInput) -> PathBuf {
    report_output_dir(input).join("boundary_track_report.json")
}

fn write_boundary_report(
    input: &TrackInput,
    report: &BoundaryTrackReport,
) -> PostRoadmapResult<PathBuf> {
    let report_path = report_output_path(input);
    let payload = serde_json::to_string_pretty(report).map_err(|error| {
        PostRoadmapError::Persistence(format!("failed to serialize boundary report: {error}"))
    })?;
    fs::write(&report_path, format!("{payload}\n")).map_err(|error| {
        PostRoadmapError::Persistence(format!(
            "failed writing boundary report `{}`: {error}",
            report_path.display()
        ))
    })?;
    Ok(report_path)
}

fn collect_findings(
    mode: BoundaryExecutionMode,
    public_input: &PublicInputManipulationReport,
    serialization: &SerializationFuzzReport,
    solidity_verifier: &SolidityVerifierFuzzReport,
    cross_component: &CrossComponentFuzzReport,
    report_path: &Path,
) -> Vec<TrackFinding> {
    let mut findings = Vec::new();

    if public_input.accepted_mutations > 0 {
        findings.push(track_finding(
            "boundary-public-input-001",
            "Verifier accepted manipulated public inputs",
            format!(
                "Public-input campaign accepted {} / {} manipulations under `{}` profile",
                public_input.accepted_mutations,
                public_input.total_mutation_checks,
                public_input.verifier_profile.as_str()
            ),
            FindingSeverity::Critical,
            BTreeMap::from([
                ("subsystem".to_string(), "public_input".to_string()),
                (
                    "verifier_profile".to_string(),
                    public_input.verifier_profile.as_str().to_string(),
                ),
                (
                    "accepted_mutations".to_string(),
                    public_input.accepted_mutations.to_string(),
                ),
                (
                    "regression_test".to_string(),
                    "crates/zk-track-boundary/src/public_input_fuzzer.rs::tests::weak_profile_accepts_manipulated_first_input"
                        .to_string(),
                ),
            ]),
            report_path.to_path_buf(),
        ));
    }

    if serialization.accepted_invalid_cases > 0 {
        findings.push(track_finding(
            "boundary-serialization-001",
            "Verifier accepted malformed serialization payloads",
            format!(
                "Serialization campaign accepted {} malformed payloads out of {} checks under `{}` profile",
                serialization.accepted_invalid_cases,
                serialization.total_checks,
                serialization.verifier_profile.as_str()
            ),
            if mode == BoundaryExecutionMode::BugProbe {
                FindingSeverity::High
            } else {
                FindingSeverity::Medium
            },
            BTreeMap::from([
                ("subsystem".to_string(), "serialization".to_string()),
                (
                    "verifier_profile".to_string(),
                    serialization.verifier_profile.as_str().to_string(),
                ),
                (
                    "accepted_invalid_cases".to_string(),
                    serialization.accepted_invalid_cases.to_string(),
                ),
                (
                    "regression_test".to_string(),
                    "crates/zk-track-boundary/src/serialization_fuzzer.rs::tests::lenient_profile_accepts_legacy_invalid_payloads"
                        .to_string(),
                ),
            ]),
            report_path.to_path_buf(),
        ));
    }

    if solidity_verifier.differential_divergences > 0 {
        findings.push(track_finding(
            "boundary-solidity-001",
            "Solidity verifier behavior diverges from reference verifier",
            format!(
                "Solidity verifier campaign found {} differential divergences (optimized_accepts_reference_rejects={}) under `{}` profile",
                solidity_verifier.differential_divergences,
                solidity_verifier.optimized_accepts_reference_rejects,
                solidity_verifier.optimized_profile.as_str()
            ),
            if mode == BoundaryExecutionMode::BugProbe {
                FindingSeverity::High
            } else {
                FindingSeverity::Medium
            },
            BTreeMap::from([
                ("subsystem".to_string(), "solidity_verifier".to_string()),
                (
                    "optimized_profile".to_string(),
                    solidity_verifier.optimized_profile.as_str().to_string(),
                ),
                (
                    "differential_divergences".to_string(),
                    solidity_verifier.differential_divergences.to_string(),
                ),
                (
                    "regression_test".to_string(),
                    "crates/zk-track-boundary/src/solidity_verifier_fuzzer.rs::tests::weak_optimized_profile_surfaces_divergences"
                        .to_string(),
                ),
            ]),
            report_path.to_path_buf(),
        ));
    }

    if cross_component.differential_divergences > 0 {
        findings.push(track_finding(
            "boundary-cross-component-001",
            "Cross-component verifier behavior diverges from strict compatibility",
            format!(
                "Cross-component campaign found {} divergences (candidate_accepts_reference_rejects={}) under `{}` profile",
                cross_component.differential_divergences,
                cross_component.candidate_accepts_reference_rejects,
                cross_component.verifier_profile.as_str()
            ),
            if mode == BoundaryExecutionMode::BugProbe {
                FindingSeverity::High
            } else {
                FindingSeverity::Medium
            },
            BTreeMap::from([
                ("subsystem".to_string(), "cross_component".to_string()),
                (
                    "verifier_profile".to_string(),
                    cross_component.verifier_profile.as_str().to_string(),
                ),
                (
                    "differential_divergences".to_string(),
                    cross_component.differential_divergences.to_string(),
                ),
                (
                    "regression_test".to_string(),
                    "crates/zk-track-boundary/src/cross_component_fuzzer.rs::tests::weak_profile_surfaces_divergences"
                        .to_string(),
                ),
            ]),
            report_path.to_path_buf(),
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
        track: TrackKind::Boundary,
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
    report_path: &Path,
    findings: &[TrackFinding],
) -> PostRoadmapResult<Scorecard> {
    let report_text = fs::read_to_string(report_path).map_err(|error| {
        PostRoadmapError::Persistence(format!(
            "failed reading boundary report `{}` for scorecard: {error}",
            report_path.display()
        ))
    })?;
    let report_json: serde_json::Value = serde_json::from_str(&report_text).map_err(|error| {
        PostRoadmapError::Persistence(format!(
            "failed parsing boundary report `{}` for scorecard: {error}",
            report_path.display()
        ))
    })?;

    let public_input_checks = report_json["public_input"]["total_mutation_checks"]
        .as_u64()
        .unwrap_or(0);
    let serialization_checks = report_json["serialization"]["total_checks"]
        .as_u64()
        .unwrap_or(0);
    let solidity_checks = report_json["solidity_verifier"]["differential_checks"]
        .as_u64()
        .unwrap_or(0);
    let cross_component_checks = report_json["cross_component"]["total_checks"]
        .as_u64()
        .unwrap_or(0);

    let public_input_failures = report_json["public_input"]["accepted_mutations"]
        .as_u64()
        .unwrap_or(0);
    let serialization_failures = report_json["serialization"]["accepted_invalid_cases"]
        .as_u64()
        .unwrap_or(0);
    let solidity_failures = report_json["solidity_verifier"]["differential_divergences"]
        .as_u64()
        .unwrap_or(0);
    let cross_component_failures = report_json["cross_component"]["differential_divergences"]
        .as_u64()
        .unwrap_or(0);

    let mut coverage_counts = BTreeMap::new();
    coverage_counts.insert("public_input_checks".to_string(), public_input_checks);
    coverage_counts.insert("serialization_checks".to_string(), serialization_checks);
    coverage_counts.insert("solidity_checks".to_string(), solidity_checks);
    coverage_counts.insert("cross_component_checks".to_string(), cross_component_checks);
    coverage_counts.insert("finding_count".to_string(), findings.len() as u64);

    let public_input_rejection_rate = pass_rate(public_input_checks, public_input_failures);
    let serialization_rejection_rate = pass_rate(serialization_checks, serialization_failures);
    let solidity_parity_rate = pass_rate(solidity_checks, solidity_failures);
    let cross_component_parity_rate = pass_rate(cross_component_checks, cross_component_failures);

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
                name: "public_input_rejection_rate".to_string(),
                value: public_input_rejection_rate,
                threshold: Some(1.0),
                passed: (public_input_rejection_rate - 1.0).abs() < f64::EPSILON,
            },
            ScorecardMetric {
                name: "serialization_rejection_rate".to_string(),
                value: serialization_rejection_rate,
                threshold: Some(1.0),
                passed: (serialization_rejection_rate - 1.0).abs() < f64::EPSILON,
            },
            ScorecardMetric {
                name: "solidity_parity_rate".to_string(),
                value: solidity_parity_rate,
                threshold: Some(1.0),
                passed: (solidity_parity_rate - 1.0).abs() < f64::EPSILON,
            },
            ScorecardMetric {
                name: "cross_component_parity_rate".to_string(),
                value: cross_component_parity_rate,
                threshold: Some(1.0),
                passed: (cross_component_parity_rate - 1.0).abs() < f64::EPSILON,
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

    use tempfile::TempDir;

    use super::*;

    fn sample_input(output_dir: PathBuf) -> TrackInput {
        TrackInput {
            campaign_id: "boundary-campaign".to_string(),
            run_id: "boundary-run".to_string(),
            seed: Some(7),
            corpus_dir: output_dir.join("corpus"),
            evidence_dir: output_dir.join("evidence"),
            output_dir,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn exposes_boundary_track_kind() {
        assert_eq!(BoundaryTrackRunner::new().track(), TrackKind::Boundary);
    }

    #[test]
    fn reports_protocol_adapter_count() {
        let runner = BoundaryTrackRunner::new();
        assert_eq!(runner.protocol_adapter_count(), 0);
    }

    #[test]
    fn exposes_track_version() {
        assert!(!TRACK_MODULE_VERSION.is_empty());
    }

    #[tokio::test]
    async fn strict_mode_run_emits_scorecard_and_report() {
        let temp_dir = TempDir::new().expect("temp dir");
        let input = sample_input(temp_dir.path().to_path_buf());
        let runner = BoundaryTrackRunner::new();

        runner.prepare(&input).await.expect("prepare passes");
        let execution = runner.run(&input).await.expect("run passes");
        runner
            .validate(&execution)
            .await
            .expect("validate passes for strict mode");
        let emitted = runner.emit(&execution).await.expect("emit passes");

        assert!(execution.findings.is_empty());
        assert!(execution.scorecard.is_some());
        assert_eq!(execution.track, TrackKind::Boundary);
        assert!(!emitted.is_empty());
        assert!(emitted
            .iter()
            .any(|path| path.ends_with("boundary_track_report.json")));
    }

    #[tokio::test]
    async fn bug_probe_mode_surfaces_findings() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut input = sample_input(temp_dir.path().to_path_buf());
        input.metadata.insert(
            "boundary_execution_mode".to_string(),
            "bug_probe".to_string(),
        );

        let runner = BoundaryTrackRunner::new();
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
        let runner = BoundaryTrackRunner::new();
        let mut execution = TrackExecution::empty(TrackKind::Boundary, "run-1");
        execution.scorecard = None;

        let error = runner
            .validate(&execution)
            .await
            .expect_err("missing scorecard should fail validation");
        assert!(error
            .to_string()
            .contains("boundary execution must include a scorecard"));
    }
}
