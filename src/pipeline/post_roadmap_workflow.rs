use std::collections::{BTreeSet, HashSet};

use zk_postroadmap_core::{
    FindingSeverity, PostRoadmapError, PostRoadmapResult, TrackInput, TrackKind,
};

use crate::pipeline::post_roadmap_foundation::{
    build_foundation_sprint_state, FoundationSprintState,
};
use crate::pipeline::post_roadmap_runner::{PostRoadmapRunSummary, PostRoadmapRunner};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum WorkflowStage {
    Generate,
    Boundary,
    Compiler,
    Semantic,
    Crypto,
    Attack,
    Interpret,
    Validate,
    Regress,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PostRoadmapPromotionPolicy {
    pub deterministic_replay_metric: String,
    pub min_deterministic_replay_rate: f64,
    pub require_explicit_coverage_counts: bool,
    pub require_regression_tests_for: BTreeSet<FindingSeverity>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PostRoadmapWorkflowConfig {
    pub activated: bool,
    pub fail_on_promotion_gate_failure: bool,
    pub weekly_cadence: Vec<WorkflowStage>,
    pub integrated_pipeline: Vec<WorkflowStage>,
    pub promotion_policy: PostRoadmapPromotionPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionGateResult {
    pub passed: bool,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackFindingRef {
    pub track: TrackKind,
    pub finding_id: String,
    pub severity: FindingSeverity,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratorPriority {
    pub source_finding_id: String,
    pub priority: u8,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SharedDataFlowReport {
    pub compiler_generated_circuits: Vec<String>,
    pub semantic_candidate_findings: Vec<TrackFindingRef>,
    pub crypto_validation_notes: Vec<String>,
    pub next_cycle_generator_priorities: Vec<GeneratorPriority>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PostRoadmapWorkflowReport {
    pub summary: PostRoadmapRunSummary,
    pub foundation: FoundationSprintState,
    pub shared_data_flow: SharedDataFlowReport,
    pub promotion_gate: PromotionGateResult,
    pub weekly_cadence: Vec<WorkflowStage>,
    pub integrated_pipeline: Vec<WorkflowStage>,
}

pub struct PostRoadmapWorkflowRunner {
    runner: PostRoadmapRunner,
    config: PostRoadmapWorkflowConfig,
}

impl PostRoadmapWorkflowRunner {
    pub fn new(runner: PostRoadmapRunner) -> Self {
        Self {
            runner,
            config: PostRoadmapWorkflowConfig::default(),
        }
    }

    pub fn with_config(runner: PostRoadmapRunner, config: PostRoadmapWorkflowConfig) -> Self {
        Self { runner, config }
    }

    pub fn config(&self) -> &PostRoadmapWorkflowConfig {
        &self.config
    }

    pub async fn run_cycle(
        &self,
        input: &TrackInput,
    ) -> PostRoadmapResult<PostRoadmapWorkflowReport> {
        if !self.config.activated {
            return Err(PostRoadmapError::Configuration(
                "post-roadmap workflow is disabled; explicit activation is required after phase-8 sustained-gate exit".to_string(),
            ));
        }

        let summary = self.runner.execute(input).await;
        let foundation = build_foundation_sprint_state(input, &summary);
        let shared_data_flow = build_shared_data_flow(&summary);
        let promotion_gate = evaluate_promotion_gates(&summary, &self.config.promotion_policy);

        if self.config.fail_on_promotion_gate_failure && !promotion_gate.passed {
            return Err(PostRoadmapError::Validation(format!(
                "post-roadmap promotion gates failed: {}",
                promotion_gate.failures.join("; ")
            )));
        }

        Ok(PostRoadmapWorkflowReport {
            summary,
            foundation,
            shared_data_flow,
            promotion_gate,
            weekly_cadence: self.config.weekly_cadence.clone(),
            integrated_pipeline: self.config.integrated_pipeline.clone(),
        })
    }
}

pub fn evaluate_promotion_gates(
    summary: &PostRoadmapRunSummary,
    policy: &PostRoadmapPromotionPolicy,
) -> PromotionGateResult {
    let mut failures = Vec::new();

    if !summary.failures.is_empty() {
        failures.push("track stage failures must be zero for promotion".to_string());
    }

    for execution in &summary.runs {
        let track = execution.track;
        match &execution.scorecard {
            Some(scorecard) => {
                if scorecard.false_positive_count > scorecard.false_positive_budget {
                    failures.push(format!(
                        "{track:?}: false_positive_count {} exceeds budget {}",
                        scorecard.false_positive_count, scorecard.false_positive_budget
                    ));
                }
                if policy.require_explicit_coverage_counts && scorecard.coverage_counts.is_empty() {
                    failures.push(format!("{track:?}: coverage counts must be explicit"));
                }
                match scorecard
                    .metrics
                    .iter()
                    .find(|metric| metric.name == policy.deterministic_replay_metric)
                {
                    Some(metric) if metric.value >= policy.min_deterministic_replay_rate => {}
                    Some(metric) => failures.push(format!(
                        "{track:?}: deterministic replay {} below minimum {}",
                        metric.value, policy.min_deterministic_replay_rate
                    )),
                    None => failures.push(format!(
                        "{track:?}: missing `{}` metric",
                        policy.deterministic_replay_metric
                    )),
                }
            }
            None => failures.push(format!("{track:?}: missing scorecard")),
        }

        for finding in &execution.findings {
            if policy
                .require_regression_tests_for
                .contains(&finding.severity)
            {
                let has_regression_test = finding
                    .metadata
                    .get("regression_test")
                    .map(|value| !value.trim().is_empty())
                    .unwrap_or(false);
                if !has_regression_test {
                    failures.push(format!(
                        "{track:?}/{}: regression_test metadata required for {:?} findings",
                        finding.id, finding.severity
                    ));
                }
            }
        }
    }

    PromotionGateResult {
        passed: failures.is_empty(),
        failures,
    }
}

pub fn build_shared_data_flow(summary: &PostRoadmapRunSummary) -> SharedDataFlowReport {
    let mut compiler_generated_circuits = HashSet::new();
    let mut semantic_candidate_findings = Vec::new();
    let mut crypto_validation_notes = HashSet::new();
    let mut next_cycle_generator_priorities = Vec::new();

    for execution in &summary.runs {
        match execution.track {
            TrackKind::Compiler => {
                for finding in &execution.findings {
                    semantic_candidate_findings.push(TrackFindingRef {
                        track: execution.track,
                        finding_id: finding.id.clone(),
                        severity: finding.severity,
                        title: finding.title.clone(),
                    });
                    if let Some(circuit) = finding.metadata.get("generated_circuit") {
                        let trimmed = circuit.trim();
                        if !trimmed.is_empty() {
                            compiler_generated_circuits.insert(trimmed.to_string());
                        }
                    }
                }
                for replay in &execution.replay_artifacts {
                    for path in &replay.evidence_paths {
                        compiler_generated_circuits.insert(path.display().to_string());
                    }
                }
            }
            TrackKind::Boundary => {
                semantic_candidate_findings.extend(execution.findings.iter().map(|finding| {
                    TrackFindingRef {
                        track: execution.track,
                        finding_id: finding.id.clone(),
                        severity: finding.severity,
                        title: finding.title.clone(),
                    }
                }));
            }
            TrackKind::Crypto => match &execution.scorecard {
                Some(scorecard) => {
                    for metric in &scorecard.metrics {
                        crypto_validation_notes.insert(format!(
                            "{}:{}:{}",
                            metric.name, metric.value, metric.passed
                        ));
                    }
                }
                None => {
                    crypto_validation_notes.insert("missing_crypto_scorecard".to_string());
                }
            },
            TrackKind::Semantic => {
                for finding in &execution.findings {
                    let priority = finding
                        .metadata
                        .get("generator_priority")
                        .and_then(|value| value.parse::<u8>().ok())
                        .unwrap_or_else(|| default_priority_for_severity(finding.severity));
                    let reason = finding
                        .metadata
                        .get("generator_reason")
                        .cloned()
                        .unwrap_or_else(|| finding.title.clone());
                    next_cycle_generator_priorities.push(GeneratorPriority {
                        source_finding_id: finding.id.clone(),
                        priority,
                        reason,
                    });
                }
            }
        }
    }

    semantic_candidate_findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    next_cycle_generator_priorities.sort_by(|left, right| right.priority.cmp(&left.priority));

    let mut compiler_generated_circuits: Vec<String> =
        compiler_generated_circuits.into_iter().collect();
    compiler_generated_circuits.sort();

    let mut crypto_validation_notes: Vec<String> = crypto_validation_notes.into_iter().collect();
    crypto_validation_notes.sort();

    SharedDataFlowReport {
        compiler_generated_circuits,
        semantic_candidate_findings,
        crypto_validation_notes,
        next_cycle_generator_priorities,
    }
}

fn default_priority_for_severity(severity: FindingSeverity) -> u8 {
    match severity {
        FindingSeverity::Critical => 90,
        FindingSeverity::High => 75,
        FindingSeverity::Medium => 50,
        FindingSeverity::Low => 25,
        FindingSeverity::Info => 10,
    }
}

pub fn recommended_roi_track_order() -> Vec<TrackKind> {
    vec![
        TrackKind::Boundary,
        TrackKind::Compiler,
        TrackKind::Semantic,
        TrackKind::Crypto,
    ]
}

pub fn default_weekly_cadence() -> Vec<WorkflowStage> {
    vec![
        WorkflowStage::Generate,
        WorkflowStage::Boundary,
        WorkflowStage::Semantic,
        WorkflowStage::Crypto,
        WorkflowStage::Regress,
    ]
}

pub fn default_integrated_pipeline() -> Vec<WorkflowStage> {
    vec![
        WorkflowStage::Generate,
        WorkflowStage::Attack,
        WorkflowStage::Interpret,
        WorkflowStage::Validate,
        WorkflowStage::Regress,
    ]
}

impl Default for PostRoadmapPromotionPolicy {
    fn default() -> Self {
        Self {
            deterministic_replay_metric: "deterministic_replay_rate".to_string(),
            min_deterministic_replay_rate: 1.0,
            require_explicit_coverage_counts: true,
            require_regression_tests_for: [FindingSeverity::High, FindingSeverity::Critical]
                .into_iter()
                .collect(),
        }
    }
}

impl Default for PostRoadmapWorkflowConfig {
    fn default() -> Self {
        Self {
            activated: false,
            fail_on_promotion_gate_failure: true,
            weekly_cadence: default_weekly_cadence(),
            integrated_pipeline: default_integrated_pipeline(),
            promotion_policy: PostRoadmapPromotionPolicy::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use chrono::Utc;
    use zk_postroadmap_core::{
        ReplayArtifact, Scorecard, ScorecardMetric, TrackExecution, TrackFinding,
    };

    use crate::pipeline::post_roadmap_runner::default_post_roadmap_tracks;

    use super::*;

    fn sample_input() -> TrackInput {
        TrackInput {
            campaign_id: "workflow".to_string(),
            run_id: "workflow-run".to_string(),
            seed: Some(11),
            corpus_dir: PathBuf::from("corpus"),
            evidence_dir: PathBuf::from("evidence"),
            output_dir: PathBuf::from("output"),
            metadata: BTreeMap::new(),
        }
    }

    fn sample_summary() -> PostRoadmapRunSummary {
        let mut boundary_meta = BTreeMap::new();
        boundary_meta.insert(
            "regression_test".to_string(),
            "tests/regression/high.rs".to_string(),
        );

        PostRoadmapRunSummary {
            runs: vec![
                TrackExecution {
                    track: TrackKind::Boundary,
                    run_id: "run".to_string(),
                    started_at: Utc::now(),
                    finished_at: Utc::now(),
                    findings: vec![TrackFinding {
                        id: "boundary-1".to_string(),
                        track: TrackKind::Boundary,
                        title: "Boundary finding".to_string(),
                        summary: "Requires regression".to_string(),
                        severity: FindingSeverity::High,
                        reproducible: true,
                        evidence_paths: vec![],
                        metadata: boundary_meta,
                    }],
                    replay_artifacts: vec![],
                    scorecard: Some(build_scorecard(TrackKind::Boundary, 1.0, 10)),
                },
                TrackExecution {
                    track: TrackKind::Compiler,
                    run_id: "run".to_string(),
                    started_at: Utc::now(),
                    finished_at: Utc::now(),
                    findings: vec![TrackFinding {
                        id: "compiler-1".to_string(),
                        track: TrackKind::Compiler,
                        title: "Compiler edge case".to_string(),
                        summary: "Generated adversarial circuit".to_string(),
                        severity: FindingSeverity::Medium,
                        reproducible: true,
                        evidence_paths: vec![],
                        metadata: {
                            let mut metadata = BTreeMap::new();
                            metadata.insert(
                                "generated_circuit".to_string(),
                                "generated/case_2.noir".to_string(),
                            );
                            metadata
                        },
                    }],
                    replay_artifacts: vec![ReplayArtifact {
                        replay_id: "compiler-replay".to_string(),
                        track: TrackKind::Compiler,
                        command: vec!["cargo".to_string(), "run".to_string()],
                        env: BTreeMap::new(),
                        evidence_paths: vec![PathBuf::from("generated/case_3.halo2")],
                        notes: String::new(),
                    }],
                    scorecard: Some(build_scorecard(TrackKind::Compiler, 1.0, 3)),
                },
                TrackExecution {
                    track: TrackKind::Semantic,
                    run_id: "run".to_string(),
                    started_at: Utc::now(),
                    finished_at: Utc::now(),
                    findings: vec![TrackFinding {
                        id: "semantic-1".to_string(),
                        track: TrackKind::Semantic,
                        title: "Generator focus".to_string(),
                        summary: "Prioritize malformed lookup patterns".to_string(),
                        severity: FindingSeverity::High,
                        reproducible: true,
                        evidence_paths: vec![],
                        metadata: {
                            let mut metadata = BTreeMap::new();
                            metadata.insert("generator_priority".to_string(), "88".to_string());
                            metadata.insert(
                                "generator_reason".to_string(),
                                "lookup underconstrained edge".to_string(),
                            );
                            metadata.insert(
                                "regression_test".to_string(),
                                "tests/regression/semantic.rs".to_string(),
                            );
                            metadata
                        },
                    }],
                    replay_artifacts: vec![],
                    scorecard: Some(build_scorecard(TrackKind::Semantic, 1.0, 4)),
                },
                TrackExecution {
                    track: TrackKind::Crypto,
                    run_id: "run".to_string(),
                    started_at: Utc::now(),
                    finished_at: Utc::now(),
                    findings: vec![],
                    replay_artifacts: vec![],
                    scorecard: Some(Scorecard {
                        track: TrackKind::Crypto,
                        schema_version: zk_postroadmap_core::POST_ROADMAP_SCHEMA_VERSION
                            .to_string(),
                        evaluated_at: Utc::now(),
                        coverage_counts: {
                            let mut coverage = BTreeMap::new();
                            coverage.insert("field_ops".to_string(), 8);
                            coverage
                        },
                        metrics: vec![
                            ScorecardMetric {
                                name: "deterministic_replay_rate".to_string(),
                                value: 1.0,
                                threshold: Some(1.0),
                                passed: true,
                            },
                            ScorecardMetric {
                                name: "math_noise_filter_rate".to_string(),
                                value: 1.0,
                                threshold: Some(1.0),
                                passed: true,
                            },
                        ],
                        false_positive_budget: 0,
                        false_positive_count: 0,
                    }),
                },
            ],
            failures: vec![],
            emitted_paths: vec![],
        }
    }

    fn build_scorecard(track: TrackKind, replay_rate: f64, coverage: u64) -> Scorecard {
        let mut coverage_counts = BTreeMap::new();
        if coverage > 0 {
            coverage_counts.insert("constraints".to_string(), coverage);
        }
        Scorecard {
            track,
            schema_version: zk_postroadmap_core::POST_ROADMAP_SCHEMA_VERSION.to_string(),
            evaluated_at: Utc::now(),
            coverage_counts,
            metrics: vec![ScorecardMetric {
                name: "deterministic_replay_rate".to_string(),
                value: replay_rate,
                threshold: Some(1.0),
                passed: replay_rate >= 1.0,
            }],
            false_positive_budget: 0,
            false_positive_count: 0,
        }
    }

    #[test]
    fn defaults_match_workflow_requirements() {
        assert_eq!(
            recommended_roi_track_order(),
            vec![
                TrackKind::Boundary,
                TrackKind::Compiler,
                TrackKind::Semantic,
                TrackKind::Crypto,
            ]
        );
        assert_eq!(
            default_weekly_cadence(),
            vec![
                WorkflowStage::Generate,
                WorkflowStage::Boundary,
                WorkflowStage::Semantic,
                WorkflowStage::Crypto,
                WorkflowStage::Regress,
            ]
        );
        assert_eq!(
            default_integrated_pipeline(),
            vec![
                WorkflowStage::Generate,
                WorkflowStage::Attack,
                WorkflowStage::Interpret,
                WorkflowStage::Validate,
                WorkflowStage::Regress,
            ]
        );
    }

    #[test]
    fn shared_data_flow_links_tracks() {
        let report = build_shared_data_flow(&sample_summary());
        assert_eq!(
            report.compiler_generated_circuits,
            vec![
                "generated/case_2.noir".to_string(),
                "generated/case_3.halo2".to_string(),
            ]
        );
        let finding_ids: Vec<String> = report
            .semantic_candidate_findings
            .iter()
            .map(|entry| entry.finding_id.clone())
            .collect();
        assert_eq!(
            finding_ids,
            vec!["boundary-1".to_string(), "compiler-1".to_string()]
        );
        assert_eq!(
            report.next_cycle_generator_priorities[0],
            GeneratorPriority {
                source_finding_id: "semantic-1".to_string(),
                priority: 88,
                reason: "lookup underconstrained edge".to_string(),
            }
        );
        assert!(report
            .crypto_validation_notes
            .iter()
            .any(|entry| entry.starts_with("math_noise_filter_rate:1")));
    }

    #[test]
    fn promotion_gate_fails_without_required_regression_test() {
        let mut summary = sample_summary();
        summary.runs[0].findings[0].metadata.clear();
        let gate = evaluate_promotion_gates(&summary, &PostRoadmapPromotionPolicy::default());
        assert!(!gate.passed);
        assert!(gate
            .failures
            .iter()
            .any(|entry| entry.contains("regression_test metadata required")));
    }

    #[test]
    fn promotion_gate_fails_when_coverage_is_missing() {
        let mut summary = sample_summary();
        summary.runs[0].scorecard = Some(build_scorecard(TrackKind::Boundary, 1.0, 0));
        let gate = evaluate_promotion_gates(&summary, &PostRoadmapPromotionPolicy::default());
        assert!(!gate.passed);
        assert!(gate
            .failures
            .iter()
            .any(|entry| entry.contains("coverage counts must be explicit")));
    }

    #[test]
    fn promotion_gate_passes_when_requirements_are_met() {
        let summary = sample_summary();
        let gate = evaluate_promotion_gates(&summary, &PostRoadmapPromotionPolicy::default());
        assert!(gate.passed);
    }

    #[tokio::test]
    async fn workflow_runner_requires_explicit_activation() {
        let runner = PostRoadmapRunner::new(default_post_roadmap_tracks());
        let workflow = PostRoadmapWorkflowRunner::new(runner);
        let error = workflow.run_cycle(&sample_input()).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("post-roadmap workflow is disabled"));
    }

    #[tokio::test]
    async fn workflow_runner_executes_when_activated() {
        let runner = PostRoadmapRunner::new(default_post_roadmap_tracks());
        let mut config = PostRoadmapWorkflowConfig::default();
        config.activated = true;
        config.fail_on_promotion_gate_failure = false;
        let workflow = PostRoadmapWorkflowRunner::with_config(runner, config);
        let report = workflow
            .run_cycle(&sample_input())
            .await
            .expect("activated workflow should run");
        assert_eq!(report.weekly_cadence, default_weekly_cadence());
        assert_eq!(report.integrated_pipeline, default_integrated_pipeline());
        assert_eq!(
            report.foundation.shared_finding_schema_version,
            zk_postroadmap_core::POST_ROADMAP_SCHEMA_VERSION
        );
    }

    #[test]
    fn roi_order_is_respected_by_track_runner_sorting() {
        let tracks = default_post_roadmap_tracks();
        let ordered: Vec<TrackKind> = tracks.iter().map(|runner| runner.track()).collect();
        assert_eq!(ordered, recommended_roi_track_order());
    }
}
