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
