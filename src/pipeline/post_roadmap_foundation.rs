use std::collections::BTreeMap;
use std::path::PathBuf;

use zk_postroadmap_core::{FindingSeverity, TrackInput, TrackKind, POST_ROADMAP_SCHEMA_VERSION};

use crate::pipeline::post_roadmap_runner::PostRoadmapRunSummary;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedStoreLayout {
    pub shared_corpus_store: PathBuf,
    pub shared_evidence_store: PathBuf,
    pub shared_replay_store: PathBuf,
    pub shared_dashboard_store: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayHarnessState {
    pub replay_artifact_count: u64,
    pub minimization_queue_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardSnapshot {
    pub total_runs: u64,
    pub total_findings: u64,
    pub total_failures: u64,
    pub findings_by_track: BTreeMap<TrackKind, u64>,
    pub high_critical_without_regression: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundationSprintState {
    pub stores: SharedStoreLayout,
    pub shared_finding_schema_version: String,
    pub replay_harness: ReplayHarnessState,
    pub dashboard: DashboardSnapshot,
}

pub fn build_foundation_sprint_state(
    input: &TrackInput,
    summary: &PostRoadmapRunSummary,
) -> FoundationSprintState {
    let stores = SharedStoreLayout {
        shared_corpus_store: input.corpus_dir.join("post_roadmap").join("shared"),
        shared_evidence_store: input.evidence_dir.join("post_roadmap").join("shared"),
        shared_replay_store: input.output_dir.join("post_roadmap").join("replay"),
        shared_dashboard_store: input.output_dir.join("post_roadmap").join("dashboard"),
    };

    let mut findings_by_track = BTreeMap::new();
    let mut total_findings = 0_u64;
    let mut high_critical_without_regression = 0_u64;
    let mut replay_artifact_count = 0_u64;
    let mut minimization_queue_count = 0_u64;

    for execution in &summary.runs {
        replay_artifact_count += execution.replay_artifacts.len() as u64;
        for finding in &execution.findings {
            total_findings += 1;
            minimization_queue_count += u64::from(finding.reproducible);
            *findings_by_track.entry(execution.track).or_insert(0) += 1;

            let requires_regression = matches!(
                finding.severity,
                FindingSeverity::High | FindingSeverity::Critical
            );
            let has_regression_test = finding
                .metadata
                .get("regression_test")
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false);
            if requires_regression && !has_regression_test {
                high_critical_without_regression += 1;
            }
        }
    }

    FoundationSprintState {
        stores,
        shared_finding_schema_version: POST_ROADMAP_SCHEMA_VERSION.to_string(),
        replay_harness: ReplayHarnessState {
            replay_artifact_count,
            minimization_queue_count,
        },
        dashboard: DashboardSnapshot {
            total_runs: summary.runs.len() as u64,
            total_findings,
            total_failures: summary.failures.len() as u64,
            findings_by_track,
            high_critical_without_regression,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use chrono::Utc;
    use zk_postroadmap_core::{TrackExecution, TrackFinding};

    use super::*;

    fn sample_input() -> TrackInput {
        TrackInput {
            campaign_id: "foundation".to_string(),
            run_id: "run-1".to_string(),
            seed: Some(1),
            corpus_dir: PathBuf::from("corpus"),
            evidence_dir: PathBuf::from("evidence"),
            output_dir: PathBuf::from("output"),
            metadata: BTreeMap::new(),
        }
    }

    fn sample_summary() -> PostRoadmapRunSummary {
        let mut with_regression = BTreeMap::new();
        with_regression.insert(
            "regression_test".to_string(),
            "tests/regression/high.rs".to_string(),
        );

        let high = TrackFinding {
            id: "f-high".to_string(),
            track: TrackKind::Boundary,
            title: "High".to_string(),
            summary: "High severity".to_string(),
            severity: FindingSeverity::High,
            reproducible: true,
            evidence_paths: vec![],
            metadata: with_regression,
        };
        let critical_without_test = TrackFinding {
            id: "f-critical".to_string(),
            track: TrackKind::Compiler,
            title: "Critical".to_string(),
            summary: "Critical severity".to_string(),
            severity: FindingSeverity::Critical,
            reproducible: false,
            evidence_paths: vec![],
            metadata: BTreeMap::new(),
        };

        PostRoadmapRunSummary {
            runs: vec![
                TrackExecution {
                    track: TrackKind::Boundary,
                    run_id: "run-1".to_string(),
                    started_at: Utc::now(),
                    finished_at: Utc::now(),
                    findings: vec![high],
                    replay_artifacts: vec![],
                    scorecard: None,
                },
                TrackExecution {
                    track: TrackKind::Compiler,
                    run_id: "run-1".to_string(),
                    started_at: Utc::now(),
                    finished_at: Utc::now(),
                    findings: vec![critical_without_test],
                    replay_artifacts: vec![],
                    scorecard: None,
                },
            ],
            failures: vec![],
            emitted_paths: vec![],
        }
    }

    #[test]
    fn builds_foundation_layout_and_dashboard() {
        let state = build_foundation_sprint_state(&sample_input(), &sample_summary());
        assert_eq!(
            state.stores.shared_corpus_store,
            PathBuf::from("corpus/post_roadmap/shared")
        );
        assert_eq!(
            state.stores.shared_evidence_store,
            PathBuf::from("evidence/post_roadmap/shared")
        );
        assert_eq!(
            state.stores.shared_replay_store,
            PathBuf::from("output/post_roadmap/replay")
        );
        assert_eq!(
            state.stores.shared_dashboard_store,
            PathBuf::from("output/post_roadmap/dashboard")
        );
        assert_eq!(
            state.shared_finding_schema_version,
            POST_ROADMAP_SCHEMA_VERSION
        );
        assert_eq!(state.dashboard.total_runs, 2);
        assert_eq!(state.dashboard.total_findings, 2);
        assert_eq!(
            state
                .dashboard
                .findings_by_track
                .get(&TrackKind::Boundary)
                .copied()
                .unwrap_or(0),
            1
        );
        assert_eq!(
            state
                .dashboard
                .findings_by_track
                .get(&TrackKind::Compiler)
                .copied()
                .unwrap_or(0),
            1
        );
        assert_eq!(state.dashboard.high_critical_without_regression, 1);
    }
}
