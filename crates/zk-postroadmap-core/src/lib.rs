//! Shared contracts and error taxonomy for deferred post-roadmap tracks.

mod contracts;
mod errors;
mod runner;

pub use contracts::{
    FindingSeverity, ReplayArtifact, Scorecard, ScorecardMetric, TrackExecution, TrackFinding,
    TrackInput, TrackKind, POST_ROADMAP_SCHEMA_VERSION,
};
pub use errors::{PostRoadmapError, PostRoadmapResult, RunnerStage};
pub use runner::TrackRunner;

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use crate::{
        FindingSeverity, Scorecard, ScorecardMetric, TrackExecution, TrackFinding, TrackKind,
        POST_ROADMAP_SCHEMA_VERSION,
    };

    #[test]
    fn serializes_core_contracts_with_schema_version() {
        let execution = TrackExecution {
            track: TrackKind::Boundary,
            run_id: "run-7".to_string(),
            findings: vec![TrackFinding {
                id: "finding-1".to_string(),
                track: TrackKind::Boundary,
                title: "Public input binding issue".to_string(),
                summary: "Verifier accepted manipulated public inputs".to_string(),
                severity: FindingSeverity::Critical,
                reproducible: true,
                evidence_paths: vec![],
                metadata: Default::default(),
            }],
            replay_artifacts: vec![],
            scorecard: Some(Scorecard {
                track: TrackKind::Boundary,
                schema_version: POST_ROADMAP_SCHEMA_VERSION.to_string(),
                evaluated_at: chrono::Utc::now(),
                coverage_counts: Default::default(),
                metrics: vec![ScorecardMetric {
                    name: "deterministic_replay_rate".to_string(),
                    value: 1.0,
                    threshold: Some(1.0),
                    passed: true,
                }],
                false_positive_budget: 0,
                false_positive_count: 0,
            }),
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        };

        let json = serde_json::to_value(execution).expect("serializes track execution");
        let scorecard = json
            .get("scorecard")
            .and_then(Value::as_object)
            .expect("scorecard object");
        assert_eq!(
            scorecard
                .get("schema_version")
                .and_then(Value::as_str)
                .expect("schema version"),
            POST_ROADMAP_SCHEMA_VERSION
        );
    }
}
