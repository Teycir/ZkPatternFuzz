use std::path::PathBuf;

use zk_postroadmap_core::{
    PostRoadmapError, RunnerStage, TrackExecution, TrackInput, TrackKind, TrackRunner,
};

/// Executes deferred post-roadmap tracks in ROI order with stage isolation.
pub struct PostRoadmapRunner {
    tracks: Vec<Box<dyn TrackRunner>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackFailure {
    pub track: TrackKind,
    pub stage: RunnerStage,
    pub error: String,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct PostRoadmapRunSummary {
    pub runs: Vec<TrackExecution>,
    pub failures: Vec<TrackFailure>,
    pub emitted_paths: Vec<PathBuf>,
}

impl PostRoadmapRunner {
    pub fn new(tracks: Vec<Box<dyn TrackRunner>>) -> Self {
        Self {
            tracks: Self::sort_tracks(tracks),
        }
    }

    pub fn default() -> Self {
        Self::new(default_post_roadmap_tracks())
    }

    pub async fn execute(&self, input: &TrackInput) -> PostRoadmapRunSummary {
        let mut summary = PostRoadmapRunSummary::default();

        for track_runner in &self.tracks {
            let track = track_runner.track();

            if let Err(error) = track_runner.prepare(input).await {
                summary
                    .failures
                    .push(TrackFailure::from_error(track, RunnerStage::Prepare, error));
                continue;
            }

            let execution = match track_runner.run(input).await {
                Ok(execution) => execution,
                Err(error) => {
                    summary
                        .failures
                        .push(TrackFailure::from_error(track, RunnerStage::Run, error));
                    continue;
                }
            };

            if let Err(error) = track_runner.validate(&execution).await {
                summary.failures.push(TrackFailure::from_error(
                    track,
                    RunnerStage::Validate,
                    error,
                ));
                continue;
            }

            match track_runner.emit(&execution).await {
                Ok(emitted_paths) => summary.emitted_paths.extend(emitted_paths),
                Err(error) => {
                    summary
                        .failures
                        .push(TrackFailure::from_error(track, RunnerStage::Emit, error))
                }
            }

            summary.runs.push(execution);
        }

        summary
    }

    fn sort_tracks(mut tracks: Vec<Box<dyn TrackRunner>>) -> Vec<Box<dyn TrackRunner>> {
        tracks.sort_by_key(|runner| runner.track().execution_order());
        tracks
    }
}

impl TrackFailure {
    fn from_error(track: TrackKind, stage: RunnerStage, error: PostRoadmapError) -> Self {
        Self {
            track,
            stage,
            error: error.to_string(),
        }
    }
}

pub fn default_post_roadmap_tracks() -> Vec<Box<dyn TrackRunner>> {
    vec![
        Box::new(zk_track_boundary::BoundaryTrackRunner::new()),
        Box::new(zk_track_compiler::CompilerTrackRunner::new()),
        Box::new(zk_track_semantic::SemanticTrackRunner::new()),
        Box::new(zk_track_crypto::CryptoTrackRunner::new()),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use async_trait::async_trait;
    use zk_postroadmap_core::{PostRoadmapResult, TrackExecution};

    use super::*;

    #[derive(Debug, Clone)]
    struct StubRunner {
        track: TrackKind,
        fail_on: Option<RunnerStage>,
    }

    impl StubRunner {
        fn ok(track: TrackKind) -> Self {
            Self {
                track,
                fail_on: None,
            }
        }

        fn fail(track: TrackKind, stage: RunnerStage) -> Self {
            Self {
                track,
                fail_on: Some(stage),
            }
        }

        fn fail_if_requested(&self, stage: RunnerStage) -> PostRoadmapResult<()> {
            if self.fail_on == Some(stage) {
                return Err(PostRoadmapError::Infrastructure(format!(
                    "{} stage failed",
                    stage
                )));
            }
            Ok(())
        }
    }

    #[async_trait]
    impl TrackRunner for StubRunner {
        fn track(&self) -> TrackKind {
            self.track
        }

        async fn prepare(&self, _input: &TrackInput) -> PostRoadmapResult<()> {
            self.fail_if_requested(RunnerStage::Prepare)
        }

        async fn run(&self, input: &TrackInput) -> PostRoadmapResult<TrackExecution> {
            self.fail_if_requested(RunnerStage::Run)?;
            Ok(TrackExecution::empty(self.track, input.run_id.clone()))
        }

        async fn validate(&self, _execution: &TrackExecution) -> PostRoadmapResult<()> {
            self.fail_if_requested(RunnerStage::Validate)
        }

        async fn emit(&self, _execution: &TrackExecution) -> PostRoadmapResult<Vec<PathBuf>> {
            self.fail_if_requested(RunnerStage::Emit)?;
            Ok(vec![])
        }
    }

    fn sample_input() -> TrackInput {
        TrackInput {
            campaign_id: "campaign-1".to_string(),
            run_id: "run-1".to_string(),
            seed: Some(7),
            corpus_dir: PathBuf::from("corpus"),
            evidence_dir: PathBuf::from("evidence"),
            output_dir: PathBuf::from("output"),
            metadata: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn executes_tracks_in_roi_order() {
        let runner = PostRoadmapRunner::new(vec![
            Box::new(StubRunner::ok(TrackKind::Semantic)),
            Box::new(StubRunner::ok(TrackKind::Crypto)),
            Box::new(StubRunner::ok(TrackKind::Boundary)),
            Box::new(StubRunner::ok(TrackKind::Compiler)),
        ]);

        let summary = runner.execute(&sample_input()).await;
        let order: Vec<TrackKind> = summary.runs.iter().map(|run| run.track).collect();
        assert_eq!(
            order,
            vec![
                TrackKind::Boundary,
                TrackKind::Compiler,
                TrackKind::Semantic,
                TrackKind::Crypto,
            ]
        );
    }

    #[tokio::test]
    async fn continues_after_stage_failure() {
        let runner = PostRoadmapRunner::new(vec![
            Box::new(StubRunner::fail(TrackKind::Boundary, RunnerStage::Run)),
            Box::new(StubRunner::ok(TrackKind::Compiler)),
        ]);

        let summary = runner.execute(&sample_input()).await;
        assert_eq!(summary.runs.len(), 1);
        assert_eq!(summary.runs[0].track, TrackKind::Compiler);
        assert_eq!(summary.failures.len(), 1);
        assert_eq!(summary.failures[0].track, TrackKind::Boundary);
        assert_eq!(summary.failures[0].stage, RunnerStage::Run);
    }
}
