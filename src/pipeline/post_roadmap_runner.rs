use std::collections::BTreeSet;
use std::path::PathBuf;

use zk_postroadmap_core::{
    PostRoadmapError, RunnerStage, TrackExecution, TrackInput, TrackKind, TrackRunner,
};

/// Executes deferred post-roadmap tracks in ROI order with stage isolation.
pub struct PostRoadmapRunner {
    tracks: Vec<Box<dyn TrackRunner>>,
    config: PostRoadmapRunnerConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostRoadmapRunnerConfig {
    enabled_tracks: BTreeSet<TrackKind>,
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
        Self::with_config(tracks, PostRoadmapRunnerConfig::default())
    }

    pub fn with_config(tracks: Vec<Box<dyn TrackRunner>>, config: PostRoadmapRunnerConfig) -> Self {
        Self {
            tracks: Self::sort_tracks(tracks),
            config,
        }
    }

    pub async fn execute(&self, input: &TrackInput) -> PostRoadmapRunSummary {
        let mut summary = PostRoadmapRunSummary::default();

        for track_runner in &self.tracks {
            let track = track_runner.track();
            if !self.config.is_enabled(track) {
                continue;
            }

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

impl Default for PostRoadmapRunner {
    fn default() -> Self {
        Self::new(default_post_roadmap_tracks())
    }
}

impl PostRoadmapRunnerConfig {
    pub fn only<I>(tracks: I) -> Self
    where
        I: IntoIterator<Item = TrackKind>,
    {
        Self {
            enabled_tracks: tracks.into_iter().collect(),
        }
    }

    pub fn all_enabled() -> Self {
        Self::default()
    }

    pub fn is_enabled(&self, track: TrackKind) -> bool {
        self.enabled_tracks.contains(&track)
    }
}

impl Default for PostRoadmapRunnerConfig {
    fn default() -> Self {
        Self::only([
            TrackKind::Boundary,
            TrackKind::Compiler,
            TrackKind::Semantic,
            TrackKind::Crypto,
        ])
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
