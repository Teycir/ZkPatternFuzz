//! Shared contracts and error taxonomy for deferred post-roadmap tracks.

mod contracts;
mod errors;
mod runner;

pub const POST_ROADMAP_CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub use contracts::{
    FindingSeverity, ReplayArtifact, Scorecard, ScorecardMetric, TrackExecution, TrackFinding,
    TrackInput, TrackKind, POST_ROADMAP_SCHEMA_VERSION,
};
pub use errors::{PostRoadmapError, PostRoadmapResult, RunnerStage};
pub use runner::TrackRunner;
