use std::path::PathBuf;

use async_trait::async_trait;

use crate::{PostRoadmapResult, TrackExecution, TrackInput, TrackKind};

#[async_trait]
pub trait TrackRunner: Send + Sync {
    fn track(&self) -> TrackKind;
    async fn prepare(&self, input: &TrackInput) -> PostRoadmapResult<()>;
    async fn run(&self, input: &TrackInput) -> PostRoadmapResult<TrackExecution>;
    async fn validate(&self, execution: &TrackExecution) -> PostRoadmapResult<()>;
    async fn emit(&self, execution: &TrackExecution) -> PostRoadmapResult<Vec<PathBuf>>;
}
