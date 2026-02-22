use std::path::PathBuf;

use async_trait::async_trait;
use zk_postroadmap_core::{PostRoadmapResult, TrackExecution, TrackInput, TrackKind, TrackRunner};

#[derive(Debug, Default)]
pub struct SemanticTrackRunner;

impl SemanticTrackRunner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TrackRunner for SemanticTrackRunner {
    fn track(&self) -> TrackKind {
        TrackKind::Semantic
    }

    async fn prepare(&self, _input: &TrackInput) -> PostRoadmapResult<()> {
        Ok(())
    }

    async fn run(&self, input: &TrackInput) -> PostRoadmapResult<TrackExecution> {
        Ok(TrackExecution::empty(self.track(), input.run_id.clone()))
    }

    async fn validate(&self, _execution: &TrackExecution) -> PostRoadmapResult<()> {
        Ok(())
    }

    async fn emit(&self, _execution: &TrackExecution) -> PostRoadmapResult<Vec<PathBuf>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_semantic_track_kind() {
        assert_eq!(SemanticTrackRunner::new().track(), TrackKind::Semantic);
    }
}
