use std::path::PathBuf;

use async_trait::async_trait;
use zk_postroadmap_core::{PostRoadmapResult, TrackExecution, TrackInput, TrackKind, TrackRunner};

#[derive(Debug, Default)]
pub struct BoundaryTrackRunner;

impl BoundaryTrackRunner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TrackRunner for BoundaryTrackRunner {
    fn track(&self) -> TrackKind {
        TrackKind::Boundary
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
    fn exposes_boundary_track_kind() {
        assert_eq!(BoundaryTrackRunner::new().track(), TrackKind::Boundary);
    }
}
