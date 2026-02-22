mod adapters;

use std::path::PathBuf;

use async_trait::async_trait;
use zk_postroadmap_core::{PostRoadmapResult, TrackExecution, TrackInput, TrackKind, TrackRunner};

pub use adapters::{ExploitabilityAssessment, SemanticIntent, SemanticIntentAdapter};

pub const TRACK_MODULE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default)]
pub struct SemanticTrackRunner {
    intent_adapters: Vec<Box<dyn SemanticIntentAdapter>>,
}

impl SemanticTrackRunner {
    pub fn new() -> Self {
        Self {
            intent_adapters: Vec::new(),
        }
    }

    pub fn with_intent_adapter(mut self, adapter: Box<dyn SemanticIntentAdapter>) -> Self {
        self.intent_adapters.push(adapter);
        self
    }

    pub fn intent_adapter_count(&self) -> usize {
        self.intent_adapters.len()
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

    #[test]
    fn reports_intent_adapter_count() {
        let runner = SemanticTrackRunner::new();
        assert_eq!(runner.intent_adapter_count(), 0);
    }

    #[test]
    fn exposes_track_version() {
        assert!(!TRACK_MODULE_VERSION.is_empty());
    }
}
