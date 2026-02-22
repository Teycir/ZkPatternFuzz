mod adapters;

use std::path::PathBuf;

use async_trait::async_trait;
use zk_postroadmap_core::{PostRoadmapResult, TrackExecution, TrackInput, TrackKind, TrackRunner};

pub use adapters::{
    CompilerBackendAdapter, CompilerCrashClass, CompilerDiagnostic, CompilerGenerationRequest,
    CompilerGenerationResult,
};

pub const TRACK_MODULE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default)]
pub struct CompilerTrackRunner {
    backend_adapters: Vec<Box<dyn CompilerBackendAdapter>>,
}

impl CompilerTrackRunner {
    pub fn new() -> Self {
        Self {
            backend_adapters: Vec::new(),
        }
    }

    pub fn with_backend_adapter(mut self, adapter: Box<dyn CompilerBackendAdapter>) -> Self {
        self.backend_adapters.push(adapter);
        self
    }

    pub fn backend_adapter_count(&self) -> usize {
        self.backend_adapters.len()
    }
}

#[async_trait]
impl TrackRunner for CompilerTrackRunner {
    fn track(&self) -> TrackKind {
        TrackKind::Compiler
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
    fn exposes_compiler_track_kind() {
        assert_eq!(CompilerTrackRunner::new().track(), TrackKind::Compiler);
    }

    #[test]
    fn reports_backend_adapter_count() {
        let runner = CompilerTrackRunner::new();
        assert_eq!(runner.backend_adapter_count(), 0);
    }

    #[test]
    fn exposes_track_version() {
        assert!(!TRACK_MODULE_VERSION.is_empty());
    }
}
