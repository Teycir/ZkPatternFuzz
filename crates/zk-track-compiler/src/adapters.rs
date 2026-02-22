use async_trait::async_trait;
use zk_postroadmap_core::PostRoadmapResult;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompilerGenerationRequest {
    pub seed: u64,
    pub max_constraints: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompilerGenerationResult {
    pub source_path: String,
    pub backend_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompilerCrashClass {
    Timeout,
    InternalCompilerError,
    Panic,
    UserError,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompilerDiagnostic {
    pub class: Option<CompilerCrashClass>,
    pub message: String,
}

#[async_trait]
pub trait CompilerBackendAdapter: Send + Sync {
    fn backend_name(&self) -> &'static str;
    async fn generate(
        &self,
        request: &CompilerGenerationRequest,
    ) -> PostRoadmapResult<CompilerGenerationResult>;
    async fn compile(&self, source_path: &str) -> PostRoadmapResult<CompilerDiagnostic>;
}
