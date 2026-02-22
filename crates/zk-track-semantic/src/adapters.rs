use async_trait::async_trait;
use zk_postroadmap_core::PostRoadmapResult;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SemanticIntent {
    pub source: String,
    pub invariants: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExploitabilityAssessment {
    pub exploitable: bool,
    pub rationale: String,
    pub confidence: u8,
}

#[async_trait]
pub trait SemanticIntentAdapter: Send + Sync {
    fn provider_name(&self) -> &'static str;
    async fn extract_intent(&self, source_text: &str) -> PostRoadmapResult<SemanticIntent>;
    async fn classify_exploitability(
        &self,
        intent: &SemanticIntent,
        violation_summary: &str,
    ) -> PostRoadmapResult<ExploitabilityAssessment>;
}
