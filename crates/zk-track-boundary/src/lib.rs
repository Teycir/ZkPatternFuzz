mod adapters;
mod public_input_fuzzer;
mod serialization_fuzzer;
mod solidity_verifier_fuzzer;

use std::path::PathBuf;

use async_trait::async_trait;
use zk_postroadmap_core::{PostRoadmapResult, TrackExecution, TrackInput, TrackKind, TrackRunner};

pub use adapters::{
    BoundaryProtocolAdapter, BoundaryProtocolCase, BoundaryProtocolResult, SerializationAdapter,
    VerifierAdapter,
};
pub use public_input_fuzzer::{
    run_public_input_manipulation_campaign, PublicInputAttackScenario,
    PublicInputManipulationConfig, PublicInputManipulationFinding, PublicInputManipulationReport,
    PublicInputMutationStrategy, PublicInputVerifierProfile,
};
pub use serialization_fuzzer::{
    run_serialization_fuzz_campaign, CrossLanguageSerializationCase, ProofSerializationEdgeCase,
    PublicInputSerializationEdgeCase, SerializationFormat, SerializationFuzzConfig,
    SerializationFuzzFinding, SerializationFuzzReport, SerializationVerifierProfile,
};
pub use solidity_verifier_fuzzer::{
    run_solidity_verifier_fuzz_campaign, PairingManipulationCase, SolidityEdgeCase,
    SolidityVerifierFinding, SolidityVerifierFuzzConfig, SolidityVerifierFuzzReport,
    SolidityVerifierProfile, VerifierInputMutation,
};

pub const TRACK_MODULE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default)]
pub struct BoundaryTrackRunner {
    protocol_adapters: Vec<Box<dyn BoundaryProtocolAdapter>>,
}

impl BoundaryTrackRunner {
    pub fn new() -> Self {
        Self {
            protocol_adapters: Vec::new(),
        }
    }

    pub fn with_protocol_adapter(mut self, adapter: Box<dyn BoundaryProtocolAdapter>) -> Self {
        self.protocol_adapters.push(adapter);
        self
    }

    pub fn protocol_adapter_count(&self) -> usize {
        self.protocol_adapters.len()
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
        let _protocol_adapters = self.protocol_adapters.len();
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

    #[test]
    fn reports_protocol_adapter_count() {
        let runner = BoundaryTrackRunner::new();
        assert_eq!(runner.protocol_adapter_count(), 0);
    }

    #[test]
    fn exposes_track_version() {
        assert!(!TRACK_MODULE_VERSION.is_empty());
    }
}
