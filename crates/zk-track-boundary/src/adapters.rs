use async_trait::async_trait;
use zk_postroadmap_core::PostRoadmapResult;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BoundaryProtocolCase {
    pub case_id: String,
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BoundaryProtocolResult {
    pub accepted: bool,
    pub notes: Vec<String>,
}

#[async_trait]
pub trait VerifierAdapter: Send + Sync {
    async fn verify(
        &self,
        proof_bytes: &[u8],
        public_inputs: &[Vec<u8>],
    ) -> PostRoadmapResult<bool>;
}

pub trait SerializationAdapter: Send + Sync {
    fn encode_public_inputs(&self, public_inputs: &[String]) -> PostRoadmapResult<Vec<Vec<u8>>>;
}

#[async_trait]
pub trait BoundaryProtocolAdapter: Send + Sync {
    fn protocol_name(&self) -> &'static str;
    fn verifier(&self) -> &dyn VerifierAdapter;
    fn serialization(&self) -> &dyn SerializationAdapter;

    async fn run_case(
        &self,
        case: &BoundaryProtocolCase,
    ) -> PostRoadmapResult<BoundaryProtocolResult> {
        let encoded_inputs = self
            .serialization()
            .encode_public_inputs(&case.public_inputs)?;
        let accepted = self
            .verifier()
            .verify(&case.proof_bytes, &encoded_inputs)
            .await?;
        Ok(BoundaryProtocolResult {
            accepted,
            notes: vec![],
        })
    }
}
