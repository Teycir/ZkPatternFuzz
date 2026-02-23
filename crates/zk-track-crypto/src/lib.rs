mod curve_fuzzer;
mod field_fuzzer;
mod generators;
mod oracle;
mod pairing_fuzzer;
mod property_checker;

use std::path::PathBuf;

use async_trait::async_trait;
use zk_postroadmap_core::{PostRoadmapResult, TrackExecution, TrackInput, TrackKind, TrackRunner};

pub use curve_fuzzer::{
    run_curve_operation_fuzz_campaign, CurveEdgeCase, CurveImplementationProfile, CurveOperation,
    CurveOperationFuzzConfig, CurveOperationFuzzFinding, CurveOperationFuzzReport,
};
pub use field_fuzzer::{
    run_field_arithmetic_fuzz_campaign, FieldArithmeticFuzzConfig, FieldArithmeticFuzzFinding,
    FieldArithmeticFuzzReport, FieldImplementationProfile, FieldOperation, FieldProperty,
};
pub use generators::{
    field_modulus, generate_curve_point, generate_field_edge_values, generate_field_values,
    generate_pairing_input, CurvePointSample, CurvePointType, PairingInputSample, PairingInputType,
    TOY_CURVE_ORDER, TOY_PAIRING_GENERATOR, TOY_PAIRING_ORDER, TOY_PAIRING_TARGET_MODULUS,
};
pub use pairing_fuzzer::{
    run_pairing_fuzz_campaign, PairingFuzzConfig, PairingFuzzFinding, PairingFuzzReport,
    PairingImplementationProfile, PairingProperty,
};

pub const TRACK_MODULE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Default)]
pub struct CryptoTrackRunner;

impl CryptoTrackRunner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TrackRunner for CryptoTrackRunner {
    fn track(&self) -> TrackKind {
        TrackKind::Crypto
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
    fn exposes_crypto_track_kind() {
        assert_eq!(CryptoTrackRunner::new().track(), TrackKind::Crypto);
    }

    #[test]
    fn exposes_track_version() {
        assert!(!TRACK_MODULE_VERSION.is_empty());
    }
}
