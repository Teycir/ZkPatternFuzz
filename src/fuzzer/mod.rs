//! Core fuzzing engine for ZK circuits

mod constants;
mod mutators;
mod oracle;
mod engine;
mod power_schedule;
mod structure_aware;
pub mod grammar;
pub mod oracles;

pub use constants::*;
pub use mutators::*;
pub use oracle::*;
pub use engine::FuzzingEngine;
pub use oracles::{
    SemanticOracle, OracleConfig, OracleStats, CombinedSemanticOracle,
    NullifierOracle, MerkleOracle, CommitmentOracle, RangeProofOracle,
};
pub use zk_core::{CoverageMap, FieldElement, Finding, ProofOfConcept, TestCase, TestMetadata};

use crate::config::*;
use crate::progress::ProgressReporter;
use crate::reporting::FuzzReport;

/// Main fuzzer engine
pub struct ZkFuzzer {
    config: FuzzConfig,
    seed: Option<u64>,
}

impl ZkFuzzer {
    /// Create a new fuzzer with the given configuration
    pub fn new(config: FuzzConfig, seed: Option<u64>) -> Self {
        Self {
            config,
            seed,
        }
    }

    /// Create and run using the new engine with progress reporting
    pub async fn run_with_progress(
        config: FuzzConfig,
        seed: Option<u64>,
        workers: usize,
        verbose: bool,
    ) -> anyhow::Result<FuzzReport> {
        // Calculate total iterations for progress bar
        let total: u64 = config.attacks.iter().map(|a| {
            a.config.get("witness_pairs").and_then(|v| v.as_u64()).unwrap_or(1000)
            + a.config.get("forge_attempts").and_then(|v| v.as_u64()).unwrap_or(0)
            + a.config.get("samples").and_then(|v| v.as_u64()).unwrap_or(0)
        }).sum();

        let progress = ProgressReporter::new(&config.campaign.name, total.max(1000), verbose);

        let mut engine = FuzzingEngine::new(config, seed, workers)?;
        let report = engine.run(Some(&progress)).await?;

        progress.finish(&engine.stats());

        Ok(report)
    }

    /// Run the fuzzing campaign
    pub async fn run(&mut self) -> anyhow::Result<FuzzReport> {
        let mut engine = FuzzingEngine::new(self.config.clone(), self.seed, 1)?;
        engine.run(None).await
    }
}
