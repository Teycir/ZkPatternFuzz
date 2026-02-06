//! Core fuzzing engine for ZK circuits
//!
//! ## Phased Scheduling
//!
//! The [`phased_scheduler`] module enables time-budgeted attack phases with
//! corpus carryover and early termination conditions.
//!
//! ## Oracle Diversity
//!
//! The [`oracle_diversity`] module tracks which oracle types fire during
//! fuzzing and measures violation pattern diversity.
//!
//! ## Adaptive Scheduling
//!
//! The [`adaptive_attack_scheduler`] module dynamically reallocates budget
//! between attack types based on their effectiveness.
//!
//! ## Near-Miss Detection
//!
//! The [`near_miss`] module detects when oracles are "almost" triggered,
//! providing feedback for intelligent mutation.

mod constants;
mod mutators;
mod oracle;
mod engine;
pub mod adaptive_attack_scheduler;
pub mod near_miss;
pub mod oracle_diversity;
pub mod phased_scheduler;
mod power_schedule;
mod structure_aware;
pub mod grammar;
pub mod oracles;

pub use constants::*;
pub use mutators::*;
pub use oracle::*;
pub use engine::FuzzingEngine;
pub use adaptive_attack_scheduler::{
    AdaptiveScheduler, AdaptiveSchedulerConfig, AdaptiveSchedulerStats,
    AttackResults, NearMissEvent, YamlSuggestion, SuggestionType,
};
pub use near_miss::{NearMissDetector, NearMiss, NearMissConfig, NearMissStats};
pub use oracle_diversity::{OracleDiversityTracker, OracleDiversityStats, OracleFire};
pub use oracles::{
    SemanticOracle, OracleConfig, OracleStats, CombinedSemanticOracle,
    NullifierOracle, MerkleOracle, CommitmentOracle, RangeProofOracle,
};
pub use phased_scheduler::{PhasedScheduler, PhaseResult, ScheduleBuilder, PhaseExecutionResult};
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
