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
//!
//! ## Adaptive Orchestrator
//!
//! The [`adaptive_orchestrator`] module implements the endgame workflow for
//! catching hard-to-detect zero-day vulnerabilities using Opus analysis.
//!
//! ## Performance Optimizations (Phase 4.4)
//!
//! The [`constraint_cache`] module provides thread-safe constraint evaluation caching.
//! The [`async_pipeline`] module provides async execution pipeline for high throughput.

pub mod adaptive_attack_scheduler;
pub mod adaptive_orchestrator;
pub mod async_pipeline; // Phase 4.4: Async execution pipeline
mod constants;
pub mod constraint_cache; // Phase 4.4: Constraint evaluation caching
mod engine;
pub mod grammar;
pub mod invariant_checker; // Phase 2: Fuzz-continuous invariant checking
mod mutators;
pub mod near_miss;
mod oracle;
pub mod oracle_correlation; // Phase 6A: Cross-oracle correlation
pub mod oracle_diversity;
pub mod oracle_state; // Phase 5.7: Bounded oracle state management
pub mod oracle_validation; // Phase 0 Fix: Oracle validation framework
pub mod oracles;
pub mod phased_scheduler;
mod power_schedule;
pub mod structure_aware;

pub use adaptive_attack_scheduler::{
    AdaptiveScheduler, AdaptiveSchedulerConfig, AdaptiveSchedulerStats, AttackResults,
    NearMissEvent, SuggestionType, YamlSuggestion,
};
pub use adaptive_orchestrator::{
    AdaptiveCampaignResults, AdaptiveOrchestrator, AdaptiveOrchestratorBuilder,
    AdaptiveOrchestratorConfig, ConfirmedZeroDay,
};
pub use constants::*;
pub use engine::FuzzingEngine;
pub use mutators::*;
pub use near_miss::{NearMiss, NearMissConfig, NearMissDetector, NearMissStats};
pub use oracle::*;
pub use oracle_diversity::{OracleDiversityStats, OracleDiversityTracker, OracleFire};
pub use oracles::{
    CombinedSemanticOracle, CommitmentOracle, MerkleOracle, NullifierOracle, OracleConfig,
    OracleStats, RangeProofOracle, SemanticOracle,
};
pub use phased_scheduler::{PhaseExecutionResult, PhaseResult, PhasedScheduler, ScheduleBuilder};
pub use zk_core::{CoverageMap, FieldElement, Finding, ProofOfConcept, TestCase, TestMetadata};

use crate::config::*;
use crate::progress::ProgressReporter;
use crate::reporting::FuzzReport;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// Main fuzzer engine
pub struct ZkFuzzer {
    config: FuzzConfig,
    seed: Option<u64>,
}

#[derive(Debug, Clone)]
struct PhaseRunSummary {
    findings: Vec<Finding>,
    max_coverage: u64,
    executions: u64,
    duration_seconds: u64,
}

impl ZkFuzzer {
    /// Create a new fuzzer with the given configuration
    pub fn new(config: FuzzConfig, seed: Option<u64>) -> Self {
        Self { config, seed }
    }

    /// Create and run using the new engine with progress reporting
    pub async fn run_with_progress(
        config: FuzzConfig,
        seed: Option<u64>,
        workers: usize,
        verbose: bool,
    ) -> anyhow::Result<FuzzReport> {
        if !config.get_schedule().is_empty() {
            return Self::run_with_schedule(config, seed, workers).await;
        }

        // Calculate total iterations for progress bar
        let total: u64 = config
            .attacks
            .iter()
            .map(|a| {
                a.config
                    .get("witness_pairs")
                    .and_then(|v| v.as_u64())
                    .map(|value| value)
                    .or_else(|| Some(1000))
                    .expect("default witness_pairs injected")
                    + a.config
                        .get("forge_attempts")
                        .and_then(|v| v.as_u64())
                        .map(|value| value)
                        .or_else(|| Some(0))
                        .expect("default forge_attempts injected")
                    + a.config
                        .get("samples")
                        .and_then(|v| v.as_u64())
                        .map(|value| value)
                        .or_else(|| Some(0))
                        .expect("default samples injected")
            })
            .sum();

        let progress = ProgressReporter::new(&config.campaign.name, total.max(1000), verbose);

        let mut engine = FuzzingEngine::new(config, seed, workers)?;
        let report = engine.run(Some(&progress)).await?;

        progress.finish(&engine.stats());

        Ok(report)
    }

    /// Run the fuzzing campaign
    pub async fn run(&mut self) -> anyhow::Result<FuzzReport> {
        self.run_with_workers(1).await
    }

    /// Run the fuzzing campaign without progress UI, honoring worker count
    pub async fn run_with_workers(&mut self, workers: usize) -> anyhow::Result<FuzzReport> {
        if !self.config.get_schedule().is_empty() {
            return Self::run_with_schedule(self.config.clone(), self.seed, workers).await;
        }

        let mut engine = FuzzingEngine::new(self.config.clone(), self.seed, workers)?;
        engine.run(None).await
    }

    async fn run_with_schedule(
        config: FuzzConfig,
        seed: Option<u64>,
        workers: usize,
    ) -> anyhow::Result<FuzzReport> {
        let scheduler = PhasedScheduler::from_config(&config);
        let summaries: Arc<Mutex<Vec<PhaseRunSummary>>> = Arc::new(Mutex::new(Vec::new()));
        let union_constraints: Arc<Mutex<HashSet<usize>>> = Arc::new(Mutex::new(HashSet::new()));
        let base_output_dir = config.reporting.output_dir.clone();

        let corpus_limit = config
            .campaign
            .parameters
            .additional
            .get("phase_corpus_limit")
            .and_then(|v| v.as_u64())
            .map(|value| value)
            .or_else(|| Some(500))
            .expect("default phase corpus limit injected") as usize;

        scheduler
            .execute(&config, {
                let summaries = summaries.clone();
                let union_constraints = union_constraints.clone();
                let base_output_dir = base_output_dir.clone();
                move |mut phase_config, corpus| {
                    let summaries = summaries.clone();
                    let union_constraints = union_constraints.clone();
                    let base_output_dir = base_output_dir.clone();
                    async move {
                        if let Some(phase_name) = phase_config
                            .campaign
                            .parameters
                            .additional
                            .get("phase_name")
                            .and_then(|v| v.as_str())
                        {
                            phase_config.reporting.output_dir =
                                base_output_dir.join("phases").join(phase_name);
                        }

                        let mut engine = FuzzingEngine::new(phase_config, seed, workers)?;

                        let seed_inputs = {
                            let corpus = corpus.read().await;
                            corpus.clone()
                        };

                        if !seed_inputs.is_empty() {
                            engine.seed_corpus_from_inputs(&seed_inputs);
                        }

                        let report = engine.run(None).await?;

                        let phase_constraints = engine.coverage_constraint_ids();
                        if let Ok(mut guard) = union_constraints.lock() {
                            guard.extend(phase_constraints);
                        }

                        let new_inputs = engine.collect_corpus_inputs(corpus_limit);
                        {
                            let mut corpus = corpus.write().await;
                            corpus.clear();
                            corpus.extend(new_inputs);
                        }

                        let summary = PhaseRunSummary {
                            findings: report.findings.clone(),
                            max_coverage: engine.max_coverage(),
                            executions: report.statistics.total_executions,
                            duration_seconds: report.duration_seconds,
                        };
                        if let Ok(mut guard) = summaries.lock() {
                            guard.push(summary);
                        }

                        Ok(PhaseExecutionResult {
                            findings: report.findings,
                            coverage_percentage: report.statistics.coverage_percentage,
                            corpus_size: engine.corpus_len(),
                            early_terminated: false,
                            termination_reason: None,
                        })
                    }
                }
            })
            .await?;

        let summaries = summaries
            .lock()
            .map_err(|_| anyhow::anyhow!("phase summaries mutex poisoned"))?
            .clone();

        let mut findings = Vec::new();
        let mut total_exec = 0u64;
        let mut total_duration = 0u64;
        let mut max_coverage = 0u64;

        for summary in summaries {
            findings.extend(summary.findings);
            total_exec += summary.executions;
            total_duration += summary.duration_seconds;
            max_coverage = max_coverage.max(summary.max_coverage);
        }

        let edge_coverage = union_constraints
            .lock()
            .map_err(|_| anyhow::anyhow!("union constraints mutex poisoned"))?
            .len() as u64;

        let mut report = FuzzReport::new(
            config.campaign.name.clone(),
            findings,
            CoverageMap {
                constraint_hits: std::collections::HashMap::new(),
                edge_coverage,
                max_coverage,
            },
            config.reporting.clone(),
        );
        report.duration_seconds = total_duration;
        report.statistics.total_executions = total_exec;

        Ok(report)
    }
}
