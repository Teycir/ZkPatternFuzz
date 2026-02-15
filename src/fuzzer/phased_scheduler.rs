//! Phased Attack Scheduler for ZkPatternFuzz
//!
//! Executes attacks in configurable phases with time budgets,
//! corpus carryover between phases, and early termination conditions.
//!
//! # Example
//!
//! ```yaml
//! schedule:
//!   - phase: "seed"
//!     duration_sec: 60
//!     attacks: ["underconstrained"]
//!   - phase: "deep"
//!     duration_sec: 600
//!     attacks: ["soundness", "collision"]
//! ```

use crate::config::v2::{EarlyTerminateCondition, SchedulePhase};
use crate::config::FuzzConfig;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use zk_core::{AttackType, FieldElement, Finding};

/// Phase execution result
#[derive(Debug, Clone)]
pub struct PhaseResult {
    /// Phase name
    pub phase_name: String,
    /// Duration of phase execution
    pub duration: Duration,
    /// Findings discovered in this phase
    pub findings: Vec<Finding>,
    /// Coverage percentage at end of phase
    pub coverage_percentage: f64,
    /// Corpus size at end of phase
    pub corpus_size: usize,
    /// Whether phase terminated early
    pub early_terminated: bool,
    /// Reason for early termination (if any)
    pub termination_reason: Option<String>,
}

/// Statistics tracked during phased execution
#[derive(Debug, Clone, Default)]
pub struct PhasedSchedulerStats {
    /// Results for each completed phase
    pub phase_results: Vec<PhaseResult>,
    /// Total findings across all phases
    pub total_findings: usize,
    /// Total execution time
    pub total_duration: Duration,
    /// Current phase index
    pub current_phase: usize,
    /// Whether scheduling is complete
    pub completed: bool,
}

/// Callback trait for phase lifecycle events
pub trait PhaseCallback: Send + Sync {
    /// Called when a phase starts
    fn on_phase_start(&self, phase: &SchedulePhase, phase_index: usize);

    /// Called when a phase completes
    fn on_phase_complete(&self, result: &PhaseResult, phase_index: usize);

    /// Called periodically during phase execution
    fn on_phase_progress(&self, phase_name: &str, elapsed: Duration, coverage: f64);
}

/// Default no-op callback
pub struct NoopPhaseCallback;

impl PhaseCallback for NoopPhaseCallback {
    fn on_phase_start(&self, _phase: &SchedulePhase, _phase_index: usize) {}
    fn on_phase_complete(&self, _result: &PhaseResult, _phase_index: usize) {}
    fn on_phase_progress(&self, _phase_name: &str, _elapsed: Duration, _coverage: f64) {}
}

/// Logging callback for phase events
pub struct LoggingPhaseCallback;

impl PhaseCallback for LoggingPhaseCallback {
    fn on_phase_start(&self, phase: &SchedulePhase, phase_index: usize) {
        tracing::info!(
            "Starting phase {} ({}/{}): {} attacks, {} sec budget",
            phase.phase,
            phase_index + 1,
            "?", // Total phases not known here
            phase.attacks.len(),
            phase.duration_sec
        );
    }

    fn on_phase_complete(&self, result: &PhaseResult, phase_index: usize) {
        tracing::info!(
            "Completed phase {} ({}): {} findings, {:.1}% coverage, {:?}{}",
            result.phase_name,
            phase_index + 1,
            result.findings.len(),
            result.coverage_percentage,
            result.duration,
            if result.early_terminated {
                format!(
                    " [early: {}]",
                    match result.termination_reason.as_deref() {
                        Some(reason) => reason,
                        None => "unknown",
                    }
                )
            } else {
                String::new()
            }
        );
    }

    fn on_phase_progress(&self, phase_name: &str, elapsed: Duration, coverage: f64) {
        tracing::debug!(
            "Phase {} progress: {:?} elapsed, {:.1}% coverage",
            phase_name,
            elapsed,
            coverage
        );
    }
}

/// Phased attack scheduler
pub struct PhasedScheduler {
    /// Schedule phases to execute
    phases: Vec<SchedulePhase>,
    /// Shared corpus between phases
    corpus: Arc<RwLock<Vec<Vec<FieldElement>>>>,
    /// Phase callback
    callback: Arc<dyn PhaseCallback>,
    /// Current statistics
    stats: Arc<RwLock<PhasedSchedulerStats>>,
}

impl PhasedScheduler {
    /// Create a new phased scheduler from schedule configuration
    pub fn new(phases: Vec<SchedulePhase>) -> Self {
        Self {
            phases,
            corpus: Arc::new(RwLock::new(Vec::new())),
            callback: Arc::new(LoggingPhaseCallback),
            stats: Arc::new(RwLock::new(PhasedSchedulerStats::default())),
        }
    }

    /// Create scheduler from FuzzConfig
    pub fn from_config(config: &FuzzConfig) -> Self {
        let phases = config.get_schedule();
        if phases.is_empty() {
            // Default single-phase schedule
            Self::new(vec![SchedulePhase {
                phase: "default".to_string(),
                duration_sec: config.campaign.parameters.timeout_seconds,
                attacks: config
                    .attacks
                    .iter()
                    .map(|a| format!("{:?}", a.attack_type).to_lowercase())
                    .collect(),
                max_iterations: None,
                early_terminate: None,
                carry_corpus: true,
                mutation_weights: HashMap::new(),
            }])
        } else {
            Self::new(phases)
        }
    }

    /// Set phase callback
    pub fn with_callback(mut self, callback: Arc<dyn PhaseCallback>) -> Self {
        self.callback = callback;
        self
    }

    /// Get current statistics
    pub async fn stats(&self) -> PhasedSchedulerStats {
        self.stats.read().await.clone()
    }

    /// Execute all phases
    pub async fn execute<F, Fut>(
        &self,
        config: &FuzzConfig,
        executor: F,
    ) -> anyhow::Result<Vec<PhaseResult>>
    where
        F: Fn(FuzzConfig, Arc<RwLock<Vec<Vec<FieldElement>>>>) -> Fut + Send + Sync,
        Fut: std::future::Future<Output = anyhow::Result<PhaseExecutionResult>>,
    {
        let mut results = Vec::new();
        let start_time = Instant::now();

        for (phase_index, phase) in self.phases.iter().enumerate() {
            // Update current phase
            {
                let mut stats = self.stats.write().await;
                stats.current_phase = phase_index;
            }

            // Notify callback
            self.callback.on_phase_start(phase, phase_index);

            // Build phase-specific config
            let phase_config = self.build_phase_config(config, phase);

            // Execute phase
            let phase_start = Instant::now();
            let exec_result = executor(phase_config, self.corpus.clone()).await?;

            // Build phase result
            let phase_result = PhaseResult {
                phase_name: phase.phase.clone(),
                duration: phase_start.elapsed(),
                findings: exec_result.findings.clone(),
                coverage_percentage: exec_result.coverage_percentage,
                corpus_size: exec_result.corpus_size,
                early_terminated: exec_result.early_terminated,
                termination_reason: exec_result.termination_reason.clone(),
            };

            // Notify callback
            self.callback.on_phase_complete(&phase_result, phase_index);

            // Update stats
            {
                let mut stats = self.stats.write().await;
                stats.total_findings += phase_result.findings.len();
                stats.phase_results.push(phase_result.clone());
            }

            results.push(phase_result.clone());

            // Check for early termination of entire schedule
            if self.should_terminate_schedule(&phase_result, phase) {
                tracing::info!(
                    "Terminating schedule after phase {} due to {:?}",
                    phase.phase,
                    phase_result.termination_reason
                );
                break;
            }

            // Clear corpus if not carrying over
            if !phase.carry_corpus {
                let mut corpus = self.corpus.write().await;
                corpus.clear();
            }
        }

        // Mark complete
        {
            let mut stats = self.stats.write().await;
            stats.completed = true;
            stats.total_duration = start_time.elapsed();
        }

        Ok(results)
    }

    /// Build phase-specific configuration
    fn build_phase_config(&self, base_config: &FuzzConfig, phase: &SchedulePhase) -> FuzzConfig {
        let mut config = base_config.clone();

        // Filter attacks to only those in this phase
        config.attacks.retain(|a| {
            let attack_name = format!("{:?}", a.attack_type).to_lowercase();
            phase.attacks.iter().any(|p| {
                p.to_lowercase() == attack_name || p.to_lowercase() == attack_name.replace("_", "")
            })
        });

        // Set phase timeout
        config.campaign.parameters.timeout_seconds = phase.duration_sec;
        config.campaign.parameters.additional.insert(
            "fuzzing_timeout_seconds".to_string(),
            serde_yaml::Value::Number(phase.duration_sec.into()),
        );

        // Add phase-specific parameters
        config.campaign.parameters.additional.insert(
            "phase_name".to_string(),
            serde_yaml::Value::String(phase.phase.clone()),
        );

        if let Some(max_iter) = phase.max_iterations {
            config.campaign.parameters.additional.insert(
                "max_iterations".to_string(),
                serde_yaml::Value::Number(max_iter.into()),
            );
        }

        // Apply mutation weights
        if !phase.mutation_weights.is_empty() {
            let mutation_weights = match serde_yaml::to_value(&phase.mutation_weights) {
                Ok(value) => value,
                Err(err) => {
                    panic!(
                        "Failed to serialize phase mutation weights for '{}': {}",
                        phase.phase, err
                    )
                }
            };
            config
                .campaign
                .parameters
                .additional
                .insert("mutation_weights".to_string(), mutation_weights);
        }

        config
    }

    /// Check if entire schedule should terminate
    fn should_terminate_schedule(&self, result: &PhaseResult, phase: &SchedulePhase) -> bool {
        if let Some(ref early) = phase.early_terminate {
            // Check critical findings
            if let Some(threshold) = early.on_critical_findings {
                let critical_count = result
                    .findings
                    .iter()
                    .filter(|f| f.severity == zk_core::Severity::Critical)
                    .count();
                if critical_count >= threshold as usize {
                    return true;
                }
            }
        }
        false
    }

    /// Parse attack type from string
    pub fn parse_attack_type(s: &str) -> Option<AttackType> {
        match s.to_lowercase().as_str() {
            "underconstrained" => Some(AttackType::Underconstrained),
            "soundness" => Some(AttackType::Soundness),
            "arithmetic_overflow" | "arithmeticoverflow" => Some(AttackType::ArithmeticOverflow),
            "collision" => Some(AttackType::Collision),
            "boundary" => Some(AttackType::Boundary),
            "constraint_bypass" | "constraintbypass" => Some(AttackType::ConstraintBypass),
            "witness_leakage" | "witnessleakage" => Some(AttackType::WitnessLeakage),
            "replay_attack" | "replayattack" => Some(AttackType::ReplayAttack),
            "bit_decomposition" | "bitdecomposition" => Some(AttackType::BitDecomposition),
            "malleability" => Some(AttackType::Malleability),
            "verification_fuzzing" | "verificationfuzzing" => Some(AttackType::VerificationFuzzing),
            "witness_fuzzing" | "witnessfuzzing" => Some(AttackType::WitnessFuzzing),
            "differential" => Some(AttackType::Differential),
            _ => None,
        }
    }
}

/// Result from executing a single phase
#[derive(Debug, Clone)]
pub struct PhaseExecutionResult {
    pub findings: Vec<Finding>,
    pub coverage_percentage: f64,
    pub corpus_size: usize,
    pub early_terminated: bool,
    pub termination_reason: Option<String>,
}

/// Early termination checker
pub struct EarlyTerminationChecker {
    condition: EarlyTerminateCondition,
    #[allow(dead_code)]
    start_time: Instant,
    last_coverage_time: Instant,
    last_coverage: f64,
    critical_findings: usize,
}

impl EarlyTerminationChecker {
    pub fn new(condition: EarlyTerminateCondition) -> Self {
        let now = Instant::now();
        Self {
            condition,
            start_time: now,
            last_coverage_time: now,
            last_coverage: 0.0,
            critical_findings: 0,
        }
    }

    /// Update with current state and check for termination
    pub fn check(&mut self, coverage: f64, new_critical_findings: usize) -> Option<String> {
        // Update tracking
        self.critical_findings += new_critical_findings;

        // Check critical findings threshold
        if let Some(threshold) = self.condition.on_critical_findings {
            if self.critical_findings >= threshold as usize {
                return Some(format!(
                    "Critical findings threshold reached ({} >= {})",
                    self.critical_findings, threshold
                ));
            }
        }

        // Check coverage threshold
        if let Some(target) = self.condition.on_coverage_percent {
            if coverage >= target {
                return Some(format!(
                    "Coverage target reached ({:.1}% >= {:.1}%)",
                    coverage, target
                ));
            }
        }

        // Check stale coverage
        if let Some(stale_sec) = self.condition.on_stale_seconds {
            if (coverage - self.last_coverage).abs() > 0.01 {
                // Coverage changed
                self.last_coverage = coverage;
                self.last_coverage_time = Instant::now();
            } else if self.last_coverage_time.elapsed().as_secs() >= stale_sec {
                return Some(format!("Coverage stale for {} seconds", stale_sec));
            }
        }

        None
    }
}

/// Builder for phase schedules
pub struct ScheduleBuilder {
    phases: Vec<SchedulePhase>,
}

impl ScheduleBuilder {
    pub fn new() -> Self {
        Self { phases: Vec::new() }
    }

    /// Add an exploration phase
    pub fn exploration(mut self, duration_sec: u64) -> Self {
        self.phases.push(SchedulePhase {
            phase: "exploration".to_string(),
            duration_sec,
            attacks: vec!["underconstrained".to_string(), "boundary".to_string()],
            max_iterations: None,
            early_terminate: Some(EarlyTerminateCondition {
                on_critical_findings: Some(5),
                on_coverage_percent: None,
                on_stale_seconds: Some(30),
            }),
            carry_corpus: true,
            mutation_weights: HashMap::new(),
        });
        self
    }

    /// Add a deep testing phase
    pub fn deep_testing(mut self, duration_sec: u64) -> Self {
        self.phases.push(SchedulePhase {
            phase: "deep_testing".to_string(),
            duration_sec,
            attacks: vec![
                "soundness".to_string(),
                "arithmetic_overflow".to_string(),
                "collision".to_string(),
            ],
            max_iterations: None,
            early_terminate: None,
            carry_corpus: true,
            mutation_weights: HashMap::new(),
        });
        self
    }

    /// Add a custom phase
    pub fn phase(mut self, phase: SchedulePhase) -> Self {
        self.phases.push(phase);
        self
    }

    /// Build the scheduler
    pub fn build(self) -> PhasedScheduler {
        PhasedScheduler::new(self.phases)
    }
}

impl Default for ScheduleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schedule_builder() {
        let scheduler = ScheduleBuilder::new()
            .exploration(60)
            .deep_testing(300)
            .build();

        assert_eq!(scheduler.phases.len(), 2);
        assert_eq!(scheduler.phases[0].phase, "exploration");
        assert_eq!(scheduler.phases[1].phase, "deep_testing");
    }

    #[test]
    fn test_parse_attack_type() {
        assert_eq!(
            PhasedScheduler::parse_attack_type("underconstrained"),
            Some(AttackType::Underconstrained)
        );
        assert_eq!(
            PhasedScheduler::parse_attack_type("SOUNDNESS"),
            Some(AttackType::Soundness)
        );
        assert_eq!(
            PhasedScheduler::parse_attack_type("arithmetic_overflow"),
            Some(AttackType::ArithmeticOverflow)
        );
        assert_eq!(PhasedScheduler::parse_attack_type("unknown"), None);
    }

    #[test]
    fn test_early_termination_critical_findings() {
        let condition = EarlyTerminateCondition {
            on_critical_findings: Some(3),
            on_coverage_percent: None,
            on_stale_seconds: None,
        };

        let mut checker = EarlyTerminationChecker::new(condition);

        assert!(checker.check(0.0, 1).is_none());
        assert!(checker.check(0.0, 1).is_none());
        assert!(checker.check(0.0, 1).is_some()); // 3rd critical finding
    }

    #[test]
    fn test_early_termination_coverage() {
        let condition = EarlyTerminateCondition {
            on_critical_findings: None,
            on_coverage_percent: Some(80.0),
            on_stale_seconds: None,
        };

        let mut checker = EarlyTerminationChecker::new(condition);

        assert!(checker.check(50.0, 0).is_none());
        assert!(checker.check(75.0, 0).is_none());
        assert!(checker.check(80.0, 0).is_some()); // Coverage target reached
    }
}
