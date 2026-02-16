use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) async fn run_continuous_fuzzing_phase(
        &mut self,
        iterations: u64,
        timeout_seconds: Option<u64>,
        progress: Option<&ProgressReporter>,
        mode_label: &str,
        phases_total: u64,
        phases_completed_base: u64,
    ) -> anyhow::Result<()> {
        let start = Instant::now();
        let timeout = timeout_seconds.map(Duration::from_secs);

        // Phase 0 Fix: Per-execution timeout for hang detection (configurable, default 30s)
        let additional = &self.config.campaign.parameters.additional;
        let execution_timeout_ms = Self::additional_u64(additional, "execution_timeout_ms")
            .or_else(|| Self::additional_u64(additional, "timeout_per_execution").map(|v| v * 1000))
            .map(|value| value)
            .or_else(|| Some(30_000))
            .expect("default timeout injected")
            .max(1);

        let minimize_enabled = match Self::additional_bool(additional, "corpus_minimize_enabled") {
            Some(value) => value,
            None => true,
        };
        let minimize_interval = Self::additional_u64(additional, "corpus_minimize_interval")
            .map(|value| value)
            .or_else(|| Some(10_000))
            .expect("default minimize interval injected")
            .max(1);
        let minimize_min_size = Self::additional_u64(additional, "corpus_minimize_min_size")
            .map(|value| value)
            .or_else(|| Some(1_000))
            .expect("default minimize min size injected")
            .max(1) as usize;
        let execution_timeout = Duration::from_millis(execution_timeout_ms);

        tracing::info!(
            "Starting continuous fuzzing phase: {} iterations, timeout: {:?}, per-exec timeout: {:?}",
            iterations,
            timeout,
            execution_timeout
        );

        let mut completed = 0u64;
        let mut hang_count = 0u64;
        let mut crash_count = 0u64;
        let mut accepted_count = 0u64;
        let mut failed_count = 0u64;
        let mut sample_errors: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut last_progress_write = Instant::now();

        while completed < iterations {
            // Check overall timeout
            if let Some(t) = timeout {
                if start.elapsed() >= t {
                    tracing::info!(
                        "Continuous fuzzing timeout reached after {} iterations",
                        completed
                    );
                    break;
                }
            }

            // Core fuzzing loop: select_from_corpus → mutate → execute_and_learn
            let test_case = self.generate_test_case();

            // Phase 0 Fix: Execute with timeout for hang detection
            let exec_start = Instant::now();
            let result = self.execute_and_learn(&test_case);
            let exec_duration = exec_start.elapsed();

            // Phase 0 Fix: Detect hangs (execution took too long)
            if exec_duration >= execution_timeout {
                hang_count += 1;
                tracing::warn!(
                    "🐢 HANG DETECTED at iteration {}: execution took {:?} (limit: {:?})",
                    completed,
                    exec_duration,
                    execution_timeout
                );
                // Add to findings as potential DoS vulnerability
                self.record_hang_finding(&test_case, exec_duration)?;
            }

            // Phase 0 Fix: Detect crashes (execution returned error/panic indicators)
            if result.is_crash() {
                crash_count += 1;
                tracing::warn!(
                    "💥 CRASH DETECTED at iteration {}: {:?}",
                    completed,
                    result.error_message()
                );
                // Add to findings as potential crash vulnerability
                self.record_crash_finding(&test_case, &result)?;
            }

            // Phase 2A: Check invariants against every accepted witness
            if result.success {
                accepted_count += 1;
                self.check_invariants_against(&test_case, &result)?;
            } else {
                failed_count += 1;
                if sample_errors.len() < 3 {
                    if let Some(err) = result.error_message() {
                        sample_errors.insert(err);
                    }
                }
            }

            // Track coverage improvements
            if result.coverage.new_coverage {
                tracing::debug!(
                    "New coverage at iteration {}: {} constraints",
                    completed,
                    result.coverage.satisfied_constraints.len()
                );
            }

            completed += 1;

            if let Some(p) = progress {
                if completed.is_multiple_of(100) {
                    p.inc();
                }
            }

            // Progress snapshot (cheap, periodic). This gives a "percent done" signal even when
            // wall-clock duration is not predictable.
            if last_progress_write.elapsed() >= Duration::from_secs(10)
                || completed.is_multiple_of(5000)
            {
                let frac = if iterations == 0 {
                    0.0
                } else {
                    (completed as f64) / (iterations as f64)
                }
                .clamp(0.0, 1.0);

                self.write_progress_snapshot(
                    mode_label,
                    "continuous",
                    phases_total,
                    phases_completed_base,
                    Some(frac),
                    serde_json::json!({
                        "completed": completed,
                        "iterations": iterations,
                        "accepted": accepted_count,
                        "failed": failed_count,
                        "hangs": hang_count,
                        "crashes": crash_count,
                        "elapsed_seconds": start.elapsed().as_secs_f64(),
                    }),
                );
                last_progress_write = Instant::now();
            }

            // Update power scheduler periodically
            if completed.is_multiple_of(1000) {
                self.update_power_scheduler_globals();
            }

            // Phase 0 Fix: Periodic corpus minimization to maintain quality
            // Run every 10,000 iterations to reduce redundant test cases
            if minimize_enabled
                && completed.is_multiple_of(minimize_interval)
                && completed > 0
                && self.core.corpus().len() >= minimize_min_size
            {
                let stats = self.core.corpus().minimize();
                tracing::debug!(
                    "Periodic corpus minimization: {} → {} entries",
                    stats.original_size,
                    stats.minimized_size
                );
            }
        }

        // Phase 0 Fix: Final corpus minimization before reporting
        let final_stats = if minimize_enabled {
            self.core.corpus().minimize()
        } else {
            let size = self.core.corpus().len();
            minimizer::MinimizationStats::compute(size, size)
        };

        tracing::info!(
            "Continuous fuzzing complete: {} iterations in {:.2}s, {} findings, {} hangs, {} crashes, accepted={}, failed={}, corpus: {}",
            completed,
            start.elapsed().as_secs_f64(),
            self.with_findings_read(|findings| findings.len())?,
            hang_count,
            crash_count,
            accepted_count,
            failed_count,
            final_stats.minimized_size
        );

        let frac = if iterations == 0 {
            0.0
        } else {
            (completed as f64) / (iterations as f64)
        }
        .clamp(0.0, 1.0);
        self.write_progress_snapshot(
            mode_label,
            "continuous_done",
            phases_total,
            phases_completed_base,
            Some(frac),
            serde_json::json!({
                "completed": completed,
                "iterations": iterations,
                "accepted": accepted_count,
                "failed": failed_count,
                "hangs": hang_count,
                "crashes": crash_count,
                "elapsed_seconds": start.elapsed().as_secs_f64(),
            }),
        );

        if accepted_count == 0 && failed_count > 0 && !sample_errors.is_empty() {
            tracing::warn!(
                "Continuous fuzzing accepted 0 witnesses; sample execution errors: {:?}",
                sample_errors
            );
        }

        Ok(())
    }

    /// Phase 0 Fix: Record a hang as a potential DoS finding
    pub(super) fn record_hang_finding(
        &mut self,
        test_case: &TestCase,
        duration: Duration,
    ) -> anyhow::Result<()> {
        use zk_core::{Finding, ProofOfConcept, Severity};

        let finding = Finding {
            attack_type: zk_core::AttackType::WitnessFuzzing,
            severity: Severity::Medium,
            description: format!(
                "Execution Hang Detected: Circuit execution took {:?}, exceeding timeout. Potential DoS vulnerability.",
                duration
            ),
            poc: ProofOfConcept {
                witness_a: test_case.inputs.clone(),
                witness_b: None,
                public_inputs: vec![],
                proof: None,
            },
            location: Some(format!(
                "Hang at iteration {} after {:?}",
                self.core.execution_count(),
                duration
            )),
        };

        self.with_findings_write(|findings| findings.push(finding))?;
        Ok(())
    }

    /// Phase 0 Fix: Record a crash as a finding
    pub(super) fn record_crash_finding(
        &mut self,
        test_case: &TestCase,
        result: &ExecutionResult,
    ) -> anyhow::Result<()> {
        use zk_core::{Finding, ProofOfConcept, Severity};

        let error_msg = result
            .error_message()
            .map(|value| value)
            .or_else(|| Some("Unknown crash".to_string()))
            .expect("default crash message injected");

        let finding = Finding {
            attack_type: zk_core::AttackType::WitnessFuzzing,
            severity: Severity::High,
            description: format!(
                "Execution Crash Detected: {}. Potential vulnerability or implementation bug.",
                error_msg
            ),
            poc: ProofOfConcept {
                witness_a: test_case.inputs.clone(),
                witness_b: None,
                public_inputs: vec![],
                proof: None,
            },
            location: Some(format!(
                "Crash at iteration {}: {}",
                self.core.execution_count(),
                error_msg
            )),
        };

        self.with_findings_write(|findings| findings.push(finding))?;
        Ok(())
    }

    /// Phase 2A: Check invariants against every accepted witness
    ///
    /// Unlike the one-shot enforce_invariants(), this is called for every
    /// successful execution in the fuzzing loop, enabling continuous
    /// invariant violation detection.
    ///
    /// IMPORTANT: Uses cached InvariantChecker to maintain uniqueness tracking state
    /// across executions. Without caching, uniqueness invariants (e.g., nullifier_unique)
    /// would never detect duplicates because each execution would start with a fresh empty set.
    pub(super) fn check_invariants_against(
        &mut self,
        test_case: &TestCase,
        result: &ExecutionResult,
    ) -> anyhow::Result<()> {
        // Use cached checker to maintain uniqueness tracking state
        let Some(checker) = self.invariant_checker.as_mut() else {
            return Ok(());
        };

        // Check all invariants using cached state
        let violations = checker.check(&test_case.inputs, &result.outputs, result.success);

        // Record violations as findings
        for violation in violations {
            self.record_invariant_violation(&violation, test_case)?;
        }
        Ok(())
    }
}
