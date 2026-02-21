use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    /// Parse power schedule strategy from configuration
    ///
    /// Power schedules determine how energy is assigned to test cases:
    /// - **FAST**: Favor fast-executing test cases
    /// - **COE**: Cut-Off Exponential - balance speed and coverage
    /// - **EXPLORE**: Prioritize unexplored paths
    /// - **MMOPT**: Min-Max Optimal - balanced approach (default)
    /// - **RARE**: Focus on rare edge cases
    /// - **SEEK**: Actively seek new coverage
    ///
    /// Specified in campaign YAML as:
    /// ```yaml
    /// campaign:
    ///   parameters:
    ///     power_schedule: "MMOPT"
    /// ```
    /// Execute the complete fuzzing campaign
    ///
    /// This is the main entry point that runs the entire fuzzing workflow:
    /// 1. Analyzes circuit complexity and structure
    /// 2. Performs static analysis (taint, source code patterns)
    /// 3. Seeds initial corpus with interesting values
    /// 4. Executes configured attacks (underconstrained, soundness, etc.)
    /// 5. Runs coverage-guided fuzzing loop
    /// 6. Generates comprehensive report
    ///
    /// # Arguments
    ///
    /// * `progress` - Optional progress reporter for interactive display
    ///
    /// # Returns
    ///
    /// Returns a `FuzzReport` containing:
    /// - All discovered vulnerabilities with severity ratings
    /// - Proof-of-concept test cases for reproduction
    /// - Coverage statistics and execution metrics
    /// - Recommendations for fixing issues
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use zk_fuzzer::config::FuzzConfig;
    /// use zk_fuzzer::fuzzer::FuzzingEngine;
    /// use zk_fuzzer::progress::ProgressReporter;
    ///
    /// # fn main() -> anyhow::Result<()> {
    /// # let config_yaml = r#"
    /// # campaign:
    /// #   name: "Doc Engine Run"
    /// #   version: "1.0"
    /// #   target:
    /// #     framework: "circom"
    /// #     circuit_path: "./circuits/example.circom"
    /// #     main_component: "Main"
    /// #
    /// # attacks:
    /// #   - type: "boundary"
    /// #     description: "Quick boundary check"
    /// #     config:
    /// #       test_values: ["0", "1"]
    /// #
    /// # inputs:
    /// #   - name: "a"
    /// #     type: "field"
    /// #     fuzz_strategy: "random"
    /// # "#;
    /// # let temp = tempfile::NamedTempFile::new()?;
    /// # std::fs::write(temp.path(), config_yaml)?;
    /// # let config = FuzzConfig::from_yaml(temp.path().to_str().unwrap())?;
    /// let mut engine = FuzzingEngine::new(config, Some(12345), 1)?;
    ///
    /// let rt = tokio::runtime::Runtime::new()?;
    /// // Run with progress reporting
    /// let reporter = ProgressReporter::new("Doc Engine Run", 10, false);
    /// let _report = rt.block_on(async { engine.run(Some(&reporter)).await })?;
    ///
    /// // Run without progress (CI/CD mode)
    /// // let _report = rt.block_on(async { engine.run(None).await })?;
    /// # Ok(())
    /// # }
    /// ```
    pub(super) fn with_findings_write<R>(
        &self,
        apply: impl FnOnce(&mut Vec<Finding>) -> R,
    ) -> anyhow::Result<R> {
        let findings_store = self.core.findings();
        let mut store = findings_store.write();
        Ok(apply(&mut store))
    }

    pub(super) fn with_findings_read<R>(
        &self,
        apply: impl FnOnce(&Vec<Finding>) -> R,
    ) -> anyhow::Result<R> {
        let findings_store = self.core.findings();
        let store = findings_store.read();
        Ok(apply(&store))
    }

    fn configure_wall_clock_deadline(&mut self, start_time: Instant) -> Option<u64> {
        let timeout_seconds = self
            .config
            .campaign
            .parameters
            .additional
            .get("fuzzing_timeout_seconds")
            .and_then(|v| v.as_u64());

        self.wall_clock_deadline = timeout_seconds.and_then(|seconds| {
            let bounded = seconds.max(1);
            start_time.checked_add(Duration::from_secs(bounded))
        });

        if let Some(seconds) = timeout_seconds {
            if self.wall_clock_deadline.is_some() {
                tracing::info!(
                    "Global wall-clock timeout enabled for this run: {}s",
                    seconds.max(1)
                );
            } else {
                tracing::warn!(
                    "Failed to configure global wall-clock timeout from {}s (overflow)",
                    seconds
                );
            }
        }

        timeout_seconds
    }

    pub(super) fn wall_clock_timeout_reached(&self) -> bool {
        self.wall_clock_deadline
            .map(|deadline| Instant::now() >= deadline)
            .unwrap_or(false)
    }

    pub(super) fn wall_clock_remaining(&self) -> Option<Duration> {
        self.wall_clock_deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    pub async fn run(&mut self, progress: Option<&ProgressReporter>) -> anyhow::Result<FuzzReport> {
        let start_time = Instant::now();
        self.core.set_start_time(start_time);
        let _configured_wall_clock_timeout = self.configure_wall_clock_deadline(start_time);

        let additional = &self.config.campaign.parameters.additional;
        let evidence_mode = Self::additional_bool(additional, "evidence_mode").unwrap_or(false);
        // Engagement contract: in evidence mode, fail fast on misconfiguration that would cause
        // patterns/attacks to be silently skipped.
        let engagement_strict =
            Self::additional_bool(additional, "engagement_strict").unwrap_or(evidence_mode);
        let mode_label = if evidence_mode { "evidence" } else { "run" };
        let phases_total = 1u64
            .saturating_add(self.config.attacks.len() as u64)
            .saturating_add(1)
            .saturating_add(1); // seeded_corpus + attacks + continuous + reporting

        self.run_bootstrap_phase(progress, mode_label, phases_total, evidence_mode)?;

        // Run attacks
        let (attacks_total, wall_clock_timed_out) = self
            .run_attack_phase(
                progress,
                mode_label,
                phases_total,
                start_time,
                engagement_strict,
            )
            .await?;

        // Finish simple tracker
        if let Some(ref tracker) = self.simple_tracker {
            tracker.finish();
        }

        // Phase 0 Fix: Run continuous fuzzing phase after attacks
        let iterations = self
            .config
            .campaign
            .parameters
            .additional
            .get("max_iterations")
            .and_then(|v| v.as_u64())
            .or_else(|| {
                self.config
                    .campaign
                    .parameters
                    .additional
                    .get("fuzzing_iterations")
                    .and_then(|v| v.as_u64())
            })
            .unwrap_or(1000);

        let timeout = self
            .config
            .campaign
            .parameters
            .additional
            .get("fuzzing_timeout_seconds")
            .and_then(|v| v.as_u64());

        if iterations > 0 && !wall_clock_timed_out && !self.wall_clock_timeout_reached() {
            let phases_completed = 1u64.saturating_add(attacks_total);
            self.write_progress_snapshot(
                mode_label,
                "continuous_start",
                phases_total,
                phases_completed,
                Some(0.0),
                serde_json::json!({
                    "iterations": iterations,
                    "timeout_seconds": timeout,
                }),
            );
            tracing::warn!(
                "MILESTONE continuous_start target={} iterations={} timeout={:?}",
                self.config.campaign.name,
                iterations,
                timeout
            );
            self.run_continuous_fuzzing_phase(
                iterations,
                timeout,
                progress,
                mode_label,
                phases_total,
                phases_completed,
            )
            .await?;
            tracing::warn!(
                "MILESTONE continuous_complete target={}",
                self.config.campaign.name
            );
            let phases_completed = phases_completed.saturating_add(1);
            self.write_progress_snapshot(
                mode_label,
                "continuous_complete",
                phases_total,
                phases_completed,
                Some(0.0),
                serde_json::json!({}),
            );
        } else if iterations > 0 {
            tracing::warn!(
                "Skipping continuous fuzzing phase: global wall-clock timeout already reached"
            );
            let phases_completed = 1u64.saturating_add(attacks_total);
            self.write_progress_snapshot(
                mode_label,
                "continuous_skipped_timeout",
                phases_total,
                phases_completed,
                Some(0.0),
                serde_json::json!({
                    "reason": "wall_clock_timeout",
                    "elapsed_seconds": start_time.elapsed().as_secs_f64(),
                }),
            );
        }

        self.finalize_run_report(start_time, mode_label, phases_total)
    }
}
