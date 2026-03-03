use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) async fn run_continuation_phase(
        &mut self,
        progress: Option<&ProgressReporter>,
        mode_label: &str,
        phases_total: u64,
        attacks_total: u64,
        wall_clock_timed_out: bool,
        start_time: Instant,
    ) -> anyhow::Result<()> {
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
        } else if iterations > 0 && (wall_clock_timed_out || self.wall_clock_timeout_reached()) {
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

        Ok(())
    }
}
