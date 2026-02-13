//! Progress reporting and real-time statistics
//!
//! Uses indicatif for terminal-based progress bars and status updates.

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use zk_fuzzer_core::FuzzingStats;

/// Progress reporter with real-time terminal updates
pub struct ProgressReporter {
    multi_progress: MultiProgress,
    main_bar: ProgressBar,
    stats_bar: ProgressBar,
    start_time: Instant,
    total_iterations: u64,
    verbose: bool,
}

impl ProgressReporter {
    /// Create a new progress reporter
    pub fn new(campaign_name: &str, total_iterations: u64, verbose: bool) -> Self {
        let multi = MultiProgress::new();

        // Main progress bar
        let main_bar = multi.add(ProgressBar::new(total_iterations));
        main_bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
                .unwrap()
                .progress_chars("█▓▒░"),
        );
        main_bar.set_message(format!("Fuzzing: {}", campaign_name));

        // Stats bar (spinner with stats)
        let stats_bar = multi.add(ProgressBar::new_spinner());
        stats_bar.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.yellow} {msg}")
                .unwrap(),
        );
        stats_bar.enable_steady_tick(Duration::from_millis(100));

        Self {
            multi_progress: multi,
            main_bar,
            stats_bar,
            start_time: Instant::now(),
            total_iterations,
            verbose,
        }
    }

    /// Update progress with current statistics
    pub fn update(&self, stats: &FuzzingStats) {
        self.main_bar.set_position(stats.executions);

        let status = format!(
            "execs/s: {:.1} | coverage: {:.1}% | crashes: {} | corpus: {}",
            stats.executions_per_second,
            stats.coverage_percentage,
            stats.crashes,
            stats.corpus_size
        );
        self.stats_bar.set_message(status);
    }

    /// Log a new finding
    pub fn log_finding(&self, severity: &str, description: &str) {
        let msg = format!("🔴 [{}] {}", severity, description);
        self.main_bar.println(msg);
    }

    /// Log new coverage discovery
    pub fn log_new_coverage(&self, constraint_count: usize) {
        if self.verbose {
            let msg = format!("🟢 New coverage: {} constraints", constraint_count);
            self.main_bar.println(msg);
        }
    }

    /// Log an attack starting
    pub fn log_attack_start(&self, attack_name: &str) {
        let msg = format!("⚔️  Starting attack: {}", attack_name);
        self.main_bar.println(msg);
    }

    /// Log an attack completion
    pub fn log_attack_complete(&self, attack_name: &str, findings: usize) {
        let emoji = if findings > 0 { "⚠️" } else { "✅" };
        let msg = format!(
            "{} Completed: {} ({} findings)",
            emoji, attack_name, findings
        );
        self.main_bar.println(msg);
    }

    /// Log a general message
    pub fn log_message(&self, message: &str) {
        self.main_bar.println(message);
    }

    /// Increment execution count
    pub fn inc(&self) {
        self.main_bar.inc(1);
    }

    /// Set a custom message
    pub fn set_message(&self, msg: &str) {
        self.main_bar.set_message(msg.to_string());
    }

    /// Finish with a summary
    pub fn finish(&self, stats: &FuzzingStats) {
        let total = self.total_iterations.max(stats.executions);
        self.main_bar.set_length(total);
        self.main_bar.finish_with_message(format!(
            "Complete - {}/{} execs, {:.1}% coverage, {} findings",
            stats.executions, total, stats.coverage_percentage, stats.crashes
        ));
        self.stats_bar.finish_and_clear();
        let _ = self.multi_progress.clear();
    }

    /// Finish with an error
    pub fn finish_with_error(&self, error: &str) {
        self.main_bar
            .abandon_with_message(format!("Error: {}", error));
        self.stats_bar.finish_and_clear();
        let _ = self.multi_progress.clear();
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
}

/// Simple progress tracker without terminal UI (for non-interactive use)
pub struct SimpleProgressTracker {
    start_time: Instant,
    last_log_time: Instant,
    log_interval: Duration,
    stats: FuzzingStats,
}

impl SimpleProgressTracker {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            last_log_time: Instant::now(),
            log_interval: Duration::from_secs(10),
            stats: FuzzingStats::default(),
        }
    }

    pub fn with_log_interval(mut self, interval: Duration) -> Self {
        self.log_interval = interval;
        self
    }

    pub fn update(&mut self, stats: FuzzingStats) {
        self.stats = stats;
        self.stats.update_exec_rate(self.start_time);

        if self.last_log_time.elapsed() >= self.log_interval {
            self.log_status();
            self.last_log_time = Instant::now();
        }
    }

    fn log_status(&self) {
        tracing::info!(
            "Progress: {} execs ({:.1}/s), {:.1}% coverage, {} crashes, corpus: {}",
            self.stats.executions,
            self.stats.executions_per_second,
            self.stats.coverage_percentage,
            self.stats.crashes,
            self.stats.corpus_size
        );
    }

    pub fn finish(&self) {
        tracing::info!(
            "Fuzzing complete: {} executions in {:.1}s ({:.1}/s)",
            self.stats.executions,
            self.start_time.elapsed().as_secs_f64(),
            self.stats.executions_per_second
        );
    }
}

impl Default for SimpleProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared progress reporter for concurrent access
pub type SharedProgressReporter = Arc<ProgressReporter>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzing_stats() {
        let stats = FuzzingStats {
            executions: 1000,
            crashes: 5,
            coverage_percentage: 75.5,
            ..FuzzingStats::default()
        };

        assert_eq!(stats.executions, 1000);
        assert_eq!(stats.crashes, 5);
    }

    #[test]
    fn test_simple_progress_tracker() {
        let mut tracker =
            SimpleProgressTracker::new().with_log_interval(Duration::from_millis(100));

        let stats = FuzzingStats {
            executions: 100,
            crashes: 1,
            coverage_percentage: 50.0,
            ..Default::default()
        };

        tracker.update(stats);
        assert_eq!(tracker.stats.executions, 100);
    }
}
