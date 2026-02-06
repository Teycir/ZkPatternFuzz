//! Shared fuzzing statistics.

use std::time::Instant;

/// Statistics tracked during fuzzing
#[derive(Debug, Clone, Default)]
pub struct FuzzingStats {
    pub executions: u64,
    pub crashes: u64,
    pub coverage_percentage: f64,
    pub unique_crashes: u64,
    pub corpus_size: usize,
    pub executions_per_second: f64,
    pub elapsed_seconds: u64,
    pub new_coverage_count: u64,
}

impl FuzzingStats {
    pub fn update_exec_rate(&mut self, start_time: Instant) {
        let elapsed = start_time.elapsed().as_secs_f64();
        self.elapsed_seconds = elapsed as u64;
        if elapsed > 0.0 {
            self.executions_per_second = self.executions as f64 / elapsed;
        }
    }
}
