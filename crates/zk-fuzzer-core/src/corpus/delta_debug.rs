//! Delta Debugging for Test Case Minimization
//!
//! Implements the delta debugging algorithm (Zeller 1999) for minimizing
//! test cases while preserving the failure-inducing property.
//!
//! # Algorithm Overview
//!
//! Delta debugging works by systematically removing parts of the input:
//! 1. Split input into n chunks
//! 2. Try removing each chunk; if failure persists, keep the reduced input
//! 3. If no single chunk removal works, try removing complements
//! 4. Double the granularity (more, smaller chunks) and repeat
//! 5. Stop when granularity equals input size
//!
//! # Example
//!
//! ```rust,ignore
//! use zk_fuzzer_core::corpus::delta_debug::{DeltaDebugger, OracleResult};
//!
//! let debugger = DeltaDebugger::new(|input| {
//!     // Test if input still triggers the bug
//!     if causes_bug(input) {
//!         OracleResult::Fail
//!     } else {
//!         OracleResult::Pass
//!     }
//! });
//!
//! let minimal = debugger.minimize(&failing_input)?;
//! ```

use std::time::{Duration, Instant};
use zk_core::{FieldElement, TestCase, TestMetadata};

/// Result of testing a candidate input
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleResult {
    /// Input still triggers the failure
    Fail,
    /// Input no longer triggers the failure
    Pass,
    /// Test was inconclusive (e.g., different error)
    Unresolved,
}

/// Configuration for delta debugging
#[derive(Debug, Clone)]
pub struct DeltaDebugConfig {
    /// Maximum time to spend minimizing
    pub max_time: Duration,
    /// Maximum number of oracle queries
    pub max_queries: usize,
    /// Minimum granularity (stop when chunks are this small)
    pub min_granularity: usize,
    /// Whether to try complement reduction
    pub try_complements: bool,
    /// Enable hierarchical reduction (fields first, then within fields)
    pub hierarchical: bool,
}

impl Default for DeltaDebugConfig {
    fn default() -> Self {
        Self {
            max_time: Duration::from_secs(300),
            max_queries: 10000,
            min_granularity: 1,
            try_complements: true,
            hierarchical: true,
        }
    }
}

/// Statistics from minimization
#[derive(Debug, Clone, Default)]
pub struct DeltaDebugStats {
    /// Number of oracle queries made
    pub queries: usize,
    /// Number of successful reductions
    pub reductions: usize,
    /// Original input size
    pub original_size: usize,
    /// Minimized input size
    pub minimized_size: usize,
    /// Reduction percentage
    pub reduction_percent: f64,
    /// Time spent minimizing
    pub elapsed: Duration,
}

impl DeltaDebugStats {
    pub fn new(original_size: usize) -> Self {
        Self {
            original_size,
            ..Default::default()
        }
    }

    pub fn finalize(&mut self, minimized_size: usize, elapsed: Duration) {
        self.minimized_size = minimized_size;
        self.elapsed = elapsed;
        self.reduction_percent = if self.original_size > 0 {
            ((self.original_size - minimized_size) as f64 / self.original_size as f64) * 100.0
        } else {
            0.0
        };
    }
}

/// Delta debugging minimizer
pub struct DeltaDebugger<F>
where
    F: Fn(&[FieldElement]) -> OracleResult,
{
    oracle: F,
    config: DeltaDebugConfig,
}

impl<F> DeltaDebugger<F>
where
    F: Fn(&[FieldElement]) -> OracleResult,
{
    /// Create a new delta debugger with the given oracle function
    pub fn new(oracle: F) -> Self {
        Self {
            oracle,
            config: DeltaDebugConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(oracle: F, config: DeltaDebugConfig) -> Self {
        Self { oracle, config }
    }

    /// Minimize a failing test case
    ///
    /// The oracle should return `OracleResult::Fail` for inputs that
    /// still exhibit the bug.
    pub fn minimize(
        &self,
        input: &[FieldElement],
    ) -> Result<(Vec<FieldElement>, DeltaDebugStats), String> {
        let start = Instant::now();
        let mut stats = DeltaDebugStats::new(input.len());

        // Verify initial input fails
        stats.queries += 1;
        if (self.oracle)(input) != OracleResult::Fail {
            return Err("Initial input does not fail the oracle".to_string());
        }

        let mut current = input.to_vec();
        let mut n = 2; // Start with 2 chunks

        while n <= current.len() && stats.queries < self.config.max_queries {
            if start.elapsed() > self.config.max_time {
                break;
            }

            let chunk_size = current.len().div_ceil(n);
            let mut reduced = false;

            // Try removing each chunk
            for i in 0..n {
                let start_idx = i * chunk_size;
                let end_idx = ((i + 1) * chunk_size).min(current.len());

                if start_idx >= current.len() {
                    break;
                }

                // Create candidate without chunk i
                let candidate: Vec<_> = current[..start_idx]
                    .iter()
                    .chain(current[end_idx..].iter())
                    .cloned()
                    .collect();

                if candidate.is_empty() {
                    continue;
                }

                stats.queries += 1;
                if (self.oracle)(&candidate) == OracleResult::Fail {
                    current = candidate;
                    stats.reductions += 1;
                    reduced = true;
                    n = 2.max(n - 1); // Reduce granularity
                    break;
                }
            }

            // Try complements if no single chunk removal worked
            if !reduced && self.config.try_complements && n > 2 {
                for i in 0..n {
                    let start_idx = i * chunk_size;
                    let end_idx = ((i + 1) * chunk_size).min(current.len());

                    if start_idx >= current.len() {
                        break;
                    }

                    // Keep only chunk i (complement of removal)
                    let candidate: Vec<_> = current[start_idx..end_idx].to_vec();

                    if candidate.is_empty() {
                        continue;
                    }

                    stats.queries += 1;
                    if (self.oracle)(&candidate) == OracleResult::Fail {
                        current = candidate;
                        stats.reductions += 1;
                        reduced = true;
                        n = 2;
                        break;
                    }
                }
            }

            if !reduced {
                // Increase granularity
                n = (2 * n).min(current.len());
                if n >= current.len() {
                    break;
                }
            }
        }

        // Try 1-minimality (remove individual elements)
        if self.config.min_granularity == 1 {
            let mut i = 0;
            while i < current.len() && stats.queries < self.config.max_queries {
                if start.elapsed() > self.config.max_time {
                    break;
                }

                let candidate: Vec<_> = current[..i]
                    .iter()
                    .chain(current[i + 1..].iter())
                    .cloned()
                    .collect();

                if !candidate.is_empty() {
                    stats.queries += 1;
                    if (self.oracle)(&candidate) == OracleResult::Fail {
                        current = candidate;
                        stats.reductions += 1;
                        // Don't increment i since we removed element at i
                        continue;
                    }
                }
                i += 1;
            }
        }

        stats.finalize(current.len(), start.elapsed());
        Ok((current, stats))
    }

    /// Minimize a test case with multiple field groups
    ///
    /// This performs hierarchical minimization:
    /// 1. First try to remove entire field groups
    /// 2. Then minimize within each remaining group
    pub fn minimize_structured(
        &self,
        groups: &[Vec<FieldElement>],
    ) -> Result<(Vec<Vec<FieldElement>>, DeltaDebugStats), String> {
        let start = Instant::now();
        let total_elements: usize = groups.iter().map(|g| g.len()).sum();
        let mut stats = DeltaDebugStats::new(total_elements);

        // Flatten and verify
        let flat: Vec<_> = groups.iter().flatten().cloned().collect();
        stats.queries += 1;
        if (self.oracle)(&flat) != OracleResult::Fail {
            return Err("Initial input does not fail the oracle".to_string());
        }

        let mut current_groups = groups.to_vec();

        // Phase 1: Remove entire groups
        if self.config.hierarchical {
            let mut i = 0;
            while i < current_groups.len() {
                if start.elapsed() > self.config.max_time {
                    break;
                }

                let candidate: Vec<Vec<_>> = current_groups[..i]
                    .iter()
                    .chain(current_groups[i + 1..].iter())
                    .cloned()
                    .collect();

                if candidate.is_empty() {
                    i += 1;
                    continue;
                }

                let flat_candidate: Vec<_> = candidate.iter().flatten().cloned().collect();
                stats.queries += 1;

                if (self.oracle)(&flat_candidate) == OracleResult::Fail {
                    current_groups = candidate;
                    stats.reductions += 1;
                    // Don't increment i
                } else {
                    i += 1;
                }
            }
        }

        // Phase 2: Minimize within each group
        for group_idx in 0..current_groups.len() {
            if start.elapsed() > self.config.max_time {
                break;
            }

            let group = &current_groups[group_idx];
            if group.len() <= 1 {
                continue;
            }

            // Create oracle that tests within this group
            let mut i = 0;
            while i < current_groups[group_idx].len() {
                if start.elapsed() > self.config.max_time
                    || stats.queries >= self.config.max_queries
                {
                    break;
                }

                let mut candidate_groups = current_groups.clone();
                candidate_groups[group_idx] = current_groups[group_idx][..i]
                    .iter()
                    .chain(current_groups[group_idx][i + 1..].iter())
                    .cloned()
                    .collect();

                if candidate_groups[group_idx].is_empty() {
                    i += 1;
                    continue;
                }

                let flat_candidate: Vec<_> = candidate_groups.iter().flatten().cloned().collect();
                stats.queries += 1;

                if (self.oracle)(&flat_candidate) == OracleResult::Fail {
                    current_groups = candidate_groups;
                    stats.reductions += 1;
                } else {
                    i += 1;
                }
            }
        }

        let final_size: usize = current_groups.iter().map(|g| g.len()).sum();
        stats.finalize(final_size, start.elapsed());

        Ok((current_groups, stats))
    }
}

/// Minimize a test case using delta debugging
pub fn minimize_test_case<F>(
    test_case: &TestCase,
    oracle: F,
    config: Option<DeltaDebugConfig>,
) -> Result<(TestCase, DeltaDebugStats), String>
where
    F: Fn(&[FieldElement]) -> OracleResult,
{
    let config = config.unwrap_or_default();
    let debugger = DeltaDebugger::with_config(oracle, config);

    let (minimized_inputs, stats) = debugger.minimize(&test_case.inputs)?;

    let minimized_test = TestCase {
        inputs: minimized_inputs,
        expected_output: test_case.expected_output.clone(),
        metadata: TestMetadata {
            generation: test_case.metadata.generation,
            mutation_history: vec!["delta_debug_minimized".to_string()],
            coverage_bits: test_case.metadata.coverage_bits,
        },
    };

    Ok((minimized_test, stats))
}

/// Binary search variant for monotonic failures
///
/// When the failure is monotonic (removing elements can only help),
/// this is more efficient than full delta debugging.
pub fn binary_minimize<F>(
    input: &[FieldElement],
    oracle: F,
) -> Result<(Vec<FieldElement>, usize), String>
where
    F: Fn(&[FieldElement]) -> OracleResult,
{
    if input.is_empty() {
        return Err("Empty input".to_string());
    }

    if oracle(input) != OracleResult::Fail {
        return Err("Initial input does not fail".to_string());
    }

    let mut queries = 1;
    let mut lo = 0;
    let mut hi = input.len();

    // Binary search for minimum prefix that still fails
    while lo < hi - 1 {
        let mid = (lo + hi) / 2;
        let prefix = &input[..mid];

        queries += 1;
        if oracle(prefix) == OracleResult::Fail {
            hi = mid;
        } else {
            lo = mid;
        }
    }

    Ok((input[..hi].to_vec(), queries))
}

#[cfg(test)]
#[path = "delta_debug_tests.rs"]
mod tests;
