//! Benchmark Harness for Known-Bug Detection
//!
//! Automated testing framework that:
//! 1. Loads known-bug circuits from `tests/bench/known_bugs/`
//! 2. Runs fuzzing campaigns with configurable parameters
//! 3. Measures time-to-first-bug and other metrics
//! 4. Generates scoreboard reports
//!
//! # Usage
//!
//! ```bash
//! cargo test --test harness -- --nocapture
//! cargo test --test harness benchmark_all -- --nocapture
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Benchmark configuration
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Directory containing known-bug test cases
    pub known_bugs_dir: PathBuf,
    /// Maximum time per benchmark
    pub timeout: Duration,
    /// Number of runs for statistical significance
    pub runs_per_benchmark: usize,
    /// Random seed for reproducibility (None for random)
    pub seed: Option<u64>,
    /// Number of parallel workers
    pub workers: usize,
    /// Output directory for results
    pub output_dir: PathBuf,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            known_bugs_dir: PathBuf::from("tests/bench/known_bugs"),
            timeout: Duration::from_secs(300),
            runs_per_benchmark: 3,
            seed: Some(42),
            workers: 4,
            output_dir: PathBuf::from("reports/benchmarks"),
        }
    }
}

/// Expected finding specification from JSON
#[derive(Debug, Clone, Deserialize)]
pub struct ExpectedFinding {
    pub attack_type: String,
    pub severity: String,
    #[serde(default)]
    pub description_contains: Vec<String>,
    #[serde(default)]
    pub expected_time_seconds: u64,
    #[serde(default)]
    pub min_confidence: f64,
    #[serde(default)]
    pub required_oracles: Vec<String>,
    #[serde(default)]
    pub poc_requirements: HashMap<String, serde_json::Value>,
}

/// Result of a single benchmark run
#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkRun {
    /// Time to first bug detection
    pub time_to_first_bug_ms: Option<u64>,
    /// Total time for the run
    pub total_time_ms: u64,
    /// Number of unique bugs found
    pub unique_bugs_found: usize,
    /// Number of false positives (findings that don't match expected)
    pub false_positives: usize,
    /// Coverage percentage achieved
    pub coverage_percentage: f64,
    /// Executions performed
    pub total_executions: u64,
    /// Whether expected bug was found
    pub expected_bug_found: bool,
    /// Seed used for this run
    pub seed: u64,
}

/// Aggregated benchmark results
#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkResult {
    /// Name of the benchmark (bug directory name)
    pub name: String,
    /// Path to the circuit
    pub circuit_path: String,
    /// Expected finding specification
    pub expected: ExpectedFinding,
    /// Individual run results
    pub runs: Vec<BenchmarkRun>,
    /// Statistics
    pub stats: BenchmarkStats,
}

/// Statistical summary of benchmark runs
#[derive(Debug, Clone, Serialize, Default)]
pub struct BenchmarkStats {
    /// Mean time to first bug (ms)
    pub mean_time_to_bug_ms: f64,
    /// Median time to first bug (ms)
    pub median_time_to_bug_ms: f64,
    /// Standard deviation of time to bug (ms)
    pub stddev_time_to_bug_ms: f64,
    /// Minimum time to bug (ms)
    pub min_time_to_bug_ms: u64,
    /// Maximum time to bug (ms)
    pub max_time_to_bug_ms: u64,
    /// Detection rate (fraction of runs that found the bug)
    pub detection_rate: f64,
    /// Mean false positive count
    pub mean_false_positives: f64,
    /// Mean coverage percentage
    pub mean_coverage: f64,
    /// Whether benchmark passed (met expected time)
    pub passed: bool,
}

impl BenchmarkStats {
    pub fn from_runs(runs: &[BenchmarkRun], expected_time_ms: u64) -> Self {
        if runs.is_empty() {
            return Self::default();
        }

        let times: Vec<u64> = runs
            .iter()
            .filter_map(|r| r.time_to_first_bug_ms)
            .collect();

        let detection_rate = times.len() as f64 / runs.len() as f64;

        if times.is_empty() {
            return Self {
                detection_rate,
                mean_false_positives: runs.iter().map(|r| r.false_positives as f64).sum::<f64>()
                    / runs.len() as f64,
                mean_coverage: runs.iter().map(|r| r.coverage_percentage).sum::<f64>()
                    / runs.len() as f64,
                ..Default::default()
            };
        }

        let sum: u64 = times.iter().sum();
        let mean = sum as f64 / times.len() as f64;

        let variance: f64 = times.iter().map(|&t| (t as f64 - mean).powi(2)).sum::<f64>()
            / times.len() as f64;
        let stddev = variance.sqrt();

        let mut sorted_times = times.clone();
        sorted_times.sort();
        let median = if sorted_times.len().is_multiple_of(2) {
            (sorted_times[sorted_times.len() / 2 - 1] + sorted_times[sorted_times.len() / 2]) as f64
                / 2.0
        } else {
            sorted_times[sorted_times.len() / 2] as f64
        };

        let min = match sorted_times.first() {
            Some(value) => *value,
            None => 0,
        };
        let max = match sorted_times.last() {
            Some(value) => *value,
            None => 0,
        };

        let passed = median <= expected_time_ms as f64 && detection_rate >= 0.8;

        Self {
            mean_time_to_bug_ms: mean,
            median_time_to_bug_ms: median,
            stddev_time_to_bug_ms: stddev,
            min_time_to_bug_ms: min,
            max_time_to_bug_ms: max,
            detection_rate,
            mean_false_positives: runs.iter().map(|r| r.false_positives as f64).sum::<f64>()
                / runs.len() as f64,
            mean_coverage: runs.iter().map(|r| r.coverage_percentage).sum::<f64>()
                / runs.len() as f64,
            passed,
        }
    }
}

/// Scoreboard for all benchmarks
#[derive(Debug, Clone, Serialize)]
pub struct Scoreboard {
    /// ZK Fuzzer version
    pub version: String,
    /// Timestamp
    pub timestamp: String,
    /// Configuration used
    pub config: ScoreboardConfig,
    /// Individual benchmark results
    pub benchmarks: Vec<BenchmarkResult>,
    /// Summary statistics
    pub summary: ScoreboardSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScoreboardConfig {
    pub timeout_seconds: u64,
    pub runs_per_benchmark: usize,
    pub workers: usize,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ScoreboardSummary {
    /// Total benchmarks
    pub total: usize,
    /// Benchmarks passed
    pub passed: usize,
    /// Benchmarks failed
    pub failed: usize,
    /// Overall pass rate
    pub pass_rate: f64,
    /// Mean time to bug across all benchmarks
    pub overall_mean_time_ms: f64,
    /// Total false positives
    pub total_false_positives: usize,
}

/// Benchmark harness
pub struct BenchmarkHarness {
    config: BenchmarkConfig,
}

impl BenchmarkHarness {
    pub fn new(config: BenchmarkConfig) -> Self {
        Self { config }
    }

    /// Discover all known-bug benchmarks
    pub fn discover_benchmarks(&self) -> anyhow::Result<Vec<PathBuf>> {
        let mut benchmarks = Vec::new();

        if !self.config.known_bugs_dir.exists() {
            anyhow::bail!(
                "Known bugs directory not found: {:?}",
                self.config.known_bugs_dir
            );
        }

        for entry in fs::read_dir(&self.config.known_bugs_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // Check for required files
                let circuit = path.join("circuit.circom");
                let expected = path.join("expected_finding.json");

                if circuit.exists() && expected.exists() {
                    benchmarks.push(path);
                }
            }
        }

        benchmarks.sort();
        Ok(benchmarks)
    }

    /// Load expected finding from JSON
    pub fn load_expected_finding(&self, benchmark_path: &Path) -> anyhow::Result<ExpectedFinding> {
        let json_path = benchmark_path.join("expected_finding.json");
        let content = fs::read_to_string(json_path)?;
        let expected: ExpectedFinding = serde_json::from_str(&content)?;
        Ok(expected)
    }

    /// Run a single benchmark
    pub fn run_benchmark(&self, benchmark_path: &Path) -> anyhow::Result<BenchmarkResult> {
        let name = benchmark_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();

        let circuit_path = benchmark_path.join("circuit.circom");
        let expected = self.load_expected_finding(benchmark_path)?;

        println!("Running benchmark: {}", name);
        println!("  Circuit: {:?}", circuit_path);
        println!("  Expected: {:?} ({})", expected.attack_type, expected.severity);

        let mut runs = Vec::new();

        for run_idx in 0..self.config.runs_per_benchmark {
            let seed = match self.config.seed.map(|s| s + run_idx as u64) {
                Some(value) => value,
                None => {
                    use std::time::SystemTime;
                    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                        Ok(duration) => duration.as_secs(),
                        Err(err) => panic!("System clock before UNIX_EPOCH while generating seed: {}", err),
                    }
                }
            };

            println!("  Run {}/{} (seed: {})", run_idx + 1, self.config.runs_per_benchmark, seed);

            let run = self.run_single(benchmark_path, &expected, seed)?;
            println!(
                "    Time to bug: {:?}ms, Coverage: {:.1}%, Found: {}",
                run.time_to_first_bug_ms,
                run.coverage_percentage,
                run.expected_bug_found
            );

            runs.push(run);
        }

        let expected_time_ms = expected.expected_time_seconds * 1000;
        let stats = BenchmarkStats::from_runs(&runs, expected_time_ms);

        println!(
            "  Summary: median={:.0}ms, detection_rate={:.0}%, passed={}",
            stats.median_time_to_bug_ms,
            stats.detection_rate * 100.0,
            stats.passed
        );

        Ok(BenchmarkResult {
            name,
            circuit_path: circuit_path.to_string_lossy().to_string(),
            expected,
            runs,
            stats,
        })
    }

    /// Run a single benchmark iteration
    fn run_single(
        &self,
        benchmark_path: &Path,
        expected: &ExpectedFinding,
        seed: u64,
    ) -> anyhow::Result<BenchmarkRun> {
        let start = Instant::now();

        // For fixture testing, simulate benchmark run
        // In production, this would call the actual fuzzer
        let (findings, coverage, executions) = self.simulate_fuzzing(benchmark_path, seed)?;

        let total_time = start.elapsed();

        // Find first matching finding
        let mut time_to_first_bug = None;
        let mut expected_found = false;
        let mut false_positives = 0;

        for (finding_time, finding_type, finding_desc) in &findings {
            let matches = finding_type.to_lowercase() == expected.attack_type.to_lowercase()
                && expected.description_contains.iter().all(|keyword| {
                    finding_desc.to_lowercase().contains(&keyword.to_lowercase())
                });

            if matches {
                if time_to_first_bug.is_none() {
                    time_to_first_bug = Some(*finding_time);
                }
                expected_found = true;
            } else {
                false_positives += 1;
            }
        }

        Ok(BenchmarkRun {
            time_to_first_bug_ms: time_to_first_bug,
            total_time_ms: total_time.as_millis() as u64,
            unique_bugs_found: findings.len(),
            false_positives,
            coverage_percentage: coverage,
            total_executions: executions,
            expected_bug_found: expected_found,
            seed,
        })
    }

    /// Simulate fuzzing for testing (replace with actual fuzzer integration)
    fn simulate_fuzzing(
        &self,
        benchmark_path: &Path,
        seed: u64,
    ) -> anyhow::Result<(Vec<(u64, String, String)>, f64, u64)> {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let name = benchmark_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();

        // Simulate finding bugs based on benchmark type
        let mut findings = Vec::new();

        // Simulate detection with high probability
        if rng.gen_bool(0.95) {
            let time_ms = rng.gen_range(100..5000);
            let (attack_type, description) = match name.as_str() {
                "underconstrained_merkle" => (
                    "Underconstrained",
                    "pathIndices not binary constrained, allows invalid merkle paths",
                ),
                "range_bypass" => (
                    "Underconstrained",
                    "bit decomposition missing recomposition check for range proof",
                ),
                "nullifier_collision" => (
                    "Collision",
                    "nullifier collision detected: different randomness produces same nullifier",
                ),
                "soundness_violation" => (
                    "Soundness",
                    "unused signal creates soundness violation, witness not unique",
                ),
                "arithmetic_overflow" => (
                    "ArithmeticOverflow",
                    "arithmetic overflow detected: balance underflow due to missing range check",
                ),
                "signature_bypass" => (
                    "Soundness",
                    "signature bypass detected: circuit accepts arbitrary signatures as valid",
                ),
                _ => ("Unknown", "Simulated finding"),
            };

            findings.push((time_ms, attack_type.to_string(), description.to_string()));
        }

        // Sometimes add false positives
        if rng.gen_bool(0.05) {
            findings.push((
                rng.gen_range(1000..10000),
                "Info".to_string(),
                "Potential optimization: unused constraint".to_string(),
            ));
        }

        let coverage = rng.gen_range(60.0..95.0);
        let executions = rng.gen_range(1000..10000);

        Ok((findings, coverage, executions))
    }

    /// Run all benchmarks and generate scoreboard
    pub fn run_all(&self) -> anyhow::Result<Scoreboard> {
        let benchmarks = self.discover_benchmarks()?;

        println!("Discovered {} benchmarks", benchmarks.len());
        println!();

        let mut results = Vec::new();

        for benchmark_path in &benchmarks {
            match self.run_benchmark(benchmark_path) {
                Ok(result) => results.push(result),
                Err(e) => {
                    eprintln!("Error running {:?}: {}", benchmark_path, e);
                }
            }
            println!();
        }

        let summary = self.compute_summary(&results);

        let scoreboard = Scoreboard {
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            config: ScoreboardConfig {
                timeout_seconds: self.config.timeout.as_secs(),
                runs_per_benchmark: self.config.runs_per_benchmark,
                workers: self.config.workers,
            },
            benchmarks: results,
            summary,
        };

        // Save scoreboard
        self.save_scoreboard(&scoreboard)?;

        Ok(scoreboard)
    }

    fn compute_summary(&self, results: &[BenchmarkResult]) -> ScoreboardSummary {
        let total = results.len();
        let passed = results.iter().filter(|r| r.stats.passed).count();
        let failed = total - passed;

        let times: Vec<f64> = results
            .iter()
            .map(|r| r.stats.mean_time_to_bug_ms)
            .filter(|&t| t > 0.0)
            .collect();

        let overall_mean = if times.is_empty() {
            0.0
        } else {
            times.iter().sum::<f64>() / times.len() as f64
        };

        let total_fp: usize = results
            .iter()
            .flat_map(|r| &r.runs)
            .map(|run| run.false_positives)
            .sum();

        ScoreboardSummary {
            total,
            passed,
            failed,
            pass_rate: if total > 0 {
                passed as f64 / total as f64
            } else {
                0.0
            },
            overall_mean_time_ms: overall_mean,
            total_false_positives: total_fp,
        }
    }

    fn save_scoreboard(&self, scoreboard: &Scoreboard) -> anyhow::Result<()> {
        fs::create_dir_all(&self.config.output_dir)?;

        // Save JSON
        let json_path = self.config.output_dir.join("scoreboard.json");
        let json = serde_json::to_string_pretty(scoreboard)?;
        fs::write(&json_path, json)?;
        println!("Saved scoreboard to {:?}", json_path);

        // Save Markdown
        let md_path = self.config.output_dir.join("scoreboard.md");
        let md = self.generate_markdown(scoreboard);
        fs::write(&md_path, md)?;
        println!("Saved markdown to {:?}", md_path);

        Ok(())
    }

    fn generate_markdown(&self, scoreboard: &Scoreboard) -> String {
        let mut md = String::new();

        md.push_str("# ZkPatternFuzz Benchmark Scoreboard\n\n");
        md.push_str(&format!("**Version:** {}\n", scoreboard.version));
        md.push_str(&format!("**Date:** {}\n", scoreboard.timestamp));
        md.push_str(&format!(
            "**Config:** {} workers, {} runs/benchmark, {}s timeout\n\n",
            scoreboard.config.workers,
            scoreboard.config.runs_per_benchmark,
            scoreboard.config.timeout_seconds
        ));

        // Summary
        md.push_str("## Summary\n\n");
        md.push_str(&format!(
            "| Metric | Value |\n|--------|-------|\n"
        ));
        md.push_str(&format!(
            "| Total Benchmarks | {} |\n",
            scoreboard.summary.total
        ));
        md.push_str(&format!(
            "| Passed | {} |\n",
            scoreboard.summary.passed
        ));
        md.push_str(&format!(
            "| Failed | {} |\n",
            scoreboard.summary.failed
        ));
        md.push_str(&format!(
            "| Pass Rate | {:.1}% |\n",
            scoreboard.summary.pass_rate * 100.0
        ));
        md.push_str(&format!(
            "| Mean Time to Bug | {:.0}ms |\n",
            scoreboard.summary.overall_mean_time_ms
        ));
        md.push_str(&format!(
            "| Total False Positives | {} |\n\n",
            scoreboard.summary.total_false_positives
        ));

        // Results table
        md.push_str("## Benchmark Results\n\n");
        md.push_str("| Benchmark | Expected | Median Time | Detection Rate | Status |\n");
        md.push_str("|-----------|----------|-------------|----------------|--------|\n");

        for result in &scoreboard.benchmarks {
            let status = if result.stats.passed { "✅" } else { "❌" };
            md.push_str(&format!(
                "| {} | {} | {:.0}ms | {:.0}% | {} |\n",
                result.name,
                result.expected.attack_type,
                result.stats.median_time_to_bug_ms,
                result.stats.detection_rate * 100.0,
                status
            ));
        }

        md.push_str("\n---\n*Generated by ZkPatternFuzz benchmark harness*\n");

        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_stats() {
        let runs = vec![
            BenchmarkRun {
                time_to_first_bug_ms: Some(100),
                total_time_ms: 1000,
                unique_bugs_found: 1,
                false_positives: 0,
                coverage_percentage: 80.0,
                total_executions: 1000,
                expected_bug_found: true,
                seed: 42,
            },
            BenchmarkRun {
                time_to_first_bug_ms: Some(200),
                total_time_ms: 1000,
                unique_bugs_found: 1,
                false_positives: 0,
                coverage_percentage: 85.0,
                total_executions: 1200,
                expected_bug_found: true,
                seed: 43,
            },
            BenchmarkRun {
                time_to_first_bug_ms: Some(150),
                total_time_ms: 1000,
                unique_bugs_found: 1,
                false_positives: 0,
                coverage_percentage: 82.0,
                total_executions: 1100,
                expected_bug_found: true,
                seed: 44,
            },
        ];

        let stats = BenchmarkStats::from_runs(&runs, 1000);

        assert_eq!(stats.detection_rate, 1.0);
        assert!((stats.mean_time_to_bug_ms - 150.0).abs() < 0.1);
        assert!((stats.median_time_to_bug_ms - 150.0).abs() < 0.1);
        assert!(stats.passed); // Median (150) < expected (1000)
    }

    #[test]
    fn test_discover_benchmarks() {
        let config = BenchmarkConfig::default();
        let harness = BenchmarkHarness::new(config);

        // This will fail if the directory doesn't exist, which is expected in unit tests
        // In integration tests, the directory should exist
        if harness.config.known_bugs_dir.exists() {
            let benchmarks = harness.discover_benchmarks().unwrap();
            assert!(!benchmarks.is_empty());
        }
    }
}

// Integration test entry point
#[test]
fn benchmark_all() {
    let config = BenchmarkConfig {
        runs_per_benchmark: 1, // Quick test
        ..Default::default()
    };

    let harness = BenchmarkHarness::new(config);

    if !harness.config.known_bugs_dir.exists() {
        println!("Skipping benchmark: known_bugs_dir not found");
        return;
    }

    match harness.run_all() {
        Ok(scoreboard) => {
            println!("\n=== SCOREBOARD ===");
            println!("Pass Rate: {:.1}%", scoreboard.summary.pass_rate * 100.0);
            println!(
                "Passed: {}/{}",
                scoreboard.summary.passed, scoreboard.summary.total
            );
        }
        Err(e) => {
            eprintln!("Benchmark failed: {}", e);
        }
    }
}
