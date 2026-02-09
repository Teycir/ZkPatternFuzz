//! Chain Benchmark Harness for Mode 3: Multi-Step Chain Fuzzing
//!
//! This benchmark measures the FP/FN rate and performance metrics
//! of the chain fuzzer against ground truth circuits.
//!
//! Run with: `cargo bench --bench chain_benchmark`
//! (Note: This is too slow for regular test suite)

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

/// Benchmark result for chain fuzzing
#[derive(Debug, Clone)]
pub struct ChainBenchmarkResult {
    /// Number of true positives (correctly detected bugs)
    pub true_positives: usize,
    /// Number of false positives (findings on clean code)
    pub false_positives: usize,
    /// Number of false negatives (missed bugs)
    pub false_negatives: usize,
    /// Number of true negatives (correctly passed clean code)
    pub true_negatives: usize,
    /// Precision: TP / (TP + FP)
    pub precision: f64,
    /// Recall: TP / (TP + FN)
    pub recall: f64,
    /// Mean L_min across all findings
    pub mean_l_min: f64,
    /// P(L_min >= 2) - probability of deep findings
    pub p_deep: f64,
    /// Mean time to first finding per chain
    pub mean_time_to_first: Duration,
    /// Total benchmark duration
    pub total_duration: Duration,
    /// Per-chain results
    pub chain_results: HashMap<String, ChainResult>,
}

/// Result for a single chain benchmark
#[derive(Debug, Clone)]
pub struct ChainResult {
    /// Chain name
    pub name: String,
    /// Expected outcome
    pub expected_outcome: String,
    /// Actual outcome
    pub actual_outcome: String,
    /// Number of findings
    pub findings_count: usize,
    /// L_min values for each finding
    pub l_min_values: Vec<usize>,
    /// Time to first finding (if any)
    pub time_to_first: Option<Duration>,
    /// Execution duration
    pub duration: Duration,
    /// Whether this chain passed (matched expected)
    pub passed: bool,
}

impl ChainBenchmarkResult {
    /// Create a new benchmark result
    pub fn new() -> Self {
        Self {
            true_positives: 0,
            false_positives: 0,
            false_negatives: 0,
            true_negatives: 0,
            precision: 0.0,
            recall: 0.0,
            mean_l_min: 0.0,
            p_deep: 0.0,
            mean_time_to_first: Duration::ZERO,
            total_duration: Duration::ZERO,
            chain_results: HashMap::new(),
        }
    }

    /// Compute derived metrics after all chains have been processed
    pub fn compute_metrics(&mut self) {
        // Precision
        let precision_denom = self.true_positives + self.false_positives;
        self.precision = if precision_denom > 0 {
            self.true_positives as f64 / precision_denom as f64
        } else {
            1.0
        };

        // Recall
        let recall_denom = self.true_positives + self.false_negatives;
        self.recall = if recall_denom > 0 {
            self.true_positives as f64 / recall_denom as f64
        } else {
            1.0
        };

        // Mean L_min
        let all_l_mins: Vec<usize> = self.chain_results.values()
            .flat_map(|r| r.l_min_values.iter().copied())
            .collect();
        
        self.mean_l_min = if !all_l_mins.is_empty() {
            all_l_mins.iter().sum::<usize>() as f64 / all_l_mins.len() as f64
        } else {
            0.0
        };

        // P(L_min >= 2)
        let deep_count = all_l_mins.iter().filter(|&&l| l >= 2).count();
        self.p_deep = if !all_l_mins.is_empty() {
            deep_count as f64 / all_l_mins.len() as f64
        } else {
            0.0
        };

        // Mean time to first finding
        let times: Vec<Duration> = self.chain_results.values()
            .filter_map(|r| r.time_to_first)
            .collect();
        
        self.mean_time_to_first = if !times.is_empty() {
            times.iter().sum::<Duration>() / times.len() as u32
        } else {
            Duration::ZERO
        };
    }

    /// Generate a markdown report
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        
        md.push_str("# Chain Benchmark Report\n\n");
        md.push_str(&format!("**Generated:** {}\n\n", chrono::Utc::now().to_rfc3339()));
        
        md.push_str("## Summary Metrics\n\n");
        md.push_str("| Metric | Value | Target |\n");
        md.push_str("|--------|-------|--------|\n");
        md.push_str(&format!("| Precision | {:.2}% | >= 90% |\n", self.precision * 100.0));
        md.push_str(&format!("| Recall | {:.2}% | >= 80% |\n", self.recall * 100.0));
        md.push_str(&format!("| Mean L_min (D) | {:.2} | > 1 |\n", self.mean_l_min));
        md.push_str(&format!("| P(L_min >= 2) | {:.2}% | > 0% |\n", self.p_deep * 100.0));
        md.push_str(&format!("| Mean Time to First | {:.2}s | - |\n", self.mean_time_to_first.as_secs_f64()));
        md.push_str(&format!("| Total Duration | {:.2}s | - |\n\n", self.total_duration.as_secs_f64()));

        md.push_str("## Confusion Matrix\n\n");
        md.push_str("| | Predicted Positive | Predicted Negative |\n");
        md.push_str("|---|---|---|\n");
        md.push_str(&format!("| Actual Positive | TP: {} | FN: {} |\n", self.true_positives, self.false_negatives));
        md.push_str(&format!("| Actual Negative | FP: {} | TN: {} |\n\n", self.false_positives, self.true_negatives));

        md.push_str("## Per-Chain Results\n\n");
        md.push_str("| Chain | Expected | Actual | Findings | L_min | Time | Status |\n");
        md.push_str("|-------|----------|--------|----------|-------|------|--------|\n");
        
        for (name, result) in &self.chain_results {
            let l_min_str = if result.l_min_values.is_empty() {
                "-".to_string()
            } else {
                format!("{:?}", result.l_min_values)
            };
            
            let status = if result.passed { "✓" } else { "✗" };
            
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {:.2}s | {} |\n",
                name,
                result.expected_outcome,
                result.actual_outcome,
                result.findings_count,
                l_min_str,
                result.duration.as_secs_f64(),
                status
            ));
        }

        md.push_str("\n## CI Gate Status\n\n");
        let precision_pass = self.precision >= 0.9;
        let recall_pass = self.recall >= 0.8;
        
        md.push_str(&format!("- Precision >= 0.9: {} ({:.2}%)\n", 
            if precision_pass { "✓ PASS" } else { "✗ FAIL" },
            self.precision * 100.0
        ));
        md.push_str(&format!("- Recall >= 0.8: {} ({:.2}%)\n",
            if recall_pass { "✓ PASS" } else { "✗ FAIL" },
            self.recall * 100.0
        ));
        
        let overall = precision_pass && recall_pass;
        md.push_str(&format!("\n**Overall:** {}\n", 
            if overall { "✓ PASS" } else { "✗ FAIL" }
        ));

        md
    }
}

impl Default for ChainBenchmarkResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Ground truth chain definitions for benchmarking
pub fn get_benchmark_chains() -> Vec<BenchmarkChain> {
    vec![
        BenchmarkChain {
            name: "deposit_withdraw_buggy".to_string(),
            campaign_path: "tests/ground_truth/chains/deposit_withdraw/chain_campaign.yaml".to_string(),
            expected_finding: true,
            expected_assertion: Some("nullifier_uniqueness".to_string()),
        },
        BenchmarkChain {
            name: "update_verify_buggy".to_string(),
            campaign_path: "tests/ground_truth/chains/update_verify/chain_campaign.yaml".to_string(),
            expected_finding: true,
            expected_assertion: Some("root_propagation".to_string()),
        },
        BenchmarkChain {
            name: "sign_verify_buggy".to_string(),
            campaign_path: "tests/ground_truth/chains/sign_verify/chain_campaign.yaml".to_string(),
            expected_finding: true,
            expected_assertion: Some("signature_validity".to_string()),
        },
        BenchmarkChain {
            name: "clean_deposit_withdraw".to_string(),
            campaign_path: "tests/ground_truth/chains/clean_deposit_withdraw/chain_campaign.yaml".to_string(),
            expected_finding: false,
            expected_assertion: None,
        },
    ]
}

/// Definition of a benchmark chain
#[derive(Debug, Clone)]
pub struct BenchmarkChain {
    pub name: String,
    pub campaign_path: String,
    pub expected_finding: bool,
    pub expected_assertion: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_result_metrics() {
        let mut result = ChainBenchmarkResult {
            true_positives: 3,
            false_positives: 0,
            false_negatives: 0,
            true_negatives: 1,
            ..Default::default()
        };

        result.chain_results.insert("test1".to_string(), ChainResult {
            name: "test1".to_string(),
            expected_outcome: "CONFIRMED".to_string(),
            actual_outcome: "CONFIRMED".to_string(),
            findings_count: 1,
            l_min_values: vec![2],
            time_to_first: Some(Duration::from_secs(5)),
            duration: Duration::from_secs(10),
            passed: true,
        });

        result.compute_metrics();

        assert_eq!(result.precision, 1.0);
        assert_eq!(result.recall, 1.0);
        assert_eq!(result.mean_l_min, 2.0);
        assert_eq!(result.p_deep, 1.0);
    }

    #[test]
    fn test_markdown_generation() {
        let mut result = ChainBenchmarkResult {
            true_positives: 2,
            false_positives: 1,
            false_negatives: 0,
            true_negatives: 1,
            precision: 0.666,
            recall: 1.0,
            mean_l_min: 2.5,
            p_deep: 0.8,
            mean_time_to_first: Duration::from_secs(3),
            total_duration: Duration::from_secs(60),
            chain_results: HashMap::new(),
        };

        let md = result.to_markdown();
        
        assert!(md.contains("Chain Benchmark Report"));
        assert!(md.contains("Precision"));
        assert!(md.contains("Recall"));
        assert!(md.contains("Confusion Matrix"));
    }

    #[test]
    fn test_benchmark_chains_exist() {
        let chains = get_benchmark_chains();
        
        assert_eq!(chains.len(), 4);
        assert_eq!(chains.iter().filter(|c| c.expected_finding).count(), 3);
        assert_eq!(chains.iter().filter(|c| !c.expected_finding).count(), 1);
    }
}
