//! Ground Truth Test Suite
//!
//! This test suite measures the false positive and false negative rates of
//! ZkPatternFuzz against known-buggy and known-clean circuits.
//!
//! # Test Categories
//!
//! 1. **True Positives**: Known-buggy circuits where we expect to find vulnerabilities
//! 2. **True Negatives**: Known-clean circuits where we expect no findings
//!
//! # Success Criteria
//!
//! - All known bugs must be detected (100% detection rate for TP)
//! - Zero false positives on clean circuits (0% FP rate)
//!
//! # Usage
//!
//! ```bash
//! cargo test --test ground_truth_test -- --nocapture
//! cargo test --test ground_truth_test ground_truth_known_bugs -- --nocapture
//! cargo test --test ground_truth_test ground_truth_clean_circuits -- --nocapture
//! ```

use std::path::PathBuf;
use std::collections::HashMap;

/// Test configuration for ground truth evaluation
#[derive(Debug, Clone)]
pub struct GroundTruthConfig {
    /// Timeout per circuit in seconds
    pub timeout_secs: u64,
    /// Number of fuzzing iterations
    pub iterations: u64,
    /// Random seed for reproducibility
    pub seed: u64,
    /// Number of workers
    pub workers: usize,
}

impl Default for GroundTruthConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 60,
            iterations: 10000,
            seed: 42,
            workers: 4,
        }
    }
}

/// Result of a ground truth test
#[derive(Debug, Clone)]
pub struct GroundTruthResult {
    /// Circuit name
    pub name: String,
    /// Whether a bug was expected
    pub bug_expected: bool,
    /// Whether a bug was found
    pub bug_found: bool,
    /// Number of findings
    pub findings_count: usize,
    /// Time taken in milliseconds
    pub time_ms: u64,
    /// Is this a true positive?
    pub is_true_positive: bool,
    /// Is this a false positive?
    pub is_false_positive: bool,
    /// Is this a false negative?
    pub is_false_negative: bool,
    /// Is this a true negative?
    pub is_true_negative: bool,
}

/// Aggregate statistics from ground truth tests
#[derive(Debug, Default)]
pub struct GroundTruthStats {
    pub total_tests: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub true_negatives: usize,
    pub false_negatives: usize,
}

impl GroundTruthStats {
    pub fn add_result(&mut self, result: &GroundTruthResult) {
        self.total_tests += 1;
        if result.is_true_positive {
            self.true_positives += 1;
        }
        if result.is_false_positive {
            self.false_positives += 1;
        }
        if result.is_true_negative {
            self.true_negatives += 1;
        }
        if result.is_false_negative {
            self.false_negatives += 1;
        }
    }

    pub fn detection_rate(&self) -> f64 {
        let expected_positives = self.true_positives + self.false_negatives;
        if expected_positives == 0 {
            return 1.0;
        }
        self.true_positives as f64 / expected_positives as f64
    }

    pub fn false_positive_rate(&self) -> f64 {
        let expected_negatives = self.true_negatives + self.false_positives;
        if expected_negatives == 0 {
            return 0.0;
        }
        self.false_positives as f64 / expected_negatives as f64
    }

    pub fn accuracy(&self) -> f64 {
        if self.total_tests == 0 {
            return 1.0;
        }
        (self.true_positives + self.true_negatives) as f64 / self.total_tests as f64
    }

    pub fn print_summary(&self) {
        println!("\n═══════════════════════════════════════════════════════════════");
        println!("                    GROUND TRUTH SUMMARY                        ");
        println!("═══════════════════════════════════════════════════════════════");
        println!();
        println!("  Total Tests:        {}", self.total_tests);
        println!();
        println!("  True Positives:     {} (bugs correctly detected)", self.true_positives);
        println!("  True Negatives:     {} (clean circuits correctly passed)", self.true_negatives);
        println!("  False Positives:    {} (false alarms)", self.false_positives);
        println!("  False Negatives:    {} (missed bugs)", self.false_negatives);
        println!();
        println!("  Detection Rate:     {:.1}%", self.detection_rate() * 100.0);
        println!("  False Positive Rate: {:.1}%", self.false_positive_rate() * 100.0);
        println!("  Overall Accuracy:   {:.1}%", self.accuracy() * 100.0);
        println!();
        
        if self.false_negatives > 0 {
            println!("  ⚠️  WARNING: {} bugs were MISSED", self.false_negatives);
        }
        if self.false_positives > 0 {
            println!("  ⚠️  WARNING: {} false positives reported", self.false_positives);
        }
        if self.false_negatives == 0 && self.false_positives == 0 {
            println!("  ✅ PERFECT SCORE: 100% detection, 0% false positives");
        }
        println!("═══════════════════════════════════════════════════════════════\n");
    }
}

/// Known bug test cases from tests/bench/known_bugs/
fn known_bug_circuits() -> Vec<(String, PathBuf, bool)> {
    let base_dir = PathBuf::from("tests/bench/known_bugs");
    
    let mut cases = Vec::new();
    
    // Each subdirectory contains a known-buggy circuit
    let bug_dirs = [
        "underconstrained_merkle",
        "arithmetic_overflow",
        "nullifier_collision",
        "range_bypass",
        "soundness_violation",
    ];
    
    for dir in bug_dirs {
        let circuit_path = base_dir.join(dir).join("circuit.circom");
        if circuit_path.exists() {
            cases.push((
                dir.to_string(),
                circuit_path,
                true, // bug_expected = true for known bugs
            ));
        }
    }
    
    cases
}

/// Clean circuit test cases (should have NO findings)
fn clean_circuits() -> Vec<(String, PathBuf, bool)> {
    // These circuits are correctly constrained and should produce no findings
    // TODO: Add actual clean circuit paths when available
    vec![
        // Example placeholder - replace with actual clean circuits
        // ("clean_poseidon".to_string(), PathBuf::from("circuits/clean/poseidon.circom"), false),
    ]
}

/// Run a single ground truth test
#[cfg(feature = "ground_truth")]
fn run_ground_truth_test(
    name: &str,
    circuit_path: &PathBuf,
    bug_expected: bool,
    config: &GroundTruthConfig,
) -> GroundTruthResult {
    use std::time::Instant;
    
    let start = Instant::now();
    
    // TODO: Implement actual fuzzing campaign execution
    // This would create a FuzzConfig, run FuzzingEngine, and collect findings
    
    // Placeholder implementation
    let findings_count = 0;
    let bug_found = findings_count > 0;
    
    let elapsed_ms = start.elapsed().as_millis() as u64;
    
    GroundTruthResult {
        name: name.to_string(),
        bug_expected,
        bug_found,
        findings_count,
        time_ms: elapsed_ms,
        is_true_positive: bug_expected && bug_found,
        is_false_positive: !bug_expected && bug_found,
        is_false_negative: bug_expected && !bug_found,
        is_true_negative: !bug_expected && !bug_found,
    }
}

/// Test: Known-buggy circuits should be detected
#[test]
#[ignore = "Requires circom installation and circuit compilation"]
fn ground_truth_known_bugs() {
    let config = GroundTruthConfig::default();
    let mut stats = GroundTruthStats::default();
    
    println!("\n=== Ground Truth Test: Known Bugs ===\n");
    
    for (name, path, bug_expected) in known_bug_circuits() {
        println!("Testing: {} ({:?})", name, path);
        
        if !path.exists() {
            println!("  SKIP: Circuit file not found");
            continue;
        }
        
        // For now, just verify the test structure exists
        // TODO: Enable actual fuzzing when circom is available
        println!("  Expected: bug = {}", bug_expected);
        println!("  Status: PENDING (requires circom)\n");
    }
    
    // Print summary
    println!("\nKnown bug circuits found: {}", known_bug_circuits().len());
    println!("Note: Run with circom installed for actual testing\n");
}

/// Test: Clean circuits should produce no findings
#[test]
#[ignore = "Requires clean circuit test cases"]
fn ground_truth_clean_circuits() {
    let config = GroundTruthConfig::default();
    let mut stats = GroundTruthStats::default();
    
    println!("\n=== Ground Truth Test: Clean Circuits ===\n");
    
    for (name, path, bug_expected) in clean_circuits() {
        println!("Testing: {} ({:?})", name, path);
        
        if !path.exists() {
            println!("  SKIP: Circuit file not found");
            continue;
        }
        
        println!("  Expected: bug = {}", bug_expected);
        println!("  Status: PENDING\n");
    }
    
    println!("\nClean circuits found: {}", clean_circuits().len());
}

/// Test: Full ground truth evaluation
#[test]
#[ignore = "Requires circom installation"]
fn ground_truth_full_evaluation() {
    let config = GroundTruthConfig::default();
    let mut stats = GroundTruthStats::default();
    
    println!("\n=== Full Ground Truth Evaluation ===\n");
    println!("Configuration:");
    println!("  Timeout: {} seconds", config.timeout_secs);
    println!("  Iterations: {}", config.iterations);
    println!("  Seed: {}", config.seed);
    println!("  Workers: {}\n", config.workers);
    
    // Collect all test cases
    let mut all_tests = Vec::new();
    all_tests.extend(known_bug_circuits());
    all_tests.extend(clean_circuits());
    
    println!("Total test cases: {}", all_tests.len());
    println!("  Known bugs: {}", known_bug_circuits().len());
    println!("  Clean circuits: {}", clean_circuits().len());
    
    // Note: Actual execution would happen here with circom installed
    println!("\n⚠️  Full evaluation requires circom installation");
    println!("   Run: npm install -g snarkjs && brew install circom (or equivalent)\n");
    
    // Print expected outcome
    println!("Expected outcomes:");
    println!("  - All {} known bugs should be detected", known_bug_circuits().len());
    println!("  - All {} clean circuits should pass with 0 findings", clean_circuits().len());
}

/// Smoke test: Verify test infrastructure works
#[test]
fn ground_truth_infrastructure_smoke_test() {
    // Verify known bug directories exist
    let known_bugs = known_bug_circuits();
    
    println!("\n=== Ground Truth Infrastructure Smoke Test ===\n");
    
    for (name, path, expected) in &known_bugs {
        let exists = path.exists();
        println!("  {} -> exists={}, bug_expected={}", name, exists, expected);
    }
    
    // At minimum, verify the test structure exists
    let base_dir = PathBuf::from("tests/bench/known_bugs");
    assert!(base_dir.exists(), "Known bugs directory should exist");
    
    // Verify at least one known bug case exists
    assert!(!known_bugs.is_empty(), "Should have at least one known bug test case");
    
    println!("\n✅ Ground truth infrastructure is set up correctly\n");
}
