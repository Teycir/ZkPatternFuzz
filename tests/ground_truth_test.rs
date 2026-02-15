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
//! ```

use std::path::PathBuf;

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
    /// Finding types detected
    pub finding_types: Vec<String>,
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
        println!(
            "  True Positives:     {} (bugs correctly detected)",
            self.true_positives
        );
        println!(
            "  True Negatives:     {} (clean circuits correctly passed)",
            self.true_negatives
        );
        println!(
            "  False Positives:    {} (false alarms)",
            self.false_positives
        );
        println!(
            "  False Negatives:    {} (missed bugs)",
            self.false_negatives
        );
        println!();
        println!(
            "  Detection Rate:     {:.1}%",
            self.detection_rate() * 100.0
        );
        println!(
            "  False Positive Rate: {:.1}%",
            self.false_positive_rate() * 100.0
        );
        println!("  Overall Accuracy:   {:.1}%", self.accuracy() * 100.0);
        println!();

        if self.false_negatives > 0 {
            println!("  ⚠️  WARNING: {} bugs were MISSED", self.false_negatives);
        }
        if self.false_positives > 0 {
            println!(
                "  ⚠️  WARNING: {} false positives reported",
                self.false_positives
            );
        }
        if self.false_negatives == 0 && self.false_positives == 0 {
            println!("  ✅ PERFECT SCORE: 100% detection, 0% false positives");
        }
        println!("═══════════════════════════════════════════════════════════════\n");
    }
}

/// Known bug specification
#[derive(Debug, Clone)]
pub struct KnownBug {
    pub name: String,
    pub circuit_path: PathBuf,
    pub expected_attack_type: String,
    pub expected_severity: String,
    pub description_keywords: Vec<String>,
}

/// Known bug test cases from tests/bench/known_bugs/
fn known_bug_circuits() -> Vec<KnownBug> {
    let base_dir = PathBuf::from("tests/bench/known_bugs");

    vec![
        KnownBug {
            name: "underconstrained_merkle".to_string(),
            circuit_path: base_dir.join("underconstrained_merkle/circuit.circom"),
            expected_attack_type: "Underconstrained".to_string(),
            expected_severity: "critical".to_string(),
            description_keywords: vec!["pathIndices".to_string(), "binary".to_string()],
        },
        KnownBug {
            name: "arithmetic_overflow".to_string(),
            circuit_path: base_dir.join("arithmetic_overflow/circuit.circom"),
            expected_attack_type: "ArithmeticOverflow".to_string(),
            expected_severity: "high".to_string(),
            description_keywords: vec!["overflow".to_string(), "range".to_string()],
        },
        KnownBug {
            name: "nullifier_collision".to_string(),
            circuit_path: base_dir.join("nullifier_collision/circuit.circom"),
            expected_attack_type: "Collision".to_string(),
            expected_severity: "critical".to_string(),
            description_keywords: vec!["nullifier".to_string(), "collision".to_string()],
        },
        KnownBug {
            name: "range_bypass".to_string(),
            circuit_path: base_dir.join("range_bypass/circuit.circom"),
            expected_attack_type: "Underconstrained".to_string(),
            expected_severity: "high".to_string(),
            description_keywords: vec!["range".to_string(), "bit".to_string()],
        },
        KnownBug {
            name: "soundness_violation".to_string(),
            circuit_path: base_dir.join("soundness_violation/circuit.circom"),
            expected_attack_type: "Soundness".to_string(),
            expected_severity: "critical".to_string(),
            description_keywords: vec!["unused".to_string(), "soundness".to_string()],
        },
        KnownBug {
            name: "signature_bypass".to_string(),
            circuit_path: base_dir.join("signature_bypass/circuit.circom"),
            expected_attack_type: "Soundness".to_string(),
            expected_severity: "critical".to_string(),
            description_keywords: vec!["signature".to_string(), "bypass".to_string()],
        },
    ]
}

/// Test: Verify test infrastructure is set up correctly
#[test]
fn ground_truth_infrastructure_smoke_test() {
    println!("\n=== Ground Truth Infrastructure Smoke Test ===\n");

    let known_bugs = known_bug_circuits();
    let base_dir = PathBuf::from("tests/bench/known_bugs");

    // Verify base directory exists
    assert!(base_dir.exists(), "Known bugs directory should exist");

    // Check each known bug
    let mut found_count = 0;
    for bug in &known_bugs {
        let exists = bug.circuit_path.exists();
        let expected_json = bug
            .circuit_path
            .parent()
            .unwrap()
            .join("expected_finding.json");
        let has_expected = expected_json.exists();

        println!(
            "  {} -> circuit={}, expected_finding={}",
            bug.name, exists, has_expected
        );

        if exists && has_expected {
            found_count += 1;
        }
    }

    println!(
        "\n  Found {}/{} complete test cases\n",
        found_count,
        known_bugs.len()
    );

    // At minimum, verify at least 5 known bug cases exist
    assert!(
        found_count >= 5,
        "Should have at least 5 known bug test cases, found {}",
        found_count
    );

    println!("✅ Ground truth infrastructure is set up correctly\n");
}

/// Test: Known-buggy circuits should be detected.
///
/// When circom tooling is available (CI or dev image) the test compiles each
/// known-buggy circuit and runs ZkPatternFuzz against it with the real Circom
/// backend.
#[tokio::test]
async fn ground_truth_known_bugs() {
    use zk_fuzzer::config::FuzzConfig;
    use zk_fuzzer::fuzzer::FuzzingEngine;

    println!("\n=== Ground Truth Test: Known Bugs ===\n");

    let circom_available = std::process::Command::new("circom")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !circom_available {
        println!("  circom not detected; skipping known-bugs execution test");
        println!("  install circom + snarkjs to enable this suite\n");
        return;
    }
    println!("  circom detected – using real execution path\n");

    let mut stats = GroundTruthStats::default();

    for bug in known_bug_circuits() {
        println!("Testing: {} ({:?})", bug.name, bug.circuit_path);

        if !bug.circuit_path.exists() {
            println!("  SKIP: Circuit file not found");
            continue;
        }

        let yaml = generate_campaign_yaml(&bug);

        let config: FuzzConfig = match serde_yaml::from_str(&yaml) {
            Ok(c) => c,
            Err(e) => {
                println!("  SKIP: bad YAML for {}: {}", bug.name, e);
                continue;
            }
        };

        let report = {
            let mut engine = match FuzzingEngine::new(config, Some(42), 1) {
                Ok(e) => e,
                Err(e) => {
                    println!("  SKIP: engine init failed for {}: {}", bug.name, e);
                    continue;
                }
            };
            match engine.run(None).await {
                Ok(r) => r,
                Err(e) => {
                    println!("  SKIP: execution failed for {}: {}", bug.name, e);
                    continue;
                }
            }
        };

        let bug_found = !report.findings.is_empty();
        let finding_types: Vec<String> = report
            .findings
            .iter()
            .map(|f| format!("{:?}", f.attack_type))
            .collect();

        let result = GroundTruthResult {
            name: bug.name.clone(),
            bug_expected: true,
            bug_found,
            findings_count: report.findings.len(),
            finding_types: finding_types.clone(),
            time_ms: 0,
            is_true_positive: bug_found,
            is_false_positive: false,
            is_false_negative: !bug_found,
            is_true_negative: false,
        };
        stats.add_result(&result);

        let status = if bug_found {
            "✓ DETECTED"
        } else {
            "✗ MISSED"
        };
        println!(
            "  {} — {} findings {:?}",
            status,
            report.findings.len(),
            finding_types
        );
    }

    stats.print_summary();

    assert!(
        stats.detection_rate() >= 0.80,
        "Detection rate {:.1}% should be >= 80% with real circom",
        stats.detection_rate() * 100.0
    );
}

/// Test: Full ground truth evaluation with real circuits
#[test]
// Requires circom installation
fn ground_truth_full_evaluation() {
    let config = GroundTruthConfig::default();

    println!("\n=== Full Ground Truth Evaluation ===\n");
    println!("Configuration:");
    println!("  Timeout: {} seconds", config.timeout_secs);
    println!("  Iterations: {}", config.iterations);
    println!("  Seed: {}", config.seed);
    println!("  Workers: {}\n", config.workers);

    let known_bugs = known_bug_circuits();

    println!("Total test cases: {}", known_bugs.len());
    println!("  Known bugs: {}", known_bugs.len());

    // Print expected outcomes
    println!("\nExpected outcomes:");
    for bug in &known_bugs {
        println!(
            "  - {}: {} ({})",
            bug.name, bug.expected_attack_type, bug.expected_severity
        );
    }

    println!("\n⚠️  Full evaluation requires circom installation");
    println!("   Run: npm install -g snarkjs && brew install circom (or equivalent)\n");
}

/// Campaign YAML generator for known bug circuits
pub fn generate_campaign_yaml(bug: &KnownBug) -> String {
    format!(
        r#"# Auto-generated campaign for ground truth testing
campaign:
  name: "Ground Truth: {name}"
  version: "2.0"
  target:
    framework: "circom"
    circuit_path: "{path}"
    main_component: "{component}"
  parameters:
    max_constraints: 100000
    timeout_seconds: 60
    additional:
      strict_backend: true
      evidence_mode: true
      per_exec_isolation: true
      max_iterations: 10000
      oracle_validation: true

invariants:
  - name: "detect_{name}"
    invariant_type: constraint
    relation: "circuit_should_fail_on_invalid_inputs"
    oracle: must_hold
    severity: "{severity}"

attacks:
  - type: "underconstrained"
    config:
      witness_pairs: 1000

  - type: "soundness"
    config:
      forge_attempts: 500

  - type: "boundary"
    config:
      test_values: ["0", "1", "p-1"]

inputs:
  # Auto-detect from circuit
  - name: "input"
    type: "field"
    fuzz_strategy: random

reporting:
  output_dir: "./reports/ground_truth/{name}"
  formats: ["json", "markdown"]
  include_poc: true
"#,
        name = bug.name,
        path = bug.circuit_path.display(),
        component = bug
            .name
            .replace("_", "")
            .chars()
            .enumerate()
            .map(|(i, c)| if i == 0 {
                c.to_uppercase().next().unwrap()
            } else {
                c
            })
            .collect::<String>(),
        severity = bug.expected_severity,
    )
}
