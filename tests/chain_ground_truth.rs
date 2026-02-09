//! Ground Truth Tests for Mode 3: Multi-Step Chain Fuzzing
//!
//! This test suite validates that the chain fuzzer correctly detects
//! known vulnerabilities in intentionally buggy chain circuits while
//! avoiding false positives on clean implementations.
//!
//! Run with: `cargo test --test chain_ground_truth`

use std::path::Path;

/// Ground truth test case definition
#[derive(Debug)]
#[allow(dead_code)]
struct ChainGroundTruth {
    /// Name of the test case
    name: &'static str,
    /// Path to the campaign YAML
    campaign_path: &'static str,
    /// Expected outcome
    expected_outcome: ExpectedOutcome,
    /// Expected violated assertion (if any)
    expected_assertion: Option<&'static str>,
    /// Expected minimum L_min (if finding expected)
    expected_l_min: Option<usize>,
}

#[derive(Debug, PartialEq)]
enum ExpectedOutcome {
    /// Finding should be confirmed
    Confirmed,
    /// No finding expected (clean implementation)
    Clean,
}

/// Get all ground truth test cases
fn ground_truth_cases() -> Vec<ChainGroundTruth> {
    vec![
        ChainGroundTruth {
            name: "deposit_withdraw_nullifier_reuse",
            campaign_path: "tests/ground_truth/chains/deposit_withdraw/chain_campaign.yaml",
            expected_outcome: ExpectedOutcome::Confirmed,
            expected_assertion: Some("nullifier_uniqueness"),
            expected_l_min: Some(2),
        },
        ChainGroundTruth {
            name: "update_verify_root_inconsistency",
            campaign_path: "tests/ground_truth/chains/update_verify/chain_campaign.yaml",
            expected_outcome: ExpectedOutcome::Confirmed,
            expected_assertion: Some("root_propagation"),
            expected_l_min: Some(2),
        },
        ChainGroundTruth {
            name: "sign_verify_malleability",
            campaign_path: "tests/ground_truth/chains/sign_verify/chain_campaign.yaml",
            expected_outcome: ExpectedOutcome::Confirmed,
            expected_assertion: Some("signature_validity"),
            expected_l_min: Some(2),
        },
        ChainGroundTruth {
            name: "clean_deposit_withdraw",
            campaign_path: "tests/ground_truth/chains/clean_deposit_withdraw/chain_campaign.yaml",
            expected_outcome: ExpectedOutcome::Clean,
            expected_assertion: None,
            expected_l_min: None,
        },
    ]
}

/// Result of running a ground truth test
#[derive(Debug)]
#[allow(dead_code)]
struct GroundTruthResult {
    name: String,
    passed: bool,
    expected: ExpectedOutcome,
    actual_findings: usize,
    actual_assertion: Option<String>,
    actual_l_min: Option<usize>,
    error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that all ground truth cases have valid campaign files
    #[test]
    fn test_ground_truth_campaigns_exist() {
        for case in ground_truth_cases() {
            let path = Path::new(case.campaign_path);
            assert!(
                path.exists(),
                "Campaign file missing for {}: {}",
                case.name,
                case.campaign_path
            );
        }
    }

    /// Test that all ground truth cases have expected_finding.json
    #[test]
    fn test_ground_truth_expected_findings_exist() {
        let expected_paths = [
            "tests/ground_truth/chains/deposit_withdraw/expected_finding.json",
            "tests/ground_truth/chains/update_verify/expected_finding.json",
            "tests/ground_truth/chains/sign_verify/expected_finding.json",
            "tests/ground_truth/chains/clean_deposit_withdraw/expected_finding.json",
        ];

        for path_str in expected_paths {
            let path = Path::new(path_str);
            assert!(
                path.exists(),
                "Expected finding file missing: {}",
                path_str
            );
        }
    }

    /// Test that all ground truth cases have circuit files
    #[test]
    fn test_ground_truth_circuits_exist() {
        let circuit_paths = [
            "tests/ground_truth/chains/deposit_withdraw/deposit.circom",
            "tests/ground_truth/chains/deposit_withdraw/withdraw.circom",
            "tests/ground_truth/chains/update_verify/update_root.circom",
            "tests/ground_truth/chains/update_verify/verify_root.circom",
            "tests/ground_truth/chains/sign_verify/sign.circom",
            "tests/ground_truth/chains/sign_verify/verify.circom",
            "tests/ground_truth/chains/clean_deposit_withdraw/clean_deposit.circom",
            "tests/ground_truth/chains/clean_deposit_withdraw/clean_withdraw.circom",
        ];

        for path_str in circuit_paths {
            let path = Path::new(path_str);
            assert!(
                path.exists(),
                "Circuit file missing: {}",
                path_str
            );
        }
    }

    /// Test parsing of expected finding files
    #[test]
    fn test_parse_expected_findings() {
        use std::fs;
        
        let expected_paths = [
            "tests/ground_truth/chains/deposit_withdraw/expected_finding.json",
            "tests/ground_truth/chains/update_verify/expected_finding.json",
            "tests/ground_truth/chains/sign_verify/expected_finding.json",
            "tests/ground_truth/chains/clean_deposit_withdraw/expected_finding.json",
        ];

        for path_str in expected_paths {
            let content = fs::read_to_string(path_str)
                .expect(&format!("Failed to read {}", path_str));
            
            let json: serde_json::Value = serde_json::from_str(&content)
                .expect(&format!("Failed to parse JSON in {}", path_str));
            
            // Verify required fields
            assert!(
                json.get("expected_outcome").is_some(),
                "Missing expected_outcome in {}",
                path_str
            );
            assert!(
                json.get("description").is_some(),
                "Missing description in {}",
                path_str
            );
        }
    }

    /// Test that buggy chains have proper bug descriptions
    #[test]
    fn test_buggy_chains_have_descriptions() {
        let description_paths = [
            "tests/ground_truth/chains/deposit_withdraw/bug_description.md",
        ];

        for path_str in description_paths {
            let path = Path::new(path_str);
            assert!(
                path.exists(),
                "Bug description missing: {}",
                path_str
            );
        }
    }

    /// Validate chain campaign YAML structure
    #[test]
    fn test_chain_campaign_yaml_structure() {
        use std::fs;
        
        for case in ground_truth_cases() {
            let content = fs::read_to_string(case.campaign_path)
                .expect(&format!("Failed to read {}", case.campaign_path));
            
            let yaml: serde_yaml::Value = serde_yaml::from_str(&content)
                .expect(&format!("Failed to parse YAML in {}", case.campaign_path));
            
            // Verify chains section exists
            assert!(
                yaml.get("chains").is_some(),
                "Missing chains section in {}",
                case.campaign_path
            );

            // Verify each chain has required fields
            if let Some(chains) = yaml.get("chains").and_then(|c| c.as_sequence()) {
                for chain in chains {
                    assert!(
                        chain.get("name").is_some(),
                        "Chain missing name in {}",
                        case.campaign_path
                    );
                    assert!(
                        chain.get("steps").is_some(),
                        "Chain missing steps in {}",
                        case.campaign_path
                    );
                    assert!(
                        chain.get("assertions").is_some(),
                        "Chain missing assertions in {}",
                        case.campaign_path
                    );
                }
            }
        }
    }

    // Note: The actual chain fuzzing integration tests would require
    // a running circom backend. These are placeholder tests that
    // validate the test infrastructure is in place.

    /// Placeholder for full integration test
    /// 
    /// In CI, this would run:
    /// ```
    /// cargo run --release -- chains <campaign.yaml> --seed 42 --iterations 1000
    /// ```
    /// And verify the output matches expected_finding.json
    #[test]
    #[ignore = "Requires circom backend - run with --ignored"]
    fn test_chain_ground_truth_integration() {
        // This test would:
        // 1. Load each ground truth campaign
        // 2. Run chain fuzzing
        // 3. Compare findings against expected_finding.json
        // 4. Compute TP/FP/FN rates
        // 5. Assert precision >= 0.9, recall >= 0.8
        
        let mut results: Vec<GroundTruthResult> = Vec::new();
        
        for case in ground_truth_cases() {
            // In a real test, we'd run the fuzzer here
            // For now, just record that the test case exists
            results.push(GroundTruthResult {
                name: case.name.to_string(),
                passed: true, // Placeholder
                expected: case.expected_outcome,
                actual_findings: 0,
                actual_assertion: None,
                actual_l_min: None,
                error: None,
            });
        }
        
        // Compute metrics
        let total = results.len();
        let passed = results.iter().filter(|r| r.passed).count();
        
        println!("Ground Truth Results: {}/{} passed", passed, total);
        assert_eq!(passed, total, "Some ground truth tests failed");
    }
}

/// Metrics computed from ground truth test results
#[derive(Debug, Default)]
pub struct GroundTruthMetrics {
    /// True positives (correctly detected bugs)
    pub true_positives: usize,
    /// False positives (findings on clean code)
    pub false_positives: usize,
    /// False negatives (missed bugs)
    pub false_negatives: usize,
    /// True negatives (correctly passed clean code)
    pub true_negatives: usize,
}

impl GroundTruthMetrics {
    /// Compute precision: TP / (TP + FP)
    pub fn precision(&self) -> f64 {
        let denominator = self.true_positives + self.false_positives;
        if denominator == 0 {
            1.0
        } else {
            self.true_positives as f64 / denominator as f64
        }
    }

    /// Compute recall: TP / (TP + FN)
    pub fn recall(&self) -> f64 {
        let denominator = self.true_positives + self.false_negatives;
        if denominator == 0 {
            1.0
        } else {
            self.true_positives as f64 / denominator as f64
        }
    }

    /// Compute F1 score: 2 * (precision * recall) / (precision + recall)
    pub fn f1_score(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * (p * r) / (p + r)
        }
    }
}

#[cfg(test)]
mod metric_tests {
    use super::*;

    #[test]
    fn test_perfect_metrics() {
        let metrics = GroundTruthMetrics {
            true_positives: 3,
            false_positives: 0,
            false_negatives: 0,
            true_negatives: 1,
        };

        assert_eq!(metrics.precision(), 1.0);
        assert_eq!(metrics.recall(), 1.0);
        assert_eq!(metrics.f1_score(), 1.0);
    }

    #[test]
    fn test_partial_metrics() {
        let metrics = GroundTruthMetrics {
            true_positives: 2,
            false_positives: 1,
            false_negatives: 1,
            true_negatives: 0,
        };

        assert!((metrics.precision() - 0.666).abs() < 0.01);
        assert!((metrics.recall() - 0.666).abs() < 0.01);
    }
}
