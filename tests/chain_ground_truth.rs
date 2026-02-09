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

#[derive(Debug, PartialEq, Clone, Copy)]
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

    /// Real integration test: runs each ground truth case through the chain fuzzer
    /// with real circom backends and verifies findings match expectations.
    #[test]
    fn test_chain_ground_truth_integration() {
        use std::collections::HashMap;
        use std::sync::Arc;
        use zk_fuzzer::chain_fuzzer::{
            ChainRunner, ChainMutator, ChainShrinker,
            CrossStepInvariantChecker, ChainFinding,
        };
        use zk_fuzzer::config::{FuzzConfig, parse_chains};
        use zk_fuzzer::config::v2::CircuitPathConfig;
        use zk_fuzzer::executor::ExecutorFactory;
        use zk_core::{CircuitExecutor, FieldElement, Framework};
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mut metrics = super::GroundTruthMetrics::default();
        let mut results: Vec<GroundTruthResult> = Vec::new();

        for case in ground_truth_cases() {
            println!("\n══ Ground Truth: {} ══", case.name);

            let config = match FuzzConfig::from_yaml(case.campaign_path) {
                Ok(c) => c,
                Err(e) => {
                    results.push(GroundTruthResult {
                        name: case.name.to_string(),
                        passed: false,
                        expected: case.expected_outcome,
                        actual_findings: 0,
                        actual_assertion: None,
                        actual_l_min: None,
                        error: Some(format!("Config load failed: {}", e)),
                    });
                    continue;
                }
            };

            let chains = parse_chains(&config);
            if chains.is_empty() {
                results.push(GroundTruthResult {
                    name: case.name.to_string(),
                    passed: false,
                    expected: case.expected_outcome,
                    actual_findings: 0,
                    actual_assertion: None,
                    actual_l_min: None,
                    error: Some("No chains in campaign YAML".to_string()),
                });
                continue;
            }

            let circuit_root = config.campaign.target.circuit_path.clone();
            let mut circuit_map: HashMap<String, CircuitPathConfig> = HashMap::new();
            for chain_cfg in &config.chains {
                for (name, cfg) in &chain_cfg.circuits {
                    circuit_map.entry(name.clone()).or_insert_with(|| cfg.clone());
                }
            }
            let mut executors: HashMap<String, Arc<dyn CircuitExecutor>> = HashMap::new();

            for chain in &chains {
                for step in &chain.steps {
                    if executors.contains_key(&step.circuit_ref) {
                        continue;
                    }
                    let (circuit_path, main_component, framework) = if let Some(cfg) = circuit_map.get(&step.circuit_ref) {
                        let framework = cfg.framework.unwrap_or(config.campaign.target.framework);
                        let main_component = cfg
                            .main_component
                            .as_deref()
                            .unwrap_or(&step.circuit_ref)
                            .to_string();
                        (cfg.path.clone(), main_component, framework)
                    } else {
                        let root = if circuit_root.is_dir() {
                            circuit_root.clone()
                        } else {
                            circuit_root.parent().unwrap_or(&circuit_root).to_path_buf()
                        };
                        let fallback_path = root.join(format!("{}.circom", step.circuit_ref));
                        (
                            fallback_path,
                            config.campaign.target.main_component.clone(),
                            config.campaign.target.framework,
                        )
                    };
                    let circom_path = circuit_path.to_str().unwrap_or("");

                    match ExecutorFactory::create(framework, circom_path, &main_component) {
                        Ok(exec) => {
                            println!("  Loaded circuit: {} ({} inputs, {} constraints)",
                                step.circuit_ref,
                                exec.num_private_inputs(),
                                exec.num_constraints(),
                            );
                            executors.insert(step.circuit_ref.clone(), exec);
                        }
                        Err(e) => {
                            println!("  SKIP: Failed to load circuit {}: {}", step.circuit_ref, e);
                            results.push(GroundTruthResult {
                                name: case.name.to_string(),
                                passed: false,
                                expected: case.expected_outcome,
                                actual_findings: 0,
                                actual_assertion: None,
                                actual_l_min: None,
                                error: Some(format!("Circuit load failed for {}: {}", step.circuit_ref, e)),
                            });
                            continue;
                        }
                    }
                }
            }

            if executors.len() < chains.iter().flat_map(|c| c.steps.iter()).map(|s| &s.circuit_ref).collect::<std::collections::HashSet<_>>().len() {
                continue;
            }

            let runner = ChainRunner::new(executors.clone())
                .with_timeout(std::time::Duration::from_secs(30));
            let mutator = ChainMutator::new();
            let mut rng = ChaCha8Rng::seed_from_u64(42);

            let mut all_findings: Vec<ChainFinding> = Vec::new();
            let iterations = 500;

            for chain in &chains {
                let checker = CrossStepInvariantChecker::from_spec(chain);
                let mut current_inputs: HashMap<String, Vec<FieldElement>> = HashMap::new();

                for iter in 0..iterations {
                    let result = runner.execute(chain, &current_inputs, &mut rng);

                    if result.completed {
                        let violations = checker.check(&result.trace);

                        for violation in &violations {
                            let shrinker = ChainShrinker::new(
                                ChainRunner::new(executors.clone()),
                                CrossStepInvariantChecker::from_spec(chain),
                            ).with_seed(42);

                            let shrink_result = shrinker.minimize(
                                chain, &current_inputs, violation,
                            );

                            let finding = zk_core::Finding {
                                attack_type: zk_core::AttackType::CircuitComposition,
                                severity: match violation.severity.to_lowercase().as_str() {
                                    "critical" => zk_core::Severity::Critical,
                                    "high" => zk_core::Severity::High,
                                    _ => zk_core::Severity::Medium,
                                },
                                description: format!(
                                    "{}: {}",
                                    violation.assertion_name, violation.description
                                ),
                                poc: zk_core::ProofOfConcept {
                                    witness_a: result.trace.steps.first()
                                        .map(|s| s.inputs.clone())
                                        .unwrap_or_default(),
                                    witness_b: result.trace.steps.get(1)
                                        .map(|s| s.inputs.clone()),
                                    public_inputs: vec![],
                                    proof: None,
                                },
                                location: Some(format!("chain:{}", chain.name)),
                            };

                            let chain_finding = ChainFinding::new(
                                finding,
                                chain.len(),
                                shrink_result.l_min,
                                result.trace.clone(),
                                &chain.name,
                            ).with_violated_assertion(&violation.assertion_name);

                            all_findings.push(chain_finding);
                        }

                        if !violations.is_empty() {
                            println!("  Found {} violation(s) at iteration {}", violations.len(), iter);
                            break;
                        }
                    }

                    let (mutated, _) = mutator.mutate_inputs(chain, &current_inputs, &mut rng);
                    current_inputs = mutated;
                }
            }

            let expected: serde_json::Value = {
                let content = std::fs::read_to_string(
                    Path::new(case.campaign_path).parent().unwrap().join("expected_finding.json")
                ).unwrap();
                serde_json::from_str(&content).unwrap()
            };

            let _expected_outcome = expected["expected_outcome"].as_str().unwrap_or("");
            let expected_assertion = expected["violated_assertion"].as_str();

            let passed;
            match case.expected_outcome {
                ExpectedOutcome::Confirmed => {
                    if all_findings.is_empty() {
                        println!("  FAIL: Expected CONFIRMED finding but got 0 findings");
                        metrics.false_negatives += 1;
                        passed = false;
                    } else {
                        let assertion_match = expected_assertion.map_or(true, |ea| {
                            all_findings.iter().any(|f| {
                                f.violated_assertion.as_deref() == Some(ea)
                            })
                        });

                        let l_min_ok = case.expected_l_min.map_or(true, |el| {
                            all_findings.iter().any(|f| f.l_min >= el)
                        });

                        if assertion_match && l_min_ok {
                            println!("  PASS: Found {} finding(s), assertion match={}, l_min match={}",
                                all_findings.len(), assertion_match, l_min_ok);
                            metrics.true_positives += 1;
                            passed = true;
                        } else {
                            println!("  FAIL: assertion_match={}, l_min_ok={}", assertion_match, l_min_ok);
                            metrics.false_negatives += 1;
                            passed = false;
                        }
                    }
                }
                ExpectedOutcome::Clean => {
                    if all_findings.is_empty() {
                        println!("  PASS: No findings (true negative)");
                        metrics.true_negatives += 1;
                        passed = true;
                    } else {
                        println!("  FAIL: Expected CLEAN but got {} finding(s)", all_findings.len());
                        metrics.false_positives += 1;
                        passed = false;
                    }
                }
            }

            let first_finding = all_findings.first();
            results.push(GroundTruthResult {
                name: case.name.to_string(),
                passed,
                expected: case.expected_outcome,
                actual_findings: all_findings.len(),
                actual_assertion: first_finding.and_then(|f| f.violated_assertion.clone()),
                actual_l_min: first_finding.map(|f| f.l_min),
                error: None,
            });
        }

        println!("\n══════════════════════════════════════════════");
        println!("Ground Truth Results:");
        println!("  TP={} FP={} FN={} TN={}",
            metrics.true_positives, metrics.false_positives,
            metrics.false_negatives, metrics.true_negatives);
        println!("  Precision={:.2} Recall={:.2} F1={:.2}",
            metrics.precision(), metrics.recall(), metrics.f1_score());
        println!("══════════════════════════════════════════════\n");

        for r in &results {
            println!("  {} {} (findings={}, assertion={:?}, l_min={:?}{})",
                if r.passed { "✓" } else { "✗" },
                r.name,
                r.actual_findings,
                r.actual_assertion,
                r.actual_l_min,
                r.error.as_ref().map_or(String::new(), |e| format!(", error={}", e)),
            );
        }

        let total = results.len();
        let passed = results.iter().filter(|r| r.passed).count();
        assert!(
            passed == total,
            "Ground truth: {}/{} passed. Precision={:.2}, Recall={:.2}",
            passed, total, metrics.precision(), metrics.recall()
        );
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
