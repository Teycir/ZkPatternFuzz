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
        },
        ChainGroundTruth {
            name: "deposit_withdraw_triple_nullifier_reuse",
            campaign_path: "tests/ground_truth/chains/deposit_withdraw_triple/chain_campaign.yaml",
        },
        ChainGroundTruth {
            name: "update_verify_root_inconsistency",
            campaign_path: "tests/ground_truth/chains/update_verify/chain_campaign.yaml",
        },
        ChainGroundTruth {
            name: "update_update_verify_root_mismatch",
            campaign_path: "tests/ground_truth/chains/update_update_verify/chain_campaign.yaml",
        },
        ChainGroundTruth {
            name: "sign_verify_malleability",
            campaign_path: "tests/ground_truth/chains/sign_verify/chain_campaign.yaml",
        },
        ChainGroundTruth {
            name: "clean_deposit_withdraw",
            campaign_path: "tests/ground_truth/chains/clean_deposit_withdraw/chain_campaign.yaml",
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
    use std::hash::{Hash, Hasher};

    #[derive(Debug)]
    struct RunSettings {
        iterations: usize,
        shrink_max_attempts: usize,
        chain_timeout: std::time::Duration,
        mode: &'static str,
    }

    #[derive(Debug)]
    struct ExpectedSpec {
        outcome: ExpectedOutcome,
        violated_assertion: Option<String>,
        l_min_expected: Option<usize>,
    }

    fn optional_env(name: &str) -> Option<String> {
        match std::env::var(name) {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => panic!("Invalid {} value: {}", name, e),
        }
    }

    fn env_present(name: &str) -> bool {
        match std::env::var(name) {
            Ok(value) => !value.is_empty(),
            Err(std::env::VarError::NotPresent) => false,
            Err(e) => panic!("Invalid {} value: {}", name, e),
        }
    }

    fn parse_env_usize(name: &str) -> Option<usize> {
        let value = optional_env(name)?;
        match value.parse() {
            Ok(parsed) => Some(parsed),
            Err(e) => panic!("Invalid {}='{}': {}", name, value, e),
        }
    }

    fn parse_env_u64(name: &str) -> Option<u64> {
        let value = optional_env(name)?;
        match value.parse() {
            Ok(parsed) => Some(parsed),
            Err(e) => panic!("Invalid {}='{}': {}", name, value, e),
        }
    }

    fn seed_from_name(name: &str) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        name.hash(&mut hasher);
        hasher.finish()
    }

    fn expected_path_for_campaign(campaign_path: &str) -> std::path::PathBuf {
        Path::new(campaign_path)
            .parent()
            .unwrap()
            .join("expected_finding.json")
    }

    fn resolve_run_settings(config: &zk_fuzzer::config::FuzzConfig) -> RunSettings {
        let mut iterations = 500;
        let mut shrink_max_attempts = 100;
        let mut chain_timeout =
            std::time::Duration::from_secs(config.campaign.parameters.timeout_seconds);
        let mut mode = "full";

        let mode_env = optional_env("ZKPF_GROUND_TRUTH_MODE");
        let ci_smoke = env_present("CI") && !env_present("ZKPF_GROUND_TRUTH_FULL");
        let smoke = match mode_env.as_deref() {
            Some("smoke") => true,
            Some("full") => false,
            _ => ci_smoke,
        };

        if smoke {
            iterations = 100;
            shrink_max_attempts = 30;
            mode = "smoke";
        }

        if let Some(iters) = parse_env_usize("ZKPF_GROUND_TRUTH_ITERS") {
            iterations = iters;
            mode = "custom";
        }
        if let Some(attempts) = parse_env_usize("ZKPF_GROUND_TRUTH_SHRINK_ATTEMPTS") {
            shrink_max_attempts = attempts;
            mode = "custom";
        }
        if let Some(secs) = parse_env_u64("ZKPF_GROUND_TRUTH_CHAIN_TIMEOUT_SECS") {
            chain_timeout = std::time::Duration::from_secs(secs);
            mode = "custom";
        }

        RunSettings {
            iterations,
            shrink_max_attempts,
            chain_timeout,
            mode,
        }
    }

    fn parse_expected_outcome(value: &serde_json::Value) -> ExpectedOutcome {
        let raw = value
            .as_str()
            .expect("expected_outcome missing or not a string");
        match raw.to_ascii_lowercase().as_str() {
            "confirmed" => ExpectedOutcome::Confirmed,
            "clean" => ExpectedOutcome::Clean,
            other => panic!("Unknown expected_outcome value: {}", other),
        }
    }

    fn load_expected_spec(campaign_path: &str) -> ExpectedSpec {
        let expected_path = expected_path_for_campaign(campaign_path);
        let content = match std::fs::read_to_string(&expected_path) {
            Ok(content) => content,
            Err(err) => panic!("Failed to read {}: {}", expected_path.display(), err),
        };
        let json: serde_json::Value = match serde_json::from_str(&content) {
            Ok(json) => json,
            Err(err) => panic!("Failed to parse JSON in {}: {}", expected_path.display(), err),
        };

        let outcome = parse_expected_outcome(&json["expected_outcome"]);
        let violated_assertion = json["violated_assertion"].as_str().map(|s| s.to_string());
        let l_min_expected = json["l_min_expected"].as_u64().map(|v| v as usize);

        match outcome {
            ExpectedOutcome::Confirmed => {
                if violated_assertion.is_none() {
                    panic!(
                        "expected_finding.json missing violated_assertion for CONFIRMED: {}",
                        expected_path.display()
                    );
                }
                if l_min_expected.is_none() {
                    panic!(
                        "expected_finding.json missing l_min_expected for CONFIRMED: {}",
                        expected_path.display()
                    );
                }
            }
            ExpectedOutcome::Clean => {
                if violated_assertion.is_some() || l_min_expected.is_some() {
                    panic!(
                        "expected_finding.json should not set violated_assertion/l_min_expected for CLEAN: {}",
                        expected_path.display()
                    );
                }
            }
        }

        ExpectedSpec {
            outcome,
            violated_assertion,
            l_min_expected,
        }
    }

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
        for case in ground_truth_cases() {
            let path = expected_path_for_campaign(case.campaign_path);
            assert!(
                path.exists(),
                "Expected finding file missing: {}",
                path.display()
            );
        }
    }

    /// Test that all ground truth cases have circuit files
    #[test]
    fn test_ground_truth_circuits_exist() {
        use zk_fuzzer::config::FuzzConfig;

        for case in ground_truth_cases() {
            let config = match FuzzConfig::from_yaml(case.campaign_path) {
                Ok(config) => config,
                Err(err) => panic!("Failed to parse {}: {}", case.campaign_path, err),
            };

            let mut circuit_paths = vec![config.campaign.target.circuit_path.clone()];
            for chain in &config.chains {
                for cfg in chain.circuits.values() {
                    circuit_paths.push(cfg.path.clone());
                }
            }

            for path in circuit_paths {
                assert!(
                    path.exists(),
                    "Circuit file missing for {}: {}",
                    case.name,
                    path.display()
                );
            }
        }
    }

    /// Test parsing of expected finding files
    #[test]
    fn test_parse_expected_findings() {
        use std::fs;

        for case in ground_truth_cases() {
            let expected_path = expected_path_for_campaign(case.campaign_path);
            let content = match fs::read_to_string(&expected_path) {
                Ok(content) => content,
                Err(err) => panic!("Failed to read {}: {}", expected_path.display(), err),
            };

            let json: serde_json::Value = match serde_json::from_str(&content) {
                Ok(json) => json,
                Err(err) => panic!("Failed to parse JSON in {}: {}", expected_path.display(), err),
            };

            // Verify required fields
            assert!(
                json.get("expected_outcome").is_some(),
                "Missing expected_outcome in {}",
                expected_path.display()
            );
            assert!(
                json.get("description").is_some(),
                "Missing description in {}",
                expected_path.display()
            );

            load_expected_spec(case.campaign_path);
        }
    }

    /// Test that buggy chains have proper bug descriptions
    #[test]
    fn test_buggy_chains_have_descriptions() {
        for case in ground_truth_cases() {
            let expected_spec = load_expected_spec(case.campaign_path);
            if expected_spec.outcome != ExpectedOutcome::Confirmed {
                continue;
            }

            let path = Path::new(case.campaign_path)
                .parent()
                .unwrap()
                .join("bug_description.md");
            assert!(
                path.exists(),
                "Bug description missing for {}: {}",
                case.name,
                path.display()
            );
        }
    }

    /// Validate chain campaign YAML structure
    #[test]
    fn test_chain_campaign_yaml_structure() {
        use std::fs;

        for case in ground_truth_cases() {
            let content = match fs::read_to_string(case.campaign_path) {
                Ok(content) => content,
                Err(err) => panic!("Failed to read {}: {}", case.campaign_path, err),
            };

            let yaml: serde_yaml::Value = match serde_yaml::from_str(&content) {
                Ok(yaml) => yaml,
                Err(err) => panic!("Failed to parse YAML in {}: {}", case.campaign_path, err),
            };

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
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;
        use std::collections::{HashMap, HashSet};
        use std::sync::Arc;
        use std::time::Instant;
        use zk_core::{CircuitExecutor, FieldElement};
        use zk_fuzzer::chain_fuzzer::{
            ChainFinding, ChainMutator, ChainRunner, ChainShrinker, CrossStepInvariantChecker,
        };
        use zk_fuzzer::config::v2::CircuitPathConfig;
        use zk_fuzzer::config::{parse_chains, FuzzConfig};
        use zk_fuzzer::executor::ExecutorFactory;

        let mut metrics = super::GroundTruthMetrics::default();
        let mut results: Vec<GroundTruthResult> = Vec::new();

        for case in ground_truth_cases() {
            println!("\n══ Ground Truth: {} ══", case.name);
            let expected_spec = load_expected_spec(case.campaign_path);

            let config = match FuzzConfig::from_yaml(case.campaign_path) {
                Ok(c) => c,
                Err(e) => {
                    results.push(GroundTruthResult {
                        name: case.name.to_string(),
                        passed: false,
                        expected: expected_spec.outcome,
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
                    expected: expected_spec.outcome,
                    actual_findings: 0,
                    actual_assertion: None,
                    actual_l_min: None,
                    error: Some("No chains in campaign YAML".to_string()),
                });
                continue;
            }

            let settings = resolve_run_settings(&config);
            println!(
                "  Mode: {} (iterations={}, shrink_attempts={}, chain_timeout={}s)",
                settings.mode,
                settings.iterations,
                settings.shrink_max_attempts,
                settings.chain_timeout.as_secs()
            );
            let mut case_error: Option<String> = None;

            let required_circuits: HashSet<String> = chains
                .iter()
                .flat_map(|c| c.steps.iter().map(|s| s.circuit_ref.clone()))
                .collect();

            let mut circuit_map: HashMap<String, CircuitPathConfig> = HashMap::new();
            for chain_cfg in &config.chains {
                for (name, cfg) in &chain_cfg.circuits {
                    circuit_map
                        .entry(name.clone())
                        .or_insert_with(|| cfg.clone());
                }
            }
            let mut executors: HashMap<String, Arc<dyn CircuitExecutor>> = HashMap::new();
            let mut load_error: Option<String> = None;

            'load: for chain in &chains {
                for step in &chain.steps {
                    if executors.contains_key(&step.circuit_ref) {
                        continue;
                    }
                    let (circuit_path, main_component, framework) =
                        if let Some(cfg) = circuit_map.get(&step.circuit_ref) {
                            let framework = match cfg.framework {
                                Some(framework) => framework,
                                None => config.campaign.target.framework,
                            };
                            let main_component = match cfg.main_component.as_deref() {
                                Some(component) => component.to_string(),
                                None => step.circuit_ref.clone(),
                            };
                            (cfg.path.clone(), main_component, framework)
                        } else {
                            load_error = Some(format!(
                                "Missing explicit chain circuit mapping for '{}'",
                                step.circuit_ref
                            ));
                            break 'load;
                        };
                    let circom_path = match circuit_path.to_str() {
                        Some(p) => p,
                        None => {
                            load_error = Some(format!(
                                "Circuit path is not valid UTF-8 for {}: {}",
                                step.circuit_ref,
                                circuit_path.display()
                            ));
                            break 'load;
                        }
                    };

                    match ExecutorFactory::create(framework, circom_path, &main_component) {
                        Ok(exec) => {
                            println!(
                                "  Loaded circuit: {} ({} inputs, {} constraints)",
                                step.circuit_ref,
                                exec.num_private_inputs(),
                                exec.num_constraints(),
                            );
                            executors.insert(step.circuit_ref.clone(), exec);
                        }
                        Err(e) => {
                            load_error = Some(format!(
                                "Circuit load failed for {}: {}",
                                step.circuit_ref, e
                            ));
                            break 'load;
                        }
                    }
                }
            }

            if let Some(err) = load_error {
                results.push(GroundTruthResult {
                    name: case.name.to_string(),
                    passed: false,
                    expected: expected_spec.outcome,
                    actual_findings: 0,
                    actual_assertion: None,
                    actual_l_min: None,
                    error: Some(err),
                });
                continue;
            }

            if executors.len() < required_circuits.len() {
                let mut missing: Vec<String> = required_circuits
                    .iter()
                    .filter(|name| !executors.contains_key(*name))
                    .cloned()
                    .collect();
                missing.sort();
                results.push(GroundTruthResult {
                    name: case.name.to_string(),
                    passed: false,
                    expected: expected_spec.outcome,
                    actual_findings: 0,
                    actual_assertion: None,
                    actual_l_min: None,
                    error: Some(format!(
                        "Missing executors for circuits: {}",
                        missing.join(", ")
                    )),
                });
                continue;
            }

            let case_deadline = Instant::now() + settings.chain_timeout;
            let runner = ChainRunner::new(executors.clone())
                .with_timeout(std::time::Duration::from_secs(30));
            let mutator = ChainMutator::new();
            let mut rng = ChaCha8Rng::seed_from_u64(seed_from_name(case.name));

            let mut all_findings: Vec<ChainFinding> = Vec::new();
            let iterations = match expected_spec.outcome {
                ExpectedOutcome::Clean => settings.iterations.min(200),
                ExpectedOutcome::Confirmed => settings.iterations,
            };

            'chain_run: for chain in &chains {
                let checker = CrossStepInvariantChecker::from_spec(chain);
                let mut shrinker: Option<ChainShrinker> = None;
                let mut current_inputs: HashMap<String, Vec<FieldElement>> = HashMap::new();

                for iter in 0..iterations {
                    if Instant::now() >= case_deadline {
                        case_error = Some(format!(
                            "Timed out after {}s",
                            settings.chain_timeout.as_secs()
                        ));
                        break 'chain_run;
                    }

                    let result = runner.execute(chain, &current_inputs, &mut rng);

                    if result.completed {
                        let violations = checker.check(&result.trace);

                        for violation in &violations {
                            if Instant::now() >= case_deadline {
                                case_error = Some(format!(
                                    "Timed out after {}s",
                                    settings.chain_timeout.as_secs()
                                ));
                                break 'chain_run;
                            }

                            let shrinker = shrinker.get_or_insert_with(|| {
                                let shrink_runner = ChainRunner::new(executors.clone())
                                    .with_timeout(std::time::Duration::from_secs(30));
                                let shrink_seed =
                                    seed_from_name(&format!("{}::{}", case.name, chain.name));
                                ChainShrinker::new(
                                    shrink_runner,
                                    CrossStepInvariantChecker::from_spec(chain),
                                )
                                .with_seed(shrink_seed)
                                .with_max_attempts(settings.shrink_max_attempts)
                            });

                            let shrink_result =
                                shrinker.minimize(chain, &current_inputs, violation);
                            let witness_a = match result.trace.steps.first() {
                                Some(step_result) => step_result.inputs.clone(),
                                None => {
                                    case_error = Some(format!(
                                        "Chain '{}' produced a violation without any execution steps",
                                        chain.name
                                    ));
                                    break 'chain_run;
                                }
                            };

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
                                    witness_a,
                                    witness_b: result.trace.steps.get(1).map(|s| s.inputs.clone()),
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
                            )
                            .with_violated_assertion(&violation.assertion_name);

                            all_findings.push(chain_finding);
                        }

                        if !violations.is_empty() {
                            println!(
                                "  Found {} violation(s) at iteration {}",
                                violations.len(),
                                iter
                            );
                            break;
                        }
                    }

                    let (mutated, _) = mutator.mutate_inputs(chain, &current_inputs, &mut rng);
                    current_inputs = mutated;
                }
            }

            let mut timeout_note: Option<String> = None;
            if let Some(err) = case_error {
                if expected_spec.outcome == ExpectedOutcome::Clean && all_findings.is_empty() {
                    timeout_note = Some(err);
                } else {
                    results.push(GroundTruthResult {
                        name: case.name.to_string(),
                        passed: false,
                        expected: expected_spec.outcome,
                        actual_findings: all_findings.len(),
                        actual_assertion: all_findings
                            .first()
                            .and_then(|f| f.violated_assertion.clone()),
                        actual_l_min: all_findings.first().map(|f| f.l_min),
                        error: Some(err),
                    });
                    continue;
                }
            }

            let passed;
            match expected_spec.outcome {
                ExpectedOutcome::Confirmed => {
                    if all_findings.is_empty() {
                        println!("  FAIL: Expected CONFIRMED finding but got 0 findings");
                        metrics.false_negatives += 1;
                        passed = false;
                    } else {
                        let assertion_match = match expected_spec.violated_assertion.as_deref() {
                            Some(ea) => all_findings
                                .iter()
                                .any(|f| f.violated_assertion.as_deref() == Some(ea)),
                            None => true,
                        };

                        let l_min_ok = match expected_spec.l_min_expected {
                            Some(el) => all_findings.iter().any(|f| f.l_min >= el),
                            None => true,
                        };

                        if assertion_match && l_min_ok {
                            println!(
                                "  PASS: Found {} finding(s), assertion match={}, l_min match={}",
                                all_findings.len(),
                                assertion_match,
                                l_min_ok
                            );
                            metrics.true_positives += 1;
                            passed = true;
                        } else {
                            println!(
                                "  FAIL: assertion_match={}, l_min_ok={}",
                                assertion_match, l_min_ok
                            );
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
                        println!(
                            "  FAIL: Expected CLEAN but got {} finding(s)",
                            all_findings.len()
                        );
                        metrics.false_positives += 1;
                        passed = false;
                    }
                }
            }

            let first_finding = all_findings.first();
            results.push(GroundTruthResult {
                name: case.name.to_string(),
                passed,
                expected: expected_spec.outcome,
                actual_findings: all_findings.len(),
                actual_assertion: first_finding.and_then(|f| f.violated_assertion.clone()),
                actual_l_min: first_finding.map(|f| f.l_min),
                error: timeout_note,
            });
        }

        println!("\n══════════════════════════════════════════════");
        println!("Ground Truth Results:");
        println!(
            "  TP={} FP={} FN={} TN={}",
            metrics.true_positives,
            metrics.false_positives,
            metrics.false_negatives,
            metrics.true_negatives
        );
        println!(
            "  Precision={:.2} Recall={:.2} F1={:.2}",
            metrics.precision(),
            metrics.recall(),
            metrics.f1_score()
        );
        println!("══════════════════════════════════════════════\n");

        for r in &results {
            println!(
                "  {} {} (findings={}, assertion={:?}, l_min={:?}{})",
                if r.passed { "✓" } else { "✗" },
                r.name,
                r.actual_findings,
                r.actual_assertion,
                r.actual_l_min,
                match r.error.as_ref() {
                    Some(error) => format!(", error={}", error),
                    None => String::new(),
                },
            );
        }

        let total = results.len();
        let passed = results.iter().filter(|r| r.passed).count();
        assert!(
            passed == total,
            "Ground truth: {}/{} passed. Precision={:.2}, Recall={:.2}",
            passed,
            total,
            metrics.precision(),
            metrics.recall()
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
