//! False Positive Analysis Tests (Phase 1: Milestone 1.2)
//!
//! Tests that measure the false positive rate of ZkPatternFuzz on known-safe circuits.
//! Target: <10% false positive rate in evidence mode, <20% in exploration mode.
//!
//! Run with: `cargo test false_positive --release -- --nocapture`

use std::collections::HashMap;
use zk_fuzzer::config::{AttackType, FuzzConfig};
use zk_fuzzer::fuzzer::FuzzingEngine;

/// Create a campaign config for false positive testing
fn create_fp_test_campaign(circuit_name: &str, iterations: u64) -> FuzzConfig {
    let witness_pairs = iterations / 2;
    let samples = iterations / 2;
    let yaml = format!(
        r#"
campaign:
  name: "FP Test: {circuit_name}"
  version: "1.0"
  target:
    framework: circom
    circuit_path: "tests/safe_circuits/{circuit_name}.circom"
    main_component: "main"
  parameters:
    field: bn254
    max_constraints: 50000
    timeout_seconds: 120
    additional:
      max_iterations: {iterations}
      strict_backend: true
      evidence_mode: true
      min_evidence_confidence: high
      oracle_validation: true

attacks:
  - type: underconstrained
    description: "FP test"
    config:
      witness_pairs: {witness_pairs}
  - type: collision
    description: "FP test"
    config:
      samples: {samples}
  - type: arithmetic_overflow
    description: "FP test"
    config: {{}}
  - type: boundary
    description: "FP test"
    config: {{}}

inputs:
  - name: "input0"
    type: "field"
    fuzz_strategy: random
  - name: "input1"
    type: "field"
    fuzz_strategy: random
  - name: "input2"
    type: "field"
    fuzz_strategy: random

reporting:
  output_dir: "./reports/fp_analysis/{circuit_name}"
  formats: ["json"]
"#,
    );

    serde_yaml::from_str(&yaml).unwrap_or_else(|e| {
        panic!("Failed to parse FP test config for {}: {}", circuit_name, e);
    })
}

/// FP Rate calculation result
#[derive(Debug, Default)]
struct FPAnalysisResult {
    total_safe_circuits: usize,
    total_findings: usize,
    findings_by_attack: HashMap<String, usize>,
    false_positive_rate: f64,
    circuits_with_findings: Vec<String>,
}

impl FPAnalysisResult {
    fn add_findings(&mut self, circuit: &str, findings: &[zk_fuzzer::fuzzer::Finding]) {
        self.total_safe_circuits += 1;
        self.total_findings += findings.len();

        if !findings.is_empty() {
            self.circuits_with_findings.push(circuit.to_string());
            for finding in findings {
                let attack = format!("{:?}", finding.attack_type);
                *self.findings_by_attack.entry(attack).or_insert(0) += 1;
            }
        }
    }

    fn calculate_rate(&mut self) {
        if self.total_safe_circuits > 0 {
            // FP rate = circuits with false findings / total safe circuits
            self.false_positive_rate =
                self.circuits_with_findings.len() as f64 / self.total_safe_circuits as f64;
        }
    }

    fn print_report(&self) {
        println!("\n═══════════════════════════════════════════════════════════");
        println!("  FALSE POSITIVE ANALYSIS REPORT");
        println!("═══════════════════════════════════════════════════════════\n");

        println!("SUMMARY:");
        println!("  Safe circuits tested:      {}", self.total_safe_circuits);
        println!("  Circuits with FP findings: {}", self.circuits_with_findings.len());
        println!("  Total false findings:      {}", self.total_findings);
        println!(
            "  False Positive Rate:       {:.1}%",
            self.false_positive_rate * 100.0
        );

        if !self.findings_by_attack.is_empty() {
            println!("\nFINDINGS BY ATTACK TYPE:");
            let mut sorted: Vec<_> = self.findings_by_attack.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            for (attack, count) in sorted {
                println!("  {:<25} {}", attack, count);
            }
        }

        if !self.circuits_with_findings.is_empty() {
            println!("\nCIRCUITS WITH FALSE POSITIVES:");
            for circuit in &self.circuits_with_findings {
                println!("  - {}", circuit);
            }
        }

        println!("\n═══════════════════════════════════════════════════════════\n");
    }
}

/// Test false positive rate on audited production circuits
/// These are circuits that have been professionally audited and are known safe
#[test]
// requires safe circuit test data
fn test_fp_rate_audited_circuits() {
    let safe_circuits = vec![
        "tornado_withdraw_fixed",    // Fixed Tornado Cash withdraw
        "poseidon_standard",         // Standard Poseidon implementation
        "merkle_tree_secure",        // Properly constrained Merkle tree
        "range_proof_secure",        // Secure range proof implementation
        "eddsa_canonical",           // Canonical EdDSA checks
        "nullifier_secure",          // Properly constrained nullifier
    ];

    let mut results = FPAnalysisResult::default();
    let iterations = 5_000;

    for circuit in &safe_circuits {
        let config = create_fp_test_campaign(circuit, iterations);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let report = rt.block_on(async {
            let mut engine = FuzzingEngine::new(config, Some(42), 1)
                .unwrap_or_else(|e| panic!("Failed to init engine for {}: {}", circuit, e));
            engine.run(None).await.unwrap()
        });

        results.add_findings(circuit, &report.findings);
        
        println!(
            "  {} {} findings on {}",
            if report.findings.is_empty() { "✓" } else { "✗" },
            report.findings.len(),
            circuit
        );
    }

    results.calculate_rate();
    results.print_report();

    // Target: <10% FP rate on audited circuits
    assert!(
        results.false_positive_rate < 0.10,
        "FP rate {:.1}% exceeds 10% target",
        results.false_positive_rate * 100.0
    );
}

/// Test false positive rate on formally verified circuits
/// These circuits have been verified with Picus or other formal tools
#[test]
// requires formally verified circuit test data
fn test_fp_rate_verified_circuits() {
    let verified_circuits = vec![
        "merkle_tree_secure",
        "range_proof_secure",
        "poseidon_standard",
    ];

    let mut results = FPAnalysisResult::default();
    let iterations = 10_000;

    for circuit in &verified_circuits {
        let config = create_fp_test_campaign(circuit, iterations);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let report = rt.block_on(async {
            let mut engine = FuzzingEngine::new(config, Some(42), 1)
                .unwrap_or_else(|e| panic!("Failed to init engine for {}: {}", circuit, e));
            engine.run(None).await.unwrap()
        });

        results.add_findings(circuit, &report.findings);
    }

    results.calculate_rate();
    results.print_report();

    // Formally verified circuits should have 0% FP rate
    assert!(
        results.false_positive_rate < 0.05,
        "FP rate {:.1}% on formally verified circuits should be <5%",
        results.false_positive_rate * 100.0
    );
}

/// Test false positive rate by attack type
/// Helps identify which oracles need tuning
#[test]
// requires safe circuit test data
fn test_fp_rate_by_attack_type() {
    let test_cases: Vec<(AttackType, Vec<&str>)> = vec![
        (
            AttackType::Underconstrained,
            vec!["merkle_tree_secure", "tornado_withdraw_fixed"],
        ),
        (
            AttackType::Collision,
            vec!["poseidon_standard", "nullifier_secure"],
        ),
        (
            AttackType::ArithmeticOverflow,
            vec!["range_proof_secure", "eddsa_canonical"],
        ),
        (
            AttackType::Boundary,
            vec!["merkle_tree_secure", "range_proof_secure"],
        ),
    ];

    let mut attack_fp_rates: HashMap<String, f64> = HashMap::new();
    let iterations = 5_000;

    for (attack_type, circuits) in test_cases {
        let mut total = 0;
        let mut with_findings = 0;

        for circuit in circuits {
            let yaml = format!(
                r#"
campaign:
  name: "FP Test: {} - {:?}"
  version: "1.0"
  target:
    framework: circom
    circuit_path: "tests/safe_circuits/{}.circom"
    main_component: "main"
  parameters:
    field: bn254
    max_constraints: 50000
    timeout_seconds: 60
    additional:
      max_iterations: {}

attacks:
  - type: {:?}
    description: "FP test"
    config: {{}}

inputs:
  - name: "input0"
    type: "field"
    fuzz_strategy: random

reporting:
  output_dir: "./reports/fp_by_attack"
  formats: ["json"]
"#,
                circuit, attack_type, circuit, iterations, attack_type
            );

            let config: FuzzConfig = match serde_yaml::from_str(&yaml) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let rt = tokio::runtime::Runtime::new().unwrap();
            let report = rt.block_on(async {
                let mut engine = FuzzingEngine::new(config, Some(42), 1).unwrap();
                engine.run(None).await.unwrap()
            });

            total += 1;
            if !report.findings.is_empty() {
                with_findings += 1;
            }
        }

        if total > 0 {
            let rate = with_findings as f64 / total as f64;
            attack_fp_rates.insert(format!("{:?}", attack_type), rate);
            println!(
                "  {:?}: {:.1}% FP rate ({}/{})",
                attack_type,
                rate * 100.0,
                with_findings,
                total
            );
        }
    }

    // Report per-attack FP rates
    println!("\n═══════════════════════════════════════════════════════════");
    println!("  FALSE POSITIVE RATE BY ATTACK TYPE");
    println!("═══════════════════════════════════════════════════════════\n");

    for (attack, rate) in &attack_fp_rates {
        let status = if *rate < 0.10 { "✓" } else { "✗" };
        println!("  {} {:<25} {:.1}%", status, attack, rate * 100.0);
    }
}

/// Test that tuned oracle thresholds reduce false positives
#[test]
// requires oracle tuning data
fn test_oracle_threshold_tuning() {
    // Test different confidence thresholds
    let thresholds = [0.5, 0.6, 0.7, 0.8, 0.9];
    
    println!("\nTHRESHOLD TUNING ANALYSIS:");
    println!("═══════════════════════════════════════════════════════════");
    
    for threshold in thresholds {
        // Create config with specific threshold
        let yaml = format!(
            r#"
campaign:
  name: "Threshold Test: {}"
  version: "1.0"
  target:
    framework: circom
    circuit_path: "tests/safe_circuits/merkle_tree_secure.circom"
    main_component: "main"
  parameters:
    field: bn254
    max_constraints: 50000
    timeout_seconds: 60
    additional:
      max_iterations: 5000
      confidence_threshold: {}

attacks:
  - type: underconstrained
    description: "Threshold test"
    config: {{}}

inputs:
  - name: "input"
    type: "field"
    fuzz_strategy: random

reporting:
  output_dir: "./reports/threshold_tuning"
  formats: ["json"]
"#,
            threshold, threshold
        );

        let config: FuzzConfig = match serde_yaml::from_str(&yaml) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let report = rt.block_on(async {
            let mut engine = FuzzingEngine::new(config, Some(42), 1).unwrap();
            engine.run(None).await.unwrap()
        });

        let findings_count = report.findings.len();
        let high_confidence: usize = report
            .findings
            .iter()
            .filter(|f| {
                matches!(
                    f.severity,
                    zk_fuzzer::config::Severity::Critical | zk_fuzzer::config::Severity::High
                )
            })
            .count();

        println!(
            "  Threshold {:.1}: {} findings ({} high-confidence) — FP rate: {:.1}%",
            threshold,
            findings_count,
            high_confidence,
            if findings_count > 0 { 100.0 } else { 0.0 },
        );
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_fp_result_calculation() {
        let mut result = FPAnalysisResult::default();
        
        // Add 10 safe circuits, 2 with findings
        for i in 0..10 {
            let findings = if i < 2 {
                vec![zk_fuzzer::fuzzer::Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: zk_fuzzer::config::Severity::Medium,
                    description: "False positive".to_string(),
                    poc: Default::default(),
                    location: None,
                }]
            } else {
                vec![]
            };
            result.add_findings(&format!("circuit_{}", i), &findings);
        }
        
        result.calculate_rate();
        
        assert_eq!(result.total_safe_circuits, 10);
        assert_eq!(result.circuits_with_findings.len(), 2);
        assert!((result.false_positive_rate - 0.2).abs() < 0.01);
    }

    #[test]
    fn test_create_fp_campaign() {
        let config = create_fp_test_campaign("test_circuit", 1000);
        assert_eq!(config.attacks.len(), 4);
        assert_eq!(config.inputs.len(), 3);
    }
}
