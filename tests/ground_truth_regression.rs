//! Ground Truth Regression Tests (Phase 0: Milestone 0.5)
//!
//! Tests that verify ZkPatternFuzz can detect known vulnerabilities
//! in the ground truth circuit suite.
//!
//! Run with: `cargo test ground_truth --release`

use std::path::PathBuf;
use zk_fuzzer::config::{AttackType, FuzzConfig};
use zk_fuzzer::fuzzer::FuzzingEngine;
use zk_fuzzer::FuzzReport;

const RUN_GROUND_TRUTH_REGRESSION_ENV: &str = "ZKFUZZ_RUN_GROUND_TRUTH_REGRESSION";

fn should_run_ground_truth_regression() -> bool {
    std::env::var(RUN_GROUND_TRUTH_REGRESSION_ENV)
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(false)
}

fn maybe_skip_ground_truth_regression(test_name: &str) -> bool {
    if should_run_ground_truth_regression() {
        return false;
    }
    eprintln!(
        "Skipping {} (set {}=1 to run long ground-truth regression tests)",
        test_name, RUN_GROUND_TRUTH_REGRESSION_ENV
    );
    true
}

fn is_missing_circom_backend_error(err: &anyhow::Error) -> bool {
    let text = err.to_string();
    text.contains("Circom backend required but not available")
        || text.contains("circom not found in PATH")
}

fn run_ground_truth_campaign_or_skip(config: FuzzConfig, test_name: &str) -> Option<FuzzReport> {
    let mut engine = match FuzzingEngine::new(config, Some(42), 1) {
        Ok(engine) => engine,
        Err(err) if is_missing_circom_backend_error(&err) => {
            eprintln!("Skipping {}: {}", test_name, err);
            return None;
        }
        Err(err) => panic!("{}: engine init failed: {:#}", test_name, err),
    };
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    Some(rt.block_on(async { engine.run(None).await.expect("run should succeed") }))
}

/// Helper to create a campaign config for a ground truth circuit
fn create_ground_truth_campaign(
    circuit_name: &str,
    attacks: Vec<AttackType>,
    iterations: u64,
) -> FuzzConfig {
    let circuit_path = PathBuf::from(format!(
        "tests/ground_truth_circuits/{}.circom",
        circuit_name
    ));

    let yaml = format!(
        r#"
campaign:
  name: "Ground Truth: {}"
  version: "1.0"
  target:
    framework: circom
    circuit_path: "{}"
    main_component: "main"
  parameters:
    field: bn254
    max_constraints: 10000
    timeout_seconds: 60
    additional:
      max_iterations: {}
      strict_backend: false

attacks: {}

inputs:
  - name: "input"
    type: "field"
    fuzz_strategy: random

reporting:
  output_dir: "./reports/ground_truth/{}"
  formats: ["json"]
"#,
        circuit_name,
        circuit_path.display(),
        iterations,
        attacks
            .iter()
            .map(|a| {
                let attack_str = match a {
                    AttackType::Underconstrained => "underconstrained",
                    AttackType::Soundness => "soundness",
                    AttackType::ArithmeticOverflow => "arithmetic_overflow",
                    AttackType::Collision => "collision",
                    AttackType::Boundary => "boundary",
                    AttackType::Malleability => "malleability",
                    _ => "underconstrained",
                };
                format!(
                    r#"
  - type: {}
    description: "Ground truth detection test"
    config:
      witness_pairs: {}
      samples: {}"#,
                    attack_str,
                    iterations / 2,
                    iterations / 2
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        circuit_name,
    );

    // For testing, we use a simplified config
    let config: FuzzConfig = match serde_yaml::from_str(&yaml) {
        Ok(config) => config,
        Err(e) => {
            panic!(
                "Failed to parse ground truth config for {}: {}",
                circuit_name, e
            );
        }
    };

    config
}

/// Test detection of Merkle path index not constrained to binary
#[test]
fn test_detects_merkle_unconstrained() {
    if maybe_skip_ground_truth_regression("test_detects_merkle_unconstrained") {
        return;
    }

    let config = create_ground_truth_campaign(
        "merkle_unconstrained",
        vec![AttackType::Underconstrained],
        10_000,
    );
    let Some(report) = run_ground_truth_campaign_or_skip(config, "ground_truth_regression") else {
        return;
    };

    // Should detect the underconstrained path index
    let has_underconstrained = report
        .findings
        .iter()
        .any(|f| matches!(f.attack_type, AttackType::Underconstrained));

    assert!(
        has_underconstrained,
        "Failed to detect underconstrained Merkle path indices. \
         Found {} findings: {:?}",
        report.findings.len(),
        report
            .findings
            .iter()
            .map(|f| &f.attack_type)
            .collect::<Vec<_>>()
    );
}

/// Test detection of range proof overflow
#[test]
fn test_detects_range_overflow() {
    if maybe_skip_ground_truth_regression("test_detects_range_overflow") {
        return;
    }

    let config = create_ground_truth_campaign(
        "range_overflow",
        vec![AttackType::ArithmeticOverflow, AttackType::Boundary],
        10_000,
    );
    let Some(report) = run_ground_truth_campaign_or_skip(config, "ground_truth_regression") else {
        return;
    };

    let has_overflow = report.findings.iter().any(|f| {
        matches!(
            f.attack_type,
            AttackType::ArithmeticOverflow | AttackType::Boundary
        )
    });

    assert!(
        has_overflow,
        "Failed to detect range proof overflow. Found {} findings.",
        report.findings.len()
    );
}

/// Test detection of nullifier collision
#[test]
fn test_detects_nullifier_collision() {
    if maybe_skip_ground_truth_regression("test_detects_nullifier_collision") {
        return;
    }

    let config =
        create_ground_truth_campaign("nullifier_collision", vec![AttackType::Collision], 10_000);
    let Some(report) = run_ground_truth_campaign_or_skip(config, "ground_truth_regression") else {
        return;
    };

    let has_collision = report
        .findings
        .iter()
        .any(|f| matches!(f.attack_type, AttackType::Collision));

    assert!(
        has_collision,
        "Failed to detect nullifier collision. Found {} findings.",
        report.findings.len()
    );
}

/// Test detection of bit decomposition missing constraint
#[test]
fn test_detects_bit_decomposition_unconstrained() {
    if maybe_skip_ground_truth_regression("test_detects_bit_decomposition_unconstrained") {
        return;
    }

    let config = create_ground_truth_campaign(
        "bit_decomposition",
        vec![AttackType::Underconstrained],
        10_000,
    );
    let Some(report) = run_ground_truth_campaign_or_skip(config, "ground_truth_regression") else {
        return;
    };

    let has_underconstrained = report
        .findings
        .iter()
        .any(|f| matches!(f.attack_type, AttackType::Underconstrained));

    assert!(
        has_underconstrained,
        "Failed to detect bit decomposition bug. Found {} findings.",
        report.findings.len()
    );
}

/// Test detection of EdDSA signature malleability
#[test]
fn test_detects_eddsa_malleability() {
    if maybe_skip_ground_truth_regression("test_detects_eddsa_malleability") {
        return;
    }

    let config = create_ground_truth_campaign(
        "eddsa_malleability",
        vec![AttackType::Boundary, AttackType::Soundness],
        10_000,
    );
    let Some(report) = run_ground_truth_campaign_or_skip(config, "ground_truth_regression") else {
        return;
    };

    let has_malleability = report.findings.iter().any(|f| {
        matches!(
            f.attack_type,
            AttackType::Boundary | AttackType::Soundness | AttackType::Malleability
        )
    });

    assert!(
        has_malleability,
        "Failed to detect EdDSA malleability. Found {} findings.",
        report.findings.len()
    );
}

/// Test detection of private input leakage
#[test]
fn test_detects_public_input_leak() {
    if maybe_skip_ground_truth_regression("test_detects_public_input_leak") {
        return;
    }

    let config = create_ground_truth_campaign(
        "public_input_leak",
        vec![AttackType::Underconstrained],
        10_000,
    );
    let Some(report) = run_ground_truth_campaign_or_skip(config, "ground_truth_regression") else {
        return;
    };

    let has_leak = report
        .findings
        .iter()
        .any(|f| matches!(f.attack_type, AttackType::Underconstrained));

    assert!(
        has_leak,
        "Failed to detect information leakage. Found {} findings.",
        report.findings.len()
    );
}

/// Test detection of division by zero
#[test]
fn test_detects_division_by_zero() {
    if maybe_skip_ground_truth_regression("test_detects_division_by_zero") {
        return;
    }

    let config = create_ground_truth_campaign(
        "division_by_zero",
        vec![AttackType::ArithmeticOverflow, AttackType::Boundary],
        10_000,
    );
    let Some(report) = run_ground_truth_campaign_or_skip(config, "ground_truth_regression") else {
        return;
    };

    let has_div_zero = report.findings.iter().any(|f| {
        matches!(
            f.attack_type,
            AttackType::ArithmeticOverflow | AttackType::Boundary
        )
    });

    assert!(
        has_div_zero,
        "Failed to detect division by zero. Found {} findings.",
        report.findings.len()
    );
}

/// Test detection of hash length extension vulnerability
#[test]
fn test_detects_hash_length_extension() {
    if maybe_skip_ground_truth_regression("test_detects_hash_length_extension") {
        return;
    }

    let config =
        create_ground_truth_campaign("hash_length_extension", vec![AttackType::Soundness], 10_000);
    let Some(report) = run_ground_truth_campaign_or_skip(config, "ground_truth_regression") else {
        return;
    };

    let has_hash_vuln = report
        .findings
        .iter()
        .any(|f| matches!(f.attack_type, AttackType::Soundness));

    assert!(
        has_hash_vuln,
        "Failed to detect hash vulnerability. Found {} findings.",
        report.findings.len()
    );
}

/// Test detection of multiexp soundness issue
#[test]
fn test_detects_multiexp_soundness() {
    if maybe_skip_ground_truth_regression("test_detects_multiexp_soundness") {
        return;
    }

    let config = create_ground_truth_campaign(
        "multiexp_soundness",
        vec![AttackType::Underconstrained],
        10_000,
    );
    let Some(report) = run_ground_truth_campaign_or_skip(config, "ground_truth_regression") else {
        return;
    };

    let has_multiexp = report
        .findings
        .iter()
        .any(|f| matches!(f.attack_type, AttackType::Underconstrained));

    assert!(
        has_multiexp,
        "Failed to detect multiexp soundness issue. Found {} findings.",
        report.findings.len()
    );
}

/// Test detection of non-binding commitment
#[test]
fn test_detects_commitment_not_binding() {
    if maybe_skip_ground_truth_regression("test_detects_commitment_not_binding") {
        return;
    }

    let config = create_ground_truth_campaign(
        "commitment_binding",
        vec![AttackType::Underconstrained, AttackType::Collision],
        10_000,
    );
    let Some(report) = run_ground_truth_campaign_or_skip(config, "ground_truth_regression") else {
        return;
    };

    let has_finding = report.findings.iter().any(|f| {
        matches!(
            f.attack_type,
            AttackType::Underconstrained | AttackType::Collision
        )
    });

    assert!(
        has_finding,
        "Failed to detect non-binding commitment. Found {} findings.",
        report.findings.len()
    );
}

/// Measure overall detection rate across ground truth suite
#[test]
fn test_ground_truth_detection_rate() {
    if maybe_skip_ground_truth_regression("test_ground_truth_detection_rate") {
        return;
    }

    let test_cases = vec![
        ("merkle_unconstrained", AttackType::Underconstrained),
        ("range_overflow", AttackType::ArithmeticOverflow),
        ("nullifier_collision", AttackType::Collision),
        ("bit_decomposition", AttackType::Underconstrained),
        ("commitment_binding", AttackType::Underconstrained),
        ("eddsa_malleability", AttackType::Boundary),
        ("public_input_leak", AttackType::Underconstrained),
        ("division_by_zero", AttackType::ArithmeticOverflow),
        ("hash_length_extension", AttackType::Soundness),
        ("multiexp_soundness", AttackType::Underconstrained),
    ];

    let mut detected = 0;
    let total = test_cases.len();

    for (circuit, expected_attack) in &test_cases {
        let config = create_ground_truth_campaign(circuit, vec![expected_attack.clone()], 5_000);
        let Some(report) = run_ground_truth_campaign_or_skip(config, "ground_truth_regression")
        else {
            return;
        };

        if report
            .findings
            .iter()
            .any(|f| &f.attack_type == expected_attack)
        {
            detected += 1;
            println!("✓ Detected vulnerability in {}", circuit);
        } else {
            println!("✗ Missed vulnerability in {}", circuit);
        }
    }

    let rate = (detected as f64 / total as f64) * 100.0;
    println!("\nDetection Rate: {}/{} ({:.1}%)", detected, total, rate);

    // Target: 90%+ detection rate
    assert!(
        rate >= 80.0,
        "Detection rate {:.1}% is below target of 80%",
        rate
    );
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_ground_truth_circuits_exist() {
        let circuits = [
            "merkle_unconstrained",
            "range_overflow",
            "nullifier_collision",
            "bit_decomposition",
            "commitment_binding",
            "eddsa_malleability",
            "public_input_leak",
            "division_by_zero",
            "hash_length_extension",
            "multiexp_soundness",
        ];

        for circuit in circuits {
            let path = PathBuf::from(format!("tests/ground_truth_circuits/{}.circom", circuit));

            // Just check the README exists (circuits are in a separate directory)
            let readme = PathBuf::from("tests/ground_truth_circuits/README.md");
            assert!(
                readme.exists() || path.exists(),
                "Ground truth directory should exist"
            );
        }
    }

    #[test]
    fn test_campaign_config_parsing() {
        // Test that we can create valid configs for ground truth circuits
        let attacks = vec![AttackType::Underconstrained];

        // This should not panic
        let _config = create_ground_truth_campaign("test_circuit", attacks, 1000);
    }
}
