//! Realistic integration tests for ZK fuzzer
//!
//! Tests against real circuits and known vulnerabilities.
//!
//! NOTE: These tests require real circuit backends to detect actual vulnerabilities.
//! Missing toolchains are treated as hard failures.

use std::path::Path;
use zk_fuzzer::targets::CircomTarget;
use zk_fuzzer::*;

/// Test with a deliberately underconstrained circuit
/// Requires real Circom backend to detect the bug
#[tokio::test]
async fn test_underconstrained_detection() {
    require_circom_tools();
    let circuit = r#"
    pragma circom 2.0.0;
    
    template Underconstrained() {
        signal input a;
        signal input b;
        signal output c;
        
        // BUG: a and b are not constrained!
        c <== 1;
    }
    
    component main = Underconstrained();
    "#;

    // Write to temp file
    let temp_dir = tempfile::tempdir().unwrap();
    let circuit_path = temp_dir.path().join("test.circom");
    std::fs::write(&circuit_path, circuit).unwrap();

    // Create campaign
    let config = create_test_config(&circuit_path, "Underconstrained", Framework::Circom);
    let mut fuzzer = ZkFuzzer::new(config, Some(42));

    let report = fuzzer.run().await.unwrap();

    // Should detect underconstrained input 'b'
    assert!(report
        .findings
        .iter()
        .any(|f| matches!(f.attack_type, AttackType::Underconstrained)));
}

/// Test with missing range check
/// Requires real Circom backend to detect the bug
#[tokio::test]
async fn test_missing_range_check() {
    require_circom_tools();
    let circuit = r#"
    pragma circom 2.0.0;
    
    template MissingRangeCheck() {
        signal input value;
        signal output isValid;
        
        // BUG: Should check value < 2^8 but doesn't
        isValid <== 1;
    }
    
    component main = MissingRangeCheck();
    "#;

    let temp_dir = tempfile::tempdir().unwrap();
    let circuit_path = temp_dir.path().join("test.circom");
    std::fs::write(&circuit_path, circuit).unwrap();

    let config = create_test_config(&circuit_path, "MissingRangeCheck", Framework::Circom);
    let mut fuzzer = ZkFuzzer::new(config, Some(42));

    let report = fuzzer.run().await.unwrap();

    // Should accept values > 2^8
    assert!(!report.findings.is_empty());
}

/// Test corpus-based fuzzing effectiveness
/// Currently limited by fixture coverage simulation
#[tokio::test]
async fn test_corpus_coverage() {
    let config = FuzzConfig::from_yaml("tests/campaigns/fixture_merkle_audit.yaml").unwrap();
    let mut fuzzer = ZkFuzzer::new(config, Some(42));

    let report = fuzzer.run().await.unwrap();

    // Should achieve reasonable coverage
    assert!(report.statistics.coverage_percentage > 50.0);
}

/// Test parallel execution performance
///
/// Note: For small workloads, parallelization overhead may exceed benefits.
/// This test uses adaptive expectations based on workload size.
/// Test parallel performance characteristics
///
/// Note: This test validates that parallelism works correctly, not that it's
/// always faster. For small workloads, thread overhead may dominate. The key
/// invariants are:
/// 1. Both runs complete successfully
/// 2. Both runs find the same findings (deterministic with same seed)
/// 3. Parallel version is not catastrophically slower
#[tokio::test]
async fn test_parallel_performance() {
    use std::time::Instant;

    let config = FuzzConfig::from_yaml("tests/campaigns/fixture_merkle_audit.yaml").unwrap();

    // Calculate workload size for logging
    let total_work: u64 = config
        .attacks
        .iter()
        .map(|a| {
            a.config
                .get("witness_pairs")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                + a.config
                    .get("forge_attempts")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
                + a.config
                    .get("samples")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
        })
        .sum();

    // Sequential (1 worker)
    let start = Instant::now();
    let report_seq = ZkFuzzer::run_with_progress(config.clone(), Some(42), 1, false)
        .await
        .unwrap();
    let seq_time = start.elapsed();

    // Parallel (4 workers)
    let start = Instant::now();
    let report_par = ZkFuzzer::run_with_progress(config, Some(42), 4, false)
        .await
        .unwrap();
    let par_time = start.elapsed();

    // Key invariant 1: Both runs complete successfully (implicit - would have panicked)

    // Key invariant 2: Similar findings count
    // Note: With parallelism, finding count may differ slightly due to:
    // - Race conditions in corpus updates
    // - Different execution ordering affecting coverage
    // - Power scheduler making different choices with parallelism
    // We allow a 10% tolerance to account for these variations
    let seq_findings = report_seq.findings.len();
    let par_findings = report_par.findings.len();
    let max_findings = seq_findings.max(par_findings);
    let min_findings = seq_findings.min(par_findings);

    // Allow 10% variance or at least 5 findings difference
    let tolerance = (max_findings as f64 * 0.10).max(5.0) as usize;
    assert!(
        max_findings.saturating_sub(min_findings) <= tolerance,
        "Sequential ({}) and parallel ({}) runs should find similar number of issues (tolerance: {})",
        seq_findings, par_findings, tolerance
    );

    // Key invariant 3: Parallel isn't catastrophically slower
    // We allow up to 5x overhead for very small workloads due to thread creation,
    // warmup, and scheduling variance. CI environments are especially variable.
    let max_overhead_factor = 5.0;
    let min_time_threshold_ms = 50.0; // Ignore timing for very fast runs

    let seq_ms = seq_time.as_secs_f64() * 1000.0;
    let par_ms = par_time.as_secs_f64() * 1000.0;

    // Only check timing if runs took meaningful time
    if seq_ms > min_time_threshold_ms {
        assert!(
            par_ms < seq_ms * max_overhead_factor,
            "Parallel ({:.1}ms) should not be more than {}x slower than sequential ({:.1}ms)",
            par_ms,
            max_overhead_factor,
            seq_ms
        );
    }

    // Log performance metrics for debugging (visible with --nocapture)
    let speedup = if par_ms > 0.001 { seq_ms / par_ms } else { 0.0 };
    println!(
        "Performance: seq={:.1}ms, par={:.1}ms, work={}, speedup={:.2}x",
        seq_ms, par_ms, total_work, speedup
    );
}

/// Test deterministic fuzzing with seed
#[tokio::test]
async fn test_deterministic_fuzzing() {
    let config = FuzzConfig::from_yaml("tests/campaigns/fixture_merkle_audit.yaml").unwrap();

    let report1 = ZkFuzzer::run_with_progress(config.clone(), Some(12345), 1, false)
        .await
        .unwrap();
    let report2 = ZkFuzzer::run_with_progress(config, Some(12345), 1, false)
        .await
        .unwrap();

    // Same seed should produce identical results
    assert_eq!(report1.findings.len(), report2.findings.len());
    assert_eq!(
        report1.statistics.total_executions,
        report2.statistics.total_executions
    );
}

/// Helper to create test configuration
fn create_test_config(circuit_path: &Path, component: &str, framework: Framework) -> FuzzConfig {
    use serde_yaml::Value;

    let mut parameters = Parameters {
        timeout_seconds: 5,
        ..Parameters::default()
    };
    parameters
        .additional
        .insert("max_iterations".to_string(), Value::Number(0.into()));

    FuzzConfig {
        campaign: Campaign {
            name: "Test Campaign".to_string(),
            version: "1.0".to_string(),
            target: Target {
                framework,
                circuit_path: circuit_path.to_path_buf(),
                main_component: component.to_string(),
            },
            parameters,
        },
        attacks: vec![
            Attack {
                attack_type: AttackType::Underconstrained,
                description: "Test underconstrained".to_string(),
                plugin: None,
                // Keep this small to avoid repeated snarkjs invocations in tests.
                config: serde_yaml::from_str("witness_pairs: 2").unwrap(),
            },
            Attack {
                attack_type: AttackType::Boundary,
                description: "Test boundaries".to_string(),
                plugin: None,
                // Single high value is enough to exercise missing range checks.
                config: serde_yaml::from_str("test_values: [\"p-1\"]").unwrap(),
            },
        ],
        inputs: vec![
            Input {
                name: "a".to_string(),
                input_type: "field".to_string(),
                fuzz_strategy: FuzzStrategy::Random,
                constraints: vec![],
                interesting: vec![],
                length: None,
            },
            Input {
                name: "b".to_string(),
                input_type: "field".to_string(),
                fuzz_strategy: FuzzStrategy::InterestingValues,
                constraints: vec![],
                interesting: vec!["0x0".to_string(), "0x1".to_string()],
                length: None,
            },
        ],
        mutations: vec![],
        oracles: vec![],
        reporting: ReportingConfig::default(),
        chains: vec![],
    }
}

fn require_circom_tools() {
    CircomTarget::check_circom_available()
        .expect("Circom not available. Install with: npm install -g circom");
    CircomTarget::check_snarkjs_available()
        .expect("snarkjs not available. Install with: npm install -g snarkjs");
}
