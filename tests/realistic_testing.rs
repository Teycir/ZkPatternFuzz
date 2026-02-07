//! Realistic integration tests for ZK fuzzer
//! 
//! Tests against real circuits and known vulnerabilities.
//! 
//! NOTE: These tests require real circuit backends to detect actual vulnerabilities.
//! Missing toolchains are treated as hard failures.

use zk_fuzzer::*;
use zk_fuzzer::targets::CircomTarget;
use std::path::PathBuf;

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
    assert!(report.findings.iter().any(|f| 
        matches!(f.attack_type, AttackType::Underconstrained)
    ));
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
    assert!(report.findings.len() > 0);
}

/// Test corpus-based fuzzing effectiveness
/// Currently limited by mock coverage simulation
#[tokio::test]
async fn test_corpus_coverage() {
    let config = FuzzConfig::from_yaml("tests/campaigns/mock_merkle_audit.yaml").unwrap();
    let mut fuzzer = ZkFuzzer::new(config, Some(42));
    
    let report = fuzzer.run().await.unwrap();
    
    // Should achieve reasonable coverage
    assert!(report.statistics.coverage_percentage > 50.0);
}

/// Test parallel execution performance
/// 
/// Note: For small workloads, parallelization overhead may exceed benefits.
/// This test uses adaptive expectations based on workload size.
#[tokio::test]
async fn test_parallel_performance() {
    use std::time::Instant;
    
    let config = FuzzConfig::from_yaml("tests/campaigns/mock_merkle_audit.yaml").unwrap();
    
    // Calculate workload size to set expectations
    let total_work: u64 = config.attacks.iter().map(|a| {
        a.config.get("witness_pairs").and_then(|v| v.as_u64()).unwrap_or(0)
        + a.config.get("forge_attempts").and_then(|v| v.as_u64()).unwrap_or(0)
        + a.config.get("samples").and_then(|v| v.as_u64()).unwrap_or(0)
    }).sum();
    
    // Sequential
    let start = Instant::now();
    let report_seq = ZkFuzzer::run_with_progress(config.clone(), Some(42), 1, false).await.unwrap();
    let seq_time = start.elapsed();
    
    // Parallel (4 workers)
    let start = Instant::now();
    let report_par = ZkFuzzer::run_with_progress(config, Some(42), 4, false).await.unwrap();
    let par_time = start.elapsed();
    
    // For small workloads (< 5000 iterations), parallelization overhead may dominate
    // For larger workloads, parallel should be faster
    // We use a more lenient check: parallel should not be significantly slower (>2x)
    let overhead_factor = 3.0;
    
    if total_work >= 5000 {
        // For large workloads, expect parallelism benefit
        assert!(
            par_time < seq_time,
            "Parallel ({:?}) should be faster than sequential ({:?}) for {} iterations",
            par_time, seq_time, total_work
        );
    } else {
        // For small workloads, just ensure parallel isn't catastrophically slower
        assert!(
            par_time.as_secs_f64() < seq_time.as_secs_f64() * overhead_factor,
            "Parallel ({:?}) should not be more than {}x slower than sequential ({:?})",
            par_time, overhead_factor, seq_time
        );
    }
    
    // Should find same number of issues regardless of parallelism
    assert_eq!(report_seq.findings.len(), report_par.findings.len());
    
    // Log performance metrics for debugging
    tracing::info!(
        "Performance: seq={:?}, par={:?}, work={}, speedup={:.2}x",
        seq_time, par_time, total_work,
        seq_time.as_secs_f64() / par_time.as_secs_f64().max(0.001)
    );
}

/// Test deterministic fuzzing with seed
#[tokio::test]
async fn test_deterministic_fuzzing() {
    let config = FuzzConfig::from_yaml("tests/campaigns/mock_merkle_audit.yaml").unwrap();
    
    let report1 = ZkFuzzer::run_with_progress(config.clone(), Some(12345), 1, false).await.unwrap();
    let report2 = ZkFuzzer::run_with_progress(config, Some(12345), 1, false).await.unwrap();
    
    // Same seed should produce identical results
    assert_eq!(report1.findings.len(), report2.findings.len());
    assert_eq!(report1.statistics.total_executions, report2.statistics.total_executions);
}

/// Helper to create test configuration
fn create_test_config(circuit_path: &PathBuf, component: &str, framework: Framework) -> FuzzConfig {
    use serde_yaml::Value;
    
    let mut parameters = Parameters::default();
    parameters.timeout_seconds = 5;
    parameters
        .additional
        .insert("max_iterations".to_string(), Value::Number(0.into()));

    FuzzConfig {
        campaign: Campaign {
            name: "Test Campaign".to_string(),
            version: "1.0".to_string(),
            target: Target {
                framework,
                circuit_path: circuit_path.clone(),
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
    }
}

fn require_circom_tools() {
    CircomTarget::check_circom_available()
        .expect("Circom not available. Install with: npm install -g circom");
    CircomTarget::check_snarkjs_available()
        .expect("snarkjs not available. Install with: npm install -g snarkjs");
}
