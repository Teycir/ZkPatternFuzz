//! Real Circuit Validation Tests
//!
//! These tests validate the adaptive fuzzing system against real-world ZK circuits
//! from the zk0d repository when available.

use std::path::PathBuf;
use zk_fuzzer::analysis::opus::{OpusAnalyzer, OpusConfig};
use zk_fuzzer::config::generator::PatternType;

const DEFAULT_ZK0D_BASE: &str = "/media/elements/Repos/zk0d";
const RUN_REAL_VALIDATION_ENV: &str = "ZKFUZZ_RUN_REAL_CIRCUIT_VALIDATION";

fn should_run_real_validation() -> bool {
    std::env::var(RUN_REAL_VALIDATION_ENV)
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(false)
}

fn maybe_skip_real_validation(test_name: &str) -> bool {
    if should_run_real_validation() {
        return false;
    }
    eprintln!(
        "Skipping {} (set {}=1 to run external zk0d real-circuit validation)",
        test_name, RUN_REAL_VALIDATION_ENV
    );
    true
}

fn zk0d_base() -> PathBuf {
    match std::env::var("ZK0D_BASE") {
        Ok(path) => PathBuf::from(path),
        Err(std::env::VarError::NotPresent) => PathBuf::from(DEFAULT_ZK0D_BASE),
        Err(e) => panic!("Invalid ZK0D_BASE value: {}", e),
    }
}

/// Check if zk0d repository is available
fn zk0d_available() -> bool {
    zk0d_base().exists()
}

/// Test analysis of real privacy circuits
#[test]
// Requires zk0d repository
fn test_real_privacy_circuits() {
    if maybe_skip_real_validation("test_real_privacy_circuits") {
        return;
    }

    if !zk0d_available() {
        eprintln!("Skipping: zk0d repository not available");
        return;
    }

    let privacy_path = zk0d_base().join("cat3_privacy/circuits");
    if !privacy_path.exists() {
        eprintln!("Skipping: privacy circuits not found");
        return;
    }

    let analyzer = OpusAnalyzer::with_config(OpusConfig {
        max_files: 10,
        min_zero_day_confidence: 0.3,
        ..Default::default()
    });

    let configs = analyzer.analyze_project(&privacy_path).unwrap();

    println!("Analyzed {} privacy circuits", configs.len());

    for config in &configs {
        println!("\n=== {} ===", config.circuit_name);
        println!(
            "Patterns: {:?}",
            match config.config.base.as_ref() {
                Some(base) => base.attacks.len(),
                None => panic!(
                    "Missing generated base config for analyzed circuit: {}",
                    config.circuit_name
                ),
            }
        );
        println!("Zero-day hints: {}", config.zero_day_hints.len());

        for hint in &config.zero_day_hints {
            println!(
                "  [{:.0}%] {:?}: {}",
                hint.confidence * 100.0,
                hint.category,
                hint.description
            );
        }
    }

    // At least some circuits should be analyzed
    assert!(!configs.is_empty(), "Should analyze at least one circuit");
}

/// Test analysis of real Noir circuits (Aztec)
#[test]
// Requires zk0d repository
fn test_real_noir_circuits() {
    if maybe_skip_real_validation("test_real_noir_circuits") {
        return;
    }

    if !zk0d_available() {
        eprintln!("Skipping: zk0d repository not available");
        return;
    }

    let aztec_path = zk0d_base().join("cat3_privacy/aztec-packages/noir-projects");
    if !aztec_path.exists() {
        eprintln!("Skipping: Aztec Noir circuits not found");
        return;
    }

    let analyzer = OpusAnalyzer::with_config(OpusConfig {
        max_files: 5,
        circuit_extensions: vec!["nr".to_string()],
        ..Default::default()
    });

    let configs = analyzer.analyze_project(&aztec_path).unwrap();

    println!("Analyzed {} Noir circuits", configs.len());

    for config in &configs {
        println!("\n=== {} ===", config.circuit_name);
        println!(
            "Framework: {:?}",
            config
                .config
                .base
                .as_ref()
                .map(|b| &b.campaign.target.framework)
        );
        println!("Zero-day hints: {}", config.zero_day_hints.len());
    }
}

/// Test analysis of real Cairo circuits (StarkWare)
#[test]
// Requires zk0d repository
fn test_real_cairo_circuits() {
    if maybe_skip_real_validation("test_real_cairo_circuits") {
        return;
    }

    if !zk0d_available() {
        eprintln!("Skipping: zk0d repository not available");
        return;
    }

    let stone_path = zk0d_base().join("cat2_rollups/stone-prover");
    if !stone_path.exists() {
        eprintln!("Skipping: Stone prover not found");
        return;
    }

    let analyzer = OpusAnalyzer::with_config(OpusConfig {
        max_files: 5,
        circuit_extensions: vec!["cairo".to_string()],
        ..Default::default()
    });

    let configs = analyzer.analyze_project(&stone_path).unwrap();

    println!("Analyzed {} Cairo circuits", configs.len());

    for config in &configs {
        println!("\n=== {} ===", config.circuit_name);
        println!("Analysis summary:\n{}", config.analysis_summary);
    }
}

/// Comprehensive pattern detection on real circuits
#[test]
// Requires zk0d repository
fn test_pattern_detection_accuracy() {
    if maybe_skip_real_validation("test_pattern_detection_accuracy") {
        return;
    }

    if !zk0d_available() {
        return;
    }

    // Test nullify.circom specifically
    let nullify_path = zk0d_base().join("cat3_privacy/circuits/circuits/lib/utils/nullify.circom");

    if !nullify_path.exists() {
        eprintln!("Skipping: nullify.circom not found");
        return;
    }

    let analyzer = OpusAnalyzer::new();
    let result = analyzer.analyze_circuit(&nullify_path).unwrap();

    println!("Nullify.circom Analysis:");
    println!("  Framework: {:?}", result.framework);
    println!("  Main component: {}", result.main_component);
    println!(
        "  Inputs: {:?}",
        result.inputs.iter().map(|i| &i.name).collect::<Vec<_>>()
    );
    println!("  Patterns:");
    for pattern in &result.patterns {
        println!(
            "    - {:?} (confidence: {:.2})",
            pattern.pattern_type, pattern.confidence
        );
    }
    println!("  Zero-day hints:");
    for hint in &result.zero_day_hints {
        println!(
            "    - [{:.0}%] {:?}",
            hint.confidence * 100.0,
            hint.category
        );
    }

    // Verify expected patterns
    assert!(
        result
            .patterns
            .iter()
            .any(|p| p.pattern_type == PatternType::Nullifier),
        "Should detect nullifier pattern"
    );
    assert!(
        result
            .patterns
            .iter()
            .any(|p| matches!(p.pattern_type, PatternType::HashFunction(_))),
        "Should detect hash function (Poseidon)"
    );
}

/// Test adaptive scheduling with real circuit complexity
#[test]
// Requires zk0d repository
fn test_adaptive_scheduling_real_circuits() {
    if maybe_skip_real_validation("test_adaptive_scheduling_real_circuits") {
        return;
    }

    if !zk0d_available() {
        return;
    }

    use std::time::Duration;
    use zk_core::AttackType;
    use zk_fuzzer::fuzzer::adaptive_attack_scheduler::{AdaptiveScheduler, AttackResults};

    let privacy_path = zk0d_base().join("cat3_privacy/circuits");
    if !privacy_path.exists() {
        return;
    }

    let analyzer = OpusAnalyzer::with_config(OpusConfig {
        max_files: 3,
        ..Default::default()
    });

    let configs = analyzer.analyze_project(&privacy_path).unwrap();

    for config in configs {
        println!("\nScheduling for: {}", config.circuit_name);

        // Extract attack types from config
        let attack_types: Vec<AttackType> = config
            .config
            .base
            .as_ref()
            .map(|b| b.attacks.iter().map(|a| a.attack_type.clone()).collect())
            .expect("Missing generated base config while building attack schedule");

        if attack_types.is_empty() {
            continue;
        }

        let mut scheduler = AdaptiveScheduler::new();
        scheduler.initialize(&attack_types);

        // Simulate initial budget allocation
        let budget = scheduler.allocate_budget(Duration::from_secs(300));

        println!("  Initial budget allocation:");
        for (attack, duration) in &budget {
            println!("    {:?}: {:?}", attack, duration);
        }

        // Simulate some progress
        let results = AttackResults {
            attack_type: attack_types[0].clone(),
            new_coverage: 5,
            findings: vec![],
            near_misses: vec![],
            iterations: 100,
            duration: Duration::from_secs(10),
        };
        scheduler.update_scores(&results);

        // Check reallocation
        let new_budget = scheduler.allocate_budget(Duration::from_secs(300));
        println!("  After progress:");
        for (attack, duration) in &new_budget {
            println!("    {:?}: {:?}", attack, duration);
        }
    }
}

/// Generate YAML configs for all circuits and verify they're valid
#[test]
// Requires zk0d repository
fn test_generated_configs_validity() {
    if maybe_skip_real_validation("test_generated_configs_validity") {
        return;
    }

    if !zk0d_available() {
        return;
    }

    let privacy_path = zk0d_base().join("cat3_privacy/circuits");
    if !privacy_path.exists() {
        return;
    }

    let temp_dir = tempfile::TempDir::new().unwrap();
    let output_dir = temp_dir.path();

    let analyzer = OpusAnalyzer::with_config(OpusConfig {
        max_files: 5,
        output_dir: output_dir.to_path_buf(),
        ..Default::default()
    });

    let configs = analyzer.analyze_project(&privacy_path).unwrap();

    for config in &configs {
        let saved_path = config.save(output_dir).unwrap();
        println!("Saved: {}", saved_path.display());

        // Verify the YAML is valid by parsing it
        let yaml_content = std::fs::read_to_string(&saved_path).unwrap();
        let parsed: Result<serde_yaml::Value, _> = serde_yaml::from_str(&yaml_content);

        assert!(
            parsed.is_ok(),
            "Generated YAML should be valid: {}",
            saved_path.display()
        );
    }
}
