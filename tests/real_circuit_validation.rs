//! Real Circuit Validation Tests
//!
//! These tests validate the adaptive fuzzing system against real-world ZK circuits
//! from the zk0d repository when available.

use std::path::Path;
use zk_fuzzer::analysis::opus::{OpusAnalyzer, OpusConfig};
use zk_fuzzer::config::generator::PatternType;

const ZK0D_PATH: &str = "/media/elements/Repos/zk0d";

/// Check if zk0d repository is available
fn zk0d_available() -> bool {
    Path::new(ZK0D_PATH).exists()
}

/// Test analysis of real privacy circuits
#[test]
#[ignore = "Requires zk0d repository"]
fn test_real_privacy_circuits() {
    if !zk0d_available() {
        eprintln!("Skipping: zk0d repository not available");
        return;
    }

    let privacy_path = Path::new(ZK0D_PATH).join("cat3_privacy/circuits");
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
        println!("Patterns: {:?}", config.config.base.as_ref().map(|b| b.attacks.len()).unwrap_or(0));
        println!("Zero-day hints: {}", config.zero_day_hints.len());
        
        for hint in &config.zero_day_hints {
            println!("  [{:.0}%] {:?}: {}", hint.confidence * 100.0, hint.category, hint.description);
        }
    }

    // At least some circuits should be analyzed
    assert!(!configs.is_empty(), "Should analyze at least one circuit");
}

/// Test analysis of real Noir circuits (Aztec)
#[test]
#[ignore = "Requires zk0d repository"]
fn test_real_noir_circuits() {
    if !zk0d_available() {
        eprintln!("Skipping: zk0d repository not available");
        return;
    }

    let aztec_path = Path::new(ZK0D_PATH).join("cat3_privacy/aztec-packages/noir-projects");
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
        println!("Framework: {:?}", config.config.base.as_ref().map(|b| &b.campaign.target.framework));
        println!("Zero-day hints: {}", config.zero_day_hints.len());
    }
}

/// Test analysis of real Cairo circuits (StarkWare)
#[test]
#[ignore = "Requires zk0d repository"]
fn test_real_cairo_circuits() {
    if !zk0d_available() {
        eprintln!("Skipping: zk0d repository not available");
        return;
    }

    let stone_path = Path::new(ZK0D_PATH).join("cat2_rollups/stone-prover");
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
#[ignore = "Requires zk0d repository"]
fn test_pattern_detection_accuracy() {
    if !zk0d_available() {
        return;
    }

    // Test nullify.circom specifically
    let nullify_path = Path::new(ZK0D_PATH)
        .join("cat3_privacy/circuits/circuits/lib/utils/nullify.circom");

    if !nullify_path.exists() {
        eprintln!("Skipping: nullify.circom not found");
        return;
    }

    let analyzer = OpusAnalyzer::new();
    let result = analyzer.analyze_circuit(&nullify_path).unwrap();

    println!("Nullify.circom Analysis:");
    println!("  Framework: {:?}", result.framework);
    println!("  Main component: {}", result.main_component);
    println!("  Inputs: {:?}", result.inputs.iter().map(|i| &i.name).collect::<Vec<_>>());
    println!("  Patterns:");
    for pattern in &result.patterns {
        println!("    - {:?} (confidence: {:.2})", pattern.pattern_type, pattern.confidence);
    }
    println!("  Zero-day hints:");
    for hint in &result.zero_day_hints {
        println!("    - [{:.0}%] {:?}", hint.confidence * 100.0, hint.category);
    }

    // Verify expected patterns
    assert!(result.patterns.iter().any(|p| p.pattern_type == PatternType::Nullifier),
        "Should detect nullifier pattern");
    assert!(result.patterns.iter().any(|p| matches!(p.pattern_type, PatternType::HashFunction(_))),
        "Should detect hash function (Poseidon)");
}

/// Test adaptive scheduling with real circuit complexity
#[test]
#[ignore = "Requires zk0d repository"]
fn test_adaptive_scheduling_real_circuits() {
    if !zk0d_available() {
        return;
    }

    use zk_fuzzer::fuzzer::adaptive_attack_scheduler::{AdaptiveScheduler, AttackResults};
    use std::time::Duration;
    use zk_core::AttackType;

    let privacy_path = Path::new(ZK0D_PATH).join("cat3_privacy/circuits");
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
        let attack_types: Vec<AttackType> = config.config.base
            .as_ref()
            .map(|b| b.attacks.iter().map(|a| a.attack_type.clone()).collect())
            .unwrap_or_default();

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
#[ignore = "Requires zk0d repository"]
fn test_generated_configs_validity() {
    if !zk0d_available() {
        return;
    }

    let privacy_path = Path::new(ZK0D_PATH).join("cat3_privacy/circuits");
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
        
        assert!(parsed.is_ok(), "Generated YAML should be valid: {}", saved_path.display());
    }
}
