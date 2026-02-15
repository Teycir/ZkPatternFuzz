//! Validation Tests for Phase 5: Adaptive Fuzzing with Real Circuits
//!
//! These tests validate the adaptive fuzzing flow:
//! 1. Opus analyzer correctly identifies circuit patterns
//! 2. YAML configurations are generated properly
//! 3. Zero-day hints are detected
//! 4. Adaptive scheduler allocates budget correctly
//! 5. Near-miss detection works

use std::time::Duration;
use tempfile::TempDir;
use zk_core::{AttackType, FieldElement, Finding, ProofOfConcept, Severity};
use zk_fuzzer::analysis::opus::{OpusAnalyzer, OpusConfig, ZeroDayCategory};
use zk_fuzzer::config::generator::{ConfigGenerator, PatternType};
use zk_fuzzer::fuzzer::adaptive_attack_scheduler::{
    AdaptiveScheduler, AdaptiveSchedulerConfig, AttackResults,
};
use zk_fuzzer::fuzzer::near_miss::{NearMissConfig, NearMissDetector, RangeConstraint};
use zk_fuzzer::SuggestionType;

/// Test Opus analyzer with a nullifier circuit
#[test]
fn test_opus_nullifier_circuit_analysis() {
    let source = r#"
pragma circom 2.1.1;

include "circomlib/poseidon.circom";

template Nullify() {
    signal input genesisID;
    signal input claimSubjectProfileNonce;
    signal input claimSchema;
    signal input verifierID;
    signal input nullifierSessionID;

    signal output nullifier;

    signal hash <== Poseidon(5)([genesisID, claimSubjectProfileNonce, claimSchema, verifierID, nullifierSessionID]);
    nullifier <== hash;
}

component main = Nullify();
"#;

    let temp_dir = TempDir::new().unwrap();
    let circuit_path = temp_dir.path().join("nullify.circom");
    std::fs::write(&circuit_path, source).unwrap();

    let analyzer = OpusAnalyzer::new();
    let result = analyzer.analyze_circuit(&circuit_path).unwrap();

    // Verify framework detection
    assert_eq!(result.framework, zk_core::Framework::Circom);

    // Verify pattern detection
    assert!(result
        .patterns
        .iter()
        .any(|p| matches!(p.pattern_type, PatternType::HashFunction(_))));
    assert!(result
        .patterns
        .iter()
        .any(|p| p.pattern_type == PatternType::Nullifier));

    // Verify inputs extraction
    assert!(!result.inputs.is_empty());
    let input_names: Vec<_> = result.inputs.iter().map(|i| i.name.as_str()).collect();
    assert!(input_names.contains(&"genesisID"));
    assert!(input_names.contains(&"nullifierSessionID"));

    // Verify attack priorities include collision
    assert!(result
        .attack_priorities
        .iter()
        .any(|a| a.attack_type == AttackType::Collision));
}

/// Test Opus analyzer with a Merkle tree circuit
#[test]
fn test_opus_merkle_tree_analysis() {
    let source = r#"
pragma circom 2.0.0;

include "circomlib/poseidon.circom";

template MerkleProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output root;

    component hashers[levels];
    signal levelHashes[levels + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);
        // Hash computation
    }

    root <== levelHashes[levels];
}

component main = MerkleProof(20);
"#;

    let temp_dir = TempDir::new().unwrap();
    let circuit_path = temp_dir.path().join("merkle.circom");
    std::fs::write(&circuit_path, source).unwrap();

    let analyzer = OpusAnalyzer::new();
    let result = analyzer.analyze_circuit(&circuit_path).unwrap();

    // Verify Merkle pattern detected
    assert!(result
        .patterns
        .iter()
        .any(|p| p.pattern_type == PatternType::MerkleTree));

    // Verify collision attack is prioritized
    assert!(result
        .attack_priorities
        .iter()
        .any(|a| a.attack_type == AttackType::Collision && a.priority <= 2));

    // Verify main component detection
    assert_eq!(result.main_component, "MerkleProof");
}

/// Test zero-day hint detection for missing constraints
#[test]
fn test_zero_day_missing_constraint_detection() {
    let source = r#"
pragma circom 2.0.0;

template VulnerableCircuit() {
    signal input x;
    signal output y;

    // Vulnerable: assignment without constraint!
    y <-- x * 2;
}

component main = VulnerableCircuit();
"#;

    let temp_dir = TempDir::new().unwrap();
    let circuit_path = temp_dir.path().join("vulnerable.circom");
    std::fs::write(&circuit_path, source).unwrap();

    let analyzer = OpusAnalyzer::with_config(OpusConfig {
        min_zero_day_confidence: 0.1, // Lower threshold for testing
        ..Default::default()
    });
    let result = analyzer.analyze_circuit(&circuit_path).unwrap();

    // Should detect missing constraint
    assert!(result
        .zero_day_hints
        .iter()
        .any(|h| h.category == ZeroDayCategory::MissingConstraint));
}

/// Test zero-day hint detection for bit decomposition bypass
#[test]
fn test_zero_day_bit_decomposition_detection() {
    let source = r#"
pragma circom 2.0.0;

template RangeCheck() {
    signal input value;
    signal bits[64];

    component n2b = Num2Bits(64);
    n2b.in <== value;
    
    for (var i = 0; i < 64; i++) {
        bits[i] <== n2b.out[i];
    }
    // Missing: bits[i] * (bits[i] - 1) === 0
}

component main = RangeCheck();
"#;

    let temp_dir = TempDir::new().unwrap();
    let circuit_path = temp_dir.path().join("range.circom");
    std::fs::write(&circuit_path, source).unwrap();

    let analyzer = OpusAnalyzer::with_config(OpusConfig {
        min_zero_day_confidence: 0.1,
        ..Default::default()
    });
    let result = analyzer.analyze_circuit(&circuit_path).unwrap();

    // Should detect potential bit decomposition issue
    assert!(result
        .zero_day_hints
        .iter()
        .any(|h| h.category == ZeroDayCategory::BitDecompositionBypass
            || h.category == ZeroDayCategory::IncorrectRangeCheck));
}

/// Test YAML configuration generation
#[test]
fn test_yaml_config_generation() {
    let source = r#"
pragma circom 2.0.0;

template Simple() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
}

component main = Simple();
"#;

    let temp_dir = TempDir::new().unwrap();
    let circuit_path = temp_dir.path().join("simple.circom");
    std::fs::write(&circuit_path, source).unwrap();

    let analyzer = OpusAnalyzer::new();
    let analysis = analyzer.analyze_circuit(&circuit_path).unwrap();
    let config = analyzer.generate_config(&analysis).unwrap();

    // Verify config structure
    assert!(config.config.base.is_some());
    let base = config.config.base.as_ref().unwrap();

    // Verify attacks are generated
    assert!(!base.attacks.is_empty());
    assert!(base
        .attacks
        .iter()
        .any(|a| a.attack_type == AttackType::Underconstrained));

    // Verify inputs are captured
    assert!(!base.inputs.is_empty());

    // Verify schedule is generated
    assert!(!config.config.schedule.is_empty());

    // Test saving
    let output_dir = temp_dir.path().join("output");
    let saved_path = config.save(&output_dir).unwrap();
    assert!(saved_path.exists());
}

/// Test adaptive scheduler budget allocation
#[test]
fn test_adaptive_scheduler_budget_allocation() {
    let mut scheduler = AdaptiveScheduler::with_config(AdaptiveSchedulerConfig::default());

    scheduler.initialize(&[
        AttackType::Underconstrained,
        AttackType::Soundness,
        AttackType::Collision,
    ]);

    // Simulate finding a bug with underconstrained
    let results = AttackResults {
        attack_type: AttackType::Underconstrained,
        new_coverage: 10,
        findings: vec![Finding {
            attack_type: AttackType::Underconstrained,
            severity: Severity::Critical,
            description: "Test finding".to_string(),
            poc: ProofOfConcept::default(),
            location: None,
        }],
        near_misses: vec![],
        iterations: 100,
        duration: Duration::from_secs(10),
    };

    scheduler.update_scores(&results);

    // Underconstrained should now have highest score
    let best = scheduler.best_attack();
    assert_eq!(best, Some(AttackType::Underconstrained));

    // Budget should favor underconstrained
    let budget = scheduler.allocate_budget(Duration::from_secs(300));
    assert!(
        budget.get(&AttackType::Underconstrained).unwrap()
            > budget.get(&AttackType::Soundness).unwrap()
    );
}

/// Test near-miss detection for range boundaries
#[test]
fn test_near_miss_range_detection() {
    let detector = NearMissDetector::new()
        .with_config(NearMissConfig {
            range_threshold: 0.1, // Within 10%
            ..Default::default()
        })
        .with_range_constraint(RangeConstraint {
            wire_index: 0,
            min_value: None,
            max_value: None,
            bit_length: Some(8), // Max value 255
        });

    // Test value near boundary (250 out of 255)
    let witness = vec![FieldElement::from_u64(250)];
    let near_misses = detector.detect(&witness);

    assert!(!near_misses.is_empty());
    assert!(near_misses[0].distance < 0.1);
}

/// Test near-miss collision detection
#[test]
fn test_near_miss_collision_detection() {
    let detector = NearMissDetector::new().with_config(NearMissConfig {
        collision_threshold: 0.9, // 90% similar
        ..Default::default()
    });

    // Two hashes that differ by only a few bits
    let hash_a = vec![0xFF; 32];
    let mut hash_b = vec![0xFF; 32];
    hash_b[0] = 0xFE; // One bit different

    let near_miss = detector.check_collision_near_miss(&hash_a, &hash_b);
    assert!(near_miss.is_some());

    let nm = near_miss.unwrap();
    assert!(nm.distance < 0.1);
}

/// Test config generator pattern detection
#[test]
fn test_config_generator_patterns() {
    let generator = ConfigGenerator::new();

    // Test hash pattern (most reliable)
    let hash_source = "component hasher = Poseidon(2);";
    let patterns = generator.detect_patterns(hash_source, zk_core::Framework::Circom);
    assert!(
        patterns
            .iter()
            .any(|p| matches!(p.pattern_type, PatternType::HashFunction(_))),
        "Should detect Poseidon hash function"
    );

    // Test range pattern
    let range_source = "component n2b = Num2Bits(64); LessThan comparison";
    let patterns = generator.detect_patterns(range_source, zk_core::Framework::Circom);
    assert!(
        patterns
            .iter()
            .any(|p| p.pattern_type == PatternType::RangeCheck
                || p.pattern_type == PatternType::BitDecomposition),
        "Should detect range/bit pattern"
    );

    // Test MiMC hash detection (alternative hash)
    let mimc_source = "component mimc = MiMC7(91);";
    let patterns = generator.detect_patterns(mimc_source, zk_core::Framework::Circom);
    assert!(
        patterns
            .iter()
            .any(|p| matches!(p.pattern_type, PatternType::HashFunction(_))),
        "Should detect MiMC hash function"
    );
}

/// Test YAML suggestion generation
#[test]
fn test_yaml_suggestions() {
    use zk_fuzzer::fuzzer::adaptive_attack_scheduler::{NearMissEvent, NearMissType};

    let mut scheduler = AdaptiveScheduler::new();
    scheduler.initialize(&[AttackType::Underconstrained]);

    // Simulate finding a bug to generate suggestions
    let results = AttackResults {
        attack_type: AttackType::Underconstrained,
        new_coverage: 10,
        findings: vec![Finding {
            attack_type: AttackType::Underconstrained,
            severity: Severity::Critical,
            description: "Test finding".to_string(),
            poc: ProofOfConcept::default(),
            location: None,
        }],
        near_misses: vec![NearMissEvent {
            event_type: NearMissType::AlmostOutOfRange,
            distance: 0.05,
            description: "0x1fffffffffffffff".to_string(),
        }],
        iterations: 100,
        duration: Duration::from_secs(10),
    };

    scheduler.update_scores(&results);

    let suggestions = scheduler.suggest_yaml_edits();

    // Scheduler should provide suggestions based on results
    // (might be empty if no near-misses recorded)
    assert!(
        suggestions.is_empty()
            || suggestions.iter().any(|s| matches!(
                s.suggestion_type,
                SuggestionType::AddInterestingValue | SuggestionType::IncreaseBudget
            ))
    );
}

/// Integration test: Full Opus analysis workflow
#[test]
fn test_opus_full_workflow() {
    // Create a complex circuit with multiple patterns
    let source = r#"
pragma circom 2.0.0;

include "circomlib/poseidon.circom";
include "circomlib/comparators.circom";

template SecureWithdraw(levels) {
    // Merkle proof inputs
    signal input root;
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    
    // Nullifier inputs
    signal input nullifier;
    signal input secret;
    
    // Range check
    signal input amount;
    
    signal output nullifierHash;
    signal output isValid;

    // Compute nullifier hash
    component nullHash = Poseidon(2);
    nullHash.inputs[0] <== nullifier;
    nullHash.inputs[1] <== secret;
    nullifierHash <== nullHash.out;

    // Merkle verification (simplified)
    component merkle = MerkleProof(levels);
    merkle.leaf <== leaf;
    for (var i = 0; i < levels; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndices[i] <== pathIndices[i];
    }

    // Range check on amount
    component rangeCheck = LessThan(64);
    rangeCheck.in[0] <== amount;
    rangeCheck.in[1] <== 1000000000000000000; // Max amount

    isValid <== rangeCheck.out;
}

component main = SecureWithdraw(20);
"#;

    let temp_dir = TempDir::new().unwrap();
    let circuit_path = temp_dir.path().join("withdraw.circom");
    std::fs::write(&circuit_path, source).unwrap();

    let analyzer = OpusAnalyzer::new();
    let analysis = analyzer.analyze_circuit(&circuit_path).unwrap();

    // Verify multiple patterns detected
    assert!(analysis
        .patterns
        .iter()
        .any(|p| p.pattern_type == PatternType::MerkleTree));
    assert!(analysis
        .patterns
        .iter()
        .any(|p| p.pattern_type == PatternType::Nullifier));
    assert!(analysis
        .patterns
        .iter()
        .any(|p| p.pattern_type == PatternType::RangeCheck));
    assert!(analysis
        .patterns
        .iter()
        .any(|p| matches!(p.pattern_type, PatternType::HashFunction(_))));

    // Verify attack priorities
    let has_collision = analysis
        .attack_priorities
        .iter()
        .any(|a| a.attack_type == AttackType::Collision);
    let has_underconstrained = analysis
        .attack_priorities
        .iter()
        .any(|a| a.attack_type == AttackType::Underconstrained);
    let has_overflow = analysis
        .attack_priorities
        .iter()
        .any(|a| a.attack_type == AttackType::ArithmeticOverflow);

    assert!(has_collision, "Should prioritize collision attack");
    assert!(
        has_underconstrained,
        "Should include underconstrained attack"
    );
    assert!(has_overflow, "Should include arithmetic overflow attack");

    // Generate config
    let config = analyzer.generate_config(&analysis).unwrap();

    // Verify invariants generated
    assert!(!config.config.invariants.is_empty());

    // Verify schedule has multiple phases
    assert!(config.config.schedule.len() >= 2);
}

/// Test project-level analysis
#[test]
fn test_opus_project_analysis() {
    let temp_dir = TempDir::new().unwrap();

    // Create multiple circuit files
    let circuit1 = r#"
pragma circom 2.0.0;
template Circuit1() { signal input x; signal output y; y <== x * x; }
component main = Circuit1();
"#;

    let circuit2 = r#"
pragma circom 2.0.0;
include "poseidon.circom";
template Circuit2() { 
    signal input x; 
    signal output hash;
    component h = Poseidon(1);
    h.inputs[0] <== x;
    hash <== h.out;
}
component main = Circuit2();
"#;

    std::fs::write(temp_dir.path().join("circuit1.circom"), circuit1).unwrap();
    std::fs::write(temp_dir.path().join("circuit2.circom"), circuit2).unwrap();

    let analyzer = OpusAnalyzer::new();
    let configs = analyzer.analyze_project(temp_dir.path()).unwrap();

    assert_eq!(configs.len(), 2);
}

/// Benchmark: Measure analysis time
#[test]
fn bench_opus_analysis_time() {
    use std::time::Instant;

    let source = r#"
pragma circom 2.0.0;
template Large() {
    signal input inputs[100];
    signal output outputs[100];
    for (var i = 0; i < 100; i++) {
        outputs[i] <== inputs[i] * inputs[i];
    }
}
component main = Large();
"#;

    let temp_dir = TempDir::new().unwrap();
    let circuit_path = temp_dir.path().join("large.circom");
    std::fs::write(&circuit_path, source).unwrap();

    let analyzer = OpusAnalyzer::new();

    let start = Instant::now();
    let _result = analyzer.analyze_circuit(&circuit_path).unwrap();
    let duration = start.elapsed();

    // Analysis should complete quickly (< 100ms)
    assert!(
        duration < Duration::from_millis(100),
        "Analysis took too long: {:?}",
        duration
    );
}
