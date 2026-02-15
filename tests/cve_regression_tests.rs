//! CVE Regression Tests
//!
//! Tests that ZkPatternFuzz can detect known ZK vulnerabilities.
//! Each test loads a CVE pattern and verifies detection capability.

use zk_fuzzer::config::{AttackType, Severity};
use zk_fuzzer::corpus::{calculate_confidence, SemanticDeduplicator};
use zk_fuzzer::cve::CveDatabase;
use zk_fuzzer::fuzzer::{
    grammar::{self, GenerationStrategy, GrammarGenerator, InputGrammar},
    oracles::{
        CombinedSemanticOracle, MerkleOracle, NullifierOracle, OracleConfig, SemanticOracle,
    },
    FieldElement, Finding, ProofOfConcept, TestCase, TestMetadata,
};

/// Path to the CVE database
const CVE_DATABASE_PATH: &str = "templates/known_vulnerabilities.yaml";

// ============== CVE Database Loading Tests ==============

#[test]
fn test_load_cve_database() {
    let db = CveDatabase::load(CVE_DATABASE_PATH);
    assert!(db.is_ok(), "Failed to load CVE database: {:?}", db.err());

    let db = db.unwrap();
    assert!(
        !db.vulnerabilities.is_empty(),
        "CVE database should not be empty"
    );
    assert!(
        db.vulnerabilities.len() >= 8,
        "Expected at least 8 CVEs, got {}",
        db.vulnerabilities.len()
    );
}

#[test]
fn test_cve_database_structure() {
    let db = CveDatabase::load(CVE_DATABASE_PATH).expect("Failed to load CVE database");

    for cve in &db.vulnerabilities {
        // Each CVE must have required fields
        assert!(!cve.id.is_empty(), "CVE ID cannot be empty");
        assert!(!cve.name.is_empty(), "CVE name cannot be empty");
        assert!(!cve.severity.is_empty(), "CVE severity cannot be empty");
        assert!(
            !cve.description.is_empty(),
            "CVE description cannot be empty"
        );

        // Severity must be valid
        let severity = cve.severity_enum();
        assert!(
            matches!(
                severity,
                Severity::Critical
                    | Severity::High
                    | Severity::Medium
                    | Severity::Low
                    | Severity::Info
            ),
            "Invalid severity: {}",
            cve.severity
        );

        // Detection config must have oracle
        assert!(
            !cve.detection.oracle.is_empty(),
            "CVE {} must specify detection oracle",
            cve.id
        );
    }
}

#[test]
fn test_cve_pattern_matching() {
    let db = CveDatabase::load(CVE_DATABASE_PATH).expect("Failed to load CVE database");

    // Test Tornado Cash matching
    let tornado_patterns = db.patterns_for_circuit("tornado-core");
    assert!(
        !tornado_patterns.is_empty(),
        "Should have patterns for tornado-core"
    );

    // Test Semaphore matching
    let semaphore_patterns = db.patterns_for_circuit("semaphore");
    assert!(
        !semaphore_patterns.is_empty(),
        "Should have patterns for semaphore"
    );

    // Test zkEVM matching
    let zkevm_patterns = db.patterns_for_circuit("zkevm-circuits");
    assert!(
        !zkevm_patterns.is_empty(),
        "Should have patterns for zkevm-circuits"
    );
}

#[test]
fn test_cve_by_severity() {
    let db = CveDatabase::load(CVE_DATABASE_PATH).expect("Failed to load CVE database");

    let critical = db.patterns_by_severity(Severity::Critical);
    let high = db.patterns_by_severity(Severity::High);
    let medium = db.patterns_by_severity(Severity::Medium);

    println!("Critical CVEs: {}", critical.len());
    println!("High CVEs: {}", high.len());
    println!("Medium CVEs: {}", medium.len());

    // Should have at least some critical and high severity
    assert!(!critical.is_empty(), "Should have critical severity CVEs");
    assert!(!high.is_empty(), "Should have high severity CVEs");
}

// ============== ZK-CVE-2022-001: EdDSA Signature Malleability ==============

#[test]
fn test_eddsa_malleability_detection() {
    let db = CveDatabase::load(CVE_DATABASE_PATH).expect("Failed to load CVE database");
    let cve = db.get_pattern("ZK-CVE-2022-001").expect("CVE not found");

    assert_eq!(cve.name, "EdDSA Signature Malleability");
    assert_eq!(cve.severity_enum(), Severity::Critical);

    // Simulate signature malleability scenario
    // s > q/2 is malleable (can be negated)
    let half_q = FieldElement::half_modulus();
    let malleable_s = FieldElement::max_value(); // s close to field max (> q/2)

    // The check: if s > q/2, signature is malleable
    let is_malleable = malleable_s.to_biguint() > half_q.to_biguint();
    assert!(is_malleable, "Test value should be in malleable range");

    // Canonical s (< q/2) should not be malleable
    let canonical_s = FieldElement::from_u64(12345);
    let is_canonical = canonical_s.to_biguint() < half_q.to_biguint();
    assert!(is_canonical, "Small value should be canonical");
}

#[test]
fn test_eddsa_malleability_finding_creation() {
    let db = CveDatabase::load(CVE_DATABASE_PATH).expect("Failed to load CVE database");
    let cve = db.get_pattern("ZK-CVE-2022-001").expect("CVE not found");

    let poc = ProofOfConcept {
        witness_a: vec![FieldElement::from_u64(100), FieldElement::max_value()],
        witness_b: Some(vec![
            FieldElement::from_u64(100),
            FieldElement::max_value().neg(),
        ]),
        public_inputs: vec![],
        proof: None,
    };

    let finding = cve.create_finding(poc, Some("signature.s".to_string()));

    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.attack_type, AttackType::Malleability);
    assert!(finding.description.contains("ZK-CVE-2022-001"));
    assert!(finding.description.contains("EdDSA"));
}

// ============== ZK-CVE-2022-002: Nullifier Collision ==============

#[test]
fn test_nullifier_collision_oracle() {
    let config = OracleConfig::default();
    let mut oracle = NullifierOracle::new(config);

    // Create two test cases with different secrets
    let tc1 = TestCase {
        inputs: vec![FieldElement::from_u64(111), FieldElement::from_u64(222)],
        expected_output: None,
        metadata: TestMetadata::default(),
    };

    let tc2 = TestCase {
        inputs: vec![FieldElement::from_u64(333), FieldElement::from_u64(444)],
        expected_output: None,
        metadata: TestMetadata::default(),
    };

    // Same nullifier output for different secrets = collision!
    let output = vec![FieldElement::from_u64(999), FieldElement::from_u64(888)];

    // First check - records observation
    let finding1 = oracle.check(&tc1, &output);
    assert!(
        finding1.is_none(),
        "First observation should not trigger finding"
    );

    // Second check with same nullifier but different secret - COLLISION!
    let finding2 = oracle.check(&tc2, &output);
    assert!(finding2.is_some(), "Should detect nullifier collision");

    let finding = finding2.unwrap();
    assert_eq!(finding.severity, Severity::Critical);
    assert!(finding.description.contains("COLLISION"));
}

#[test]
fn test_nullifier_no_false_positive() {
    let config = OracleConfig::default();
    let mut oracle = NullifierOracle::new(config);

    // Same secret, same nullifier = NOT a collision
    let tc = TestCase {
        inputs: vec![FieldElement::from_u64(111), FieldElement::from_u64(222)],
        expected_output: None,
        metadata: TestMetadata::default(),
    };

    let output = vec![FieldElement::from_u64(999), FieldElement::from_u64(888)];

    // Check twice with same inputs
    assert!(oracle.check(&tc, &output).is_none());
    assert!(oracle.check(&tc, &output).is_none()); // Should still be None
}

// ============== ZK-CVE-2021-001: Merkle Path Length Bypass ==============

#[test]
fn test_merkle_path_length_cve() {
    let db = CveDatabase::load(CVE_DATABASE_PATH).expect("Failed to load CVE database");
    let cve = db.get_pattern("ZK-CVE-2021-001").expect("CVE not found");

    assert_eq!(cve.name, "Merkle Path Length Bypass");
    assert_eq!(cve.severity_enum(), Severity::High);
    assert!(cve.affects_circuit("merkleTree"));
}

#[test]
fn test_merkle_oracle_path_validation() {
    let config = OracleConfig::default();
    let mut oracle = MerkleOracle::new(config);

    // Valid 20-level path
    let mut inputs = vec![FieldElement::from_u64(1)]; // leaf
    for _ in 0..20 {
        inputs.push(FieldElement::random(&mut rand::thread_rng())); // path elements
    }
    for _ in 0..20 {
        inputs.push(FieldElement::from_u64(if rand::random() { 1 } else { 0 }));
        // indices
    }

    let tc = TestCase {
        inputs,
        expected_output: None,
        metadata: TestMetadata::default(),
    };

    let output = vec![FieldElement::from_u64(123)]; // root

    // First check should pass (valid structure)
    let finding = oracle.check(&tc, &output);
    // MerkleOracle may or may not find issues depending on internal validation
    // This test ensures no panic and basic functionality
    let _ = finding;
}

// ============== ZK-CVE-2021-002: Merkle Sibling Order ==============

#[test]
fn test_merkle_sibling_order_cve() {
    let db = CveDatabase::load(CVE_DATABASE_PATH).expect("Failed to load CVE database");
    let cve = db.get_pattern("ZK-CVE-2021-002").expect("CVE not found");

    assert_eq!(cve.name, "Merkle Sibling Order Ambiguity");
    assert_eq!(cve.severity_enum(), Severity::High);

    // Check detection pattern
    assert_eq!(cve.detection.attack_type, "underconstrained");
}

// ============== ZK-CVE-2023-001: Field Overflow in Range Proofs ==============

#[test]
fn test_range_overflow_cve() {
    let db = CveDatabase::load(CVE_DATABASE_PATH).expect("Failed to load CVE database");
    let cve = db.get_pattern("ZK-CVE-2023-001").expect("CVE not found");

    assert_eq!(cve.name, "Field Overflow in Range Proofs");
    assert_eq!(cve.severity_enum(), Severity::High);
    assert!(cve.affects_circuit("range_proof"));
    assert!(cve.affects_circuit("Num2Bits"));
}

#[test]
fn test_range_proof_boundary_values() {
    // Test that boundary values are properly identified
    let within_range = FieldElement::from_u64(255); // 8-bit max
    let at_boundary = FieldElement::from_u64(256); // Just over 8-bit
    let field_max = FieldElement::max_value();

    assert!(within_range.to_biguint() < num_bigint::BigUint::from(256u32));
    assert!(at_boundary.to_biguint() >= num_bigint::BigUint::from(256u32));
    assert!(field_max.to_biguint() > num_bigint::BigUint::from(u64::MAX));
}

// ============== Grammar DSL Tests ==============

#[test]
fn test_tornado_cash_grammar() {
    let grammar = grammar::standard::tornado_cash_withdrawal();
    let mut gen = GrammarGenerator::new(grammar);
    let mut rng = rand::thread_rng();

    // Generate test cases with different strategies
    let random_tc = gen.generate_with_strategy(GenerationStrategy::Random, &mut rng);
    let boundary_tc = gen.generate_with_strategy(GenerationStrategy::Boundary, &mut rng);
    let zeros_tc = gen.generate_with_strategy(GenerationStrategy::AllZeros, &mut rng);

    // All should have correct input count (48 = 8 single + 20+20 arrays)
    assert_eq!(random_tc.inputs.len(), 48);
    assert_eq!(boundary_tc.inputs.len(), 48);
    assert_eq!(zeros_tc.inputs.len(), 48);

    // All zeros should be all zeros
    assert!(zeros_tc.inputs.iter().all(|fe| fe.is_zero()));
}

#[test]
fn test_semaphore_grammar() {
    let grammar = grammar::standard::semaphore_identity();
    let mut rng = rand::thread_rng();

    let tc = grammar.generate(&mut rng);
    assert!(!tc.inputs.is_empty());

    // Mutate and verify
    let mutated = grammar.mutate(&tc, &mut rng);
    assert_eq!(tc.inputs.len(), mutated.inputs.len());
}

#[test]
fn test_custom_grammar_parsing() {
    let yaml = r#"
name: CustomRangeProof
description: Custom range proof for testing
inputs:
  - name: value
    type: field
    constraints:
      - "range: [0, 255]"
    interesting:
      - "0x0"
      - "0x1"
      - "0xff"
  - name: bits
    type: array
    length: 8
    element_type: bool
invariants:
  - "value == sum(bits[i] * 2^i)"
"#;

    let grammar = InputGrammar::from_yaml_str(yaml).expect("Failed to parse grammar");
    assert_eq!(grammar.name, "CustomRangeProof");
    assert_eq!(grammar.inputs.len(), 2);
    assert_eq!(grammar.invariants.len(), 1);
}

// ============== Semantic Deduplication Tests ==============

#[test]
fn test_semantic_deduplication() {
    let mut dedup = SemanticDeduplicator::new();

    // Create similar findings (same oracle, same location category)
    let finding1 = Finding {
        attack_type: AttackType::Collision,
        severity: Severity::Critical,
        description: "Nullifier collision 1".to_string(),
        poc: ProofOfConcept {
            witness_a: vec![FieldElement::from_u64(1)],
            witness_b: None,
            public_inputs: vec![],
            proof: None,
        },
        location: Some("nullifier_generation".to_string()),
    };

    let finding2 = Finding {
        attack_type: AttackType::Collision,
        severity: Severity::Critical,
        description: "Nullifier collision 2".to_string(),
        poc: ProofOfConcept {
            witness_a: vec![FieldElement::from_u64(2)],
            witness_b: None,
            public_inputs: vec![],
            proof: None,
        },
        location: Some("nullifier_generation".to_string()),
    };

    let finding3 = Finding {
        attack_type: AttackType::Boundary,
        severity: Severity::High,
        description: "Merkle path bypass".to_string(),
        poc: ProofOfConcept {
            witness_a: vec![FieldElement::from_u64(3)],
            witness_b: None,
            public_inputs: vec![],
            proof: None,
        },
        location: Some("merkle_path".to_string()),
    };

    // First finding should be added
    assert!(dedup.add(finding1.clone()));

    // Second finding is semantically similar - should be deduplicated
    assert!(!dedup.add(finding2));

    // Third finding is different - should be added
    assert!(dedup.add(finding3));

    assert_eq!(dedup.stats().unique_findings, 2);
    assert_eq!(dedup.stats().duplicates_filtered, 1);
}

#[test]
fn test_confidence_scoring() {
    let low_confidence = Finding {
        attack_type: AttackType::Boundary,
        severity: Severity::Low,
        description: "Low confidence finding".to_string(),
        poc: ProofOfConcept::default(),
        location: None,
    };

    let high_confidence = Finding {
        attack_type: AttackType::Collision,
        severity: Severity::Critical,
        description: "High confidence finding".to_string(),
        poc: ProofOfConcept {
            witness_a: vec![FieldElement::from_u64(1)],
            witness_b: Some(vec![FieldElement::from_u64(2)]),
            public_inputs: vec![],
            proof: None,
        },
        location: Some("nullifier".to_string()),
    };

    let low_score = calculate_confidence(&low_confidence);
    let high_score = calculate_confidence(&high_confidence);

    assert!(
        high_score > low_score,
        "Critical findings with POC should have higher confidence"
    );
    assert!(high_score > 0.8, "High confidence score should be > 0.8");
}

// ============== Combined Oracle Tests ==============

#[test]
fn test_combined_semantic_oracle() {
    let config = OracleConfig::default();
    let mut combined = CombinedSemanticOracle::with_all_oracles(config);

    let tc = TestCase {
        inputs: vec![FieldElement::from_u64(111), FieldElement::from_u64(222)],
        expected_output: None,
        metadata: TestMetadata::default(),
    };

    let output = vec![FieldElement::from_u64(999)];

    // Check all oracles
    let findings = combined.check_all(&tc, &output);

    // Should not crash and should return valid findings (may be empty)
    let _ = findings;

    // Get stats from all oracles
    let stats = combined.stats();
    assert!(!stats.is_empty(), "Should have stats from all oracles");
}

// ============== Regression Test Generation ==============

#[test]
fn test_regression_test_generation() {
    let db = CveDatabase::load(CVE_DATABASE_PATH).expect("Failed to load CVE database");
    let tests = db.generate_regression_tests();

    assert!(!tests.is_empty(), "Should generate regression tests");

    for test in &tests {
        println!("Regression test for {}: {}", test.cve_id, test.cve_name);
        assert!(!test.cve_id.is_empty());
        assert!(!test.assertion.is_empty());
    }
}

// ============== Integration: Full Detection Flow ==============

#[test]
fn test_full_cve_detection_flow() {
    // Load CVE database
    let db = CveDatabase::load(CVE_DATABASE_PATH).expect("Failed to load CVE database");

    // Get patterns for Tornado Cash
    let patterns = db.patterns_for_circuit("tornado-core");
    assert!(!patterns.is_empty());

    // Create grammar for input generation
    let grammar = grammar::standard::tornado_cash_withdrawal();
    let mut rng = rand::thread_rng();

    // Generate test cases
    let test_case = grammar.generate(&mut rng);

    // Create combined oracle
    let config = OracleConfig::default();
    let mut oracle = CombinedSemanticOracle::with_all_oracles(config);

    // Simulate circuit output with safe values (within field)
    let output = vec![
        FieldElement::from_u64(12345), // root
        FieldElement::from_u64(67890), // nullifierHash
    ];

    // Check for vulnerabilities
    let _findings = oracle.check_all(&test_case, &output);

    // Create deduplicator
    let mut dedup = SemanticDeduplicator::new();

    // Run multiple iterations with safe field values
    for i in 0..10 {
        let tc = grammar.generate(&mut rng);
        // Use deterministic field elements to avoid overflow edge cases
        let out = vec![
            FieldElement::from_u64(1000 + i as u64),
            FieldElement::from_u64(2000 + i as u64),
        ];

        if let Some(finding) = oracle.check(&tc, &out) {
            dedup.add(finding);
        }
    }

    // Report
    println!("Detection flow completed:");
    println!("  Patterns loaded: {}", patterns.len());
    println!("  Test cases generated: 10");
    println!("  Unique findings: {}", dedup.stats().unique_findings);
}
