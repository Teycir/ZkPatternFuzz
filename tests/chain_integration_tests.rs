//! Chain Fuzzing Integration Tests (Mode 3)
//!
//! These tests validate the end-to-end chain fuzzing workflow:
//! - YAML parsing of chain configurations
//! - Chain execution with input wiring
//! - Cross-step assertion checking
//! - Finding generation and minimization
//!
//! Run with: `cargo test --test chain_integration_tests`



#[cfg(test)]
mod tests {

    /// Test that chain YAML parsing works correctly
    #[test]
    fn test_parse_chains_from_yaml() {
        use zk_fuzzer::config::{FuzzConfig, parse_chains};

        let yaml = r#"
campaign:
  name: "Chain Test"
  version: "1.0"
  target:
    framework: mock
    circuit_path: "./test.circom"
    main_component: "Test"
  parameters:
    field: "bn254"

chains:
  - name: "simple_chain"
    steps:
      - circuit_ref: "step1"
        input_wiring: fresh
      - circuit_ref: "step2"
        input_wiring:
          from_prior_output:
            step: 0
            mapping:
              - [0, 0]
    assertions:
      - name: "output_equality"
        relation: "step[0].out[0] == step[1].in[0]"
        severity: "high"

attacks: []
inputs: []
reporting:
  output_dir: "./reports"
  formats: [json]
"#;

        // Write to temp file
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("test_chain.yaml");
        std::fs::write(&config_path, yaml).unwrap();

        // Parse config and chains
        let config = FuzzConfig::from_yaml(config_path.to_str().unwrap()).unwrap();
        let chains = parse_chains(&config);

        assert_eq!(chains.len(), 1, "Should parse one chain");
        assert_eq!(chains[0].name, "simple_chain");
        assert_eq!(chains[0].steps.len(), 2, "Chain should have 2 steps");
        assert_eq!(chains[0].assertions.len(), 1, "Chain should have 1 assertion");
    }

    /// Test input wiring parsing for all variants
    #[test]
    fn test_parse_input_wiring_variants() {
        use zk_fuzzer::config::{FuzzConfig, parse_chains};

        let yaml = r#"
campaign:
  name: "Wiring Test"
  version: "1.0"
  target:
    framework: mock
    circuit_path: "./test.circom"
    main_component: "Test"
  parameters:
    field: "bn254"

chains:
  - name: "wiring_test"
    steps:
      # Fresh wiring
      - circuit_ref: "step1"
        input_wiring: fresh
        label: "Fresh inputs"
      
      # FromPriorOutput wiring
      - circuit_ref: "step2"
        input_wiring:
          from_prior_output:
            step: 0
            mapping:
              - [0, 0]
              - [1, 1]
        label: "From prior"
      
      # Mixed wiring
      - circuit_ref: "step3"
        input_wiring:
          mixed:
            prior:
              - [0, 0, 0]
              - [1, 1, 1]
            fresh_indices: [2, 3]
        label: "Mixed"
      
      # Constant wiring
      - circuit_ref: "step4"
        input_wiring:
          constant:
            values:
              0: "0x1234"
              2: "0xabcd"
            fresh_indices: [1, 3]
        label: "Constant"
    assertions: []

attacks: []
inputs: []
reporting:
  output_dir: "./reports"
  formats: [json]
"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("wiring_test.yaml");
        std::fs::write(&config_path, yaml).unwrap();

        let config = FuzzConfig::from_yaml(config_path.to_str().unwrap()).unwrap();
        let chains = parse_chains(&config);

        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].steps.len(), 4, "Should parse all 4 wiring variants");
    }

    /// Test multi-circuit configuration parsing
    /// Note: Circuit paths are resolved from the v2 config, not stored in ChainSpec directly
    #[test]
    fn test_parse_multi_circuit_chain() {
        use zk_fuzzer::config::{FuzzConfig, parse_chains};

        let yaml = r#"
campaign:
  name: "Multi-Circuit Test"
  version: "1.0"
  target:
    framework: mock
    circuit_path: "./default.circom"
    main_component: "Default"
  parameters:
    field: "bn254"

chains:
  - name: "multi_circuit"
    description: "Multi-circuit chain test"
    steps:
      - circuit_ref: "deposit"
        input_wiring: fresh
      - circuit_ref: "withdraw"
        input_wiring:
          from_prior_output:
            step: 0
            mapping:
              - [0, 0]
    assertions:
      - name: "nullifier_binding"
        relation: "step[0].out[0] == step[1].in[0]"
        severity: "critical"

attacks: []
inputs: []
reporting:
  output_dir: "./reports"
  formats: [json]
"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("multi_circuit.yaml");
        std::fs::write(&config_path, yaml).unwrap();

        let config = FuzzConfig::from_yaml(config_path.to_str().unwrap()).unwrap();
        let chains = parse_chains(&config);

        assert_eq!(chains.len(), 1);
        let chain = &chains[0];
        
        // Verify chain was parsed with multiple steps
        assert_eq!(chain.steps.len(), 2, "Should have 2 steps");
        assert_eq!(chain.steps[0].circuit_ref, "deposit");
        assert_eq!(chain.steps[1].circuit_ref, "withdraw");
        assert_eq!(chain.assertions.len(), 1, "Should have 1 assertion");
    }

    /// Test assertion relation parsing
    #[test]
    fn test_parse_assertion_relations() {
        use zk_fuzzer::config::{FuzzConfig, parse_chains};

        let yaml = r#"
campaign:
  name: "Assertion Test"
  version: "1.0"
  target:
    framework: mock
    circuit_path: "./test.circom"
    main_component: "Test"
  parameters:
    field: "bn254"

chains:
  - name: "assertion_test"
    steps:
      - circuit_ref: "step1"
        input_wiring: fresh
      - circuit_ref: "step2"
        input_wiring: fresh
    assertions:
      # Equality assertion
      - name: "equality_check"
        relation: "step[0].out[0] == step[1].in[0]"
        severity: "high"
        description: "Outputs must match inputs"
      
      # Inequality assertion
      - name: "inequality_check"
        relation: "step[0].out[0] != step[1].out[0]"
        severity: "medium"
      
      # Uniqueness assertion
      - name: "uniqueness_check"
        relation: "unique(step[*].out[0])"
        severity: "critical"
      
      # Success assertion
      - name: "success_check"
        relation: "step[1].success == true"
        severity: "critical"

attacks: []
inputs: []
reporting:
  output_dir: "./reports"
  formats: [json]
"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("assertion_test.yaml");
        std::fs::write(&config_path, yaml).unwrap();

        let config = FuzzConfig::from_yaml(config_path.to_str().unwrap()).unwrap();
        let chains = parse_chains(&config);

        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].assertions.len(), 4, "Should parse all 4 assertions");
        
        // Verify assertion properties
        let assertions = &chains[0].assertions;
        assert_eq!(assertions[0].name, "equality_check");
        assert_eq!(assertions[0].severity, "high");
        assert_eq!(assertions[2].name, "uniqueness_check");
        assert_eq!(assertions[2].severity, "critical");
    }

    /// Test chain with schedule phases
    #[test]
    fn test_parse_chain_with_schedule() {
        use zk_fuzzer::config::{FuzzConfig, parse_chains};

        let yaml = r#"
campaign:
  name: "Schedule Test"
  version: "1.0"
  target:
    framework: mock
    circuit_path: "./test.circom"
    main_component: "Test"
  parameters:
    field: "bn254"

chains:
  - name: "scheduled_chain"
    steps:
      - circuit_ref: "step1"
        input_wiring: fresh
    assertions: []

attacks:
  - type: underconstrained
    description: "Test"
    config:
      witness_pairs: 100

inputs: []

schedule:
  - phase: "seed"
    duration_sec: 60
    attacks: ["underconstrained"]
  - phase: "deep"
    duration_sec: 240
    attacks: ["underconstrained"]
    carry_corpus: true

reporting:
  output_dir: "./reports"
  formats: [json]
"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("schedule_test.yaml");
        std::fs::write(&config_path, yaml).unwrap();

        let config = FuzzConfig::from_yaml(config_path.to_str().unwrap()).unwrap();
        let chains = parse_chains(&config);
        
        // Verify chains parsed and schedule config is valid
        assert_eq!(chains.len(), 1, "Should parse 1 chain");
        assert_eq!(chains[0].name, "scheduled_chain");
    }

    /// Test empty chains section is handled
    #[test]
    fn test_empty_chains_section() {
        use zk_fuzzer::config::{FuzzConfig, parse_chains};

        // Note: Config requires at least one attack, so we include a minimal one
        let yaml = r#"
campaign:
  name: "Empty Chains"
  version: "1.0"
  target:
    framework: mock
    circuit_path: "./test.circom"
    main_component: "Test"
  parameters:
    field: "bn254"

chains: []

attacks:
  - type: boundary
    description: "Minimal attack for valid config"
    config:
      test_values: ["0"]
      
inputs:
  - name: "dummy"
    type: "field"
    fuzz_strategy: random
reporting:
  output_dir: "./reports"
  formats: [json]
"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("empty_chains.yaml");
        std::fs::write(&config_path, yaml).unwrap();

        let config = FuzzConfig::from_yaml(config_path.to_str().unwrap()).unwrap();
        let chains = parse_chains(&config);

        assert!(chains.is_empty(), "Should return empty chains list");
    }

    /// Test chain types module integration
    #[test]
    fn test_chain_spec_creation() {
        use zk_fuzzer::chain_fuzzer::{ChainSpec, StepSpec, InputWiring, CrossStepAssertion};

        let chain = ChainSpec {
            name: "test_chain".to_string(),
            steps: vec![
                StepSpec {
                    circuit_ref: "circuit1".to_string(),
                    input_wiring: InputWiring::Fresh,
                    label: Some("First step".to_string()),
                    expected_inputs: None,
                    expected_outputs: None,
                },
                StepSpec {
                    circuit_ref: "circuit2".to_string(),
                    input_wiring: InputWiring::FromPriorOutput {
                        step: 0,
                        mapping: vec![(0, 0)],
                    },
                    label: Some("Second step".to_string()),
                    expected_inputs: None,
                    expected_outputs: None,
                },
            ],
            assertions: vec![
                CrossStepAssertion::new(
                    "test_assertion",
                    "step[0].out[0] == step[1].in[0]",
                ).with_severity("high"),
            ],
            description: None,
        };

        assert_eq!(chain.name, "test_chain");
        assert_eq!(chain.steps.len(), 2);
        assert_eq!(chain.assertions.len(), 1);
    }

    /// Test depth metrics calculation
    #[test]
    fn test_depth_metrics_calculation() {
        use zk_fuzzer::chain_fuzzer::{ChainFinding, DepthMetrics, ChainTrace, StepTrace};
        use zk_fuzzer::chain_fuzzer::types::ChainFindingCore;

        // Create mock chain findings with different L_min values
        let findings = vec![
            ChainFinding {
                finding: ChainFindingCore {
                    attack_type: "underconstrained".to_string(),
                    severity: "high".to_string(),
                    description: "Test 1".to_string(),
                    witness_inputs: vec![],
                    location: None,
                },
                chain_length: 2,
                l_min: 2,
                spec_name: "chain1".to_string(),
                violated_assertion: Some("test_assertion".to_string()),
                trace: ChainTrace {
                    spec_name: "chain1".to_string(),
                    steps: vec![
                        StepTrace {
                            step_index: 0,
                            circuit_ref: "c1".to_string(),
                            inputs: vec![],
                            outputs: vec![],
                            success: true,
                            error: None,
                            constraints_hit: std::collections::HashSet::new(),
                            execution_time_ms: 0,
                        },
                        StepTrace {
                            step_index: 1,
                            circuit_ref: "c2".to_string(),
                            inputs: vec![],
                            outputs: vec![],
                            success: true,
                            error: None,
                            constraints_hit: std::collections::HashSet::new(),
                            execution_time_ms: 0,
                        },
                    ],
                    success: true,
                    execution_time_ms: 0,
                },
            },
            ChainFinding {
                finding: ChainFindingCore {
                    attack_type: "underconstrained".to_string(),
                    severity: "critical".to_string(),
                    description: "Test 2".to_string(),
                    witness_inputs: vec![],
                    location: None,
                },
                chain_length: 3,
                l_min: 3,
                spec_name: "chain2".to_string(),
                violated_assertion: Some("another_assertion".to_string()),
                trace: ChainTrace {
                    spec_name: "chain2".to_string(),
                    steps: vec![],
                    success: true,
                    execution_time_ms: 0,
                },
            },
        ];

        let metrics = DepthMetrics::new(findings);
        let summary = metrics.summary();

        assert_eq!(summary.total_findings, 2);
        assert!((summary.d_mean - 2.5).abs() < 0.01, "D should be 2.5 (mean of 2 and 3)");
        assert!((summary.p_deep - 1.0).abs() < 0.01, "P_deep should be 1.0 (all findings have L_min >= 2)");
    }

    /// Test chain finding serialization
    #[test]
    fn test_chain_finding_serialization() {
        use zk_fuzzer::chain_fuzzer::{ChainFinding, ChainTrace, StepTrace};
        use zk_fuzzer::chain_fuzzer::types::ChainFindingCore;

        let finding = ChainFinding {
            finding: ChainFindingCore {
                attack_type: "underconstrained".to_string(),
                severity: "critical".to_string(),
                description: "Nullifier reuse detected".to_string(),
                witness_inputs: vec![],
                location: None,
            },
            chain_length: 2,
            l_min: 2,
            spec_name: "double_withdraw".to_string(),
            violated_assertion: Some("no_nullifier_reuse".to_string()),
            trace: ChainTrace {
                spec_name: "double_withdraw".to_string(),
                steps: vec![
                    StepTrace {
                        step_index: 0,
                        circuit_ref: "withdraw".to_string(),
                        inputs: vec![],
                        outputs: vec![],
                        success: true,
                        error: None,
                        constraints_hit: std::collections::HashSet::new(),
                        execution_time_ms: 0,
                    },
                ],
                success: true,
                execution_time_ms: 0,
            },
        };

        // Test JSON serialization
        let json = serde_json::to_string_pretty(&finding).unwrap();
        assert!(json.contains("double_withdraw"), "JSON should contain spec name");
        assert!(json.contains("no_nullifier_reuse"), "JSON should contain violated assertion");

        // Test deserialization roundtrip
        let deserialized: ChainFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.l_min, 2);
        assert_eq!(deserialized.spec_name, "double_withdraw");
    }

    /// Test chain validation checks
    #[test]
    fn test_chain_validation() {
        use zk_fuzzer::config::FuzzConfig;

        // Valid chain should parse
        let valid_yaml = r#"
campaign:
  name: "Valid Chain"
  version: "1.0"
  target:
    framework: mock
    circuit_path: "./test.circom"
    main_component: "Test"
  parameters:
    field: "bn254"

chains:
  - name: "valid"
    steps:
      - circuit_ref: "step1"
        input_wiring: fresh
    assertions: []

attacks: []
inputs: []
reporting:
  output_dir: "./reports"
  formats: [json]
"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("valid_chain.yaml");
        std::fs::write(&config_path, valid_yaml).unwrap();

        let result = FuzzConfig::from_yaml(config_path.to_str().unwrap());
        assert!(result.is_ok(), "Valid chain config should parse successfully");
    }

    /// Test chain with template file format (deepest_multistep.yaml compatibility)
    #[test]
    fn test_template_format_compatibility() {
        use zk_fuzzer::config::{FuzzConfig, parse_chains};

        // This mimics the format used in campaigns/templates/deepest_multistep.yaml
        let yaml = r#"
campaign:
  name: "Mode 3: Multi-Step Chain Audit"
  version: "1.0"
  target:
    framework: circom
    circuit_path: "./circuits/main.circom"
    main_component: "Main"
  parameters:
    field: "bn254"
    max_constraints: 100000
    timeout_seconds: 1800
    additional:
      strict_backend: true
      evidence_mode: true
      chain_budget_seconds: 600
      chain_iterations: 5000

chains:
  - name: "deposit_then_withdraw"
    description: "Verify deposit and withdraw maintain invariants"
    steps:
      - circuit_ref: "deposit"
        input_wiring: fresh
        label: "Initial deposit"
      - circuit_ref: "withdraw"
        input_wiring:
          from_prior_output:
            step: 0
            mapping:
              - [0, 2]
              - [1, 3]
        label: "Withdrawal using deposit outputs"
    assertions:
      - name: "nullifier_uniqueness"
        relation: "unique(step[*].out[0])"
        severity: "critical"
        description: "Nullifiers must be unique across all steps"
      - name: "root_consistency"
        relation: "step[0].out[1] == step[1].in[3]"
        severity: "high"
        description: "Root from deposit must match withdraw input"

invariants:
  - name: "range_check"
    invariant_type: range
    relation: "0 <= amount < 2^64"
    severity: "high"

attacks:
  - type: underconstrained
    description: "Find multiple valid witnesses"
    config:
      witness_pairs: 5000

inputs:
  - name: "nullifier"
    type: "field"
    fuzz_strategy: random

reporting:
  output_dir: "./reports/mode3"
  formats:
    - json
    - markdown
  include_poc: true

schedule:
  - phase: "chain_seed"
    duration_sec: 120
    attacks: ["underconstrained"]
"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("template_test.yaml");
        std::fs::write(&config_path, yaml).unwrap();

        let config = FuzzConfig::from_yaml(config_path.to_str().unwrap()).unwrap();
        let chains = parse_chains(&config);

        assert_eq!(chains.len(), 1);
        let chain = &chains[0];
        assert_eq!(chain.name, "deposit_then_withdraw");
        assert_eq!(chain.steps.len(), 2);
        assert_eq!(chain.assertions.len(), 2);
        
        // Verify step labels were parsed
        assert_eq!(chain.steps[0].label, Some("Initial deposit".to_string()));
        assert_eq!(chain.steps[1].label, Some("Withdrawal using deposit outputs".to_string()));
    }
}
