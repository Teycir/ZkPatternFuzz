use tempfile::tempdir;
use zk_core::{AttackType, FieldElement, Finding, ProofOfConcept, Severity};
use zk_fuzzer::config::{Framework, FuzzConfig, FuzzStrategy, Input};
use zk_fuzzer::reporting::evidence::{BackendIdentity, EvidenceGenerator};

fn make_input(name: &str) -> Input {
    Input {
        name: name.to_string(),
        input_type: "field".to_string(),
        fuzz_strategy: FuzzStrategy::Random,
        constraints: Vec::new(),
        interesting: Vec::new(),
        length: None,
    }
}

fn make_finding(witness_a: Vec<FieldElement>) -> Finding {
    Finding {
        attack_type: AttackType::Metamorphic,
        severity: Severity::Medium,
        description: "evidence witness serialization regression".to_string(),
        poc: ProofOfConcept {
            witness_a,
            witness_b: None,
            public_inputs: Vec::new(),
            proof: None,
        },
        location: None,
        class: None,
    }
}

#[test]
fn generate_bundle_writes_array_shape_for_indexed_inputs() {
    let workspace = tempdir().expect("tempdir");
    let circuit_path = workspace.path().join("dummy.circom");
    std::fs::write(
        &circuit_path,
        "pragma circom 2.0.0; template main(){signal input in[2]; signal output out; out <== in[0] + in[1];} component main = main();\n",
    )
    .expect("write dummy circuit");

    let mut config = FuzzConfig::default_v2();
    config.campaign.name = "evidence_test".to_string();
    config.campaign.target.framework = Framework::Circom;
    config.campaign.target.circuit_path = circuit_path;
    config.campaign.target.main_component = "main".to_string();
    config.inputs = vec![make_input("in[0]"), make_input("in[1]")];

    let output_dir = workspace.path().join("evidence");
    let generator = EvidenceGenerator::new(config, output_dir);
    let finding = make_finding(vec![FieldElement::from_u64(7), FieldElement::from_u64(9)]);

    let bundle = generator
        .generate_bundle(&finding, BackendIdentity::from_framework(Framework::Circom))
        .expect("generate evidence bundle");

    let witness_path = bundle.witness_json.expect("witness path");
    let witness_value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(witness_path).expect("read witness json"))
            .expect("parse witness json");

    assert!(witness_value.get("in").is_some());
    assert!(witness_value.get("in[0]").is_none());
    assert!(witness_value.get("in[1]").is_none());

    let values = witness_value
        .get("in")
        .and_then(|v| v.as_array())
        .expect("array-shaped in input");
    assert_eq!(values.len(), 2);
    assert_eq!(values[0], serde_json::Value::String("7".to_string()));
    assert_eq!(values[1], serde_json::Value::String("9".to_string()));
}

#[test]
fn generate_bundle_keeps_plain_input_names_unchanged() {
    let workspace = tempdir().expect("tempdir");
    let circuit_path = workspace.path().join("dummy_plain.circom");
    std::fs::write(
        &circuit_path,
        "pragma circom 2.0.0; template main(){signal input a; signal input b; signal output out; out <== a + b;} component main = main();\n",
    )
    .expect("write dummy plain circuit");

    let mut config = FuzzConfig::default_v2();
    config.campaign.name = "evidence_test_plain".to_string();
    config.campaign.target.framework = Framework::Circom;
    config.campaign.target.circuit_path = circuit_path;
    config.campaign.target.main_component = "main".to_string();
    config.inputs = vec![make_input("a"), make_input("b")];

    let output_dir = workspace.path().join("evidence");
    let generator = EvidenceGenerator::new(config, output_dir);
    let finding = make_finding(vec![FieldElement::from_u64(3), FieldElement::from_u64(4)]);

    let bundle = generator
        .generate_bundle(&finding, BackendIdentity::from_framework(Framework::Circom))
        .expect("generate evidence bundle");

    let witness_path = bundle.witness_json.expect("witness path");
    let witness_value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(witness_path).expect("read witness json"))
            .expect("parse witness json");

    assert_eq!(
        witness_value.get("a"),
        Some(&serde_json::Value::String("3".to_string()))
    );
    assert_eq!(
        witness_value.get("b"),
        Some(&serde_json::Value::String("4".to_string()))
    );
}
