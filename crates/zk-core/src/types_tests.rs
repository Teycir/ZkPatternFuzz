use super::*;

fn make_finding(description: &str, witness_b: Option<Vec<FieldElement>>) -> Finding {
    Finding {
        attack_type: AttackType::Underconstrained,
        severity: Severity::High,
        description: description.to_string(),
        class: None,
        location: None,
        poc: ProofOfConcept {
            witness_a: vec![FieldElement::from_u64(1)],
            witness_b,
            public_inputs: vec![],
            proof: None,
        },
    }
}

#[test]
fn classify_single_witness_is_heuristic() {
    let finding = make_finding("Potential semantic check fired", None);
    assert_eq!(finding.classify(), FindingClass::Heuristic);
}

#[test]
fn classify_cross_witness_evidence_as_oracle_violation() {
    let finding = make_finding(
        "Different witnesses produce identical output",
        Some(vec![FieldElement::from_u64(2)]),
    );
    assert_eq!(finding.classify(), FindingClass::OracleViolation);
}

#[test]
fn classify_invariant_violation() {
    let finding = make_finding("Invariant violated: output uniqueness", None);
    assert_eq!(finding.classify(), FindingClass::InvariantViolation);
}

#[test]
fn deserialize_finding_supports_phase3_and_advanced_attack_variants() {
    let mev: Finding = serde_json::from_str(
        r#"{
                "attack_type":"Mev",
                "severity":"high",
                "description":"mev test",
                "location":null,
                "poc_witness_a":[]
            }"#,
    )
    .expect("deserialize Mev finding");
    assert_eq!(mev.attack_type, AttackType::Mev);

    let batch: Finding = serde_json::from_str(
        r#"{
                "attack_type":"BatchVerification",
                "severity":"medium",
                "description":"batch test",
                "location":null,
                "poc_witness_a":[]
            }"#,
    )
    .expect("deserialize BatchVerification finding");
    assert_eq!(batch.attack_type, AttackType::BatchVerification);

    let front_running: Finding = serde_json::from_str(
        r#"{
                "attack_type":"FrontRunning",
                "severity":"high",
                "description":"front-running test",
                "location":null,
                "poc_witness_a":[]
            }"#,
    )
    .expect("deserialize FrontRunning finding");
    assert_eq!(front_running.attack_type, AttackType::FrontRunning);

    let zkevm: Finding = serde_json::from_str(
        r#"{
                "attack_type":"ZkEvm",
                "severity":"medium",
                "description":"zkevm test",
                "location":null,
                "poc_witness_a":[]
            }"#,
    )
    .expect("deserialize ZkEvm finding");
    assert_eq!(zkevm.attack_type, AttackType::ZkEvm);

    let sidechannel: Finding = serde_json::from_str(
        r#"{
                "attack_type":"SidechannelAdvanced",
                "severity":"medium",
                "description":"sidechannel test",
                "location":null,
                "poc_witness_a":[]
            }"#,
    )
    .expect("deserialize SidechannelAdvanced finding");
    assert_eq!(sidechannel.attack_type, AttackType::SidechannelAdvanced);

    let quantum: Finding = serde_json::from_str(
        r#"{
                "attack_type":"QuantumResistance",
                "severity":"high",
                "description":"quantum test",
                "location":null,
                "poc_witness_a":[]
            }"#,
    )
    .expect("deserialize QuantumResistance finding");
    assert_eq!(quantum.attack_type, AttackType::QuantumResistance);

    let privacy: Finding = serde_json::from_str(
        r#"{
                "attack_type":"PrivacyAdvanced",
                "severity":"medium",
                "description":"privacy test",
                "location":null,
                "poc_witness_a":[]
            }"#,
    )
    .expect("deserialize PrivacyAdvanced finding");
    assert_eq!(privacy.attack_type, AttackType::PrivacyAdvanced);

    let defi: Finding = serde_json::from_str(
        r#"{
                "attack_type":"DefiAdvanced",
                "severity":"high",
                "description":"defi test",
                "location":null,
                "poc_witness_a":[]
            }"#,
    )
    .expect("deserialize DefiAdvanced finding");
    assert_eq!(defi.attack_type, AttackType::DefiAdvanced);

    let circom_static: Finding = serde_json::from_str(
        r#"{
                "attack_type":"CircomStaticLint",
                "severity":"high",
                "description":"circom static lint test",
                "location":"sample.circom:10",
                "poc_witness_a":[]
            }"#,
    )
    .expect("deserialize CircomStaticLint finding");
    assert_eq!(circom_static.attack_type, AttackType::CircomStaticLint);
}

#[test]
fn serialize_finding_uses_structured_attack_type_and_class() {
    let finding = make_finding("Invariant violated: output uniqueness", None);
    let value = serde_json::to_value(&finding).expect("serialize finding");
    assert_eq!(
        value.get("attack_type").and_then(|v| v.as_str()),
        Some("underconstrained")
    );
    assert_eq!(
        value.get("class").and_then(|v| v.as_str()),
        Some("invariant_violation")
    );
}

#[test]
fn deserialize_finding_accepts_snake_case_attack_type() {
    let finding: Finding = serde_json::from_str(
        r#"{
                "attack_type":"constraint_inference",
                "severity":"high",
                "description":"constraint inference test",
                "location":null,
                "poc_witness_a":[]
            }"#,
    )
    .expect("deserialize snake_case attack_type");
    assert_eq!(finding.attack_type, AttackType::ConstraintInference);
}
