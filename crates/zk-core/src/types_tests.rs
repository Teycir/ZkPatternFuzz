use super::*;

fn make_finding(description: &str, witness_b: Option<Vec<FieldElement>>) -> Finding {
    Finding {
        attack_type: AttackType::Underconstrained,
        severity: Severity::High,
        description: description.to_string(),
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
}
