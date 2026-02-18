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
fn deserialize_finding_supports_phase3_attack_variants() {
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
}
