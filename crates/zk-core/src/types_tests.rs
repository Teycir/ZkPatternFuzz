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
