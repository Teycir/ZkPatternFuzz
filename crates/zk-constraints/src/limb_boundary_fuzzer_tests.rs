use super::*;
use crate::constraint_types::{ExtendedConstraint, LinearCombination, R1CSConstraint, WireRef};
use crate::limb_analysis::detect_limb_decomposition;
use std::collections::HashMap;

fn make_relation() -> Vec<ExtendedConstraint> {
    let mut sum = LinearCombination::new();
    sum.add_term(WireRef::named(10, "limb0"), FieldElement::one());
    sum.add_term(WireRef::named(11, "limb1"), FieldElement::from_u64(1 << 16));
    let mut out = LinearCombination::new();
    out.add_term(WireRef::named(12, "packed"), FieldElement::one());

    vec![
        ExtendedConstraint::Range(crate::constraint_types::RangeConstraint {
            wire: WireRef::named(10, "limb0"),
            bits: 16,
            method: crate::constraint_types::RangeMethod::Plookup,
        }),
        ExtendedConstraint::Range(crate::constraint_types::RangeConstraint {
            wire: WireRef::named(11, "limb1"),
            bits: 16,
            method: crate::constraint_types::RangeMethod::Plookup,
        }),
        ExtendedConstraint::R1CS(R1CSConstraint {
            a: LinearCombination::constant(FieldElement::one()),
            b: sum,
            c: out,
        }),
    ]
}

#[test]
fn test_generates_individual_limb_boundaries() {
    let analysis = detect_limb_decomposition(&make_relation());
    let fuzzer = LimbBoundaryFuzzer::new();
    let cases = fuzzer.generate_cases(&analysis);

    assert!(cases.iter().any(|c| {
        c.kind == LimbBoundaryCaseKind::LimbZero
            && c.target_wire == Some(10)
            && c.assignments.get(&10).map(FieldElement::is_zero) == Some(true)
    }));
    assert!(cases.iter().any(|c| {
        c.kind == LimbBoundaryCaseKind::LimbMax
            && c.target_wire == Some(10)
            && c.assignments.get(&10) == Some(&FieldElement::from_u64((1 << 16) - 1))
    }));
    assert!(cases.iter().any(|c| {
        c.kind == LimbBoundaryCaseKind::LimbOverflow
            && c.target_wire == Some(10)
            && c.assignments.get(&10) == Some(&FieldElement::from_u64(1 << 16))
    }));
}

#[test]
fn test_generates_sum_overflow_candidate_with_custom_modulus() {
    let analysis = detect_limb_decomposition(&make_relation());

    // Force overflow-positive sum cases for this small synthetic relation.
    let config = LimbBoundaryFuzzerConfig {
        field_modulus: num_bigint::BigUint::from(1000u64),
        ..LimbBoundaryFuzzerConfig::default()
    };
    let fuzzer = LimbBoundaryFuzzer::with_config(config);
    let cases = fuzzer.generate_cases(&analysis);

    let sum_case = cases
        .iter()
        .find(|c| c.kind == LimbBoundaryCaseKind::SumOverflow)
        .expect("sum-overflow case should be generated");

    assert!(sum_case.expected_sum_overflow);
    assert_eq!(sum_case.relation_constraint_index, Some(2));
}

#[test]
fn test_generates_carry_propagation_edges() {
    let analysis = detect_limb_decomposition(&make_relation());
    let fuzzer = LimbBoundaryFuzzer::new();
    let cases = fuzzer.generate_cases(&analysis);

    assert!(cases.iter().any(|c| {
        c.kind == LimbBoundaryCaseKind::CarryPropagation
            && c.relation_constraint_index == Some(2)
            && c.assignments.get(&10) == Some(&FieldElement::from_u64((1 << 16) - 1))
            && c.assignments.get(&11) == Some(&FieldElement::one())
    }));
    assert!(cases.iter().any(|c| {
        c.kind == LimbBoundaryCaseKind::CarryPropagation
            && c.relation_constraint_index == Some(2)
            && c.assignments.get(&10) == Some(&FieldElement::from_u64(1 << 16))
    }));
}

#[test]
fn test_respects_generation_toggles() {
    let analysis = detect_limb_decomposition(&make_relation());
    let config = LimbBoundaryFuzzerConfig {
        fuzz_individual_boundaries: false,
        fuzz_sum_overflow: true,
        fuzz_carry_edges: false,
        ..LimbBoundaryFuzzerConfig::default()
    };
    let fuzzer = LimbBoundaryFuzzer::with_config(config);
    let baseline = HashMap::from([(99usize, FieldElement::from_u64(7))]);
    let cases = fuzzer.generate_cases_with_baseline(&analysis, &baseline);

    assert!(cases
        .iter()
        .all(|case| case.kind == LimbBoundaryCaseKind::SumOverflow));
    assert!(cases.iter().all(|case| case.assignments.contains_key(&99)));
}
