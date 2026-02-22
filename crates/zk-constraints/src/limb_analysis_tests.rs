use super::*;
use crate::constraint_types::{R1CSConstraint, RangeConstraint, RangeMethod};
use std::collections::HashMap;

fn lc_constant_one() -> LinearCombination {
    LinearCombination::constant(FieldElement::one())
}

fn lc_single(wire: WireRef, coeff: FieldElement) -> LinearCombination {
    let mut lc = LinearCombination::new();
    lc.add_term(wire, coeff);
    lc
}

#[test]
fn test_detects_limb_candidates_from_name_and_bit_width() {
    let constraints = vec![
        ExtendedConstraint::Range(RangeConstraint {
            wire: WireRef::named(1, "sig_limb0"),
            bits: 64,
            method: RangeMethod::Plookup,
        }),
        ExtendedConstraint::Range(RangeConstraint {
            wire: WireRef::new(2),
            bits: 64,
            method: RangeMethod::Plookup,
        }),
        ExtendedConstraint::AcirOpcode(AcirOpcode::Range {
            input: WireRef::named(3, "chunk1"),
            bits: 32,
        }),
        ExtendedConstraint::AcirOpcode(AcirOpcode::BlackBox(BlackBoxOp::Range {
            input: WireRef::named(4, "flag"),
            bits: 1,
        })),
    ];

    let report = detect_limb_decomposition(&constraints);

    assert!(report.limb_by_wire(1).is_some());
    assert!(report.limb_by_wire(2).is_some());
    assert!(report.limb_by_wire(3).is_some());
    assert!(report.limb_by_wire(4).is_none());
    assert_eq!(report.wire_bit_widths.get(&1), Some(&64usize));
    assert_eq!(report.wire_bit_widths.get(&4), Some(&1usize));
}

#[test]
fn test_detects_reconstruction_from_power_of_two_sum() {
    let constraints = vec![
        ExtendedConstraint::Range(RangeConstraint {
            wire: WireRef::named(10, "limb0"),
            bits: 16,
            method: RangeMethod::Plookup,
        }),
        ExtendedConstraint::Range(RangeConstraint {
            wire: WireRef::named(11, "limb1"),
            bits: 16,
            method: RangeMethod::Plookup,
        }),
        ExtendedConstraint::R1CS(R1CSConstraint {
            a: lc_constant_one(),
            b: {
                let mut lc = LinearCombination::new();
                lc.add_term(WireRef::named(10, "limb0"), FieldElement::one());
                lc.add_term(WireRef::named(11, "limb1"), FieldElement::from_u64(1 << 16));
                lc
            },
            c: lc_single(WireRef::named(12, "packed"), FieldElement::one()),
        }),
    ];

    let report = detect_limb_decomposition(&constraints);
    assert_eq!(report.reconstructions.len(), 1);

    let reconstruction = &report.reconstructions[0];
    assert_eq!(reconstruction.full_value_wire.index, 12);
    assert_eq!(reconstruction.limb_terms.len(), 2);
    assert_eq!(reconstruction.limb_terms[0].wire.index, 10);
    assert_eq!(reconstruction.limb_terms[0].shift_bits, Some(0));
    assert_eq!(reconstruction.limb_terms[1].wire.index, 11);
    assert_eq!(reconstruction.limb_terms[1].shift_bits, Some(16));
    assert!(reconstruction.confidence >= 0.7);
}

#[test]
fn test_skips_reconstruction_when_coefficients_are_not_power_of_two() {
    let constraints = vec![
        ExtendedConstraint::Range(RangeConstraint {
            wire: WireRef::named(20, "limb0"),
            bits: 16,
            method: RangeMethod::Plookup,
        }),
        ExtendedConstraint::Range(RangeConstraint {
            wire: WireRef::named(21, "limb1"),
            bits: 16,
            method: RangeMethod::Plookup,
        }),
        ExtendedConstraint::R1CS(R1CSConstraint {
            a: lc_constant_one(),
            b: {
                let mut lc = LinearCombination::new();
                lc.add_term(WireRef::named(20, "limb0"), FieldElement::one());
                lc.add_term(WireRef::named(21, "limb1"), FieldElement::from_u64(3));
                lc
            },
            c: lc_single(WireRef::named(22, "packed"), FieldElement::one()),
        }),
    ];

    let report = detect_limb_decomposition(&constraints);
    assert!(report.reconstructions.is_empty());
}

#[test]
fn test_external_wire_names_can_seed_detection() {
    let constraints = vec![ExtendedConstraint::Add {
        a: WireRef::new(30),
        b: WireRef::new(31),
        c: WireRef::new(32),
    }];
    let mut names = HashMap::new();
    names.insert(30usize, "state_limb_0".to_string());

    let analyzer = LimbAnalyzer::new();
    let report = analyzer.analyze_with_wire_names(&constraints, &names);

    assert!(report.limb_by_wire(30).is_some());
}
