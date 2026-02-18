
use super::*;

#[test]
fn test_boundary_tester_default() {
    let tester = BoundaryTester::new();
    assert!(tester.test_field_boundaries);
    assert!(tester.test_overflow);
    assert!(!tester.bit_widths.is_empty());
}

#[test]
fn test_generate_field_boundaries() {
    let tester = BoundaryTester::new();
    let values = tester.generate_field_boundaries();

    // Should include 0, 1, p-1, p
    assert!(values.len() >= 4);

    // Check zero is included
    assert!(values.iter().any(|(fe, _, _)| *fe == FieldElement::zero()));

    // Check one is included
    assert!(values.iter().any(|(fe, _, _)| *fe == FieldElement::one()));
}

#[test]
fn test_generate_bit_boundaries() {
    let tester = BoundaryTester::new();
    let values = tester.generate_bit_boundaries(8);

    // Should include 2^8-1=255, 2^8=256, 2^8+1=257, 2^7=128
    assert!(values.len() >= 4);

    // Check 255 is included
    let has_255 = values
        .iter()
        .any(|(fe, _, _)| *fe == FieldElement::from_u64(255));
    assert!(has_255);
}

#[test]
fn test_generate_integer_boundaries() {
    let tester = BoundaryTester::new();
    let values = tester.generate_integer_boundaries();

    // Should have u8, u16, u32, u64 boundaries
    assert!(values.len() >= 4);
}

#[test]
fn test_generate_all_test_values() {
    let tester = BoundaryTester::new().with_bit_widths(vec![8, 16]);

    let values = tester.generate_all_test_values();
    assert!(!values.is_empty());

    // Check we have different categories
    let categories: std::collections::HashSet<_> = values.iter().map(|(_, _, cat)| cat).collect();
    assert!(categories.len() >= 2);
}

#[test]
fn test_range_spec_boundary_values() {
    let range = common_ranges::age_range();
    let values = range.boundary_values();

    // Should include min, max, below min, above max, middle
    assert!(values.len() >= 4);
}

#[test]
fn test_biguint_to_field_element() {
    let small = BigUint::from(42u32);
    let fe = biguint_to_field_element(&small).unwrap();
    assert_eq!(fe, FieldElement::from_u64(42));

    // Test zero
    let zero = BigUint::from(0u32);
    let fe_zero = biguint_to_field_element(&zero).unwrap();
    assert_eq!(fe_zero, FieldElement::zero());
}

#[test]
fn test_check_range_enforcement() {
    let tester = BoundaryTester::new();
    let range = common_ranges::percentage_range(); // 0-100

    // Fixture circuit that only accepts values <= 50
    let accepts = |fe: &FieldElement| {
        let bytes = fe.to_bytes();
        let value = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
        value <= 50
    };

    let vulnerabilities = tester.check_range_enforcement(accepts, &range);

    // Should find vulnerability at max (100) and above max (101)
    // since our fixture only accepts <= 50
    assert!(!vulnerabilities.is_empty());
}

#[test]
fn test_common_ranges() {
    assert_eq!(common_ranges::u8_range().max, BigUint::from(255u32));
    assert_eq!(common_ranges::percentage_range().max, BigUint::from(100u32));
    assert_eq!(common_ranges::age_range().max, BigUint::from(150u32));
}

#[test]
fn test_overflow_values() {
    let tester = BoundaryTester::new().with_overflow_testing(true);
    let values = tester.generate_overflow_values();

    // Should have near-modulus and near-zero values
    assert!(!values.is_empty());

    let has_near_modulus = values
        .iter()
        .any(|(_, _, cat)| *cat == BoundaryCategory::NearModulus);
    let has_near_zero = values
        .iter()
        .any(|(_, _, cat)| *cat == BoundaryCategory::NearZero);

    assert!(has_near_modulus);
    assert!(has_near_zero);
}

#[test]
fn test_sign_boundaries() {
    let tester = BoundaryTester::new().with_sign_boundary_testing(true);
    let values = tester.generate_sign_boundaries();

    // Should have (p-1)/2 and surrounding values
    assert!(values.len() >= 2);
    assert!(values
        .iter()
        .all(|(_, _, cat)| *cat == BoundaryCategory::SignBoundary));
}
