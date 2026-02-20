use super::*;
use crate::constants::BN254_HALF_MODULUS;
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn test_add_one() {
    let input = FieldElement::zero();
    let result = add_one(&input);
    assert_eq!(result, FieldElement::one());
}

#[test]
fn test_sub_one() {
    let input = FieldElement::one();
    let result = sub_one(&input);
    assert_eq!(result, FieldElement::zero());
}

#[test]
fn test_bit_flip() {
    let mut rng = StdRng::seed_from_u64(42);
    let input = FieldElement::zero();
    let result = bit_flip(&input, &mut rng);
    // Should have exactly one bit different
    let diff_count: u32 = input
        .0
        .iter()
        .zip(result.0.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum();
    assert_eq!(diff_count, 1);
}

#[test]
fn test_negate_reduces_to_valid_field() {
    // Negating zero gives all 0xff bytes, which exceeds the modulus
    // After reduction, it should be less than the modulus
    let input = FieldElement::zero();
    let result = negate(&input);
    let modulus = bn254_modulus_bytes();
    // Result should be less than modulus (properly reduced)
    assert!(compare_bytes(&result.0, &modulus) == std::cmp::Ordering::Less);
}

#[test]
fn test_add_one_with_overflow_reduces() {
    // Start with p-1 (maximum valid field element)
    let mut p_minus_one = [0u8; 32];
    if let Ok(decoded) = hex::decode(BN254_MODULUS_MINUS_ONE) {
        p_minus_one.copy_from_slice(&decoded);
    }
    let input = FieldElement(p_minus_one);

    // Adding 1 to p-1 gives p, which should reduce to 0
    let result = add_one(&input);
    assert_eq!(result, FieldElement::zero());
}

#[test]
fn test_double_with_overflow_reduces() {
    // Start with a value that when doubled exceeds the modulus
    // Half of modulus + 1, when doubled, will exceed modulus
    let mut half_plus = [0u8; 32];
    if let Ok(decoded) = hex::decode(BN254_HALF_MODULUS) {
        half_plus.copy_from_slice(&decoded);
    }
    // Add 1 to make it slightly more than half
    half_plus[31] = half_plus[31].wrapping_add(1);

    let input = FieldElement(half_plus);
    let result = double(&input);

    // Result should be properly reduced (less than modulus)
    let modulus = bn254_modulus_bytes();
    assert!(compare_bytes(&result.0, &modulus) == std::cmp::Ordering::Less);
}

#[test]
fn test_modular_reduction() {
    // Value exactly at modulus should reduce to 0
    let modulus = bn254_modulus_bytes();
    let result = reduce_modulo_field(FieldElement(modulus));
    assert_eq!(result, FieldElement::zero());
}

#[test]
fn test_value_below_modulus_unchanged() {
    // Values below modulus should not be changed
    let input = FieldElement::from_u64(12345);
    let result = reduce_modulo_field(input.clone());
    assert_eq!(result, input);
}
