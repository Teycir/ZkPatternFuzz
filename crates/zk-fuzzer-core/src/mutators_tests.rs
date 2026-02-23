use super::*;
use crate::constants::{bn254_modulus_minus_one_bytes, BN254_HALF_MODULUS};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::cmp::Ordering;

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
fn test_sub_one_wraps_zero_to_p_minus_one() {
    let input = FieldElement::zero();
    let result = sub_one(&input);
    assert_eq!(result, FieldElement::max_value());
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
fn test_bit_flip_reduces_to_valid_field() {
    let mut rng = StdRng::seed_from_u64(7);
    let input = FieldElement::max_value();
    let result = bit_flip(&input, &mut rng);
    let modulus = bn254_modulus_bytes();
    assert!(compare_bytes(&result.0, &modulus) == std::cmp::Ordering::Less);
}

#[test]
fn test_byte_flip_reduces_to_valid_field() {
    let mut rng = StdRng::seed_from_u64(11);
    let input = FieldElement::max_value();
    let result = byte_flip(&input, &mut rng);
    let modulus = bn254_modulus_bytes();
    assert!(compare_bytes(&result.0, &modulus) == std::cmp::Ordering::Less);
}

#[test]
fn test_field_negate_uses_true_field_negation() {
    let input = FieldElement::from_u64(5);
    let result = field_negate(&input);
    assert_eq!(result, input.neg());
}

#[test]
fn test_bitwise_not_mutation_reduces_to_valid_field() {
    // Bitwise NOT of zero is 0xff..ff and must be reduced into the field.
    let input = FieldElement::zero();
    let result = bitwise_not_mutation(&input);
    let modulus = bn254_modulus_bytes();
    assert!(compare_bytes(&result.0, &modulus) == std::cmp::Ordering::Less);
}

#[test]
fn test_add_one_with_overflow_reduces() {
    // Start with p-1 (maximum valid field element)
    let p_minus_one = bn254_modulus_minus_one_bytes();
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

#[test]
fn test_boundary_mutation_values_are_in_field() {
    let mut rng = StdRng::seed_from_u64(123);
    let modulus = bn254_modulus_bytes();

    for _ in 0..10_000 {
        let value = boundary_mutation(&mut rng);
        assert_eq!(
            compare_bytes(&value.0, &modulus),
            Ordering::Less,
            "boundary mutation produced out-of-field value"
        );
    }
}

#[test]
fn test_mutate_field_element_stress_summary() {
    let mut rng = StdRng::seed_from_u64(0x5EED);
    let modulus = bn254_modulus_bytes();

    let mut seed_inputs = vec![
        FieldElement::zero(),
        FieldElement::one(),
        FieldElement::max_value(),
        FieldElement::half_modulus(),
    ];
    for _ in 0..64 {
        seed_inputs.push(FieldElement::random(&mut rng));
    }

    let rounds_per_seed = 1_000usize;
    let mut invalid = 0usize;
    let mut total = 0usize;

    for seed in &seed_inputs {
        let mut current = seed.clone();
        for _ in 0..rounds_per_seed {
            current = mutate_field_element(&current, &mut rng);
            total += 1;
            if compare_bytes(&current.0, &modulus) != Ordering::Less {
                invalid += 1;
            }
        }
    }

    let invalid_rate = invalid as f64 / total as f64;
    println!(
        "mutator_stress_summary total={} invalid={} invalid_rate={:.9}",
        total, invalid, invalid_rate
    );

    assert_eq!(
        invalid, 0,
        "mutator stress produced {} out-of-field values out of {}",
        invalid, total
    );
}
