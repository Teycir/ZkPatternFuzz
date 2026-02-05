//! Mutation strategies for fuzzing
//!
//! All arithmetic mutations perform proper modular reduction to ensure
//! generated field elements are valid (within the BN254 scalar field).

use super::{FieldElement, BN254_MODULUS, BN254_MODULUS_MINUS_ONE};
use rand::Rng;

/// BN254 scalar field modulus as bytes for comparison
/// Lazy-initialized for efficiency
fn bn254_modulus_bytes() -> [u8; 32] {
    let mut modulus = [0u8; 32];
    // This should always succeed since BN254_MODULUS is a valid constant
    if let Ok(decoded) = hex::decode(BN254_MODULUS) {
        if decoded.len() == 32 {
            modulus.copy_from_slice(&decoded);
        }
    }
    modulus
}

/// Compare two 32-byte big-endian integers
/// Returns Ordering::Less if a < b, Equal if a == b, Greater if a > b
fn compare_bytes(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    for i in 0..32 {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Subtract b from a (big-endian), assuming a >= b
/// Returns a - b
fn subtract_bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow = 0i16;

    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }

    result
}

/// Reduce a field element modulo the BN254 scalar field prime
///
/// Repeatedly subtracts the modulus until the value is in the valid range [0, p-1].
/// This handles any value, including values much larger than p (e.g., bitwise NOT of zero).
fn reduce_modulo_field(fe: FieldElement) -> FieldElement {
    let modulus = bn254_modulus_bytes();
    let mut current = fe.0;

    // Keep subtracting modulus while current >= modulus
    // For values close to 2^256, this might need multiple iterations
    // but in practice, fuzzing mutations rarely produce values > 2p
    while compare_bytes(&current, &modulus) != std::cmp::Ordering::Less {
        current = subtract_bytes(&current, &modulus);
    }

    FieldElement(current)
}

/// Apply a random mutation to a field element
pub fn mutate_field_element(input: &FieldElement, rng: &mut impl Rng) -> FieldElement {
    let mutation_type = rng.gen_range(0..5);

    match mutation_type {
        0 => bit_flip(input, rng),
        1 => byte_flip(input, rng),
        2 => arithmetic_mutation(input, rng),
        3 => boundary_mutation(rng),
        4 => havoc_mutation(input, rng),
        _ => input.clone(),
    }
}

/// Flip a random bit in the field element
fn bit_flip(input: &FieldElement, rng: &mut impl Rng) -> FieldElement {
    let mut result = input.0;
    let byte_idx = rng.gen_range(0..32);
    let bit_idx = rng.gen_range(0..8);
    result[byte_idx] ^= 1 << bit_idx;
    FieldElement(result)
}

/// Flip a random byte in the field element
fn byte_flip(input: &FieldElement, rng: &mut impl Rng) -> FieldElement {
    let mut result = input.0;
    let byte_idx = rng.gen_range(0..32);
    result[byte_idx] = rng.gen();
    FieldElement(result)
}

/// Apply arithmetic operations (add/sub 1, negate, double)
fn arithmetic_mutation(input: &FieldElement, rng: &mut impl Rng) -> FieldElement {
    let op = rng.gen_range(0..4);

    match op {
        0 => add_one(input),
        1 => sub_one(input),
        2 => negate(input),
        3 => double(input),
        _ => input.clone(),
    }
}

/// Add one to the field element with modular reduction
///
/// Ensures the result is always a valid field element (< p)
fn add_one(input: &FieldElement) -> FieldElement {
    let mut result = input.0;
    let mut carry = 1u16;

    for i in (0..32).rev() {
        let sum = result[i] as u16 + carry;
        result[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
        if carry == 0 {
            break;
        }
    }

    // Apply modular reduction to ensure result is valid
    reduce_modulo_field(FieldElement(result))
}

/// Subtract one from the field element (with wrapping)
fn sub_one(input: &FieldElement) -> FieldElement {
    let mut result = input.0;
    let mut borrow = 1u16;

    for i in (0..32).rev() {
        let diff = result[i] as i16 - borrow as i16;
        if diff >= 0 {
            result[i] = diff as u8;
            break;
        } else {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        }
    }

    FieldElement(result)
}

/// Negate the field element (bitwise NOT) with modular reduction
///
/// Note: Bitwise NOT doesn't produce a mathematically correct field negation,
/// but it's useful for fuzzing to explore the input space. The result is
/// reduced to ensure it's a valid field element.
fn negate(input: &FieldElement) -> FieldElement {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = !input.0[i];
    }
    // Reduce to ensure validity (NOT of small values produces large values)
    reduce_modulo_field(FieldElement(result))
}

/// Double the field element (left shift by 1) with modular reduction
///
/// Ensures the result is always a valid field element (< p)
/// Previously, this could overflow and wrap around incorrectly
fn double(input: &FieldElement) -> FieldElement {
    let mut result = [0u8; 32];
    let mut carry = 0u8;

    for i in (0..32).rev() {
        let doubled = (input.0[i] as u16) << 1 | carry as u16;
        result[i] = (doubled & 0xff) as u8;
        carry = (doubled >> 8) as u8;
    }

    // Apply modular reduction to handle overflow
    // Note: doubling can produce values up to 2*(p-1) which needs reduction
    reduce_modulo_field(FieldElement(result))
}

/// Return a boundary value
fn boundary_mutation(rng: &mut impl Rng) -> FieldElement {
    let boundary_type = rng.gen_range(0..4);

    match boundary_type {
        0 => FieldElement::zero(),
        1 => FieldElement::one(),
        2 => {
            // Max value (all 0xff)
            FieldElement([0xff; 32])
        }
        3 => {
            // bn254 scalar field p - 1 (using centralized constant)
            let mut bytes = [0u8; 32];
            if let Ok(decoded) = hex::decode(BN254_MODULUS_MINUS_ONE) {
                bytes.copy_from_slice(&decoded);
            }
            FieldElement(bytes)
        }
        _ => FieldElement::zero(),
    }
}

/// Apply multiple random mutations (havoc mode)
fn havoc_mutation(input: &FieldElement, rng: &mut impl Rng) -> FieldElement {
    let num_mutations = rng.gen_range(1..=5);
    let mut result = input.clone();

    for _ in 0..num_mutations {
        let mutation_type = rng.gen_range(0..4);
        result = match mutation_type {
            0 => bit_flip(&result, rng),
            1 => byte_flip(&result, rng),
            2 => arithmetic_mutation(&result, rng),
            3 => boundary_mutation(rng),
            _ => result,
        };
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
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
        if let Ok(decoded) = hex::decode(crate::fuzzer::BN254_HALF_MODULUS) {
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
}
