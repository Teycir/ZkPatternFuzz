//! Mutation strategies for fuzzing
//!
//! All arithmetic mutations perform proper modular reduction to ensure
//! generated field elements are valid (within the BN254 scalar field).

use crate::constants::{bn254_modulus_bytes, bn254_modulus_minus_one_bytes};
use rand::Rng;
use zk_core::constants::bn254_modulus_biguint;
use zk_core::FieldElement;

/// Compare two 32-byte big-endian integers
/// Returns Ordering::Less if a < b, Equal if a == b, Greater if a > b
fn compare_bytes(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    for (a_byte, b_byte) in a.iter().zip(b.iter()) {
        match a_byte.cmp(b_byte) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Reduce a field element modulo the BN254 scalar field prime
///
/// Uses BigUint modulo for bounded and predictable runtime even when
/// values are far above the modulus (e.g. bitwise-not mutations).
fn reduce_modulo_field(fe: FieldElement) -> FieldElement {
    let modulus = bn254_modulus_bytes();
    if compare_bytes(&fe.0, &modulus) == std::cmp::Ordering::Less {
        return fe;
    }
    let reduced = fe.to_biguint() % bn254_modulus_biguint();
    FieldElement::from_bytes(&reduced.to_bytes_be())
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
    reduce_modulo_field(FieldElement(result))
}

/// Flip a random byte in the field element
fn byte_flip(input: &FieldElement, rng: &mut impl Rng) -> FieldElement {
    let mut result = input.0;
    let byte_idx = rng.gen_range(0..32);
    result[byte_idx] = rng.gen();
    reduce_modulo_field(FieldElement(result))
}

/// Apply arithmetic operations (add/sub 1, field-negate, double, bitwise-not)
fn arithmetic_mutation(input: &FieldElement, rng: &mut impl Rng) -> FieldElement {
    let op = rng.gen_range(0..5);

    match op {
        0 => add_one(input),
        1 => sub_one(input),
        2 => field_negate(input),
        3 => double(input),
        4 => bitwise_not_mutation(input),
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
    // In field arithmetic, 0 - 1 wraps to p - 1.
    if input.is_zero() {
        return FieldElement::max_value();
    }

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

    reduce_modulo_field(FieldElement(result))
}

/// Negate the field element using true field arithmetic: -x mod p.
fn field_negate(input: &FieldElement) -> FieldElement {
    input.neg()
}

/// Bitwise inversion mutation (kept separate from field negation semantics).
fn bitwise_not_mutation(input: &FieldElement) -> FieldElement {
    let mut result = [0u8; 32];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = !input.0[i];
    }
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
            // Highest 256-bit value reduced into field domain.
            reduce_modulo_field(FieldElement([0xff; 32]))
        }
        3 => {
            // bn254 scalar field p - 1 (using centralized constant bytes)
            FieldElement(bn254_modulus_minus_one_bytes())
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
#[path = "mutators_tests.rs"]
mod tests;
