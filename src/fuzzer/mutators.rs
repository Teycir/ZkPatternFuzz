//! Mutation strategies for fuzzing

use super::FieldElement;
use rand::Rng;

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

/// Add one to the field element (with wrapping)
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

    FieldElement(result)
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

/// Negate the field element (bitwise NOT)
fn negate(input: &FieldElement) -> FieldElement {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = !input.0[i];
    }
    FieldElement(result)
}

/// Double the field element (left shift by 1)
fn double(input: &FieldElement) -> FieldElement {
    let mut result = [0u8; 32];
    let mut carry = 0u8;

    for i in (0..32).rev() {
        let doubled = (input.0[i] as u16) << 1 | carry as u16;
        result[i] = (doubled & 0xff) as u8;
        carry = (doubled >> 8) as u8;
    }

    FieldElement(result)
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
            // bn254 scalar field p - 1
            let mut bytes = [0u8; 32];
            let hex = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
            if let Ok(decoded) = hex::decode(hex) {
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
    use rand::SeedableRng;
    use rand::rngs::StdRng;

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
    fn test_negate() {
        let input = FieldElement::zero();
        let result = negate(&input);
        assert_eq!(result.0, [0xff; 32]);
    }
}
