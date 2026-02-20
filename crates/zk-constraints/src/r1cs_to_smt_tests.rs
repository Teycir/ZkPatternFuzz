use super::*;
use num_bigint::BigUint;

fn build_simple_r1cs() -> R1CS {
    let modulus = BigUint::parse_bytes(BN254_MODULUS.as_bytes(), 10).unwrap();

    let c1 = R1CSConstraint {
        // x * 1 = 2
        a: vec![(1, BigUint::from(1u32))],
        b: vec![(0, BigUint::from(1u32))],
        c: vec![(0, BigUint::from(2u32))],
    };

    let c2 = R1CSConstraint {
        // y * 1 = 3
        a: vec![(2, BigUint::from(1u32))],
        b: vec![(0, BigUint::from(1u32))],
        c: vec![(0, BigUint::from(3u32))],
    };

    let c3 = R1CSConstraint {
        // (x + y) * 1 = 5
        a: vec![(1, BigUint::from(1u32)), (2, BigUint::from(1u32))],
        b: vec![(0, BigUint::from(1u32))],
        c: vec![(0, BigUint::from(5u32))],
    };

    R1CS {
        field_size: modulus,
        field_bytes: 32,
        num_wires: 3,
        num_public_outputs: 0,
        num_public_inputs: 1,
        num_private_inputs: 1,
        num_labels: 0,
        constraints: vec![c1, c2, c3],
        wire_names: Vec::new(),
        custom_gates_used: false,
    }
}

fn eval_lc(terms: &[(usize, BigUint)], wires: &[BigUint], modulus: &BigUint) -> BigUint {
    let mut acc = BigUint::from(0u32);
    for (idx, coeff) in terms {
        let value = match wires.get(*idx).cloned() {
            Some(v) => v,
            None => panic!("Wire index {} out of bounds in linear combination", idx),
        };
        let term = (coeff * value) % modulus;
        acc = (acc + term) % modulus;
    }
    acc
}

fn satisfies_constraints(r1cs: &R1CS, inputs: &[FieldElement]) -> bool {
    let modulus = &r1cs.field_size;
    let mut wires = vec![BigUint::from(1u32); r1cs.num_wires];

    if let Some(first) = inputs.first() {
        wires[1] = first.to_biguint();
    }
    if let Some(second) = inputs.get(1) {
        wires[2] = second.to_biguint();
    }

    for constraint in &r1cs.constraints {
        let a = eval_lc(&constraint.a, &wires, modulus);
        let b = eval_lc(&constraint.b, &wires, modulus);
        let c = eval_lc(&constraint.c, &wires, modulus);
        let lhs = (a * b) % modulus;
        if lhs != c {
            return false;
        }
    }

    true
}

#[test]
fn test_generate_constraint_guided_inputs() {
    let r1cs = build_simple_r1cs();
    let solutions = generate_constraint_guided_inputs(&r1cs, 3, 2000);

    assert!(!solutions.is_empty(), "Expected at least one solution");

    for inputs in &solutions {
        assert_eq!(inputs.len(), 2, "Expected 2 inputs (public + private)");
        assert!(
            satisfies_constraints(&r1cs, inputs),
            "Generated inputs should satisfy constraints"
        );
    }
}
