
use super::*;
use std::io::Cursor;

/// Create a minimal valid R1CS binary for testing
fn create_test_r1cs() -> Vec<u8> {
    let mut data = Vec::new();

    // Magic: "r1cs"
    data.extend_from_slice(b"r1cs");

    // Version: 1
    data.extend_from_slice(&1u32.to_le_bytes());

    // Number of sections: 2 (header + constraints)
    data.extend_from_slice(&2u32.to_le_bytes());

    // Section 1: Header (type=1)
    data.extend_from_slice(&1u32.to_le_bytes());
    // Section size (we'll calculate this)
    let header_size = 4 + 32 + 4 * 4 + 8 + 4; // field_bytes + field + counts + labels + num_constraints
    data.extend_from_slice(&(header_size as u64).to_le_bytes());

    // Field bytes: 32
    data.extend_from_slice(&32u32.to_le_bytes());

    // Field modulus (BN254)
    let modulus = BigUint::parse_bytes(BN254_MODULUS.as_bytes(), 10).unwrap();
    let mut mod_bytes = modulus.to_bytes_le();
    mod_bytes.resize(32, 0);
    data.extend_from_slice(&mod_bytes);

    // Wire counts
    data.extend_from_slice(&10u32.to_le_bytes()); // num_wires
    data.extend_from_slice(&1u32.to_le_bytes()); // num_public_outputs
    data.extend_from_slice(&2u32.to_le_bytes()); // num_public_inputs
    data.extend_from_slice(&3u32.to_le_bytes()); // num_private_inputs
    data.extend_from_slice(&10u64.to_le_bytes()); // num_labels
    data.extend_from_slice(&1u32.to_le_bytes()); // num_constraints

    // Section 2: Constraints (type=2)
    data.extend_from_slice(&2u32.to_le_bytes());

    // One simple constraint: wire_1 * wire_2 = wire_3
    // A: 1 term (wire_1, coeff=1)
    // B: 1 term (wire_2, coeff=1)
    // C: 1 term (wire_3, coeff=1)
    let constraint_size = (4 + 4 + 32) * 3; // 3 linear combinations, each with 1 term
    data.extend_from_slice(&(constraint_size as u64).to_le_bytes());

    // A: wire_1 * 1
    data.extend_from_slice(&1u32.to_le_bytes()); // num_terms
    data.extend_from_slice(&1u32.to_le_bytes()); // wire_idx
    let mut one = [0u8; 32];
    one[0] = 1;
    data.extend_from_slice(&one);

    // B: wire_2 * 1
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&one);

    // C: wire_3 * 1
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&one);

    data
}

#[test]
fn test_parse_r1cs_binary() {
    let data = create_test_r1cs();
    let mut cursor = Cursor::new(data);

    let r1cs = R1CS::parse(&mut cursor).expect("Should parse test R1CS");

    assert_eq!(r1cs.num_wires, 10);
    assert_eq!(r1cs.num_public_inputs, 2);
    assert_eq!(r1cs.num_private_inputs, 3);
    assert_eq!(r1cs.num_public_outputs, 1);
    assert_eq!(r1cs.constraints.len(), 1);

    // Check constraint structure
    let c = &r1cs.constraints[0];
    assert_eq!(c.a.len(), 1);
    assert_eq!(c.b.len(), 1);
    assert_eq!(c.c.len(), 1);
    assert_eq!(c.a[0].0, 1); // wire_1
    assert_eq!(c.b[0].0, 2); // wire_2
    assert_eq!(c.c[0].0, 3); // wire_3
}

#[test]
fn test_input_wire_indices() {
    let data = create_test_r1cs();
    let mut cursor = Cursor::new(data);
    let r1cs = R1CS::parse(&mut cursor).unwrap();

    let input_indices = r1cs.input_wire_indices();
    // Should be 1..=6 (1 public output + 2 public inputs + 3 private inputs)
    assert_eq!(input_indices, vec![1, 2, 3, 4, 5, 6]);

    let public_indices = r1cs.public_input_indices();
    assert_eq!(public_indices, vec![2, 3]); // After public output

    let private_indices = r1cs.private_input_indices();
    assert_eq!(private_indices, vec![4, 5, 6]);
}

#[test]
fn test_constraint_to_extended() {
    let constraint = R1CSConstraint {
        a: vec![(1, BigUint::from(1u32))],
        b: vec![(2, BigUint::from(1u32))],
        c: vec![(3, BigUint::from(1u32))],
    };

    let extended = constraint.to_extended();

    // Should be an R1CS constraint
    match extended {
        crate::ExtendedConstraint::R1CS(_) => (),
        _ => panic!("Expected R1CS constraint"),
    }
}

#[test]
fn test_biguint_to_field_element_endianness() {
    let one = BigUint::from(1u32);
    let fe = biguint_to_field_element(&one);
    assert_eq!(fe, FieldElement::from_u64(1));
}

#[test]
fn test_generate_smt_inputs_simple_r1cs() {
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

    let r1cs = R1CS {
        field_size: modulus.clone(),
        field_bytes: 32,
        num_wires: 3,
        num_public_outputs: 0,
        num_public_inputs: 1,
        num_private_inputs: 1,
        num_labels: 0,
        constraints: vec![c1, c2, c3],
        wire_names: Vec::new(),
        custom_gates_used: false,
    };

    let solutions = crate::r1cs_to_smt::generate_constraint_guided_inputs(&r1cs, 2, 2000);
    assert!(!solutions.is_empty(), "Expected at least one solution");

    fn eval_lc(terms: &[(usize, BigUint)], wires: &[BigUint], modulus: &BigUint) -> BigUint {
        let mut acc = BigUint::from(0u32);
        for (idx, coeff) in terms {
            let value = match wires.get(*idx).cloned() {
                Some(v) => v,
                None => panic!(
                    "Wire index {} out of bounds in test linear combination",
                    idx
                ),
            };
            let term = (coeff * value) % modulus;
            acc = (acc + term) % modulus;
        }
        acc
    }

    for inputs in solutions {
        assert_eq!(inputs.len(), 2);

        let mut wires = vec![BigUint::from(1u32); r1cs.num_wires];
        wires[1] = inputs[0].to_biguint();
        wires[2] = inputs[1].to_biguint();

        for constraint in &r1cs.constraints {
            let a = eval_lc(&constraint.a, &wires, &modulus);
            let b = eval_lc(&constraint.b, &wires, &modulus);
            let c = eval_lc(&constraint.c, &wires, &modulus);
            let lhs = (a * b) % &modulus;
            assert_eq!(lhs, c, "Generated inputs should satisfy constraints");
        }
    }
}

#[test]
fn test_invalid_magic() {
    let mut data = create_test_r1cs();
    data[0] = b'x'; // Corrupt magic

    let mut cursor = Cursor::new(data);
    let result = R1CS::parse(&mut cursor);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("bad magic"));
}
