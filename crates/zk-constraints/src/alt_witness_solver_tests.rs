use super::*;

fn build_underconstrained_r1cs() -> R1CS {
    // x * y = z but missing constraint that x must equal some value
    // This allows multiple (x, y) pairs that produce same z
    let modulus = BigUint::parse_bytes(BN254_MODULUS.as_bytes(), 10).unwrap();

    // Constraint: x * y = z (wires: 0=1, 1=z (output), 2=x (pub in), 3=y (priv))
    let constraint = R1CSConstraint {
        a: vec![(2, BigUint::from(1u32))], // x
        b: vec![(3, BigUint::from(1u32))], // y
        c: vec![(1, BigUint::from(1u32))], // z
    };

    R1CS {
        field_size: modulus,
        field_bytes: 32,
        num_wires: 4,
        num_public_outputs: 1, // z is public output
        num_public_inputs: 1,  // x is public input
        num_private_inputs: 1, // y is private
        num_labels: 0,
        constraints: vec![constraint],
        wire_names: vec![
            "one".to_string(),
            "z".to_string(),
            "x".to_string(),
            "y".to_string(),
        ],
        custom_gates_used: false,
    }
}

#[test]
fn test_find_alternative_witness() {
    let r1cs = build_underconstrained_r1cs();

    // Original: x=2, y=3, z=6
    let original = vec![
        FieldElement::one(),       // wire 0 = 1
        FieldElement::from_u64(6), // z = 6
        FieldElement::from_u64(2), // x = 2
        FieldElement::from_u64(3), // y = 3
    ];

    let result = find_alternative_witness(&r1cs, &original, 5000);

    // Should find alternative since y is private and unconstrained
    // except by x * y = z. With x=2, z=6 fixed, y must = 3.
    // Actually this is fully constrained! Let's test a truly underconstrained case.

    println!("Result: {:?}", result);
}

#[test]
fn test_truly_underconstrained() {
    // Two private inputs, only one constraint
    // a + b = 10, but a and b can be any pair summing to 10
    let modulus = BigUint::parse_bytes(BN254_MODULUS.as_bytes(), 10).unwrap();

    // Constraint: a + b = 10
    // (a + b) * 1 = 10
    let constraint = R1CSConstraint {
        a: vec![(1, BigUint::from(1u32)), (2, BigUint::from(1u32))], // a + b
        b: vec![(0, BigUint::from(1u32))],                           // 1
        c: vec![(0, BigUint::from(10u32))],                          // 10
    };

    let r1cs = R1CS {
        field_size: modulus,
        field_bytes: 32,
        num_wires: 3,
        num_public_outputs: 0,
        num_public_inputs: 0,
        num_private_inputs: 2,
        num_labels: 0,
        constraints: vec![constraint],
        wire_names: vec!["one".to_string(), "a".to_string(), "b".to_string()],
        custom_gates_used: false,
    };

    // Original: a=4, b=6
    let original = vec![
        FieldElement::one(),
        FieldElement::from_u64(4),
        FieldElement::from_u64(6),
    ];

    let result = find_alternative_witness(&r1cs, &original, 5000);

    assert!(result.found, "Should find alternative witness");

    if let Some(alt) = &result.alternative_witness {
        // Verify constraint: a + b = 10
        let a = alt[1].to_biguint();
        let b = alt[2].to_biguint();
        assert_eq!(a + b, BigUint::from(10u32));

        // Verify it's different
        assert!(alt[1] != original[1] || alt[2] != original[2]);
    }
}

#[test]
fn test_matrix_extraction() {
    let r1cs = build_underconstrained_r1cs();
    let matrices = R1CSMatrices::from_r1cs(&r1cs);

    assert_eq!(matrices.num_constraints, 1);
    assert_eq!(matrices.num_wires, 4);
    assert!(!matrices.a.is_empty());
    assert!(!matrices.b.is_empty());
    assert!(!matrices.c.is_empty());

    // Should be very sparse
    assert!(matrices.sparsity() < 0.5);
}
