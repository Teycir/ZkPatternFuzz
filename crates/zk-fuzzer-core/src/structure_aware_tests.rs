use super::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn test_boolean_mutation() {
    let mutator = StructureAwareMutator::new(Framework::Circom)
        .with_structures(vec![InputStructure::Boolean]);

    let mut rng = StdRng::seed_from_u64(42);
    let zero = FieldElement::zero();
    let result = mutator.mutate_structured(&zero, &InputStructure::Boolean, &mut rng);
    assert_eq!(result, FieldElement::one());
}

#[test]
fn test_integer_mutation_stays_in_range() {
    let mutator = StructureAwareMutator::new(Framework::Circom);
    let mut rng = StdRng::seed_from_u64(42);

    for _ in 0..100 {
        let input = FieldElement::from_u64(100);
        let result = mutator.mutate_integer(&input, 8, &mut rng);
        let value = mutator.to_u64(&result);
        assert!(value <= 255, "8-bit value should be <= 255, got {}", value);
    }
}

#[test]
fn test_circom_structure_inference() {
    let source = r#"
            signal input secret;
            signal input bits[8];
            signal input merkle_path[20];
            signal output nullifier;
        "#;

    let structures = StructureAwareMutator::infer_circom_structure(source);
    assert!(!structures.is_empty());
}

#[test]
fn test_circom_structure_inference_from_usage_patterns() {
    let source = r#"
            signal input a0;
            signal input a1;
            signal input a2[3];
            signal input a3[2];
            signal output out;

            a0 * (a0 - 1) === 0;
            tmp <== poseidon(a1, 7);
            flag <== a2[0] * (a2[0] - 1);
            root <== merkle_compute(a3[0], a3[1]);
        "#;

    let structures = StructureAwareMutator::infer_circom_structure(source);
    assert_eq!(
        structures,
        vec![
            InputStructure::Boolean,
            InputStructure::HashPreimage { num_elements: 2 },
            InputStructure::BitDecomposition { bits: 3 },
            InputStructure::MerklePath { depth: 2 },
        ]
    );
}

#[test]
fn test_circom_structure_inference_ignores_inline_comments() {
    let source = r#"
            signal input a0; // boolean selector
            signal private input a1[2]; // merkle path fragment

            a0 * (a0 - 1) === 0;
            out <== merkle_verify(a1[0], a1[1]);
        "#;

    let structures = StructureAwareMutator::infer_circom_structure(source);
    assert_eq!(
        structures,
        vec![
            InputStructure::Boolean,
            InputStructure::MerklePath { depth: 2 },
        ]
    );
}

#[test]
fn test_circom_usage_inference_ignores_inline_usage_comments() {
    let source = r#"
            signal input x0;
            signal input x1;

            out <== x0; // merkle hash poseidon
            out2 <== x1 + 1;
        "#;

    let structures = StructureAwareMutator::infer_circom_structure(source);
    assert_eq!(
        structures,
        vec![InputStructure::Field, InputStructure::Field]
    );
}

#[test]
fn test_noir_structure_inference_from_type_and_usage() {
    let source = r#"
        fn main(p0: Field, p1: [Field; 4], p2: bool, p3: u32, p4: [bool; 8]) {
            assert(p0 == 0 || p0 == 1);
            let _h = poseidon(p0, p3 as Field);
            let _root = merkle_root(p1);
            assert(p2 == true);
        }
    "#;

    let structures = StructureAwareMutator::infer_noir_structure(source);
    assert_eq!(
        structures,
        vec![
            InputStructure::Boolean,
            InputStructure::MerklePath { depth: 4 },
            InputStructure::Boolean,
            InputStructure::Integer { bits: 32 },
            InputStructure::BitDecomposition { bits: 8 },
        ]
    );
}

#[test]
fn test_splice() {
    let mut rng = StdRng::seed_from_u64(42);
    let a = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
    let b = vec![FieldElement::from_u64(3), FieldElement::from_u64(4)];

    let result = Splicer::splice(&a, &b, &mut rng);
    assert_eq!(result.len(), 2);
}
