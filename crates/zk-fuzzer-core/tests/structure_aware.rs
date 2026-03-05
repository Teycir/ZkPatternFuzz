use rand::rngs::StdRng;
use rand::SeedableRng;
use zk_core::{FieldElement, Framework};
use zk_fuzzer_core::structure_aware::{InputStructure, Splicer, StructureAwareMutator};

fn field_to_u64(value: &FieldElement) -> u64 {
    let tail: [u8; 8] = value.0[24..32]
        .try_into()
        .expect("field element tail should be 8 bytes");
    u64::from_be_bytes(tail)
}

#[test]
fn boolean_mutation_flips_zero_to_one() {
    let mutator = StructureAwareMutator::new(Framework::Circom)
        .with_structures(vec![InputStructure::Boolean]);

    let mut rng = StdRng::seed_from_u64(42);
    let result = mutator.mutate(&[FieldElement::zero()], &mut rng);
    assert_eq!(result, vec![FieldElement::one()]);
}

#[test]
fn integer_mutation_stays_in_range() {
    let mutator = StructureAwareMutator::new(Framework::Circom)
        .with_structures(vec![InputStructure::Integer { bits: 8 }]);
    let mut rng = StdRng::seed_from_u64(42);

    for _ in 0..100 {
        let result = mutator.mutate(&[FieldElement::from_u64(100)], &mut rng);
        assert_eq!(result.len(), 1);
        assert!(
            field_to_u64(&result[0]) <= 255,
            "8-bit value should be <= 255, got {}",
            field_to_u64(&result[0])
        );
    }
}

#[test]
fn circom_structure_inference_detects_declared_inputs() {
    let source = r#"
            signal input secret;
            signal input bits[8];
            signal input merkle_path[20];
            signal output nullifier;
        "#;

    let structures = StructureAwareMutator::infer_structure_from_source(source, Framework::Circom);
    assert!(!structures.is_empty());
}

#[test]
fn circom_structure_inference_uses_usage_patterns() {
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

    let structures = StructureAwareMutator::infer_structure_from_source(source, Framework::Circom);
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
fn circom_structure_inference_ignores_inline_comments() {
    let source = r#"
            signal input a0; // boolean selector
            signal private input a1[2]; // merkle path fragment

            a0 * (a0 - 1) === 0;
            out <== merkle_verify(a1[0], a1[1]);
        "#;

    let structures = StructureAwareMutator::infer_structure_from_source(source, Framework::Circom);
    assert_eq!(
        structures,
        vec![
            InputStructure::Boolean,
            InputStructure::MerklePath { depth: 2 },
        ]
    );
}

#[test]
fn circom_usage_inference_ignores_inline_usage_comments() {
    let source = r#"
            signal input x0;
            signal input x1;

            out <== x0; // merkle hash poseidon
            out2 <== x1 + 1;
        "#;

    let structures = StructureAwareMutator::infer_structure_from_source(source, Framework::Circom);
    assert_eq!(
        structures,
        vec![InputStructure::Field, InputStructure::Field]
    );
}

#[test]
fn noir_structure_inference_uses_types_and_usage() {
    let source = r#"
        fn main(p0: Field, p1: [Field; 4], p2: bool, p3: u32, p4: [bool; 8]) {
            assert(p0 == 0 || p0 == 1);
            let _h = poseidon(p0, p3 as Field);
            let _root = merkle_root(p1);
            assert(p2 == true);
        }
    "#;

    let structures = StructureAwareMutator::infer_structure_from_source(source, Framework::Noir);
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
fn splice_preserves_input_width() {
    let mut rng = StdRng::seed_from_u64(42);
    let a = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
    let b = vec![FieldElement::from_u64(3), FieldElement::from_u64(4)];

    let result = Splicer::splice(&a, &b, &mut rng);
    assert_eq!(result.len(), 2);
}
