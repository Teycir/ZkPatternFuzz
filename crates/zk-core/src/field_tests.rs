use super::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn random_field_elements_are_canonical_bn254_values() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let modulus = BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("valid BN254 modulus");

    for _ in 0..1024 {
        let fe = FieldElement::random(&mut rng);
        let value = fe.to_biguint();
        assert!(value < modulus);
    }
}
