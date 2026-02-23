use super::*;
use crate::constants::BN254_SCALAR_MODULUS_HEX;
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

#[test]
fn from_bytes_checked_rejects_non_canonical_values() {
    let modulus_hex = format!("0x{}", BN254_SCALAR_MODULUS_HEX);
    let modulus = FieldElement::from_hex(&modulus_hex).expect("modulus hex must parse");
    let err = FieldElement::from_bytes_checked(&modulus.to_bytes())
        .expect_err("modulus itself must be rejected as non-canonical");
    assert!(err
        .to_string()
        .contains("must be < modulus"));
}

#[test]
fn from_bytes_reduced_maps_modulus_to_zero() {
    let modulus_hex = format!("0x{}", BN254_SCALAR_MODULUS_HEX);
    let modulus = FieldElement::from_hex(&modulus_hex).expect("modulus hex must parse");
    let reduced = FieldElement::from_bytes_reduced(&modulus.to_bytes());
    assert!(reduced.is_zero());
    assert!(reduced.is_canonical());
}
