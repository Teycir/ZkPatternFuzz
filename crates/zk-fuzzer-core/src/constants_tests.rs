
use super::*;

#[test]
fn test_bn254_modulus_bytes() {
    let bytes = bn254_modulus_bytes();
    assert_eq!(bytes[0], 0x30);
    assert_eq!(bytes[31], 0x01);
}

#[test]
fn test_bn254_modulus_minus_one_bytes() {
    let bytes = bn254_modulus_minus_one_bytes();
    assert_eq!(bytes[0], 0x30);
    assert_eq!(bytes[31], 0x00);
}

#[test]
fn test_field_type_boundary_values() {
    let bn254 = FieldType::Bn254;
    let boundaries = bn254.boundary_values();
    assert!(boundaries.len() >= 4);
}
