use super::*;
use num_bigint::BigUint;

#[test]
fn test_expand_zero() {
    let modulus = [0u8; 32];
    let result = expand_value_placeholder("0", &modulus).unwrap();
    assert_eq!(result, vec![0u8; 32]);
}

#[test]
fn test_expand_one() {
    let modulus = [0u8; 32];
    let result = expand_value_placeholder("1", &modulus).unwrap();
    let mut expected = vec![0u8; 32];
    expected[31] = 1;
    assert_eq!(result, expected);
}

#[test]
fn test_expand_hex() {
    let modulus = [0u8; 32];
    let result = expand_value_placeholder("0xdead", &modulus).unwrap();
    assert_eq!(result, vec![0xde, 0xad]);
}

#[test]
fn test_expand_invalid_hex_returns_error() {
    let modulus = [0u8; 32];
    let result = expand_value_placeholder("0xZZZZ", &modulus);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.reason.contains("Invalid hex"));
}

#[test]
fn test_expand_invalid_decimal_returns_error() {
    let modulus = [0u8; 32];
    let result = expand_value_placeholder("not_a_number", &modulus);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.reason.contains("Invalid decimal"));
}

#[test]
fn test_expand_max_offsets() {
    let mut modulus = [0u8; 32];
    modulus[31] = 5; // p = 5

    let max = expand_value_placeholder("max", &modulus).unwrap();
    let max_minus = expand_value_placeholder("max-1", &modulus).unwrap();
    let max_plus = expand_value_placeholder("max+1", &modulus).unwrap();
    let p_plus = expand_value_placeholder("p+1", &modulus).unwrap();

    assert_eq!(BigUint::from_bytes_be(&max), BigUint::from(4u8));
    assert_eq!(BigUint::from_bytes_be(&max_minus), BigUint::from(3u8));
    assert_eq!(BigUint::from_bytes_be(&max_plus), BigUint::from(5u8));
    assert_eq!(BigUint::from_bytes_be(&p_plus), BigUint::from(6u8));
}

#[test]
fn test_expand_field_mod_offsets_and_negative() {
    let mut modulus = [0u8; 32];
    modulus[31] = 5; // p = 5

    let field_mod_minus = expand_value_placeholder("field_mod-1", &modulus).unwrap();
    let max_field_minus = expand_value_placeholder("max_field-1", &modulus).unwrap();
    let neg_one = expand_value_placeholder("-1", &modulus).unwrap();

    assert_eq!(BigUint::from_bytes_be(&field_mod_minus), BigUint::from(4u8));
    assert_eq!(BigUint::from_bytes_be(&max_field_minus), BigUint::from(3u8));
    assert_eq!(BigUint::from_bytes_be(&neg_one), BigUint::from(4u8));
}
