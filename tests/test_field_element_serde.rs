use zk_core::constants::{BN254_SCALAR_MODULUS_HEX, BN254_SCALAR_MODULUS_MINUS_ONE_HEX};
use zk_core::FieldElement;

#[test]
fn field_element_deserialize_rejects_non_canonical_hex() {
    let json = format!("\"0x{}\"", BN254_SCALAR_MODULUS_HEX);
    let parsed = serde_json::from_str::<FieldElement>(&json);
    assert!(
        parsed.is_err(),
        "serde deserialization should reject modulus value as non-canonical"
    );
}

#[test]
fn field_element_deserialize_accepts_canonical_hex() {
    let json = format!("\"0x{}\"", BN254_SCALAR_MODULUS_MINUS_ONE_HEX);
    let parsed = serde_json::from_str::<FieldElement>(&json);
    assert!(parsed.is_ok(), "p-1 should remain canonical and parse");
}
