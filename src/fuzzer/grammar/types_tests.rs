use super::*;

#[test]
fn test_input_type_description() {
    assert!(!InputType::Field.description().is_empty());
    assert!(!InputType::MerklePath.description().is_empty());
}

#[test]
fn test_composite_types() {
    assert!(!InputType::Field.is_composite());
    assert!(InputType::Array.is_composite());
    assert!(InputType::MerklePath.is_composite());
}

#[test]
fn test_entropy_bit_count() {
    assert!(EntropyLevel::Low.bit_count() < EntropyLevel::Medium.bit_count());
    assert!(EntropyLevel::Medium.bit_count() < EntropyLevel::High.bit_count());
}
