
use super::*;

fn make_range_test(value: u64) -> TestCase {
    TestCase {
        inputs: vec![FieldElement::from_u64(value)],
        expected_output: None,
        metadata: Default::default(),
    }
}

#[test]
fn test_value_in_range_passes() {
    let config = OracleConfig::default();
    let mut oracle = RangeProofOracle::new(config).with_range(0, 100);

    let tc = make_range_test(50);
    let output = vec![];

    assert!(oracle.check(&tc, &output).is_none());
}

#[test]
fn test_value_above_range_fails() {
    let config = OracleConfig::default();
    let mut oracle = RangeProofOracle::new(config).with_range(0, 100);

    let tc = make_range_test(200);
    let output = vec![];

    let finding = oracle.check(&tc, &output);
    assert!(finding.is_some());
    assert!(finding.unwrap().description.contains("ABOVE MAXIMUM"));
}

#[test]
fn test_bit_width_range() {
    let config = OracleConfig::default();
    let mut oracle = RangeProofOracle::new(config).with_bits(8); // [0, 256)

    // 255 should pass
    let tc1 = make_range_test(255);
    assert!(oracle.check(&tc1, &[]).is_none());

    // 256 should fail
    let tc2 = make_range_test(256);
    let finding = oracle.check(&tc2, &[]);
    assert!(finding.is_some());
}
