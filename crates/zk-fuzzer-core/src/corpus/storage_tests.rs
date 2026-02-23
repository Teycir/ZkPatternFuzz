use super::*;
use tempfile::TempDir;
use zk_core::constants::BN254_SCALAR_MODULUS_HEX;

#[test]
fn test_save_load_test_case() {
    let temp_dir = TempDir::new().unwrap();
    let entry = CorpusEntry::new(
        TestCase {
            inputs: vec![FieldElement::one(), FieldElement::from_u64(42)],
            expected_output: None,
            metadata: TestMetadata::default(),
        },
        12345,
    )
    .with_new_coverage();

    save_test_case(&entry, temp_dir.path(), 0).unwrap();

    let loaded = load_test_case(&temp_dir.path().join("test_case_000000.json")).unwrap();
    assert_eq!(loaded.coverage_hash, entry.coverage_hash);
    assert!(loaded.discovered_new_coverage);
    assert_eq!(loaded.test_case.inputs.len(), 2);
}

#[test]
fn test_load_test_case_rejects_non_canonical_inputs() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("test_case_000000.json");
    let payload = serde_json::json!({
        "inputs": [format!("0x{}", BN254_SCALAR_MODULUS_HEX)],
        "coverage_hash": 1u64,
        "discovered_new_coverage": false,
        "execution_count": 0u64
    });
    std::fs::write(&path, serde_json::to_string_pretty(&payload).unwrap()).unwrap();

    let err = load_test_case(&path).expect_err("non-canonical field element must be rejected");
    assert!(err.to_string().contains("not canonical"));
}
