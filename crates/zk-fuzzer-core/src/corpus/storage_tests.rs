
use super::*;
use tempfile::TempDir;

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
