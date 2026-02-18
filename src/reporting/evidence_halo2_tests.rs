
use super::*;
use tempfile::TempDir;

#[test]
fn test_generate_halo2_verify_script() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("verify.rs");
    let spec_path = temp_dir.path().join("spec.json");
    let witness_path = temp_dir.path().join("witness.json");

    std::fs::write(&spec_path, "{}").unwrap();
    std::fs::write(&witness_path, "{}").unwrap();

    generate_halo2_verify_script(&script_path, &spec_path, &witness_path).unwrap();

    let content = std::fs::read_to_string(&script_path).unwrap();
    assert!(content.contains("Halo2Target"));
    assert!(content.contains("parse_witness_inputs"));
    assert!(!content.contains("YourCircuit"));
}
