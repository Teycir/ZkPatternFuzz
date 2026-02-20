use super::*;
use tempfile::TempDir;

#[test]
fn test_convert_witness_to_cairo_input() {
    let temp_dir = TempDir::new().unwrap();
    let witness_path = temp_dir.path().join("witness.json");
    let input_path = temp_dir.path().join("input.json");

    let witness_json = r#"{"x": "5", "y": "10"}"#;
    std::fs::write(&witness_path, witness_json).unwrap();

    convert_witness_to_cairo_input(&witness_path, &input_path).unwrap();

    let content = std::fs::read_to_string(&input_path).unwrap();
    assert!(content.contains("\"x\""));
    assert!(content.contains("\"y\""));
}
