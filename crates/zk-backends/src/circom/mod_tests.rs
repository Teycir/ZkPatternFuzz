use super::*;
use std::path::PathBuf;

fn find_test_circuits_dir() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..6 {
        let candidate = dir.join("tests").join("circuits");
        if candidate.exists() {
            return candidate;
        }
        if !dir.pop() {
            break;
        }
    }
    panic!("tests/circuits directory not found from CARGO_MANIFEST_DIR");
}

#[test]
fn test_field_element_conversion() {
    let fe = FieldElement::from_u64(12345);
    let decimal = field_element_to_decimal(&fe);
    let parsed = parse_decimal_to_field_element(&decimal).unwrap();
    assert_eq!(fe, parsed);
}

#[test]
fn test_signal_extraction() {
    let source = r#"
            signal input a;
            signal input b;
            signal output c;
            signal private input d;
        "#;

    let signals = analysis::extract_signals(source);
    assert_eq!(signals.len(), 4);
    assert_eq!(signals[0].name, "a");
    assert_eq!(signals[0].direction, analysis::SignalDirection::Input);
}

#[test]
fn test_constraint_parsing() {
    let circuits_dir = find_test_circuits_dir();
    let circuit_path = circuits_dir.join("multiplier.circom");
    let build_dir = circuits_dir.join("build");

    let target = CircomTarget::new(circuit_path.to_str().unwrap(), "Multiplier")
        .unwrap()
        .with_build_dir(build_dir);

    let constraints = target.load_constraints().unwrap();
    assert!(!constraints.is_empty());
}

#[test]
fn test_file_has_nonzero_size() {
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty.bin");
    let full = dir.path().join("full.bin");

    std::fs::write(&empty, []).unwrap();
    std::fs::write(&full, [1u8, 2u8]).unwrap();

    assert!(!file_has_nonzero_size(&dir.path().join("missing.bin")).unwrap());
    assert!(!file_has_nonzero_size(&empty).unwrap());
    assert!(file_has_nonzero_size(&full).unwrap());
}
