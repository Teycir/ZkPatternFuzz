use zk_core::Framework;
use zk_fuzzer::analysis::{OpusAnalyzer, ZeroDayCategory};

#[test]
fn test_opus_analyzer_creation() {
    let analyzer = OpusAnalyzer::new();
    let temp = tempfile::tempdir().expect("temp dir should be creatable");
    let generated = analyzer
        .analyze_project(temp.path())
        .expect("empty project should be analyzable");
    assert!(generated.is_empty());
}

#[test]
fn test_circuit_analysis() {
    let source = r#"
            pragma circom 2.0.0;
            
            template MerkleProof(levels) {
                signal input leaf;
                signal input pathElements[levels];
                signal input pathIndices[levels];
                signal output root;
                
                component hasher = Poseidon(2);
            }
            
            component main = MerkleProof(20);
        "#;

    let analyzer = OpusAnalyzer::new();
    let temp = tempfile::NamedTempFile::with_suffix(".circom").unwrap();
    std::fs::write(temp.path(), source).unwrap();

    let result = analyzer.analyze_circuit(temp.path()).unwrap();

    assert_eq!(result.framework, Framework::Circom);
    assert!(!result.patterns.is_empty());
    assert!(!result.inputs.is_empty());
}

#[test]
fn test_missing_constraint_detection() {
    let source = r#"
            pragma circom 2.0.0;
            template Main() {
                signal input in;
                signal output out;
                out <-- in * 2;  // Assignment without constraint!
            }
            component main = Main();
        "#;

    let analyzer = OpusAnalyzer::new();
    let temp = tempfile::NamedTempFile::with_suffix(".circom").expect("temp file");
    std::fs::write(temp.path(), source).expect("write test circuit");
    let result = analyzer
        .analyze_circuit(temp.path())
        .expect("circuit analysis should succeed");

    assert!(
        result
            .zero_day_hints
            .iter()
            .any(|hint| hint.category == ZeroDayCategory::MissingConstraint),
        "missing-constraint detector should emit a hint via analyze_circuit"
    );
}
