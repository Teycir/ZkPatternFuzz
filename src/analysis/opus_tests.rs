
use super::*;

#[test]
fn test_opus_analyzer_creation() {
    let analyzer = OpusAnalyzer::new();
    assert!(!analyzer.zero_day_detectors.is_empty());
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
            signal out;
            out <-- in * 2;  // Assignment without constraint!
        "#;

    let detector = MissingConstraintDetector;
    let hints = detector.detect(source, Framework::Circom, &[]);

    assert!(!hints.is_empty());
    assert_eq!(hints[0].category, ZeroDayCategory::MissingConstraint);
}
