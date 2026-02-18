    use super::*;

    #[test]
    fn test_merkle_pattern_detection() {
        let source = r#"
            template MerkleProof(levels) {
                signal input leaf;
                signal input pathElements[levels];
                signal input pathIndices[levels];
                signal output root;
            }
        "#;

        let generator = ConfigGenerator::new();
        let patterns = generator.detect_patterns(source, Framework::Circom);

        assert!(!patterns.is_empty());
        assert!(patterns
            .iter()
            .any(|p| p.pattern_type == PatternType::MerkleTree));
    }

    #[test]
    fn test_hash_pattern_detection() {
        let source = r#"
            include "circomlib/poseidon.circom";
            
            template HashCheck() {
                signal input x;
                component hasher = Poseidon(1);
            }
        "#;

        let generator = ConfigGenerator::new();
        let patterns = generator.detect_patterns(source, Framework::Circom);

        assert!(patterns.iter().any(
            |p| matches!(&p.pattern_type, PatternType::HashFunction(name) if name == "poseidon")
        ));
    }

    #[test]
    fn test_detect_main_component() {
        let source = r#"
            template MerkleProof() {
                // ...
            }
            component main = MerkleProof();
        "#;

        let main = detect_main_component(source, Framework::Circom);
        assert_eq!(main, "MerkleProof");
    }

    #[test]
    fn test_parse_circom_input() {
        let line = "    signal input leaf;";
        let input = parse_circom_input(line).unwrap();
        assert_eq!(input.name, "leaf");
        assert_eq!(input.input_type, "field");
    }

    #[test]
    fn test_parse_circom_array_input() {
        let line = "    signal input pathElements[20];";
        let input = parse_circom_input(line).unwrap();
        assert_eq!(input.name, "pathElements");
        assert_eq!(input.input_type, "array<field>");
        assert_eq!(input.length, Some(20));
    }
