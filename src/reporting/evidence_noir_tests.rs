    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_convert_witness_to_prover_toml() {
        let temp_dir = TempDir::new().unwrap();
        let witness_path = temp_dir.path().join("witness.json");
        let prover_path = temp_dir.path().join("Prover.toml");

        let witness_json = r#"{
            "x": "5",
            "y": "10",
            "arr": ["1", "2", "3"]
        }"#;

        std::fs::write(&witness_path, witness_json).unwrap();
        convert_witness_to_prover_toml(&witness_path, &prover_path).unwrap();

        let toml_content = std::fs::read_to_string(&prover_path).unwrap();
        assert!(toml_content.contains("x = "));
        assert!(toml_content.contains("y = "));
        assert!(toml_content.contains("arr = "));
    }
