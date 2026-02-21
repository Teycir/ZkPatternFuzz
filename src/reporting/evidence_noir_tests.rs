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

#[test]
fn test_nargo_missing_subcommand_message_detection() {
    let stderr = "error: unrecognized subcommand 'prove'\n\nUsage: nargo <COMMAND>";
    assert!(nargo_missing_subcommand_message("", stderr, "prove"));
    assert!(!nargo_missing_subcommand_message(
        "",
        "error: package not found",
        "prove"
    ));
}

#[test]
fn test_barretenberg_missing_tool_message_detection() {
    assert!(barretenberg_missing_tool_message(
        "",
        "bb: command not found"
    ));
    assert!(barretenberg_missing_tool_message(
        "",
        "error: failed to execute /usr/local/bin/bb: No such file or directory"
    ));
    assert!(!barretenberg_missing_tool_message(
        "",
        "error: verification failed due to invalid proof"
    ));
}

#[test]
fn test_noir_proof_candidates_include_project_name_and_common_locations() {
    let temp_dir = TempDir::new().unwrap();
    std::fs::write(
        temp_dir.path().join("Nargo.toml"),
        "[package]\nname = \"demo\"\ntype = \"bin\"\nauthors = [\"\"]\n\n[dependencies]\n",
    )
    .unwrap();

    let candidates = noir_proof_candidates(temp_dir.path());
    assert!(candidates
        .iter()
        .any(|path| path.ends_with("proofs/noir.proof")));
    assert!(candidates
        .iter()
        .any(|path| path.ends_with("proofs/main.proof")));
    assert!(candidates
        .iter()
        .any(|path| path.ends_with("proofs/demo.proof")));
    assert!(candidates
        .iter()
        .any(|path| path.ends_with("target/proofs/demo.proof")));
}
