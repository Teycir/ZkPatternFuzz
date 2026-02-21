use super::*;

#[test]
fn test_parse_noir_field() {
    let fe = parse_noir_field("12345").unwrap();
    assert_eq!(fe, FieldElement::from_u64(12345));

    let fe_hex = parse_noir_field("0x1234").unwrap();
    assert_eq!(fe_hex.0[30], 0x12);
    assert_eq!(fe_hex.0[31], 0x34);
}

#[test]
fn test_function_extraction() {
    let source = r#"
            fn main(x: Field, y: pub Field) -> Field {
                x + y
            }
            
            fn helper(a: u64) {
                // ...
            }
        "#;

    let functions = analysis::extract_functions(source);
    assert_eq!(functions.len(), 2);
    assert!(functions[0].is_main);
    assert_eq!(functions[0].params.len(), 2);
}

#[test]
fn test_proof_file_candidates_include_name_and_main_without_duplicates() {
    use std::collections::HashSet;

    let mut target = NoirTarget::new("/tmp/noir-proof-candidates").expect("target construction");
    target.metadata = Some(NoirMetadata {
        name: "demo".to_string(),
        num_opcodes: 0,
        num_witnesses: 0,
        num_public_inputs: 0,
        num_return_values: 0,
        abi: NoirAbi::default(),
    });
    target.compiled = true;

    let candidates = target.proof_file_candidates();
    let unique_len = candidates.iter().collect::<HashSet<_>>().len();
    assert_eq!(
        candidates.len(),
        unique_len,
        "candidates should be deduplicated"
    );

    assert!(candidates
        .iter()
        .any(|path| path.ends_with("proofs/demo.proof")));
    assert!(candidates
        .iter()
        .any(|path| path.ends_with("proofs/main.proof")));
    assert!(candidates
        .iter()
        .any(|path| path.ends_with("target/proofs/demo.proof")));
    assert!(candidates
        .iter()
        .any(|path| path.ends_with("target/main.proof")));

    target.metadata.as_mut().expect("metadata").name = "main".to_string();
    let deduped = target.proof_file_candidates();
    let deduped_unique_len = deduped.iter().collect::<HashSet<_>>().len();
    assert_eq!(deduped.len(), deduped_unique_len);
    assert!(
        deduped
            .iter()
            .all(|path| path.to_string_lossy().contains("main.proof")),
        "all candidates should use main.proof when project name is main"
    );
}

#[test]
fn test_candidate_artifact_paths_include_project_target_json() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let project = temp_dir.path().join("noir_project");
    std::fs::create_dir_all(project.join("src")).expect("create src");
    std::fs::create_dir_all(project.join("target")).expect("create target");
    std::fs::write(
        project.join("Nargo.toml"),
        "[package]\nname = \"program\"\ntype = \"bin\"\nauthors = [\"\"]\n\n[dependencies]\n",
    )
    .expect("write manifest");
    std::fs::write(
        project.join("target/program.json"),
        r#"{"abi":{"parameters":[],"return_type":null}}"#,
    )
    .expect("write artifact");

    let target = NoirTarget::new(project.to_str().expect("utf8 path")).expect("target");
    let candidates = target
        .candidate_artifact_paths()
        .expect("resolve artifact candidates");

    assert!(candidates
        .iter()
        .any(|path| path.ends_with("target/program.json")));
}

#[test]
fn test_num_private_inputs_counts_only_private_abi_parameters() {
    use crate::TargetCircuit;

    let mut target = NoirTarget::new("/tmp/noir-input-counts").expect("target construction");
    target.metadata = Some(NoirMetadata {
        name: "demo".to_string(),
        num_opcodes: 0,
        num_witnesses: 0,
        num_public_inputs: 0,
        num_return_values: 0,
        abi: NoirAbi {
            parameters: vec![
                NoirParameter {
                    name: "x".to_string(),
                    typ: NoirType::Field,
                    visibility: Visibility::Private,
                },
                NoirParameter {
                    name: "y".to_string(),
                    typ: NoirType::Field,
                    visibility: Visibility::Public,
                },
            ],
            return_type: None,
        },
    });
    target.compiled = true;

    assert_eq!(target.num_private_inputs(), 1);
    assert_eq!(target.num_public_inputs(), 1);
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
