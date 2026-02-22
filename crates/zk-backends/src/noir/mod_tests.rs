use super::*;
use std::path::Path;

fn write_noir_manifest(project: &Path, package_name: &str) {
    std::fs::create_dir_all(project.join("src")).expect("create src");
    std::fs::write(
        project.join("Nargo.toml"),
        format!(
            "[package]\nname = \"{package_name}\"\ntype = \"bin\"\nauthors = [\"\"]\n\n[dependencies]\n"
        ),
    )
    .expect("write manifest");
}

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
fn test_proof_file_candidates_cover_custom_build_dir_layouts() {
    let mut target = NoirTarget::new("/tmp/noir-proof-layouts").expect("target construction");
    target.metadata = Some(NoirMetadata {
        name: "demo".to_string(),
        num_opcodes: 0,
        num_witnesses: 0,
        num_public_inputs: 0,
        num_return_values: 0,
        abi: NoirAbi::default(),
    });
    target.compiled = true;
    target.build_dir = Path::new("/tmp/noir-proof-layouts-build").to_path_buf();

    let candidates = target.proof_file_candidates();

    assert!(candidates
        .iter()
        .any(|path| path.ends_with(Path::new("proofs/demo.proof"))));
    assert!(candidates
        .iter()
        .any(|path| path.ends_with(Path::new("proofs/main.proof"))));
    assert!(candidates
        .iter()
        .any(|path| path.ends_with(Path::new("target/demo.proof"))));
    assert!(candidates
        .iter()
        .any(|path| path.ends_with(Path::new("noir-proof-layouts-build/demo.proof"))));
}

#[test]
fn test_validate_proof_artifact_bytes_contract() {
    let empty_err = validate_proof_artifact_bytes(&[]).expect_err("empty proof must fail");
    assert!(
        empty_err.to_string().contains("empty"),
        "unexpected error: {empty_err}"
    );

    validate_proof_artifact_bytes(&[1, 2, 3]).expect("non-empty proof should pass");
}

#[test]
fn test_verify_inputs_digest_contract_is_deterministic() {
    let inputs = vec![FieldElement::from_u64(3), FieldElement::from_u64(5)];
    let digest_a = verify_inputs_digest_hex(&inputs);
    let digest_b = verify_inputs_digest_hex(&inputs);
    assert_eq!(digest_a, digest_b, "same inputs must hash identically");

    let permuted = vec![FieldElement::from_u64(5), FieldElement::from_u64(3)];
    let digest_permuted = verify_inputs_digest_hex(&permuted);
    assert_ne!(
        digest_a, digest_permuted,
        "input order must influence deterministic hash"
    );
}

#[test]
fn test_verify_inputs_contract_path_format_and_payload() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let project = temp_dir.path().join("verify_contract_project");
    let build_dir = project.join("target/custom_build");
    let target = NoirTarget::new(project.to_str().expect("utf8 path"))
        .expect("target")
        .with_build_dir(build_dir.clone());

    let inputs = vec![FieldElement::from_u64(7), FieldElement::from_u64(11)];
    let contract_path = target
        .write_verify_inputs_contract(&inputs)
        .expect("write contract");
    assert_eq!(
        contract_path,
        build_dir.join("verify_inputs_contract.json"),
        "contract path must be stable under build_dir"
    );

    let payload_before = std::fs::read(&contract_path).expect("read first payload");
    let parsed: NoirVerifyInputsContract =
        serde_json::from_slice(&payload_before).expect("parse contract json");
    assert_eq!(parsed.contract_version, 1);
    assert_eq!(parsed.framework, "noir");
    assert_eq!(parsed.field, "bn254");
    assert_eq!(parsed.count, 2);
    assert_eq!(
        parsed.inputs_sha256,
        verify_inputs_digest_hex(&inputs),
        "hash must match canonical digest"
    );
    assert_eq!(parsed.public_inputs_hex.len(), 2);
    assert!(parsed
        .public_inputs_hex
        .iter()
        .all(|value| value.starts_with("0x")));

    target
        .write_verify_inputs_contract(&inputs)
        .expect("rewrite contract");
    let payload_after = std::fs::read(&contract_path).expect("read second payload");
    assert_eq!(
        payload_before, payload_after,
        "contract serialization must be deterministic for identical verify inputs"
    );
}

#[test]
fn test_candidate_artifact_paths_include_project_target_json() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let project = temp_dir.path().join("noir_project");
    std::fs::create_dir_all(project.join("target")).expect("create target");
    write_noir_manifest(&project, "program");
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
fn test_parse_abi_supports_known_artifact_layouts() {
    struct Case {
        name: &'static str,
        build_dir_rel: Option<&'static str>,
        artifact_rel: &'static str,
    }

    let cases = [
        Case {
            name: "project_target_named",
            build_dir_rel: None,
            artifact_rel: "target/program.json",
        },
        Case {
            name: "project_target_main",
            build_dir_rel: None,
            artifact_rel: "target/main.json",
        },
        Case {
            name: "custom_build_named",
            build_dir_rel: Some("target/custom_build"),
            artifact_rel: "target/custom_build/program.json",
        },
        Case {
            name: "custom_build_nested",
            build_dir_rel: Some("target/custom_build"),
            artifact_rel: "target/custom_build/cache/programs/program.json",
        },
    ];

    for case in cases {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let project = temp_dir.path().join(case.name);
        let artifact_path = project.join(case.artifact_rel);
        let parent = artifact_path.parent().expect("artifact parent");

        std::fs::create_dir_all(parent).expect("create artifact parent");
        write_noir_manifest(&project, "program");
        std::fs::write(
            &artifact_path,
            r#"{
                "abi": {
                    "parameters": [{"name":"x","type":{"kind":"field"},"visibility":"private"}],
                    "return_type": null
                }
            }"#,
        )
        .expect("write artifact");

        let mut target = NoirTarget::new(project.to_str().expect("utf8 path")).expect("target");
        if let Some(build_dir_rel) = case.build_dir_rel {
            target = target.with_build_dir(project.join(build_dir_rel));
        }

        let abi = target
            .parse_abi()
            .unwrap_or_else(|err| panic!("{} parse_abi failed: {err}", case.name));
        assert_eq!(abi.parameters.len(), 1, "{}", case.name);
        assert_eq!(abi.parameters[0].name, "x", "{}", case.name);
    }
}

#[test]
fn test_parse_nargo_info_supports_legacy_and_modern_schemas() {
    struct Case {
        name: &'static str,
        payload: &'static str,
        expected: (usize, usize, usize),
    }

    let cases = [
        Case {
            name: "legacy_scalar_schema",
            payload: r#"{"opcodes":12,"witnesses":9,"public_inputs":2}"#,
            expected: (12, 9, 2),
        },
        Case {
            name: "modern_single_program",
            payload: r#"{
                "programs":[
                    {"functions":[{"name":"main","opcodes":4},{"name":"helper","opcodes":7}]}
                ],
                "witnesses":13,
                "public_inputs":3
            }"#,
            expected: (11, 13, 3),
        },
        Case {
            name: "modern_multi_program",
            payload: r#"{
                "programs":[
                    {"functions":[{"opcodes":5}]},
                    {"functions":[{"opcodes":8},{"opcodes":2}]}
                ]
            }"#,
            expected: (15, 0, 0),
        },
    ];

    let target = NoirTarget::new("/tmp/noir-info-compat").expect("target construction");
    for case in cases {
        let actual = target
            .parse_nargo_info(case.payload)
            .unwrap_or_else(|err| panic!("{} parse_nargo_info failed: {err}", case.name));
        assert_eq!(actual, case.expected, "{}", case.name);
    }
}

#[test]
fn test_parse_nargo_info_rejects_missing_opcodes() {
    let target = NoirTarget::new("/tmp/noir-info-missing-opcodes").expect("target construction");
    let err = target
        .parse_nargo_info(r#"{"witnesses":1,"public_inputs":1}"#)
        .expect_err("missing opcodes should error");
    assert!(
        err.to_string().contains("Missing 'opcodes'"),
        "unexpected error: {err}"
    );
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
