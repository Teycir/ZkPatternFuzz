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
    assert_eq!(candidates.len(), 2);
    assert!(candidates
        .iter()
        .any(|path| path.ends_with("proofs/demo.proof")));
    assert!(candidates
        .iter()
        .any(|path| path.ends_with("proofs/main.proof")));

    target.metadata.as_mut().expect("metadata").name = "main".to_string();
    let deduped = target.proof_file_candidates();
    assert_eq!(deduped.len(), 1);
    assert!(deduped[0].ends_with("proofs/main.proof"));
}
