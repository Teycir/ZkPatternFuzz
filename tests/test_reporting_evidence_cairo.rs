use tempfile::TempDir;
use zk_core::{AttackType, Finding, ProofOfConcept, Severity};
use zk_fuzzer::reporting::evidence::VerificationResult;
use zk_fuzzer::reporting::evidence_cairo::{generate_cairo_proof, generate_cairo_repro_script};

#[test]
fn test_generate_cairo_repro_script() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("repro.sh");
    let program_path = temp_dir.path().join("program.json");
    std::fs::write(&program_path, "{}").unwrap();

    let finding = Finding {
        attack_type: AttackType::Soundness,
        severity: Severity::High,
        description: "Cairo script generation".to_string(),
        poc: ProofOfConcept::default(),
        location: None,
    };

    let cmd = generate_cairo_repro_script(&script_path, &finding, &program_path)
        .expect("repro script generation should succeed");
    assert!(cmd.contains("./repro.sh"));

    let content = std::fs::read_to_string(&script_path).unwrap();
    assert!(content.contains("cairo-run"));
    assert!(content.contains("cpu_air_prover"));
}

#[test]
fn test_generate_cairo_proof_missing_witness_returns_failure() {
    let temp_dir = TempDir::new().unwrap();
    let finding = Finding {
        attack_type: AttackType::Soundness,
        severity: Severity::High,
        description: "Missing witness".to_string(),
        poc: ProofOfConcept::default(),
        location: None,
    };
    let program_path = temp_dir.path().join("program.json");
    std::fs::write(&program_path, "{}").unwrap();

    let (_proof, result) = generate_cairo_proof(temp_dir.path(), &finding, &program_path)
        .expect("call should not error on missing witness");
    match result {
        VerificationResult::Failed(msg) => assert!(msg.contains("witness.json not found")),
        other => panic!("expected failure result, got {:?}", other),
    }
}
