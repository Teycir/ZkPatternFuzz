use tempfile::TempDir;
use zk_core::{AttackType, Finding, ProofOfConcept, Severity};
use zk_fuzzer::reporting::evidence::VerificationResult;
use zk_fuzzer::reporting::evidence_noir::{generate_noir_proof, generate_noir_repro_script};

#[test]
fn test_generate_noir_repro_script() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("repro.sh");
    let project_path = temp_dir.path().join("noir_project");
    std::fs::create_dir_all(&project_path).unwrap();

    let finding = Finding {
        attack_type: AttackType::Soundness,
        severity: Severity::High,
        description: "Noir script generation".to_string(),
        poc: ProofOfConcept::default(),
        location: None,
    };

    let cmd = generate_noir_repro_script(&script_path, &finding, &project_path)
        .expect("repro script generation should succeed");
    assert!(cmd.contains("./repro.sh"));

    let content = std::fs::read_to_string(&script_path).unwrap();
    assert!(content.contains("nargo prove"));
    assert!(content.contains("nargo verify"));
}

#[test]
fn test_generate_noir_proof_missing_witness_returns_failure() {
    let temp_dir = TempDir::new().unwrap();
    let finding = Finding {
        attack_type: AttackType::Soundness,
        severity: Severity::High,
        description: "Missing witness".to_string(),
        poc: ProofOfConcept::default(),
        location: None,
    };

    let (_proof, result) = generate_noir_proof(temp_dir.path(), &finding, temp_dir.path())
        .expect("call should not error on missing witness");
    match result {
        VerificationResult::Failed(msg) => assert!(msg.contains("witness.json not found")),
        other => panic!("expected failure result, got {:?}", other),
    }
}
