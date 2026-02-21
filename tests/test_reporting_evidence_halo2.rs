use tempfile::TempDir;
use zk_core::{AttackType, Finding, ProofOfConcept, Severity};
use zk_fuzzer::reporting::evidence_halo2::generate_halo2_repro_script;

#[test]
fn test_generate_halo2_repro_script_writes_verify_helper() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("repro.sh");
    let spec_path = temp_dir.path().join("spec.json");
    let witness_path = temp_dir.path().join("witness.json"); // required by generated helper script
    std::fs::write(&spec_path, "{}").unwrap();
    std::fs::write(&witness_path, "{}").unwrap();

    let finding = Finding {
        attack_type: AttackType::Soundness,
        severity: Severity::High,
        description: "Halo2 script generation".to_string(),
        poc: ProofOfConcept::default(),
        location: None,
    };

    let cmd = generate_halo2_repro_script(&script_path, &finding, Some(&spec_path))
        .expect("repro script generation should succeed");
    assert!(cmd.contains("./repro.sh"));

    let verify_path = temp_dir.path().join("verify_halo2.rs");
    assert!(verify_path.exists(), "verify_halo2.rs should be generated");

    let content = std::fs::read_to_string(&verify_path).unwrap();
    assert!(content.contains("Halo2Target"));
    assert!(content.contains("parse_witness_inputs"));
    assert!(
        !content.contains("YourCircuit"),
        "must use generic backend target"
    );
}
