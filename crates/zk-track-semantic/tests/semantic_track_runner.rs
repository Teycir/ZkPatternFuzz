use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use tempfile::tempdir;
use zk_postroadmap_core::{TrackInput, TrackRunner};
use zk_track_semantic::{
    HeuristicSemanticIntentAdapter, SemanticIntentAdapter, SemanticTrackRunner,
};

#[tokio::test]
async fn heuristic_adapter_extracts_semantic_intent_and_exploitability() {
    let adapter = HeuristicSemanticIntentAdapter;
    let intent = adapter
        .extract_intent(
            "Only admin can withdraw. Verifier must reject forged proofs and never bypass auth.",
        )
        .await
        .expect("intent extraction should succeed");

    assert!(!intent.invariants.is_empty());
    assert!(!intent.required_behaviors.is_empty());
    assert!(!intent.forbidden_behaviors.is_empty());
    assert!(!intent.security_properties.is_empty());

    let assessment = adapter
        .classify_exploitability(
            &intent,
            "TODO bypass marker found in withdrawal verifier path for admin auth.",
        )
        .await
        .expect("exploitability classification should succeed");
    assert!(assessment.confidence >= 65);
    assert!(assessment.exploitable);
}

#[tokio::test]
async fn semantic_track_runner_end_to_end_generates_report_and_findings() {
    let tmp = tempdir().expect("tempdir");
    let project_root = tmp.path().join("sample_project");
    fs::create_dir_all(project_root.join("src")).expect("create project source directory");
    fs::create_dir_all(project_root.join("docs")).expect("create project docs directory");
    fs::create_dir_all(tmp.path().join("output")).expect("create output directory");

    fs::write(
        project_root.join("README.md"),
        "# Sample\nOnly admin can withdraw and verifier must reject forged proofs.\n",
    )
    .expect("write readme");
    fs::write(
        project_root.join("src").join("withdraw.circom"),
        r#"
        // only admin can withdraw
        // verifier must reject forged proofs
        template Withdraw() {
            // TODO: temporary bypass auth checks for local testing
            signal input amount;
            signal input admin;
        }
        "#,
    )
    .expect("write sample source");

    let runner = SemanticTrackRunner::new();
    let input = TrackInput {
        campaign_id: "campaign-semantic".to_string(),
        run_id: "run-semantic-1".to_string(),
        seed: Some(42),
        corpus_dir: tmp.path().join("corpus"),
        evidence_dir: tmp.path().join("evidence"),
        output_dir: tmp.path().join("output"),
        metadata: BTreeMap::from([(
            "semantic_root".to_string(),
            project_root.to_string_lossy().into_owned(),
        )]),
    };

    runner
        .prepare(&input)
        .await
        .expect("prepare should succeed");
    let execution = runner.run(&input).await.expect("run should succeed");
    runner
        .validate(&execution)
        .await
        .expect("validate should succeed");
    let emitted_paths = runner.emit(&execution).await.expect("emit should succeed");

    assert!(!execution.findings.is_empty());
    assert!(execution.scorecard.is_some());
    assert!(execution
        .scorecard
        .as_ref()
        .expect("scorecard")
        .coverage_counts
        .contains_key("files_scanned"));
    assert!(execution
        .scorecard
        .as_ref()
        .expect("scorecard")
        .metrics
        .iter()
        .any(|metric| metric.name == "deterministic_replay_rate"));
    assert!(!emitted_paths.is_empty());

    let report_path = emitted_paths
        .iter()
        .find(|path| is_semantic_report(path))
        .expect("expected semantic report path");
    let report_json = fs::read_to_string(report_path).expect("read report");
    let report_value: serde_json::Value =
        serde_json::from_str(&report_json).expect("parse report json");
    assert_eq!(report_value["run_id"], "run-semantic-1");
    assert!(
        report_value["findings_count"]
            .as_u64()
            .expect("findings_count as u64")
            >= 1
    );
}

fn is_semantic_report(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == "semantic_track_report.json")
        .unwrap_or(false)
}
