use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use tempfile::tempdir;
use zk_postroadmap_core::{TrackInput, TrackRunner};
use zk_track_semantic::{
    ExternalUserSemanticIntentAdapter, HeuristicSemanticIntentAdapter,
    ModelGuidedSemanticIntentAdapter, SemanticIntentAdapter, SemanticTrackRunner,
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
async fn model_guided_adapter_synthesizes_formal_invariants() {
    let adapter = ModelGuidedSemanticIntentAdapter::new("mistral-large")
        .with_system_prompt("strict formal extraction for security invariants");
    let intent = adapter
        .extract_intent(
            "Only admin can mint. Verifier must never accept replay proofs. Proof verification should always reject malformed public inputs.",
        )
        .await
        .expect("intent extraction should succeed");

    assert!(intent
        .invariants
        .iter()
        .any(|line| line.starts_with("invariant.authorization:")));
    assert!(intent
        .invariants
        .iter()
        .any(|line| line.starts_with("formal.strict_requirement:")));
    assert!(intent
        .security_properties
        .iter()
        .any(|line| line.starts_with("security_critical:")));
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
        metadata: BTreeMap::from([
            (
                "semantic_root".to_string(),
                project_root.to_string_lossy().into_owned(),
            ),
            ("semantic_adapter".to_string(), "model_guided".to_string()),
            (
                "semantic_model_name".to_string(),
                "mistral-large".to_string(),
            ),
            (
                "semantic_system_prompt".to_string(),
                "strict formal extraction".to_string(),
            ),
        ]),
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
    let adapter = report_value["adapter"].as_str().expect("adapter as str");
    assert_eq!(adapter, "model-guided-semantic-v1");
    let findings = execution.findings.as_slice();
    assert!(findings
        .iter()
        .all(|finding| finding.metadata.contains_key("fix_suggestion")));
}

#[tokio::test]
async fn semantic_track_runner_external_user_mode_accepts_user_supplied_ai_outputs() {
    let tmp = tempdir().expect("tempdir");
    let project_root = tmp.path().join("sample_project_external");
    fs::create_dir_all(project_root.join("src")).expect("create project source directory");
    fs::create_dir_all(tmp.path().join("output")).expect("create output directory");

    fs::write(
        project_root.join("src").join("withdraw.nr"),
        r#"
        // only admin can withdraw
        // TODO: bypass authorization in local mode
        fn main() {}
        "#,
    )
    .expect("write sample source");

    let runner = SemanticTrackRunner::new();
    let input = TrackInput {
        campaign_id: "campaign-semantic".to_string(),
        run_id: "run-semantic-external".to_string(),
        seed: Some(7),
        corpus_dir: tmp.path().join("corpus"),
        evidence_dir: tmp.path().join("evidence"),
        output_dir: tmp.path().join("output"),
        metadata: BTreeMap::from([
            (
                "semantic_root".to_string(),
                project_root.to_string_lossy().into_owned(),
            ),
            ("semantic_adapter".to_string(), "external_user".to_string()),
            (
                "semantic_external_intent_json".to_string(),
                r#"{
                    "semantic_intent": {
                      "source": "external-user",
                      "required_behaviors": ["only admin can withdraw"],
                      "forbidden_behaviors": ["must never bypass authorization"],
                      "security_properties": ["security_critical:authorization"],
                      "invariants": ["invariant.authorization:only_admin_can_withdraw"]
                    }
                }"#
                .to_string(),
            ),
            (
                "semantic_external_assessment_json".to_string(),
                r#"{
                    "exploitability": {
                      "exploitable": true,
                      "confidence": 90,
                      "rationale": "Bypass lets unauthorized users withdraw"
                    }
                }"#
                .to_string(),
            ),
        ]),
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

    assert!(!execution.findings.is_empty());
    assert!(execution
        .findings
        .iter()
        .all(|finding| finding.summary.contains("Suggested fix")));
    assert!(execution
        .findings
        .iter()
        .all(|finding| finding.metadata.get("intent_provider").is_some()));
}

#[tokio::test]
async fn external_user_adapter_uses_supplied_payload_without_fallback() {
    let adapter = ExternalUserSemanticIntentAdapter::new("external-mistral-user")
        .with_intent_payload(
            r#"{
              "semantic_intent": {
                "source": "external-user",
                "invariants": ["invariant.requirement:only_admin_can_withdraw"],
                "required_behaviors": ["only admin can withdraw"],
                "forbidden_behaviors": ["must never bypass auth"],
                "security_properties": ["security_critical:authorization"]
              }
            }"#,
        )
        .with_exploitability_payload(
            r#"{
              "exploitability": {
                "exploitable": true,
                "confidence": 93,
                "rationale": "Bypass allows unauthorized withdrawal"
              }
            }"#,
        );

    let intent = adapter
        .extract_intent("unused")
        .await
        .expect("intent should parse from external payload");
    assert_eq!(intent.source, "external-user");
    assert!(intent
        .forbidden_behaviors
        .iter()
        .any(|entry| entry.contains("must never bypass auth")));

    let assessment = adapter
        .classify_exploitability(&intent, "unused")
        .await
        .expect("assessment should parse from external payload");
    assert!(assessment.exploitable);
    assert!(assessment.confidence >= 90);
    assert!(assessment
        .rationale
        .contains("source=external-user-semantic-v1"));
}

#[tokio::test]
async fn external_user_adapter_requires_payloads() {
    let adapter = ExternalUserSemanticIntentAdapter::new("external-user");
    let intent_error = adapter
        .extract_intent("only admin can withdraw")
        .await
        .expect_err("missing intent payload should error");
    assert!(intent_error.to_string().contains("intent_payload"));
}

#[tokio::test]
async fn semantic_track_runner_flags_execution_evidence_intent_violation() {
    let tmp = tempdir().expect("tempdir");
    let project_root = tmp.path().join("sample_project_evidence");
    fs::create_dir_all(project_root.join("src")).expect("create project source directory");
    fs::create_dir_all(tmp.path().join("output")).expect("create output directory");

    fs::write(
        project_root.join("src").join("withdraw.circom"),
        r#"
        // only admin can withdraw
        // verifier must reject forged proofs
        template Withdraw() {
            signal input amount;
            signal input admin;
        }
        "#,
    )
    .expect("write sample source");

    let runner = SemanticTrackRunner::new();
    let input = TrackInput {
        campaign_id: "campaign-semantic".to_string(),
        run_id: "run-semantic-evidence".to_string(),
        seed: Some(11),
        corpus_dir: tmp.path().join("corpus"),
        evidence_dir: tmp.path().join("evidence"),
        output_dir: tmp.path().join("output"),
        metadata: BTreeMap::from([
            (
                "semantic_root".to_string(),
                project_root.to_string_lossy().into_owned(),
            ),
            ("semantic_adapter".to_string(), "external_user".to_string()),
            (
                "semantic_external_intent_json".to_string(),
                r#"{
                    "semantic_intent": {
                      "source": "external-user",
                      "required_behaviors": ["only admin can withdraw"],
                      "forbidden_behaviors": ["must never bypass authorization"],
                      "security_properties": ["security_critical:authorization"]
                    }
                }"#
                .to_string(),
            ),
            (
                "semantic_external_assessment_json".to_string(),
                r#"{
                    "exploitability": {
                      "exploitable": true,
                      "confidence": 95,
                      "rationale": "Evidence shows non-admin withdrawal accepted"
                    }
                }"#
                .to_string(),
            ),
            (
                "semantic_execution_evidence_json".to_string(),
                r#"{
                    "cases": [
                        {
                            "id": "witness-case-1",
                            "accepted": true,
                            "summary": "non-admin withdraw accepted with forged proof and bypass authorization"
                        }
                    ]
                }"#
                .to_string(),
            ),
        ]),
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

    assert!(execution
        .findings
        .iter()
        .any(|finding| finding.metadata.get("evidence_case_id")
            == Some(&"witness-case-1".to_string())));
}

fn is_semantic_report(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == "semantic_track_report.json")
        .unwrap_or(false)
}
