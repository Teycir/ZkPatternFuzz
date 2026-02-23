use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use async_trait::async_trait;
use tempfile::tempdir;
use zk_postroadmap_core::{PostRoadmapResult, TrackInput, TrackRunner};
use zk_track_semantic::{
    ExploitabilityAssessment, ExternalUserSemanticIntentAdapter,
    HeuristicAugmentedSemanticIntentAdapter, HeuristicSemanticIntentAdapter, SemanticIntent,
    SemanticIntentAdapter, SemanticTrackRunner,
};

#[derive(Debug, Default)]
struct NonExploitableHighConfidenceAdapter;

#[async_trait]
impl SemanticIntentAdapter for NonExploitableHighConfidenceAdapter {
    fn provider_name(&self) -> &'static str {
        "non-exploitable-high-confidence-test-adapter"
    }

    async fn extract_intent(&self, source_text: &str) -> PostRoadmapResult<SemanticIntent> {
        if source_text.trim().is_empty() {
            return Ok(SemanticIntent {
                source: self.provider_name().to_string(),
                ..SemanticIntent::default()
            });
        }
        Ok(SemanticIntent {
            source: self.provider_name().to_string(),
            required_behaviors: vec!["verifier must reject unauthorized operations".to_string()],
            forbidden_behaviors: vec!["must never bypass authorization".to_string()],
            security_properties: vec!["authorization".to_string()],
            invariants: vec!["invariant.authorization:no_bypass".to_string()],
        })
    }

    async fn classify_exploitability(
        &self,
        _intent: &SemanticIntent,
        _violation_summary: &str,
    ) -> PostRoadmapResult<ExploitabilityAssessment> {
        Ok(ExploitabilityAssessment {
            exploitable: false,
            confidence: 80,
            rationale: "non-exploitable test fixture".to_string(),
        })
    }
}

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
async fn heuristic_augmented_adapter_synthesizes_formal_invariants() {
    let adapter = HeuristicAugmentedSemanticIntentAdapter::new("mistral-large")
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
            (
                "semantic_adapter".to_string(),
                "heuristic_augmented".to_string(),
            ),
            (
                "semantic_guidance_label".to_string(),
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
    assert_eq!(adapter, "heuristic-augmented-semantic-v1");
    let findings = execution.findings.as_slice();
    assert!(findings
        .iter()
        .all(|finding| finding.metadata.contains_key("fix_suggestion")));
    let ai_bundle_path = emitted_paths
        .iter()
        .find(|path| is_ai_bundle(path))
        .expect("expected AI ingest bundle path");
    let ai_bundle_json = fs::read_to_string(ai_bundle_path).expect("read AI ingest bundle");
    let ai_bundle_value: serde_json::Value =
        serde_json::from_str(&ai_bundle_json).expect("parse AI ingest bundle JSON");
    assert_eq!(ai_bundle_value["mode"], "output_only_for_external_ai");
    assert!(ai_bundle_value["instructions"]
        .as_str()
        .expect("instructions string")
        .contains("does not ingest AI responses"));
    let ai_worklist_path = emitted_paths
        .iter()
        .find(|path| is_ai_exploitability_worklist(path))
        .expect("expected AI exploitability worklist path");
    let ai_worklist_json =
        fs::read_to_string(ai_worklist_path).expect("read AI exploitability worklist");
    let ai_worklist_value: serde_json::Value =
        serde_json::from_str(&ai_worklist_json).expect("parse AI exploitability worklist JSON");
    assert_eq!(ai_worklist_value["mode"], "output_only_for_external_ai");
    assert!(
        ai_worklist_value["exploitability_tasks"]
            .as_array()
            .expect("exploitability_tasks as array")
            .len()
            >= 1
    );
    assert!(
        ai_worklist_value["poc_generation_tasks"]
            .as_array()
            .expect("poc_generation_tasks as array")
            .len()
            >= 1
    );
    assert!(ai_worklist_value["instructions"]
        .as_str()
        .expect("instructions string")
        .contains("does not ingest AI responses"));
    let actionable_report_path = emitted_paths
        .iter()
        .find(|path| is_semantic_actionable_report(path))
        .expect("expected semantic actionable report path");
    let actionable_report_json =
        fs::read_to_string(actionable_report_path).expect("read semantic actionable report");
    let actionable_report_value: serde_json::Value =
        serde_json::from_str(&actionable_report_json).expect("parse semantic actionable report");
    assert_eq!(
        actionable_report_value["mode"],
        "output_only_for_external_ai"
    );
    let actionable_findings = actionable_report_value["findings"]
        .as_array()
        .expect("findings as array");
    assert!(!actionable_findings.is_empty());
    assert!(
        actionable_findings[0]["fix_suggestion"]
            .as_str()
            .expect("fix_suggestion as str")
            .contains("enforce")
            || actionable_findings[0]["fix_suggestion"]
                .as_str()
                .expect("fix_suggestion as str")
                .contains("Replace")
            || actionable_findings[0]["fix_suggestion"]
                .as_str()
                .expect("fix_suggestion as str")
                .contains("Add")
    );
}

#[tokio::test]
async fn semantic_track_runner_rejects_external_user_adapter_in_producer_only_mode() {
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
    let error = runner
        .run(&input)
        .await
        .expect_err("external adapter should be disabled in producer-only mode");
    assert!(error
        .to_string()
        .contains("producer-only mode: semantic runner does not ingest external AI payloads"));
}

#[tokio::test]
async fn external_user_adapter_uses_supplied_payload_without_recovery() {
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

#[tokio::test]
async fn semantic_track_runner_rejects_multiple_explicit_intent_adapters() {
    let tmp = tempdir().expect("tempdir");
    let project_root = tmp.path().join("sample_project_multi_adapter");
    fs::create_dir_all(project_root.join("src")).expect("create project source directory");
    fs::create_dir_all(tmp.path().join("output")).expect("create output directory");

    fs::write(
        project_root.join("src").join("withdraw.circom"),
        r#"
        // only admin can withdraw
        template Withdraw() {
            // TODO: bypass auth checks
            signal input amount;
        }
        "#,
    )
    .expect("write sample source");

    let runner = SemanticTrackRunner::new()
        .with_intent_adapter(Box::new(HeuristicSemanticIntentAdapter))
        .with_intent_adapter(Box::new(HeuristicAugmentedSemanticIntentAdapter::new(
            "mistral",
        )));
    let input = TrackInput {
        campaign_id: "campaign-semantic".to_string(),
        run_id: "run-semantic-multi-adapter".to_string(),
        seed: Some(17),
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
    let error = runner
        .run(&input)
        .await
        .expect_err("multiple explicit adapters must be rejected");
    assert!(error
        .to_string()
        .contains("supports exactly one explicit intent adapter"));
}

#[tokio::test]
async fn semantic_track_runner_keeps_non_exploitable_high_confidence_findings_low_severity() {
    let tmp = tempdir().expect("tempdir");
    let project_root = tmp.path().join("sample_project_low_severity");
    fs::create_dir_all(project_root.join("src")).expect("create project source directory");
    fs::create_dir_all(tmp.path().join("output")).expect("create output directory");

    fs::write(
        project_root.join("README.md"),
        "Only admin can withdraw and verifier must reject unauthorized actions.\n",
    )
    .expect("write readme");
    fs::write(
        project_root.join("src").join("withdraw.circom"),
        r#"
        // TODO: temporary bypass guard for local debug
        template Withdraw() {
            signal input amount;
        }
        "#,
    )
    .expect("write sample source");

    let runner = SemanticTrackRunner::new()
        .with_intent_adapter(Box::new(NonExploitableHighConfidenceAdapter));
    let input = TrackInput {
        campaign_id: "campaign-semantic".to_string(),
        run_id: "run-semantic-low-severity".to_string(),
        seed: Some(19),
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
    assert!(!execution.findings.is_empty());
    assert!(execution.findings.iter().all(|finding| {
        finding.severity == zk_postroadmap_core::FindingSeverity::Low
            && finding
                .metadata
                .get("exploitable")
                .map(|value| value == "false")
                .unwrap_or(false)
    }));
    runner
        .validate(&execution)
        .await
        .expect("single non-exploitable finding should stay within FP budget");
}

#[tokio::test]
async fn semantic_track_runner_false_positive_budget_can_fail_validation() {
    let tmp = tempdir().expect("tempdir");
    let project_root = tmp.path().join("sample_project_fp_budget");
    fs::create_dir_all(project_root.join("src")).expect("create project source directory");
    fs::create_dir_all(tmp.path().join("output")).expect("create output directory");

    fs::write(
        project_root.join("README.md"),
        "Only admin can withdraw and verifier must reject unauthorized actions.\n",
    )
    .expect("write readme");
    for index in 0..3 {
        fs::write(
            project_root
                .join("src")
                .join(format!("withdraw_{index}.circom")),
            r#"
            // TODO: temporary bypass guard for local debug
            template Withdraw() {
                signal input amount;
            }
            "#,
        )
        .expect("write sample source");
    }

    let runner = SemanticTrackRunner::new()
        .with_intent_adapter(Box::new(NonExploitableHighConfidenceAdapter));
    let input = TrackInput {
        campaign_id: "campaign-semantic".to_string(),
        run_id: "run-semantic-fp-budget".to_string(),
        seed: Some(23),
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
    let error = runner
        .validate(&execution)
        .await
        .expect_err("false-positive budget should fail when too many non-exploitable findings");
    assert!(error
        .to_string()
        .contains("semantic false-positive budget exceeded"));
}

#[tokio::test]
async fn semantic_track_runner_ignores_markers_outside_intent_text_scope() {
    let tmp = tempdir().expect("tempdir");
    let project_root = tmp.path().join("sample_project_marker_scope");
    fs::create_dir_all(project_root.join("src")).expect("create project source directory");
    fs::create_dir_all(tmp.path().join("output")).expect("create output directory");

    fs::write(
        project_root.join("README.md"),
        "Only admin can withdraw and verifier must reject unauthorized actions.\n",
    )
    .expect("write readme");
    fs::write(
        project_root.join("src").join("withdraw.circom"),
        r#"
        template Withdraw() {
            signal input amount;
            signal output flagged;
            flagged <== amount + 1;
            // No comments with suspicious markers here.
            var marker = "TODO bypass auth in string literal only";
        }
        "#,
    )
    .expect("write sample source");

    let runner = SemanticTrackRunner::new()
        .with_intent_adapter(Box::new(NonExploitableHighConfidenceAdapter));
    let input = TrackInput {
        campaign_id: "campaign-semantic".to_string(),
        run_id: "run-semantic-marker-scope".to_string(),
        seed: Some(29),
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
    assert!(
        execution.findings.is_empty(),
        "markers from non-comment code literals should not trigger findings"
    );
}

fn is_semantic_report(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == "semantic_track_report.json")
        .unwrap_or(false)
}

fn is_ai_bundle(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == "ai_ingest_bundle.json")
        .unwrap_or(false)
}

fn is_ai_exploitability_worklist(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == "ai_exploitability_worklist.json")
        .unwrap_or(false)
}

fn is_semantic_actionable_report(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == "semantic_actionable_report.json")
        .unwrap_or(false)
}
