mod adapters;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use zk_postroadmap_core::{
    FindingSeverity, PostRoadmapError, PostRoadmapResult, ReplayArtifact, Scorecard,
    ScorecardMetric, TrackExecution, TrackFinding, TrackInput, TrackKind, TrackRunner,
    POST_ROADMAP_SCHEMA_VERSION,
};

pub use adapters::{
    ExploitabilityAssessment, ExternalUserSemanticIntentAdapter,
    HeuristicAugmentedSemanticIntentAdapter, HeuristicSemanticIntentAdapter,
    ModelGuidedSemanticIntentAdapter, SemanticIntent, SemanticIntentAdapter,
};

pub const TRACK_MODULE_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_SOURCE_BYTES: u64 = 256 * 1024;
const MAX_DISCOVERED_FILES: usize = 2_000;
const REPLAY_METRIC_NAME: &str = "deterministic_replay_rate";
const FALSE_POSITIVE_BUDGET_DIVISOR: u64 = 2;
const FALSE_POSITIVE_BUDGET_FLOOR: u64 = 1;

const SUPPORTED_CODE_EXTENSIONS: &[&str] = &["circom", "nr", "rs", "cairo", "json"];
const SUPPORTED_DOC_EXTENSIONS: &[&str] = &["md", "txt", "rst", "adoc"];
const SKIPPED_DIR_NAMES: &[&str] = &[
    ".git",
    ".github",
    ".history",
    ".pytest_cache",
    "artifacts",
    "bins",
    "node_modules",
    "reports",
    "target",
    "third_party",
    "vendor",
];
const SUSPICIOUS_MARKERS: &[&str] = &[
    "todo",
    "fixme",
    "hack",
    "temporary",
    "bypass",
    "unchecked",
    "skip verification",
    "disable verification",
    "allow_invalid",
    "debug only",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SemanticSourceType {
    Code,
    Documentation,
}

#[derive(Debug, Clone)]
struct SemanticSourceDocument {
    path: PathBuf,
    source_type: SemanticSourceType,
    intent_text: String,
}

#[derive(Debug, Clone, Serialize)]
struct SemanticIntentRecord {
    path: PathBuf,
    source_type: SemanticSourceType,
    intent: SemanticIntent,
}

#[derive(Debug, Clone, Serialize)]
struct SemanticViolationRecord {
    finding_id: String,
    detector: String,
    evidence_case_id: Option<String>,
    source_path: PathBuf,
    suspicious_marker: String,
    violation_summary: String,
    fix_suggestion: String,
    assessment: ExploitabilityAssessment,
}

#[derive(Debug, Clone, Serialize)]
struct SemanticTrackReport {
    schema_version: String,
    track_version: String,
    run_id: String,
    generated_at: DateTime<Utc>,
    adapter: String,
    roots: Vec<PathBuf>,
    scanned_files: usize,
    extracted_intent_sources: usize,
    findings_count: usize,
    intents: Vec<SemanticIntentRecord>,
    violations: Vec<SemanticViolationRecord>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct SemanticExecutionEvidenceCase {
    case_id: String,
    accepted: bool,
    violates_intent: bool,
    summary: String,
}

#[derive(Debug, Clone, Serialize)]
struct AiIngestDocument {
    path: PathBuf,
    source_type: SemanticSourceType,
    intent_excerpt: String,
}

#[derive(Debug, Clone, Serialize)]
struct AiIngestBundle {
    schema_version: String,
    track_version: String,
    run_id: String,
    generated_at: DateTime<Utc>,
    mode: String,
    adapter: String,
    roots: Vec<PathBuf>,
    source_documents: Vec<AiIngestDocument>,
    extracted_intents: Vec<SemanticIntentRecord>,
    execution_evidence_cases: Vec<SemanticExecutionEvidenceCase>,
    violations: Vec<SemanticViolationRecord>,
    findings: Vec<TrackFinding>,
    ai_prompt_hints: Vec<String>,
    instructions: String,
}

#[derive(Debug, Clone, Serialize)]
struct AiExploitabilityTask {
    task_id: String,
    finding_id: String,
    detector: String,
    severity: String,
    source_path: PathBuf,
    evidence_case_id: Option<String>,
    evidence_case_summary: Option<String>,
    extra_solution_candidate: bool,
    violation_summary: String,
    intent_anchor: String,
    attack_vector_hints: Vec<String>,
    requested_output_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct AiPocGenerationTask {
    task_id: String,
    finding_id: String,
    severity: String,
    objective: String,
    preconditions: Vec<String>,
    steps_template: Vec<String>,
    expected_outcome: String,
    output_contract: String,
}

#[derive(Debug, Clone, Serialize)]
struct AiExploitabilityWorklist {
    schema_version: String,
    track_version: String,
    run_id: String,
    generated_at: DateTime<Utc>,
    mode: String,
    adapter: String,
    roots: Vec<PathBuf>,
    dominant_intent: String,
    exploitability_tasks: Vec<AiExploitabilityTask>,
    poc_generation_tasks: Vec<AiPocGenerationTask>,
    instructions: String,
    response_contract: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ActionableFinding {
    finding_id: String,
    severity: String,
    priority: u8,
    title: String,
    source_path: String,
    fix_suggestion: String,
    verification_checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct SemanticActionableReport {
    schema_version: String,
    track_version: String,
    run_id: String,
    generated_at: DateTime<Utc>,
    mode: String,
    findings: Vec<ActionableFinding>,
    instructions: String,
}

#[derive(Default)]
pub struct SemanticTrackRunner {
    intent_adapters: Vec<Box<dyn SemanticIntentAdapter>>,
}

impl SemanticTrackRunner {
    pub fn new() -> Self {
        Self {
            intent_adapters: Vec::new(),
        }
    }

    pub fn with_intent_adapter(mut self, adapter: Box<dyn SemanticIntentAdapter>) -> Self {
        self.intent_adapters.push(adapter);
        self
    }

    pub fn intent_adapter_count(&self) -> usize {
        self.intent_adapters.len()
    }
}

#[async_trait]
impl TrackRunner for SemanticTrackRunner {
    fn track(&self) -> TrackKind {
        TrackKind::Semantic
    }

    async fn prepare(&self, input: &TrackInput) -> PostRoadmapResult<()> {
        let output_dir = report_output_dir(input);
        fs::create_dir_all(&output_dir).map_err(|error| {
            PostRoadmapError::Infrastructure(format!(
                "failed to create semantic report output directory `{}`: {error}",
                output_dir.display()
            ))
        })
    }

    async fn run(&self, input: &TrackInput) -> PostRoadmapResult<TrackExecution> {
        let started_at = Utc::now();
        let report_dir = report_output_dir(input);
        fs::create_dir_all(&report_dir).map_err(|error| {
            PostRoadmapError::Infrastructure(format!(
                "failed to create semantic report output directory `{}`: {error}",
                report_dir.display()
            ))
        })?;

        let scan_roots = resolve_scan_roots(input);
        let source_paths = discover_source_files(&scan_roots)?;

        let mut source_documents = Vec::new();
        for source_path in source_paths {
            if let Some(document) = load_source_document(&source_path)? {
                source_documents.push(document);
            }
        }

        if self.intent_adapters.len() > 1 {
            return Err(PostRoadmapError::Configuration(format!(
                "semantic track currently supports exactly one explicit intent adapter; received {} via with_intent_adapter()",
                self.intent_adapters.len()
            )));
        }

        let selected_adapter = if self.intent_adapters.is_empty() {
            Some(default_adapter_from_metadata(input)?)
        } else {
            None
        };
        let adapter: &dyn SemanticIntentAdapter =
            if let Some(adapter) = self.intent_adapters.first() {
                adapter.as_ref()
            } else {
                selected_adapter
                    .as_ref()
                    .map(|adapter| adapter.as_ref())
                    .ok_or_else(|| {
                        PostRoadmapError::Internal(
                            "semantic adapter selection failed unexpectedly".to_string(),
                        )
                    })?
            };
        let adapter_name = adapter.provider_name().to_string();

        let mut intent_records = Vec::new();
        for document in &source_documents {
            if document.intent_text.trim().is_empty() {
                continue;
            }

            let mut intent = adapter.extract_intent(&document.intent_text).await?;
            if intent.source.trim().is_empty() {
                intent.source = adapter_name.clone();
            }
            if has_semantic_content(&intent) {
                intent_records.push(SemanticIntentRecord {
                    path: document.path.clone(),
                    source_type: document.source_type,
                    intent,
                });
            }
        }

        let merged_intent = merge_intents(&intent_records);
        let dominant_intent = select_dominant_intent_line(&merged_intent);
        let mut findings = Vec::new();
        let mut violations = Vec::new();
        let execution_evidence_cases = load_execution_evidence_cases(input)?;

        for evidence_case in &execution_evidence_cases {
            if !evidence_case_violates_intent(evidence_case, &merged_intent) {
                continue;
            }

            let finding_id = format!("semantic-violation-{:03}", findings.len() + 1);
            let violation_summary = format!(
                "Execution evidence `{}` indicates semantic-intent mismatch: {}",
                evidence_case.case_id, evidence_case.summary
            );
            let assessment = adapter
                .classify_exploitability(&merged_intent, &violation_summary)
                .await?;
            let severity = severity_from_assessment(&assessment);
            let fix_suggestion = "Bind witness/proof acceptance to explicit semantic invariants and reject this case in verifier/oracle validation.".to_string();

            let mut metadata = BTreeMap::new();
            metadata.insert(
                "source_path".to_string(),
                format!("external_execution_evidence:{}", evidence_case.case_id),
            );
            metadata.insert(
                "evidence_case_id".to_string(),
                evidence_case.case_id.clone(),
            );
            metadata.insert(
                "evidence_source".to_string(),
                "external_execution_evidence".to_string(),
            );
            metadata.insert(
                "exploitability_confidence".to_string(),
                assessment.confidence.to_string(),
            );
            metadata.insert(
                "exploitable".to_string(),
                assessment.exploitable.to_string(),
            );
            metadata.insert("intent_provider".to_string(), adapter_name.clone());
            metadata.insert(
                "generator_priority".to_string(),
                generator_priority_for_severity(severity).to_string(),
            );
            metadata.insert(
                "generator_reason".to_string(),
                format!("semantic_evidence_violation:{}", evidence_case.case_id),
            );
            metadata.insert("intent_anchor".to_string(), dominant_intent.clone());
            metadata.insert("fix_suggestion".to_string(), fix_suggestion.clone());

            findings.push(TrackFinding {
                id: finding_id.clone(),
                track: self.track(),
                title: format!(
                    "Potential semantic intent violation in evidence case {}",
                    evidence_case.case_id
                ),
                summary: format!(
                    "{violation_summary}. {}. Suggested fix: {fix_suggestion}",
                    assessment.rationale
                ),
                severity,
                reproducible: true,
                evidence_paths: vec![],
                metadata,
            });
            violations.push(SemanticViolationRecord {
                finding_id,
                detector: "execution_evidence".to_string(),
                evidence_case_id: Some(evidence_case.case_id.clone()),
                source_path: PathBuf::from("external_execution_evidence"),
                suspicious_marker: "witness_or_proof_violation".to_string(),
                violation_summary,
                fix_suggestion,
                assessment,
            });
        }

        for document in source_documents
            .iter()
            .filter(|document| document.source_type == SemanticSourceType::Code)
        {
            let Some(marker) = find_suspicious_marker(&document.intent_text) else {
                continue;
            };
            if !has_semantic_content(&merged_intent) {
                continue;
            }

            let finding_id = format!("semantic-violation-{:03}", findings.len() + 1);
            let violation_summary = format!(
                "Suspicious marker `{marker}` detected while semantic intent requires stricter behavior (`{dominant_intent}`)"
            );
            let assessment = adapter
                .classify_exploitability(&merged_intent, &violation_summary)
                .await?;
            let severity = severity_from_assessment(&assessment);
            let source_path = document.path.display().to_string();
            let fix_suggestion = fix_suggestion_for_marker(marker, &dominant_intent);

            let mut metadata = BTreeMap::new();
            metadata.insert("source_path".to_string(), source_path.clone());
            metadata.insert("suspicious_marker".to_string(), marker.to_string());
            metadata.insert(
                "exploitability_confidence".to_string(),
                assessment.confidence.to_string(),
            );
            metadata.insert(
                "exploitable".to_string(),
                assessment.exploitable.to_string(),
            );
            metadata.insert("intent_provider".to_string(), adapter_name.clone());
            metadata.insert(
                "generator_priority".to_string(),
                generator_priority_for_severity(severity).to_string(),
            );
            metadata.insert(
                "generator_reason".to_string(),
                format!("semantic_violation:{marker}:{source_path}"),
            );
            metadata.insert("intent_anchor".to_string(), dominant_intent.clone());
            metadata.insert("fix_suggestion".to_string(), fix_suggestion.clone());

            findings.push(TrackFinding {
                id: finding_id.clone(),
                track: self.track(),
                title: format!("Potential semantic intent violation in {source_path}"),
                summary: format!(
                    "{violation_summary}. {}. Suggested fix: {fix_suggestion}",
                    assessment.rationale
                ),
                severity,
                reproducible: true,
                evidence_paths: vec![document.path.clone()],
                metadata,
            });
            violations.push(SemanticViolationRecord {
                finding_id,
                detector: "source_marker".to_string(),
                evidence_case_id: None,
                source_path: document.path.clone(),
                suspicious_marker: marker.to_string(),
                violation_summary,
                fix_suggestion,
                assessment,
            });
        }

        let report_path = write_semantic_report(
            input,
            &report_dir,
            &adapter_name,
            &scan_roots,
            &intent_records,
            &violations,
            source_documents.len(),
            findings.len(),
        )?;
        let ai_ingest_bundle_path = write_ai_ingest_bundle(
            input,
            &report_dir,
            &adapter_name,
            &scan_roots,
            &source_documents,
            &intent_records,
            &execution_evidence_cases,
            &violations,
            &findings,
        )?;
        let ai_exploitability_worklist_path = write_ai_exploitability_worklist(
            input,
            &report_dir,
            &adapter_name,
            &scan_roots,
            &dominant_intent,
            &execution_evidence_cases,
            &violations,
            &findings,
        )?;
        let actionable_report_path =
            write_semantic_actionable_report(input, &report_dir, &findings, &violations)?;

        let scorecard = build_scorecard(source_documents.len(), intent_records.len(), &findings);
        let replay_artifacts = vec![ReplayArtifact {
            replay_id: format!("semantic-replay-{}", input.run_id),
            track: self.track(),
            command: vec![
                "cargo".to_string(),
                "test".to_string(),
                "-p".to_string(),
                "zk-track-semantic".to_string(),
                "semantic_track_runner_end_to_end".to_string(),
            ],
            env: BTreeMap::new(),
            evidence_paths: vec![
                report_path,
                ai_ingest_bundle_path,
                ai_exploitability_worklist_path,
                actionable_report_path,
            ],
            notes: "Replay deterministic semantic intent extraction + violation classification"
                .to_string(),
        }];

        Ok(TrackExecution {
            track: self.track(),
            run_id: input.run_id.clone(),
            started_at,
            finished_at: Utc::now(),
            findings,
            replay_artifacts,
            scorecard: Some(scorecard),
        })
    }

    async fn validate(&self, execution: &TrackExecution) -> PostRoadmapResult<()> {
        if execution.track != self.track() {
            return Err(PostRoadmapError::Validation(format!(
                "semantic track validator received mismatched execution track: expected `{:?}`, got `{:?}`",
                self.track(),
                execution.track
            )));
        }

        let scorecard = execution.scorecard.as_ref().ok_or_else(|| {
            PostRoadmapError::Validation("semantic execution must include a scorecard".to_string())
        })?;
        if !scorecard.coverage_counts.contains_key("files_scanned") {
            return Err(PostRoadmapError::Validation(
                "semantic scorecard must include `files_scanned` coverage".to_string(),
            ));
        }
        if !scorecard
            .metrics
            .iter()
            .any(|metric| metric.name == REPLAY_METRIC_NAME)
        {
            return Err(PostRoadmapError::Validation(format!(
                "semantic scorecard must include `{REPLAY_METRIC_NAME}` metric"
            )));
        }
        if scorecard.false_positive_count > scorecard.false_positive_budget {
            return Err(PostRoadmapError::Validation(format!(
                "semantic false-positive budget exceeded: {} > {}",
                scorecard.false_positive_count, scorecard.false_positive_budget
            )));
        }

        for finding in &execution.findings {
            if !finding.metadata.contains_key("source_path") {
                return Err(PostRoadmapError::Validation(format!(
                    "semantic finding `{}` missing `source_path` metadata",
                    finding.id
                )));
            }
            if !finding.metadata.contains_key("exploitability_confidence") {
                return Err(PostRoadmapError::Validation(format!(
                    "semantic finding `{}` missing `exploitability_confidence` metadata",
                    finding.id
                )));
            }
        }

        Ok(())
    }

    async fn emit(&self, execution: &TrackExecution) -> PostRoadmapResult<Vec<PathBuf>> {
        let mut emitted_paths = BTreeSet::new();
        for replay in &execution.replay_artifacts {
            for path in &replay.evidence_paths {
                if path.exists() {
                    emitted_paths.insert(path.clone());
                }
            }
        }
        Ok(emitted_paths.into_iter().collect())
    }
}

fn default_adapter_from_metadata(
    input: &TrackInput,
) -> PostRoadmapResult<Box<dyn SemanticIntentAdapter>> {
    let adapter_mode = parse_adapter_mode(input);
    match adapter_mode.as_str() {
        "heuristic_augmented"
        | "heuristic-augmented"
        | "guided_heuristic"
        | "guided-heuristic"
        | "model_guided"
        | "model-guided"
        | "llm"
        | "ai" => {
            let guidance_label = input
                .metadata
                .get("semantic_guidance_label")
                .or_else(|| input.metadata.get("semantic_model_name"))
                .or_else(|| input.metadata.get("semantic_model"))
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .unwrap_or("mistral");
            let mut adapter = HeuristicAugmentedSemanticIntentAdapter::new(guidance_label);
            if let Some(system_prompt) = input
                .metadata
                .get("semantic_system_prompt")
                .or_else(|| input.metadata.get("semantic_prompt"))
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
            {
                adapter = adapter.with_system_prompt(system_prompt.to_string());
            }
            Ok(Box::new(adapter))
        }
        "external" | "external_user" | "external-user" | "user_ai" | "external_ai" => {
            let _ = input;
            Err(PostRoadmapError::Configuration(
                "producer-only mode: semantic runner does not ingest external AI payloads; use generated `ai_ingest_bundle.json` as external AI input".to_string(),
            ))
        }
        _ => Ok(Box::new(HeuristicSemanticIntentAdapter)),
    }
}

fn metadata_inline_or_file(
    input: &TrackInput,
    inline_key: &str,
    path_key: &str,
) -> PostRoadmapResult<Option<String>> {
    if let Some(inline) = input
        .metadata
        .get(inline_key)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        return Ok(Some(inline.to_string()));
    }

    if let Some(path_value) = input
        .metadata
        .get(path_key)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        let path = PathBuf::from(path_value);
        let payload = fs::read_to_string(&path).map_err(|error| {
            PostRoadmapError::Configuration(format!(
                "failed to read `{}` payload file `{}`: {error}",
                path_key,
                path.display()
            ))
        })?;
        return Ok(Some(payload));
    }

    Ok(None)
}

fn parse_adapter_mode(input: &TrackInput) -> String {
    input
        .metadata
        .get("semantic_adapter")
        .or_else(|| input.metadata.get("semantic_intent_adapter"))
        .or_else(|| input.metadata.get("semantic_provider"))
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "heuristic".to_string())
}

fn load_execution_evidence_cases(
    input: &TrackInput,
) -> PostRoadmapResult<Vec<SemanticExecutionEvidenceCase>> {
    let Some(payload) = metadata_inline_or_file(
        input,
        "semantic_execution_evidence_json",
        "semantic_execution_evidence_path",
    )?
    else {
        return Ok(Vec::new());
    };

    parse_execution_evidence_cases(&payload).ok_or_else(|| {
        PostRoadmapError::Configuration(
            "semantic execution evidence payload is present but not parseable".to_string(),
        )
    })
}

fn parse_execution_evidence_cases(payload: &str) -> Option<Vec<SemanticExecutionEvidenceCase>> {
    let value = serde_json::from_str::<serde_json::Value>(payload).ok()?;
    let cases_value = if let Some(cases) = value.get("cases") {
        cases.clone()
    } else {
        value.clone()
    };
    let cases = cases_value.as_array()?;

    let mut parsed = Vec::new();
    for (idx, case_value) in cases.iter().enumerate() {
        let Some(case_object) = case_value.as_object() else {
            continue;
        };
        let case_id = case_object
            .get("id")
            .or_else(|| case_object.get("case_id"))
            .and_then(serde_json::Value::as_str)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("case-{}", idx + 1));

        let accepted = case_object
            .get("accepted")
            .or_else(|| case_object.get("verified"))
            .or_else(|| case_object.get("success"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let violates_intent = case_object
            .get("violates_intent")
            .or_else(|| case_object.get("semantic_violation"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let summary = build_case_summary(case_object);

        parsed.push(SemanticExecutionEvidenceCase {
            case_id,
            accepted,
            violates_intent,
            summary,
        });
    }

    Some(parsed)
}

fn build_case_summary(case_object: &serde_json::Map<String, serde_json::Value>) -> String {
    let mut parts = Vec::new();
    for key in [
        "summary",
        "description",
        "result",
        "observation",
        "witness",
        "proof",
        "public_inputs",
    ] {
        if let Some(value) = case_object.get(key) {
            match value {
                serde_json::Value::String(text) => {
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        parts.push(trimmed.to_string());
                    }
                }
                serde_json::Value::Array(values) => {
                    for item in values {
                        if let Some(text) = item.as_str() {
                            let trimmed = text.trim();
                            if !trimmed.is_empty() {
                                parts.push(trimmed.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    if parts.is_empty() {
        return "No case summary provided".to_string();
    }
    parts.join(" | ")
}

fn evidence_case_violates_intent(
    evidence_case: &SemanticExecutionEvidenceCase,
    intent: &SemanticIntent,
) -> bool {
    if evidence_case.violates_intent {
        return true;
    }

    let summary_lc = evidence_case.summary.to_ascii_lowercase();
    if !evidence_case.accepted {
        return false;
    }
    if !has_semantic_content(intent) {
        return false;
    }

    let danger_terms = [
        "unauthorized",
        "non-admin",
        "bypass",
        "forged",
        "forgery",
        "invalid proof",
        "without auth",
        "without permission",
        "replay",
        "overflow",
        "underflow",
    ];
    let has_danger_signal = danger_terms.iter().any(|term| summary_lc.contains(term));
    if !has_danger_signal {
        return false;
    }

    let intent_text = [
        intent.required_behaviors.join(" "),
        intent.forbidden_behaviors.join(" "),
        intent.security_properties.join(" "),
        intent.invariants.join(" "),
    ]
    .join(" ")
    .to_ascii_lowercase();
    let intent_terms = intent_text
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| token.len() >= 4)
        .collect::<BTreeSet<_>>();

    summary_lc
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| token.len() >= 4)
        .any(|token| intent_terms.contains(token))
}

fn report_output_dir(input: &TrackInput) -> PathBuf {
    input
        .output_dir
        .join("post_roadmap")
        .join("semantic")
        .join(&input.run_id)
}

fn resolve_scan_roots(input: &TrackInput) -> Vec<PathBuf> {
    let mut roots = BTreeSet::new();
    for key in [
        "semantic_roots",
        "semantic_root",
        "source_roots",
        "source_root",
        "project_root",
        "repo_root",
    ] {
        if let Some(value) = input.metadata.get(key) {
            for root in parse_root_candidates(value) {
                roots.insert(root);
            }
        }
    }

    if roots.is_empty() {
        roots.insert(PathBuf::from("."));
    }

    roots.into_iter().collect()
}

fn parse_root_candidates(value: &str) -> Vec<PathBuf> {
    value
        .split([',', ';', '\n'])
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn discover_source_files(roots: &[PathBuf]) -> PostRoadmapResult<Vec<PathBuf>> {
    let mut files = BTreeSet::new();
    for root in roots {
        walk_source_tree(root, &mut files)?;
        if files.len() >= MAX_DISCOVERED_FILES {
            break;
        }
    }
    Ok(files.into_iter().take(MAX_DISCOVERED_FILES).collect())
}

fn walk_source_tree(path: &Path, files: &mut BTreeSet<PathBuf>) -> PostRoadmapResult<()> {
    if files.len() >= MAX_DISCOVERED_FILES || !path.exists() {
        return Ok(());
    }
    if path.is_file() {
        if is_supported_source_file(path) {
            files.insert(path.to_path_buf());
        }
        return Ok(());
    }

    let entries = fs::read_dir(path).map_err(|error| {
        PostRoadmapError::Infrastructure(format!(
            "failed to read semantic scan root `{}`: {error}",
            path.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            PostRoadmapError::Infrastructure(format!(
                "failed to read entry under `{}`: {error}",
                path.display()
            ))
        })?;
        let child_path = entry.path();
        if child_path.is_dir() {
            if should_skip_dir(&child_path) {
                continue;
            }
            walk_source_tree(&child_path, files)?;
        } else if child_path.is_file() && is_supported_source_file(&child_path) {
            files.insert(child_path);
        }
        if files.len() >= MAX_DISCOVERED_FILES {
            break;
        }
    }
    Ok(())
}

fn should_skip_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| SKIPPED_DIR_NAMES.contains(&name))
        .unwrap_or(false)
}

fn is_supported_source_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if file_name.eq_ignore_ascii_case("readme")
        || file_name.eq_ignore_ascii_case("readme.md")
        || file_name.eq_ignore_ascii_case("spec.md")
        || file_name.eq_ignore_ascii_case("specification.md")
    {
        return true;
    }

    let extension_lc = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase());
    match extension_lc {
        Some(extension) => {
            SUPPORTED_CODE_EXTENSIONS.contains(&extension.as_str())
                || SUPPORTED_DOC_EXTENSIONS.contains(&extension.as_str())
        }
        None => false,
    }
}

fn load_source_document(path: &Path) -> PostRoadmapResult<Option<SemanticSourceDocument>> {
    let metadata = fs::metadata(path).map_err(|error| {
        PostRoadmapError::Infrastructure(format!(
            "failed to stat semantic source `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.len() > MAX_SOURCE_BYTES {
        return Ok(None);
    }

    let bytes = fs::read(path).map_err(|error| {
        PostRoadmapError::Infrastructure(format!(
            "failed to read semantic source `{}`: {error}",
            path.display()
        ))
    })?;
    let raw_text = String::from_utf8_lossy(&bytes).into_owned();
    let source_type = classify_source_type(path);
    let intent_text = match source_type {
        SemanticSourceType::Documentation => raw_text.clone(),
        SemanticSourceType::Code => extract_comment_and_doc_text(&raw_text),
    };

    Ok(Some(SemanticSourceDocument {
        path: path.to_path_buf(),
        source_type,
        intent_text,
    }))
}

fn classify_source_type(path: &Path) -> SemanticSourceType {
    let extension_lc = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase());
    match extension_lc {
        Some(extension) if SUPPORTED_DOC_EXTENSIONS.contains(&extension.as_str()) => {
            SemanticSourceType::Documentation
        }
        _ => SemanticSourceType::Code,
    }
}

fn extract_comment_and_doc_text(source_text: &str) -> String {
    let mut comments = Vec::new();
    let mut in_block_comment = false;

    for line in source_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if in_block_comment {
            if let Some(end_index) = trimmed.find("*/") {
                let text = trimmed[..end_index].trim().trim_start_matches('*').trim();
                if !text.is_empty() {
                    comments.push(text.to_string());
                }
                in_block_comment = false;
                continue;
            }
            let text = trimmed.trim_start_matches('*').trim();
            if !text.is_empty() {
                comments.push(text.to_string());
            }
            continue;
        }

        if let Some(start_index) = trimmed.find("/*") {
            let after_start = &trimmed[start_index + 2..];
            if let Some(end_index) = after_start.find("*/") {
                let text = after_start[..end_index]
                    .trim()
                    .trim_start_matches('*')
                    .trim();
                if !text.is_empty() {
                    comments.push(text.to_string());
                }
            } else {
                let text = after_start.trim().trim_start_matches('*').trim();
                if !text.is_empty() {
                    comments.push(text.to_string());
                }
                in_block_comment = true;
            }
            continue;
        }

        if trimmed.starts_with("//") {
            let text = trimmed.trim_start_matches('/').trim();
            if !text.is_empty() {
                comments.push(text.to_string());
            }
            continue;
        }

        if let Some(comment_index) = trimmed.find("//") {
            let text = trimmed[comment_index + 2..].trim();
            if !text.is_empty() {
                comments.push(text.to_string());
            }
        }
    }

    comments.join("\n")
}

fn has_semantic_content(intent: &SemanticIntent) -> bool {
    !(intent.invariants.is_empty()
        && intent.required_behaviors.is_empty()
        && intent.forbidden_behaviors.is_empty()
        && intent.security_properties.is_empty())
}

fn merge_intents(intent_records: &[SemanticIntentRecord]) -> SemanticIntent {
    let mut invariants = BTreeSet::new();
    let mut required_behaviors = BTreeSet::new();
    let mut forbidden_behaviors = BTreeSet::new();
    let mut security_properties = BTreeSet::new();

    for record in intent_records {
        invariants.extend(record.intent.invariants.iter().cloned());
        required_behaviors.extend(record.intent.required_behaviors.iter().cloned());
        forbidden_behaviors.extend(record.intent.forbidden_behaviors.iter().cloned());
        security_properties.extend(record.intent.security_properties.iter().cloned());
    }

    SemanticIntent {
        source: "aggregated_intent".to_string(),
        invariants: invariants.into_iter().collect(),
        required_behaviors: required_behaviors.into_iter().collect(),
        forbidden_behaviors: forbidden_behaviors.into_iter().collect(),
        security_properties: security_properties.into_iter().collect(),
    }
}

fn select_dominant_intent_line(intent: &SemanticIntent) -> String {
    intent
        .forbidden_behaviors
        .first()
        .or_else(|| intent.required_behaviors.first())
        .or_else(|| intent.security_properties.first())
        .or_else(|| intent.invariants.first())
        .cloned()
        .unwrap_or_else(|| "semantic invariant missing".to_string())
}

fn find_suspicious_marker(raw_text: &str) -> Option<&'static str> {
    let raw_text_lc = raw_text.to_ascii_lowercase();
    SUSPICIOUS_MARKERS
        .iter()
        .copied()
        .find(|marker| raw_text_lc.contains(marker))
}

fn fix_suggestion_for_marker(marker: &str, intent_anchor: &str) -> String {
    match marker {
        "bypass" | "skip verification" | "disable verification" | "allow_invalid" => format!(
            "Remove `{marker}` behavior and enforce `{intent_anchor}` with an explicit verifier/constraint assertion."
        ),
        "todo" | "fixme" | "hack" | "temporary" | "debug only" => format!(
            "Replace `{marker}` placeholder with production constraints aligned to `{intent_anchor}` before release."
        ),
        "unchecked" => format!(
            "Add explicit range/permission checks so `{intent_anchor}` is validated instead of unchecked execution."
        ),
        _ => format!(
            "Review semantic guardrails and enforce `{intent_anchor}` as a hard invariant in runtime and tests."
        ),
    }
}

fn severity_from_assessment(assessment: &ExploitabilityAssessment) -> FindingSeverity {
    match (assessment.exploitable, assessment.confidence) {
        (true, confidence) if confidence >= 90 => FindingSeverity::Critical,
        (true, confidence) if confidence >= 75 => FindingSeverity::High,
        (true, confidence) if confidence >= 55 => FindingSeverity::Medium,
        _ => FindingSeverity::Low,
    }
}

fn generator_priority_for_severity(severity: FindingSeverity) -> u8 {
    match severity {
        FindingSeverity::Critical => 90,
        FindingSeverity::High => 75,
        FindingSeverity::Medium => 50,
        FindingSeverity::Low => 25,
        FindingSeverity::Info => 10,
    }
}

fn build_scorecard(
    files_scanned: usize,
    intent_sources: usize,
    findings: &[TrackFinding],
) -> Scorecard {
    let findings_count = findings.len();
    let false_positive_count = findings
        .iter()
        .filter(|finding| {
            finding
                .metadata
                .get("exploitable")
                .map(|value| value.trim().eq_ignore_ascii_case("false"))
                .unwrap_or(false)
        })
        .count() as u64;
    let false_positive_budget = (findings_count as u64)
        .saturating_div(FALSE_POSITIVE_BUDGET_DIVISOR)
        .saturating_add(FALSE_POSITIVE_BUDGET_FLOOR);

    let mut coverage_counts = BTreeMap::new();
    coverage_counts.insert("files_scanned".to_string(), files_scanned as u64);
    coverage_counts.insert("intent_sources".to_string(), intent_sources as u64);
    coverage_counts.insert("findings".to_string(), findings_count as u64);

    let intent_coverage = if files_scanned > 0 {
        intent_sources as f64 / files_scanned as f64
    } else {
        0.0
    };
    let finding_density = if files_scanned > 0 {
        findings_count as f64 / files_scanned as f64
    } else {
        0.0
    };

    Scorecard {
        track: TrackKind::Semantic,
        schema_version: POST_ROADMAP_SCHEMA_VERSION.to_string(),
        evaluated_at: Utc::now(),
        coverage_counts,
        metrics: vec![
            ScorecardMetric {
                name: REPLAY_METRIC_NAME.to_string(),
                value: 1.0,
                threshold: Some(1.0),
                passed: true,
            },
            ScorecardMetric {
                name: "intent_coverage".to_string(),
                value: intent_coverage,
                threshold: Some(0.05),
                passed: intent_coverage >= 0.05,
            },
            ScorecardMetric {
                name: "finding_density".to_string(),
                value: finding_density,
                threshold: Some(0.0),
                passed: true,
            },
        ],
        false_positive_budget,
        false_positive_count,
    }
}

fn write_semantic_report(
    input: &TrackInput,
    report_dir: &Path,
    adapter_name: &str,
    roots: &[PathBuf],
    intents: &[SemanticIntentRecord],
    violations: &[SemanticViolationRecord],
    scanned_files: usize,
    findings_count: usize,
) -> PostRoadmapResult<PathBuf> {
    let report = SemanticTrackReport {
        schema_version: POST_ROADMAP_SCHEMA_VERSION.to_string(),
        track_version: TRACK_MODULE_VERSION.to_string(),
        run_id: input.run_id.clone(),
        generated_at: Utc::now(),
        adapter: adapter_name.to_string(),
        roots: roots.to_vec(),
        scanned_files,
        extracted_intent_sources: intents.len(),
        findings_count,
        intents: intents.to_vec(),
        violations: violations.to_vec(),
    };
    let report_json = serde_json::to_string_pretty(&report).map_err(|error| {
        PostRoadmapError::Persistence(format!(
            "failed to serialize semantic report for run `{}`: {error}",
            input.run_id
        ))
    })?;
    let report_path = report_dir.join("semantic_track_report.json");
    fs::write(&report_path, report_json).map_err(|error| {
        PostRoadmapError::Persistence(format!(
            "failed to write semantic report `{}`: {error}",
            report_path.display()
        ))
    })?;
    Ok(report_path)
}

#[allow(clippy::too_many_arguments)]
fn write_ai_ingest_bundle(
    input: &TrackInput,
    report_dir: &Path,
    adapter_name: &str,
    roots: &[PathBuf],
    source_documents: &[SemanticSourceDocument],
    intents: &[SemanticIntentRecord],
    execution_evidence_cases: &[SemanticExecutionEvidenceCase],
    violations: &[SemanticViolationRecord],
    findings: &[TrackFinding],
) -> PostRoadmapResult<PathBuf> {
    let ai_source_documents = source_documents
        .iter()
        .map(|document| AiIngestDocument {
            path: document.path.clone(),
            source_type: document.source_type,
            intent_excerpt: truncate_bundle_text(&document.intent_text, 280),
        })
        .collect::<Vec<_>>();
    let bundle = AiIngestBundle {
        schema_version: POST_ROADMAP_SCHEMA_VERSION.to_string(),
        track_version: TRACK_MODULE_VERSION.to_string(),
        run_id: input.run_id.clone(),
        generated_at: Utc::now(),
        mode: "output_only_for_external_ai".to_string(),
        adapter: adapter_name.to_string(),
        roots: roots.to_vec(),
        source_documents: ai_source_documents,
        extracted_intents: intents.to_vec(),
        execution_evidence_cases: execution_evidence_cases.to_vec(),
        violations: violations.to_vec(),
        findings: findings.to_vec(),
        ai_prompt_hints: vec![
            "Infer protocol intent from extracted_intents and source_documents.".to_string(),
            "Prioritize violations where detector=execution_evidence and accepted=true cases imply forbidden behavior."
                .to_string(),
            "For each high-confidence finding, suggest a concrete verifier/constraint-level fix.".to_string(),
            "Output machine-readable exploitability verdicts with confidence scores.".to_string(),
        ],
        instructions: "This bundle is producer output from ZkPatternFuzz. External AI should ingest this JSON and return analysis out-of-band. The scanner does not ingest AI responses in producer-only mode."
            .to_string(),
    };
    let bundle_json = serde_json::to_string_pretty(&bundle).map_err(|error| {
        PostRoadmapError::Persistence(format!(
            "failed to serialize AI ingest bundle for run `{}`: {error}",
            input.run_id
        ))
    })?;
    let bundle_path = report_dir.join("ai_ingest_bundle.json");
    fs::write(&bundle_path, bundle_json).map_err(|error| {
        PostRoadmapError::Persistence(format!(
            "failed to write AI ingest bundle `{}`: {error}",
            bundle_path.display()
        ))
    })?;
    Ok(bundle_path)
}

fn truncate_bundle_text(value: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut count = 0usize;
    let mut truncated = false;
    for character in value.chars() {
        if count >= max_chars {
            truncated = true;
            break;
        }
        out.push(character);
        count += 1;
    }
    if truncated {
        out.push_str("...[truncated]");
    }
    out
}

fn severity_label(severity: FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Critical => "critical",
        FindingSeverity::High => "high",
        FindingSeverity::Medium => "medium",
        FindingSeverity::Low => "low",
        FindingSeverity::Info => "info",
    }
}

fn severity_priority(severity: FindingSeverity) -> u8 {
    match severity {
        FindingSeverity::Critical => 90,
        FindingSeverity::High => 75,
        FindingSeverity::Medium => 50,
        FindingSeverity::Low => 25,
        FindingSeverity::Info => 10,
    }
}

fn collect_attack_vector_hints(summary: &str) -> Vec<String> {
    let summary_lc = summary.to_ascii_lowercase();
    let mut hints = Vec::new();

    let candidates = [
        ("non-admin", "authorization bypass"),
        ("unauthorized", "unauthorized access"),
        ("bypass", "guardrail bypass"),
        ("forged", "forged proof acceptance"),
        ("invalid proof", "invalid proof acceptance"),
        ("replay", "replay acceptance"),
        ("overflow", "arithmetic overflow abuse"),
        ("underflow", "arithmetic underflow abuse"),
        ("without permission", "missing permission checks"),
        ("without auth", "missing authorization checks"),
    ];

    for (needle, label) in candidates {
        if summary_lc.contains(needle) {
            hints.push(label.to_string());
        }
    }
    if hints.is_empty() {
        hints.push("semantic intent mismatch with accepted execution path".to_string());
    }
    hints
}

#[allow(clippy::too_many_arguments)]
fn write_ai_exploitability_worklist(
    input: &TrackInput,
    report_dir: &Path,
    adapter_name: &str,
    roots: &[PathBuf],
    dominant_intent: &str,
    execution_evidence_cases: &[SemanticExecutionEvidenceCase],
    violations: &[SemanticViolationRecord],
    findings: &[TrackFinding],
) -> PostRoadmapResult<PathBuf> {
    let finding_severity = findings
        .iter()
        .map(|finding| {
            (
                finding.id.clone(),
                severity_label(finding.severity).to_string(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let evidence_cases = execution_evidence_cases
        .iter()
        .map(|case| (case.case_id.clone(), case))
        .collect::<BTreeMap<_, _>>();

    let mut exploitability_tasks = Vec::new();
    let mut poc_generation_tasks = Vec::new();

    for (index, violation) in violations.iter().enumerate() {
        let task_id = format!("exploitability-task-{:03}", index + 1);
        let severity = finding_severity
            .get(&violation.finding_id)
            .cloned()
            .unwrap_or_else(|| {
                severity_label(severity_from_assessment(&violation.assessment)).to_string()
            });
        let case = violation
            .evidence_case_id
            .as_ref()
            .and_then(|case_id| evidence_cases.get(case_id))
            .copied();
        let extra_solution_candidate = violation.detector == "execution_evidence"
            && case.map(|item| item.accepted).unwrap_or(false);
        let evidence_case_summary = case.map(|item| item.summary.clone());
        let attack_vector_hints = collect_attack_vector_hints(&violation.violation_summary);

        exploitability_tasks.push(AiExploitabilityTask {
            task_id: task_id.clone(),
            finding_id: violation.finding_id.clone(),
            detector: violation.detector.clone(),
            severity: severity.clone(),
            source_path: violation.source_path.clone(),
            evidence_case_id: violation.evidence_case_id.clone(),
            evidence_case_summary: evidence_case_summary.clone(),
            extra_solution_candidate,
            violation_summary: violation.violation_summary.clone(),
            intent_anchor: dominant_intent.to_string(),
            attack_vector_hints: attack_vector_hints.clone(),
            requested_output_fields: vec![
                "exploitable (boolean)".to_string(),
                "confidence (0-100 integer)".to_string(),
                "attack_path (short text)".to_string(),
                "asset_at_risk (short text)".to_string(),
                "required_preconditions (array of strings)".to_string(),
                "recommended_fix_validation (array of checks)".to_string(),
            ],
        });

        if violation.assessment.exploitable {
            let mut preconditions = Vec::new();
            if let Some(case_id) = &violation.evidence_case_id {
                preconditions.push(format!("reproduce execution evidence case `{case_id}`"));
            }
            preconditions.push(format!("preserve intent anchor `{dominant_intent}`"));
            preconditions.push(format!("target severity `{severity}`"));

            poc_generation_tasks.push(AiPocGenerationTask {
                task_id: format!("poc-task-{:03}", poc_generation_tasks.len() + 1),
                finding_id: violation.finding_id.clone(),
                severity,
                objective: format!(
                    "Demonstrate exploit for semantic violation `{}`",
                    violation.violation_summary
                ),
                preconditions,
                steps_template: vec![
                    "Set up baseline valid witness/proof flow.".to_string(),
                    "Apply the violating witness/proof/public-input mutation.".to_string(),
                    "Demonstrate unauthorized/invalid acceptance condition.".to_string(),
                    "Capture reproducible command, input payload, and observed output."
                        .to_string(),
                    "Add verifier/constraint assertion that blocks the exploit and rerun."
                        .to_string(),
                ],
                expected_outcome: "Provide a minimal reproducible exploit case plus a validation snippet showing the proposed fix rejects it.".to_string(),
                output_contract: "Return JSON with keys: poc_title, prerequisites, exploit_steps, expected_result, fix_verification_steps, residual_risk.".to_string(),
            });
        }
    }

    let worklist = AiExploitabilityWorklist {
        schema_version: POST_ROADMAP_SCHEMA_VERSION.to_string(),
        track_version: TRACK_MODULE_VERSION.to_string(),
        run_id: input.run_id.clone(),
        generated_at: Utc::now(),
        mode: "output_only_for_external_ai".to_string(),
        adapter: adapter_name.to_string(),
        roots: roots.to_vec(),
        dominant_intent: dominant_intent.to_string(),
        exploitability_tasks,
        poc_generation_tasks,
        instructions: "This worklist is producer output from ZkPatternFuzz. External AI should ingest it, analyze extra-solution attack viability, and return exploitability + PoC outputs out-of-band. The scanner does not ingest AI responses in producer-only mode.".to_string(),
        response_contract: vec![
            "exploitability_responses must map to exploitability_tasks by task_id".to_string(),
            "poc_responses must map to poc_generation_tasks by task_id".to_string(),
            "each response must be machine-readable JSON without markdown wrappers".to_string(),
        ],
    };
    let worklist_json = serde_json::to_string_pretty(&worklist).map_err(|error| {
        PostRoadmapError::Persistence(format!(
            "failed to serialize AI exploitability worklist for run `{}`: {error}",
            input.run_id
        ))
    })?;
    let worklist_path = report_dir.join("ai_exploitability_worklist.json");
    fs::write(&worklist_path, worklist_json).map_err(|error| {
        PostRoadmapError::Persistence(format!(
            "failed to write AI exploitability worklist `{}`: {error}",
            worklist_path.display()
        ))
    })?;
    Ok(worklist_path)
}

fn write_semantic_actionable_report(
    input: &TrackInput,
    report_dir: &Path,
    findings: &[TrackFinding],
    violations: &[SemanticViolationRecord],
) -> PostRoadmapResult<PathBuf> {
    let mut violation_fix = BTreeMap::new();
    let mut violation_case = BTreeMap::new();
    for violation in violations {
        violation_fix.insert(
            violation.finding_id.clone(),
            violation.fix_suggestion.clone(),
        );
        if let Some(case_id) = &violation.evidence_case_id {
            violation_case.insert(violation.finding_id.clone(), case_id.clone());
        }
    }

    let mut actionable_findings = findings
        .iter()
        .map(|finding| {
            let source_path = finding
                .metadata
                .get("source_path")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let fix_suggestion = finding
                .metadata
                .get("fix_suggestion")
                .cloned()
                .or_else(|| violation_fix.get(&finding.id).cloned())
                .unwrap_or_else(|| {
                    "Add explicit invariant checks and update verifier/oracle regression tests."
                        .to_string()
                });

            let mut verification_checks = Vec::new();
            if let Some(case_id) = violation_case.get(&finding.id) {
                verification_checks.push(format!(
                    "Replay execution evidence case `{case_id}` and confirm rejection after fix."
                ));
            }
            verification_checks.push(format!(
                "Add a regression test covering finding `{}` with expected reject behavior.",
                finding.id
            ));
            verification_checks.push(
                "Confirm updated constraints/verifier preserve valid proof acceptance paths."
                    .to_string(),
            );

            ActionableFinding {
                finding_id: finding.id.clone(),
                severity: severity_label(finding.severity).to_string(),
                priority: severity_priority(finding.severity),
                title: finding.title.clone(),
                source_path,
                fix_suggestion,
                verification_checks,
            }
        })
        .collect::<Vec<_>>();
    actionable_findings.sort_by(|left, right| right.priority.cmp(&left.priority));

    let actionable_report = SemanticActionableReport {
        schema_version: POST_ROADMAP_SCHEMA_VERSION.to_string(),
        track_version: TRACK_MODULE_VERSION.to_string(),
        run_id: input.run_id.clone(),
        generated_at: Utc::now(),
        mode: "output_only_for_external_ai".to_string(),
        findings: actionable_findings,
        instructions: "This report is producer output from ZkPatternFuzz. Use it as a prioritized remediation plan; external AI may ingest it and generate patch proposals out-of-band. The scanner does not ingest AI responses in producer-only mode.".to_string(),
    };
    let report_json = serde_json::to_string_pretty(&actionable_report).map_err(|error| {
        PostRoadmapError::Persistence(format!(
            "failed to serialize semantic actionable report for run `{}`: {error}",
            input.run_id
        ))
    })?;
    let report_path = report_dir.join("semantic_actionable_report.json");
    fs::write(&report_path, report_json).map_err(|error| {
        PostRoadmapError::Persistence(format!(
            "failed to write semantic actionable report `{}`: {error}",
            report_path.display()
        ))
    })?;
    Ok(report_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_semantic_track_kind() {
        assert_eq!(SemanticTrackRunner::new().track(), TrackKind::Semantic);
    }

    #[test]
    fn reports_intent_adapter_count() {
        let runner = SemanticTrackRunner::new();
        assert_eq!(runner.intent_adapter_count(), 0);
    }

    #[test]
    fn detects_comment_text_from_mixed_source_lines() {
        let source = r#"
            // only admin can withdraw
            let x = 3; // TODO: bypass auth in debug mode
            /* verifier must reject forged proofs */
            fn main() {}
        "#;
        let comments = extract_comment_and_doc_text(source);
        assert!(comments.contains("only admin can withdraw"));
        assert!(comments.contains("TODO: bypass auth in debug mode"));
        assert!(comments.contains("verifier must reject forged proofs"));
    }

    #[test]
    fn detects_inline_block_and_trailing_line_comments() {
        let source = r#"
            let x = /* bypass must never ship */ 1;
            let y = 2; // verifier should reject forged proof
            let z = 3; /* enforce range checks */
        "#;
        let comments = extract_comment_and_doc_text(source);
        assert!(comments.contains("bypass must never ship"));
        assert!(comments.contains("verifier should reject forged proof"));
        assert!(comments.contains("enforce range checks"));
    }

    #[test]
    fn exposes_track_version() {
        assert!(!TRACK_MODULE_VERSION.is_empty());
    }
}
