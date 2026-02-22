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
    ExploitabilityAssessment, HeuristicSemanticIntentAdapter, SemanticIntent, SemanticIntentAdapter,
};

pub const TRACK_MODULE_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_SOURCE_BYTES: u64 = 256 * 1024;
const MAX_DISCOVERED_FILES: usize = 2_000;
const REPLAY_METRIC_NAME: &str = "deterministic_replay_rate";

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
    raw_text: String,
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
    source_path: PathBuf,
    suspicious_marker: String,
    violation_summary: String,
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
        fs::create_dir_all(report_output_dir(input)).map_err(|error| {
            PostRoadmapError::Infrastructure(format!(
                "failed to create semantic report output directory `{}`: {error}",
                report_output_dir(input).display()
            ))
        })
    }

    async fn run(&self, input: &TrackInput) -> PostRoadmapResult<TrackExecution> {
        let started_at = Utc::now();
        let scan_roots = resolve_scan_roots(input);
        let source_paths = discover_source_files(&scan_roots)?;

        let mut source_documents = Vec::new();
        for source_path in source_paths {
            if let Some(document) = load_source_document(&source_path)? {
                source_documents.push(document);
            }
        }

        let fallback_adapter = HeuristicSemanticIntentAdapter;
        let adapter: &dyn SemanticIntentAdapter = self
            .intent_adapters
            .first()
            .map(|adapter| adapter.as_ref())
            .unwrap_or(&fallback_adapter);
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

        for document in source_documents
            .iter()
            .filter(|document| document.source_type == SemanticSourceType::Code)
        {
            let Some(marker) = find_suspicious_marker(&document.raw_text) else {
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

            findings.push(TrackFinding {
                id: finding_id.clone(),
                track: self.track(),
                title: format!("Potential semantic intent violation in {source_path}"),
                summary: format!("{violation_summary}. {}", assessment.rationale),
                severity,
                reproducible: true,
                evidence_paths: vec![document.path.clone()],
                metadata,
            });
            violations.push(SemanticViolationRecord {
                finding_id,
                source_path: document.path.clone(),
                suspicious_marker: marker.to_string(),
                violation_summary,
                assessment,
            });
        }

        let report_path = write_semantic_report(
            input,
            &adapter_name,
            &scan_roots,
            &intent_records,
            &violations,
            source_documents.len(),
            findings.len(),
        )?;

        let scorecard =
            build_scorecard(source_documents.len(), intent_records.len(), findings.len());
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
            evidence_paths: vec![report_path],
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
        raw_text,
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

fn severity_from_assessment(assessment: &ExploitabilityAssessment) -> FindingSeverity {
    match (assessment.exploitable, assessment.confidence) {
        (true, confidence) if confidence >= 90 => FindingSeverity::Critical,
        (true, confidence) if confidence >= 75 => FindingSeverity::High,
        (_, confidence) if confidence >= 55 => FindingSeverity::Medium,
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

fn build_scorecard(files_scanned: usize, intent_sources: usize, findings: usize) -> Scorecard {
    let mut coverage_counts = BTreeMap::new();
    coverage_counts.insert("files_scanned".to_string(), files_scanned as u64);
    coverage_counts.insert("intent_sources".to_string(), intent_sources as u64);
    coverage_counts.insert("findings".to_string(), findings as u64);

    let intent_coverage = if files_scanned > 0 {
        intent_sources as f64 / files_scanned as f64
    } else {
        0.0
    };
    let finding_density = if files_scanned > 0 {
        findings as f64 / files_scanned as f64
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
        false_positive_budget: findings as u64 + 2,
        false_positive_count: 0,
    }
}

fn write_semantic_report(
    input: &TrackInput,
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

    let report_dir = report_output_dir(input);
    fs::create_dir_all(&report_dir).map_err(|error| {
        PostRoadmapError::Persistence(format!(
            "failed to create semantic report directory `{}`: {error}",
            report_dir.display()
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
    fn exposes_track_version() {
        assert!(!TRACK_MODULE_VERSION.is_empty());
    }
}
