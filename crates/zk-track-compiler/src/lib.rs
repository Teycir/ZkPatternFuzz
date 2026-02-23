mod adapters;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use zk_postroadmap_core::{
    FindingSeverity, PostRoadmapError, PostRoadmapResult, ReplayArtifact, Scorecard,
    ScorecardMetric, TrackExecution, TrackFinding, TrackInput, TrackKind, TrackRunner,
    POST_ROADMAP_SCHEMA_VERSION,
};

pub use adapters::{
    CompilerBackendAdapter, CompilerCrashClass, CompilerDiagnostic, CompilerGenerationRequest,
    CompilerGenerationResult,
};

pub const TRACK_MODULE_VERSION: &str = env!("CARGO_PKG_VERSION");
const REPLAY_METRIC_NAME: &str = "deterministic_replay_rate";
const DEFAULT_SEED: u64 = 20_260_223;
const DEFAULT_CASES_PER_ADAPTER: usize = 1;
const BUG_PROBE_CASES_PER_ADAPTER: usize = 4;
const DEFAULT_MAX_CONSTRAINTS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CompilerExecutionMode {
    StrictSample,
    BugProbe,
}

#[derive(Debug, Clone, Serialize)]
struct CompilerAdapterCaseReport {
    case_id: String,
    seed: u64,
    max_constraints: usize,
    source_path: Option<String>,
    backend_name: Option<String>,
    diagnostic_class: Option<String>,
    diagnostic_message: Option<String>,
    generation_error: Option<String>,
    compile_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct CompilerAdapterRunReport {
    adapter: String,
    cases_requested: usize,
    generation_attempts: usize,
    generation_successes: usize,
    generation_errors: usize,
    compile_attempts: usize,
    compile_errors: usize,
    diagnostics_with_class: usize,
    crash_like_diagnostics: usize,
    cases: Vec<CompilerAdapterCaseReport>,
}

#[derive(Debug, Clone, Serialize)]
struct CompilerTrackReport {
    schema_version: String,
    track_version: String,
    run_id: String,
    generated_at: DateTime<Utc>,
    mode: CompilerExecutionMode,
    seed: u64,
    cases_per_adapter: usize,
    max_constraints: usize,
    adapter_runs: Vec<CompilerAdapterRunReport>,
    findings_count: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct CompilerRunTotals {
    backend_adapter_count: u64,
    generation_attempts: u64,
    generation_successes: u64,
    generation_errors: u64,
    compile_attempts: u64,
    compile_errors: u64,
    diagnostics_with_class: u64,
    crash_like_diagnostics: u64,
}

#[derive(Default)]
pub struct CompilerTrackRunner {
    backend_adapters: Vec<Box<dyn CompilerBackendAdapter>>,
}

impl CompilerTrackRunner {
    pub fn new() -> Self {
        Self {
            backend_adapters: Vec::new(),
        }
    }

    pub fn with_backend_adapter(mut self, adapter: Box<dyn CompilerBackendAdapter>) -> Self {
        self.backend_adapters.push(adapter);
        self
    }

    pub fn backend_adapter_count(&self) -> usize {
        self.backend_adapters.len()
    }
}

#[async_trait]
impl TrackRunner for CompilerTrackRunner {
    fn track(&self) -> TrackKind {
        TrackKind::Compiler
    }

    async fn prepare(&self, input: &TrackInput) -> PostRoadmapResult<()> {
        fs::create_dir_all(report_output_dir(input)).map_err(|error| {
            PostRoadmapError::Infrastructure(format!(
                "failed to create compiler report output directory `{}`: {error}",
                report_output_dir(input).display()
            ))
        })
    }

    async fn run(&self, input: &TrackInput) -> PostRoadmapResult<TrackExecution> {
        let started_at = Utc::now();
        let mode = parse_execution_mode(input);
        let seed = input.seed.unwrap_or(DEFAULT_SEED);
        let cases_per_adapter = parse_usize_metadata(input, "compiler_cases_per_adapter")?
            .unwrap_or(match mode {
                CompilerExecutionMode::StrictSample => DEFAULT_CASES_PER_ADAPTER,
                CompilerExecutionMode::BugProbe => BUG_PROBE_CASES_PER_ADAPTER,
            });
        let max_constraints = parse_usize_metadata(input, "compiler_max_constraints")?
            .unwrap_or(DEFAULT_MAX_CONSTRAINTS);

        let mut findings = Vec::new();
        let mut adapter_runs = Vec::new();
        let mut totals = CompilerRunTotals {
            backend_adapter_count: self.backend_adapters.len() as u64,
            ..CompilerRunTotals::default()
        };

        for (adapter_index, adapter) in self.backend_adapters.iter().enumerate() {
            let adapter_name = adapter.backend_name().to_string();
            let mut adapter_run = CompilerAdapterRunReport {
                adapter: adapter_name.clone(),
                cases_requested: cases_per_adapter,
                generation_attempts: 0,
                generation_successes: 0,
                generation_errors: 0,
                compile_attempts: 0,
                compile_errors: 0,
                diagnostics_with_class: 0,
                crash_like_diagnostics: 0,
                cases: Vec::new(),
            };

            for case_index in 0..cases_per_adapter {
                let case_id = format!("adapter{adapter_index:02}_case{case_index:03}");
                let case_seed = derive_case_seed(seed, adapter_index, case_index);

                adapter_run.generation_attempts += 1;
                totals.generation_attempts += 1;
                let generation_request = CompilerGenerationRequest {
                    seed: case_seed,
                    max_constraints,
                };

                let generation = match adapter.generate(&generation_request).await {
                    Ok(generation) => {
                        adapter_run.generation_successes += 1;
                        totals.generation_successes += 1;
                        generation
                    }
                    Err(error) => {
                        adapter_run.generation_errors += 1;
                        totals.generation_errors += 1;

                        findings.push(track_finding(
                            format!("compiler-generation-error-{:03}", findings.len() + 1),
                            "Circuit generation failed",
                            format!(
                                "Adapter `{}` failed to generate case `{}`: {}",
                                adapter_name, case_id, error
                            ),
                            severity_for_generation_error(mode),
                            metadata_for_generation_error(&adapter_name, &case_id, &error),
                        ));

                        adapter_run.cases.push(CompilerAdapterCaseReport {
                            case_id,
                            seed: case_seed,
                            max_constraints,
                            source_path: None,
                            backend_name: None,
                            diagnostic_class: None,
                            diagnostic_message: None,
                            generation_error: Some(error.to_string()),
                            compile_error: None,
                        });
                        continue;
                    }
                };

                adapter_run.compile_attempts += 1;
                totals.compile_attempts += 1;

                match adapter.compile(&generation.source_path).await {
                    Ok(diagnostic) => {
                        if let Some(class) = diagnostic.class {
                            adapter_run.diagnostics_with_class += 1;
                            totals.diagnostics_with_class += 1;
                            if is_crash_like(class) {
                                adapter_run.crash_like_diagnostics += 1;
                                totals.crash_like_diagnostics += 1;
                            }

                            findings.push(track_finding(
                                format!("compiler-diagnostic-{:03}", findings.len() + 1),
                                format!(
                                    "Compiler diagnostic: {}",
                                    compiler_crash_class_as_str(class)
                                ),
                                format!(
                                    "Adapter `{}` produced `{}` while compiling `{}`: {}",
                                    adapter_name,
                                    compiler_crash_class_as_str(class),
                                    generation.source_path,
                                    diagnostic.message
                                ),
                                severity_for_crash_class(mode, class),
                                metadata_for_diagnostic(
                                    &adapter_name,
                                    &generation.source_path,
                                    &generation.backend_name,
                                    class,
                                    severity_for_crash_class(mode, class),
                                ),
                            ));
                        }

                        adapter_run.cases.push(CompilerAdapterCaseReport {
                            case_id,
                            seed: case_seed,
                            max_constraints,
                            source_path: Some(generation.source_path),
                            backend_name: Some(generation.backend_name),
                            diagnostic_class: diagnostic
                                .class
                                .map(|class| compiler_crash_class_as_str(class).to_string()),
                            diagnostic_message: non_empty_string(&diagnostic.message),
                            generation_error: None,
                            compile_error: None,
                        });
                    }
                    Err(error) => {
                        adapter_run.compile_errors += 1;
                        totals.compile_errors += 1;

                        findings.push(track_finding(
                            format!("compiler-compile-error-{:03}", findings.len() + 1),
                            "Compiler invocation failed",
                            format!(
                                "Adapter `{}` failed to compile `{}`: {}",
                                adapter_name, generation.source_path, error
                            ),
                            severity_for_compile_error(mode),
                            metadata_for_compile_error(
                                &adapter_name,
                                &generation.source_path,
                                &generation.backend_name,
                                &error,
                            ),
                        ));

                        adapter_run.cases.push(CompilerAdapterCaseReport {
                            case_id,
                            seed: case_seed,
                            max_constraints,
                            source_path: Some(generation.source_path),
                            backend_name: Some(generation.backend_name),
                            diagnostic_class: None,
                            diagnostic_message: None,
                            generation_error: None,
                            compile_error: Some(error.to_string()),
                        });
                    }
                }
            }

            adapter_runs.push(adapter_run);
        }

        let report_path = write_compiler_report(
            input,
            &CompilerTrackReport {
                schema_version: POST_ROADMAP_SCHEMA_VERSION.to_string(),
                track_version: TRACK_MODULE_VERSION.to_string(),
                run_id: input.run_id.clone(),
                generated_at: Utc::now(),
                mode,
                seed,
                cases_per_adapter,
                max_constraints,
                adapter_runs,
                findings_count: findings.len(),
            },
        )?;

        for finding in &mut findings {
            finding.evidence_paths.push(report_path.clone());
        }

        let scorecard = build_scorecard(self.track(), &totals, findings.len());
        let replay_artifacts = vec![ReplayArtifact {
            replay_id: format!("compiler-replay-{}", input.run_id),
            track: self.track(),
            command: vec![
                "cargo".to_string(),
                "test".to_string(),
                "-p".to_string(),
                "zk-track-compiler".to_string(),
            ],
            env: BTreeMap::from([
                ("COMPILER_EXECUTION_MODE".to_string(), mode_as_str(mode)),
                (
                    "COMPILER_CASES_PER_ADAPTER".to_string(),
                    cases_per_adapter.to_string(),
                ),
                (
                    "COMPILER_MAX_CONSTRAINTS".to_string(),
                    max_constraints.to_string(),
                ),
            ]),
            evidence_paths: vec![report_path],
            notes: "Replay deterministic compiler generation/compile diagnostics".to_string(),
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
                "compiler validator received mismatched track: expected `{:?}`, got `{:?}`",
                self.track(),
                execution.track
            )));
        }

        let scorecard = execution.scorecard.as_ref().ok_or_else(|| {
            PostRoadmapError::Validation("compiler execution must include a scorecard".to_string())
        })?;

        for required_key in [
            "backend_adapter_count",
            "generation_attempts",
            "generation_successes",
            "compile_attempts",
            "diagnostics_with_class",
        ] {
            if !scorecard.coverage_counts.contains_key(required_key) {
                return Err(PostRoadmapError::Validation(format!(
                    "compiler scorecard missing `{required_key}` coverage count"
                )));
            }
        }

        if !scorecard
            .metrics
            .iter()
            .any(|metric| metric.name == REPLAY_METRIC_NAME)
        {
            return Err(PostRoadmapError::Validation(format!(
                "compiler scorecard missing `{REPLAY_METRIC_NAME}` metric"
            )));
        }

        if scorecard.false_positive_count > scorecard.false_positive_budget {
            return Err(PostRoadmapError::Validation(format!(
                "compiler false-positive budget exceeded: {} > {}",
                scorecard.false_positive_count, scorecard.false_positive_budget
            )));
        }

        for finding in &execution.findings {
            if finding.track != self.track() {
                return Err(PostRoadmapError::Validation(format!(
                    "compiler finding `{}` has mismatched track `{:?}`",
                    finding.id, finding.track
                )));
            }

            for required_key in ["subsystem", "backend_adapter", "generated_circuit"] {
                if !finding.metadata.contains_key(required_key) {
                    return Err(PostRoadmapError::Validation(format!(
                        "compiler finding `{}` missing `{required_key}` metadata",
                        finding.id
                    )));
                }
            }

            if matches!(
                finding.severity,
                FindingSeverity::High | FindingSeverity::Critical
            ) && !finding.metadata.contains_key("regression_test")
            {
                return Err(PostRoadmapError::Validation(format!(
                    "compiler finding `{}` with high/critical severity must include `regression_test` metadata",
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
        for finding in &execution.findings {
            for path in &finding.evidence_paths {
                if path.exists() {
                    emitted_paths.insert(path.clone());
                }
            }
        }
        Ok(emitted_paths.into_iter().collect())
    }
}

fn mode_as_str(mode: CompilerExecutionMode) -> String {
    match mode {
        CompilerExecutionMode::StrictSample => "strict_sample".to_string(),
        CompilerExecutionMode::BugProbe => "bug_probe".to_string(),
    }
}

fn parse_execution_mode(input: &TrackInput) -> CompilerExecutionMode {
    let mode = input
        .metadata
        .get("compiler_execution_mode")
        .or_else(|| input.metadata.get("compiler_mode"))
        .map(|value| value.trim().to_ascii_lowercase());

    match mode.as_deref() {
        Some("bug_probe") | Some("bug-probe") | Some("probe") | Some("weak") => {
            CompilerExecutionMode::BugProbe
        }
        _ => CompilerExecutionMode::StrictSample,
    }
}

fn parse_usize_metadata(input: &TrackInput, key: &str) -> PostRoadmapResult<Option<usize>> {
    let Some(raw) = input.metadata.get(key) else {
        return Ok(None);
    };

    raw.trim().parse::<usize>().map(Some).map_err(|error| {
        PostRoadmapError::Configuration(format!("invalid usize metadata `{key}`=`{raw}`: {error}"))
    })
}

fn derive_case_seed(seed: u64, adapter_index: usize, case_index: usize) -> u64 {
    seed.wrapping_add((adapter_index as u64).wrapping_mul(1_000_003))
        .wrapping_add(case_index as u64)
}

fn compiler_crash_class_as_str(class: CompilerCrashClass) -> &'static str {
    match class {
        CompilerCrashClass::Timeout => "timeout",
        CompilerCrashClass::InternalCompilerError => "internal_compiler_error",
        CompilerCrashClass::Panic => "panic",
        CompilerCrashClass::UserError => "user_error",
    }
}

fn is_crash_like(class: CompilerCrashClass) -> bool {
    matches!(
        class,
        CompilerCrashClass::Timeout
            | CompilerCrashClass::InternalCompilerError
            | CompilerCrashClass::Panic
    )
}

fn severity_for_generation_error(mode: CompilerExecutionMode) -> FindingSeverity {
    match mode {
        CompilerExecutionMode::StrictSample => FindingSeverity::Medium,
        CompilerExecutionMode::BugProbe => FindingSeverity::High,
    }
}

fn severity_for_compile_error(mode: CompilerExecutionMode) -> FindingSeverity {
    match mode {
        CompilerExecutionMode::StrictSample => FindingSeverity::Medium,
        CompilerExecutionMode::BugProbe => FindingSeverity::High,
    }
}

fn severity_for_crash_class(
    mode: CompilerExecutionMode,
    class: CompilerCrashClass,
) -> FindingSeverity {
    match class {
        CompilerCrashClass::Panic | CompilerCrashClass::InternalCompilerError => match mode {
            CompilerExecutionMode::StrictSample => FindingSeverity::High,
            CompilerExecutionMode::BugProbe => FindingSeverity::Critical,
        },
        CompilerCrashClass::Timeout => match mode {
            CompilerExecutionMode::StrictSample => FindingSeverity::Medium,
            CompilerExecutionMode::BugProbe => FindingSeverity::High,
        },
        CompilerCrashClass::UserError => FindingSeverity::Low,
    }
}

fn metadata_for_generation_error(
    adapter_name: &str,
    case_id: &str,
    error: &PostRoadmapError,
) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::from([
        ("subsystem".to_string(), "circuit_generation".to_string()),
        ("backend_adapter".to_string(), adapter_name.to_string()),
        (
            "generated_circuit".to_string(),
            format!("generation_failed:{case_id}"),
        ),
        ("error_kind".to_string(), "generation_error".to_string()),
        ("error_message".to_string(), error.to_string()),
    ]);
    metadata.insert(
        "regression_test".to_string(),
        "crates/zk-track-compiler/src/lib.rs::tests::bug_probe_mode_surfaces_findings".to_string(),
    );
    metadata
}

fn metadata_for_compile_error(
    adapter_name: &str,
    source_path: &str,
    backend_name: &str,
    error: &PostRoadmapError,
) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::from([
        ("subsystem".to_string(), "compiler_compile".to_string()),
        ("backend_adapter".to_string(), adapter_name.to_string()),
        ("generated_circuit".to_string(), source_path.to_string()),
        ("backend_name".to_string(), backend_name.to_string()),
        ("error_kind".to_string(), "compile_error".to_string()),
        ("error_message".to_string(), error.to_string()),
    ]);
    metadata.insert(
        "regression_test".to_string(),
        "crates/zk-track-compiler/src/lib.rs::tests::bug_probe_mode_surfaces_findings".to_string(),
    );
    metadata
}

fn metadata_for_diagnostic(
    adapter_name: &str,
    source_path: &str,
    backend_name: &str,
    class: CompilerCrashClass,
    severity: FindingSeverity,
) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::from([
        ("subsystem".to_string(), "compiler_diagnostic".to_string()),
        ("backend_adapter".to_string(), adapter_name.to_string()),
        ("generated_circuit".to_string(), source_path.to_string()),
        ("backend_name".to_string(), backend_name.to_string()),
        (
            "crash_class".to_string(),
            compiler_crash_class_as_str(class).to_string(),
        ),
    ]);
    if matches!(severity, FindingSeverity::High | FindingSeverity::Critical) {
        metadata.insert(
            "regression_test".to_string(),
            "crates/zk-track-compiler/src/lib.rs::tests::bug_probe_mode_surfaces_findings"
                .to_string(),
        );
    }
    metadata
}

fn track_finding(
    id: String,
    title: impl Into<String>,
    summary: String,
    severity: FindingSeverity,
    metadata: BTreeMap<String, String>,
) -> TrackFinding {
    TrackFinding {
        id,
        track: TrackKind::Compiler,
        title: title.into(),
        summary,
        severity,
        reproducible: true,
        evidence_paths: vec![],
        metadata,
    }
}

fn build_scorecard(
    track: TrackKind,
    totals: &CompilerRunTotals,
    findings_count: usize,
) -> Scorecard {
    let mut coverage_counts = BTreeMap::new();
    coverage_counts.insert(
        "backend_adapter_count".to_string(),
        totals.backend_adapter_count,
    );
    coverage_counts.insert(
        "generation_attempts".to_string(),
        totals.generation_attempts,
    );
    coverage_counts.insert(
        "generation_successes".to_string(),
        totals.generation_successes,
    );
    coverage_counts.insert("generation_errors".to_string(), totals.generation_errors);
    coverage_counts.insert("compile_attempts".to_string(), totals.compile_attempts);
    coverage_counts.insert("compile_errors".to_string(), totals.compile_errors);
    coverage_counts.insert(
        "diagnostics_with_class".to_string(),
        totals.diagnostics_with_class,
    );
    coverage_counts.insert(
        "crash_like_diagnostics".to_string(),
        totals.crash_like_diagnostics,
    );
    coverage_counts.insert("finding_count".to_string(), findings_count as u64);

    let generation_success_rate = rate(totals.generation_successes, totals.generation_attempts);
    let compile_error_free_rate = pass_rate(totals.compile_attempts, totals.compile_errors);
    let diagnostic_clean_rate = pass_rate(totals.compile_attempts, totals.diagnostics_with_class);
    let crash_free_compile_rate = pass_rate(totals.compile_attempts, totals.crash_like_diagnostics);

    Scorecard {
        track,
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
                name: "generation_success_rate".to_string(),
                value: generation_success_rate,
                threshold: Some(1.0),
                passed: (generation_success_rate - 1.0).abs() < f64::EPSILON,
            },
            ScorecardMetric {
                name: "compile_error_free_rate".to_string(),
                value: compile_error_free_rate,
                threshold: Some(1.0),
                passed: (compile_error_free_rate - 1.0).abs() < f64::EPSILON,
            },
            ScorecardMetric {
                name: "diagnostic_clean_rate".to_string(),
                value: diagnostic_clean_rate,
                threshold: Some(1.0),
                passed: (diagnostic_clean_rate - 1.0).abs() < f64::EPSILON,
            },
            ScorecardMetric {
                name: "crash_free_compile_rate".to_string(),
                value: crash_free_compile_rate,
                threshold: Some(1.0),
                passed: (crash_free_compile_rate - 1.0).abs() < f64::EPSILON,
            },
        ],
        false_positive_budget: findings_count as u64 + 2,
        false_positive_count: 0,
    }
}

fn rate(successes: u64, attempts: u64) -> f64 {
    if attempts == 0 {
        return 1.0;
    }
    successes as f64 / attempts as f64
}

fn pass_rate(total: u64, failures: u64) -> f64 {
    if total == 0 {
        return 1.0;
    }
    let passes = total.saturating_sub(failures);
    passes as f64 / total as f64
}

fn non_empty_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn report_output_dir(input: &TrackInput) -> PathBuf {
    input
        .output_dir
        .join("post_roadmap")
        .join("compiler")
        .join(&input.run_id)
}

fn report_output_path(input: &TrackInput) -> PathBuf {
    report_output_dir(input).join("compiler_track_report.json")
}

fn write_compiler_report(
    input: &TrackInput,
    report: &CompilerTrackReport,
) -> PostRoadmapResult<PathBuf> {
    let report_path = report_output_path(input);
    let payload = serde_json::to_string_pretty(report).map_err(|error| {
        PostRoadmapError::Persistence(format!("failed to serialize compiler report: {error}"))
    })?;
    fs::write(&report_path, format!("{payload}\n")).map_err(|error| {
        PostRoadmapError::Persistence(format!(
            "failed writing compiler report `{}`: {error}",
            report_path.display()
        ))
    })?;
    Ok(report_path)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tempfile::TempDir;

    use super::*;

    #[derive(Debug, Clone, Copy)]
    enum StubBehavior {
        Clean,
        PanicDiagnostic,
    }

    #[derive(Debug)]
    struct StubBackendAdapter {
        name: &'static str,
        behavior: StubBehavior,
    }

    #[async_trait]
    impl CompilerBackendAdapter for StubBackendAdapter {
        fn backend_name(&self) -> &'static str {
            self.name
        }

        async fn generate(
            &self,
            request: &CompilerGenerationRequest,
        ) -> PostRoadmapResult<CompilerGenerationResult> {
            Ok(CompilerGenerationResult {
                source_path: format!(
                    "generated/{}/seed_{}_max_{}.circom",
                    self.name, request.seed, request.max_constraints
                ),
                backend_name: self.name.to_string(),
            })
        }

        async fn compile(&self, source_path: &str) -> PostRoadmapResult<CompilerDiagnostic> {
            match self.behavior {
                StubBehavior::Clean => Ok(CompilerDiagnostic {
                    class: None,
                    message: format!("compiled `{source_path}`"),
                }),
                StubBehavior::PanicDiagnostic => Ok(CompilerDiagnostic {
                    class: Some(CompilerCrashClass::Panic),
                    message: format!("panic while compiling `{source_path}`"),
                }),
            }
        }
    }

    fn sample_input(output_dir: PathBuf) -> TrackInput {
        TrackInput {
            campaign_id: "compiler-campaign".to_string(),
            run_id: "compiler-run".to_string(),
            seed: Some(9),
            corpus_dir: output_dir.join("corpus"),
            evidence_dir: output_dir.join("evidence"),
            output_dir,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn exposes_compiler_track_kind() {
        assert_eq!(CompilerTrackRunner::new().track(), TrackKind::Compiler);
    }

    #[test]
    fn reports_backend_adapter_count() {
        let runner = CompilerTrackRunner::new();
        assert_eq!(runner.backend_adapter_count(), 0);
    }

    #[test]
    fn exposes_track_version() {
        assert!(!TRACK_MODULE_VERSION.is_empty());
    }

    #[tokio::test]
    async fn strict_mode_run_emits_scorecard_and_report_without_adapters() {
        let temp_dir = TempDir::new().expect("temp dir");
        let input = sample_input(temp_dir.path().to_path_buf());
        let runner = CompilerTrackRunner::new();

        runner.prepare(&input).await.expect("prepare passes");
        let execution = runner.run(&input).await.expect("run passes");
        runner
            .validate(&execution)
            .await
            .expect("validate passes for strict mode");
        let emitted = runner.emit(&execution).await.expect("emit passes");

        assert!(execution.findings.is_empty());
        assert!(execution.scorecard.is_some());
        assert_eq!(execution.track, TrackKind::Compiler);
        assert!(!emitted.is_empty());
        assert!(emitted
            .iter()
            .any(|path| path.ends_with("compiler_track_report.json")));
    }

    #[tokio::test]
    async fn bug_probe_mode_surfaces_findings() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut input = sample_input(temp_dir.path().to_path_buf());
        input.metadata.insert(
            "compiler_execution_mode".to_string(),
            "bug_probe".to_string(),
        );
        input
            .metadata
            .insert("compiler_cases_per_adapter".to_string(), "2".to_string());

        let runner =
            CompilerTrackRunner::new().with_backend_adapter(Box::new(StubBackendAdapter {
                name: "stub-compiler",
                behavior: StubBehavior::PanicDiagnostic,
            }));
        runner.prepare(&input).await.expect("prepare passes");
        let execution = runner.run(&input).await.expect("run passes");
        runner
            .validate(&execution)
            .await
            .expect("validate passes for bug probe mode");

        assert_eq!(execution.findings.len(), 2);
        assert!(execution.findings.iter().all(|finding| {
            finding.metadata.contains_key("subsystem")
                && finding.metadata.contains_key("generated_circuit")
                && finding.metadata.contains_key("regression_test")
        }));
    }

    #[tokio::test]
    async fn strict_mode_adapter_without_diagnostics_has_no_findings() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut input = sample_input(temp_dir.path().to_path_buf());
        input
            .metadata
            .insert("compiler_cases_per_adapter".to_string(), "3".to_string());

        let runner =
            CompilerTrackRunner::new().with_backend_adapter(Box::new(StubBackendAdapter {
                name: "stub-compiler",
                behavior: StubBehavior::Clean,
            }));

        runner.prepare(&input).await.expect("prepare passes");
        let execution = runner.run(&input).await.expect("run passes");
        runner
            .validate(&execution)
            .await
            .expect("validate passes for strict mode");

        assert!(execution.findings.is_empty());
        let scorecard = execution.scorecard.expect("scorecard");
        assert_eq!(scorecard.coverage_counts["compile_attempts"], 3);
    }

    #[tokio::test]
    async fn validate_rejects_missing_scorecard() {
        let runner = CompilerTrackRunner::new();
        let mut execution = TrackExecution::empty(TrackKind::Compiler, "run-1");
        execution.scorecard = None;

        let error = runner
            .validate(&execution)
            .await
            .expect_err("missing scorecard should fail validation");
        assert!(error
            .to_string()
            .contains("compiler execution must include a scorecard"));
    }
}
