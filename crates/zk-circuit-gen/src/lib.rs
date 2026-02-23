use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Circom,
    Noir,
    Halo2,
    Cairo,
}

impl Backend {
    pub const ALL: [Backend; 4] = [Self::Circom, Self::Noir, Self::Halo2, Self::Cairo];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Circom => "circom",
            Self::Noir => "noir",
            Self::Halo2 => "halo2",
            Self::Cairo => "cairo",
        }
    }

    pub fn file_extension(self) -> &'static str {
        match self {
            Self::Circom => "circom",
            Self::Noir => "nr",
            Self::Halo2 => "rs",
            Self::Cairo => "cairo",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationStrategy {
    DeepNesting,
    WideConstraints,
    PathologicalLoops,
    MixedTypes,
    MalformedIr,
}

impl MutationStrategy {
    pub const ALL: [MutationStrategy; 5] = [
        Self::DeepNesting,
        Self::WideConstraints,
        Self::PathologicalLoops,
        Self::MixedTypes,
        Self::MalformedIr,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeepNesting => "deep_nesting",
            Self::WideConstraints => "wide_constraints",
            Self::PathologicalLoops => "pathological_loops",
            Self::MixedTypes => "mixed_types",
            Self::MalformedIr => "malformed_ir",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircuitDsl {
    pub name: String,
    #[serde(default)]
    pub public_inputs: Vec<String>,
    #[serde(default)]
    pub private_inputs: Vec<String>,
    #[serde(default)]
    pub outputs: Vec<String>,
    #[serde(default)]
    pub assignments: Vec<Assignment>,
    #[serde(default)]
    pub constraints: Vec<ConstraintEq>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Assignment {
    pub target: String,
    pub expression: Expression,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConstraintEq {
    pub left: Expression,
    pub right: Expression,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Expression {
    Signal {
        name: String,
    },
    Constant {
        value: i64,
    },
    Add {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Sub {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Mul {
        left: Box<Expression>,
        right: Box<Expression>,
    },
}

#[derive(Debug, Error)]
pub enum CircuitGenError {
    #[error("failed to parse DSL YAML: {0}")]
    ParseYaml(#[from] serde_yaml::Error),
    #[error("JSON serialization/parsing error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid DSL: {0}")]
    Validation(String),
}

#[derive(Debug, Clone)]
struct ValidatedDsl {
    intermediates: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BulkGenerationConfig {
    pub output_dir: PathBuf,
    pub circuits_per_backend: usize,
    pub seed: u64,
    pub backends: Vec<Backend>,
    pub mutation_strategies: Vec<MutationStrategy>,
    pub mutation_intensity: usize,
}

impl BulkGenerationConfig {
    pub fn new(output_dir: impl Into<PathBuf>) -> Self {
        Self {
            output_dir: output_dir.into(),
            circuits_per_backend: 1_000,
            seed: 1_337,
            backends: Backend::ALL.to_vec(),
            mutation_strategies: Vec::new(),
            mutation_intensity: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationGenerationSummary {
    pub strategy: MutationStrategy,
    pub generated: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendGenerationSummary {
    pub backend: Backend,
    pub generated: usize,
    pub mutated_generated: usize,
    pub mutation_breakdown: Vec<MutationGenerationSummary>,
    pub output_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BulkGenerationReport {
    pub seed: u64,
    pub circuits_per_backend: usize,
    pub mutation_intensity: usize,
    pub mutation_strategies: Vec<MutationStrategy>,
    pub total_circuits: usize,
    pub output_dir: PathBuf,
    pub report_path: PathBuf,
    pub backends: Vec<BackendGenerationSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalAiPatternBundle {
    pub source: String,
    pub generated_at: String,
    #[serde(default)]
    pub notes: Vec<String>,
    pub patterns: Vec<AdversarialPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdversarialPattern {
    pub pattern_id: String,
    pub rationale: String,
    #[serde(default)]
    pub issue_refs: Vec<String>,
    pub target_backends: Vec<Backend>,
    #[serde(default)]
    pub mutation_strategies: Vec<MutationStrategy>,
    #[serde(default = "default_pattern_circuits_per_backend")]
    pub circuits_per_backend: usize,
    #[serde(default = "default_pattern_mutation_intensity")]
    pub mutation_intensity: usize,
    #[serde(default)]
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdversarialGenerationConfig {
    pub output_dir: PathBuf,
    pub seed: u64,
}

impl AdversarialGenerationConfig {
    pub fn new(output_dir: impl Into<PathBuf>) -> Self {
        Self {
            output_dir: output_dir.into(),
            seed: 7_331,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatternBackendGenerationSummary {
    pub backend: Backend,
    pub generated: usize,
    pub mutated_generated: usize,
    pub output_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdversarialPatternGenerationSummary {
    pub pattern_id: String,
    pub issue_refs: Vec<String>,
    pub priority: u32,
    pub backends: Vec<PatternBackendGenerationSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdversarialGenerationReport {
    pub source: String,
    pub generated_at: String,
    pub seed: u64,
    pub total_patterns: usize,
    pub total_circuits: usize,
    pub output_dir: PathBuf,
    pub report_path: PathBuf,
    pub patterns: Vec<AdversarialPatternGenerationSummary>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompilerFeedbackClass {
    Crash,
    Timeout,
    InternalCompilerError,
    UserError,
    Success,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatternFeedback {
    pub pattern_id: String,
    pub backend: Backend,
    pub class: CompilerFeedbackClass,
    #[serde(default = "default_feedback_hits")]
    pub hits: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatternFeedbackBatch {
    #[serde(default)]
    pub entries: Vec<PatternFeedback>,
}

pub fn parse_dsl_yaml(value: &str) -> Result<CircuitDsl, CircuitGenError> {
    serde_yaml::from_str(value).map_err(CircuitGenError::ParseYaml)
}

pub fn parse_dsl_json(value: &str) -> Result<CircuitDsl, CircuitGenError> {
    serde_json::from_str(value).map_err(CircuitGenError::Json)
}

pub fn parse_external_ai_pattern_bundle_json(
    value: &str,
) -> Result<ExternalAiPatternBundle, CircuitGenError> {
    serde_json::from_str(value).map_err(CircuitGenError::Json)
}

pub fn parse_pattern_feedback_json(value: &str) -> Result<PatternFeedbackBatch, CircuitGenError> {
    serde_json::from_str(value).map_err(CircuitGenError::Json)
}

pub fn render_backend_template(
    dsl: &CircuitDsl,
    backend: Backend,
) -> Result<String, CircuitGenError> {
    let validated = validate_dsl(dsl)?;
    match backend {
        Backend::Circom => Ok(render_circom(dsl, &validated)),
        Backend::Noir => Ok(render_noir(dsl)),
        Backend::Halo2 => Ok(render_halo2(dsl, &validated)),
        Backend::Cairo => Ok(render_cairo(dsl)),
    }
}

pub fn render_mutated_template(
    dsl: &CircuitDsl,
    backend: Backend,
    strategy: MutationStrategy,
    intensity: usize,
) -> Result<String, CircuitGenError> {
    let bounded_intensity = intensity.max(1);
    match strategy {
        MutationStrategy::DeepNesting => {
            let mutated = mutate_deep_nesting(dsl, bounded_intensity);
            render_backend_template(&mutated, backend)
        }
        MutationStrategy::WideConstraints => {
            let mutated = mutate_wide_constraints(dsl, bounded_intensity);
            render_backend_template(&mutated, backend)
        }
        MutationStrategy::PathologicalLoops => {
            let rendered = render_backend_template(dsl, backend)?;
            Ok(insert_pathological_loop(
                rendered,
                backend,
                bounded_intensity,
            ))
        }
        MutationStrategy::MixedTypes => {
            let rendered = render_backend_template(dsl, backend)?;
            Ok(insert_mixed_type_snippet(rendered, backend))
        }
        MutationStrategy::MalformedIr => {
            let rendered = render_backend_template(dsl, backend)?;
            Ok(inject_malformed_ir(rendered))
        }
    }
}

pub fn generate_random_circuit_dsl<R: Rng>(
    rng: &mut R,
    backend: Backend,
    ordinal: usize,
) -> CircuitDsl {
    let name = format!("gen_{}_{}", backend.as_str(), ordinal);

    let public_count = rng.gen_range(1..=3);
    let private_count = rng.gen_range(1..=4);
    let output_count = rng.gen_range(1..=2);
    let intermediate_count = rng.gen_range(1..=4);
    let constraint_count = rng.gen_range(1..=4);

    let public_inputs = (0..public_count)
        .map(|idx| format!("pub_{idx}"))
        .collect::<Vec<_>>();
    let private_inputs = (0..private_count)
        .map(|idx| format!("priv_{idx}"))
        .collect::<Vec<_>>();
    let outputs = (0..output_count)
        .map(|idx| format!("out_{idx}"))
        .collect::<Vec<_>>();

    let mut available = Vec::new();
    available.extend(public_inputs.iter().cloned());
    available.extend(private_inputs.iter().cloned());

    let mut assignments = Vec::new();
    for idx in 0..intermediate_count {
        let target = format!("tmp_{idx}");
        let expression = random_expression(rng, &available, 2);
        assignments.push(Assignment {
            target: target.clone(),
            expression,
        });
        available.push(target);
    }

    for output in &outputs {
        let expression = random_expression(rng, &available, 2);
        assignments.push(Assignment {
            target: output.clone(),
            expression,
        });
        available.push(output.clone());
    }

    let mut constraints = Vec::new();
    for _ in 0..constraint_count {
        let left_name = available[rng.gen_range(0..available.len())].clone();
        constraints.push(ConstraintEq {
            left: Expression::Signal { name: left_name },
            right: random_expression(rng, &available, 2),
        });
    }

    CircuitDsl {
        name,
        public_inputs,
        private_inputs,
        outputs,
        assignments,
        constraints,
    }
}

pub fn generate_bulk_corpus(
    config: &BulkGenerationConfig,
) -> Result<BulkGenerationReport, CircuitGenError> {
    if config.circuits_per_backend == 0 {
        return Err(CircuitGenError::Validation(
            "circuits_per_backend must be greater than zero".to_string(),
        ));
    }
    if config.backends.is_empty() {
        return Err(CircuitGenError::Validation(
            "at least one backend must be selected for bulk generation".to_string(),
        ));
    }
    if config.mutation_intensity == 0 {
        return Err(CircuitGenError::Validation(
            "mutation_intensity must be greater than zero".to_string(),
        ));
    }

    fs::create_dir_all(&config.output_dir)?;
    let mut rng = StdRng::seed_from_u64(config.seed);
    let mut backend_rows = Vec::new();
    let mut total_circuits = 0usize;

    for backend in &config.backends {
        let backend_dir = config.output_dir.join(backend.as_str());
        fs::create_dir_all(&backend_dir)?;
        let mut mutation_counts = config
            .mutation_strategies
            .iter()
            .copied()
            .map(|strategy| (strategy, 0usize))
            .collect::<Vec<_>>();

        for ordinal in 0..config.circuits_per_backend {
            let dsl = generate_random_circuit_dsl(&mut rng, *backend, ordinal);
            let rendered = render_backend_template(&dsl, *backend)?;
            let file_name = format!("{}.{}", dsl.name, backend.file_extension());
            let dsl_name = format!("{}.dsl.json", dsl.name);

            fs::write(backend_dir.join(file_name), rendered)?;
            fs::write(
                backend_dir.join(dsl_name),
                serde_json::to_string_pretty(&dsl)? + "\n",
            )?;
            total_circuits += 1;

            for (strategy, count) in &mut mutation_counts {
                let mutated =
                    render_mutated_template(&dsl, *backend, *strategy, config.mutation_intensity)?;
                let mut_name = format!(
                    "{}__mut_{}.{}",
                    dsl.name,
                    strategy.as_str(),
                    backend.file_extension()
                );
                fs::write(backend_dir.join(mut_name), mutated)?;
                *count += 1;
                total_circuits += 1;
            }
        }

        backend_rows.push(BackendGenerationSummary {
            backend: *backend,
            generated: config.circuits_per_backend,
            mutated_generated: mutation_counts.iter().map(|(_, count)| *count).sum(),
            mutation_breakdown: mutation_counts
                .into_iter()
                .map(|(strategy, generated)| MutationGenerationSummary {
                    strategy,
                    generated,
                })
                .collect(),
            output_dir: backend_dir,
        });
    }

    let report_path = config.output_dir.join("latest_report.json");
    let report = BulkGenerationReport {
        seed: config.seed,
        circuits_per_backend: config.circuits_per_backend,
        mutation_intensity: config.mutation_intensity,
        mutation_strategies: config.mutation_strategies.clone(),
        total_circuits,
        output_dir: config.output_dir.clone(),
        report_path: report_path.clone(),
        backends: backend_rows,
    };
    fs::write(&report_path, serde_json::to_string_pretty(&report)? + "\n")?;
    Ok(report)
}

pub fn evolve_patterns_from_feedback(
    bundle: &ExternalAiPatternBundle,
    feedback: &PatternFeedbackBatch,
) -> Result<ExternalAiPatternBundle, CircuitGenError> {
    validate_external_pattern_bundle(bundle)?;

    let known_pattern_ids = bundle
        .patterns
        .iter()
        .map(|pattern| pattern.pattern_id.as_str())
        .collect::<BTreeSet<_>>();

    #[derive(Default)]
    struct FeedbackStats {
        priority_delta: u32,
        crash_like_hits: usize,
    }

    let mut stats_by_pattern: BTreeMap<String, FeedbackStats> = BTreeMap::new();
    for entry in &feedback.entries {
        if !known_pattern_ids.contains(entry.pattern_id.as_str()) {
            return Err(CircuitGenError::Validation(format!(
                "feedback references unknown pattern_id `{}`",
                entry.pattern_id
            )));
        }
        let hits = entry.hits.max(1);
        let priority_weight: u32 = match entry.class {
            CompilerFeedbackClass::Crash => 6,
            CompilerFeedbackClass::Timeout => 5,
            CompilerFeedbackClass::InternalCompilerError => 7,
            CompilerFeedbackClass::UserError => 1,
            CompilerFeedbackClass::Success => 0,
        };
        let crash_like = matches!(
            entry.class,
            CompilerFeedbackClass::Crash
                | CompilerFeedbackClass::Timeout
                | CompilerFeedbackClass::InternalCompilerError
        );
        let stats = stats_by_pattern
            .entry(entry.pattern_id.clone())
            .or_default();
        stats.priority_delta = stats
            .priority_delta
            .saturating_add(priority_weight.saturating_mul(hits as u32));
        if crash_like {
            stats.crash_like_hits = stats.crash_like_hits.saturating_add(hits);
        }
    }

    let mut evolved = bundle.clone();
    for pattern in &mut evolved.patterns {
        if let Some(stats) = stats_by_pattern.get(&pattern.pattern_id) {
            pattern.priority = pattern.priority.saturating_add(stats.priority_delta);
            if stats.crash_like_hits > 0 {
                pattern.mutation_intensity = (pattern.mutation_intensity + 1).min(12);
                pattern.circuits_per_backend =
                    (pattern.circuits_per_backend + stats.crash_like_hits.min(8)).min(10_000);
            }
        }
    }

    evolved.patterns.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.pattern_id.cmp(&right.pattern_id))
    });
    Ok(evolved)
}

pub fn generate_adversarial_corpus_from_external_patterns(
    bundle: &ExternalAiPatternBundle,
    config: &AdversarialGenerationConfig,
) -> Result<AdversarialGenerationReport, CircuitGenError> {
    validate_external_pattern_bundle(bundle)?;
    fs::create_dir_all(&config.output_dir)?;

    let mut rng = StdRng::seed_from_u64(config.seed);
    let mut total_circuits = 0usize;
    let mut pattern_rows = Vec::new();

    let mut ordered_patterns = bundle.patterns.clone();
    ordered_patterns.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.pattern_id.cmp(&right.pattern_id))
    });

    for pattern in &ordered_patterns {
        let pattern_slug = sanitize_fs_token(&pattern.pattern_id);
        let pattern_dir = config.output_dir.join(&pattern_slug);
        fs::create_dir_all(&pattern_dir)?;
        let mut backend_rows = Vec::new();

        for backend in dedup_backends(&pattern.target_backends) {
            let backend_dir = pattern_dir.join(backend.as_str());
            fs::create_dir_all(&backend_dir)?;
            let mut generated = 0usize;
            let mut mutated_generated = 0usize;

            for ordinal in 0..pattern.circuits_per_backend {
                let mut dsl =
                    generate_random_circuit_dsl(&mut rng, backend, total_circuits + ordinal);
                dsl.name = format!("adv_{}_{}_{}", pattern_slug, backend.as_str(), ordinal);

                let rendered = render_backend_template(&dsl, backend)?;
                fs::write(
                    backend_dir.join(format!("{}.{}", dsl.name, backend.file_extension())),
                    rendered,
                )?;
                fs::write(
                    backend_dir.join(format!("{}.dsl.json", dsl.name)),
                    serde_json::to_string_pretty(&dsl)? + "\n",
                )?;

                generated += 1;
                total_circuits += 1;

                for strategy in dedup_mutation_strategies(&pattern.mutation_strategies) {
                    let mutated = render_mutated_template(
                        &dsl,
                        backend,
                        strategy,
                        pattern.mutation_intensity,
                    )?;
                    fs::write(
                        backend_dir.join(format!(
                            "{}__mut_{}.{}",
                            dsl.name,
                            strategy.as_str(),
                            backend.file_extension()
                        )),
                        mutated,
                    )?;
                    mutated_generated += 1;
                    total_circuits += 1;
                }
            }

            backend_rows.push(PatternBackendGenerationSummary {
                backend,
                generated,
                mutated_generated,
                output_dir: backend_dir,
            });
        }

        pattern_rows.push(AdversarialPatternGenerationSummary {
            pattern_id: pattern.pattern_id.clone(),
            issue_refs: pattern.issue_refs.clone(),
            priority: pattern.priority,
            backends: backend_rows,
        });
    }

    let report_path = config.output_dir.join("latest_report.json");
    let report = AdversarialGenerationReport {
        source: bundle.source.clone(),
        generated_at: bundle.generated_at.clone(),
        seed: config.seed,
        total_patterns: ordered_patterns.len(),
        total_circuits,
        output_dir: config.output_dir.clone(),
        report_path: report_path.clone(),
        patterns: pattern_rows,
    };
    fs::write(&report_path, serde_json::to_string_pretty(&report)? + "\n")?;
    Ok(report)
}

fn mutate_deep_nesting(dsl: &CircuitDsl, intensity: usize) -> CircuitDsl {
    let mut mutated = dsl.clone();
    let seed_name = dsl
        .public_inputs
        .first()
        .or_else(|| dsl.private_inputs.first())
        .or_else(|| dsl.outputs.first())
        .cloned()
        .unwrap_or_else(|| "seed".to_string());
    let depth = 6 + (intensity * 3);
    let nested = build_nested_expression(seed_name, depth);

    if let Some(output_name) = mutated.outputs.first().cloned() {
        for assignment in &mut mutated.assignments {
            if assignment.target == output_name {
                assignment.expression = nested;
                return mutated;
            }
        }
    }
    if let Some(last_assignment) = mutated.assignments.last_mut() {
        last_assignment.expression = nested;
    }
    mutated
}

fn mutate_wide_constraints(dsl: &CircuitDsl, intensity: usize) -> CircuitDsl {
    let mut mutated = dsl.clone();
    let anchor = dsl
        .outputs
        .first()
        .or_else(|| dsl.public_inputs.first())
        .or_else(|| dsl.private_inputs.first())
        .cloned()
        .unwrap_or_else(|| "anchor".to_string());
    let extra_constraints = 8 + (intensity * 8);

    for index in 0..extra_constraints {
        mutated.constraints.push(ConstraintEq {
            left: Expression::Signal {
                name: anchor.clone(),
            },
            right: Expression::Add {
                left: Box::new(Expression::Signal {
                    name: anchor.clone(),
                }),
                right: Box::new(Expression::Constant {
                    value: index as i64,
                }),
            },
        });
    }
    mutated
}

fn build_nested_expression(seed_name: String, depth: usize) -> Expression {
    let mut expression = Expression::Signal { name: seed_name };
    for index in 0..depth {
        let constant = Expression::Constant {
            value: ((index % 7) + 1) as i64,
        };
        expression = if index % 2 == 0 {
            Expression::Add {
                left: Box::new(expression),
                right: Box::new(constant),
            }
        } else {
            Expression::Mul {
                left: Box::new(expression),
                right: Box::new(constant),
            }
        };
    }
    expression
}

fn insert_pathological_loop(rendered: String, backend: Backend, intensity: usize) -> String {
    let iterations = 50_000 * intensity;
    let snippet = match backend {
        Backend::Circom => format!(
            "\n    // mutation:pathological_loops\n    for (var i = 0; i < {iterations}; i++) {{\n        signal loop_probe;\n        loop_probe <== i;\n    }}\n"
        ),
        Backend::Noir => format!(
            "\n    // mutation:pathological_loops\n    for i in 0..{iterations} {{\n        let _loop_probe = i;\n    }}\n"
        ),
        Backend::Halo2 => format!(
            "\n        // mutation:pathological_loops\n        for _i in 0..{iterations} {{\n            let _loop_probe = Fr::from(1u64);\n            let _ = _loop_probe;\n        }}\n"
        ),
        Backend::Cairo => format!(
            "\n    // mutation:pathological_loops\n    let mut i = 0;\n    loop {{\n        if i == {iterations} {{\n            break;\n        }};\n        i = i + 1;\n    }};\n"
        ),
    };
    insert_before_last_brace(&rendered, &snippet)
}

fn insert_mixed_type_snippet(rendered: String, backend: Backend) -> String {
    let snippet = match backend {
        Backend::Circom => "\n    // mutation:mixed_types\n    signal mixed_bool;\n    mixed_bool <-- 1;\n    mixed_bool * (mixed_bool - 1) === 0;\n".to_string(),
        Backend::Noir => "\n    // mutation:mixed_types\n    let narrow_u8: u8 = 255;\n    let widened_field: Field = narrow_u8 as Field;\n    constrain widened_field == widened_field;\n".to_string(),
        Backend::Halo2 => "\n        // mutation:mixed_types\n        let mixed_u8: u8 = 255;\n        let _mixed_field = Fr::from(mixed_u8 as u64);\n".to_string(),
        Backend::Cairo => "\n    // mutation:mixed_types\n    let narrow_u128: u128 = 255_u128;\n    let widened_felt: felt252 = narrow_u128.into();\n    assert(widened_felt == widened_felt, 'mixed_types');\n".to_string(),
    };
    insert_before_last_brace(&rendered, &snippet)
}

fn inject_malformed_ir(mut rendered: String) -> String {
    rendered.push_str("\n@@MALFORMED_IR@@\n");
    rendered
}

fn insert_before_last_brace(rendered: &str, snippet: &str) -> String {
    if let Some(index) = rendered.rfind('}') {
        let (before, after) = rendered.split_at(index);
        let mut out = String::with_capacity(rendered.len() + snippet.len() + 1);
        out.push_str(before);
        out.push_str(snippet);
        out.push_str(after);
        out
    } else {
        format!("{rendered}\n{snippet}")
    }
}

fn random_expression<R: Rng>(rng: &mut R, available: &[String], depth: usize) -> Expression {
    if depth == 0 || rng.gen_bool(0.40) {
        return random_leaf_expression(rng, available);
    }
    let left = Box::new(random_expression(rng, available, depth - 1));
    let right = Box::new(random_expression(rng, available, depth - 1));
    match rng.gen_range(0..3) {
        0 => Expression::Add { left, right },
        1 => Expression::Sub { left, right },
        _ => Expression::Mul { left, right },
    }
}

fn random_leaf_expression<R: Rng>(rng: &mut R, available: &[String]) -> Expression {
    if !available.is_empty() && rng.gen_bool(0.75) {
        let index = rng.gen_range(0..available.len());
        Expression::Signal {
            name: available[index].clone(),
        }
    } else {
        Expression::Constant {
            value: rng.gen_range(-9..=9),
        }
    }
}

fn default_pattern_circuits_per_backend() -> usize {
    10
}

fn default_pattern_mutation_intensity() -> usize {
    3
}

fn default_feedback_hits() -> usize {
    1
}

fn validate_external_pattern_bundle(
    bundle: &ExternalAiPatternBundle,
) -> Result<(), CircuitGenError> {
    if bundle.source.trim().is_empty() {
        return Err(CircuitGenError::Validation(
            "external AI pattern bundle source must not be empty".to_string(),
        ));
    }
    if bundle.generated_at.trim().is_empty() {
        return Err(CircuitGenError::Validation(
            "external AI pattern bundle generated_at must not be empty".to_string(),
        ));
    }
    if bundle.patterns.is_empty() {
        return Err(CircuitGenError::Validation(
            "external AI pattern bundle must include at least one pattern".to_string(),
        ));
    }

    let mut seen_pattern_ids = BTreeSet::new();
    for pattern in &bundle.patterns {
        if pattern.pattern_id.trim().is_empty() {
            return Err(CircuitGenError::Validation(
                "pattern_id must not be empty".to_string(),
            ));
        }
        if !seen_pattern_ids.insert(pattern.pattern_id.clone()) {
            return Err(CircuitGenError::Validation(format!(
                "duplicate pattern_id `{}`",
                pattern.pattern_id
            )));
        }
        if sanitize_fs_token(&pattern.pattern_id).is_empty() {
            return Err(CircuitGenError::Validation(format!(
                "pattern `{}` contains no filesystem-safe characters",
                pattern.pattern_id
            )));
        }
        if pattern.issue_refs.is_empty() {
            return Err(CircuitGenError::Validation(format!(
                "pattern `{}` must include at least one issue_refs entry",
                pattern.pattern_id
            )));
        }
        if pattern.target_backends.is_empty() {
            return Err(CircuitGenError::Validation(format!(
                "pattern `{}` must target at least one backend",
                pattern.pattern_id
            )));
        }
        if pattern.circuits_per_backend == 0 {
            return Err(CircuitGenError::Validation(format!(
                "pattern `{}` circuits_per_backend must be greater than zero",
                pattern.pattern_id
            )));
        }
        if pattern.mutation_intensity == 0 {
            return Err(CircuitGenError::Validation(format!(
                "pattern `{}` mutation_intensity must be greater than zero",
                pattern.pattern_id
            )));
        }
    }
    Ok(())
}

fn dedup_backends(backends: &[Backend]) -> Vec<Backend> {
    let mut deduped = Vec::new();
    for backend in backends {
        if !deduped.contains(backend) {
            deduped.push(*backend);
        }
    }
    deduped
}

fn dedup_mutation_strategies(strategies: &[MutationStrategy]) -> Vec<MutationStrategy> {
    let mut deduped = Vec::new();
    for strategy in strategies {
        if !deduped.contains(strategy) {
            deduped.push(*strategy);
        }
    }
    deduped
}

fn sanitize_fs_token(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        let is_ok = ch.is_ascii_alphanumeric() || ch == '-' || ch == '_';
        if is_ok {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

fn validate_dsl(dsl: &CircuitDsl) -> Result<ValidatedDsl, CircuitGenError> {
    let name = dsl.name.trim();
    if name.is_empty() {
        return Err(CircuitGenError::Validation(
            "circuit name must not be empty".to_string(),
        ));
    }
    validate_identifier(name)?;

    let mut declared = BTreeSet::new();
    for item in dsl.public_inputs.iter().chain(dsl.private_inputs.iter()) {
        validate_identifier(item)?;
        if !declared.insert(item.clone()) {
            return Err(CircuitGenError::Validation(format!(
                "duplicate signal declaration `{item}`"
            )));
        }
    }

    let mut output_set = BTreeSet::new();
    for output in &dsl.outputs {
        validate_identifier(output)?;
        if !output_set.insert(output.clone()) {
            return Err(CircuitGenError::Validation(format!(
                "duplicate output declaration `{output}`"
            )));
        }
        if declared.contains(output) {
            return Err(CircuitGenError::Validation(format!(
                "output `{output}` reuses input identifier"
            )));
        }
    }

    let mut known_signals = declared.clone();
    let mut assigned_outputs = BTreeSet::new();
    let mut assigned_targets = BTreeSet::new();
    let mut intermediates = Vec::new();

    for assignment in &dsl.assignments {
        validate_identifier(&assignment.target)?;
        validate_expression_references(&assignment.expression, &known_signals)?;

        if declared.contains(&assignment.target) {
            return Err(CircuitGenError::Validation(format!(
                "assignment target `{}` cannot overwrite an input",
                assignment.target
            )));
        }
        if !assigned_targets.insert(assignment.target.clone()) {
            return Err(CircuitGenError::Validation(format!(
                "assignment target `{}` is defined more than once",
                assignment.target
            )));
        }

        if output_set.contains(&assignment.target) {
            assigned_outputs.insert(assignment.target.clone());
        } else {
            intermediates.push(assignment.target.clone());
        }
        known_signals.insert(assignment.target.clone());
    }

    for output in &dsl.outputs {
        if !assigned_outputs.contains(output) {
            return Err(CircuitGenError::Validation(format!(
                "output `{output}` is never assigned"
            )));
        }
    }

    for constraint in &dsl.constraints {
        validate_expression_references(&constraint.left, &known_signals)?;
        validate_expression_references(&constraint.right, &known_signals)?;
    }

    if dsl.assignments.is_empty() && dsl.constraints.is_empty() {
        return Err(CircuitGenError::Validation(
            "DSL must include at least one assignment or one constraint".to_string(),
        ));
    }

    Ok(ValidatedDsl { intermediates })
}

fn validate_identifier(value: &str) -> Result<(), CircuitGenError> {
    if value.is_empty() {
        return Err(CircuitGenError::Validation(
            "identifier must not be empty".to_string(),
        ));
    }
    let mut chars = value.chars();
    let first = chars.next().unwrap_or('_');
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(CircuitGenError::Validation(format!(
            "identifier `{value}` must start with [A-Za-z_]"
        )));
    }
    if chars.any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_')) {
        return Err(CircuitGenError::Validation(format!(
            "identifier `{value}` must contain only [A-Za-z0-9_]"
        )));
    }
    Ok(())
}

fn validate_expression_references(
    expression: &Expression,
    known: &BTreeSet<String>,
) -> Result<(), CircuitGenError> {
    for name in collect_signal_references(expression) {
        if !known.contains(&name) {
            return Err(CircuitGenError::Validation(format!(
                "expression references unknown signal `{name}`"
            )));
        }
    }
    Ok(())
}

fn collect_signal_references(expression: &Expression) -> Vec<String> {
    let mut out = Vec::new();
    collect_refs_into(expression, &mut out);
    out
}

fn collect_refs_into(expression: &Expression, out: &mut Vec<String>) {
    match expression {
        Expression::Signal { name } => out.push(name.clone()),
        Expression::Constant { .. } => {}
        Expression::Add { left, right }
        | Expression::Sub { left, right }
        | Expression::Mul { left, right } => {
            collect_refs_into(left, out);
            collect_refs_into(right, out);
        }
    }
}

fn render_expression(expression: &Expression) -> String {
    match expression {
        Expression::Signal { name } => name.clone(),
        Expression::Constant { value } => value.to_string(),
        Expression::Add { left, right } => {
            format!(
                "({} + {})",
                render_expression(left),
                render_expression(right)
            )
        }
        Expression::Sub { left, right } => {
            format!(
                "({} - {})",
                render_expression(left),
                render_expression(right)
            )
        }
        Expression::Mul { left, right } => {
            format!(
                "({} * {})",
                render_expression(left),
                render_expression(right)
            )
        }
    }
}

fn render_circom(dsl: &CircuitDsl, validated: &ValidatedDsl) -> String {
    let mut lines = vec![
        "pragma circom 2.1.6;".to_string(),
        "".to_string(),
        format!("template {}() {{", dsl.name),
        "    // Public/private visibility is assigned by the host when wiring `main` inputs."
            .to_string(),
    ];

    for signal in dsl.public_inputs.iter().chain(dsl.private_inputs.iter()) {
        lines.push(format!("    signal input {signal};"));
    }
    for output in &dsl.outputs {
        lines.push(format!("    signal output {output};"));
    }
    for intermediate in &validated.intermediates {
        lines.push(format!("    signal {intermediate};"));
    }
    lines.push("".to_string());

    for assignment in &dsl.assignments {
        lines.push(format!(
            "    {} <== {};",
            assignment.target,
            render_expression(&assignment.expression)
        ));
    }
    if !dsl.constraints.is_empty() {
        lines.push("".to_string());
    }
    for constraint in &dsl.constraints {
        lines.push(format!(
            "    {} === {};",
            render_expression(&constraint.left),
            render_expression(&constraint.right)
        ));
    }

    lines.push("}".to_string());
    lines.push("".to_string());
    lines.push(format!("component main = {}();", dsl.name));
    lines.join("\n")
}

fn render_noir(dsl: &CircuitDsl) -> String {
    let mut params = Vec::new();
    for input in &dsl.public_inputs {
        params.push(format!("pub {input}: Field"));
    }
    for input in &dsl.private_inputs {
        params.push(format!("{input}: Field"));
    }

    let return_type = if dsl.outputs.is_empty() {
        "".to_string()
    } else if dsl.outputs.len() == 1 {
        " -> Field".to_string()
    } else {
        let types = vec!["Field"; dsl.outputs.len()].join(", ");
        format!(" -> ({types})")
    };

    let mut lines = vec![
        format!("fn main({}){} {{", params.join(", "), return_type),
        "    // Generated from compiler-fuzzing DSL.".to_string(),
    ];
    for assignment in &dsl.assignments {
        lines.push(format!(
            "    let {} = {};",
            assignment.target,
            render_expression(&assignment.expression)
        ));
    }
    for constraint in &dsl.constraints {
        lines.push(format!(
            "    constrain {} == {};",
            render_expression(&constraint.left),
            render_expression(&constraint.right)
        ));
    }
    if dsl.outputs.len() == 1 {
        lines.push(format!("    {}", dsl.outputs[0]));
    } else if dsl.outputs.len() > 1 {
        lines.push(format!("    ({})", dsl.outputs.join(", ")));
    }
    lines.push("}".to_string());
    lines.join("\n")
}

fn render_cairo(dsl: &CircuitDsl) -> String {
    let mut params = Vec::new();
    for input in dsl.public_inputs.iter().chain(dsl.private_inputs.iter()) {
        params.push(format!("{input}: felt252"));
    }

    let return_type = if dsl.outputs.is_empty() {
        "".to_string()
    } else if dsl.outputs.len() == 1 {
        " -> felt252".to_string()
    } else {
        let types = vec!["felt252"; dsl.outputs.len()].join(", ");
        format!(" -> ({types})")
    };

    let mut lines = vec![
        "fn main(".to_string(),
        format!("    {}", params.join(", ")),
        format!("){} {{", return_type),
        "    // Generated from compiler-fuzzing DSL.".to_string(),
    ];
    for assignment in &dsl.assignments {
        lines.push(format!(
            "    let {} = {};",
            assignment.target,
            render_expression(&assignment.expression)
        ));
    }
    for constraint in &dsl.constraints {
        lines.push(format!(
            "    assert({} == {}, 'dsl_constraint_failed');",
            render_expression(&constraint.left),
            render_expression(&constraint.right)
        ));
    }
    if dsl.outputs.len() == 1 {
        lines.push(format!("    {}", dsl.outputs[0]));
    } else if dsl.outputs.len() > 1 {
        lines.push(format!("    ({})", dsl.outputs.join(", ")));
    }
    lines.push("}".to_string());
    lines.join("\n")
}

fn render_halo2(dsl: &CircuitDsl, validated: &ValidatedDsl) -> String {
    let mut signals = Vec::new();
    signals.extend(dsl.public_inputs.iter().cloned());
    signals.extend(dsl.private_inputs.iter().cloned());
    signals.extend(dsl.outputs.iter().cloned());
    signals.extend(validated.intermediates.iter().cloned());
    if signals.is_empty() {
        signals.push("value".to_string());
    }

    let circuit_name = to_pascal_case(&dsl.name);
    let config_name = format!("{circuit_name}Config");
    let advice_field = |name: &str| format!("col_{name}");
    let primary_col = advice_field(&signals[0]);

    let mut lines = vec![
        "use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};".to_string(),
        "use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error};".to_string(),
        "use halo2_proofs::poly::Rotation;".to_string(),
        "use halo2curves::bn256::Fr;".to_string(),
        "".to_string(),
        "#[derive(Clone, Debug)]".to_string(),
        format!("pub struct {config_name} {{"),
    ];
    for signal in &signals {
        lines.push(format!("    pub {}: Column<Advice>,", advice_field(signal)));
    }
    lines.push("}".to_string());
    lines.push("".to_string());
    lines.push(format!("pub struct {circuit_name}Circuit;"));
    lines.push("".to_string());
    lines.push(format!("impl Circuit<Fr> for {circuit_name}Circuit {{"));
    lines.push(format!("    type Config = {config_name};"));
    lines.push("    type FloorPlanner = SimpleFloorPlanner;".to_string());
    lines.push("".to_string());
    lines.push("    fn without_witnesses(&self) -> Self {".to_string());
    lines.push(format!("        {circuit_name}Circuit"));
    lines.push("    }".to_string());
    lines.push("".to_string());
    lines.push("    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {".to_string());
    for signal in &signals {
        lines.push(format!(
            "        let {} = meta.advice_column();",
            advice_field(signal)
        ));
    }
    lines.push("".to_string());
    for (index, constraint) in dsl.constraints.iter().enumerate() {
        lines.push(format!(
            "        meta.create_gate(\"dsl_constraint_{}\", |meta| {{",
            index + 1
        ));
        lines.push(format!(
            "            // enforce {} == {}",
            render_expression(&constraint.left),
            render_expression(&constraint.right)
        ));
        lines.push(format!(
            "            let lhs = meta.query_advice({}, Rotation::cur());",
            primary_col
        ));
        lines.push(format!(
            "            let rhs = meta.query_advice({}, Rotation::cur());",
            primary_col
        ));
        lines.push("            vec![lhs - rhs]".to_string());
        lines.push("        });".to_string());
    }
    lines.push("".to_string());
    lines.push(format!("        {config_name} {{"));
    for signal in &signals {
        lines.push(format!(
            "            {}: {},",
            advice_field(signal),
            advice_field(signal)
        ));
    }
    lines.push("        }".to_string());
    lines.push("    }".to_string());
    lines.push("".to_string());
    lines.push(
        "    fn synthesize(&self, _config: Self::Config, _layouter: impl Layouter<Fr>) -> Result<(), Error> {".to_string(),
    );
    lines.push("        // Assignment plan generated from DSL:".to_string());
    for assignment in &dsl.assignments {
        lines.push(format!(
            "        // {} = {};",
            assignment.target,
            render_expression(&assignment.expression)
        ));
    }
    lines.push("        Ok(())".to_string());
    lines.push("    }".to_string());
    lines.push("}".to_string());
    lines.join("\n")
}

fn to_pascal_case(value: &str) -> String {
    let mut out = String::new();
    for part in value.split('_').filter(|part| !part.is_empty()) {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.extend(chars.map(|c| c.to_ascii_lowercase()));
        }
    }
    if out.is_empty() {
        "GeneratedCircuit".to_string()
    } else {
        out
    }
}
