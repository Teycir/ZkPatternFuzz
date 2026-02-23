use std::collections::BTreeMap;
use std::fs;
use std::process::Command;

use rand::rngs::StdRng;
use rand::SeedableRng;
use tempfile::tempdir;
use zk_circuit_gen::{
    compare_compiled_structures, compile_and_extract_structure,
    evaluate_known_compiler_bug_regressions, evolve_patterns_from_feedback,
    extract_semantic_intent_from_text, generate_adversarial_corpus_from_external_patterns,
    generate_bulk_corpus, generate_random_circuit_dsl, parse_dsl_yaml,
    parse_external_ai_pattern_bundle_json, parse_pattern_feedback_json, render_backend_template,
    render_mutated_template, render_semantic_constraint_report_markdown,
    run_compiler_crash_detection, run_compiler_probe_case, run_differential_compiler_matrix,
    run_differential_compiler_matrix_with_constraint_overrides,
    run_differential_version_matrix_campaign, verify_compiled_constraints_match_intent,
    AdversarialGenerationConfig, Assignment, Backend, BulkGenerationConfig, CircuitDsl,
    CompilerExecutionStatus, CompilerFailureClass, CompilerProbeCase, ConstraintEq,
    DifferentialComparisonAxis, DifferentialVersionMatrixConfig, Expression,
    KnownCompilerBugExpectation, MutationStrategy, RegressionStatus, SemanticIntentKind,
};

fn sample_dsl() -> CircuitDsl {
    CircuitDsl {
        name: "membership_check".to_string(),
        public_inputs: vec!["root".to_string()],
        private_inputs: vec!["leaf".to_string(), "path".to_string()],
        outputs: vec!["is_member".to_string()],
        assignments: vec![
            Assignment {
                target: "acc".to_string(),
                expression: Expression::Add {
                    left: Box::new(Expression::Signal {
                        name: "leaf".to_string(),
                    }),
                    right: Box::new(Expression::Signal {
                        name: "path".to_string(),
                    }),
                },
            },
            Assignment {
                target: "is_member".to_string(),
                expression: Expression::Sub {
                    left: Box::new(Expression::Signal {
                        name: "acc".to_string(),
                    }),
                    right: Box::new(Expression::Signal {
                        name: "root".to_string(),
                    }),
                },
            },
        ],
        constraints: vec![ConstraintEq {
            left: Expression::Signal {
                name: "is_member".to_string(),
            },
            right: Expression::Constant { value: 0 },
        }],
    }
}

fn compile_halo2_template_with_rustc_stub(
    compile_dir: &std::path::Path,
    case_id: &str,
    rendered: &str,
) -> Result<(bool, String), Box<dyn std::error::Error>> {
    let wrapper_path = compile_dir.join(format!("{case_id}.rs"));
    let artifact_path = compile_dir.join(format!("lib{case_id}.rlib"));
    let wrapper = format!("{}\n\n{}", halo2_stub_prelude(), rendered);
    fs::write(&wrapper_path, wrapper)?;

    let output = Command::new("rustc")
        .arg("--edition=2021")
        .arg("--crate-type=lib")
        .arg(&wrapper_path)
        .arg("-o")
        .arg(&artifact_path)
        .output()?;
    if output.status.success() {
        return Ok((true, String::new()));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr_excerpt = stderr.lines().take(12).collect::<Vec<_>>().join("\n");
    Ok((false, stderr_excerpt))
}

fn halo2_stub_prelude() -> &'static str {
    r#"#![allow(dead_code)]
#![allow(unused_imports)]

mod halo2_proofs {
    pub mod circuit {
        pub trait Layouter<F> {}
        #[derive(Clone, Debug)]
        pub struct SimpleFloorPlanner;
        #[derive(Clone, Debug)]
        pub struct Value<F>(pub Option<F>);
    }

    pub mod poly {
        #[derive(Clone, Copy, Debug)]
        pub struct Rotation;
        impl Rotation {
            pub fn cur() -> Self {
                Self
            }
        }
    }

    pub mod plonk {
        use super::circuit::Layouter;
        use super::poly::Rotation;
        use std::marker::PhantomData;

        #[derive(Clone, Copy, Debug)]
        pub struct Advice;

        #[derive(Clone, Copy, Debug)]
        pub struct Column<T> {
            _index: usize,
            _marker: PhantomData<T>,
        }

        #[derive(Clone, Debug)]
        pub struct Error;

        #[derive(Clone, Debug)]
        pub struct Expression<F> {
            _marker: PhantomData<F>,
        }

        impl<F> std::ops::Sub for Expression<F> {
            type Output = Expression<F>;
            fn sub(self, _rhs: Self) -> Self::Output {
                Expression {
                    _marker: PhantomData,
                }
            }
        }

        pub struct VirtualCells<F> {
            _marker: PhantomData<F>,
        }

        impl<F> VirtualCells<F> {
            pub fn query_advice(
                &mut self,
                _column: Column<Advice>,
                _rotation: Rotation,
            ) -> Expression<F> {
                Expression {
                    _marker: PhantomData,
                }
            }
        }

        pub struct ConstraintSystem<F> {
            next: usize,
            _marker: PhantomData<F>,
        }

        impl<F> ConstraintSystem<F> {
            pub fn advice_column(&mut self) -> Column<Advice> {
                let index = self.next;
                self.next += 1;
                Column {
                    _index: index,
                    _marker: PhantomData,
                }
            }

            pub fn create_gate(
                &mut self,
                _name: &str,
                mut gate: impl FnMut(&mut VirtualCells<F>) -> Vec<Expression<F>>,
            ) {
                let mut cells = VirtualCells {
                    _marker: PhantomData,
                };
                let _ = gate(&mut cells);
            }
        }

        impl<F> Default for ConstraintSystem<F> {
            fn default() -> Self {
                Self {
                    next: 0,
                    _marker: PhantomData,
                }
            }
        }

        pub trait Circuit<F>: Sized {
            type Config: Clone;
            type FloorPlanner;
            fn without_witnesses(&self) -> Self;
            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config;
            fn synthesize(
                &self,
                config: Self::Config,
                layouter: impl Layouter<F>,
            ) -> Result<(), Error>;
        }
    }
}

mod halo2curves {
    pub mod bn256 {
        #[derive(Clone, Copy, Debug)]
        pub struct Fr(pub u64);
    }
}
"#
}

#[test]
fn parses_yaml_dsl() {
    let yaml = r#"
name: tiny
public_inputs: [a]
private_inputs: [b]
outputs: [out]
assignments:
  - target: out
    expression:
      op: add
      left:
        op: signal
        name: a
      right:
        op: signal
        name: b
constraints:
  - left:
      op: signal
      name: out
    right:
      op: constant
      value: 3
"#;
    let dsl = parse_dsl_yaml(yaml).expect("valid yaml dsl");
    assert_eq!(dsl.name, "tiny");
    assert_eq!(dsl.outputs, vec!["out".to_string()]);
}

#[test]
fn renders_backend_templates() {
    let dsl = sample_dsl();

    let circom = render_backend_template(&dsl, Backend::Circom).expect("circom");
    assert!(circom.contains("pragma circom"));
    assert!(circom.contains("component main = membership_check();"));

    let noir = render_backend_template(&dsl, Backend::Noir).expect("noir");
    assert!(noir.contains("fn main("));
    assert!(noir.contains("constrain"));

    let cairo = render_backend_template(&dsl, Backend::Cairo).expect("cairo");
    assert!(cairo.contains("fn main("));
    assert!(cairo.contains("assert("));

    let halo2 = render_backend_template(&dsl, Backend::Halo2).expect("halo2");
    assert!(halo2.contains("impl Circuit<Fr>"));
    assert!(halo2.contains("meta.create_gate"));
}

#[test]
fn rejects_unknown_signal_reference() {
    let mut dsl = sample_dsl();
    dsl.assignments[0].expression = Expression::Signal {
        name: "unknown_signal".to_string(),
    };
    let error = render_backend_template(&dsl, Backend::Circom)
        .expect_err("unknown signal should fail validation");
    assert!(error.to_string().contains("unknown signal"));
}

#[test]
fn rejects_unassigned_output() {
    let mut dsl = sample_dsl();
    dsl.assignments.pop();
    let error = render_backend_template(&dsl, Backend::Noir)
        .expect_err("unassigned output should fail validation");
    assert!(error.to_string().contains("never assigned"));
}

#[test]
fn random_dsl_generation_renders_across_backends() {
    let mut rng = StdRng::seed_from_u64(7);
    for backend in Backend::ALL {
        for ordinal in 0..32 {
            let dsl = generate_random_circuit_dsl(&mut rng, backend, ordinal);
            let rendered = render_backend_template(&dsl, backend).expect("rendered");
            assert!(!rendered.trim().is_empty());
        }
    }
}

#[test]
fn bulk_generator_writes_expected_files_and_report() {
    let tmp = tempdir().expect("tempdir");
    let mut config = BulkGenerationConfig::new(tmp.path());
    config.circuits_per_backend = 5;
    config.seed = 99;
    config.backends = vec![Backend::Circom, Backend::Noir];

    let report = generate_bulk_corpus(&config).expect("bulk generation");
    assert_eq!(report.circuits_per_backend, 5);
    assert!(report.mutation_strategies.is_empty());
    assert_eq!(report.total_circuits, 10);
    assert_eq!(report.backends.len(), 2);
    assert!(report.report_path.exists());

    for backend in [Backend::Circom, Backend::Noir] {
        let dir = tmp.path().join(backend.as_str());
        let entries = fs::read_dir(&dir)
            .expect("read backend dir")
            .map(|entry| entry.expect("entry").path())
            .collect::<Vec<_>>();
        let source_files = entries
            .iter()
            .filter(|path| {
                path.extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext == backend.file_extension())
                    .unwrap_or(false)
            })
            .count();
        let dsl_files = entries
            .iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.ends_with(".dsl.json"))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(source_files, 5);
        assert_eq!(dsl_files, 5);
    }
}

#[test]
fn mutation_strategies_render_expected_signals() {
    let dsl = sample_dsl();

    let deep = render_mutated_template(&dsl, Backend::Noir, MutationStrategy::DeepNesting, 3)
        .expect("deep nesting render");
    assert!(deep.contains("let is_member ="));

    let wide = render_mutated_template(&dsl, Backend::Circom, MutationStrategy::WideConstraints, 2)
        .expect("wide constraints render");
    let wide_constraint_count = wide.matches(" === ").count();
    assert!(wide_constraint_count >= 1 + (8 + (2 * 8)));

    let loops =
        render_mutated_template(&dsl, Backend::Cairo, MutationStrategy::PathologicalLoops, 1)
            .expect("pathological loops render");
    assert!(loops.contains("mutation:pathological_loops"));

    let mixed = render_mutated_template(&dsl, Backend::Halo2, MutationStrategy::MixedTypes, 1)
        .expect("mixed types render");
    assert!(mixed.contains("mutation:mixed_types"));

    let malformed =
        render_mutated_template(&dsl, Backend::Circom, MutationStrategy::MalformedIr, 1)
            .expect("malformed ir render");
    assert!(malformed.contains("@@MALFORMED_IR@@"));
}

#[test]
fn bulk_generator_emits_mutated_corpus_variants() {
    let tmp = tempdir().expect("tempdir");
    let mut config = BulkGenerationConfig::new(tmp.path());
    config.circuits_per_backend = 3;
    config.seed = 11;
    config.backends = vec![Backend::Circom];
    config.mutation_strategies = vec![MutationStrategy::DeepNesting, MutationStrategy::MalformedIr];
    config.mutation_intensity = 2;

    let report = generate_bulk_corpus(&config).expect("bulk generation with mutations");
    assert_eq!(report.total_circuits, 3 + (3 * 2));
    assert_eq!(report.backends.len(), 1);
    assert_eq!(report.backends[0].mutated_generated, 6);
    assert_eq!(report.backends[0].mutation_breakdown.len(), 2);

    let dir = tmp.path().join("circom");
    let entries = fs::read_dir(&dir)
        .expect("read backend dir")
        .map(|entry| entry.expect("entry").path())
        .collect::<Vec<_>>();
    let mutated_sources = entries
        .iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.contains("__mut_") && name.ends_with(".circom"))
                .unwrap_or(false)
        })
        .count();
    assert_eq!(mutated_sources, 6);
}

#[test]
fn adversarial_generator_consumes_external_ai_bundle() {
    let tmp = tempdir().expect("tempdir");
    let bundle_json = r#"
{
  "source": "external_ai_user",
  "generated_at": "2026-02-23T00:00:00Z",
  "patterns": [
    {
      "pattern_id": "issue_1234",
      "rationale": "deep nesting parser pressure",
      "issue_refs": ["https://example.com/issues/1234"],
      "target_backends": ["circom"],
      "mutation_strategies": ["deep_nesting", "malformed_ir"],
      "circuits_per_backend": 2,
      "mutation_intensity": 2,
      "priority": 8
    },
    {
      "pattern_id": "issue_5678",
      "rationale": "type checker pressure",
      "issue_refs": ["https://example.com/issues/5678"],
      "target_backends": ["noir", "halo2"],
      "mutation_strategies": [],
      "circuits_per_backend": 1,
      "mutation_intensity": 3,
      "priority": 4
    }
  ]
}
"#;

    let bundle = parse_external_ai_pattern_bundle_json(bundle_json).expect("bundle parse");
    let mut config = AdversarialGenerationConfig::new(tmp.path());
    config.seed = 2026;

    let report =
        generate_adversarial_corpus_from_external_patterns(&bundle, &config).expect("generate");
    assert_eq!(report.total_patterns, 2);
    assert_eq!(report.total_circuits, 8);
    assert!(report.report_path.exists());

    let circom_dir = tmp.path().join("issue_1234").join("circom");
    let circom_sources = fs::read_dir(&circom_dir)
        .expect("read issue_1234 circom dir")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("circom"))
        .count();
    assert_eq!(circom_sources, 6);
}

#[test]
fn adversarial_generator_supports_ten_plus_external_patterns() {
    let tmp = tempdir().expect("tempdir");
    let bundle_json =
        include_str!("../../../tests/datasets/circuit_gen/external_ai_patterns.top10.sample.json");
    let bundle = parse_external_ai_pattern_bundle_json(bundle_json).expect("bundle parse");

    let mut config = AdversarialGenerationConfig::new(tmp.path());
    config.seed = 2027;
    let report =
        generate_adversarial_corpus_from_external_patterns(&bundle, &config).expect("generate");

    assert_eq!(report.total_patterns, 10);
    assert!(report.total_circuits >= 10);
    assert!(report.report_path.exists());
    assert!(report
        .patterns
        .iter()
        .all(|pattern| !pattern.issue_refs.is_empty()));
}

#[test]
fn adversarial_pattern_evolution_increases_priority_from_crash_feedback() {
    let bundle_json = r#"
{
  "source": "external_ai_user",
  "generated_at": "2026-02-23T00:00:00Z",
  "patterns": [
    {
      "pattern_id": "issue_a",
      "rationale": "compiler stress pattern a",
      "issue_refs": ["https://example.com/issues/a"],
      "target_backends": ["circom"],
      "mutation_strategies": ["deep_nesting"],
      "circuits_per_backend": 3,
      "mutation_intensity": 2,
      "priority": 1
    },
    {
      "pattern_id": "issue_b",
      "rationale": "compiler stress pattern b",
      "issue_refs": ["https://example.com/issues/b"],
      "target_backends": ["noir"],
      "mutation_strategies": ["wide_constraints"],
      "circuits_per_backend": 3,
      "mutation_intensity": 2,
      "priority": 1
    }
  ]
}
"#;
    let feedback_json = r#"
{
  "entries": [
    {
      "pattern_id": "issue_a",
      "backend": "circom",
      "class": "crash",
      "hits": 2
    },
    {
      "pattern_id": "issue_b",
      "backend": "noir",
      "class": "success",
      "hits": 5
    }
  ]
}
"#;

    let bundle = parse_external_ai_pattern_bundle_json(bundle_json).expect("bundle parse");
    let feedback = parse_pattern_feedback_json(feedback_json).expect("feedback parse");
    let evolved = evolve_patterns_from_feedback(&bundle, &feedback).expect("evolve");

    assert_eq!(evolved.patterns[0].pattern_id, "issue_a");
    assert!(evolved.patterns[0].priority > 1);
    assert!(evolved.patterns[0].mutation_intensity > 2);
    assert!(evolved.patterns[0].circuits_per_backend > 3);
}

#[test]
fn semantic_intent_extraction_reads_comments_and_docs() {
    let source = r#"
template Main() {
  signal input admin;
  signal output out;
  // only admin can mint
  /* users must not mint without admin role */
  out <== admin;
}
"#;
    let docs = r#"
Minting must require admin authorization.
Amount must be less than 1000.
"#;

    let extraction = extract_semantic_intent_from_text(source, Some(docs), Some(Backend::Circom));
    assert_eq!(extraction.source_backend, Some(Backend::Circom));
    assert!(extraction.comment_lines.len() >= 2);
    assert!(extraction.documentation_lines.len() >= 2);
    assert!(extraction
        .signals
        .iter()
        .any(|signal| signal.kind == SemanticIntentKind::AccessControl));
    assert!(extraction
        .signals
        .iter()
        .any(|signal| signal.kind == SemanticIntentKind::BoundaryCondition));
    assert!(extraction
        .signals
        .iter()
        .any(|signal| signal.kind == SemanticIntentKind::ForbiddenBehavior));
}

#[test]
fn semantic_intent_extraction_dedups_identical_statements() {
    let source = r#"
// only admin can mint
// only admin can mint
"#;
    let extraction = extract_semantic_intent_from_text(source, None, None);
    assert_eq!(extraction.signals.len(), 1);
}

#[test]
fn compile_structure_extraction_reports_constraint_and_shape_metrics() {
    let dsl = sample_dsl();
    let summary =
        compile_and_extract_structure(&dsl, Backend::Circom).expect("structure extraction");

    assert_eq!(summary.circuit_name, "membership_check");
    assert_eq!(summary.backend, Backend::Circom);
    assert_eq!(summary.constraint_count, 1);
    assert_eq!(summary.assignment_count, 2);
    assert_eq!(summary.signal_count, 5);
    assert_eq!(summary.intermediate_count, 1);
    assert!(summary.expression_node_count > 0);
    assert!(summary.max_expression_depth >= 2);
    assert!(summary.signal_reference_count >= 5);
    assert!(summary.unique_signal_references >= 4);
    assert!(summary.rendered_line_count > 0);
    assert!(summary.rendered_byte_size > 0);
}

#[test]
fn semantic_constraint_verification_matches_extracted_intent() {
    let source = r#"
template Main() {
  // only admin can mint
  // amount must be less than 1000
  // users must not mint without admin role
}
"#;

    let dsl = CircuitDsl {
        name: "semantic_guard".to_string(),
        public_inputs: vec!["admin".to_string(), "bound".to_string()],
        private_inputs: vec!["amount".to_string()],
        outputs: vec!["out".to_string()],
        assignments: vec![
            Assignment {
                target: "tmp".to_string(),
                expression: Expression::Sub {
                    left: Box::new(Expression::Signal {
                        name: "bound".to_string(),
                    }),
                    right: Box::new(Expression::Signal {
                        name: "amount".to_string(),
                    }),
                },
            },
            Assignment {
                target: "out".to_string(),
                expression: Expression::Mul {
                    left: Box::new(Expression::Signal {
                        name: "admin".to_string(),
                    }),
                    right: Box::new(Expression::Signal {
                        name: "tmp".to_string(),
                    }),
                },
            },
        ],
        constraints: vec![
            ConstraintEq {
                left: Expression::Signal {
                    name: "bound".to_string(),
                },
                right: Expression::Constant { value: 1000 },
            },
            ConstraintEq {
                left: Expression::Signal {
                    name: "out".to_string(),
                },
                right: Expression::Constant { value: 0 },
            },
        ],
    };

    let intent = extract_semantic_intent_from_text(source, None, Some(Backend::Circom));
    let report = verify_compiled_constraints_match_intent(&dsl, Backend::Circom, &intent)
        .expect("semantic verification");
    assert_eq!(report.total_intents, 3);
    assert_eq!(report.matched_intents, 3);
    assert_eq!(report.mismatched_intents, 0);
    assert!(report.constraint_gaps.is_empty());
    assert!(report.narrative_findings.is_empty());
}

#[test]
fn semantic_constraint_verification_reports_mismatch_when_boundary_unenforced() {
    let source = r#"
template Main() {
  // amount must be less than 5000
}
"#;
    let dsl = CircuitDsl {
        name: "boundary_mismatch".to_string(),
        public_inputs: vec!["amount".to_string()],
        private_inputs: vec![],
        outputs: vec!["out".to_string()],
        assignments: vec![Assignment {
            target: "out".to_string(),
            expression: Expression::Signal {
                name: "amount".to_string(),
            },
        }],
        constraints: vec![ConstraintEq {
            left: Expression::Signal {
                name: "amount".to_string(),
            },
            right: Expression::Constant { value: 1000 },
        }],
    };

    let intent = extract_semantic_intent_from_text(source, None, Some(Backend::Circom));
    let report = verify_compiled_constraints_match_intent(&dsl, Backend::Circom, &intent)
        .expect("semantic verification");
    assert_eq!(report.total_intents, 1);
    assert_eq!(report.matched_intents, 0);
    assert_eq!(report.mismatched_intents, 1);
    assert_eq!(report.constraint_gaps.len(), 1);
    assert_eq!(report.narrative_findings.len(), 1);
    assert!(report.narrative_findings[0].contains("Circuit allows"));
    assert!(report.narrative_findings[0].contains("docs say"));
    assert!(report.constraint_gaps[0].satisfiable_candidate);
    assert_eq!(
        report.constraint_gaps[0].intent_kind,
        SemanticIntentKind::BoundaryCondition
    );
    assert!(report
        .checks
        .iter()
        .any(|check| check.intent_kind == SemanticIntentKind::BoundaryCondition && !check.matched));

    let markdown = render_semantic_constraint_report_markdown(&report);
    assert!(markdown.contains("Semantic Constraint Match Report"));
    assert!(markdown.contains("Circuit allows"));
    assert!(markdown.contains("docs say"));
}

#[test]
fn semantic_violation_sample_detects_at_least_five_boundary_gaps() {
    let source =
        include_str!("../../../tests/datasets/circuit_gen/semantic_source.no_intent.sample.circom");
    let docs = include_str!(
        "../../../tests/datasets/circuit_gen/semantic_doc.boundary_violations.sample.md"
    );
    let dsl = parse_dsl_yaml(include_str!(
        "../../../tests/datasets/circuit_gen/structure_dsl.sample.yaml"
    ))
    .expect("dsl parse");

    let intent = extract_semantic_intent_from_text(source, Some(docs), Some(Backend::Circom));
    let report = verify_compiled_constraints_match_intent(&dsl, Backend::Circom, &intent)
        .expect("semantic verification");

    assert!(report.total_intents >= 6);
    assert!(report.mismatched_intents >= 5);
    assert!(report.constraint_gaps.len() >= 5);
    assert!(report.narrative_findings.len() >= 5);
}

#[test]
fn differential_matrix_compares_compiler_versions_and_backends() {
    let dsl = sample_dsl();
    let report = run_differential_compiler_matrix(
        &dsl,
        &[Backend::Circom, Backend::Noir],
        &["circom_v2_0".to_string(), "circom_v2_1".to_string()],
    )
    .expect("run differential matrix");

    assert_eq!(report.observations.len(), 4);
    assert_eq!(report.comparisons.len(), 4);
    assert_eq!(report.optimization_regressions, 0);
    assert!(report
        .comparisons
        .iter()
        .any(|entry| entry.axis == DifferentialComparisonAxis::CompilerVersion));
    assert!(report
        .comparisons
        .iter()
        .any(|entry| entry.axis == DifferentialComparisonAxis::Backend));
}

#[test]
fn differential_structure_comparison_flags_optimization_regression() {
    let dsl = sample_dsl();
    let lhs = compile_and_extract_structure(&dsl, Backend::Circom).expect("lhs");
    let mut rhs = lhs.clone();
    rhs.constraint_count += 5;

    let comparison = compare_compiled_structures(
        DifferentialComparisonAxis::CompilerVersion,
        "circom_v2_0",
        "circom_v2_1",
        &lhs,
        &rhs,
        Some(Backend::Circom),
        None,
    );
    assert_eq!(comparison.constraint_delta, 5);
    assert!(comparison.optimization_regression);
    assert!(!comparison.structure_match);
}

#[test]
fn differential_matrix_constraint_override_detects_optimization_regression() {
    let dsl = sample_dsl();
    let mut overrides = BTreeMap::new();
    overrides.insert("circom_v2_1".to_string(), 3usize);
    let report = run_differential_compiler_matrix_with_constraint_overrides(
        &dsl,
        &[Backend::Circom],
        &["circom_v2_0".to_string(), "circom_v2_1".to_string()],
        &overrides,
    )
    .expect("run differential matrix with overrides");

    assert_eq!(report.observations.len(), 2);
    assert_eq!(report.comparisons.len(), 1);
    assert_eq!(report.optimization_regressions, 1);
    assert!(report.comparisons[0].optimization_regression);
    assert_eq!(report.comparisons[0].constraint_delta, 3);
}

#[test]
fn differential_version_matrix_campaign_runs_n_times_m() {
    let tmp = tempdir().expect("tempdir");
    let mut config = DifferentialVersionMatrixConfig::new(tmp.path());
    config.circuits = 12;
    config.seed = 101;
    config.backends = vec![Backend::Circom];
    config.compiler_ids = vec![
        "circom_v2_0".to_string(),
        "circom_v2_1".to_string(),
        "circom_v2_2".to_string(),
    ];

    let report = run_differential_version_matrix_campaign(&config).expect("matrix campaign");
    assert_eq!(report.circuits, 12);
    assert_eq!(report.compiler_ids.len(), 3);
    assert_eq!(report.backends, vec![Backend::Circom]);
    assert_eq!(report.total_observations, 12 * 3);
    assert_eq!(report.total_comparisons, 12 * 3); // C(3,2)=3 per circuit
    assert!(report.report_path.exists());
    assert_eq!(report.circuits_rows.len(), 12);
    assert!(report
        .circuits_rows
        .iter()
        .all(|row| row.report_path.exists()));
}

#[test]
fn generated_halo2_templates_compile_with_rustc_stub_backend() {
    let tmp = tempdir().expect("tempdir");
    let compile_dir = tmp.path().join("compile");
    fs::create_dir_all(&compile_dir).expect("create compile dir");

    let mut rng = StdRng::seed_from_u64(20260223);
    for ordinal in 0..6 {
        let dsl = generate_random_circuit_dsl(&mut rng, Backend::Halo2, ordinal);
        let rendered = render_backend_template(&dsl, Backend::Halo2).expect("rendered");
        let (success, stderr_excerpt) = compile_halo2_template_with_rustc_stub(
            &compile_dir,
            &format!("halo2_case_{ordinal}"),
            &rendered,
        )
        .expect("compile probe");
        assert!(
            success,
            "halo2 template failed to compile for circuit `{}`: {}",
            dsl.name, stderr_excerpt
        );
    }
}

#[test]
fn compiler_probe_case_detects_timeout() {
    let tmp = tempdir().expect("tempdir");
    let source_path = tmp.path().join("timeout_probe.circom");
    fs::write(&source_path, "template Main() {}").expect("write source");

    let case = CompilerProbeCase {
        case_id: "case_timeout".to_string(),
        compiler_id: "circom_v2_1".to_string(),
        source_path,
        command: vec![
            "bash".to_string(),
            "-lc".to_string(),
            "sleep 0.2".to_string(),
        ],
        timeout_ms: 30,
    };

    let result = run_compiler_probe_case(&case).expect("probe result");
    assert_eq!(result.status, CompilerExecutionStatus::Timeout);
    assert_eq!(result.failure_class, Some(CompilerFailureClass::Timeout));
}

#[test]
fn crash_detection_classifies_failures_and_generates_bug_reports() {
    let tmp = tempdir().expect("tempdir");
    let source_path = tmp.path().join("probe_input.circom");
    fs::write(&source_path, "template Main() {}").expect("write source");

    let cases = vec![
        CompilerProbeCase {
            case_id: "case_success".to_string(),
            compiler_id: "circom_v2_1".to_string(),
            source_path: source_path.clone(),
            command: vec!["bash".to_string(), "-lc".to_string(), "echo ok".to_string()],
            timeout_ms: 100,
        },
        CompilerProbeCase {
            case_id: "case_crash".to_string(),
            compiler_id: "circom_v2_1".to_string(),
            source_path: source_path.clone(),
            command: vec![
                "bash".to_string(),
                "-lc".to_string(),
                "echo segmentation fault 1>&2; exit 139".to_string(),
            ],
            timeout_ms: 100,
        },
        CompilerProbeCase {
            case_id: "case_ice".to_string(),
            compiler_id: "circom_v2_1".to_string(),
            source_path: source_path.clone(),
            command: vec![
                "bash".to_string(),
                "-lc".to_string(),
                "echo internal compiler error: assertion failed 1>&2; exit 101".to_string(),
            ],
            timeout_ms: 100,
        },
        CompilerProbeCase {
            case_id: "case_user_error".to_string(),
            compiler_id: "circom_v2_1".to_string(),
            source_path: source_path.clone(),
            command: vec![
                "bash".to_string(),
                "-lc".to_string(),
                "echo syntax error at line 1 1>&2; exit 1".to_string(),
            ],
            timeout_ms: 100,
        },
    ];

    let report =
        run_compiler_crash_detection(&cases, tmp.path().join("repros")).expect("crash detection");
    assert_eq!(report.total_cases, 4);
    assert_eq!(report.succeeded, 1);
    assert_eq!(report.failed, 3);
    assert_eq!(report.timed_out, 0);
    assert_eq!(
        report.class_counts.get(&CompilerFailureClass::Crash),
        Some(&1)
    );
    assert_eq!(
        report
            .class_counts
            .get(&CompilerFailureClass::InternalCompilerError),
        Some(&1)
    );
    assert_eq!(
        report.class_counts.get(&CompilerFailureClass::UserError),
        Some(&1)
    );
    assert_eq!(report.bug_reports.len(), 3);
    assert!(report
        .bug_reports
        .iter()
        .all(|entry| entry.repro_source_path.exists()));
}

#[test]
fn known_bug_regression_report_marks_reproduced_fixed_and_missing() {
    let tmp = tempdir().expect("tempdir");
    let source_path = tmp.path().join("probe_input.circom");
    fs::write(&source_path, "template Main() {}").expect("write source");

    let cases = vec![
        CompilerProbeCase {
            case_id: "case_crash".to_string(),
            compiler_id: "circom_v2_1".to_string(),
            source_path: source_path.clone(),
            command: vec![
                "bash".to_string(),
                "-lc".to_string(),
                "echo segmentation fault 1>&2; exit 139".to_string(),
            ],
            timeout_ms: 100,
        },
        CompilerProbeCase {
            case_id: "case_user_error".to_string(),
            compiler_id: "circom_v2_1".to_string(),
            source_path: source_path.clone(),
            command: vec![
                "bash".to_string(),
                "-lc".to_string(),
                "echo syntax error at line 1 1>&2; exit 1".to_string(),
            ],
            timeout_ms: 100,
        },
    ];
    let report =
        run_compiler_crash_detection(&cases, tmp.path().join("repros")).expect("crash detection");

    let expectations = vec![
        KnownCompilerBugExpectation {
            bug_id: "bug_reproduced".to_string(),
            compiler_id: "circom_v2_1".to_string(),
            expected_class: CompilerFailureClass::Crash,
            source_pattern: "case_crash".to_string(),
        },
        KnownCompilerBugExpectation {
            bug_id: "bug_fixed".to_string(),
            compiler_id: "circom_v2_1".to_string(),
            expected_class: CompilerFailureClass::Crash,
            source_pattern: "case_user_error".to_string(),
        },
        KnownCompilerBugExpectation {
            bug_id: "bug_missing".to_string(),
            compiler_id: "circom_v2_1".to_string(),
            expected_class: CompilerFailureClass::Timeout,
            source_pattern: "case_timeout".to_string(),
        },
    ];

    let regression = evaluate_known_compiler_bug_regressions(&report, &expectations);
    assert_eq!(regression.total_expectations, 3);
    assert_eq!(regression.reproduced, 1);
    assert_eq!(regression.fixed, 1);
    assert_eq!(regression.missing_signal, 1);
    assert!(regression
        .results
        .iter()
        .any(|entry| entry.bug_id == "bug_reproduced"
            && entry.status == RegressionStatus::Reproduced));
    assert!(regression
        .results
        .iter()
        .any(|entry| entry.bug_id == "bug_fixed" && entry.status == RegressionStatus::Fixed));
    assert!(regression
        .results
        .iter()
        .any(|entry| entry.bug_id == "bug_missing"
            && entry.status == RegressionStatus::MissingSignal));
}
