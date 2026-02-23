use std::fs;

use rand::rngs::StdRng;
use rand::SeedableRng;
use tempfile::tempdir;
use zk_circuit_gen::{
    compile_and_extract_structure, evolve_patterns_from_feedback,
    extract_semantic_intent_from_text, generate_adversarial_corpus_from_external_patterns,
    generate_bulk_corpus, generate_random_circuit_dsl, parse_dsl_yaml,
    parse_external_ai_pattern_bundle_json, parse_pattern_feedback_json, render_backend_template,
    render_mutated_template, AdversarialGenerationConfig, Assignment, Backend,
    BulkGenerationConfig, CircuitDsl, ConstraintEq, Expression, MutationStrategy,
    SemanticIntentKind,
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
