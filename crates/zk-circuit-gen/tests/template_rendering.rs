use std::fs;

use rand::rngs::StdRng;
use rand::SeedableRng;
use tempfile::tempdir;
use zk_circuit_gen::{
    generate_bulk_corpus, generate_random_circuit_dsl, parse_dsl_yaml, render_backend_template,
    Assignment, Backend, BulkGenerationConfig, CircuitDsl, ConstraintEq, Expression,
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
