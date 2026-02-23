use zk_circuit_gen::{
    parse_dsl_yaml, render_backend_template, Assignment, Backend, CircuitDsl, ConstraintEq,
    Expression,
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
