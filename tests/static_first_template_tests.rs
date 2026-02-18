use std::path::PathBuf;

fn static_first_template_path() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("templates")
        .join("traits")
        .join("static_first_pass.yaml")
        .to_string_lossy()
        .to_string()
}

fn load_static_first_template() -> serde_yaml::Value {
    let path = static_first_template_path();
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read static-first template '{}': {:#}", path, err));
    serde_yaml::from_str(&source).unwrap_or_else(|err| {
        panic!(
            "failed to parse static-first template '{}': {:#}",
            path, err
        )
    })
}

#[test]
fn static_first_template_enables_branch_dependent_constraint_check() {
    let template = load_static_first_template();
    let checks = template["attacks"][0]["config"]["circom_static_lint"]["enabled_checks"]
        .as_sequence()
        .expect("circom_static_lint.enabled_checks should be a YAML sequence");
    assert!(
        checks.iter().any(|value| value.as_str() == Some("branch_dependent_constraint")),
        "static-first template should enable branch_dependent_constraint check, got {:?}",
        checks
    );
}

#[test]
fn static_first_template_keeps_fail_fast_severity_gating() {
    let template = load_static_first_template();
    let static_phase = template["schedule"]
        .as_sequence()
        .and_then(|phases| phases.first())
        .expect("static-first template should include a first schedule phase");

    let fail_levels = static_phase["fail_on_findings"]
        .as_sequence()
        .expect("static_prepass.fail_on_findings should be a YAML sequence");
    assert!(
        fail_levels.iter().any(|value| value.as_str() == Some("critical")),
        "static_prepass should fail-fast on critical findings"
    );
    assert!(
        fail_levels.iter().any(|value| value.as_str() == Some("high")),
        "static_prepass should fail-fast on high findings"
    );
}
