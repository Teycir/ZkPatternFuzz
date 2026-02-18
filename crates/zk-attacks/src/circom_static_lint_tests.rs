use super::*;

#[test]
fn circom_static_lint_default_checks_enabled() {
    let config = CircomStaticLintConfig::default();
    assert!(config.enabled_checks.contains(&StaticCheck::UnusedSignal));
    assert!(config
        .enabled_checks
        .contains(&StaticCheck::UnconstrainedOutput));
    assert!(config
        .enabled_checks
        .contains(&StaticCheck::DivisionBySignal));
    assert!(config
        .enabled_checks
        .contains(&StaticCheck::MissingConstraint));
}

#[test]
fn circom_static_lint_detects_common_issues() {
    let source = r#"
template Main() {
    signal input a;
    signal output out;
    signal tmp;
    signal divisor;

    tmp <-- a / divisor;
    out <-- tmp;
}
component main = Main();
"#;

    let lint = CircomStaticLint::new(CircomStaticLintConfig::default());
    let findings = lint.scan_source(source, Some("mock.circom".to_string()));
    assert!(!findings.is_empty());
    assert!(findings
        .iter()
        .all(|finding| finding.attack_type == AttackType::CircomStaticLint));
    assert!(findings
        .iter()
        .any(|finding| finding.description.contains("not constrained with <==")));
}

#[test]
fn circom_static_lint_parse_checks() {
    let parsed = CircomStaticLint::parse_checks(&[
        "unused_signal".to_string(),
        "division_by_signal".to_string(),
        "unknown".to_string(),
    ]);
    assert_eq!(parsed.len(), 2);
    assert!(parsed.contains(&StaticCheck::UnusedSignal));
    assert!(parsed.contains(&StaticCheck::DivisionBySignal));
}
