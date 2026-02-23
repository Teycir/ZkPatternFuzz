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
    assert!(config
        .enabled_checks
        .contains(&StaticCheck::BranchDependentConstraint));
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
    let findings = lint.scan_source(source, Some("test.circom".to_string()));
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
        "branch_dependent_constraint".to_string(),
        "unknown".to_string(),
    ]);
    assert_eq!(parsed.len(), 3);
    assert!(parsed.contains(&StaticCheck::UnusedSignal));
    assert!(parsed.contains(&StaticCheck::DivisionBySignal));
    assert!(parsed.contains(&StaticCheck::BranchDependentConstraint));
}

#[test]
fn circom_static_lint_detects_branch_dependent_assignments() {
    let source = r#"
template Main() {
    signal input selector;
    signal input a;
    signal output out;
    if (selector == 1) {
        out <-- a;
    } else {
        out <-- 0;
    }
}
component main = Main();
"#;

    let lint = CircomStaticLint::new(CircomStaticLintConfig {
        enabled_checks: vec![StaticCheck::BranchDependentConstraint],
        max_findings_per_check: 10,
        case_sensitive: false,
    });
    let findings = lint.scan_source(source, Some("test.circom".to_string()));

    assert!(findings.iter().any(|finding| {
        finding
            .description
            .contains("assigned with '<--' inside conditional")
    }));
}

#[test]
fn circom_static_lint_ignores_commented_patterns() {
    let source = r#"
template Main() {
    signal input a;
    signal output out;
    // out <-- a / divisor;
    /*
      tmp <-- a / divisor;
      out <-- tmp;
    */
    out <== a;
}
component main = Main();
"#;

    let lint = CircomStaticLint::new(CircomStaticLintConfig {
        enabled_checks: vec![
            StaticCheck::UnconstrainedOutput,
            StaticCheck::DivisionBySignal,
            StaticCheck::MissingConstraint,
        ],
        max_findings_per_check: 10,
        case_sensitive: false,
    });
    let findings = lint.scan_source(source, Some("test.circom".to_string()));
    assert!(
        findings.is_empty(),
        "commented-out risky patterns should not trigger findings, got {:?}",
        findings
            .iter()
            .map(|finding| finding.description.clone())
            .collect::<Vec<_>>()
    );
}
