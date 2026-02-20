use super::*;

#[test]
fn parse_reason_tsv_reads_reason_codes() {
    let stdout = r#"
REASON_TSV_START
template	suffix	reason_code	status	stage	high_confidence_detected
a.yaml	x	completed	completed	done	0
b.yaml	y	key_generation_failed	failed	preflight_backend	1
REASON_TSV_END
"#;
    let parsed = parse_reason_tsv(stdout);
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].reason_code, "completed");
    assert!(!parsed[0].high_confidence_detected);
    assert_eq!(parsed[1].reason_code, "key_generation_failed");
    assert!(parsed[1].high_confidence_detected);
}

#[test]
fn parse_scan_findings_total_sums_lines() {
    let stdout = r#"
scan findings: 2
other line
scan findings: 5
"#;
    assert_eq!(parse_scan_findings_total(stdout), 7);
}

#[test]
fn wilson_interval_is_bounded() {
    let ci = wilson_interval(7, 10);
    assert!(ci.lower >= 0.0);
    assert!(ci.upper <= 1.0);
    assert!(ci.lower <= ci.upper);
}

#[test]
fn reached_completion_accepts_critical_findings_reason() {
    let mut reason_counts = BTreeMap::new();
    reason_counts.insert("critical_findings_detected".to_string(), 1);
    assert!(reached_completion(&reason_counts));
}

#[test]
fn suite_completion_rate_uses_completion_state_not_exit_code() {
    let outcomes = vec![
        TrialOutcome {
            suite_name: "suite".to_string(),
            suite_description: None,
            positive: false,
            target_name: "a".to_string(),
            trial_idx: 1,
            seed: 1,
            exit_code: 1,
            completed: true,
            scan_findings_total: 0,
            detected: false,
            high_confidence_detected: false,
            attack_stage_reached: true,
            reason_counts: BTreeMap::new(),
            error_message: None,
        },
        TrialOutcome {
            suite_name: "suite".to_string(),
            suite_description: None,
            positive: false,
            target_name: "b".to_string(),
            trial_idx: 2,
            seed: 2,
            exit_code: 1,
            completed: true,
            scan_findings_total: 0,
            detected: false,
            high_confidence_detected: false,
            attack_stage_reached: true,
            reason_counts: BTreeMap::new(),
            error_message: None,
        },
        TrialOutcome {
            suite_name: "suite".to_string(),
            suite_description: None,
            positive: false,
            target_name: "c".to_string(),
            trial_idx: 3,
            seed: 3,
            exit_code: 0,
            completed: false,
            scan_findings_total: 0,
            detected: false,
            high_confidence_detected: false,
            attack_stage_reached: true,
            reason_counts: BTreeMap::new(),
            error_message: None,
        },
    ];

    let suites = compute_suite_summaries(&outcomes);
    assert_eq!(suites.len(), 1);
    assert!((suites[0].completion_rate - (2.0 / 3.0)).abs() < 1e-12);
}

#[test]
fn actionable_safe_false_positives_only_counts_high_confidence() {
    let safe_low_conf = TrialOutcome {
        suite_name: "safe".to_string(),
        suite_description: None,
        positive: false,
        target_name: "a".to_string(),
        trial_idx: 1,
        seed: 1,
        exit_code: 1,
        completed: true,
        scan_findings_total: 0,
        detected: true,
        high_confidence_detected: false,
        attack_stage_reached: true,
        reason_counts: BTreeMap::new(),
        error_message: None,
    };
    let safe_high_conf = TrialOutcome {
        suite_name: "safe".to_string(),
        suite_description: None,
        positive: false,
        target_name: "b".to_string(),
        trial_idx: 1,
        seed: 2,
        exit_code: 1,
        completed: true,
        scan_findings_total: 0,
        detected: true,
        high_confidence_detected: true,
        attack_stage_reached: true,
        reason_counts: BTreeMap::new(),
        error_message: None,
    };
    let safe_runs = vec![&safe_low_conf, &safe_high_conf];
    assert_eq!(actionable_safe_false_positives(&safe_runs), 1);
}
