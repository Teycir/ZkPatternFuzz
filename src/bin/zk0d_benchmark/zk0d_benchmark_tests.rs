
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
