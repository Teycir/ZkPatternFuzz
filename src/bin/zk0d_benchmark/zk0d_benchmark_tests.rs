    use super::*;

    #[test]
    fn parse_reason_tsv_reads_reason_codes() {
        let stdout = r#"
REASON_TSV_START
template	suffix	reason_code	status	stage
a.yaml	x	completed	completed	done
b.yaml	y	key_generation_failed	failed	preflight_backend
REASON_TSV_END
"#;
        let parsed = parse_reason_tsv(stdout);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], "completed");
        assert_eq!(parsed[1], "key_generation_failed");
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
