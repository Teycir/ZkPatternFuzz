
use super::*;

#[test]
fn parse_reason_tsv_rows_extracts_reason_codes() {
    let out = r#"
noise
REASON_TSV_START
template	suffix	reason_code	status	stage
a.yaml	a	completed	completed	done
b.yaml	b	key_generation_failed	failed	preflight_backend
REASON_TSV_END
tail
"#;
    let rows = parse_reason_tsv_rows(out);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].reason_code, "completed");
    assert_eq!(rows[1].reason_code, "key_generation_failed");
}
