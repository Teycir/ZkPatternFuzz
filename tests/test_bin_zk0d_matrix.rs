mod zk0d_matrix_under_test {
    #![allow(dead_code, unused_imports)]
    include!("../src/bin/zk0d_matrix.rs");

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn args_parser_accepts_core_flags() {
            let args = Args::try_parse_from([
                "zk0d_matrix",
                "--matrix",
                "targets/zk0d_matrix.yaml",
                "--registry",
                "targets/fuzzer_registry.yaml",
                "--output-root",
                "artifacts/external_targets/manual/scan_output",
                "--jobs",
                "2",
                "--workers",
                "4",
            ])
            .expect("parse matrix args");

            assert_eq!(args.matrix, "targets/zk0d_matrix.yaml");
            assert_eq!(args.registry, "targets/fuzzer_registry.yaml");
            assert_eq!(
                args.output_root.as_deref(),
                Some("artifacts/external_targets/manual/scan_output")
            );
            assert_eq!(args.jobs, 2);
            assert_eq!(args.workers, 4);
        }

        #[test]
        fn resolve_matrix_output_root_defaults_from_summary_path() {
            let args = Args::try_parse_from([
                "zk0d_matrix",
                "--matrix",
                "targets/zk0d_matrix.yaml",
                "--registry",
                "targets/fuzzer_registry.yaml",
                "--summary-tsv",
                "artifacts/external_targets/manual/latest_summary.tsv",
            ])
            .expect("parse matrix args");
            let parsed = resolve_matrix_output_root(&args).expect("resolve matrix output root");
            assert_eq!(
                parsed,
                Some(std::path::PathBuf::from(
                    "artifacts/external_targets/manual/scan_output"
                ))
            );
        }

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
    }
}
