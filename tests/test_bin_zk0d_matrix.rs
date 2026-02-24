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
        fn resolve_matrix_output_root_uses_cli_override() {
            let args = Args::try_parse_from([
                "zk0d_matrix",
                "--matrix",
                "targets/zk0d_matrix.yaml",
                "--registry",
                "targets/fuzzer_registry.yaml",
                "--output-root",
                "artifacts/external_targets/manual/scan_output",
            ])
            .expect("parse matrix args");
            let parsed = resolve_matrix_output_root(&args).expect("resolve matrix output root");
            assert_eq!(
                parsed,
                std::path::PathBuf::from("artifacts/external_targets/manual/scan_output")
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

        #[test]
        fn infer_reason_code_from_output_detects_unknown_alias() {
            let code =
                infer_reason_code_from_output(1, "", "Error: Unknown alias 'external_manual'");
            assert_eq!(code.as_deref(), Some("selector_alias_unknown"));
        }

        #[test]
        fn infer_reason_code_from_output_falls_back_for_nonzero_exit() {
            let code = infer_reason_code_from_output(1, "", "random failure");
            assert_eq!(code.as_deref(), Some("batch_failed_no_reason"));
        }

        #[test]
        fn target_run_critical_findings_only_is_not_counted_as_failure() {
            let summary = TargetRunSummary {
                name: "ext003".to_string(),
                exit_code: 1,
                reason_counts: std::collections::BTreeMap::from([
                    ("critical_findings_detected".to_string(), 1usize),
                    ("selector_mismatch".to_string(), 4usize),
                ]),
            };
            assert!(!target_run_counts_as_failure(&summary));
        }

        #[test]
        fn target_run_noncritical_reason_is_counted_as_failure() {
            let summary = TargetRunSummary {
                name: "ext008".to_string(),
                exit_code: 1,
                reason_counts: std::collections::BTreeMap::from([(
                    "backend_toolchain_mismatch".to_string(),
                    1usize,
                )]),
            };
            assert!(target_run_counts_as_failure(&summary));
        }

        #[test]
        fn selector_for_target_cli_alias_overrides_matrix_alias() {
            let args = Args::try_parse_from([
                "zk0d_matrix",
                "--matrix",
                "targets/zk0d_matrix.yaml",
                "--alias",
                "cveX07_aztec_plonk_zero_bug",
            ])
            .expect("parse args");

            let target = MatrixTarget {
                name: "ext001".to_string(),
                target_circuit: "/tmp/demo.circom".to_string(),
                main_component: "main".to_string(),
                framework: "circom".to_string(),
                alias: Some("external_manual".to_string()),
                collection: None,
                template: None,
                enabled: true,
            };

            let (key, value) = selector_for_target(&args, &target).expect("selector");
            assert_eq!(key, "alias");
            assert_eq!(value, "cveX07_aztec_plonk_zero_bug");
        }

        #[test]
        fn selector_for_target_rejects_conflicting_cli_selectors() {
            let args = Args::try_parse_from([
                "zk0d_matrix",
                "--matrix",
                "targets/zk0d_matrix.yaml",
                "--alias",
                "foo",
                "--template",
                "bar.yaml",
            ])
            .expect("parse args");

            let target = MatrixTarget {
                name: "ext001".to_string(),
                target_circuit: "/tmp/demo.circom".to_string(),
                main_component: "main".to_string(),
                framework: "circom".to_string(),
                alias: Some("external_manual".to_string()),
                collection: None,
                template: None,
                enabled: true,
            };

            let err = selector_for_target(&args, &target).expect_err("selector should fail");
            let rendered = format!("{err:#}");
            assert!(
                rendered.contains("CLI selector conflict"),
                "unexpected error: {rendered}"
            );
        }
    }
}
