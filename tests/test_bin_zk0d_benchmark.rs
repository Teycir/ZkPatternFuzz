mod zk0d_benchmark_under_test {
    #![allow(dead_code, unused_imports)]
    include!("../src/bin/zk0d_benchmark.rs");

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn args_parser_accepts_core_flags() {
            let args = Args::try_parse_from([
                "zk0d_benchmark",
                "--suites",
                "targets/benchmark_suites.yaml",
                "--registry",
                "targets/fuzzer_registry.yaml",
                "--trials",
                "5",
                "--jobs",
                "2",
                "--workers",
                "3",
            ])
            .expect("parse benchmark args");

            assert_eq!(
                args.suites.as_deref(),
                Some("targets/benchmark_suites.yaml")
            );
            assert_eq!(
                args.registry.as_deref(),
                Some("targets/fuzzer_registry.yaml")
            );
            assert_eq!(args.trials, 5);
            assert_eq!(args.jobs, 2);
            assert_eq!(args.workers, 3);
        }

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
    }
}
