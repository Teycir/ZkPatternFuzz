mod zk0d_batch_under_test {
    #![allow(dead_code, unused_imports)]
    include!("../src/bin/zk0d_batch.rs");

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn args_parser_accepts_core_flags() {
            let args = Args::try_parse_from([
                "zk0d_batch",
                "--template",
                "cveX01.yaml",
                "--target-circuit",
                "circuits/demo.circom",
                "--framework",
                "circom",
                "--jobs",
                "2",
                "--workers",
                "4",
            ])
            .expect("parse batch args");

            assert_eq!(args.template.as_deref(), Some("cveX01.yaml"));
            assert_eq!(args.target_circuit.as_deref(), Some("circuits/demo.circom"));
            assert_eq!(args.framework, "circom");
            assert_eq!(args.jobs, 2);
            assert_eq!(args.workers, 4);
        }

        #[test]
        fn correlation_metadata_extracts_confidence_and_oracles() {
            let description = "abc\nCorrelation: HIGH (groups=2, oracles=3, corroborating=9)";
            assert_eq!(
                parse_correlation_confidence(description).as_deref(),
                Some("high")
            );
            assert_eq!(parse_correlation_oracle_count(description), Some(3));
        }
    }
}
