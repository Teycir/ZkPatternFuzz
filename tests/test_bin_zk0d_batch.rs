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
                "--output-root",
                "artifacts/external_targets/manual/scan_output",
                "--jobs",
                "2",
                "--workers",
                "4",
            ])
            .expect("parse batch args");

            assert_eq!(args.template.as_deref(), Some("cveX01.yaml"));
            assert_eq!(args.target_circuit.as_deref(), Some("circuits/demo.circom"));
            assert_eq!(args.framework, "circom");
            assert_eq!(
                args.output_root.as_deref(),
                Some("artifacts/external_targets/manual/scan_output")
            );
            assert_eq!(args.jobs, 2);
            assert_eq!(args.workers, 4);
        }

        #[test]
        fn resolve_scan_output_root_uses_cli_override() {
            let root = resolve_scan_output_root(Some("artifacts/external_targets/manual/scan_output"))
                .expect("resolve output root");
            assert_eq!(
                root,
                std::path::PathBuf::from("artifacts/external_targets/manual/scan_output")
            );
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

        #[test]
        fn classify_fetch_into_as_dependency_resolution_failure() {
            let doc = serde_json::json!({
                "status": "failed",
                "stage": "preflight_backend",
                "error": "Scarb build failed: failed to fetch into: /tmp/scarb/registry/git/db/alexandria.git"
            });
            assert_eq!(
                classify_run_reason_code(&doc),
                "backend_dependency_resolution_failed"
            );
        }

        #[test]
        fn classify_circom_wrapper_oob_as_compilation_failure() {
            let doc = serde_json::json!({
                "status": "failed",
                "stage": "preflight_backend",
                "error": "Failed to run circom compiler for '/tmp/x.circom'. Last errors: error[T3001]: Out of bounds exception"
            });
            assert_eq!(classify_run_reason_code(&doc), "circom_compilation_failed");
        }

        #[test]
        fn classify_dependency_resolution_failures_in_preflight() {
            let doc = serde_json::json!({
                "status": "failed",
                "stage": "preflight_backend",
                "error": "Scarb failed to load source for dependency alexandria_math"
            });
            assert_eq!(
                classify_run_reason_code(&doc),
                "backend_dependency_resolution_failed"
            );
        }

        #[test]
        fn classify_input_contract_mismatch() {
            let doc = serde_json::json!({
                "status": "failed",
                "stage": "engine_run",
                "error": "witness calculator failed: Not all inputs have been set. Only 5 out of 6"
            });
            assert_eq!(
                classify_run_reason_code(&doc),
                "backend_input_contract_mismatch"
            );
        }

        #[test]
        fn classify_backend_tooling_missing_before_generic_preflight_failure() {
            let doc = serde_json::json!({
                "status": "failed",
                "stage": "preflight_backend",
                "error": "snarkjs not found in PATH"
            });
            assert_eq!(classify_run_reason_code(&doc), "backend_tooling_missing");
        }
    }
}
