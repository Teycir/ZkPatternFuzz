mod zk0d_batch_under_test {
    #![allow(dead_code, unused_imports)]
    include!("../src/bin/zk0d_batch.rs");

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

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
            let root =
                resolve_scan_output_root(Some("artifacts/external_targets/manual/scan_output"))
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
        fn classify_backend_toolchain_mismatch_in_preflight() {
            let doc = serde_json::json!({
                "status": "failed",
                "stage": "preflight_backend",
                "error": "Scarb build failed for all configured candidates. Last errors: scarb: error[E0006]: Identifier not found. error: could not compile `orion` due to previous errors"
            });
            assert_eq!(classify_run_reason_code(&doc), "backend_toolchain_mismatch");
        }

        #[test]
        fn classify_backend_toolchain_mismatch_when_cascade_is_exhausted() {
            let doc = serde_json::json!({
                "status": "failed",
                "stage": "preflight_backend",
                "error": "Toolchain cascade exhausted; set ZK_FUZZER_SCARB_VERSION_CANDIDATES with explicit versions"
            });
            assert_eq!(classify_run_reason_code(&doc), "backend_toolchain_mismatch");
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

        #[test]
        fn run_scan_exports_signal_and_cache_env_under_output_root() {
            let temp = tempfile::tempdir().expect("tempdir");
            let script_path = temp.path().join("print_env.sh");
            std::fs::write(&script_path, "#!/usr/bin/env bash\nenv\n").expect("write script");
            let mut perms = std::fs::metadata(&script_path)
                .expect("metadata")
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).expect("chmod");

            let template = TemplateInfo {
                file_name: "dummy.yaml".to_string(),
                path: temp.path().join("dummy.yaml"),
                family: Family::Auto,
            };
            std::fs::write(&template.path, "campaign:\n  name: dummy\n").expect("write template");

            let cfg = ScanRunConfig {
                bin_path: script_path.as_path(),
                target_circuit: "circuits/demo.circom",
                framework: "circom",
                main_component: "main",
                workers: 1,
                seed: 1,
                iterations: 1,
                timeout: 1,
                scan_run_root: Some("scan_run_test"),
                scan_output_root: temp.path(),
                dry_run: false,
                artifacts_root: temp.path(),
            };

            let out = run_scan(cfg, &template, Family::Auto, false, "auto__dummy")
                .expect("run_scan should execute helper script");
            assert!(out.success, "helper script should exit successfully");
            assert!(out.stdout.contains(&format!(
                "{}={}",
                SCAN_OUTPUT_ROOT_ENV,
                temp.path().display()
            )));
            assert!(out.stdout.contains(&format!(
                "{}={}",
                RUN_SIGNAL_DIR_ENV,
                temp.path().join("run_signals").display()
            )));
            assert!(out.stdout.contains(&format!(
                "{}={}",
                BUILD_CACHE_DIR_ENV,
                temp.path().join("_build_cache").display()
            )));
            assert!(out.stdout.contains("ZKF_SCAN_RUN_ROOT=scan_run_test"));
            assert!(out
                .stdout
                .contains(&format!("{}=1", HALO2_EXTERNAL_TIMEOUT_ENV)));
            assert!(out
                .stdout
                .contains(&format!("{}=1", CAIRO_EXTERNAL_TIMEOUT_ENV)));
            assert!(out
                .stdout
                .contains(&format!("{}=1", SCARB_DOWNLOAD_TIMEOUT_ENV)));
        }

        #[test]
        fn run_scan_prefers_host_cache_for_external_halo2_targets() {
            let temp = tempfile::tempdir().expect("tempdir");
            let script_path = temp.path().join("print_env.sh");
            std::fs::write(&script_path, "#!/usr/bin/env bash\nenv\n").expect("write script");
            let mut perms = std::fs::metadata(&script_path)
                .expect("metadata")
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).expect("chmod");

            let template = TemplateInfo {
                file_name: "dummy.yaml".to_string(),
                path: temp.path().join("dummy.yaml"),
                family: Family::Auto,
            };
            std::fs::write(&template.path, "campaign:\n  name: dummy\n").expect("write template");

            let cfg = ScanRunConfig {
                bin_path: script_path.as_path(),
                target_circuit: "/tmp/external-zkevm/Cargo.toml",
                framework: "halo2",
                main_component: "main",
                workers: 1,
                seed: 1,
                iterations: 1,
                timeout: 1,
                scan_run_root: Some("scan_run_test"),
                scan_output_root: temp.path(),
                dry_run: false,
                artifacts_root: temp.path(),
            };

            let out = run_scan(cfg, &template, Family::Auto, false, "auto__dummy")
                .expect("run_scan should execute helper script");
            assert!(out.success, "helper script should exit successfully");
            assert!(out
                .stdout
                .contains(&format!("{}=1", HALO2_USE_HOST_CARGO_HOME_ENV)));
            assert!(out
                .stdout
                .contains(&format!("{}=180", HALO2_EXTERNAL_TIMEOUT_ENV)));
            assert!(out.stdout.contains("CARGO_HOME="));
        }

        #[test]
        fn host_cache_preference_targets_external_halo2_only() {
            assert!(should_prefer_host_cargo_home(
                "halo2",
                "/tmp/external-zkevm/Cargo.toml"
            ));
            assert!(!should_prefer_host_cargo_home(
                "halo2",
                "relative/local/Cargo.toml"
            ));
            assert!(!should_prefer_host_cargo_home(
                "circom",
                "/tmp/external-zkevm/Cargo.toml"
            ));
        }

        #[test]
        fn halo2_external_timeout_floor_applies_only_to_halo2() {
            assert_eq!(halo2_effective_external_timeout_secs("halo2", 5), 180);
            assert_eq!(halo2_effective_external_timeout_secs("halo2", 180), 180);
            assert_eq!(halo2_effective_external_timeout_secs("circom", 5), 5);
        }

    }
}
