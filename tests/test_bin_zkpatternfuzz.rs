mod zkpatternfuzz_under_test {
    #![allow(dead_code, unused_imports)]
    include!("../src/bin/zkpatternfuzz.rs");

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::env;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{Mutex, OnceLock};
        use std::time::Duration;

        fn env_lock() -> &'static Mutex<()> {
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            LOCK.get_or_init(|| Mutex::new(()))
        }

        fn run_scan_with_text_busy_retry(
            cfg: ScanRunConfig<'_>,
            template: &TemplateInfo,
            family: Family,
            validate_only: bool,
            output_suffix: &str,
        ) -> anyhow::Result<ScanRunResult> {
            for attempt in 0..5 {
                match run_scan(cfg, template, family, validate_only, output_suffix) {
                    Ok(result) => return Ok(result),
                    Err(err) if err.to_string().contains("Text file busy") && attempt < 4 => {
                        std::thread::sleep(Duration::from_millis(30));
                    }
                    Err(err) => return Err(err),
                }
            }
            unreachable!("retry loop should have returned on final attempt");
        }

        #[test]
        fn args_parser_accepts_core_flags() {
            let args = Args::try_parse_from([
                "zkpatternfuzz",
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
        fn resolve_results_root_reads_env_only() {
            let _guard = env_lock().lock().expect("lock env");
            let prior = env::var(SCAN_OUTPUT_ROOT_ENV).ok();
            env::set_var(
                SCAN_OUTPUT_ROOT_ENV,
                "artifacts/external_targets/manual/scan_output",
            );

            let root = resolve_results_root().expect("resolve results root");
            assert_eq!(
                root,
                std::path::PathBuf::from("artifacts/external_targets/manual/scan_output")
            );

            if let Some(value) = prior {
                env::set_var(SCAN_OUTPUT_ROOT_ENV, value);
            } else {
                env::remove_var(SCAN_OUTPUT_ROOT_ENV);
            }
        }

        #[test]
        fn load_batch_file_config_rejects_output_root_key() {
            let temp = tempfile::tempdir().expect("tempdir");
            let cfg_path = temp.path().join("run_overrides.json");
            std::fs::write(
                &cfg_path,
                r#"
{
  "run_overrides": {
    "output_root": "/tmp/forbidden"
  }
}
"#,
            )
            .expect("write config");

            let err = load_batch_file_config(cfg_path.to_str().expect("utf8 path"))
                .expect_err("output_root must be rejected");
            assert!(format!("{err:#}").contains("output_root is no longer supported"));
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
        fn run_scan_exports_signal_and_cache_env_under_results_root() {
            let temp = tempfile::tempdir().expect("tempdir");
            let script_path = temp.path().join("print_env.sh");
            std::fs::write(
                &script_path,
                format!(
                    "#!/usr/bin/env bash\n\
echo \"{}=${{{}:-}}\"\n\
echo \"{}=${{{}:-}}\"\n\
echo \"{}=${{{}:-}}\"\n\
echo \"{}=${{{}:-}}\"\n\
echo \"{}=${{{}:-}}\"\n\
echo \"{}=${{{}:-}}\"\n\
echo \"{}=${{{}:-}}\"\n",
                    SCAN_OUTPUT_ROOT_ENV,
                    SCAN_OUTPUT_ROOT_ENV,
                    RUN_SIGNAL_DIR_ENV,
                    RUN_SIGNAL_DIR_ENV,
                    BUILD_CACHE_DIR_ENV,
                    BUILD_CACHE_DIR_ENV,
                    SCAN_RUN_ROOT_ENV,
                    SCAN_RUN_ROOT_ENV,
                    HALO2_EXTERNAL_TIMEOUT_ENV,
                    HALO2_EXTERNAL_TIMEOUT_ENV,
                    CAIRO_EXTERNAL_TIMEOUT_ENV,
                    CAIRO_EXTERNAL_TIMEOUT_ENV,
                    SCARB_DOWNLOAD_TIMEOUT_ENV,
                    SCARB_DOWNLOAD_TIMEOUT_ENV
                ),
            )
            .expect("write script");
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
            let env_overrides = std::collections::BTreeMap::new();
            let extra_args: Vec<String> = Vec::new();

            let run_signal_dir = temp.path().join("run_signals");
            let build_cache_dir = temp.path().join("_build_cache");

            let cfg = ScanRunConfig {
                bin_path: script_path.as_path(),
                target_circuit: "circuits/demo.circom",
                framework: "circom",
                main_component: "main",
                env_overrides: &env_overrides,
                extra_args: &extra_args,
                workers: 1,
                seed: 1,
                iterations: 1,
                timeout: 1,
                scan_run_root: Some("scan_run_test"),
                results_root: temp.path(),
                run_signal_dir: &run_signal_dir,
                build_cache_dir: &build_cache_dir,
                dry_run: false,
                artifacts_root: temp.path(),
                memory_guard: MemoryGuardConfig {
                    enabled: false,
                    reserved_mb: 0,
                    mb_per_template: 1,
                    mb_per_worker: 1,
                    launch_floor_mb: 1,
                    wait_secs: 1,
                    poll_ms: 50,
                },
                stage_timeouts: StageTimeoutConfig {
                    detection_timeout_secs: 30,
                    proof_timeout_secs: 30,
                    stuck_step_warn_secs: 10,
                },
            };

            let out =
                run_scan_with_text_busy_retry(cfg, &template, Family::Auto, false, "auto__dummy")
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
            std::fs::write(
                &script_path,
                format!(
                    "#!/usr/bin/env bash\n\
echo \"{}=${{{}:-}}\"\n\
echo \"{}=${{{}:-}}\"\n\
echo \"{}=${{{}:-}}\"\n",
                    HALO2_USE_HOST_CARGO_HOME_ENV,
                    HALO2_USE_HOST_CARGO_HOME_ENV,
                    HALO2_EXTERNAL_TIMEOUT_ENV,
                    HALO2_EXTERNAL_TIMEOUT_ENV,
                    HALO2_CARGO_TOOLCHAIN_CANDIDATES_ENV,
                    HALO2_CARGO_TOOLCHAIN_CANDIDATES_ENV
                ),
            )
            .expect("write script");
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
            let env_overrides = std::collections::BTreeMap::new();
            let extra_args: Vec<String> = Vec::new();

            let run_signal_dir = temp.path().join("run_signals");
            let build_cache_dir = temp.path().join("_build_cache");

            let cfg = ScanRunConfig {
                bin_path: script_path.as_path(),
                target_circuit: "/tmp/external-zkevm/Cargo.toml",
                framework: "halo2",
                main_component: "main",
                env_overrides: &env_overrides,
                extra_args: &extra_args,
                workers: 1,
                seed: 1,
                iterations: 1,
                timeout: 1,
                scan_run_root: Some("scan_run_test"),
                results_root: temp.path(),
                run_signal_dir: &run_signal_dir,
                build_cache_dir: &build_cache_dir,
                dry_run: false,
                artifacts_root: temp.path(),
                memory_guard: MemoryGuardConfig {
                    enabled: false,
                    reserved_mb: 0,
                    mb_per_template: 1,
                    mb_per_worker: 1,
                    launch_floor_mb: 1,
                    wait_secs: 1,
                    poll_ms: 50,
                },
                stage_timeouts: StageTimeoutConfig {
                    detection_timeout_secs: 30,
                    proof_timeout_secs: 30,
                    stuck_step_warn_secs: 10,
                },
            };

            let out =
                run_scan_with_text_busy_retry(cfg, &template, Family::Auto, false, "auto__dummy")
                    .expect("run_scan should execute helper script");
            assert!(out.success, "helper script should exit successfully");
            assert!(out
                .stdout
                .contains(&format!("{}=0", HALO2_USE_HOST_CARGO_HOME_ENV)));
            assert!(out
                .stdout
                .contains(&format!("{}=180", HALO2_EXTERNAL_TIMEOUT_ENV)));
        }

        #[test]
        fn host_cache_preference_targets_external_halo2_only() {
            assert!(is_external_target("/tmp/external-zkevm/Cargo.toml"));
            assert!(!is_external_target("relative/local/Cargo.toml"));
        }

        #[test]
        fn halo2_external_timeout_floor_applies_only_to_halo2() {
            assert_eq!(halo2_effective_external_timeout_secs("halo2", 5), 180);
            assert_eq!(halo2_effective_external_timeout_secs("halo2", 180), 180);
            assert_eq!(halo2_effective_external_timeout_secs("circom", 5), 5);
        }

        #[test]
        fn parse_mem_available_kib_prefers_memavailable() {
            let meminfo = "\
MemTotal:       32768000 kB
MemAvailable:    8388608 kB
MemFree:         1024000 kB
";
            assert_eq!(parse_mem_available_kib(meminfo), Some(8_388_608));
        }

        #[test]
        fn memory_guard_reduces_parallelism_when_budget_is_tight() {
            let mut args = Args::try_parse_from([
                "zkpatternfuzz",
                "--template",
                "cveX01.yaml",
                "--target-circuit",
                "circuits/demo.circom",
                "--framework",
                "circom",
                "--jobs",
                "4",
                "--workers",
                "4",
            ])
            .expect("parse args");
            let guard = MemoryGuardConfig {
                enabled: true,
                reserved_mb: 2_048,
                mb_per_template: 512,
                mb_per_worker: 1_024,
                launch_floor_mb: 256,
                wait_secs: 1,
                poll_ms: 50,
            };

            apply_memory_parallelism_guardrails_with_available(&mut args, guard, Some(8_192))
                .expect("guardrail should throttle, not fail");

            assert!(args.jobs <= 4);
            assert!(args.workers <= 4);
            assert!(
                estimated_batch_memory_mb(args.jobs, args.workers, guard)
                    <= 8_192u64.saturating_sub(guard.reserved_mb)
            );
        }

        #[test]
        fn memory_guard_fail_fast_when_disabled_for_proof_stage() {
            let mut args = Args::try_parse_from([
                "zkpatternfuzz",
                "--template",
                "cveX01.yaml",
                "--target-circuit",
                "circuits/demo.circom",
                "--framework",
                "circom",
                "--jobs",
                "2",
                "--workers",
                "2",
            ])
            .expect("parse args");
            let guard = MemoryGuardConfig {
                enabled: false,
                reserved_mb: 1024,
                mb_per_template: 512,
                mb_per_worker: 1024,
                launch_floor_mb: 256,
                wait_secs: 1,
                poll_ms: 50,
            };

            let err =
                apply_memory_parallelism_guardrails_with_available(&mut args, guard, Some(8_192))
                    .expect_err("disabled memory guard should fail fast");
            assert!(err.to_string().contains(MEMORY_GUARD_ENABLED_ENV));
        }

        #[test]
        fn memory_guard_fail_fast_when_reserved_memory_is_zero() {
            let mut args = Args::try_parse_from([
                "zkpatternfuzz",
                "--template",
                "cveX01.yaml",
                "--target-circuit",
                "circuits/demo.circom",
                "--framework",
                "circom",
                "--jobs",
                "2",
                "--workers",
                "2",
            ])
            .expect("parse args");
            let guard = MemoryGuardConfig {
                enabled: true,
                reserved_mb: 0,
                mb_per_template: 512,
                mb_per_worker: 1024,
                launch_floor_mb: 256,
                wait_secs: 1,
                poll_ms: 50,
            };

            let err =
                apply_memory_parallelism_guardrails_with_available(&mut args, guard, Some(8_192))
                    .expect_err("zero reserved memory should fail fast");
            assert!(err.to_string().contains(MEMORY_GUARD_RESERVED_MB_ENV));
        }

        #[test]
        fn memory_guard_fails_when_even_minimum_parallelism_exceeds_budget() {
            let mut args = Args::try_parse_from([
                "zkpatternfuzz",
                "--template",
                "cveX01.yaml",
                "--target-circuit",
                "circuits/demo.circom",
                "--framework",
                "circom",
                "--jobs",
                "1",
                "--workers",
                "1",
            ])
            .expect("parse args");
            let guard = MemoryGuardConfig {
                enabled: true,
                reserved_mb: 1_024,
                mb_per_template: 900,
                mb_per_worker: 900,
                launch_floor_mb: 256,
                wait_secs: 1,
                poll_ms: 50,
            };

            let err =
                apply_memory_parallelism_guardrails_with_available(&mut args, guard, Some(1_600))
                    .expect_err("guardrail should fail when no safe configuration exists");
            assert!(err
                .to_string()
                .contains("cannot be safely reduced below jobs=1 workers=1"));
        }

        #[test]
        fn parse_rustup_toolchain_names_extracts_first_token_and_filters_noise() {
            let raw = "\
nightly-x86_64-unknown-linux-gnu (default)\n\
stable-x86_64-unknown-linux-gnu\n\
info: syncing channel updates\n\
error: network unavailable\n";
            let parsed = parse_rustup_toolchain_names(raw);
            assert_eq!(
                parsed,
                vec![
                    "nightly-x86_64-unknown-linux-gnu".to_string(),
                    "stable-x86_64-unknown-linux-gnu".to_string()
                ]
            );
        }

        #[test]
        fn push_unique_nonempty_dedupes_and_ignores_empty_values() {
            let mut values = Vec::new();
            push_unique_nonempty(&mut values, "");
            push_unique_nonempty(&mut values, "nightly");
            push_unique_nonempty(&mut values, "nightly");
            push_unique_nonempty(&mut values, " stable ");
            assert_eq!(values, vec!["nightly".to_string(), "stable".to_string()]);
        }

        #[test]
        fn load_batch_file_config_supports_wrapped_run_overrides_json() {
            let temp = tempfile::tempdir().expect("tempdir");
            let cfg_path = temp.path().join("run_overrides.json");
            std::fs::write(
                &cfg_path,
                r#"
{
  "run_overrides": {
    "pattern_yaml": "campaigns/cve/patterns/cveX01_dark_forest_missing_bit_length.yaml",
    "target_circuit": "tests/noir_projects/multiplier/Nargo.toml",
    "framework": "noir",
    "workers": 1,
    "iterations": 25,
    "timeout": 30,
    "env": {
      "ZKF_HIGH_CONFIDENCE_MIN_ORACLES": 2
    }
  }
}
"#,
            )
            .expect("write config");

            let parsed = load_batch_file_config(cfg_path.to_str().expect("utf8 path"))
                .expect("parse wrapped config");
            assert_eq!(
                parsed.pattern_yaml.as_deref(),
                Some("campaigns/cve/patterns/cveX01_dark_forest_missing_bit_length.yaml")
            );
            assert_eq!(
                parsed.target_circuit.as_deref(),
                Some("tests/noir_projects/multiplier/Nargo.toml")
            );
            assert_eq!(parsed.framework.as_deref(), Some("noir"));
            assert_eq!(parsed.workers, Some(1));
            assert_eq!(parsed.iterations, Some(25));
            assert_eq!(parsed.timeout, Some(30));
            assert!(parsed.env.contains_key("ZKF_HIGH_CONFIDENCE_MIN_ORACLES"));
        }

        #[test]
        fn resolve_explicit_pattern_selection_accepts_yaml_paths() {
            let temp = tempfile::tempdir().expect("tempdir");
            let yaml_path = temp.path().join("sample_pattern.yaml");
            std::fs::write(
                &yaml_path,
                r#"
patterns:
  - id: sample
    kind: regex
    pattern: "signal"
"#,
            )
            .expect("write yaml");
            let selected = resolve_explicit_pattern_selection(
                &[yaml_path.display().to_string()],
                Family::Auto,
            )
            .expect("resolve explicit patterns");
            assert_eq!(selected.len(), 1);
            assert_eq!(selected[0].file_name, "sample_pattern.yaml");
            assert_eq!(selected[0].path, yaml_path);
        }

        #[test]
        fn discover_all_pattern_templates_only_returns_pattern_compatible_yaml() {
            let temp = tempfile::tempdir().expect("tempdir");
            let valid = temp.path().join("valid_pattern.yaml");
            let invalid = temp.path().join("not_pattern.yaml");
            std::fs::write(
                &valid,
                r#"
patterns:
  - id: valid
    kind: regex
    pattern: "main"
"#,
            )
            .expect("write valid yaml");
            std::fs::write(
                &invalid,
                r#"
campaign:
  name: not-pattern
"#,
            )
            .expect("write invalid yaml");

            let discovered =
                discover_all_pattern_templates(temp.path()).expect("discover templates");
            assert_eq!(discovered.len(), 1);
            assert_eq!(discovered[0].file_name, "valid_pattern.yaml");
            assert_eq!(discovered[0].path, valid);
        }

        #[test]
        fn dedupe_patterns_by_signature_keeps_single_full_overlap_variant() {
            let temp = tempfile::tempdir().expect("tempdir");
            let base = temp.path().join("base_pattern.yaml");
            let profiled = temp.path().join("profiled_pattern.yaml");
            std::fs::write(
                &base,
                r#"
patterns:
  - id: x
    kind: regex
    pattern: "foo"
"#,
            )
            .expect("write base");
            std::fs::write(
                &profiled,
                r#"
patterns:
  - id: x
    kind: regex
    pattern: "foo"
profiles:
  local_ptau:
    circom_ptau_path: tests/circuits/build/pot12_final.ptau
active_profile: local_ptau
"#,
            )
            .expect("write profiled");

            let selected = vec![
                TemplateInfo {
                    file_name: "base_pattern.yaml".to_string(),
                    path: base.clone(),
                    family: Family::Auto,
                },
                TemplateInfo {
                    file_name: "profiled_pattern.yaml".to_string(),
                    path: profiled.clone(),
                    family: Family::Auto,
                },
            ];
            let (kept, dropped) =
                dedupe_patterns_by_signature(selected).expect("dedupe signatures");
            assert_eq!(kept.len(), 1);
            assert_eq!(dropped.len(), 1);
            assert_eq!(kept[0].path, profiled);
            assert_eq!(dropped[0].0.path, base);
        }

        #[test]
        fn validate_pattern_only_yaml_accepts_selector_policy_keys() {
            let temp = tempfile::tempdir().expect("tempdir");
            let yaml_path = temp.path().join("selector_pattern.yaml");
            std::fs::write(
                &yaml_path,
                r#"
patterns:
  - id: contains_nullifier
    kind: regex
    pattern: "\\bnullifier\\b"
selector_policy:
  k_of_n: 1
selector_synonyms:
  zkevm:
    - zkEVM
selector_normalization:
  synonym_flexible_separators: true
"#,
            )
            .expect("write selector yaml");

            validate_pattern_only_yaml(&yaml_path)
                .expect("selector-policy keys should be accepted in batch validator");
        }

        #[test]
        fn progress_stage_is_proof_detects_reporting_and_proof_labels() {
            assert!(progress_stage_is_proof("reporting"));
            assert!(progress_stage_is_proof("proof_done"));
            assert!(progress_stage_is_proof("evidence_finalize"));
            assert!(progress_stage_is_proof("completed"));
        }

        #[test]
        fn progress_stage_is_proof_rejects_attack_progress() {
            assert!(!progress_stage_is_proof("attack_start"));
            assert!(!progress_stage_is_proof("attack_progress"));
            assert!(!progress_stage_is_proof("timeout_reached"));
        }

        #[test]
        fn format_stuck_step_warning_line_includes_window_and_stage() {
            let line =
                format_stuck_step_warning_line("cveX_demo.yaml", "attack_progress", "5/11", 75, 60);
            assert!(line.contains("[TEMPLATE WARNING] cveX_demo.yaml"));
            assert!(line.contains("warning=stuck_step"));
            assert!(line.contains("stage=attack_progress"));
            assert!(line.contains("step=5/11"));
            assert!(line.contains("no_progress_for=75s"));
            assert!(line.contains("window=60s"));
        }

        #[test]
        fn read_template_progress_update_tracks_step_fraction() {
            let temp_root = std::env::temp_dir().join(format!(
                "zkpatternfuzz_progress_update_test_{}_{}",
                std::process::id(),
                RUN_ROOT_NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&temp_root).expect("create temp root");
            let progress_path = temp_root.join("progress.json");
            std::fs::write(
                &progress_path,
                serde_json::json!({
                    "stage": "attack_progress",
                    "progress": {
                        "step_fraction": "4/11"
                    },
                    "details": {}
                })
                .to_string(),
            )
            .expect("write progress snapshot");

            let update = read_template_progress_update("cveX_demo.yaml", &progress_path)
                .expect("parse progress");
            assert_eq!(update.stage, "attack_progress");
            assert_eq!(update.step_fraction, "4/11");

            let _ = std::fs::remove_dir_all(&temp_root);
        }

        #[test]
        fn write_stage_timeout_outcome_writes_wall_clock_timeout_payload() {
            let temp_root = std::env::temp_dir().join(format!(
                "zkpatternfuzz_timeout_outcome_test_{}_{}",
                std::process::id(),
                RUN_ROOT_NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&temp_root).expect("create temp root");
            let run_root = "scan_run_test";
            let suffix = "auto__timeout_case";

            write_stage_timeout_outcome(
                &temp_root,
                Some(run_root),
                suffix,
                HardTimeoutStage::Proving,
                7,
            )
            .expect("write timeout outcome");

            let run_outcome_path = temp_root
                .join(run_root)
                .join(suffix)
                .join("run_outcome.json");
            let raw = std::fs::read_to_string(&run_outcome_path).expect("read run outcome");
            let parsed: serde_json::Value =
                serde_json::from_str(&raw).expect("parse run outcome json");
            assert_eq!(
                parsed.get("reason_code").and_then(|v| v.as_str()),
                Some("wall_clock_timeout")
            );
            assert_eq!(
                parsed.get("stage").and_then(|v| v.as_str()),
                Some("proof_timeout")
            );
            assert_eq!(
                parsed
                    .get("discovery_qualification")
                    .and_then(|v| v.get("proof_status"))
                    .and_then(|v| v.as_str()),
                Some("proof_failed")
            );

            let _ = std::fs::remove_dir_all(&temp_root);
        }

        #[test]
        fn detected_patterns_without_started_proof_are_forced_to_proof_failed() {
            let temp = tempfile::tempdir().expect("tempdir");
            let template_path = temp.path().join("pattern.yaml");
            std::fs::write(&template_path, "patterns: []\n").expect("write template");
            let template = TemplateInfo {
                file_name: "pattern.yaml".to_string(),
                path: template_path.clone(),
                family: Family::Auto,
            };
            let suffix = scan_output_suffix(&template, Family::Auto);
            let run_root = "scan_run_test";
            let artifact_dir = temp.path().join(run_root).join(&suffix);
            std::fs::create_dir_all(&artifact_dir).expect("create artifact dir");

            std::fs::write(
                artifact_dir.join("run_outcome.json"),
                serde_json::json!({
                    "status": "completed",
                    "stage": "completed",
                    "reason_code": "completed",
                    "discovery_qualification": {
                        "proof_status": "proof_skipped_by_policy"
                    }
                })
                .to_string(),
            )
            .expect("write run outcome");
            std::fs::write(
                artifact_dir.join("report.json"),
                serde_json::json!({
                    "findings": [
                        {"description": "pattern hit 1"},
                        {"description": "pattern hit 2"}
                    ]
                })
                .to_string(),
            )
            .expect("write report");

            let reasons = collect_template_outcome_reasons(
                temp.path(),
                Some(run_root),
                &[(template, Family::Auto)],
            );
            assert_eq!(reasons.len(), 1);
            let reason = &reasons[0];
            assert_eq!(reason.detected_pattern_count, 2);
            assert_eq!(reason.proof_status.as_deref(), Some("proof_failed"));
            assert_eq!(
                reason.reason_code,
                PROOF_STAGE_NOT_STARTED_REASON_CODE.to_string()
            );
        }

        #[test]
        fn detected_patterns_with_started_proof_keep_original_reason_code() {
            let temp = tempfile::tempdir().expect("tempdir");
            let template_path = temp.path().join("pattern.yaml");
            std::fs::write(&template_path, "patterns: []\n").expect("write template");
            let template = TemplateInfo {
                file_name: "pattern.yaml".to_string(),
                path: template_path.clone(),
                family: Family::Auto,
            };
            let suffix = scan_output_suffix(&template, Family::Auto);
            let run_root = "scan_run_test";
            let artifact_dir = temp.path().join(run_root).join(&suffix);
            std::fs::create_dir_all(&artifact_dir).expect("create artifact dir");

            std::fs::write(
                artifact_dir.join("run_outcome.json"),
                serde_json::json!({
                    "status": "completed_with_critical_findings",
                    "stage": "proof_done",
                    "reason_code": "critical_findings_detected",
                    "discovery_qualification": {
                        "proof_status": "exploitable"
                    }
                })
                .to_string(),
            )
            .expect("write run outcome");
            std::fs::write(
                artifact_dir.join("report.json"),
                serde_json::json!({
                    "findings": [{"description": "pattern hit"}]
                })
                .to_string(),
            )
            .expect("write report");

            let reasons = collect_template_outcome_reasons(
                temp.path(),
                Some(run_root),
                &[(template, Family::Auto)],
            );
            assert_eq!(reasons.len(), 1);
            let reason = &reasons[0];
            assert_eq!(reason.detected_pattern_count, 1);
            assert_eq!(reason.proof_status.as_deref(), Some("exploitable"));
            assert_eq!(reason.reason_code, "critical_findings_detected");
        }
    }
}
