use serde_json::json;
use std::collections::BTreeSet;
use std::env;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn threshold_env_keys() -> Vec<String> {
    zk_fuzzer::checks::benchmark_failure_dashboard::FAILURE_CLASSES
        .iter()
        .map(|class_name| {
            zk_fuzzer::checks::benchmark_failure_dashboard::env_key_for_class(class_name)
        })
        .collect()
}

fn with_patched_env<F>(overrides: &[(&str, &str)], clear: bool, f: F)
where
    F: FnOnce(),
{
    let _guard = env_lock().lock().expect("lock env");
    let keys = threshold_env_keys();
    let saved: Vec<(String, Option<String>)> = keys
        .iter()
        .map(|key| (key.clone(), env::var(key).ok()))
        .collect();

    if clear {
        for key in &keys {
            env::remove_var(key);
        }
    }
    for (key, value) in overrides {
        env::set_var(key, value);
    }

    f();

    for (key, value) in saved {
        if let Some(value) = value {
            env::set_var(&key, value);
        } else {
            env::remove_var(&key);
        }
    }
}

#[test]
fn resolve_thresholds_defaults() {
    with_patched_env(&[], true, || {
        let resolved = zk_fuzzer::checks::benchmark_failure_dashboard::resolve_thresholds(&[])
            .expect("resolve thresholds");
        assert_eq!(
            resolved,
            zk_fuzzer::checks::benchmark_failure_dashboard::default_thresholds()
        );
    });
}

#[test]
fn resolve_thresholds_env_override() {
    with_patched_env(
        &[("ZKF_FAILURE_MAX_RATE_SETUP_TOOLING", "0.20")],
        true,
        || {
            let resolved = zk_fuzzer::checks::benchmark_failure_dashboard::resolve_thresholds(&[])
                .expect("resolve thresholds");
            assert_eq!(resolved.get("setup_tooling").copied(), Some(0.20));
            let defaults = zk_fuzzer::checks::benchmark_failure_dashboard::default_thresholds();
            assert_eq!(
                resolved.get("timeouts").copied(),
                defaults.get("timeouts").copied()
            );
        },
    );
}

#[test]
fn resolve_thresholds_cli_overrides_env() {
    with_patched_env(
        &[("ZKF_FAILURE_MAX_RATE_SETUP_TOOLING", "0.20")],
        true,
        || {
            let resolved = zk_fuzzer::checks::benchmark_failure_dashboard::resolve_thresholds(&[
                "setup_tooling=0.25".to_string(),
            ])
            .expect("resolve thresholds");
            assert_eq!(resolved.get("setup_tooling").copied(), Some(0.25));
        },
    );
}

#[test]
fn resolve_thresholds_invalid_env_value() {
    with_patched_env(
        &[("ZKF_FAILURE_MAX_RATE_SETUP_TOOLING", "invalid")],
        true,
        || {
            let err = zk_fuzzer::checks::benchmark_failure_dashboard::resolve_thresholds(&[])
                .expect_err("expected invalid env parse error");
            assert!(err
                .to_string()
                .contains("$ZKF_FAILURE_MAX_RATE_SETUP_TOOLING"));
        },
    );
}

#[test]
fn resolve_thresholds_invalid_cli_class() {
    with_patched_env(&[], true, || {
        let err = zk_fuzzer::checks::benchmark_failure_dashboard::resolve_thresholds(&[
            "not_a_class=0.2".to_string(),
        ])
        .expect_err("expected invalid class");
        assert!(err.to_string().contains("Unknown failure class"));
    });
}

#[test]
fn resolve_thresholds_invalid_cli_format() {
    with_patched_env(&[], true, || {
        let err = zk_fuzzer::checks::benchmark_failure_dashboard::resolve_thresholds(&[
            "setup_tooling".to_string(),
        ])
        .expect_err("expected invalid threshold format");
        assert!(err.to_string().contains("expected CLASS=RATE"));
    });
}

#[test]
fn dashboard_output_schema_stable() {
    with_patched_env(&[], true, || {
        let summary = json!({"generated_utc": "2026-02-18T00:00:00Z", "total_runs": 10});
        let outcomes = vec![json!({"reason_counts": {"none": 10}})];
        let thresholds = zk_fuzzer::checks::benchmark_failure_dashboard::resolve_thresholds(&[])
            .expect("resolve thresholds");
        let payload = zk_fuzzer::checks::benchmark_failure_dashboard::dashboard(
            &summary,
            &outcomes,
            Path::new("artifacts/benchmark_runs/benchmark_foo/summary.json"),
            Path::new("artifacts/benchmark_runs/benchmark_foo/outcomes.json"),
            &thresholds,
        )
        .expect("build dashboard");

        let as_json = serde_json::to_value(&payload).expect("payload json");
        let keys: BTreeSet<String> = as_json
            .as_object()
            .expect("object payload")
            .keys()
            .cloned()
            .collect();
        let expected: BTreeSet<String> = [
            "generated_utc",
            "summary_path",
            "outcomes_path",
            "total_runs",
            "overall_status",
            "class_rows",
            "reason_counts",
        ]
        .into_iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(keys, expected);
        assert_eq!(payload.overall_status, "PASS");
        assert_eq!(payload.class_rows.len(), 6);
    });
}
