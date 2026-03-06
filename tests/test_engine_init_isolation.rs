use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use tracing_subscriber::fmt::MakeWriter;
use zk_fuzzer::config::*;
use zk_fuzzer::fuzzer::FuzzingEngine;

fn build_isolation_config(build_dir: &str, explicit_limit_mb: Option<u64>) -> FuzzConfig {
    let mut additional = AdditionalConfig::default();
    additional.insert(
        "circom_build_dir".to_string(),
        serde_yaml::Value::String(build_dir.to_string()),
    );
    additional.insert(
        "per_exec_isolation".to_string(),
        serde_yaml::Value::Bool(true),
    );
    additional.insert(
        "symbolic_enabled".to_string(),
        serde_yaml::Value::Bool(false),
    );
    additional.insert(
        "fail_on_resource_risk".to_string(),
        serde_yaml::Value::Bool(false),
    );
    if let Some(limit_mb) = explicit_limit_mb {
        additional.insert(
            "isolation_memory_limit_mb".to_string(),
            serde_yaml::Value::Number(limit_mb.into()),
        );
    }

    FuzzConfig {
        campaign: Campaign {
            name: "Engine Isolation Init Regression".to_string(),
            version: "1.0".to_string(),
            target: Target {
                framework: Framework::Circom,
                circuit_path: PathBuf::from("tests/circuits/range_check.circom"),
                main_component: "main".to_string(),
            },
            parameters: Parameters {
                field: "bn254".to_string(),
                max_constraints: 1000,
                timeout_seconds: 30,
                additional,
            },
        },
        attacks: vec![Attack {
            attack_type: AttackType::Boundary,
            description: "Isolation init regression".to_string(),
            plugin: None,
            config: serde_yaml::from_str(
                r#"
test_values: ["0", "1"]
"#,
            )
            .expect("valid boundary config"),
        }],
        inputs: vec![Input {
            name: "value".to_string(),
            input_type: "field".to_string(),
            fuzz_strategy: FuzzStrategy::Random,
            constraints: vec![],
            interesting: vec![],
            length: None,
        }],
        mutations: vec![],
        oracles: vec![],
        reporting: ReportingConfig::default(),
        chains: vec![],
    }
}

fn env_lock() -> &'static Mutex<()> {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_LOCK.get_or_init(|| Mutex::new(()))
}

fn capture_engine_init_logs(config: FuzzConfig) -> String {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(BufferWriter(captured.clone()))
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        FuzzingEngine::new(config, Some(31), 1).expect("engine init should succeed");
    });

    let bytes = captured.lock().expect("log buffer lock").clone();
    String::from_utf8(bytes).expect("utf8 log buffer")
}

#[test]
fn circom_isolation_default_disables_rlimit_as_when_unset() {
    let _guard = env_lock().lock().expect("env lock");
    let prior_env = std::env::var("ZK_FUZZER_ISOLATION_MEMORY_LIMIT_MB").ok();
    std::env::remove_var("ZK_FUZZER_ISOLATION_MEMORY_LIMIT_MB");

    let logs = capture_engine_init_logs(build_isolation_config(
        "/tmp/zkfuzz_tests/engine_isolation_default",
        None,
    ));

    match prior_env {
        Some(value) => std::env::set_var("ZK_FUZZER_ISOLATION_MEMORY_LIMIT_MB", value),
        None => std::env::remove_var("ZK_FUZZER_ISOLATION_MEMORY_LIMIT_MB"),
    }

    assert!(
        logs.contains("Per-exec isolation enabled"),
        "expected isolation init log, got:\n{}",
        logs
    );
    assert!(
        logs.contains("memory_limit=unlimited"),
        "expected unlimited default for circom isolation, got:\n{}",
        logs
    );
}

#[test]
fn circom_isolation_honors_explicit_memory_cap() {
    let _guard = env_lock().lock().expect("env lock");
    let prior_env = std::env::var("ZK_FUZZER_ISOLATION_MEMORY_LIMIT_MB").ok();
    std::env::remove_var("ZK_FUZZER_ISOLATION_MEMORY_LIMIT_MB");

    let logs = capture_engine_init_logs(build_isolation_config(
        "/tmp/zkfuzz_tests/engine_isolation_explicit",
        Some(1024),
    ));

    match prior_env {
        Some(value) => std::env::set_var("ZK_FUZZER_ISOLATION_MEMORY_LIMIT_MB", value),
        None => std::env::remove_var("ZK_FUZZER_ISOLATION_MEMORY_LIMIT_MB"),
    }

    assert!(
        logs.contains("Per-exec isolation enabled"),
        "expected isolation init log, got:\n{}",
        logs
    );
    assert!(
        logs.contains("memory_limit=1024 MiB"),
        "expected explicit memory cap to be preserved, got:\n{}",
        logs
    );
}

#[derive(Clone)]
struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl<'a> MakeWriter<'a> for BufferWriter {
    type Writer = BufferGuard;

    fn make_writer(&'a self) -> Self::Writer {
        BufferGuard(self.0.clone())
    }
}

struct BufferGuard(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufferGuard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("log buffer lock")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
