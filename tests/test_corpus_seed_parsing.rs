use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;
use zk_fuzzer::config::*;
use zk_fuzzer::fuzzer::FuzzingEngine;

fn build_seed_parsing_config() -> FuzzConfig {
    let mut additional = AdditionalConfig::default();
    additional.insert(
        "circom_build_dir".to_string(),
        serde_yaml::Value::String("/tmp/zkfuzz_tests/corpus_seed_parsing_range".to_string()),
    );
    additional.insert(
        "symbolic_enabled".to_string(),
        serde_yaml::Value::Bool(false),
    );
    additional.insert(
        "max_iterations".to_string(),
        serde_yaml::Value::Number(1.into()),
    );
    additional.insert(
        "fuzzing_timeout_seconds".to_string(),
        serde_yaml::Value::Number(5.into()),
    );

    FuzzConfig {
        campaign: Campaign {
            name: "Corpus Seed Parsing Regression".to_string(),
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
            description: "Seed parsing regression".to_string(),
            plugin: None,
            config: serde_yaml::from_str(
                r#"
test_values: ["0", "1"]
"#,
            )
            .expect("valid boundary config"),
        }],
        inputs: vec![
            Input {
                name: "value".to_string(),
                input_type: "field".to_string(),
                fuzz_strategy: FuzzStrategy::Random,
                constraints: vec![],
                interesting: vec!["2".to_string(), "p-1".to_string()],
                length: None,
            },
            Input {
                name: "bits".to_string(),
                input_type: "array<field>".to_string(),
                fuzz_strategy: FuzzStrategy::Random,
                constraints: vec![],
                interesting: vec![],
                length: Some(8),
            },
        ],
        mutations: vec![],
        oracles: vec![],
        reporting: ReportingConfig::default(),
        chains: vec![],
    }
}

#[test]
fn seed_corpus_parses_decimal_and_symbolic_interesting_values() {
    let mut engine =
        FuzzingEngine::new(build_seed_parsing_config(), Some(11), 1).expect("engine init");
    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(BufferWriter(captured.clone()))
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            engine.run(None).await.expect("run should succeed");
        });
    });
    let log_text = String::from_utf8(captured.lock().expect("log buffer lock").clone())
        .expect("utf8 log buffer");

    assert!(
        !log_text.contains("Ignoring invalid interesting corpus seed '2'"),
        "decimal interesting seed should parse; logs:\n{}",
        log_text
    );
    assert!(
        !log_text.contains("Ignoring invalid interesting corpus seed 'p-1'"),
        "symbolic interesting seed should parse; logs:\n{}",
        log_text
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
