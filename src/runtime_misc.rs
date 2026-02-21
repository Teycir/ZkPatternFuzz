use chrono::{DateTime, Duration as ChronoDuration, Local};
use zk_fuzzer::config::FuzzConfig;

pub(crate) fn validate_campaign(config_path: &str) -> anyhow::Result<()> {
    tracing::info!("Validating campaign: {}", config_path);
    let mut config = FuzzConfig::from_yaml(config_path)?;

    // The validate subcommand should reflect the CLI defaults used by `run/evidence/chains`.
    // Otherwise the readiness report emits noisy iteration warnings for configs that intentionally
    // omit max_iterations and rely on CLI defaults.
    {
        let additional = &mut config.campaign.parameters.additional;
        if !config.chains.is_empty() {
            // Match `chains` defaults: iterations=100000, timeout=600.
            additional
                .entry("chain_iterations".to_string())
                .or_insert_with(|| serde_yaml::Value::Number(serde_yaml::Number::from(100_000u64)));
            additional
                .entry("chain_budget_seconds".to_string())
                .or_insert_with(|| serde_yaml::Value::Number(serde_yaml::Number::from(600u64)));

            // Match `chains` run behavior (strict evidence semantics for findings).
            additional
                .entry("evidence_mode".to_string())
                .or_insert_with(|| serde_yaml::Value::Bool(true));
            additional
                .entry("engagement_strict".to_string())
                .or_insert_with(|| serde_yaml::Value::Bool(true));
        } else {
            // Match `run/evidence` defaults: iterations=100000.
            additional
                .entry("fuzzing_iterations".to_string())
                .or_insert_with(|| serde_yaml::Value::Number(serde_yaml::Number::from(100_000u64)));
        }
    }

    println!("✓ Configuration is valid");
    println!();
    println!("Campaign Details:");
    println!("  Name: {}", config.campaign.name);
    println!("  Version: {}", config.campaign.version);
    println!("  Framework: {:?}", config.campaign.target.framework);
    println!("  Circuit: {:?}", config.campaign.target.circuit_path);
    println!(
        "  Main Component: {}",
        config.campaign.target.main_component
    );
    println!();
    println!("Attacks ({}):", config.attacks.len());
    for attack in &config.attacks {
        println!("  - {:?}: {}", attack.attack_type, attack.description);
    }
    println!();
    println!("Inputs ({}):", config.inputs.len());
    for input in &config.inputs {
        println!(
            "  - {}: {} ({:?})",
            input.name, input.input_type, input.fuzz_strategy
        );
    }

    // Phase 4C: 0-day readiness check
    println!();
    let readiness = zk_fuzzer::config::check_0day_readiness(&config);
    print!("{}", readiness.format());

    if !readiness.ready_for_evidence {
        anyhow::bail!("Campaign has critical issues - not ready for evidence mode");
    }

    Ok(())
}

pub(crate) fn minimize_corpus(corpus_dir: &str, output: Option<&str>) -> anyhow::Result<()> {
    use std::path::Path;
    use zk_fuzzer::corpus::{minimizer, storage};

    tracing::info!("Loading corpus from: {}", corpus_dir);

    let entries = storage::load_corpus_from_dir(Path::new(corpus_dir))?;
    tracing::info!("Loaded {} entries", entries.len());

    let minimized = minimizer::minimize_corpus(&entries);
    let stats = minimizer::MinimizationStats::compute(entries.len(), minimized.len());

    println!("Corpus minimization:");
    println!("  Original size: {}", stats.original_size);
    println!("  Minimized size: {}", stats.minimized_size);
    println!("  Reduction: {:.1}%", stats.reduction_percentage);

    if let Some(output_dir) = output {
        let output_path = Path::new(output_dir);
        std::fs::create_dir_all(output_path)?;

        for (i, entry) in minimized.iter().enumerate() {
            storage::save_test_case(entry, output_path, i)?;
        }

        println!("Saved minimized corpus to: {}", output_dir);
    }

    Ok(())
}

pub(crate) fn generate_sample_config(output: &str, framework: &str) -> anyhow::Result<()> {
    let (circuit_path, main_component) = match framework {
        "circom" => ("./circuits/example.circom", "Main"),
        "noir" => ("./circuits/example", "main"),
        "halo2" => ("./circuits/example.rs", "ExampleCircuit"),
        "cairo" => ("./circuits/example.cairo", "main"),
        _ => ("./circuits/example.circom", "Main"),
    };

    let sample = format!(
        r#"# ZK-Fuzzer Pattern Configuration
# Generated sample for {} framework.
# This file is pattern-only and is used with `zk-fuzzer scan`.

patterns:
  - id: "contains_main_component"
    kind: regex
    pattern: "template\\s+Main|fn\\s+main|struct\\s+ExampleCircuit"
    message: "Target source has an expected main entrypoint pattern"

attacks:
  - type: underconstrained
    description: "Find inputs that satisfy constraints but produce wrong outputs"
    config:
      witness_pairs: 1000
      # Optional: fix public inputs for consistent checks
      # public_input_names: ["input1"]
      # fixed_public_inputs: ["0x01"]

  - type: soundness
    description: "Attempt to create valid proofs for false statements"
    config:
      forge_attempts: 1000
      mutation_rate: 0.1

  - type: arithmetic_overflow
    description: "Test field arithmetic edge cases"
    config:
      test_values:
        - "0"
        - "1"
        - "p-1"
        - "p"

  - type: collision
    description: "Detect hash collisions or output collisions"
    config:
      samples: 10000

inputs:
  - name: "input1"
    type: "field"
    fuzz_strategy: random
    constraints:
      - "nonzero"

  - name: "input2"
    type: "field"
    fuzz_strategy: interesting_values
    interesting:
      - "0x0"
      - "0x1"
      - "0xdead"

invariants:
  - name: "input1_nonzero"
    invariant_type: "constraint"
    relation: "input1 != 0"
    severity: "medium"
"#,
        framework
    );

    std::fs::write(output, sample)?;
    println!("Generated sample pattern: {}", output);
    println!(
        "Run with: zk-fuzzer scan {} --target-circuit {} --main-component {} --framework {}",
        output, circuit_path, main_component, framework
    );

    Ok(())
}

pub(crate) fn print_banner(config: &FuzzConfig) {
    use colored::*;

    println!();
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".bright_cyan()
    );
    println!(
        "{}",
        "║              ZK-FUZZER v0.1.0                             ║".bright_cyan()
    );
    println!(
        "{}",
        "║       Zero-Knowledge Proof Security Tester                ║".bright_cyan()
    );
    println!(
        "{}",
        "╠═══════════════════════════════════════════════════════════╣".bright_cyan()
    );
    println!(
        "{}  Campaign: {:<45} {}",
        "║".bright_cyan(),
        truncate_str(&config.campaign.name, 45).white(),
        "║".bright_cyan()
    );
    println!(
        "{}  Target:   {:<45} {}",
        "║".bright_cyan(),
        format!("{:?}", config.campaign.target.framework).yellow(),
        "║".bright_cyan()
    );
    println!(
        "{}  Attacks:  {:<45} {}",
        "║".bright_cyan(),
        format!("{} configured", config.attacks.len()).green(),
        "║".bright_cyan()
    );
    println!(
        "{}  Inputs:   {:<45} {}",
        "║".bright_cyan(),
        format!("{} defined", config.inputs.len()).green(),
        "║".bright_cyan()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝".bright_cyan()
    );
    println!();
}

pub(crate) fn print_run_window(start: DateTime<Local>, timeout_seconds: Option<u64>) {
    println!("RUN WINDOW");
    println!("  Start: {}", start.format("%Y-%m-%d %H:%M:%S %Z"));

    match timeout_seconds.and_then(|s| match i64::try_from(s) {
        Ok(seconds) => Some(seconds),
        Err(err) => {
            tracing::warn!("Timeout seconds value '{}' exceeds i64: {}", s, err);
            None
        }
    }) {
        Some(seconds) => {
            let expected_end = start + ChronoDuration::seconds(seconds);
            println!(
                "  Expected latest end: {} (timeout {}s)",
                expected_end.format("%Y-%m-%d %H:%M:%S %Z"),
                seconds
            );
            tracing::info!(
                "RUN_WINDOW start={} expected_latest_end={} timeout_seconds={}",
                start.to_rfc3339(),
                expected_end.to_rfc3339(),
                seconds
            );
        }
        None => {
            println!("  Expected latest end: unbounded (no --timeout)");
            tracing::info!(
                "RUN_WINDOW start={} expected_latest_end=unbounded",
                start.to_rfc3339()
            );
        }
    }
    println!();
}

pub(crate) fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
