use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use zk_circuit_gen::{
    evolve_patterns_from_feedback, generate_adversarial_corpus_from_external_patterns,
    parse_external_ai_pattern_bundle_json, parse_pattern_feedback_json,
    AdversarialGenerationConfig,
};

const DEFAULT_OUTPUT_DIR: &str = "artifacts/circuit_gen/adversarial_latest";
const DEFAULT_SEED: u64 = 7_331;

#[derive(Debug, Clone)]
struct CliArgs {
    patterns_json: PathBuf,
    output_dir: PathBuf,
    seed: u64,
    feedback_json: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let pattern_payload = fs::read_to_string(&args.patterns_json)?;
    let mut bundle = parse_external_ai_pattern_bundle_json(&pattern_payload)?;

    if let Some(feedback_path) = &args.feedback_json {
        let feedback_payload = fs::read_to_string(feedback_path)?;
        let feedback = parse_pattern_feedback_json(&feedback_payload)?;
        bundle = evolve_patterns_from_feedback(&bundle, &feedback)?;
    }

    fs::create_dir_all(&args.output_dir)?;
    fs::write(
        args.output_dir.join("effective_patterns.json"),
        serde_json::to_string_pretty(&bundle)? + "\n",
    )?;

    let mut config = AdversarialGenerationConfig::new(&args.output_dir);
    config.seed = args.seed;
    let report = generate_adversarial_corpus_from_external_patterns(&bundle, &config)?;

    println!(
        "adversarial generation complete: patterns={} total_circuits={} report={}",
        report.total_patterns,
        report.total_circuits,
        report.report_path.display(),
    );
    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut patterns_json = None;
    let mut output_dir = PathBuf::from(DEFAULT_OUTPUT_DIR);
    let mut seed = DEFAULT_SEED;
    let mut feedback_json = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--patterns-json" => {
                patterns_json = Some(PathBuf::from(next_value(&mut args, "--patterns-json")?))
            }
            "--output-dir" => output_dir = PathBuf::from(next_value(&mut args, "--output-dir")?),
            "--seed" => seed = next_value(&mut args, "--seed")?.parse::<u64>()?,
            "--feedback-json" => {
                feedback_json = Some(PathBuf::from(next_value(&mut args, "--feedback-json")?))
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }

    let patterns_json = patterns_json.ok_or("--patterns-json is required")?;
    Ok(CliArgs {
        patterns_json,
        output_dir,
        seed,
        feedback_json,
    })
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn print_help() {
    println!(
        "\
generate_adversarial_corpus

Generate a compiler-adversarial corpus from external AI-supplied pattern JSON.

Usage:
  cargo run -q -p zk-circuit-gen --example generate_adversarial_corpus -- [options]

Options:
  --patterns-json <path>          Required external AI pattern JSON
  --output-dir <path>             Output root (default: {DEFAULT_OUTPUT_DIR})
  --seed <u64>                    RNG seed (default: {DEFAULT_SEED})
  --feedback-json <path>          Optional compiler-feedback JSON to evolve priorities
"
    );
}
