use std::env;
use std::error::Error;
use std::path::PathBuf;

use zk_circuit_gen::{generate_bulk_corpus, Backend, BulkGenerationConfig, MutationStrategy};

const DEFAULT_OUTPUT_DIR: &str = "artifacts/circuit_gen/bulk_latest";
const DEFAULT_CIRCUITS_PER_BACKEND: usize = 1_000;
const DEFAULT_SEED: u64 = 1_337;

#[derive(Debug, Clone)]
struct CliArgs {
    output_dir: PathBuf,
    circuits_per_backend: usize,
    seed: u64,
    backends: Vec<Backend>,
    mutation_strategies: Vec<MutationStrategy>,
    mutation_intensity: usize,
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut output_dir = PathBuf::from(DEFAULT_OUTPUT_DIR);
    let mut circuits_per_backend = DEFAULT_CIRCUITS_PER_BACKEND;
    let mut seed = DEFAULT_SEED;
    let mut backends = Backend::ALL.to_vec();
    let mut mutation_strategies = Vec::new();
    let mut mutation_intensity = 3usize;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output-dir" => output_dir = PathBuf::from(next_value(&mut args, "--output-dir")?),
            "--circuits-per-backend" => {
                circuits_per_backend =
                    next_value(&mut args, "--circuits-per-backend")?.parse::<usize>()?
            }
            "--seed" => seed = next_value(&mut args, "--seed")?.parse::<u64>()?,
            "--backends" => {
                let value = next_value(&mut args, "--backends")?;
                backends = parse_backends(&value)?;
            }
            "--mutation-strategies" => {
                let value = next_value(&mut args, "--mutation-strategies")?;
                mutation_strategies = parse_mutation_strategies(&value)?;
            }
            "--mutation-intensity" => {
                mutation_intensity =
                    next_value(&mut args, "--mutation-intensity")?.parse::<usize>()?
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }

    Ok(CliArgs {
        output_dir,
        circuits_per_backend,
        seed,
        backends,
        mutation_strategies,
        mutation_intensity,
    })
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn parse_backends(value: &str) -> Result<Vec<Backend>, Box<dyn Error>> {
    let mut out = Vec::new();
    for item in value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let backend = match item.to_ascii_lowercase().as_str() {
            "circom" => Backend::Circom,
            "noir" => Backend::Noir,
            "halo2" => Backend::Halo2,
            "cairo" => Backend::Cairo,
            _ => return Err(format!("unsupported backend `{item}`").into()),
        };
        out.push(backend);
    }
    if out.is_empty() {
        return Err("backend list must not be empty".into());
    }
    Ok(out)
}

fn parse_mutation_strategies(value: &str) -> Result<Vec<MutationStrategy>, Box<dyn Error>> {
    let mut out = Vec::new();
    for item in value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let strategy = match item.to_ascii_lowercase().as_str() {
            "deep_nesting" => MutationStrategy::DeepNesting,
            "wide_constraints" => MutationStrategy::WideConstraints,
            "pathological_loops" => MutationStrategy::PathologicalLoops,
            "mixed_types" => MutationStrategy::MixedTypes,
            "malformed_ir" => MutationStrategy::MalformedIr,
            _ => return Err(format!("unsupported mutation strategy `{item}`").into()),
        };
        out.push(strategy);
    }
    Ok(out)
}

fn print_help() {
    println!(
        "\
generate_bulk_corpus

Generate a deterministic random circuit corpus for compiler fuzzing.

Usage:
  cargo run -q -p zk-circuit-gen --example generate_bulk_corpus -- [options]

Options:
  --output-dir <path>              Output root (default: {DEFAULT_OUTPUT_DIR})
  --circuits-per-backend <count>   Circuits to generate per backend (default: {DEFAULT_CIRCUITS_PER_BACKEND})
  --seed <u64>                     RNG seed (default: {DEFAULT_SEED})
  --backends <csv>                 Backend list (circom,noir,halo2,cairo)
  --mutation-strategies <csv>      Optional mutations (deep_nesting,wide_constraints,pathological_loops,mixed_types,malformed_ir)
  --mutation-intensity <n>         Mutation intensity (default: 3)
"
    );
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let mut config = BulkGenerationConfig::new(args.output_dir);
    config.circuits_per_backend = args.circuits_per_backend;
    config.seed = args.seed;
    config.backends = args.backends;
    config.mutation_strategies = args.mutation_strategies;
    config.mutation_intensity = args.mutation_intensity;

    let report = generate_bulk_corpus(&config)?;
    println!(
        "bulk circuit generation complete: total={} per_backend={} mutation_strategies={} report={}",
        report.total_circuits,
        report.circuits_per_backend,
        report.mutation_strategies.len(),
        report.report_path.display(),
    );
    Ok(())
}
