use std::env;
use std::error::Error;
use std::path::PathBuf;

use zk_circuit_gen::{
    run_differential_version_matrix_campaign, Backend, DifferentialVersionMatrixConfig,
};

#[derive(Debug, Clone)]
struct CliArgs {
    output_dir: PathBuf,
    circuits: usize,
    seed: u64,
    backends: Vec<Backend>,
    compiler_ids: Vec<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let mut config = DifferentialVersionMatrixConfig::new(args.output_dir);
    config.circuits = args.circuits;
    config.seed = args.seed;
    config.backends = args.backends;
    config.compiler_ids = args.compiler_ids;

    let report = run_differential_version_matrix_campaign(&config)?;
    println!(
        "differential version matrix complete: circuits={} observations={} comparisons={} regressions={} report={}",
        report.circuits,
        report.total_observations,
        report.total_comparisons,
        report.optimization_regressions,
        report.report_path.display()
    );
    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut output_dir = PathBuf::from("artifacts/circuit_gen/differential_version_matrix_latest");
    let mut circuits = 120usize;
    let mut seed = 42u64;
    let mut backends = vec![Backend::Circom];
    let mut compiler_ids = vec![
        "circom_v2_0".to_string(),
        "circom_v2_1".to_string(),
        "circom_v2_2".to_string(),
    ];

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output-dir" => output_dir = PathBuf::from(next_value(&mut args, "--output-dir")?),
            "--circuits" => circuits = next_value(&mut args, "--circuits")?.parse::<usize>()?,
            "--seed" => seed = next_value(&mut args, "--seed")?.parse::<u64>()?,
            "--backends" => backends = parse_backends(&next_value(&mut args, "--backends")?)?,
            "--compiler-ids" => {
                compiler_ids = parse_compiler_ids(&next_value(&mut args, "--compiler-ids")?)?;
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
        circuits,
        seed,
        backends,
        compiler_ids,
    })
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn parse_backends(raw: &str) -> Result<Vec<Backend>, Box<dyn Error>> {
    let mut out = Vec::new();
    for item in raw
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
        if !out.contains(&backend) {
            out.push(backend);
        }
    }
    if out.is_empty() {
        return Err("backend list must not be empty".into());
    }
    Ok(out)
}

fn parse_compiler_ids(raw: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let out = raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if out.len() < 2 {
        return Err("compiler list must contain at least two entries".into());
    }
    Ok(out)
}

fn print_help() {
    println!(
        "\
run_differential_version_matrix

Run N-circuit × M-compiler differential matrix and emit aggregated report.

Usage:
  cargo run -q -p zk-circuit-gen --example run_differential_version_matrix -- [options]

Options:
  --output-dir <path>      Output directory (default: artifacts/circuit_gen/differential_version_matrix_latest)
  --circuits <n>           Number of generated circuits (default: 120)
  --seed <u64>             RNG seed (default: 42)
  --backends <csv>         Backend list (default: circom)
  --compiler-ids <csv>     Compiler labels (default: circom_v2_0,circom_v2_1,circom_v2_2)
"
    );
}
