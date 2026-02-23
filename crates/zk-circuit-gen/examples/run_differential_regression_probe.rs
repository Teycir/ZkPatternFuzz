use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use zk_circuit_gen::{
    parse_dsl_json, parse_dsl_yaml, run_differential_compiler_matrix_with_constraint_overrides,
    Backend, CircuitDsl,
};

#[derive(Debug, Clone)]
struct CliArgs {
    dsl_file: PathBuf,
    backends: Vec<Backend>,
    compiler_ids: Vec<String>,
    constraint_overrides: BTreeMap<String, usize>,
    output_json: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let payload = fs::read_to_string(&args.dsl_file)?;
    let dsl = parse_dsl_by_extension(&args.dsl_file, &payload)?;
    let report = run_differential_compiler_matrix_with_constraint_overrides(
        &dsl,
        &args.backends,
        &args.compiler_ids,
        &args.constraint_overrides,
    )?;
    let json = serde_json::to_string_pretty(&report)? + "\n";

    if let Some(path) = &args.output_json {
        fs::write(path, json)?;
    } else {
        print!("{json}");
    }

    eprintln!(
        "differential regression probe complete: observations={} comparisons={} regressions={}",
        report.observations.len(),
        report.comparisons.len(),
        report.optimization_regressions
    );
    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut dsl_file = None;
    let mut backends = vec![Backend::Circom];
    let mut compiler_ids = vec!["circom_v2_0".to_string(), "circom_v2_1".to_string()];
    let mut constraint_overrides = BTreeMap::new();
    let mut output_json = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dsl-file" => dsl_file = Some(PathBuf::from(next_value(&mut args, "--dsl-file")?)),
            "--backends" => {
                backends = parse_backends(&next_value(&mut args, "--backends")?)?;
            }
            "--compiler-ids" => {
                compiler_ids = parse_compiler_ids(&next_value(&mut args, "--compiler-ids")?)?;
            }
            "--constraint-overrides" => {
                constraint_overrides =
                    parse_constraint_overrides(&next_value(&mut args, "--constraint-overrides")?)?;
            }
            "--output-json" => {
                output_json = Some(PathBuf::from(next_value(&mut args, "--output-json")?));
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }

    Ok(CliArgs {
        dsl_file: dsl_file.ok_or("--dsl-file is required")?,
        backends,
        compiler_ids,
        constraint_overrides,
        output_json,
    })
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn parse_dsl_by_extension(
    path: &std::path::Path,
    payload: &str,
) -> Result<CircuitDsl, Box<dyn Error>> {
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match ext.as_str() {
        "yaml" | "yml" => Ok(parse_dsl_yaml(payload)?),
        "json" => Ok(parse_dsl_json(payload)?),
        _ => Err(format!(
            "unsupported DSL extension `{}` (expected .yaml/.yml/.json)",
            ext
        )
        .into()),
    }
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

fn parse_constraint_overrides(raw: &str) -> Result<BTreeMap<String, usize>, Box<dyn Error>> {
    let mut out = BTreeMap::new();
    for item in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let (compiler_id, raw_delta) = item
            .split_once(':')
            .ok_or_else(|| format!("invalid override `{item}` (expected compiler_id:+N)"))?;
        let compiler_id = compiler_id.trim().to_string();
        if compiler_id.is_empty() {
            return Err(format!("invalid override `{item}` (empty compiler_id)").into());
        }
        let delta = raw_delta
            .trim()
            .trim_start_matches('+')
            .parse::<usize>()
            .map_err(|_| {
                format!("invalid override `{item}` (delta must be non-negative integer)")
            })?;
        out.insert(compiler_id, delta);
    }
    Ok(out)
}

fn print_help() {
    println!(
        "\
run_differential_regression_probe

Run differential matrix with operator-provided constraint overrides to verify
optimization regression detection behavior.

Usage:
  cargo run -q -p zk-circuit-gen --example run_differential_regression_probe -- [options]

Options:
  --dsl-file <path>              Required DSL file (.yaml/.yml/.json)
  --compiler-ids <csv>           Compiler labels (default: circom_v2_0,circom_v2_1)
  --backends <csv>               Backend list (default: circom)
  --constraint-overrides <csv>   Overrides as compiler_id:+N pairs (example: circom_v2_1:+3)
  --output-json <path>           Optional output path (default: stdout)
"
    );
}
