use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use zk_circuit_gen::{
    parse_dsl_json, parse_dsl_yaml, run_differential_compiler_matrix, Backend, CircuitDsl,
};

#[derive(Debug, Clone)]
struct CliArgs {
    dsl_file: PathBuf,
    backends: Vec<Backend>,
    compiler_ids: Vec<String>,
    output_json: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let payload = fs::read_to_string(&args.dsl_file)?;
    let dsl = parse_dsl_by_extension(&args.dsl_file, &payload)?;
    let report = run_differential_compiler_matrix(&dsl, &args.backends, &args.compiler_ids)?;
    let json = serde_json::to_string_pretty(&report)? + "\n";

    if let Some(path) = &args.output_json {
        fs::write(path, json)?;
    } else {
        print!("{json}");
    }

    eprintln!(
        "differential matrix complete: observations={} comparisons={} regressions={}",
        report.observations.len(),
        report.comparisons.len(),
        report.optimization_regressions
    );
    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut dsl_file = None;
    let mut backends = Backend::ALL.to_vec();
    let mut compiler_ids = Vec::new();
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
        compiler_ids: if compiler_ids.is_empty() {
            return Err("--compiler-ids requires at least two entries".into());
        } else {
            compiler_ids
        },
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
    let ids = raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if ids.len() < 2 {
        return Err("compiler list must contain at least two entries".into());
    }
    Ok(ids)
}

fn print_help() {
    println!(
        "\
run_differential_compiler_matrix

Compile one DSL across compiler ids and backends, then compare structure deltas.

Usage:
  cargo run -q -p zk-circuit-gen --example run_differential_compiler_matrix -- [options]

Options:
  --dsl-file <path>        Required DSL file (.yaml/.yml/.json)
  --compiler-ids <csv>     Required compiler labels (for example circom_v2_0,circom_v2_1)
  --backends <csv>         Optional backends (default: circom,noir,halo2,cairo)
  --output-json <path>     Optional output path (default: stdout)
"
    );
}
