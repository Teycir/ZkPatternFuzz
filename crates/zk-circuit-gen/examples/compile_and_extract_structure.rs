use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use zk_circuit_gen::{
    compile_and_extract_structure, parse_dsl_json, parse_dsl_yaml, Backend, CircuitDsl,
};

#[derive(Debug, Clone)]
struct CliArgs {
    dsl_file: PathBuf,
    backend: Backend,
    output_json: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let payload = fs::read_to_string(&args.dsl_file)?;
    let dsl = parse_dsl_by_extension(&args.dsl_file, &payload)?;
    let summary = compile_and_extract_structure(&dsl, args.backend)?;
    let json = serde_json::to_string_pretty(&summary)? + "\n";

    if let Some(path) = &args.output_json {
        fs::write(path, json)?;
    } else {
        print!("{json}");
    }

    eprintln!(
        "compile-structure extraction complete: backend={} constraints={} signals={} lines={}",
        summary.backend.as_str(),
        summary.constraint_count,
        summary.signal_count,
        summary.rendered_line_count
    );
    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut dsl_file = None;
    let mut backend = None;
    let mut output_json = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dsl-file" => dsl_file = Some(PathBuf::from(next_value(&mut args, "--dsl-file")?)),
            "--backend" => backend = Some(parse_backend(&next_value(&mut args, "--backend")?)?),
            "--output-json" => {
                output_json = Some(PathBuf::from(next_value(&mut args, "--output-json")?))
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }

    let dsl_file = dsl_file.ok_or("--dsl-file is required")?;
    let backend = backend.ok_or("--backend is required")?;
    Ok(CliArgs {
        dsl_file,
        backend,
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

fn parse_backend(raw: &str) -> Result<Backend, Box<dyn Error>> {
    match raw.to_ascii_lowercase().as_str() {
        "circom" => Ok(Backend::Circom),
        "noir" => Ok(Backend::Noir),
        "halo2" => Ok(Backend::Halo2),
        "cairo" => Ok(Backend::Cairo),
        _ => Err(format!("unsupported backend `{raw}`").into()),
    }
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

fn print_help() {
    println!(
        "\
compile_and_extract_structure

Compile DSL into backend template and extract constraint/structure metrics.

Usage:
  cargo run -q -p zk-circuit-gen --example compile_and_extract_structure -- [options]

Options:
  --dsl-file <path>      Required DSL file (.yaml/.yml/.json)
  --backend <name>       Required backend (circom,noir,halo2,cairo)
  --output-json <path>   Optional output path (default: stdout)
"
    );
}
