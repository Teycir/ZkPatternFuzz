use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use zk_circuit_gen::{
    extract_semantic_intent_from_text, parse_dsl_json, parse_dsl_yaml,
    verify_compiled_constraints_match_intent, Backend, CircuitDsl,
};

#[derive(Debug, Clone)]
struct CliArgs {
    source_file: PathBuf,
    dsl_file: PathBuf,
    backend: Backend,
    doc_file: Option<PathBuf>,
    output_json: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let source_code = fs::read_to_string(&args.source_file)?;
    let dsl_payload = fs::read_to_string(&args.dsl_file)?;
    let dsl = parse_dsl_by_extension(&args.dsl_file, &dsl_payload)?;
    let docs = args.doc_file.as_ref().map(fs::read_to_string).transpose()?;

    let intent =
        extract_semantic_intent_from_text(&source_code, docs.as_deref(), Some(args.backend));
    let report = verify_compiled_constraints_match_intent(&dsl, args.backend, &intent)?;
    let payload = serde_json::to_string_pretty(&report)? + "\n";

    if let Some(path) = &args.output_json {
        fs::write(path, payload)?;
    } else {
        print!("{payload}");
    }

    eprintln!(
        "semantic-constraint verification complete: intents={} matched={} mismatched={} gaps={}",
        report.total_intents,
        report.matched_intents,
        report.mismatched_intents,
        report.constraint_gaps.len()
    );
    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut source_file = None;
    let mut dsl_file = None;
    let mut backend = None;
    let mut doc_file = None;
    let mut output_json = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--source-file" => {
                source_file = Some(PathBuf::from(next_value(&mut args, "--source-file")?))
            }
            "--dsl-file" => dsl_file = Some(PathBuf::from(next_value(&mut args, "--dsl-file")?)),
            "--backend" => backend = Some(parse_backend(&next_value(&mut args, "--backend")?)?),
            "--doc-file" => doc_file = Some(PathBuf::from(next_value(&mut args, "--doc-file")?)),
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

    Ok(CliArgs {
        source_file: source_file.ok_or("--source-file is required")?,
        dsl_file: dsl_file.ok_or("--dsl-file is required")?,
        backend: backend.ok_or("--backend is required")?,
        doc_file,
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
verify_semantic_constraint_match

Verify whether compiled constraints align with extracted semantic intent.

Usage:
  cargo run -q -p zk-circuit-gen --example verify_semantic_constraint_match -- [options]

Options:
  --source-file <path>    Required source file with comments
  --dsl-file <path>       Required DSL file (.yaml/.yml/.json)
  --backend <name>        Required backend (circom,noir,halo2,cairo)
  --doc-file <path>       Optional docs file
  --output-json <path>    Optional output path (default: stdout)
"
    );
}
