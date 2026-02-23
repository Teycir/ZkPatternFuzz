use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use zk_circuit_gen::{extract_semantic_intent_from_text, Backend};

#[derive(Debug, Clone)]
struct CliArgs {
    source_file: PathBuf,
    backend: Option<Backend>,
    doc_file: Option<PathBuf>,
    output_json: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let source_code = fs::read_to_string(&args.source_file)?;
    let docs = args.doc_file.as_ref().map(fs::read_to_string).transpose()?;
    let extraction = extract_semantic_intent_from_text(&source_code, docs.as_deref(), args.backend);
    let payload = serde_json::to_string_pretty(&extraction)? + "\n";

    if let Some(path) = args.output_json {
        fs::write(path, payload)?;
    } else {
        print!("{payload}");
    }

    eprintln!(
        "semantic intent extraction complete: signals={} comments={} docs={}",
        extraction.signals.len(),
        extraction.comment_lines.len(),
        extraction.documentation_lines.len()
    );
    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut source_file = None;
    let mut backend = None;
    let mut doc_file = None;
    let mut output_json = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--source-file" => {
                source_file = Some(PathBuf::from(next_value(&mut args, "--source-file")?))
            }
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

    let source_file = source_file.ok_or("--source-file is required")?;
    Ok(CliArgs {
        source_file,
        backend,
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

fn print_help() {
    println!(
        "\
extract_semantic_intent

Extract semantic intent statements from circuit comments and optional docs.

Usage:
  cargo run -q -p zk-circuit-gen --example extract_semantic_intent -- [options]

Options:
  --source-file <path>    Required circuit source file
  --backend <name>        Optional backend hint (circom,noir,halo2,cairo)
  --doc-file <path>       Optional documentation text/markdown file
  --output-json <path>    Optional output path (default: stdout)
"
    );
}
