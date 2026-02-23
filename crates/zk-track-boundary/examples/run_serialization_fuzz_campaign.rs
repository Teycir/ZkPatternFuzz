use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use zk_track_boundary::{
    run_serialization_fuzz_campaign, SerializationFormat, SerializationFuzzConfig,
    SerializationVerifierProfile,
};

#[derive(Debug, Clone)]
struct CliArgs {
    output_json: PathBuf,
    seed: u64,
    cases_per_format: usize,
    formats: Vec<SerializationFormat>,
    verifier_profile: SerializationVerifierProfile,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let mut config = SerializationFuzzConfig::new();
    config.seed = args.seed;
    config.cases_per_format = args.cases_per_format;
    config.formats = args.formats;
    config.verifier_profile = args.verifier_profile;

    if let Some(parent) = args.output_json.parent() {
        fs::create_dir_all(parent)?;
    }

    let report = run_serialization_fuzz_campaign(&config);
    fs::write(
        &args.output_json,
        serde_json::to_string_pretty(&report)? + "\n",
    )?;

    println!(
        "serialization fuzz campaign complete: formats={} checks={} accepted_invalid={} rejected_invalid={} report={}",
        report.formats.len(),
        report.total_checks,
        report.accepted_invalid_cases,
        report.rejected_invalid_cases,
        args.output_json.display()
    );
    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut output_json =
        PathBuf::from("artifacts/boundary/serialization_sample/latest_report.json");
    let mut seed = 20_260_223u64;
    let mut cases_per_format = 12usize;
    let mut formats = SerializationFormat::ALL.to_vec();
    let mut verifier_profile = SerializationVerifierProfile::StrictCanonical;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output-json" => output_json = PathBuf::from(next_value(&mut args, "--output-json")?),
            "--seed" => seed = next_value(&mut args, "--seed")?.parse::<u64>()?,
            "--cases-per-format" => {
                cases_per_format = next_value(&mut args, "--cases-per-format")?.parse::<usize>()?
            }
            "--formats" => formats = parse_formats(&next_value(&mut args, "--formats")?)?,
            "--verifier-profile" => {
                verifier_profile =
                    parse_verifier_profile(&next_value(&mut args, "--verifier-profile")?)?
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }

    if cases_per_format == 0 {
        return Err("--cases-per-format must be greater than zero".into());
    }

    Ok(CliArgs {
        output_json,
        seed,
        cases_per_format,
        formats,
        verifier_profile,
    })
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn parse_formats(raw: &str) -> Result<Vec<SerializationFormat>, Box<dyn Error>> {
    let mut parsed = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let format = match token.to_ascii_lowercase().as_str() {
            "binary" => SerializationFormat::Binary,
            "hex" => SerializationFormat::Hex,
            "base64" => SerializationFormat::Base64,
            _ => return Err(format!("unsupported serialization format `{token}`").into()),
        };
        if !parsed.contains(&format) {
            parsed.push(format);
        }
    }
    if parsed.is_empty() {
        return Err("format list must not be empty".into());
    }
    Ok(parsed)
}

fn parse_verifier_profile(raw: &str) -> Result<SerializationVerifierProfile, Box<dyn Error>> {
    match raw.to_ascii_lowercase().as_str() {
        "strict_canonical" => Ok(SerializationVerifierProfile::StrictCanonical),
        "lenient_legacy" => Ok(SerializationVerifierProfile::LenientLegacy),
        _ => Err(format!("unsupported verifier profile `{raw}`").into()),
    }
}

fn print_help() {
    println!(
        "\
run_serialization_fuzz_campaign

Run serialization/deserialization boundary fuzzing against proof payloads, public inputs,
and cross-language transport edge cases.

Usage:
  cargo run -q -p zk-track-boundary --example run_serialization_fuzz_campaign -- [options]

Options:
  --output-json <path>            Output JSON report path
  --seed <u64>                    RNG seed (default: 20260223)
  --cases-per-format <n>          Iterations per format (default: 12)
  --formats <csv>                 binary,hex,base64 (default: all)
  --verifier-profile <name>       strict_canonical | lenient_legacy (default: strict_canonical)
"
    );
}
