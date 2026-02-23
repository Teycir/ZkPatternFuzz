use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use zk_track_crypto::{
    run_field_arithmetic_fuzz_campaign, FieldArithmeticFuzzConfig, FieldImplementationProfile,
    FieldOperation, FieldProperty,
};

#[derive(Debug, Clone)]
struct CliArgs {
    output_json: PathBuf,
    seed: u64,
    random_values: usize,
    operations: Vec<FieldOperation>,
    properties: Vec<FieldProperty>,
    implementation_profile: FieldImplementationProfile,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;

    let mut config = FieldArithmeticFuzzConfig::new();
    config.seed = args.seed;
    config.random_values = args.random_values;
    config.operations = args.operations;
    config.properties = args.properties;
    config.implementation_profile = args.implementation_profile;

    if let Some(parent) = args.output_json.parent() {
        fs::create_dir_all(parent)?;
    }

    let report = run_field_arithmetic_fuzz_campaign(&config);
    fs::write(
        &args.output_json,
        serde_json::to_string_pretty(&report)? + "\n",
    )?;

    println!(
        "field arithmetic campaign complete: checks={} operation_divergences={} property_failures={} findings={} report={}",
        report.total_checks,
        report.operation_divergences,
        report.property_failures,
        report.findings.len(),
        args.output_json.display(),
    );

    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut output_json = PathBuf::from("artifacts/crypto/field_sample/latest_report.json");
    let mut seed = 20_260_223u64;
    let mut random_values = 8usize;
    let mut operations = FieldOperation::ALL.to_vec();
    let mut properties = FieldProperty::ALL.to_vec();
    let mut implementation_profile = FieldImplementationProfile::StrictReference;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output-json" => output_json = PathBuf::from(next_value(&mut args, "--output-json")?),
            "--seed" => seed = next_value(&mut args, "--seed")?.parse::<u64>()?,
            "--random-values" => {
                random_values = next_value(&mut args, "--random-values")?.parse::<usize>()?
            }
            "--operations" => {
                operations = parse_operations(&next_value(&mut args, "--operations")?)?
            }
            "--properties" => {
                properties = parse_properties(&next_value(&mut args, "--properties")?)?
            }
            "--implementation-profile" => {
                implementation_profile =
                    parse_profile(&next_value(&mut args, "--implementation-profile")?)?
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }

    Ok(CliArgs {
        output_json,
        seed,
        random_values,
        operations,
        properties,
        implementation_profile,
    })
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn parse_operations(raw: &str) -> Result<Vec<FieldOperation>, Box<dyn Error>> {
    let mut parsed = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let operation = match token.to_ascii_lowercase().as_str() {
            "addition" => FieldOperation::Addition,
            "subtraction" => FieldOperation::Subtraction,
            "multiplication" => FieldOperation::Multiplication,
            "division" => FieldOperation::Division,
            "exponentiation" => FieldOperation::Exponentiation,
            "modular_reduction" => FieldOperation::ModularReduction,
            _ => return Err(format!("unsupported operation `{token}`").into()),
        };
        if !parsed.contains(&operation) {
            parsed.push(operation);
        }
    }

    if parsed.is_empty() {
        return Err("operation list must not be empty".into());
    }

    Ok(parsed)
}

fn parse_properties(raw: &str) -> Result<Vec<FieldProperty>, Box<dyn Error>> {
    let mut parsed = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let property = match token.to_ascii_lowercase().as_str() {
            "commutativity" => FieldProperty::Commutativity,
            "associativity" => FieldProperty::Associativity,
            "distributivity" => FieldProperty::Distributivity,
            "identity" => FieldProperty::Identity,
            "inverse" => FieldProperty::Inverse,
            _ => return Err(format!("unsupported property `{token}`").into()),
        };
        if !parsed.contains(&property) {
            parsed.push(property);
        }
    }

    if parsed.is_empty() {
        return Err("property list must not be empty".into());
    }

    Ok(parsed)
}

fn parse_profile(raw: &str) -> Result<FieldImplementationProfile, Box<dyn Error>> {
    match raw.to_ascii_lowercase().as_str() {
        "strict_reference" => Ok(FieldImplementationProfile::StrictReference),
        "weak_reduction" => Ok(FieldImplementationProfile::WeakReduction),
        _ => Err(format!("unsupported implementation profile `{raw}`").into()),
    }
}

fn print_help() {
    println!(
        "\
run_field_arithmetic_fuzz_campaign

Run field arithmetic fuzzing with edge-case values and algebraic property checks.

Usage:
  cargo run -q -p zk-track-crypto --example run_field_arithmetic_fuzz_campaign -- [options]

Options:
  --output-json <path>              Output JSON report path
  --seed <u64>                      RNG seed (default: 20260223)
  --random-values <n>               Random values on top of edge values (default: 8)
  --operations <csv>                addition,subtraction,multiplication,division,exponentiation,modular_reduction
  --properties <csv>                commutativity,associativity,distributivity,identity,inverse
  --implementation-profile <name>   strict_reference | weak_reduction (default: strict_reference)
"
    );
}
