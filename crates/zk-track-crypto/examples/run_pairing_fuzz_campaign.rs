use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use zk_track_crypto::{
    run_pairing_fuzz_campaign, PairingFuzzConfig, PairingImplementationProfile,
    PairingInputType, PairingProperty,
};

#[derive(Debug, Clone)]
struct CliArgs {
    output_json: PathBuf,
    seed: u64,
    g1_inputs: Vec<PairingInputType>,
    g2_inputs: Vec<PairingInputType>,
    properties: Vec<PairingProperty>,
    implementation_profile: PairingImplementationProfile,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;

    let mut config = PairingFuzzConfig::new();
    config.seed = args.seed;
    config.g1_inputs = args.g1_inputs;
    config.g2_inputs = args.g2_inputs;
    config.properties = args.properties;
    config.implementation_profile = args.implementation_profile;

    if let Some(parent) = args.output_json.parent() {
        fs::create_dir_all(parent)?;
    }

    let report = run_pairing_fuzz_campaign(&config);
    fs::write(
        &args.output_json,
        serde_json::to_string_pretty(&report)? + "\n",
    )?;

    println!(
        "pairing campaign complete: combinations={} checks={} property_failures={} candidate_accepts_invalid={} findings={} report={}",
        report.total_combinations,
        report.total_checks,
        report.property_failures,
        report.candidate_accepts_invalid_cases,
        report.findings.len(),
        args.output_json.display(),
    );

    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut output_json = PathBuf::from("artifacts/crypto/pairing_sample/latest_report.json");
    let mut seed = 20_260_223u64;
    let mut g1_inputs = PairingInputType::ALL.to_vec();
    let mut g2_inputs = PairingInputType::ALL.to_vec();
    let mut properties = PairingProperty::ALL.to_vec();
    let mut implementation_profile = PairingImplementationProfile::StrictSubgroupChecks;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output-json" => output_json = PathBuf::from(next_value(&mut args, "--output-json")?),
            "--seed" => seed = next_value(&mut args, "--seed")?.parse::<u64>()?,
            "--g1-inputs" => g1_inputs = parse_inputs(&next_value(&mut args, "--g1-inputs")?)?,
            "--g2-inputs" => g2_inputs = parse_inputs(&next_value(&mut args, "--g2-inputs")?)?,
            "--properties" => properties = parse_properties(&next_value(&mut args, "--properties")?)?,
            "--implementation-profile" => {
                implementation_profile = parse_profile(&next_value(&mut args, "--implementation-profile")?)?
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
        g1_inputs,
        g2_inputs,
        properties,
        implementation_profile,
    })
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn parse_inputs(raw: &str) -> Result<Vec<PairingInputType>, Box<dyn Error>> {
    let mut parsed = Vec::new();
    for token in raw.split(',').map(str::trim).filter(|item| !item.is_empty()) {
        let input_type = match token.to_ascii_lowercase().as_str() {
            "identity" => PairingInputType::Identity,
            "generator" => PairingInputType::Generator,
            "random_valid" => PairingInputType::RandomValid,
            "low_order_proxy" => PairingInputType::LowOrderProxy,
            "invalid" => PairingInputType::Invalid,
            _ => return Err(format!("unsupported pairing input `{token}`").into()),
        };
        if !parsed.contains(&input_type) {
            parsed.push(input_type);
        }
    }

    if parsed.is_empty() {
        return Err("input list must not be empty".into());
    }

    Ok(parsed)
}

fn parse_properties(raw: &str) -> Result<Vec<PairingProperty>, Box<dyn Error>> {
    let mut parsed = Vec::new();
    for token in raw.split(',').map(str::trim).filter(|item| !item.is_empty()) {
        let property = match token.to_ascii_lowercase().as_str() {
            "bilinearity" => PairingProperty::Bilinearity,
            "non_degeneracy" => PairingProperty::NonDegeneracy,
            "identity" => PairingProperty::Identity,
            "linearity_g1" => PairingProperty::LinearityG1,
            "linearity_g2" => PairingProperty::LinearityG2,
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

fn parse_profile(raw: &str) -> Result<PairingImplementationProfile, Box<dyn Error>> {
    match raw.to_ascii_lowercase().as_str() {
        "strict_subgroup_checks" => Ok(PairingImplementationProfile::StrictSubgroupChecks),
        "weak_subgroup_checks" => Ok(PairingImplementationProfile::WeakSubgroupChecks),
        _ => Err(format!("unsupported implementation profile `{raw}`").into()),
    }
}

fn print_help() {
    println!(
        "\
run_pairing_fuzz_campaign

Run pairing fuzzing on a 5x5 input matrix with bilinearity and linearity property checks.

Usage:
  cargo run -q -p zk-track-crypto --example run_pairing_fuzz_campaign -- [options]

Options:
  --output-json <path>              Output JSON report path
  --seed <u64>                      RNG seed (default: 20260223)
  --g1-inputs <csv>                 identity,generator,random_valid,low_order_proxy,invalid
  --g2-inputs <csv>                 identity,generator,random_valid,low_order_proxy,invalid
  --properties <csv>                bilinearity,non_degeneracy,identity,linearity_g1,linearity_g2
  --implementation-profile <name>   strict_subgroup_checks | weak_subgroup_checks (default: strict_subgroup_checks)
"
    );
}
