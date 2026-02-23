use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use zk_track_crypto::{
    run_curve_operation_fuzz_campaign, CurveEdgeCase, CurveImplementationProfile, CurveOperation,
    CurveOperationFuzzConfig, CurvePointType,
};

#[derive(Debug, Clone)]
struct CliArgs {
    output_json: PathBuf,
    seed: u64,
    iterations: usize,
    point_types: Vec<CurvePointType>,
    operations: Vec<CurveOperation>,
    edge_cases: Vec<CurveEdgeCase>,
    implementation_profile: CurveImplementationProfile,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;

    let mut config = CurveOperationFuzzConfig::new();
    config.seed = args.seed;
    config.iterations = args.iterations;
    config.point_types = args.point_types;
    config.operations = args.operations;
    config.edge_cases = args.edge_cases;
    config.implementation_profile = args.implementation_profile;

    if let Some(parent) = args.output_json.parent() {
        fs::create_dir_all(parent)?;
    }

    let report = run_curve_operation_fuzz_campaign(&config);
    fs::write(
        &args.output_json,
        serde_json::to_string_pretty(&report)? + "\n",
    )?;

    println!(
        "curve operation campaign complete: operation_checks={} edge_case_checks={} operation_divergences={} edge_case_failures={} findings={} report={}",
        report.operation_checks,
        report.edge_case_checks,
        report.operation_divergences,
        report.edge_case_failures,
        report.findings.len(),
        args.output_json.display(),
    );

    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut output_json = PathBuf::from("artifacts/crypto/curve_sample/latest_report.json");
    let mut seed = 20_260_223u64;
    let mut iterations = 50usize;
    let mut point_types = CurvePointType::ALL.to_vec();
    let mut operations = CurveOperation::ALL.to_vec();
    let mut edge_cases = CurveEdgeCase::ALL.to_vec();
    let mut implementation_profile = CurveImplementationProfile::StrictValidation;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output-json" => output_json = PathBuf::from(next_value(&mut args, "--output-json")?),
            "--seed" => seed = next_value(&mut args, "--seed")?.parse::<u64>()?,
            "--iterations" => {
                iterations = next_value(&mut args, "--iterations")?.parse::<usize>()?
            }
            "--point-types" => {
                point_types = parse_point_types(&next_value(&mut args, "--point-types")?)?
            }
            "--operations" => {
                operations = parse_operations(&next_value(&mut args, "--operations")?)?
            }
            "--edge-cases" => {
                edge_cases = parse_edge_cases(&next_value(&mut args, "--edge-cases")?)?
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
        iterations,
        point_types,
        operations,
        edge_cases,
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

fn parse_point_types(raw: &str) -> Result<Vec<CurvePointType>, Box<dyn Error>> {
    let mut parsed = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let point_type = match token.to_ascii_lowercase().as_str() {
            "identity" => CurvePointType::Identity,
            "generator" => CurvePointType::Generator,
            "random_valid" => CurvePointType::RandomValid,
            "random_valid_alt" => CurvePointType::RandomValidAlt,
            "low_order_proxy" => CurvePointType::LowOrderProxy,
            "invalid_not_on_curve" => CurvePointType::InvalidNotOnCurve,
            "infinity_alt_representation" => CurvePointType::InfinityAltRepresentation,
            _ => return Err(format!("unsupported point type `{token}`").into()),
        };
        if !parsed.contains(&point_type) {
            parsed.push(point_type);
        }
    }
    if parsed.is_empty() {
        return Err("point type list must not be empty".into());
    }
    Ok(parsed)
}

fn parse_operations(raw: &str) -> Result<Vec<CurveOperation>, Box<dyn Error>> {
    let mut parsed = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let operation = match token.to_ascii_lowercase().as_str() {
            "point_addition" => CurveOperation::PointAddition,
            "point_doubling" => CurveOperation::PointDoubling,
            "scalar_multiplication" => CurveOperation::ScalarMultiplication,
            "multi_scalar_multiplication" => CurveOperation::MultiScalarMultiplication,
            "point_negation" => CurveOperation::PointNegation,
            "point_validation" => CurveOperation::PointValidation,
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

fn parse_edge_cases(raw: &str) -> Result<Vec<CurveEdgeCase>, Box<dyn Error>> {
    let mut parsed = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let edge_case = match token.to_ascii_lowercase().as_str() {
            "adding_identity" => CurveEdgeCase::AddingIdentity,
            "adding_inverse" => CurveEdgeCase::AddingInverse,
            "doubling_identity" => CurveEdgeCase::DoublingIdentity,
            "zero_scalar" => CurveEdgeCase::ZeroScalar,
            "one_scalar" => CurveEdgeCase::OneScalar,
            "large_scalar_wraparound" => CurveEdgeCase::LargeScalarWraparound,
            "invalid_point_rejection" => CurveEdgeCase::InvalidPointRejection,
            _ => return Err(format!("unsupported edge case `{token}`").into()),
        };
        if !parsed.contains(&edge_case) {
            parsed.push(edge_case);
        }
    }
    if parsed.is_empty() {
        return Err("edge case list must not be empty".into());
    }
    Ok(parsed)
}

fn parse_profile(raw: &str) -> Result<CurveImplementationProfile, Box<dyn Error>> {
    match raw.to_ascii_lowercase().as_str() {
        "strict_validation" => Ok(CurveImplementationProfile::StrictValidation),
        "weak_invalid_handling" => Ok(CurveImplementationProfile::WeakInvalidHandling),
        _ => Err(format!("unsupported implementation profile `{raw}`").into()),
    }
}

fn print_help() {
    println!(
        "\
run_curve_operation_fuzz_campaign

Run curve-operation fuzzing against point-type matrices and edge-case properties.

Usage:
  cargo run -q -p zk-track-crypto --example run_curve_operation_fuzz_campaign -- [options]

Options:
  --output-json <path>              Output JSON report path
  --seed <u64>                      RNG seed (default: 20260223)
  --iterations <n>                  Iterations per point-type set (default: 50)
  --point-types <csv>               identity,generator,random_valid,random_valid_alt,low_order_proxy,invalid_not_on_curve,infinity_alt_representation
  --operations <csv>                point_addition,point_doubling,scalar_multiplication,multi_scalar_multiplication,point_negation,point_validation
  --edge-cases <csv>                adding_identity,adding_inverse,doubling_identity,zero_scalar,one_scalar,large_scalar_wraparound,invalid_point_rejection
  --implementation-profile <name>   strict_validation | weak_invalid_handling (default: strict_validation)
"
    );
}
