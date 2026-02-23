use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use zk_track_boundary::{
    run_cross_component_fuzz_campaign, ComponentMismatchCase, CrossComponentFuzzConfig,
    CrossComponentVerifierProfile, WorkflowFaultStage,
};

#[derive(Debug, Clone)]
struct CliArgs {
    output_json: PathBuf,
    seed: u64,
    combinations: usize,
    public_inputs_per_case: usize,
    fault_stages: Vec<WorkflowFaultStage>,
    mismatch_cases: Vec<ComponentMismatchCase>,
    verifier_profile: CrossComponentVerifierProfile,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let mut config = CrossComponentFuzzConfig::new();
    config.seed = args.seed;
    config.combinations = args.combinations;
    config.public_inputs_per_case = args.public_inputs_per_case;
    config.fault_stages = args.fault_stages;
    config.mismatch_cases = args.mismatch_cases;
    config.verifier_profile = args.verifier_profile;

    if let Some(parent) = args.output_json.parent() {
        fs::create_dir_all(parent)?;
    }

    let report = run_cross_component_fuzz_campaign(&config);
    fs::write(
        &args.output_json,
        serde_json::to_string_pretty(&report)? + "\n",
    )?;

    println!(
        "cross component fuzz campaign complete: combinations={} tested_combinations={} checks={} divergences={} candidate_accepts_reference_rejects={} report={}",
        report.combinations,
        report.configuration_combinations_tested,
        report.total_checks,
        report.differential_divergences,
        report.candidate_accepts_reference_rejects,
        args.output_json.display()
    );
    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut output_json =
        PathBuf::from("artifacts/boundary/cross_component_sample/latest_report.json");
    let mut seed = 20_260_223u64;
    let mut combinations = 60usize;
    let mut public_inputs_per_case = 3usize;
    let mut fault_stages = WorkflowFaultStage::ALL.to_vec();
    let mut mismatch_cases = ComponentMismatchCase::ALL.to_vec();
    let mut verifier_profile = CrossComponentVerifierProfile::StrictCompatibility;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output-json" => output_json = PathBuf::from(next_value(&mut args, "--output-json")?),
            "--seed" => seed = next_value(&mut args, "--seed")?.parse::<u64>()?,
            "--combinations" => {
                combinations = next_value(&mut args, "--combinations")?.parse::<usize>()?
            }
            "--public-inputs-per-case" => {
                public_inputs_per_case =
                    next_value(&mut args, "--public-inputs-per-case")?.parse::<usize>()?
            }
            "--fault-stages" => {
                fault_stages = parse_fault_stages(&next_value(&mut args, "--fault-stages")?)?
            }
            "--mismatch-cases" => {
                mismatch_cases = parse_mismatch_cases(&next_value(&mut args, "--mismatch-cases")?)?
            }
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

    if combinations == 0 {
        return Err("--combinations must be greater than zero".into());
    }
    if public_inputs_per_case == 0 {
        return Err("--public-inputs-per-case must be greater than zero".into());
    }

    Ok(CliArgs {
        output_json,
        seed,
        combinations,
        public_inputs_per_case,
        fault_stages,
        mismatch_cases,
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

fn parse_fault_stages(raw: &str) -> Result<Vec<WorkflowFaultStage>, Box<dyn Error>> {
    let mut parsed = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let stage = match token.to_ascii_lowercase().as_str() {
            "circuit_stage" => WorkflowFaultStage::CircuitStage,
            "prover_stage" => WorkflowFaultStage::ProverStage,
            "verifier_stage" => WorkflowFaultStage::VerifierStage,
            "transport_boundary" => WorkflowFaultStage::TransportBoundary,
            _ => return Err(format!("unsupported fault stage `{token}`").into()),
        };
        if !parsed.contains(&stage) {
            parsed.push(stage);
        }
    }
    if parsed.is_empty() {
        return Err("fault stage list must not be empty".into());
    }
    Ok(parsed)
}

fn parse_mismatch_cases(raw: &str) -> Result<Vec<ComponentMismatchCase>, Box<dyn Error>> {
    let mut parsed = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let mismatch_case = match token.to_ascii_lowercase().as_str() {
            "prover_verifier_version_mismatch" => {
                ComponentMismatchCase::ProverVerifierVersionMismatch
            }
            "circuit_verifier_flag_mismatch" => ComponentMismatchCase::CircuitVerifierFlagMismatch,
            "trusted_setup_mismatch" => ComponentMismatchCase::TrustedSetupMismatch,
            "curve_parameter_mismatch" => ComponentMismatchCase::CurveParameterMismatch,
            _ => return Err(format!("unsupported mismatch case `{token}`").into()),
        };
        if !parsed.contains(&mismatch_case) {
            parsed.push(mismatch_case);
        }
    }
    if parsed.is_empty() {
        return Err("mismatch case list must not be empty".into());
    }
    Ok(parsed)
}

fn parse_verifier_profile(raw: &str) -> Result<CrossComponentVerifierProfile, Box<dyn Error>> {
    match raw.to_ascii_lowercase().as_str() {
        "strict_compatibility" => Ok(CrossComponentVerifierProfile::StrictCompatibility),
        "weak_mismatch_acceptance" => Ok(CrossComponentVerifierProfile::WeakMismatchAcceptance),
        _ => Err(format!("unsupported verifier profile `{raw}`").into()),
    }
}

fn print_help() {
    println!(
        "\
run_cross_component_fuzz_campaign

Run cross-component boundary fuzzing across circuit/prover/verifier pipeline stages and
version/configuration mismatch combinations.

Usage:
  cargo run -q -p zk-track-boundary --example run_cross_component_fuzz_campaign -- [options]

Options:
  --output-json <path>            Output JSON report path
  --seed <u64>                    RNG seed (default: 20260223)
  --combinations <n>              Number of component combinations to test (default: 60)
  --public-inputs-per-case <n>    Public inputs per pipeline case (default: 3)
  --fault-stages <csv>            circuit_stage,prover_stage,verifier_stage,transport_boundary
  --mismatch-cases <csv>          prover_verifier_version_mismatch,circuit_verifier_flag_mismatch,trusted_setup_mismatch,curve_parameter_mismatch
  --verifier-profile <name>       strict_compatibility | weak_mismatch_acceptance (default: strict_compatibility)
"
    );
}
