use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use zk_track_boundary::{
    run_solidity_verifier_fuzz_campaign, PairingManipulationCase, SolidityEdgeCase,
    SolidityVerifierFuzzConfig, SolidityVerifierProfile, VerifierInputMutation,
};

#[derive(Debug, Clone)]
struct CliArgs {
    output_json: PathBuf,
    seed: u64,
    proofs: usize,
    public_inputs_per_proof: usize,
    input_mutations: Vec<VerifierInputMutation>,
    pairing_cases: Vec<PairingManipulationCase>,
    edge_cases: Vec<SolidityEdgeCase>,
    optimized_profile: SolidityVerifierProfile,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let mut config = SolidityVerifierFuzzConfig::new();
    config.seed = args.seed;
    config.proofs = args.proofs;
    config.public_inputs_per_proof = args.public_inputs_per_proof;
    config.input_mutations = args.input_mutations;
    config.pairing_cases = args.pairing_cases;
    config.edge_cases = args.edge_cases;
    config.optimized_profile = args.optimized_profile;

    if let Some(parent) = args.output_json.parent() {
        fs::create_dir_all(parent)?;
    }

    let report = run_solidity_verifier_fuzz_campaign(&config);
    fs::write(
        &args.output_json,
        serde_json::to_string_pretty(&report)? + "\n",
    )?;

    println!(
        "solidity verifier fuzz campaign complete: proofs={} checks={} divergences={} optimized_accepts_reference_rejects={} report={}",
        report.proofs,
        report.differential_checks,
        report.differential_divergences,
        report.optimized_accepts_reference_rejects,
        args.output_json.display()
    );
    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut output_json =
        PathBuf::from("artifacts/boundary/solidity_verifier_sample/latest_report.json");
    let mut seed = 20_260_223u64;
    let mut proofs = 500usize;
    let mut public_inputs_per_proof = 3usize;
    let mut input_mutations = VerifierInputMutation::ALL.to_vec();
    let mut pairing_cases = PairingManipulationCase::ALL.to_vec();
    let mut edge_cases = SolidityEdgeCase::ALL.to_vec();
    let mut optimized_profile = SolidityVerifierProfile::StrictParity;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output-json" => output_json = PathBuf::from(next_value(&mut args, "--output-json")?),
            "--seed" => seed = next_value(&mut args, "--seed")?.parse::<u64>()?,
            "--proofs" => proofs = next_value(&mut args, "--proofs")?.parse::<usize>()?,
            "--public-inputs-per-proof" => {
                public_inputs_per_proof =
                    next_value(&mut args, "--public-inputs-per-proof")?.parse::<usize>()?
            }
            "--input-mutations" => {
                input_mutations =
                    parse_input_mutations(&next_value(&mut args, "--input-mutations")?)?
            }
            "--pairing-cases" => {
                pairing_cases = parse_pairing_cases(&next_value(&mut args, "--pairing-cases")?)?
            }
            "--edge-cases" => {
                edge_cases = parse_edge_cases(&next_value(&mut args, "--edge-cases")?)?
            }
            "--optimized-profile" => {
                optimized_profile =
                    parse_optimized_profile(&next_value(&mut args, "--optimized-profile")?)?
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }

    if proofs == 0 {
        return Err("--proofs must be greater than zero".into());
    }
    if public_inputs_per_proof == 0 {
        return Err("--public-inputs-per-proof must be greater than zero".into());
    }

    Ok(CliArgs {
        output_json,
        seed,
        proofs,
        public_inputs_per_proof,
        input_mutations,
        pairing_cases,
        edge_cases,
        optimized_profile,
    })
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn parse_input_mutations(raw: &str) -> Result<Vec<VerifierInputMutation>, Box<dyn Error>> {
    let mut parsed = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let mutation = match token.to_ascii_lowercase().as_str() {
            "proof_byte_mutation" => VerifierInputMutation::ProofByteMutation,
            "public_input_edge_case" => VerifierInputMutation::PublicInputEdgeCase,
            "malformed_calldata" => VerifierInputMutation::MalformedCalldata,
            "gas_limit_stress" => VerifierInputMutation::GasLimitStress,
            "revert_condition_probe" => VerifierInputMutation::RevertConditionProbe,
            _ => return Err(format!("unsupported input mutation `{token}`").into()),
        };
        if !parsed.contains(&mutation) {
            parsed.push(mutation);
        }
    }
    if parsed.is_empty() {
        return Err("input mutation list must not be empty".into());
    }
    Ok(parsed)
}

fn parse_pairing_cases(raw: &str) -> Result<Vec<PairingManipulationCase>, Box<dyn Error>> {
    let mut parsed = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let case = match token.to_ascii_lowercase().as_str() {
            "pairing_equation_tamper" => PairingManipulationCase::PairingEquationTamper,
            "invalid_curve_point" => PairingManipulationCase::InvalidCurvePoint,
            "wrong_subgroup_point" => PairingManipulationCase::WrongSubgroupPoint,
            "malformed_pairing_input" => PairingManipulationCase::MalformedPairingInput,
            _ => return Err(format!("unsupported pairing case `{token}`").into()),
        };
        if !parsed.contains(&case) {
            parsed.push(case);
        }
    }
    if parsed.is_empty() {
        return Err("pairing case list must not be empty".into());
    }
    Ok(parsed)
}

fn parse_edge_cases(raw: &str) -> Result<Vec<SolidityEdgeCase>, Box<dyn Error>> {
    let mut parsed = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let case = match token.to_ascii_lowercase().as_str() {
            "gas_calculation_overflow" => SolidityEdgeCase::GasCalculationOverflow,
            "public_input_array_bounds" => SolidityEdgeCase::PublicInputArrayBounds,
            "memory_allocation_edge" => SolidityEdgeCase::MemoryAllocationEdge,
            "calldata_memory_confusion" => SolidityEdgeCase::CalldataMemoryConfusion,
            "reentrancy_callback_probe" => SolidityEdgeCase::ReentrancyCallbackProbe,
            _ => return Err(format!("unsupported edge case `{token}`").into()),
        };
        if !parsed.contains(&case) {
            parsed.push(case);
        }
    }
    if parsed.is_empty() {
        return Err("edge case list must not be empty".into());
    }
    Ok(parsed)
}

fn parse_optimized_profile(raw: &str) -> Result<SolidityVerifierProfile, Box<dyn Error>> {
    match raw.to_ascii_lowercase().as_str() {
        "strict_parity" => Ok(SolidityVerifierProfile::StrictParity),
        "weak_gas_optimization" => Ok(SolidityVerifierProfile::WeakGasOptimization),
        _ => Err(format!("unsupported optimized profile `{raw}`").into()),
    }
}

fn print_help() {
    println!(
        "\
run_solidity_verifier_fuzz_campaign

Run differential fuzzing between a strict reference verifier and a gas-optimized verifier model.

Usage:
  cargo run -q -p zk-track-boundary --example run_solidity_verifier_fuzz_campaign -- [options]

Options:
  --output-json <path>            Output JSON report path
  --seed <u64>                    RNG seed (default: 20260223)
  --proofs <n>                    Number of valid proofs to test (default: 500)
  --public-inputs-per-proof <n>   Number of public inputs per proof (default: 3)
  --input-mutations <csv>         proof_byte_mutation,public_input_edge_case,malformed_calldata,gas_limit_stress,revert_condition_probe
  --pairing-cases <csv>           pairing_equation_tamper,invalid_curve_point,wrong_subgroup_point,malformed_pairing_input
  --edge-cases <csv>              gas_calculation_overflow,public_input_array_bounds,memory_allocation_edge,calldata_memory_confusion,reentrancy_callback_probe
  --optimized-profile <name>      strict_parity | weak_gas_optimization (default: strict_parity)
"
    );
}
