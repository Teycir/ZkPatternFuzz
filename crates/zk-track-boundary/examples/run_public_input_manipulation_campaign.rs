use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use zk_track_boundary::{
    run_public_input_manipulation_campaign, PublicInputAttackScenario,
    PublicInputManipulationConfig, PublicInputMutationStrategy, PublicInputVerifierProfile,
};

#[derive(Debug, Clone)]
struct CliArgs {
    output_json: PathBuf,
    seed: u64,
    proofs: usize,
    public_inputs_per_proof: usize,
    mutation_strategies: Vec<PublicInputMutationStrategy>,
    attack_scenarios: Vec<PublicInputAttackScenario>,
    verifier_profile: PublicInputVerifierProfile,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let mut config = PublicInputManipulationConfig::new();
    config.seed = args.seed;
    config.proofs = args.proofs;
    config.public_inputs_per_proof = args.public_inputs_per_proof;
    config.mutation_strategies = args.mutation_strategies;
    config.attack_scenarios = args.attack_scenarios;
    config.verifier_profile = args.verifier_profile;

    if let Some(parent) = args.output_json.parent() {
        fs::create_dir_all(parent)?;
    }
    let report = run_public_input_manipulation_campaign(&config);
    fs::write(
        &args.output_json,
        serde_json::to_string_pretty(&report)? + "\n",
    )?;

    println!(
        "public input manipulation campaign complete: proofs={} checks={} accepted={} rejected={} report={}",
        report.proofs,
        report.total_mutation_checks,
        report.accepted_mutations,
        report.rejected_mutations,
        args.output_json.display()
    );
    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut output_json =
        PathBuf::from("artifacts/boundary/public_input_sample/latest_report.json");
    let mut seed = 13_370u64;
    let mut proofs = 1_000usize;
    let mut public_inputs_per_proof = 3usize;
    let mut mutation_strategies = PublicInputMutationStrategy::ALL.to_vec();
    let mut attack_scenarios = PublicInputAttackScenario::ALL.to_vec();
    let mut verifier_profile = PublicInputVerifierProfile::StrictBinding;

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
            "--mutation-strategies" => {
                mutation_strategies =
                    parse_mutation_strategies(&next_value(&mut args, "--mutation-strategies")?)?;
            }
            "--attack-scenarios" => {
                attack_scenarios =
                    parse_attack_scenarios(&next_value(&mut args, "--attack-scenarios")?)?;
            }
            "--verifier-profile" => {
                verifier_profile =
                    parse_verifier_profile(&next_value(&mut args, "--verifier-profile")?)?;
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
        mutation_strategies,
        attack_scenarios,
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

fn parse_mutation_strategies(
    raw: &str,
) -> Result<Vec<PublicInputMutationStrategy>, Box<dyn Error>> {
    let mut parsed = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let strategy = match token.to_ascii_lowercase().as_str() {
            "bit_flip" => PublicInputMutationStrategy::BitFlip,
            "field_boundary" => PublicInputMutationStrategy::FieldBoundary,
            "reordering" => PublicInputMutationStrategy::Reordering,
            "truncation" => PublicInputMutationStrategy::Truncation,
            "duplication" => PublicInputMutationStrategy::Duplication,
            "type_confusion" => PublicInputMutationStrategy::TypeConfusion,
            _ => return Err(format!("unsupported mutation strategy `{token}`").into()),
        };
        if !parsed.contains(&strategy) {
            parsed.push(strategy);
        }
    }
    if parsed.is_empty() {
        return Err("mutation strategy list must not be empty".into());
    }
    Ok(parsed)
}

fn parse_attack_scenarios(raw: &str) -> Result<Vec<PublicInputAttackScenario>, Box<dyn Error>> {
    let mut parsed = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let scenario = match token.to_ascii_lowercase().as_str() {
            "identity_swap" => PublicInputAttackScenario::IdentitySwap,
            "value_inflation" => PublicInputAttackScenario::ValueInflation,
            "merkle_root_swap" => PublicInputAttackScenario::MerkleRootSwap,
            _ => return Err(format!("unsupported attack scenario `{token}`").into()),
        };
        if !parsed.contains(&scenario) {
            parsed.push(scenario);
        }
    }
    if parsed.is_empty() {
        return Err("attack scenario list must not be empty".into());
    }
    Ok(parsed)
}

fn parse_verifier_profile(raw: &str) -> Result<PublicInputVerifierProfile, Box<dyn Error>> {
    match raw.to_ascii_lowercase().as_str() {
        "strict_binding" => Ok(PublicInputVerifierProfile::StrictBinding),
        "weak_first_input_binding" => Ok(PublicInputVerifierProfile::WeakFirstInputBinding),
        _ => Err(format!("unsupported verifier profile `{raw}`").into()),
    }
}

fn print_help() {
    println!(
        "\
run_public_input_manipulation_campaign

Generate valid proof/input pairs, mutate public inputs, and verify that
manipulated inputs are rejected.

Usage:
  cargo run -q -p zk-track-boundary --example run_public_input_manipulation_campaign -- [options]

Options:
  --output-json <path>             Output JSON report path
  --seed <u64>                     RNG seed (default: 13370)
  --proofs <n>                     Number of valid proofs to test (default: 1000)
  --public-inputs-per-proof <n>    Number of public inputs per proof (default: 3)
  --mutation-strategies <csv>      Strategy list (default: bit_flip,field_boundary,reordering,truncation,duplication,type_confusion)
  --attack-scenarios <csv>         Scenario list (default: identity_swap,value_inflation,merkle_root_swap)
  --verifier-profile <name>        strict_binding | weak_first_input_binding (default: strict_binding)
"
    );
}
