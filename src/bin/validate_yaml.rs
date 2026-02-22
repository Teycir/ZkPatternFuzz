use clap::Parser;
use zk_core::{validate_invariant_against_inputs, InvariantValidationError};
use zk_fuzzer::config::FuzzConfig;
use zk_fuzzer::cve::CveDatabase;

#[derive(Parser, Debug)]
#[command(name = "validate_yaml")]
#[command(about = "Validate YAML for evidence-ready fuzzing")]
struct Args {
    /// Path to campaign YAML
    campaign: String,

    /// Require v2 invariants (evidence mode)
    #[arg(long, default_value_t = true)]
    require_invariants: bool,

    /// Optional CVE database YAML to validate with strict fixture rules
    #[arg(long)]
    cve_db: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = FuzzConfig::from_yaml(&args.campaign)?;

    let mut errors: Vec<String> = Vec::new();

    if config.inputs.is_empty() {
        errors.push("No inputs defined in YAML".to_string());
    }

    let input_names: Vec<String> = config
        .inputs
        .iter()
        .map(|i| i.name.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if input_names.is_empty() {
        errors.push("Input labels are missing or empty".to_string());
    }

    if args.require_invariants {
        let invariants = config.get_invariants();
        if invariants.is_empty() {
            errors.push("Missing invariants: evidence mode requires v2 `invariants`".to_string());
        } else {
            for inv in invariants {
                match validate_invariant_against_inputs(&inv.name, &inv.relation, &input_names) {
                    Ok(_) => {}
                    Err(InvariantValidationError::EmptyInvariantName) => {
                        errors.push("Invariant name is empty".to_string());
                    }
                    Err(InvariantValidationError::EmptyRelation) => {
                        errors.push(format!("Invariant '{}' has empty relation", inv.name));
                    }
                    Err(InvariantValidationError::NoKnownInputReference { .. })
                    | Err(InvariantValidationError::RawRelationExpression(_)) => {
                        errors.push(format!(
                            "Invariant '{}' does not reference any known input label (labels: {:?})",
                            inv.name, input_names
                        ));
                    }
                    Err(InvariantValidationError::InvalidRelation(err)) => {
                        errors.push(format!(
                            "Invariant '{}' has invalid relation: {}",
                            inv.name, err
                        ));
                    }
                }
            }
        }
    }

    if !errors.is_empty() {
        eprintln!("YAML validation failed:");
        for err in errors {
            eprintln!("  - {}", err);
        }
        std::process::exit(1);
    }

    if let Some(path) = &args.cve_db {
        CveDatabase::load_strict(path).map_err(|e| {
            anyhow::anyhow!(
                "Strict CVE fixture validation failed for '{}': {:#}",
                path,
                e
            )
        })?;
        println!("✓ CVE fixtures validated successfully (strict, unambiguous)");
    }

    println!("✓ YAML validated successfully (evidence-ready)");
    Ok(())
}
