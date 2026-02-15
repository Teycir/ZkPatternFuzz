use clap::Parser;
use zk_fuzzer::config::v2::{parse_invariant_relation, InvariantAST};
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
                if inv.name.trim().is_empty() {
                    errors.push("Invariant name is empty".to_string());
                }
                if inv.relation.trim().is_empty() {
                    errors.push(format!("Invariant '{}' has empty relation", inv.name));
                    continue;
                }

                let identifiers = extract_identifiers(&inv.relation);
                let has_input_ref = identifiers
                    .iter()
                    .any(|id| input_names.iter().any(|n| n.eq_ignore_ascii_case(id)));

                if !has_input_ref {
                    errors.push(format!(
                        "Invariant '{}' does not reference any known input label (labels: {:?})",
                        inv.name, input_names
                    ));
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
        CveDatabase::load_strict(path)
            .map_err(|e| anyhow::anyhow!("Strict CVE fixture validation failed for '{}': {:#}", path, e))?;
        println!("✓ CVE fixtures validated successfully (strict, unambiguous)");
    }

    println!("✓ YAML validated successfully (evidence-ready)");
    Ok(())
}

fn extract_identifiers(relation: &str) -> Vec<String> {
    if let Ok(ast) = parse_invariant_relation(relation) {
        if !matches!(ast, InvariantAST::Raw(_)) {
            let mut out = Vec::new();
            collect_identifiers(&ast, &mut out);
            out.sort();
            out.dedup();
            return out;
        }
    }

    // Fallback: token scan
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in relation.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(current.clone());
            current.clear();
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn collect_identifiers(ast: &InvariantAST, out: &mut Vec<String>) {
    match ast {
        InvariantAST::Identifier(name) => out.push(name.clone()),
        InvariantAST::ArrayAccess(name, _) => out.push(name.clone()),
        InvariantAST::Call(_, args) => {
            for arg in args {
                out.push(arg.clone());
            }
        }
        InvariantAST::Equals(a, b)
        | InvariantAST::NotEquals(a, b)
        | InvariantAST::LessThan(a, b)
        | InvariantAST::LessThanOrEqual(a, b)
        | InvariantAST::GreaterThan(a, b)
        | InvariantAST::GreaterThanOrEqual(a, b)
        | InvariantAST::InSet(a, b) => {
            collect_identifiers(a, out);
            collect_identifiers(b, out);
        }
        InvariantAST::Range {
            lower,
            value,
            upper,
            ..
        } => {
            collect_identifiers(lower, out);
            collect_identifiers(value, out);
            collect_identifiers(upper, out);
        }
        InvariantAST::ForAll { expr, .. } => collect_identifiers(expr, out),
        InvariantAST::Set(values) => {
            for v in values {
                collect_identifiers(v, out);
            }
        }
        InvariantAST::Power(base, exp) => {
            out.push(base.clone());
            out.push(exp.clone());
        }
        InvariantAST::Literal(_) | InvariantAST::Raw(_) => {}
    }
}
