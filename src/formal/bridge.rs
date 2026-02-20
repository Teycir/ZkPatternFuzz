//! Formal verification bridge artifacts for fuzzing campaigns.
//!
//! This module closes the loop between fuzzing and formal methods by:
//! - exporting fuzz findings in a formal-tool-friendly JSON shape,
//! - importing externally maintained formal invariants into runtime fuzz invariants,
//! - generating proof-obligation skeletons (Lean/Coq) from imported invariants.

use super::{
    CircuitProperty, CoqExporter, LeanExporter, ProofExporter, ProofObligation, ProofSystem,
    PropertyType,
};
use crate::analysis::symbolic::{SymbolicConstraint, SymbolicValue};
use crate::config::v2::{parse_invariant_relation, Invariant, InvariantAST, InvariantType};
use crate::config::{AdditionalConfig, FuzzConfig, Oracle, Severity};
use crate::reporting::FuzzReport;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const DEFAULT_FIELD_MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// Runtime controls for formal bridge generation.
#[derive(Debug, Clone)]
pub struct FormalBridgeOptions {
    /// Enable bridge artifact generation after each campaign run.
    pub enabled: bool,
    /// Target proof system for generated obligations.
    pub system: ProofSystem,
    /// Upper bound for generated invariant obligations.
    pub max_obligations: usize,
}

impl Default for FormalBridgeOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            system: ProofSystem::Lean4,
            max_obligations: 128,
        }
    }
}

impl FormalBridgeOptions {
    pub fn from_additional(additional: &AdditionalConfig) -> Self {
        let enabled = additional
            .get("formal_bridge_enabled")
            .and_then(value_as_bool)
            .unwrap_or(true);
        let system = additional
            .get("formal_bridge_system")
            .and_then(value_as_str)
            .as_deref()
            .map(parse_proof_system)
            .unwrap_or(ProofSystem::Lean4);
        let max_obligations = additional
            .get("formal_bridge_max_obligations")
            .and_then(value_as_usize)
            .unwrap_or(128);
        Self {
            enabled,
            system,
            max_obligations: max_obligations.max(1),
        }
    }
}

/// Paths for generated formal bridge artifacts.
#[derive(Debug, Clone)]
pub struct FormalBridgeArtifacts {
    pub findings_export_path: PathBuf,
    pub imported_oracles_path: PathBuf,
    pub proof_module_path: PathBuf,
    pub workflow_path: PathBuf,
    pub obligations_count: usize,
}

#[derive(Debug, Deserialize)]
struct FormalInvariantDocument {
    #[serde(default)]
    invariants: Vec<Invariant>,
}

#[derive(Debug, Serialize)]
struct FormalFindingRecord {
    id: usize,
    attack_type: String,
    severity: String,
    class: String,
    description: String,
    location: Option<String>,
}

#[derive(Debug, Serialize)]
struct FormalFindingExport {
    schema_version: &'static str,
    campaign_name: String,
    timestamp: String,
    total_findings: usize,
    findings: Vec<FormalFindingRecord>,
}

#[derive(Debug, Serialize)]
struct ImportedOracleRecord {
    name: String,
    relation: String,
    severity: String,
    invariant_type: String,
}

#[derive(Debug, Serialize)]
struct ImportedOraclesExport {
    schema_version: &'static str,
    imported_oracles: Vec<ImportedOracleRecord>,
}

/// Import formal invariants from `campaign.parameters.formal_invariants_file` and merge them into
/// runtime v2 invariants/oracles so fuzzing uses them immediately.
pub fn import_formal_invariants_from_file(
    config: &mut FuzzConfig,
    config_path: &str,
) -> Result<usize> {
    let Some(raw_path) = config
        .campaign
        .parameters
        .additional
        .get("formal_invariants_file")
        .and_then(value_as_str)
    else {
        return Ok(0);
    };
    if raw_path.trim().is_empty() {
        return Ok(0);
    }

    let resolved_path = resolve_path(&raw_path, config_path);
    let imported = load_formal_invariants(&resolved_path)?;
    if imported.is_empty() {
        return Ok(0);
    }

    let mut existing = config.get_invariants();
    let mut existing_names: HashSet<String> =
        existing.iter().map(|inv| inv.name.to_lowercase()).collect();
    let mut newly_imported = Vec::new();

    for invariant in imported {
        if existing_names.insert(invariant.name.to_lowercase()) {
            existing.push(invariant.clone());
            newly_imported.push(invariant);
        }
    }

    if newly_imported.is_empty() {
        return Ok(0);
    }

    config.campaign.parameters.additional.insert(
        "v2_invariants".to_string(),
        serde_yaml::to_value(&existing)?,
    );
    merge_invariants_as_oracles(config, &newly_imported);

    Ok(newly_imported.len())
}

/// Export fuzz findings + imported invariant obligations for formal verification workflow.
pub fn export_formal_bridge_artifacts(
    output_dir: &Path,
    campaign_name: &str,
    report: &FuzzReport,
    invariants: &[Invariant],
    options: &FormalBridgeOptions,
) -> Result<FormalBridgeArtifacts> {
    let bridge_dir = output_dir.join("formal_bridge");
    std::fs::create_dir_all(&bridge_dir)?;

    let findings = report
        .findings
        .iter()
        .enumerate()
        .map(|(i, finding)| FormalFindingRecord {
            id: i,
            attack_type: format!("{:?}", finding.attack_type),
            severity: finding.severity.to_string(),
            class: finding.classify().to_string(),
            description: finding.description.clone(),
            location: finding.location.clone(),
        })
        .collect::<Vec<_>>();

    let findings_doc = FormalFindingExport {
        schema_version: "1.0",
        campaign_name: campaign_name.to_string(),
        timestamp: report.timestamp.to_rfc3339(),
        total_findings: findings.len(),
        findings,
    };

    let findings_export_path = bridge_dir.join("fuzz_findings.json");
    let findings_json = serde_json::to_string_pretty(&findings_doc)?;
    crate::util::write_file_atomic(&findings_export_path, findings_json.as_bytes())?;

    let imported_oracles = ImportedOraclesExport {
        schema_version: "1.0",
        imported_oracles: invariants
            .iter()
            .map(|inv| ImportedOracleRecord {
                name: inv.name.clone(),
                relation: inv.relation.clone(),
                severity: inv.severity.clone().unwrap_or_else(|| "medium".to_string()),
                invariant_type: format!("{:?}", inv.invariant_type),
            })
            .collect(),
    };
    let imported_oracles_path = bridge_dir.join("imported_invariants.yaml");
    let imported_yaml = serde_yaml::to_string(&imported_oracles)?;
    crate::util::write_file_atomic(&imported_oracles_path, imported_yaml.as_bytes())?;

    let obligations = build_obligations(invariants, options.max_obligations);
    let module_result = export_obligations_module(options.system, &obligations);
    let proof_module_path = bridge_dir.join(format!("FuzzBridge.{}", module_result.extension));
    crate::util::write_file_atomic(&proof_module_path, module_result.code.as_bytes())?;

    let workflow_path = bridge_dir.join("hybrid_workflow.md");
    let workflow = render_hybrid_workflow(
        campaign_name,
        report.findings.len(),
        invariants.len(),
        obligations.len(),
        options.system,
        &findings_export_path,
        &imported_oracles_path,
        &proof_module_path,
    );
    crate::util::write_file_atomic(&workflow_path, workflow.as_bytes())?;

    Ok(FormalBridgeArtifacts {
        findings_export_path,
        imported_oracles_path,
        proof_module_path,
        workflow_path,
        obligations_count: obligations.len(),
    })
}

fn load_formal_invariants(path: &Path) -> Result<Vec<Invariant>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read formal invariants file '{}'", path.display()))?;
    let parsed_value: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("failed to parse YAML '{}'", path.display()))?;

    if parsed_value.is_sequence() {
        let list: Vec<Invariant> = serde_yaml::from_value(parsed_value)?;
        return Ok(list);
    }

    let doc: FormalInvariantDocument = serde_yaml::from_str(&raw)?;
    Ok(doc.invariants)
}

fn resolve_path(raw_path: &str, config_path: &str) -> PathBuf {
    let path = PathBuf::from(raw_path);
    if path.is_absolute() {
        return path;
    }
    let config_dir = Path::new(config_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    config_dir.join(path)
}

fn merge_invariants_as_oracles(config: &mut FuzzConfig, invariants: &[Invariant]) {
    let mut existing_oracles: HashSet<String> = config
        .oracles
        .iter()
        .map(|o| o.name.to_lowercase())
        .collect();

    for invariant in invariants {
        let oracle_name = format!("formal_invariant::{}", sanitize_identifier(&invariant.name));
        if !existing_oracles.insert(oracle_name.to_lowercase()) {
            continue;
        }
        config.oracles.push(Oracle {
            name: oracle_name,
            severity: parse_severity(invariant.severity.as_deref()),
            description: format!("Imported formal invariant oracle: {}", invariant.relation),
        });
    }
}

fn parse_severity(input: Option<&str>) -> Severity {
    match input.unwrap_or("medium").trim().to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Medium,
    }
}

fn build_obligations(invariants: &[Invariant], max_obligations: usize) -> Vec<ProofObligation> {
    let mut obligations = Vec::new();

    for (idx, invariant) in invariants.iter().take(max_obligations).enumerate() {
        let post = relation_to_symbolic_constraint(&invariant.relation);
        let variables = extract_identifiers(&invariant.relation);
        obligations.push(ProofObligation {
            name: format!("invariant_{}", sanitize_identifier(&invariant.name)),
            description: format!("Imported fuzz invariant: {}", invariant.relation),
            property: CircuitProperty::ConstraintSatisfied {
                constraint_id: idx,
                description: invariant.relation.clone(),
            },
            property_type: map_property_type(&invariant.invariant_type),
            constraints: Vec::new(),
            variables,
            preconditions: Vec::new(),
            postconditions: vec![post],
        });
    }

    obligations
}

fn map_property_type(invariant_type: &InvariantType) -> PropertyType {
    match invariant_type {
        InvariantType::Uniqueness => PropertyType::Soundness,
        InvariantType::Metamorphic => PropertyType::Completeness,
        InvariantType::Range => PropertyType::Safety,
        InvariantType::Constraint | InvariantType::Custom => PropertyType::Safety,
    }
}

fn export_obligations_module(
    system: ProofSystem,
    obligations: &[ProofObligation],
) -> super::ProofResult {
    match system {
        ProofSystem::Lean4 => {
            let exporter = LeanExporter::new(DEFAULT_FIELD_MODULUS);
            exporter.export_module("FuzzBridge", obligations)
        }
        ProofSystem::Coq => {
            let exporter = CoqExporter::new(DEFAULT_FIELD_MODULUS);
            exporter.export_module("FuzzBridge", obligations)
        }
    }
}

fn relation_to_symbolic_constraint(relation: &str) -> SymbolicConstraint {
    let Ok(ast) = parse_invariant_relation(relation) else {
        return SymbolicConstraint::True;
    };
    ast_to_constraint(&ast).unwrap_or(SymbolicConstraint::True)
}

fn ast_to_constraint(ast: &InvariantAST) -> Option<SymbolicConstraint> {
    match ast {
        InvariantAST::Equals(left, right) => Some(SymbolicConstraint::Eq(
            ast_to_value(left),
            ast_to_value(right),
        )),
        InvariantAST::NotEquals(left, right) => Some(SymbolicConstraint::Neq(
            ast_to_value(left),
            ast_to_value(right),
        )),
        InvariantAST::LessThan(left, right) => Some(SymbolicConstraint::Lt(
            ast_to_value(left),
            ast_to_value(right),
        )),
        InvariantAST::LessThanOrEqual(left, right) => Some(SymbolicConstraint::Lte(
            ast_to_value(left),
            ast_to_value(right),
        )),
        InvariantAST::GreaterThan(left, right) => Some(SymbolicConstraint::Lt(
            ast_to_value(right),
            ast_to_value(left),
        )),
        InvariantAST::GreaterThanOrEqual(left, right) => Some(SymbolicConstraint::Lte(
            ast_to_value(right),
            ast_to_value(left),
        )),
        InvariantAST::Range {
            lower,
            value,
            upper,
            inclusive_lower,
            inclusive_upper,
        } => {
            let lower_check = if *inclusive_lower {
                SymbolicConstraint::Lte(ast_to_value(lower), ast_to_value(value))
            } else {
                SymbolicConstraint::Lt(ast_to_value(lower), ast_to_value(value))
            };
            let upper_check = if *inclusive_upper {
                SymbolicConstraint::Lte(ast_to_value(value), ast_to_value(upper))
            } else {
                SymbolicConstraint::Lt(ast_to_value(value), ast_to_value(upper))
            };
            Some(SymbolicConstraint::And(
                Box::new(lower_check),
                Box::new(upper_check),
            ))
        }
        _ => None,
    }
}

fn ast_to_value(ast: &InvariantAST) -> SymbolicValue {
    match ast {
        InvariantAST::Identifier(name) => SymbolicValue::symbol(&sanitize_identifier(name)),
        InvariantAST::Literal(value) => parse_literal_value(value),
        InvariantAST::Power(base, exponent) => {
            if let (Ok(base_u), Ok(exp_u)) = (base.parse::<u64>(), exponent.parse::<u32>()) {
                if exp_u <= 63 {
                    if let Some(pow) = base_u.checked_pow(exp_u) {
                        return SymbolicValue::concrete(zk_core::FieldElement::from_u64(pow));
                    }
                }
            }
            SymbolicValue::symbol(&sanitize_identifier(&format!("pow_{}_{}", base, exponent)))
        }
        InvariantAST::ArrayAccess(name, index) => {
            SymbolicValue::symbol(&sanitize_identifier(&format!("{}_{}", name, index)))
        }
        InvariantAST::Call(name, args) => {
            let joined_args = args.join("_");
            SymbolicValue::symbol(&sanitize_identifier(&format!("{}_{}", name, joined_args)))
        }
        _ => SymbolicValue::symbol("unsupported_relation_term"),
    }
}

fn parse_literal_value(raw: &str) -> SymbolicValue {
    let trimmed = raw.trim();
    if let Ok(num) = trimmed.parse::<u64>() {
        return SymbolicValue::concrete(zk_core::FieldElement::from_u64(num));
    }
    if let Ok(hex) = zk_core::FieldElement::from_hex(trimmed) {
        return SymbolicValue::concrete(hex);
    }
    SymbolicValue::symbol(&sanitize_identifier(trimmed))
}

fn extract_identifiers(relation: &str) -> Vec<String> {
    let mut vars = HashSet::new();
    let mut current = String::new();

    for ch in relation.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            current.push(ch);
        } else if !current.is_empty() {
            maybe_push_identifier(&mut vars, &current);
            current.clear();
        }
    }
    if !current.is_empty() {
        maybe_push_identifier(&mut vars, &current);
    }

    let mut out: Vec<String> = vars.into_iter().collect();
    out.sort_unstable();
    out
}

fn maybe_push_identifier(vars: &mut HashSet<String>, token: &str) {
    let lower = token.to_lowercase();
    if token.chars().all(|c| c.is_ascii_digit()) {
        return;
    }
    if matches!(lower.as_str(), "forall" | "true" | "false") {
        return;
    }
    vars.insert(sanitize_identifier(token));
}

fn sanitize_identifier(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        "unnamed".to_string()
    } else if out
        .chars()
        .next()
        .map(|ch| ch.is_ascii_digit())
        .unwrap_or(false)
    {
        format!("v_{}", out)
    } else {
        out
    }
}

fn parse_proof_system(raw: &str) -> ProofSystem {
    match raw.trim().to_lowercase().as_str() {
        "coq" => ProofSystem::Coq,
        _ => ProofSystem::Lean4,
    }
}

fn value_as_bool(value: &serde_yaml::Value) -> Option<bool> {
    match value {
        serde_yaml::Value::Bool(v) => Some(*v),
        serde_yaml::Value::String(s) => match s.trim().to_lowercase().as_str() {
            "true" | "yes" | "1" => Some(true),
            "false" | "no" | "0" => Some(false),
            _ => None,
        },
        serde_yaml::Value::Number(n) => n.as_i64().map(|v| v != 0),
        _ => None,
    }
}

fn value_as_str(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn value_as_usize(value: &serde_yaml::Value) -> Option<usize> {
    match value {
        serde_yaml::Value::Number(n) => n.as_u64().map(|v| v as usize),
        serde_yaml::Value::String(s) => s.trim().parse::<usize>().ok(),
        _ => None,
    }
}

fn render_hybrid_workflow(
    campaign_name: &str,
    finding_count: usize,
    invariant_count: usize,
    obligations_count: usize,
    system: ProofSystem,
    findings_export_path: &Path,
    imported_oracles_path: &Path,
    proof_module_path: &Path,
) -> String {
    let system_label = match system {
        ProofSystem::Lean4 => "Lean4",
        ProofSystem::Coq => "Coq",
    };

    format!(
        "# Hybrid Fuzzing + Proof Workflow\n\n\
Campaign: `{campaign_name}`\n\n\
## Generated Inputs for Formal Review\n\
- Findings exported: `{finding_count}`\n\
- Imported invariants: `{invariant_count}`\n\
- Proof obligations generated: `{obligations_count}`\n\n\
## Artifacts\n\
- Findings export: `{}`\n\
- Imported invariants as fuzzing oracles: `{}`\n\
- {system_label} obligations module: `{}`\n\n\
## Suggested Flow\n\
1. Reproduce high-severity findings from `fuzz_findings.json`.\n\
2. Review imported invariants in `imported_invariants.yaml` and tighten relations.\n\
3. Discharge obligations in `FuzzBridge.*` within {system_label}.\n\
4. Feed proven/failed obligations back into campaign invariants for the next fuzz run.\n",
        findings_export_path.display(),
        imported_oracles_path.display(),
        proof_module_path.display(),
    )
}

#[cfg(test)]
#[path = "bridge_tests.rs"]
mod tests;
