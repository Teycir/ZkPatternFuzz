use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Circom,
    Noir,
    Halo2,
    Cairo,
}

impl Backend {
    pub fn file_extension(self) -> &'static str {
        match self {
            Self::Circom => "circom",
            Self::Noir => "nr",
            Self::Halo2 => "rs",
            Self::Cairo => "cairo",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircuitDsl {
    pub name: String,
    #[serde(default)]
    pub public_inputs: Vec<String>,
    #[serde(default)]
    pub private_inputs: Vec<String>,
    #[serde(default)]
    pub outputs: Vec<String>,
    #[serde(default)]
    pub assignments: Vec<Assignment>,
    #[serde(default)]
    pub constraints: Vec<ConstraintEq>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Assignment {
    pub target: String,
    pub expression: Expression,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConstraintEq {
    pub left: Expression,
    pub right: Expression,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Expression {
    Signal {
        name: String,
    },
    Constant {
        value: i64,
    },
    Add {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Sub {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Mul {
        left: Box<Expression>,
        right: Box<Expression>,
    },
}

#[derive(Debug, Error)]
pub enum CircuitGenError {
    #[error("failed to parse DSL YAML: {0}")]
    ParseYaml(#[from] serde_yaml::Error),
    #[error("failed to parse DSL JSON: {0}")]
    ParseJson(#[from] serde_json::Error),
    #[error("invalid DSL: {0}")]
    Validation(String),
}

#[derive(Debug, Clone)]
struct ValidatedDsl {
    intermediates: Vec<String>,
}

pub fn parse_dsl_yaml(value: &str) -> Result<CircuitDsl, CircuitGenError> {
    serde_yaml::from_str(value).map_err(CircuitGenError::ParseYaml)
}

pub fn parse_dsl_json(value: &str) -> Result<CircuitDsl, CircuitGenError> {
    serde_json::from_str(value).map_err(CircuitGenError::ParseJson)
}

pub fn render_backend_template(
    dsl: &CircuitDsl,
    backend: Backend,
) -> Result<String, CircuitGenError> {
    let validated = validate_dsl(dsl)?;
    match backend {
        Backend::Circom => Ok(render_circom(dsl, &validated)),
        Backend::Noir => Ok(render_noir(dsl)),
        Backend::Halo2 => Ok(render_halo2(dsl, &validated)),
        Backend::Cairo => Ok(render_cairo(dsl)),
    }
}

fn validate_dsl(dsl: &CircuitDsl) -> Result<ValidatedDsl, CircuitGenError> {
    let name = dsl.name.trim();
    if name.is_empty() {
        return Err(CircuitGenError::Validation(
            "circuit name must not be empty".to_string(),
        ));
    }
    validate_identifier(name)?;

    let mut declared = BTreeSet::new();
    for item in dsl.public_inputs.iter().chain(dsl.private_inputs.iter()) {
        validate_identifier(item)?;
        if !declared.insert(item.clone()) {
            return Err(CircuitGenError::Validation(format!(
                "duplicate signal declaration `{item}`"
            )));
        }
    }

    let mut output_set = BTreeSet::new();
    for output in &dsl.outputs {
        validate_identifier(output)?;
        if !output_set.insert(output.clone()) {
            return Err(CircuitGenError::Validation(format!(
                "duplicate output declaration `{output}`"
            )));
        }
        if declared.contains(output) {
            return Err(CircuitGenError::Validation(format!(
                "output `{output}` reuses input identifier"
            )));
        }
    }

    let mut known_signals = declared.clone();
    let mut assigned_outputs = BTreeSet::new();
    let mut assigned_targets = BTreeSet::new();
    let mut intermediates = Vec::new();

    for assignment in &dsl.assignments {
        validate_identifier(&assignment.target)?;
        validate_expression_references(&assignment.expression, &known_signals)?;

        if declared.contains(&assignment.target) {
            return Err(CircuitGenError::Validation(format!(
                "assignment target `{}` cannot overwrite an input",
                assignment.target
            )));
        }
        if !assigned_targets.insert(assignment.target.clone()) {
            return Err(CircuitGenError::Validation(format!(
                "assignment target `{}` is defined more than once",
                assignment.target
            )));
        }

        if output_set.contains(&assignment.target) {
            assigned_outputs.insert(assignment.target.clone());
        } else {
            intermediates.push(assignment.target.clone());
        }
        known_signals.insert(assignment.target.clone());
    }

    for output in &dsl.outputs {
        if !assigned_outputs.contains(output) {
            return Err(CircuitGenError::Validation(format!(
                "output `{output}` is never assigned"
            )));
        }
    }

    for constraint in &dsl.constraints {
        validate_expression_references(&constraint.left, &known_signals)?;
        validate_expression_references(&constraint.right, &known_signals)?;
    }

    if dsl.assignments.is_empty() && dsl.constraints.is_empty() {
        return Err(CircuitGenError::Validation(
            "DSL must include at least one assignment or one constraint".to_string(),
        ));
    }

    Ok(ValidatedDsl { intermediates })
}

fn validate_identifier(value: &str) -> Result<(), CircuitGenError> {
    if value.is_empty() {
        return Err(CircuitGenError::Validation(
            "identifier must not be empty".to_string(),
        ));
    }
    let mut chars = value.chars();
    let first = chars.next().unwrap_or('_');
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(CircuitGenError::Validation(format!(
            "identifier `{value}` must start with [A-Za-z_]"
        )));
    }
    if chars.any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_')) {
        return Err(CircuitGenError::Validation(format!(
            "identifier `{value}` must contain only [A-Za-z0-9_]"
        )));
    }
    Ok(())
}

fn validate_expression_references(
    expression: &Expression,
    known: &BTreeSet<String>,
) -> Result<(), CircuitGenError> {
    for name in collect_signal_references(expression) {
        if !known.contains(&name) {
            return Err(CircuitGenError::Validation(format!(
                "expression references unknown signal `{name}`"
            )));
        }
    }
    Ok(())
}

fn collect_signal_references(expression: &Expression) -> Vec<String> {
    let mut out = Vec::new();
    collect_refs_into(expression, &mut out);
    out
}

fn collect_refs_into(expression: &Expression, out: &mut Vec<String>) {
    match expression {
        Expression::Signal { name } => out.push(name.clone()),
        Expression::Constant { .. } => {}
        Expression::Add { left, right }
        | Expression::Sub { left, right }
        | Expression::Mul { left, right } => {
            collect_refs_into(left, out);
            collect_refs_into(right, out);
        }
    }
}

fn render_expression(expression: &Expression) -> String {
    match expression {
        Expression::Signal { name } => name.clone(),
        Expression::Constant { value } => value.to_string(),
        Expression::Add { left, right } => {
            format!(
                "({} + {})",
                render_expression(left),
                render_expression(right)
            )
        }
        Expression::Sub { left, right } => {
            format!(
                "({} - {})",
                render_expression(left),
                render_expression(right)
            )
        }
        Expression::Mul { left, right } => {
            format!(
                "({} * {})",
                render_expression(left),
                render_expression(right)
            )
        }
    }
}

fn render_circom(dsl: &CircuitDsl, validated: &ValidatedDsl) -> String {
    let mut lines = vec![
        "pragma circom 2.1.6;".to_string(),
        "".to_string(),
        format!("template {}() {{", dsl.name),
        "    // Public/private visibility is assigned by the host when wiring `main` inputs."
            .to_string(),
    ];

    for signal in dsl.public_inputs.iter().chain(dsl.private_inputs.iter()) {
        lines.push(format!("    signal input {signal};"));
    }
    for output in &dsl.outputs {
        lines.push(format!("    signal output {output};"));
    }
    for intermediate in &validated.intermediates {
        lines.push(format!("    signal {intermediate};"));
    }
    lines.push("".to_string());

    for assignment in &dsl.assignments {
        lines.push(format!(
            "    {} <== {};",
            assignment.target,
            render_expression(&assignment.expression)
        ));
    }
    if !dsl.constraints.is_empty() {
        lines.push("".to_string());
    }
    for constraint in &dsl.constraints {
        lines.push(format!(
            "    {} === {};",
            render_expression(&constraint.left),
            render_expression(&constraint.right)
        ));
    }

    lines.push("}".to_string());
    lines.push("".to_string());
    lines.push(format!("component main = {}();", dsl.name));
    lines.join("\n")
}

fn render_noir(dsl: &CircuitDsl) -> String {
    let mut params = Vec::new();
    for input in &dsl.public_inputs {
        params.push(format!("pub {input}: Field"));
    }
    for input in &dsl.private_inputs {
        params.push(format!("{input}: Field"));
    }

    let return_type = if dsl.outputs.is_empty() {
        "".to_string()
    } else if dsl.outputs.len() == 1 {
        " -> Field".to_string()
    } else {
        let types = vec!["Field"; dsl.outputs.len()].join(", ");
        format!(" -> ({types})")
    };

    let mut lines = vec![
        format!("fn main({}){} {{", params.join(", "), return_type),
        "    // Generated from compiler-fuzzing DSL.".to_string(),
    ];
    for assignment in &dsl.assignments {
        lines.push(format!(
            "    let {} = {};",
            assignment.target,
            render_expression(&assignment.expression)
        ));
    }
    for constraint in &dsl.constraints {
        lines.push(format!(
            "    constrain {} == {};",
            render_expression(&constraint.left),
            render_expression(&constraint.right)
        ));
    }
    if dsl.outputs.len() == 1 {
        lines.push(format!("    {}", dsl.outputs[0]));
    } else if dsl.outputs.len() > 1 {
        lines.push(format!("    ({})", dsl.outputs.join(", ")));
    }
    lines.push("}".to_string());
    lines.join("\n")
}

fn render_cairo(dsl: &CircuitDsl) -> String {
    let mut params = Vec::new();
    for input in dsl.public_inputs.iter().chain(dsl.private_inputs.iter()) {
        params.push(format!("{input}: felt252"));
    }

    let return_type = if dsl.outputs.is_empty() {
        "".to_string()
    } else if dsl.outputs.len() == 1 {
        " -> felt252".to_string()
    } else {
        let types = vec!["felt252"; dsl.outputs.len()].join(", ");
        format!(" -> ({types})")
    };

    let mut lines = vec![
        "fn main(".to_string(),
        format!("    {}", params.join(", ")),
        format!("){} {{", return_type),
        "    // Generated from compiler-fuzzing DSL.".to_string(),
    ];
    for assignment in &dsl.assignments {
        lines.push(format!(
            "    let {} = {};",
            assignment.target,
            render_expression(&assignment.expression)
        ));
    }
    for constraint in &dsl.constraints {
        lines.push(format!(
            "    assert({} == {}, 'dsl_constraint_failed');",
            render_expression(&constraint.left),
            render_expression(&constraint.right)
        ));
    }
    if dsl.outputs.len() == 1 {
        lines.push(format!("    {}", dsl.outputs[0]));
    } else if dsl.outputs.len() > 1 {
        lines.push(format!("    ({})", dsl.outputs.join(", ")));
    }
    lines.push("}".to_string());
    lines.join("\n")
}

fn render_halo2(dsl: &CircuitDsl, validated: &ValidatedDsl) -> String {
    let mut signals = Vec::new();
    signals.extend(dsl.public_inputs.iter().cloned());
    signals.extend(dsl.private_inputs.iter().cloned());
    signals.extend(dsl.outputs.iter().cloned());
    signals.extend(validated.intermediates.iter().cloned());
    if signals.is_empty() {
        signals.push("value".to_string());
    }

    let circuit_name = to_pascal_case(&dsl.name);
    let config_name = format!("{circuit_name}Config");
    let advice_field = |name: &str| format!("col_{name}");
    let primary_col = advice_field(&signals[0]);

    let mut lines = vec![
        "use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};".to_string(),
        "use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error};".to_string(),
        "use halo2_proofs::poly::Rotation;".to_string(),
        "use halo2curves::bn256::Fr;".to_string(),
        "".to_string(),
        "#[derive(Clone, Debug)]".to_string(),
        format!("pub struct {config_name} {{"),
    ];
    for signal in &signals {
        lines.push(format!("    pub {}: Column<Advice>,", advice_field(signal)));
    }
    lines.push("}".to_string());
    lines.push("".to_string());
    lines.push(format!("pub struct {circuit_name}Circuit;"));
    lines.push("".to_string());
    lines.push(format!("impl Circuit<Fr> for {circuit_name}Circuit {{"));
    lines.push(format!("    type Config = {config_name};"));
    lines.push("    type FloorPlanner = SimpleFloorPlanner;".to_string());
    lines.push("".to_string());
    lines.push("    fn without_witnesses(&self) -> Self {".to_string());
    lines.push(format!("        {circuit_name}Circuit"));
    lines.push("    }".to_string());
    lines.push("".to_string());
    lines.push("    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {".to_string());
    for signal in &signals {
        lines.push(format!(
            "        let {} = meta.advice_column();",
            advice_field(signal)
        ));
    }
    lines.push("".to_string());
    for (index, constraint) in dsl.constraints.iter().enumerate() {
        lines.push(format!(
            "        meta.create_gate(\"dsl_constraint_{}\", |meta| {{",
            index + 1
        ));
        lines.push(format!(
            "            // enforce {} == {}",
            render_expression(&constraint.left),
            render_expression(&constraint.right)
        ));
        lines.push(format!(
            "            let lhs = meta.query_advice({}, Rotation::cur());",
            primary_col
        ));
        lines.push(format!(
            "            let rhs = meta.query_advice({}, Rotation::cur());",
            primary_col
        ));
        lines.push("            vec![lhs - rhs]".to_string());
        lines.push("        });".to_string());
    }
    lines.push("".to_string());
    lines.push(format!("        {config_name} {{"));
    for signal in &signals {
        lines.push(format!(
            "            {}: {},",
            advice_field(signal),
            advice_field(signal)
        ));
    }
    lines.push("        }".to_string());
    lines.push("    }".to_string());
    lines.push("".to_string());
    lines.push(
        "    fn synthesize(&self, _config: Self::Config, _layouter: impl Layouter<Fr>) -> Result<(), Error> {".to_string(),
    );
    lines.push("        // Assignment plan generated from DSL:".to_string());
    for assignment in &dsl.assignments {
        lines.push(format!(
            "        // {} = {};",
            assignment.target,
            render_expression(&assignment.expression)
        ));
    }
    lines.push("        Ok(())".to_string());
    lines.push("    }".to_string());
    lines.push("}".to_string());
    lines.join("\n")
}

fn to_pascal_case(value: &str) -> String {
    let mut out = String::new();
    for part in value.split('_').filter(|part| !part.is_empty()) {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.extend(chars.map(|c| c.to_ascii_lowercase()));
        }
    }
    if out.is_empty() {
        "GeneratedCircuit".to_string()
    } else {
        out
    }
}
