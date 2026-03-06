use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

use crate::FieldElement;

/// AST for invariant expressions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvariantAST {
    Identifier(String),
    Literal(String),
    Call(String, Vec<String>),
    ArrayAccess(String, String),
    Power(String, String),
    Set(Vec<InvariantAST>),
    Equals(Box<InvariantAST>, Box<InvariantAST>),
    NotEquals(Box<InvariantAST>, Box<InvariantAST>),
    LessThan(Box<InvariantAST>, Box<InvariantAST>),
    LessThanOrEqual(Box<InvariantAST>, Box<InvariantAST>),
    GreaterThan(Box<InvariantAST>, Box<InvariantAST>),
    GreaterThanOrEqual(Box<InvariantAST>, Box<InvariantAST>),
    InSet(Box<InvariantAST>, Box<InvariantAST>),
    Range {
        lower: Box<InvariantAST>,
        value: Box<InvariantAST>,
        upper: Box<InvariantAST>,
        inclusive_lower: bool,
        inclusive_upper: bool,
    },
    ForAll {
        binder: String,
        expr: Box<InvariantAST>,
    },
    Raw(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvariantParseError {
    EmptyRelation,
    EmptyExpression,
}

impl fmt::Display for InvariantParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRelation => write!(f, "relation is empty"),
            Self::EmptyExpression => write!(f, "relation contains an empty expression"),
        }
    }
}

impl Error for InvariantParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvariantValidationError {
    EmptyInvariantName,
    EmptyRelation,
    InvalidRelation(InvariantParseError),
    RawRelationExpression(String),
    NoKnownInputReference {
        relation: String,
        known_inputs: Vec<String>,
    },
}

impl fmt::Display for InvariantValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInvariantName => write!(f, "invariant name is empty"),
            Self::EmptyRelation => write!(f, "invariant relation is empty"),
            Self::InvalidRelation(err) => write!(f, "invalid invariant relation: {err}"),
            Self::RawRelationExpression(relation) => write!(
                f,
                "relation '{relation}' could not be parsed into supported invariant DSL"
            ),
            Self::NoKnownInputReference {
                relation,
                known_inputs,
            } => write!(
                f,
                "relation '{relation}' does not reference known inputs: {:?}",
                known_inputs
            ),
        }
    }
}

impl Error for InvariantValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvariantValidationResult {
    pub ast: InvariantAST,
    pub identifiers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticInvariantKind {
    Constraint,
    Range,
    Uniqueness,
    Metamorphic,
    Custom,
}

#[derive(Debug, Clone)]
pub struct SemanticInvariantSpec {
    pub name: String,
    pub relation: String,
    pub severity: String,
    pub kind: SemanticInvariantKind,
    pub ast: Option<InvariantAST>,
    pub input_indices: Vec<usize>,
    pub range_bounds: Option<(FieldElement, FieldElement, bool)>,
    pub uniqueness_key_indices: Vec<usize>,
    pub uniqueness_value_indices: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct WitnessProofPair {
    pub witness: Vec<FieldElement>,
    pub outputs: Vec<FieldElement>,
    pub proof: Option<Vec<u8>>,
    pub circuit_accepted: bool,
}

#[derive(Debug, Clone)]
pub struct SemanticViolation {
    pub invariant_name: String,
    pub relation: String,
    pub witness: Vec<FieldElement>,
    pub outputs: Vec<FieldElement>,
    pub severity: String,
    pub evidence: String,
    pub circuit_accepted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SemanticOracleEngine {
    input_map: HashMap<String, (usize, usize)>,
    uniqueness_tracker: HashMap<String, HashSet<Vec<u8>>>,
}

/// Parse invariant relation expressions.
///
/// Supported operators:
/// - equality/ordering: `==`, `!=`, `<`, `<=`, `>`, `>=`
/// - membership: `a in {0,1}` and `a ∈ {0,1}`
/// - range chains: `0 <= value < 2^64`
/// - quantifier prefix: `forall i: expr` and `∀i: expr`
pub fn parse_invariant_relation(relation: &str) -> Result<InvariantAST, InvariantParseError> {
    let relation = relation.trim();
    if relation.is_empty() {
        return Err(InvariantParseError::EmptyRelation);
    }

    if relation.starts_with('∀') || relation.to_lowercase().starts_with("forall") {
        let trimmed = relation.trim_start_matches('∀').trim();
        let trimmed = match trimmed.strip_prefix("forall") {
            Some(value) => value,
            None => trimmed,
        }
        .trim();
        if let Some((binder, body)) = trimmed.split_once(':') {
            let expr = parse_invariant_relation(body.trim())?;
            return Ok(InvariantAST::ForAll {
                binder: binder.trim().to_string(),
                expr: Box::new(expr),
            });
        }
    }

    if let Some(range_ast) = parse_range_chain(relation)? {
        return Ok(range_ast);
    }

    if let Some((left, right)) = split_in_set(relation) {
        let element = parse_expr(left.trim())?;
        let set = parse_set(right.trim())?;
        return Ok(InvariantAST::InSet(Box::new(element), Box::new(set)));
    }

    if let Some(ast) = parse_binary_op(relation, "==", InvariantAST::Equals)? {
        return Ok(ast);
    }

    if let Some(ast) = parse_binary_op(relation, "!=", InvariantAST::NotEquals)? {
        return Ok(ast);
    }

    if let Some(ast) = parse_binary_op(relation, "<=", InvariantAST::LessThanOrEqual)? {
        return Ok(ast);
    }

    if let Some(ast) = parse_binary_op(relation, ">=", InvariantAST::GreaterThanOrEqual)? {
        return Ok(ast);
    }

    if let Some(ast) = parse_binary_op(relation, "<", InvariantAST::LessThan)? {
        return Ok(ast);
    }

    if let Some(ast) = parse_binary_op(relation, ">", InvariantAST::GreaterThan)? {
        return Ok(ast);
    }

    Ok(InvariantAST::Raw(relation.to_string()))
}

fn parse_expr(expr: &str) -> Result<InvariantAST, InvariantParseError> {
    let expr = expr.trim();
    if expr.is_empty() {
        return Err(InvariantParseError::EmptyExpression);
    }

    if expr.starts_with('{') && expr.ends_with('}') {
        return parse_set(expr);
    }

    if let Some(paren_idx) = expr.find('(') {
        if expr.ends_with(')') {
            let name = &expr[..paren_idx];
            let args = &expr[paren_idx + 1..expr.len() - 1];
            return Ok(InvariantAST::Call(
                name.to_string(),
                args.split(',').map(|s| s.trim().to_string()).collect(),
            ));
        }
    }

    if let Some(bracket_idx) = expr.find('[') {
        if expr.ends_with(']') {
            let name = &expr[..bracket_idx];
            let index = &expr[bracket_idx + 1..expr.len() - 1];
            return Ok(InvariantAST::ArrayAccess(
                name.to_string(),
                index.to_string(),
            ));
        }
    }

    if expr.contains('^') {
        let parts: Vec<&str> = expr.splitn(2, '^').collect();
        if parts.len() == 2 {
            return Ok(InvariantAST::Power(
                parts[0].trim().to_string(),
                parts[1].trim().to_string(),
            ));
        }
    }

    if is_literal(expr) {
        return Ok(InvariantAST::Literal(expr.to_string()));
    }

    Ok(InvariantAST::Identifier(expr.to_string()))
}

fn parse_binary_op<F>(
    relation: &str,
    op: &str,
    make: F,
) -> Result<Option<InvariantAST>, InvariantParseError>
where
    F: Fn(Box<InvariantAST>, Box<InvariantAST>) -> InvariantAST,
{
    if relation.contains(op) {
        let parts: Vec<&str> = relation.splitn(2, op).collect();
        if parts.len() == 2 {
            return Ok(Some(make(
                Box::new(parse_expr(parts[0].trim())?),
                Box::new(parse_expr(parts[1].trim())?),
            )));
        }
    }
    Ok(None)
}

fn split_in_set(relation: &str) -> Option<(&str, &str)> {
    if let Some(pos) = relation.find('∈') {
        let (left, right) = relation.split_at(pos);
        let right = right.trim_start_matches('∈');
        return Some((left, right));
    }

    if let Some(pos) = relation.find(" in ") {
        let (left, right) = relation.split_at(pos);
        let right = right.trim_start_matches(" in ");
        return Some((left, right));
    }

    None
}

fn parse_set(expr: &str) -> Result<InvariantAST, InvariantParseError> {
    let inner = expr
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();
    if inner.is_empty() {
        return Ok(InvariantAST::Set(Vec::new()));
    }
    let elements = inner
        .split(',')
        .map(|s| parse_expr(s.trim()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(InvariantAST::Set(elements))
}

fn parse_range_chain(relation: &str) -> Result<Option<InvariantAST>, InvariantParseError> {
    let tokens: Vec<&str> = relation.split_whitespace().collect();
    if tokens.len() != 5 {
        return Ok(None);
    }
    let op1 = tokens[1];
    let op2 = tokens[3];
    let valid_op = |op: &str| matches!(op, "<" | "<=" | ">" | ">=");
    if !valid_op(op1) || !valid_op(op2) {
        return Ok(None);
    }

    let lower = parse_expr(tokens[0].trim())?;
    let value = parse_expr(tokens[2].trim())?;
    let upper = parse_expr(tokens[4].trim())?;

    let (inclusive_lower, inclusive_upper) =
        (op1 == "<=" || op1 == ">=", op2 == "<=" || op2 == ">=");

    Ok(Some(InvariantAST::Range {
        lower: Box::new(lower),
        value: Box::new(value),
        upper: Box::new(upper),
        inclusive_lower,
        inclusive_upper,
    }))
}

fn is_literal(expr: &str) -> bool {
    let lower = expr.to_lowercase();
    if lower.starts_with("0x") {
        return true;
    }
    if lower.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    matches!(
        lower.as_str(),
        "p" | "p-1" | "max" | "max_field" | "(p-1)/2" | "bit_length"
    )
}

pub fn collect_identifiers(ast: &InvariantAST, out: &mut Vec<String>) {
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
            for value in values {
                collect_identifiers(value, out);
            }
        }
        InvariantAST::Power(base, exp) => {
            out.push(base.clone());
            out.push(exp.clone());
        }
        InvariantAST::Literal(_) | InvariantAST::Raw(_) => {}
    }
}

pub fn extract_identifiers_from_ast(ast: &InvariantAST) -> Vec<String> {
    let mut identifiers = Vec::new();
    collect_identifiers(ast, &mut identifiers);
    identifiers.sort();
    identifiers.dedup();
    identifiers
}

pub fn extract_identifiers_from_relation(relation: &str) -> Vec<String> {
    let Ok(ast) = parse_invariant_relation(relation) else {
        return Vec::new();
    };
    if matches!(ast, InvariantAST::Raw(_)) {
        return Vec::new();
    }
    extract_identifiers_from_ast(&ast)
}

pub fn validate_invariant_against_inputs(
    name: &str,
    relation: &str,
    known_inputs: &[String],
) -> Result<InvariantValidationResult, InvariantValidationError> {
    if name.trim().is_empty() {
        return Err(InvariantValidationError::EmptyInvariantName);
    }

    if relation.trim().is_empty() {
        return Err(InvariantValidationError::EmptyRelation);
    }

    let ast =
        parse_invariant_relation(relation).map_err(InvariantValidationError::InvalidRelation)?;

    if matches!(ast, InvariantAST::Raw(_)) {
        return Err(InvariantValidationError::RawRelationExpression(
            relation.trim().to_string(),
        ));
    }

    let identifiers = extract_identifiers_from_ast(&ast);
    let has_known_ref = identifiers.iter().any(|id| {
        known_inputs
            .iter()
            .any(|input| input.eq_ignore_ascii_case(id))
    });

    if !has_known_ref {
        return Err(InvariantValidationError::NoKnownInputReference {
            relation: relation.trim().to_string(),
            known_inputs: known_inputs.to_vec(),
        });
    }

    Ok(InvariantValidationResult { ast, identifiers })
}

impl SemanticOracleEngine {
    fn parse_quantifier_binder(binder: &str) -> (&str, Option<&str>) {
        let trimmed = binder.trim();
        if let Some((var, domain)) = trimmed.split_once(" in ") {
            return (var.trim(), Some(domain.trim()));
        }
        (trimmed, None)
    }

    fn infer_quantifier_domain(expr: &InvariantAST, binder_var: &str) -> Option<String> {
        match expr {
            InvariantAST::ArrayAccess(name, index) if index.trim() == binder_var => {
                Some(name.clone())
            }
            InvariantAST::Equals(left, right)
            | InvariantAST::NotEquals(left, right)
            | InvariantAST::LessThan(left, right)
            | InvariantAST::LessThanOrEqual(left, right)
            | InvariantAST::GreaterThan(left, right)
            | InvariantAST::GreaterThanOrEqual(left, right)
            | InvariantAST::InSet(left, right) => Self::infer_quantifier_domain(left, binder_var)
                .or_else(|| Self::infer_quantifier_domain(right, binder_var)),
            InvariantAST::Range {
                lower,
                value,
                upper,
                ..
            } => Self::infer_quantifier_domain(lower, binder_var)
                .or_else(|| Self::infer_quantifier_domain(value, binder_var))
                .or_else(|| Self::infer_quantifier_domain(upper, binder_var)),
            InvariantAST::Set(values) => values
                .iter()
                .find_map(|value| Self::infer_quantifier_domain(value, binder_var)),
            InvariantAST::ForAll { expr, .. } => Self::infer_quantifier_domain(expr, binder_var),
            _ => None,
        }
    }

    fn substitute_quantifier(expr: &InvariantAST, binder_var: &str, index: usize) -> InvariantAST {
        let replacement = index.to_string();
        match expr {
            InvariantAST::Identifier(name) if name.trim() == binder_var => {
                InvariantAST::Literal(replacement)
            }
            InvariantAST::ArrayAccess(name, current_index) if current_index.trim() == binder_var => {
                InvariantAST::ArrayAccess(name.clone(), replacement)
            }
            InvariantAST::Equals(left, right) => InvariantAST::Equals(
                Box::new(Self::substitute_quantifier(left, binder_var, index)),
                Box::new(Self::substitute_quantifier(right, binder_var, index)),
            ),
            InvariantAST::NotEquals(left, right) => InvariantAST::NotEquals(
                Box::new(Self::substitute_quantifier(left, binder_var, index)),
                Box::new(Self::substitute_quantifier(right, binder_var, index)),
            ),
            InvariantAST::LessThan(left, right) => InvariantAST::LessThan(
                Box::new(Self::substitute_quantifier(left, binder_var, index)),
                Box::new(Self::substitute_quantifier(right, binder_var, index)),
            ),
            InvariantAST::LessThanOrEqual(left, right) => InvariantAST::LessThanOrEqual(
                Box::new(Self::substitute_quantifier(left, binder_var, index)),
                Box::new(Self::substitute_quantifier(right, binder_var, index)),
            ),
            InvariantAST::GreaterThan(left, right) => InvariantAST::GreaterThan(
                Box::new(Self::substitute_quantifier(left, binder_var, index)),
                Box::new(Self::substitute_quantifier(right, binder_var, index)),
            ),
            InvariantAST::GreaterThanOrEqual(left, right) => InvariantAST::GreaterThanOrEqual(
                Box::new(Self::substitute_quantifier(left, binder_var, index)),
                Box::new(Self::substitute_quantifier(right, binder_var, index)),
            ),
            InvariantAST::InSet(left, right) => InvariantAST::InSet(
                Box::new(Self::substitute_quantifier(left, binder_var, index)),
                Box::new(Self::substitute_quantifier(right, binder_var, index)),
            ),
            InvariantAST::Range {
                lower,
                value,
                upper,
                inclusive_lower,
                inclusive_upper,
            } => InvariantAST::Range {
                lower: Box::new(Self::substitute_quantifier(lower, binder_var, index)),
                value: Box::new(Self::substitute_quantifier(value, binder_var, index)),
                upper: Box::new(Self::substitute_quantifier(upper, binder_var, index)),
                inclusive_lower: *inclusive_lower,
                inclusive_upper: *inclusive_upper,
            },
            InvariantAST::Set(values) => InvariantAST::Set(
                values
                    .iter()
                    .map(|value| Self::substitute_quantifier(value, binder_var, index))
                    .collect(),
            ),
            InvariantAST::ForAll {
                binder,
                expr: nested_expr,
            } => InvariantAST::ForAll {
                binder: binder.clone(),
                expr: Box::new(Self::substitute_quantifier(nested_expr, binder_var, index)),
            },
            _ => expr.clone(),
        }
    }

    pub fn with_input_map(input_map: HashMap<String, (usize, usize)>) -> Self {
        Self {
            input_map,
            uniqueness_tracker: HashMap::new(),
        }
    }

    pub fn reset(&mut self) {
        self.uniqueness_tracker.clear();
    }

    pub fn check(
        &mut self,
        invariant: &SemanticInvariantSpec,
        pair: &WitnessProofPair,
    ) -> Option<SemanticViolation> {
        match invariant.kind {
            SemanticInvariantKind::Range => self.check_range(invariant, pair),
            SemanticInvariantKind::Uniqueness => self.check_uniqueness(invariant, pair),
            SemanticInvariantKind::Constraint => self.check_constraint(invariant, pair),
            SemanticInvariantKind::Metamorphic | SemanticInvariantKind::Custom => None,
        }
    }

    fn check_range(
        &self,
        invariant: &SemanticInvariantSpec,
        pair: &WitnessProofPair,
    ) -> Option<SemanticViolation> {
        let (lower, upper, is_exclusive) = invariant.range_bounds.as_ref()?;

        for idx in &invariant.input_indices {
            if *idx >= pair.witness.len() {
                continue;
            }

            let value = &pair.witness[*idx];
            if Self::field_cmp(value, lower) == std::cmp::Ordering::Less {
                return Some(SemanticViolation {
                    invariant_name: invariant.name.clone(),
                    relation: invariant.relation.clone(),
                    witness: pair.witness.clone(),
                    outputs: pair.outputs.clone(),
                    severity: invariant.severity.clone(),
                    evidence: format!(
                        "Input at index {} = {} is below lower bound {}",
                        idx,
                        value.to_hex(),
                        lower.to_hex()
                    ),
                    circuit_accepted: pair.circuit_accepted,
                });
            }

            let cmp = Self::field_cmp(value, upper);
            let upper_violated = if *is_exclusive {
                cmp != std::cmp::Ordering::Less
            } else {
                cmp == std::cmp::Ordering::Greater
            };

            if upper_violated {
                return Some(SemanticViolation {
                    invariant_name: invariant.name.clone(),
                    relation: invariant.relation.clone(),
                    witness: pair.witness.clone(),
                    outputs: pair.outputs.clone(),
                    severity: invariant.severity.clone(),
                    evidence: format!(
                        "Input at index {} = {} exceeds upper bound {} (exclusive={})",
                        idx,
                        value.to_hex(),
                        upper.to_hex(),
                        is_exclusive
                    ),
                    circuit_accepted: pair.circuit_accepted,
                });
            }
        }

        None
    }

    fn check_uniqueness(
        &mut self,
        invariant: &SemanticInvariantSpec,
        pair: &WitnessProofPair,
    ) -> Option<SemanticViolation> {
        if invariant.uniqueness_key_indices.is_empty()
            || invariant.uniqueness_value_indices.is_empty()
        {
            return None;
        }

        let key_hash = self.compute_hash(&invariant.uniqueness_key_indices, &pair.witness);
        let value_hash = self.compute_hash(&invariant.uniqueness_value_indices, &pair.witness);

        let value_hex = hex::encode(&value_hash);
        for (other_key, other_values) in &self.uniqueness_tracker {
            if other_key.starts_with(&format!("{}:", invariant.name))
                && other_values.contains(&value_hash)
            {
                return Some(SemanticViolation {
                    invariant_name: invariant.name.clone(),
                    relation: invariant.relation.clone(),
                    witness: pair.witness.clone(),
                    outputs: pair.outputs.clone(),
                    severity: invariant.severity.clone(),
                    evidence: format!(
                        "Uniqueness violation: value {} seen with different keys",
                        value_hex
                    ),
                    circuit_accepted: pair.circuit_accepted,
                });
            }
        }

        let tracker_key = format!("{}:{}", invariant.name, hex::encode(&key_hash));
        self.uniqueness_tracker
            .entry(tracker_key)
            .or_default()
            .insert(value_hash);

        None
    }

    fn check_constraint(
        &self,
        invariant: &SemanticInvariantSpec,
        pair: &WitnessProofPair,
    ) -> Option<SemanticViolation> {
        let ast = invariant.ast.as_ref()?;
        self.check_constraint_ast(ast, invariant, pair)
    }

    fn check_constraint_ast(
        &self,
        ast: &InvariantAST,
        invariant: &SemanticInvariantSpec,
        pair: &WitnessProofPair,
    ) -> Option<SemanticViolation> {
        match ast {
            InvariantAST::Equals(left, right) => {
                let left_val = self.evaluate_expr(left, pair)?;
                let right_val = self.evaluate_expr(right, pair)?;
                if left_val != right_val {
                    return Some(self.mk_violation(
                        invariant,
                        pair,
                        format!(
                            "Constraint violated: {} != {}",
                            left_val.to_hex(),
                            right_val.to_hex()
                        ),
                    ));
                }
            }
            InvariantAST::NotEquals(left, right) => {
                let left_val = self.evaluate_expr(left, pair)?;
                let right_val = self.evaluate_expr(right, pair)?;
                if left_val == right_val {
                    return Some(self.mk_violation(
                        invariant,
                        pair,
                        format!(
                            "Constraint violated: {} should not equal {}",
                            left_val.to_hex(),
                            right_val.to_hex()
                        ),
                    ));
                }
            }
            InvariantAST::LessThan(left, right) => {
                let left_val = self.evaluate_expr(left, pair)?;
                let right_val = self.evaluate_expr(right, pair)?;
                if Self::field_cmp(&left_val, &right_val) != std::cmp::Ordering::Less {
                    return Some(self.mk_violation(
                        invariant,
                        pair,
                        format!(
                            "Constraint violated: {} not < {}",
                            left_val.to_hex(),
                            right_val.to_hex()
                        ),
                    ));
                }
            }
            InvariantAST::LessThanOrEqual(left, right) => {
                let left_val = self.evaluate_expr(left, pair)?;
                let right_val = self.evaluate_expr(right, pair)?;
                if matches!(
                    Self::field_cmp(&left_val, &right_val),
                    std::cmp::Ordering::Greater
                ) {
                    return Some(self.mk_violation(
                        invariant,
                        pair,
                        format!(
                            "Constraint violated: {} not <= {}",
                            left_val.to_hex(),
                            right_val.to_hex()
                        ),
                    ));
                }
            }
            InvariantAST::GreaterThan(left, right) => {
                let left_val = self.evaluate_expr(left, pair)?;
                let right_val = self.evaluate_expr(right, pair)?;
                if Self::field_cmp(&left_val, &right_val) != std::cmp::Ordering::Greater {
                    return Some(self.mk_violation(
                        invariant,
                        pair,
                        format!(
                            "Constraint violated: {} not > {}",
                            left_val.to_hex(),
                            right_val.to_hex()
                        ),
                    ));
                }
            }
            InvariantAST::GreaterThanOrEqual(left, right) => {
                let left_val = self.evaluate_expr(left, pair)?;
                let right_val = self.evaluate_expr(right, pair)?;
                if matches!(
                    Self::field_cmp(&left_val, &right_val),
                    std::cmp::Ordering::Less
                ) {
                    return Some(self.mk_violation(
                        invariant,
                        pair,
                        format!(
                            "Constraint violated: {} not >= {}",
                            left_val.to_hex(),
                            right_val.to_hex()
                        ),
                    ));
                }
            }
            InvariantAST::InSet(value_expr, set_expr) => {
                let value = self.evaluate_expr(value_expr, pair)?;
                let set_values = self.evaluate_set(set_expr, pair)?;
                if !set_values.contains(&value) {
                    return Some(self.mk_violation(
                        invariant,
                        pair,
                        format!("Constraint violated: {} not in set", value.to_hex()),
                    ));
                }
            }
            InvariantAST::Range {
                lower,
                value,
                upper,
                inclusive_lower,
                inclusive_upper,
            } => {
                let lower_value = self.evaluate_expr(lower, pair)?;
                let value_value = self.evaluate_expr(value, pair)?;
                let upper_value = self.evaluate_expr(upper, pair)?;

                let lower_ok = match Self::field_cmp(&value_value, &lower_value) {
                    std::cmp::Ordering::Less => false,
                    std::cmp::Ordering::Equal => *inclusive_lower,
                    std::cmp::Ordering::Greater => true,
                };
                let upper_ok = match Self::field_cmp(&value_value, &upper_value) {
                    std::cmp::Ordering::Less => true,
                    std::cmp::Ordering::Equal => *inclusive_upper,
                    std::cmp::Ordering::Greater => false,
                };

                if !lower_ok || !upper_ok {
                    return Some(self.mk_violation(
                        invariant,
                        pair,
                        format!(
                            "Constraint violated: {} outside range {}..{}",
                            value_value.to_hex(),
                            lower_value.to_hex(),
                            upper_value.to_hex()
                        ),
                    ));
                }
            }
            InvariantAST::ForAll { binder, expr } => {
                let (binder_var, domain) = Self::parse_quantifier_binder(binder);
                let domain = domain
                    .map(str::to_string)
                    .or_else(|| Self::infer_quantifier_domain(expr, binder_var))?;
                let (_, len) = self.input_map.get(&domain.to_lowercase()).copied()?;
                for idx in 0..len {
                    let substituted = Self::substitute_quantifier(expr, binder_var, idx);
                    if let Some(violation) = self.check_constraint_ast(&substituted, invariant, pair)
                    {
                        return Some(violation);
                    }
                }
                return None;
            }
            _ => {}
        }

        None
    }

    fn mk_violation(
        &self,
        invariant: &SemanticInvariantSpec,
        pair: &WitnessProofPair,
        evidence: String,
    ) -> SemanticViolation {
        SemanticViolation {
            invariant_name: invariant.name.clone(),
            relation: invariant.relation.clone(),
            witness: pair.witness.clone(),
            outputs: pair.outputs.clone(),
            severity: invariant.severity.clone(),
            evidence,
            circuit_accepted: pair.circuit_accepted,
        }
    }

    fn evaluate_set(
        &self,
        expr: &InvariantAST,
        pair: &WitnessProofPair,
    ) -> Option<Vec<FieldElement>> {
        if let InvariantAST::Set(values) = expr {
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                out.push(self.evaluate_expr(value, pair)?);
            }
            return Some(out);
        }
        None
    }

    fn evaluate_expr(&self, expr: &InvariantAST, pair: &WitnessProofPair) -> Option<FieldElement> {
        match expr {
            InvariantAST::Identifier(name) => {
                let lower = name.to_lowercase();
                if let Some(&(offset, _)) = self.input_map.get(&lower) {
                    return pair.witness.get(offset).cloned();
                }

                if lower.starts_with("output") {
                    let idx_str = lower.trim_start_matches("output").trim_start_matches('_');
                    let idx = idx_str.parse::<usize>().ok()?;
                    return pair.outputs.get(idx).cloned();
                }

                if lower == "proof_len" {
                    let len = pair.proof.as_ref().map(|proof| proof.len()).unwrap_or(0);
                    return Some(FieldElement::from_u64(len as u64));
                }

                None
            }
            InvariantAST::ArrayAccess(name, index) => {
                let lower = name.to_lowercase();
                let idx = index.trim().parse::<usize>().ok()?;
                let (offset, len) = self.input_map.get(&lower).copied()?;
                if idx >= len {
                    return None;
                }
                pair.witness.get(offset + idx).cloned()
            }
            InvariantAST::Literal(value) => Self::parse_field_value(value),
            InvariantAST::Power(base, exp) => {
                if base.trim() != "2" {
                    return None;
                }
                let bits = exp.trim().parse::<u32>().ok()?;
                if bits > 63 {
                    return None;
                }
                Some(FieldElement::from_u64(1u64 << bits))
            }
            _ => None,
        }
    }

    fn parse_field_value(raw: &str) -> Option<FieldElement> {
        let trimmed = raw.trim();
        if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
            return FieldElement::from_hex(trimmed).ok();
        }
        let value = trimmed.parse::<u64>().ok()?;
        Some(FieldElement::from_u64(value))
    }

    fn compute_hash(&self, indices: &[usize], witness: &[FieldElement]) -> Vec<u8> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        for idx in indices {
            if let Some(value) = witness.get(*idx) {
                hasher.update(value.0);
            }
        }
        hasher.finalize().to_vec()
    }

    fn field_cmp(a: &FieldElement, b: &FieldElement) -> std::cmp::Ordering {
        a.0.cmp(&b.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        extract_identifiers_from_relation, parse_invariant_relation,
        validate_invariant_against_inputs, InvariantAST, InvariantParseError,
        InvariantValidationError, SemanticInvariantKind, SemanticInvariantSpec,
        SemanticOracleEngine, WitnessProofPair,
    };
    use crate::FieldElement;
    use std::collections::HashMap;

    #[test]
    fn parse_equals_with_function_call() {
        let ast = parse_invariant_relation("root == merkle(leaf, path)").expect("parse");
        match ast {
            InvariantAST::Equals(left, right) => {
                assert!(matches!(*left, InvariantAST::Identifier(_)));
                assert!(matches!(*right, InvariantAST::Call(_, _)));
            }
            _ => panic!("expected equality AST"),
        }
    }

    #[test]
    fn parse_forall_with_set_membership() {
        let ast = parse_invariant_relation("∀i: path[i] ∈ {0,1}").expect("parse");
        match ast {
            InvariantAST::ForAll { expr, .. } => {
                assert!(matches!(*expr, InvariantAST::InSet(_, _)));
            }
            _ => panic!("expected forall AST"),
        }
    }

    #[test]
    fn parse_rejects_empty_relation() {
        let err = parse_invariant_relation("  ").expect_err("must fail");
        assert_eq!(err, InvariantParseError::EmptyRelation);
    }

    #[test]
    fn identifier_extraction_is_deduplicated() {
        let ids = extract_identifiers_from_relation("x == hash(x, y)");
        assert_eq!(ids, vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn validate_accepts_known_input_reference() {
        let known_inputs = vec!["nullifier".to_string(), "path".to_string()];
        let result = validate_invariant_against_inputs(
            "nullifier_uniqueness",
            "nullifier != prior_nullifier",
            &known_inputs,
        )
        .expect("validation must pass");
        assert!(result.identifiers.contains(&"nullifier".to_string()));
    }

    #[test]
    fn validate_rejects_raw_relation() {
        let known_inputs = vec!["x".to_string()];
        let err = validate_invariant_against_inputs("raw", "x + y", &known_inputs)
            .expect_err("must fail");
        assert!(matches!(
            err,
            InvariantValidationError::RawRelationExpression(_)
        ));
    }

    #[test]
    fn validate_rejects_missing_input_reference() {
        let known_inputs = vec!["public_input".to_string()];
        let err = validate_invariant_against_inputs("bad", "private_witness == 0", &known_inputs)
            .expect_err("must fail");
        assert!(matches!(
            err,
            InvariantValidationError::NoKnownInputReference { .. }
        ));
    }

    fn make_fe(v: u64) -> FieldElement {
        FieldElement::from_u64(v)
    }

    #[test]
    fn semantic_engine_checks_range_on_witness() {
        let mut input_map = HashMap::new();
        input_map.insert("x".to_string(), (0usize, 1usize));
        let mut engine = SemanticOracleEngine::with_input_map(input_map);

        let spec = SemanticInvariantSpec {
            name: "x_range".to_string(),
            relation: "0 <= x < 10".to_string(),
            severity: "high".to_string(),
            kind: SemanticInvariantKind::Range,
            ast: parse_invariant_relation("0 <= x < 10").ok(),
            input_indices: vec![0],
            range_bounds: Some((make_fe(0), make_fe(10), true)),
            uniqueness_key_indices: vec![],
            uniqueness_value_indices: vec![],
        };
        let pair = WitnessProofPair {
            witness: vec![make_fe(10)],
            outputs: vec![],
            proof: None,
            circuit_accepted: true,
        };
        let violation = engine.check(&spec, &pair);
        assert!(violation.is_some());
    }

    #[test]
    fn semantic_engine_checks_uniqueness_across_pairs() {
        let mut input_map = HashMap::new();
        input_map.insert("scope".to_string(), (0usize, 1usize));
        input_map.insert("nullifier".to_string(), (1usize, 1usize));
        let mut engine = SemanticOracleEngine::with_input_map(input_map);

        let spec = SemanticInvariantSpec {
            name: "nullifier_uniqueness".to_string(),
            relation: "unique(nullifier) for each (scope)".to_string(),
            severity: "critical".to_string(),
            kind: SemanticInvariantKind::Uniqueness,
            ast: None,
            input_indices: vec![0, 1],
            range_bounds: None,
            uniqueness_key_indices: vec![0],
            uniqueness_value_indices: vec![1],
        };

        let first = WitnessProofPair {
            witness: vec![make_fe(1), make_fe(42)],
            outputs: vec![],
            proof: None,
            circuit_accepted: true,
        };
        assert!(engine.check(&spec, &first).is_none());

        let second = WitnessProofPair {
            witness: vec![make_fe(2), make_fe(42)],
            outputs: vec![],
            proof: None,
            circuit_accepted: true,
        };
        assert!(engine.check(&spec, &second).is_some());
    }

    #[test]
    fn semantic_engine_supports_proof_len_identifier() {
        let mut input_map = HashMap::new();
        input_map.insert("x".to_string(), (0usize, 1usize));
        let mut engine = SemanticOracleEngine::with_input_map(input_map);

        let spec = SemanticInvariantSpec {
            name: "proof_present".to_string(),
            relation: "proof_len > 0".to_string(),
            severity: "medium".to_string(),
            kind: SemanticInvariantKind::Constraint,
            ast: parse_invariant_relation("proof_len > 0").ok(),
            input_indices: vec![],
            range_bounds: None,
            uniqueness_key_indices: vec![],
            uniqueness_value_indices: vec![],
        };

        let with_empty_proof = WitnessProofPair {
            witness: vec![make_fe(5)],
            outputs: vec![],
            proof: None,
            circuit_accepted: true,
        };
        let violation = engine.check(&spec, &with_empty_proof);
        assert!(violation.is_some());

        let with_proof = WitnessProofPair {
            witness: vec![make_fe(5)],
            outputs: vec![],
            proof: Some(vec![0xAA, 0xBB]),
            circuit_accepted: true,
        };
        let violation = engine.check(&spec, &with_proof);
        assert!(violation.is_none());
    }
}
