use std::error::Error;
use std::fmt;

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

#[cfg(test)]
mod tests {
    use super::{
        extract_identifiers_from_relation, parse_invariant_relation,
        validate_invariant_against_inputs, InvariantAST, InvariantParseError,
        InvariantValidationError,
    };

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
}
