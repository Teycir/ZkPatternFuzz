//! Mode 3: Cross-Step Invariant Checker
//!
//! Evaluates cross-step assertions over completed chain traces to detect
//! violations that span multiple circuit executions.

use super::types::{ChainSpec, ChainTrace, CrossStepAssertion};
use regex::Regex;
use std::collections::HashSet;
use zk_core::FieldElement;

/// A violation of a cross-step assertion
#[derive(Debug, Clone)]
pub struct CrossStepViolation {
    /// Name of the violated assertion
    pub assertion_name: String,
    /// The relation that was violated
    pub relation: String,
    /// Indices of steps involved in the violation
    pub step_indices: Vec<usize>,
    /// Actual values that violated the assertion
    pub actual_values: Vec<FieldElement>,
    /// Severity of the violation
    pub severity: String,
    /// Human-readable description of the violation
    pub description: String,
}

impl CrossStepViolation {
    /// Create a new violation
    pub fn new(
        assertion_name: impl Into<String>,
        relation: impl Into<String>,
        step_indices: Vec<usize>,
        actual_values: Vec<FieldElement>,
        severity: impl Into<String>,
    ) -> Self {
        let assertion_name_str = assertion_name.into();
        let desc = format!(
            "Assertion '{}' violated across steps {:?}",
            assertion_name_str,
            step_indices
        );
        Self {
            assertion_name: assertion_name_str,
            relation: relation.into(),
            step_indices,
            actual_values,
            severity: severity.into(),
            description: desc,
        }
    }

    /// Set a custom description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }
}

/// Evaluates cross-step assertions over chain traces
pub struct CrossStepInvariantChecker {
    /// Assertions to check
    assertions: Vec<ParsedAssertion>,
}

/// Parsed form of an assertion for efficient checking
#[derive(Debug, Clone)]
struct ParsedAssertion {
    /// Original assertion
    original: CrossStepAssertion,
    /// Type of assertion
    assertion_type: AssertionType,
}

#[derive(Debug, Clone)]
enum AssertionType {
    /// step[i].out[j] == step[k].in[m]
    Equality {
        step_a: StepRef,
        field_a: FieldRef,
        step_b: StepRef,
        field_b: FieldRef,
    },
    /// step[i].out[j] != step[k].out[m]
    Inequality {
        step_a: StepRef,
        field_a: FieldRef,
        step_b: StepRef,
        field_b: FieldRef,
    },
    /// unique(step[*].out[j])
    Uniqueness {
        field_type: FieldType,
        field_index: usize,
    },
    /// step[i].success == true
    StepSuccess {
        step_index: usize,
    },
    /// Unparseable assertion (skip or warn)
    Unknown,
}

#[derive(Debug, Clone)]
enum StepRef {
    Specific(usize),
    All, // step[*]
}

#[derive(Debug, Clone)]
enum FieldRef {
    Output(usize),
    Input(usize),
}

#[derive(Debug, Clone, Copy)]
enum FieldType {
    Output,
    Input,
}

impl CrossStepInvariantChecker {
    /// Create a new checker from a chain spec
    pub fn from_spec(spec: &ChainSpec) -> Self {
        let assertions = spec.assertions.iter()
            .map(|a| ParsedAssertion {
                original: a.clone(),
                assertion_type: Self::parse_assertion(&a.relation),
            })
            .collect();

        Self { assertions }
    }

    /// Create a checker from a list of assertions
    pub fn new(assertions: Vec<CrossStepAssertion>) -> Self {
        let parsed = assertions.iter()
            .map(|a| ParsedAssertion {
                original: a.clone(),
                assertion_type: Self::parse_assertion(&a.relation),
            })
            .collect();

        Self { assertions: parsed }
    }

    /// Check all assertions against a trace, returning any violations
    pub fn check(&self, trace: &ChainTrace) -> Vec<CrossStepViolation> {
        let mut violations = Vec::new();

        for assertion in &self.assertions {
            if let Some(violation) = self.check_assertion(assertion, trace) {
                violations.push(violation);
            }
        }

        violations
    }

    /// Parse an assertion relation string into a typed form
    fn parse_assertion(relation: &str) -> AssertionType {
        let relation = relation.trim();

        // Try parsing uniqueness: unique(step[*].out[j])
        if let Some(parsed) = Self::parse_uniqueness(relation) {
            return parsed;
        }

        // Try parsing equality: step[i].out[j] == step[k].in[m]
        if let Some(parsed) = Self::parse_equality(relation) {
            return parsed;
        }

        // Try parsing inequality: step[i].out[j] != step[k].out[m]
        if let Some(parsed) = Self::parse_inequality(relation) {
            return parsed;
        }

        // Try parsing step success: step[i].success == true
        if let Some(parsed) = Self::parse_step_success(relation) {
            return parsed;
        }

        AssertionType::Unknown
    }

    fn parse_uniqueness(relation: &str) -> Option<AssertionType> {
        // Match: unique(step[*].out[N]) or unique(step[*].in[N])
        let re = Regex::new(r"unique\s*\(\s*step\s*\[\s*\*\s*\]\s*\.\s*(out|in)\s*\[\s*(\d+)\s*\]\s*\)").ok()?;
        let caps = re.captures(relation)?;

        let field_type = match caps.get(1)?.as_str() {
            "out" => FieldType::Output,
            "in" => FieldType::Input,
            _ => return None,
        };
        let field_index = caps.get(2)?.as_str().parse().ok()?;

        Some(AssertionType::Uniqueness { field_type, field_index })
    }

    fn parse_equality(relation: &str) -> Option<AssertionType> {
        // Match: step[N].out[M] == step[K].in[L]
        let re = Regex::new(
            r"step\s*\[\s*(\d+|\*)\s*\]\s*\.\s*(out|in)\s*\[\s*(\d+)\s*\]\s*==\s*step\s*\[\s*(\d+|\*)\s*\]\s*\.\s*(out|in)\s*\[\s*(\d+)\s*\]"
        ).ok()?;
        let caps = re.captures(relation)?;

        let step_a = Self::parse_step_ref(caps.get(1)?.as_str())?;
        let field_a = Self::parse_field_ref(caps.get(2)?.as_str(), caps.get(3)?.as_str())?;
        let step_b = Self::parse_step_ref(caps.get(4)?.as_str())?;
        let field_b = Self::parse_field_ref(caps.get(5)?.as_str(), caps.get(6)?.as_str())?;

        Some(AssertionType::Equality { step_a, field_a, step_b, field_b })
    }

    fn parse_inequality(relation: &str) -> Option<AssertionType> {
        // Match: step[N].out[M] != step[K].out[L]
        let re = Regex::new(
            r"step\s*\[\s*(\d+|\*)\s*\]\s*\.\s*(out|in)\s*\[\s*(\d+)\s*\]\s*!=\s*step\s*\[\s*(\d+|\*)\s*\]\s*\.\s*(out|in)\s*\[\s*(\d+)\s*\]"
        ).ok()?;
        let caps = re.captures(relation)?;

        let step_a = Self::parse_step_ref(caps.get(1)?.as_str())?;
        let field_a = Self::parse_field_ref(caps.get(2)?.as_str(), caps.get(3)?.as_str())?;
        let step_b = Self::parse_step_ref(caps.get(4)?.as_str())?;
        let field_b = Self::parse_field_ref(caps.get(5)?.as_str(), caps.get(6)?.as_str())?;

        Some(AssertionType::Inequality { step_a, field_a, step_b, field_b })
    }

    fn parse_step_success(relation: &str) -> Option<AssertionType> {
        // Match: step[N].success == true
        let re = Regex::new(r"step\s*\[\s*(\d+)\s*\]\s*\.\s*success\s*==\s*true").ok()?;
        let caps = re.captures(relation)?;
        let step_index = caps.get(1)?.as_str().parse().ok()?;
        Some(AssertionType::StepSuccess { step_index })
    }

    fn parse_step_ref(s: &str) -> Option<StepRef> {
        if s == "*" {
            Some(StepRef::All)
        } else {
            s.parse().ok().map(StepRef::Specific)
        }
    }

    fn parse_field_ref(field_type: &str, index: &str) -> Option<FieldRef> {
        let idx = index.parse().ok()?;
        match field_type {
            "out" => Some(FieldRef::Output(idx)),
            "in" => Some(FieldRef::Input(idx)),
            _ => None,
        }
    }

    /// Check a single assertion against a trace
    fn check_assertion(&self, assertion: &ParsedAssertion, trace: &ChainTrace) -> Option<CrossStepViolation> {
        match &assertion.assertion_type {
            AssertionType::Equality { step_a, field_a, step_b, field_b } => {
                self.check_equality(assertion, trace, step_a, field_a, step_b, field_b)
            }
            AssertionType::Inequality { step_a, field_a, step_b, field_b } => {
                self.check_inequality(assertion, trace, step_a, field_a, step_b, field_b)
            }
            AssertionType::Uniqueness { field_type, field_index } => {
                self.check_uniqueness(assertion, trace, *field_type, *field_index)
            }
            AssertionType::StepSuccess { step_index } => {
                self.check_step_success(assertion, trace, *step_index)
            }
            AssertionType::Unknown => {
                tracing::warn!("Skipping unknown assertion: {}", assertion.original.relation);
                None
            }
        }
    }

    fn check_equality(
        &self,
        assertion: &ParsedAssertion,
        trace: &ChainTrace,
        step_a: &StepRef,
        field_a: &FieldRef,
        step_b: &StepRef,
        field_b: &FieldRef,
    ) -> Option<CrossStepViolation> {
        let value_a = self.get_field_value(trace, step_a, field_a)?;
        let value_b = self.get_field_value(trace, step_b, field_b)?;

        if value_a != value_b {
            let step_indices = vec![
                self.step_ref_to_index(step_a).unwrap_or(0),
                self.step_ref_to_index(step_b).unwrap_or(0),
            ];
            Some(CrossStepViolation::new(
                &assertion.original.name,
                &assertion.original.relation,
                step_indices,
                vec![value_a.clone(), value_b.clone()],
                &assertion.original.severity,
            ).with_description(format!(
                "Expected {} == {}, but got {} != {}",
                self.describe_field_ref(step_a, field_a),
                self.describe_field_ref(step_b, field_b),
                value_a.to_hex(),
                value_b.to_hex(),
            )))
        } else {
            None
        }
    }

    fn check_inequality(
        &self,
        assertion: &ParsedAssertion,
        trace: &ChainTrace,
        step_a: &StepRef,
        field_a: &FieldRef,
        step_b: &StepRef,
        field_b: &FieldRef,
    ) -> Option<CrossStepViolation> {
        let value_a = self.get_field_value(trace, step_a, field_a)?;
        let value_b = self.get_field_value(trace, step_b, field_b)?;

        if value_a == value_b {
            let step_indices = vec![
                self.step_ref_to_index(step_a).unwrap_or(0),
                self.step_ref_to_index(step_b).unwrap_or(0),
            ];
            Some(CrossStepViolation::new(
                &assertion.original.name,
                &assertion.original.relation,
                step_indices,
                vec![value_a.clone()],
                &assertion.original.severity,
            ).with_description(format!(
                "Expected {} != {}, but values are equal: {}",
                self.describe_field_ref(step_a, field_a),
                self.describe_field_ref(step_b, field_b),
                value_a.to_hex(),
            )))
        } else {
            None
        }
    }

    fn check_uniqueness(
        &self,
        assertion: &ParsedAssertion,
        trace: &ChainTrace,
        field_type: FieldType,
        field_index: usize,
    ) -> Option<CrossStepViolation> {
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        let mut duplicate_steps = Vec::new();
        let mut duplicate_value = None;

        for (step_idx, step) in trace.steps.iter().enumerate() {
            let value = match field_type {
                FieldType::Output => step.outputs.get(field_index),
                FieldType::Input => step.inputs.get(field_index),
            };

            if let Some(val) = value {
                let bytes = val.to_bytes().to_vec();
                if !seen.insert(bytes) {
                    // Duplicate found
                    duplicate_steps.push(step_idx);
                    if duplicate_value.is_none() {
                        duplicate_value = Some(val.clone());
                    }
                }
            }
        }

        if !duplicate_steps.is_empty() {
            let field_name = match field_type {
                FieldType::Output => format!("out[{}]", field_index),
                FieldType::Input => format!("in[{}]", field_index),
            };
            let dup_val_hex = duplicate_value.as_ref().map(|v| v.to_hex()).unwrap_or_default();
            Some(CrossStepViolation::new(
                &assertion.original.name,
                &assertion.original.relation,
                duplicate_steps.clone(),
                duplicate_value.into_iter().collect(),
                &assertion.original.severity,
            ).with_description(format!(
                "Duplicate {} found across steps {:?}: {}",
                field_name,
                duplicate_steps,
                dup_val_hex,
            )))
        } else {
            None
        }
    }

    fn check_step_success(
        &self,
        assertion: &ParsedAssertion,
        trace: &ChainTrace,
        step_index: usize,
    ) -> Option<CrossStepViolation> {
        if let Some(step) = trace.steps.get(step_index) {
            if !step.success {
                return Some(CrossStepViolation::new(
                    &assertion.original.name,
                    &assertion.original.relation,
                    vec![step_index],
                    vec![],
                    &assertion.original.severity,
                ).with_description(format!(
                    "Step {} failed: {:?}",
                    step_index,
                    step.error,
                )));
            }
        }
        None
    }

    fn get_field_value(&self, trace: &ChainTrace, step_ref: &StepRef, field_ref: &FieldRef) -> Option<FieldElement> {
        let step = match step_ref {
            StepRef::Specific(idx) => trace.steps.get(*idx)?,
            StepRef::All => return None, // Can't get single value for all steps
        };

        match field_ref {
            FieldRef::Output(idx) => step.outputs.get(*idx).cloned(),
            FieldRef::Input(idx) => step.inputs.get(*idx).cloned(),
        }
    }

    fn step_ref_to_index(&self, step_ref: &StepRef) -> Option<usize> {
        match step_ref {
            StepRef::Specific(idx) => Some(*idx),
            StepRef::All => None,
        }
    }

    fn describe_field_ref(&self, step_ref: &StepRef, field_ref: &FieldRef) -> String {
        let step_str = match step_ref {
            StepRef::Specific(idx) => format!("step[{}]", idx),
            StepRef::All => "step[*]".to_string(),
        };
        let field_str = match field_ref {
            FieldRef::Output(idx) => format!(".out[{}]", idx),
            FieldRef::Input(idx) => format!(".in[{}]", idx),
        };
        format!("{}{}", step_str, field_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_fuzzer::types::StepTrace;

    fn create_test_trace() -> ChainTrace {
        let mut trace = ChainTrace::new("test_chain");
        
        // Step 0: outputs [42, 100]
        trace.add_step(StepTrace::success(
            0, "circuit_a",
            vec![FieldElement::one()],
            vec![FieldElement::from_u64(42), FieldElement::from_u64(100)],
        ));
        
        // Step 1: inputs include 42 (wired from step 0)
        trace.add_step(StepTrace::success(
            1, "circuit_b",
            vec![FieldElement::from_u64(42), FieldElement::from_u64(200)],
            vec![FieldElement::from_u64(42)], // Duplicate of step 0 out[0]
        ));

        trace
    }

    #[test]
    fn test_uniqueness_violation() {
        let trace = create_test_trace();
        
        let assertions = vec![
            CrossStepAssertion::unique("no_duplicate_outputs", 0),
        ];
        
        let checker = CrossStepInvariantChecker::new(assertions);
        let violations = checker.check(&trace);
        
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].assertion_name, "no_duplicate_outputs");
    }

    #[test]
    fn test_equality_check() {
        let trace = create_test_trace();
        
        // This should pass: step[0].out[0] == step[1].in[0] (both are 42)
        let assertions = vec![
            CrossStepAssertion::equal("wiring_correct", 0, 0, 1, 0),
        ];
        
        let checker = CrossStepInvariantChecker::new(assertions);
        let violations = checker.check(&trace);
        
        assert!(violations.is_empty());
    }

    #[test]
    fn test_equality_violation() {
        let trace = create_test_trace();
        
        // This should fail: step[0].out[1] != step[1].in[0] (100 != 42)
        let assertions = vec![
            CrossStepAssertion::equal("bad_wiring", 0, 1, 1, 0),
        ];
        
        let checker = CrossStepInvariantChecker::new(assertions);
        let violations = checker.check(&trace);
        
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].assertion_name, "bad_wiring");
    }
}
