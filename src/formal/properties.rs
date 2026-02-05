//! Circuit Property Extraction
//!
//! Extracts verifiable properties from ZK circuit constraints.

use crate::analysis::symbolic::{SymbolicConstraint, SymbolicValue};
use zk_core::ConstraintEquation;
use zk_core::FieldElement;
use std::collections::{HashMap, HashSet};

/// Types of circuit properties that can be extracted and verified
#[derive(Debug, Clone)]
pub enum CircuitProperty {
    /// A constraint is always satisfied for valid witnesses
    ConstraintSatisfied {
        constraint_id: usize,
        description: String,
    },
    /// A signal is never zero
    NonZero { signal: String },
    /// A signal is within a range
    Range {
        signal: String,
        min: FieldElement,
        max: FieldElement,
    },
    /// A signal is boolean (0 or 1)
    Boolean { signal: String },
    /// Signals are unique (no collisions)
    Unique { signals: Vec<String> },
    /// Output is deterministic given inputs
    Deterministic {
        inputs: Vec<String>,
        outputs: Vec<String>,
    },
}

impl CircuitProperty {
    /// Get all variables involved in this property
    pub fn variables(&self) -> HashSet<String> {
        match self {
            CircuitProperty::ConstraintSatisfied { .. } => HashSet::new(),
            CircuitProperty::NonZero { signal } => {
                let mut set = HashSet::new();
                set.insert(signal.clone());
                set
            }
            CircuitProperty::Range { signal, .. } => {
                let mut set = HashSet::new();
                set.insert(signal.clone());
                set
            }
            CircuitProperty::Boolean { signal } => {
                let mut set = HashSet::new();
                set.insert(signal.clone());
                set
            }
            CircuitProperty::Unique { signals } => signals.iter().cloned().collect(),
            CircuitProperty::Deterministic { inputs, outputs } => {
                inputs.iter().chain(outputs.iter()).cloned().collect()
            }
        }
    }

    /// Get preconditions for this property
    pub fn preconditions(&self) -> Vec<SymbolicConstraint> {
        match self {
            CircuitProperty::NonZero { signal } => {
                // Precondition: signal is a valid field element
                vec![SymbolicConstraint::Range(
                    SymbolicValue::symbol(signal),
                    SymbolicValue::concrete(FieldElement::max_value()),
                )]
            }
            CircuitProperty::Range {
                signal,
                min: _min,
                max: _max,
            } => {
                vec![SymbolicConstraint::Range(
                    SymbolicValue::symbol(signal),
                    SymbolicValue::concrete(FieldElement::max_value()),
                )]
            }
            _ => Vec::new(),
        }
    }

    /// Get postconditions for this property
    pub fn postconditions(&self) -> Vec<SymbolicConstraint> {
        match self {
            CircuitProperty::NonZero { signal } => {
                vec![SymbolicConstraint::Neq(
                    SymbolicValue::symbol(signal),
                    SymbolicValue::concrete(FieldElement::zero()),
                )]
            }
            CircuitProperty::Boolean { signal } => {
                vec![SymbolicConstraint::Boolean(SymbolicValue::symbol(signal))]
            }
            CircuitProperty::Range {
                signal,
                min: _min,
                max,
            } => {
                vec![SymbolicConstraint::Range(
                    SymbolicValue::symbol(signal),
                    SymbolicValue::concrete(max.clone()),
                )]
            }
            _ => Vec::new(),
        }
    }
}

/// Extracts properties from circuit constraints
pub struct PropertyExtractor {
    /// Detected boolean signals
    boolean_signals: HashSet<String>,
}

impl PropertyExtractor {
    pub fn new() -> Self {
        Self {
            boolean_signals: HashSet::new(),
        }
    }

    /// Extract all properties from constraints
    pub fn extract_all(&self, constraints: &[ConstraintEquation]) -> Vec<CircuitProperty> {
        let mut properties = Vec::new();

        // Analyze each constraint
        for eq in constraints {
            properties.extend(self.analyze_constraint(eq));
        }

        // Add detected boolean properties
        for signal in &self.boolean_signals {
            properties.push(CircuitProperty::Boolean {
                signal: signal.clone(),
            });
        }

        // Add constraint satisfaction properties
        for eq in constraints {
            properties.push(CircuitProperty::ConstraintSatisfied {
                constraint_id: eq.id,
                description: eq.description.clone().unwrap_or_default(),
            });
        }

        properties
    }

    /// Analyze a single constraint for properties
    fn analyze_constraint(&self, eq: &ConstraintEquation) -> Vec<CircuitProperty> {
        let mut properties = Vec::new();

        // Check for boolean constraint pattern: x * (1 - x) = 0
        if self.is_boolean_constraint(eq) {
            if let Some(signal) = self.extract_boolean_signal(eq) {
                properties.push(CircuitProperty::Boolean { signal });
            }
        }

        // Check for range constraint pattern
        if let Some((signal, min, max)) = self.extract_range_constraint(eq) {
            properties.push(CircuitProperty::Range { signal, min, max });
        }

        // Check for non-zero pattern (multiplicative inverse check)
        if let Some(signal) = self.extract_nonzero_constraint(eq) {
            properties.push(CircuitProperty::NonZero { signal });
        }

        properties
    }

    /// Check if constraint represents a boolean (x * (1-x) = 0)
    fn is_boolean_constraint(&self, eq: &ConstraintEquation) -> bool {
        // Pattern: A has one term, B = 1 - A, C = 0
        if eq.a_terms.len() != 1 || eq.b_terms.len() > 2 {
            return false;
        }

        // Check if C = 0
        let c_is_zero =
            eq.c_terms.is_empty() || (eq.c_terms.len() == 1 && eq.c_terms[0].1.is_zero());

        if !c_is_zero {
            return false;
        }

        // Check if B = 1 - A (simplified check)
        if eq.b_terms.len() == 2 {
            let has_constant = eq.b_terms.iter().any(|(_, coeff)| coeff.is_one());
            let has_negation = eq
                .b_terms
                .iter()
                .any(|(idx, _)| eq.a_terms.iter().any(|(a_idx, _)| a_idx == idx));
            return has_constant && has_negation;
        }

        false
    }

    /// Extract the signal name from a boolean constraint
    fn extract_boolean_signal(&self, eq: &ConstraintEquation) -> Option<String> {
        if eq.a_terms.len() == 1 {
            Some(format!("x{}", eq.a_terms[0].0))
        } else {
            None
        }
    }

    /// Extract range constraint if present
    fn extract_range_constraint(
        &self,
        _eq: &ConstraintEquation,
    ) -> Option<(String, FieldElement, FieldElement)> {
        // Range constraints typically use lookup tables or bit decomposition
        // This is a simplified extraction that doesn't cover all cases
        None
    }

    /// Extract non-zero constraint if present
    fn extract_nonzero_constraint(&self, eq: &ConstraintEquation) -> Option<String> {
        // Pattern: a * a_inv = 1 implies a != 0
        // Check if C = 1
        if eq.c_terms.len() == 1 && eq.c_terms[0].1.is_one() {
            // If A and B both have single terms, one might be the inverse
            if eq.a_terms.len() == 1 && eq.b_terms.len() == 1 {
                return Some(format!("x{}", eq.a_terms[0].0));
            }
        }
        None
    }

    /// Analyze constraint dependencies
    pub fn analyze_dependencies(&self, constraints: &[ConstraintEquation]) -> DependencyGraph {
        let mut graph = DependencyGraph::new();

        for eq in constraints {
            let signals: Vec<usize> = eq
                .a_terms
                .iter()
                .chain(eq.b_terms.iter())
                .chain(eq.c_terms.iter())
                .map(|(idx, _)| *idx)
                .collect();

            graph.add_constraint(eq.id, signals);
        }

        graph
    }
}

impl Default for PropertyExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// Dependency graph between constraints and signals
#[derive(Debug, Clone)]
pub struct DependencyGraph {
    /// Constraint ID -> Signal indices it depends on
    constraint_to_signals: HashMap<usize, Vec<usize>>,
    /// Signal index -> Constraint IDs that use it
    signal_to_constraints: HashMap<usize, Vec<usize>>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self {
            constraint_to_signals: HashMap::new(),
            signal_to_constraints: HashMap::new(),
        }
    }

    /// Add a constraint with its signal dependencies
    pub fn add_constraint(&mut self, constraint_id: usize, signals: Vec<usize>) {
        for &signal in &signals {
            self.signal_to_constraints
                .entry(signal)
                .or_default()
                .push(constraint_id);
        }
        self.constraint_to_signals.insert(constraint_id, signals);
    }

    /// Get signals used by a constraint
    pub fn get_constraint_signals(&self, constraint_id: usize) -> Option<&Vec<usize>> {
        self.constraint_to_signals.get(&constraint_id)
    }

    /// Get constraints that use a signal
    pub fn get_signal_constraints(&self, signal: usize) -> Option<&Vec<usize>> {
        self.signal_to_constraints.get(&signal)
    }

    /// Find strongly connected components (for detecting cyclic dependencies)
    pub fn find_cycles(&self) -> Vec<Vec<usize>> {
        // Simplified cycle detection - returns empty for now
        // A full implementation would use Tarjan's algorithm
        Vec::new()
    }

    /// Get topological order of constraints
    pub fn topological_order(&self) -> Result<Vec<usize>, String> {
        // Simplified topological sort
        Ok(self.constraint_to_signals.keys().cloned().collect())
    }
}

impl Default for DependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Validates extracted properties
pub struct PropertyValidator {
    /// Properties to validate
    properties: Vec<CircuitProperty>,
    /// Validation results
    results: Vec<ValidationResult>,
}

/// Result of property validation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub property: CircuitProperty,
    pub valid: bool,
    pub counterexample: Option<HashMap<String, FieldElement>>,
    pub message: String,
}

impl PropertyValidator {
    pub fn new(properties: Vec<CircuitProperty>) -> Self {
        Self {
            properties,
            results: Vec::new(),
        }
    }

    /// Validate all properties using the symbolic solver
    pub fn validate_all(&mut self) -> &[ValidationResult] {
        for property in &self.properties {
            let result = self.validate_property(property);
            self.results.push(result);
        }
        &self.results
    }

    /// Validate a single property
    fn validate_property(&self, property: &CircuitProperty) -> ValidationResult {
        // For now, mark all properties as requiring proof
        ValidationResult {
            property: property.clone(),
            valid: false,
            counterexample: None,
            message: "Requires formal proof".to_string(),
        }
    }

    /// Get validation results
    pub fn results(&self) -> &[ValidationResult] {
        &self.results
    }

    /// Get invalid properties
    pub fn invalid_properties(&self) -> Vec<&ValidationResult> {
        self.results.iter().filter(|r| !r.valid).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_extractor_creation() {
        let extractor = PropertyExtractor::new();
        assert!(extractor.boolean_signals.is_empty());
    }

    #[test]
    fn test_circuit_property_variables() {
        let prop = CircuitProperty::Boolean {
            signal: "x".to_string(),
        };
        let vars = prop.variables();
        assert!(vars.contains("x"));
    }

    #[test]
    fn test_dependency_graph() {
        let mut graph = DependencyGraph::new();
        graph.add_constraint(0, vec![1, 2, 3]);
        graph.add_constraint(1, vec![2, 4]);

        assert_eq!(graph.get_constraint_signals(0), Some(&vec![1, 2, 3]));
        assert!(graph.get_signal_constraints(2).unwrap().contains(&0));
        assert!(graph.get_signal_constraints(2).unwrap().contains(&1));
    }
}
