//! Constraint Complexity Analysis
//!
//! Analyzes circuit complexity metrics:
//! - R1CS constraint count
//! - Gate count (for PLONK-style circuits)
//! - Signal count
//! - Constraint density
//! - Theoretical vs actual complexity

use zk_core::CircuitInfo;
use zk_core::CircuitExecutor;
use std::sync::Arc;

/// Complexity metrics for a circuit
#[derive(Debug, Clone)]
pub struct ComplexityMetrics {
    /// Number of R1CS constraints
    pub r1cs_constraints: usize,
    /// Number of PLONK gates (if applicable)
    pub plonk_gates: Option<usize>,
    /// Number of signals (wires)
    pub signal_count: usize,
    /// Number of public inputs
    pub public_inputs: usize,
    /// Number of private inputs
    pub private_inputs: usize,
    /// Number of outputs
    pub outputs: usize,
    /// Constraint density (constraints per signal)
    pub constraint_density: f64,
    /// Degrees of freedom (signals - constraints)
    pub degrees_of_freedom: i64,
    /// Is the circuit likely underconstrained?
    pub likely_underconstrained: bool,
    /// Optimization suggestions
    pub optimization_suggestions: Vec<OptimizationSuggestion>,
}

/// Suggestion for circuit optimization
#[derive(Debug, Clone)]
pub struct OptimizationSuggestion {
    pub category: OptimizationCategory,
    pub description: String,
    pub estimated_savings: Option<String>,
    pub priority: OptimizationPriority,
}

/// Category of optimization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptimizationCategory {
    /// Reduce constraint count
    ConstraintReduction,
    /// Reduce signal count
    SignalReduction,
    /// Use more efficient operations
    OperationOptimization,
    /// Restructure circuit
    StructuralOptimization,
    /// Use lookup tables
    LookupOptimization,
    /// Parallelize operations
    Parallelization,
}

/// Priority of optimization
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OptimizationPriority {
    High,
    Medium,
    Low,
}

/// Complexity analyzer
pub struct ComplexityAnalyzer {
    /// Known optimal constraint counts for common operations
    known_optimums: std::collections::HashMap<String, usize>,
}

impl Default for ComplexityAnalyzer {
    fn default() -> Self {
        let mut known_optimums = std::collections::HashMap::new();

        // Known optimal constraint counts for common operations in BN254
        known_optimums.insert("sha256_per_block".to_string(), 25000);
        known_optimums.insert("poseidon_per_hash".to_string(), 300);
        known_optimums.insert("eddsa_signature".to_string(), 6000);
        known_optimums.insert("merkle_proof_per_level".to_string(), 400);
        known_optimums.insert("range_check_64bit".to_string(), 64);
        known_optimums.insert("comparison_256bit".to_string(), 256);

        Self { known_optimums }
    }
}

impl ComplexityAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyze complexity of a circuit executor
    pub fn analyze(&self, executor: &Arc<dyn CircuitExecutor>) -> ComplexityMetrics {
        let info = executor.circuit_info();
        self.analyze_info(&info)
    }

    /// Analyze complexity from circuit info
    pub fn analyze_info(&self, info: &CircuitInfo) -> ComplexityMetrics {
        let signal_count = info.num_private_inputs + info.num_public_inputs + info.num_outputs;
        let constraint_density = if signal_count > 0 {
            info.num_constraints as f64 / signal_count as f64
        } else {
            0.0
        };

        let degrees_of_freedom = info.degrees_of_freedom();
        let likely_underconstrained = degrees_of_freedom > 0;

        let optimization_suggestions = self.generate_suggestions(info, constraint_density);

        ComplexityMetrics {
            r1cs_constraints: info.num_constraints,
            plonk_gates: None, // Would need PLONK-specific analysis
            signal_count,
            public_inputs: info.num_public_inputs,
            private_inputs: info.num_private_inputs,
            outputs: info.num_outputs,
            constraint_density,
            degrees_of_freedom,
            likely_underconstrained,
            optimization_suggestions,
        }
    }

    fn generate_suggestions(
        &self,
        info: &CircuitInfo,
        constraint_density: f64,
    ) -> Vec<OptimizationSuggestion> {
        let mut suggestions = Vec::new();

        // Check for underconstraint
        if info.degrees_of_freedom() > 0 {
            suggestions.push(OptimizationSuggestion {
                category: OptimizationCategory::ConstraintReduction,
                description: format!(
                    "Circuit has {} degrees of freedom. Add constraints or reduce signals.",
                    info.degrees_of_freedom()
                ),
                estimated_savings: None,
                priority: OptimizationPriority::High,
            });
        }

        // Check constraint density
        if constraint_density < 0.5 {
            suggestions.push(OptimizationSuggestion {
                category: OptimizationCategory::SignalReduction,
                description: format!(
                    "Low constraint density ({:.2}). Consider combining intermediate signals.",
                    constraint_density
                ),
                estimated_savings: Some("10-30% signal reduction possible".to_string()),
                priority: OptimizationPriority::Medium,
            });
        }

        // Check for large circuits that might benefit from recursion
        if info.num_constraints > 100_000 {
            suggestions.push(OptimizationSuggestion {
                category: OptimizationCategory::StructuralOptimization,
                description: format!(
                    "Large circuit ({} constraints). Consider recursive proof composition.",
                    info.num_constraints
                ),
                estimated_savings: Some("Reduced prover time, parallel proving".to_string()),
                priority: OptimizationPriority::High,
            });
        }

        // Check for medium-sized circuits that might benefit from lookups
        if info.num_constraints > 10_000 {
            suggestions.push(OptimizationSuggestion {
                category: OptimizationCategory::LookupOptimization,
                description: "Consider using lookup tables for common operations (range checks, bitwise ops).".to_string(),
                estimated_savings: Some("2-10x constraint reduction for lookups".to_string()),
                priority: OptimizationPriority::Medium,
            });
        }

        suggestions
    }

    /// Compare circuit against known optimal implementations
    pub fn compare_to_optimal(
        &self,
        circuit_name: &str,
        actual_constraints: usize,
    ) -> Option<ComplexityComparison> {
        self.known_optimums.get(circuit_name).map(|&optimal| {
            let overhead = if optimal > 0 {
                (actual_constraints as f64 / optimal as f64 - 1.0) * 100.0
            } else {
                0.0
            };

            ComplexityComparison {
                circuit_name: circuit_name.to_string(),
                actual_constraints,
                optimal_constraints: optimal,
                overhead_percent: overhead,
                is_optimal: overhead < 10.0, // Within 10% is considered optimal
            }
        })
    }

    /// Estimate circuit complexity for common operations
    pub fn estimate_complexity(&self, operation: &str, count: usize) -> Option<usize> {
        self.known_optimums
            .get(operation)
            .map(|&per_op| per_op * count)
    }
}

/// Comparison to optimal implementation
#[derive(Debug, Clone)]
pub struct ComplexityComparison {
    pub circuit_name: String,
    pub actual_constraints: usize,
    pub optimal_constraints: usize,
    pub overhead_percent: f64,
    pub is_optimal: bool,
}

/// Detailed constraint breakdown
#[derive(Debug, Clone)]
pub struct ConstraintBreakdown {
    /// Constraints by operation type
    pub by_operation: std::collections::HashMap<String, usize>,
    /// Constraints per component
    pub by_component: std::collections::HashMap<String, usize>,
    /// Most expensive operations
    pub hotspots: Vec<(String, usize)>,
}

impl ConstraintBreakdown {
    pub fn new() -> Self {
        Self {
            by_operation: std::collections::HashMap::new(),
            by_component: std::collections::HashMap::new(),
            hotspots: Vec::new(),
        }
    }

    /// Add constraints for an operation
    pub fn add_operation(&mut self, operation: &str, count: usize) {
        *self.by_operation.entry(operation.to_string()).or_insert(0) += count;
    }

    /// Add constraints for a component
    pub fn add_component(&mut self, component: &str, count: usize) {
        *self.by_component.entry(component.to_string()).or_insert(0) += count;
    }

    /// Compute hotspots (top N most expensive)
    pub fn compute_hotspots(&mut self, n: usize) {
        let mut all: Vec<_> = self
            .by_operation
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        all.sort_by_key(|(_, v)| std::cmp::Reverse(*v));
        self.hotspots = all.into_iter().take(n).collect();
    }
}

impl Default for ConstraintBreakdown {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::MockCircuitExecutor;

    #[test]
    fn test_complexity_analyzer() {
        let analyzer = ComplexityAnalyzer::new();
        let executor: Arc<dyn CircuitExecutor> = Arc::new(MockCircuitExecutor::new("test", 10, 2));

        let metrics = analyzer.analyze(&executor);

        assert!(metrics.signal_count > 0);
    }

    #[test]
    fn test_complexity_comparison() {
        let analyzer = ComplexityAnalyzer::new();

        let comparison = analyzer.compare_to_optimal("poseidon_per_hash", 350);
        assert!(comparison.is_some());

        let comp = comparison.unwrap();
        assert!(comp.overhead_percent > 0.0);
    }

    #[test]
    fn test_constraint_breakdown() {
        let mut breakdown = ConstraintBreakdown::new();
        breakdown.add_operation("mul", 100);
        breakdown.add_operation("add", 50);
        breakdown.add_operation("range_check", 200);
        breakdown.compute_hotspots(2);

        assert_eq!(breakdown.hotspots.len(), 2);
        assert_eq!(breakdown.hotspots[0].0, "range_check");
    }
}
