//! Witness-Dependency Graph Analysis
//!
//! Builds and analyzes the dependency graph between circuit inputs and constraints.
//! Used to identify:
//! - Which inputs influence which constraints
//! - Uncovered dependency paths
//! - Optimal inputs to cover missing paths
//!
//! # Example
//!
//! ```rust,ignore
//! use zk_fuzzer::analysis::dependency::{DependencyGraph, DependencyAnalyzer};
//!
//! let analyzer = DependencyAnalyzer::new();
//! let graph = analyzer.build_graph(&executor)?;
//!
//! // Find inputs that influence constraint 42
//! let inputs = graph.inputs_for_constraint(42);
//!
//! // Get uncovered dependency paths
//! let uncovered = graph.uncovered_paths(&coverage);
//! ```

use std::collections::{HashMap, HashSet, VecDeque};
use zk_core::{CircuitExecutor, ConstraintEquation, ConstraintInspector, CoverageMap};

/// Unique identifier for a constraint
pub type ConstraintId = usize;

/// Unique identifier for an input wire
pub type InputId = usize;

/// Dependency graph between inputs and constraints
#[derive(Debug, Clone, Default)]
pub struct DependencyGraph {
    /// Map from input wire index to constraints it influences
    pub input_influences: HashMap<InputId, HashSet<ConstraintId>>,

    /// Map from constraint to input wires it depends on
    pub constraint_depends: HashMap<ConstraintId, HashSet<InputId>>,

    /// Direct constraint-to-constraint dependencies
    pub constraint_graph: HashMap<ConstraintId, HashSet<ConstraintId>>,

    /// Paths through constraints that haven't been covered
    pub uncovered_paths: Vec<Vec<ConstraintId>>,

    /// Total number of inputs
    pub num_inputs: usize,

    /// Total number of constraints
    pub num_constraints: usize,
}

impl DependencyGraph {
    /// Create a new empty dependency graph
    pub fn new(num_inputs: usize, num_constraints: usize) -> Self {
        Self {
            input_influences: HashMap::new(),
            constraint_depends: HashMap::new(),
            constraint_graph: HashMap::new(),
            uncovered_paths: Vec::new(),
            num_inputs,
            num_constraints,
        }
    }

    /// Get all inputs that influence a given constraint
    pub fn inputs_for_constraint(&self, constraint_id: ConstraintId) -> HashSet<InputId> {
        self.constraint_depends
            .get(&constraint_id)
            .cloned()
            .map_or(HashSet::new(), |v| v)
    }

    /// Get all constraints influenced by a given input
    pub fn constraints_for_input(&self, input_id: InputId) -> HashSet<ConstraintId> {
        self.input_influences
            .get(&input_id)
            .cloned()
            .map_or(HashSet::new(), |v| v)
    }

    /// Add an edge from input to constraint
    pub fn add_input_influence(&mut self, input_id: InputId, constraint_id: ConstraintId) {
        self.input_influences
            .entry(input_id)
            .or_default()
            .insert(constraint_id);
        self.constraint_depends
            .entry(constraint_id)
            .or_default()
            .insert(input_id);
    }

    /// Add a constraint-to-constraint dependency
    pub fn add_constraint_edge(&mut self, from: ConstraintId, to: ConstraintId) {
        self.constraint_graph.entry(from).or_default().insert(to);
    }

    /// Compute uncovered paths given current coverage
    pub fn compute_uncovered_paths(&mut self, coverage: &CoverageMap, max_depth: usize) {
        self.uncovered_paths.clear();

        // Find uncovered constraints
        let uncovered: HashSet<ConstraintId> = (0..self.num_constraints)
            .filter(|c| !coverage.constraint_hits.contains_key(c))
            .collect();

        if uncovered.is_empty() {
            return;
        }

        // Find paths to uncovered constraints using BFS
        for &target in &uncovered {
            if let Some(path) = self.find_path_to_constraint(target, coverage, max_depth) {
                if !path.is_empty() {
                    self.uncovered_paths.push(path);
                }
            }
        }

        // Sort paths by length (shorter paths are more actionable)
        self.uncovered_paths.sort_by_key(|p| p.len());

        // Keep only top paths to avoid explosion
        self.uncovered_paths.truncate(100);
    }

    /// Find a path from a covered constraint to an uncovered target
    fn find_path_to_constraint(
        &self,
        target: ConstraintId,
        coverage: &CoverageMap,
        max_depth: usize,
    ) -> Option<Vec<ConstraintId>> {
        // BFS from covered constraints to target
        let mut visited: HashSet<ConstraintId> = HashSet::new();
        let mut queue: VecDeque<(ConstraintId, Vec<ConstraintId>)> = VecDeque::new();

        // Start from covered constraints
        for &covered in coverage.constraint_hits.keys() {
            queue.push_back((covered, vec![covered]));
        }

        while let Some((current, path)) = queue.pop_front() {
            if path.len() > max_depth {
                continue;
            }

            if current == target {
                return Some(path);
            }

            if visited.contains(&current) {
                continue;
            }
            visited.insert(current);

            // Explore neighbors
            if let Some(neighbors) = self.constraint_graph.get(&current) {
                for &neighbor in neighbors {
                    let mut new_path = path.clone();
                    new_path.push(neighbor);
                    queue.push_back((neighbor, new_path));
                }
            }
        }

        // No path found, return just the target
        Some(vec![target])
    }

    /// Suggest inputs to cover a specific uncovered constraint
    pub fn suggest_inputs_for_coverage(&self, constraint_id: ConstraintId) -> Vec<InputId> {
        let mut inputs: Vec<InputId> = self
            .inputs_for_constraint(constraint_id)
            .into_iter()
            .collect();
        inputs.sort();
        inputs
    }

    /// Get coverage statistics
    pub fn coverage_stats(&self, coverage: &CoverageMap) -> DependencyCoverageStats {
        let covered_constraints = coverage.constraint_hits.len();
        let total_constraints = self.num_constraints;

        let mut covered_input_paths = 0;
        let mut total_input_paths = 0;

        for constraints in self.input_influences.values() {
            total_input_paths += constraints.len();
            for constraint in constraints {
                if coverage.constraint_hits.contains_key(constraint) {
                    covered_input_paths += 1;
                }
            }
        }

        let critical_uncovered = self.identify_critical_uncovered(coverage);

        DependencyCoverageStats {
            covered_constraints,
            total_constraints,
            constraint_coverage_percent: if total_constraints > 0 {
                (covered_constraints as f64 / total_constraints as f64) * 100.0
            } else {
                100.0
            },
            covered_input_paths,
            total_input_paths,
            input_path_coverage_percent: if total_input_paths > 0 {
                (covered_input_paths as f64 / total_input_paths as f64) * 100.0
            } else {
                100.0
            },
            uncovered_path_count: self.uncovered_paths.len(),
            critical_uncovered_count: critical_uncovered.len(),
            critical_uncovered,
        }
    }

    /// Identify critical uncovered constraints (high connectivity)
    fn identify_critical_uncovered(&self, coverage: &CoverageMap) -> Vec<ConstraintId> {
        let mut uncovered_with_degree: Vec<(ConstraintId, usize)> = (0..self.num_constraints)
            .filter(|c| !coverage.constraint_hits.contains_key(c))
            .map(|c| {
                let in_degree = self
                    .constraint_depends
                    .get(&c)
                    .map(|s| s.len())
                    .map_or(0, |v| v);
                let out_degree = self
                    .constraint_graph
                    .get(&c)
                    .map(|s| s.len())
                    .map_or(0, |v| v);
                (c, in_degree + out_degree)
            })
            .collect();

        // Sort by degree descending (highest connectivity first)
        uncovered_with_degree.sort_by(|a, b| b.1.cmp(&a.1));

        uncovered_with_degree
            .into_iter()
            .take(10)
            .map(|(c, _)| c)
            .collect()
    }

    /// Export graph to DOT format for visualization
    pub fn to_dot(&self) -> String {
        let mut dot = String::new();
        dot.push_str("digraph DependencyGraph {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box];\n\n");

        // Input nodes
        dot.push_str("  subgraph cluster_inputs {\n");
        dot.push_str("    label=\"Inputs\";\n");
        dot.push_str("    style=dotted;\n");
        for input_id in 0..self.num_inputs {
            dot.push_str(&format!(
                "    input_{} [label=\"Input {}\", shape=ellipse, color=blue];\n",
                input_id, input_id
            ));
        }
        dot.push_str("  }\n\n");

        // Constraint nodes
        dot.push_str("  subgraph cluster_constraints {\n");
        dot.push_str("    label=\"Constraints\";\n");
        dot.push_str("    style=dotted;\n");
        for constraint_id in 0..self.num_constraints.min(50) {
            dot.push_str(&format!(
                "    constraint_{} [label=\"C{}\"];\n",
                constraint_id, constraint_id
            ));
        }
        dot.push_str("  }\n\n");

        // Input -> Constraint edges
        for (input_id, constraints) in &self.input_influences {
            for constraint_id in constraints {
                if *constraint_id < 50 {
                    dot.push_str(&format!(
                        "  input_{} -> constraint_{} [color=blue];\n",
                        input_id, constraint_id
                    ));
                }
            }
        }

        // Constraint -> Constraint edges
        for (from, tos) in &self.constraint_graph {
            for to in tos {
                if *from < 50 && *to < 50 {
                    dot.push_str(&format!(
                        "  constraint_{} -> constraint_{} [color=gray];\n",
                        from, to
                    ));
                }
            }
        }

        dot.push_str("}\n");
        dot
    }
}

/// Statistics about dependency coverage
#[derive(Debug, Clone)]
pub struct DependencyCoverageStats {
    pub covered_constraints: usize,
    pub total_constraints: usize,
    pub constraint_coverage_percent: f64,
    pub covered_input_paths: usize,
    pub total_input_paths: usize,
    pub input_path_coverage_percent: f64,
    pub uncovered_path_count: usize,
    pub critical_uncovered_count: usize,
    pub critical_uncovered: Vec<ConstraintId>,
}

/// Dependency analyzer for building graphs from circuit executors
pub struct DependencyAnalyzer {
    /// Maximum depth for path analysis
    max_path_depth: usize,
}

impl Default for DependencyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl DependencyAnalyzer {
    /// Create a new dependency analyzer
    pub fn new() -> Self {
        Self { max_path_depth: 10 }
    }

    /// Set maximum path depth
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_path_depth = depth;
        self
    }

    /// Build dependency graph from circuit executor
    pub fn build_graph(&self, executor: &dyn CircuitExecutor) -> anyhow::Result<DependencyGraph> {
        let circuit_info = executor.circuit_info();
        let num_inputs = circuit_info.num_public_inputs + circuit_info.num_private_inputs;
        let num_constraints = executor.num_constraints();

        let mut graph = DependencyGraph::new(num_inputs, num_constraints);

        // If executor supports constraint inspection, use it
        if let Some(inspector) = executor.constraint_inspector() {
            self.build_from_inspector(&mut graph, inspector)?;
        } else {
            anyhow::bail!(
                "Dependency analysis requires a constraint inspector; {:?} does not provide one",
                executor.framework()
            );
        }

        Ok(graph)
    }

    /// Build graph from constraint inspector
    fn build_from_inspector(
        &self,
        graph: &mut DependencyGraph,
        inspector: &dyn ConstraintInspector,
    ) -> anyhow::Result<()> {
        let constraints = inspector.get_constraints();

        for (constraint_id, constraint) in constraints.iter().enumerate() {
            // Extract wire indices from constraint
            let wire_refs = self.extract_wire_refs(constraint);

            for wire_ref in wire_refs {
                // Check if wire is an input (low index typically)
                if wire_ref < graph.num_inputs {
                    graph.add_input_influence(wire_ref, constraint_id);
                }
            }
        }

        // Build constraint-to-constraint edges based on shared wires
        self.build_constraint_edges(graph, &constraints);

        Ok(())
    }

    /// Extract wire references from a constraint equation
    fn extract_wire_refs(&self, constraint: &ConstraintEquation) -> Vec<usize> {
        let mut refs = Vec::new();

        // Extract signal indices from linear combinations (R1CS: a * b = c)
        // a_terms, b_terms, c_terms are Vec<(signal_index, coefficient)>
        for (wire, _coeff) in &constraint.a_terms {
            refs.push(*wire);
        }
        for (wire, _coeff) in &constraint.b_terms {
            refs.push(*wire);
        }
        for (wire, _coeff) in &constraint.c_terms {
            refs.push(*wire);
        }

        refs.sort();
        refs.dedup();
        refs
    }

    /// Build constraint edges based on shared wires
    fn build_constraint_edges(
        &self,
        graph: &mut DependencyGraph,
        constraints: &[ConstraintEquation],
    ) {
        // Map wire to constraints that use it
        let mut wire_to_constraints: HashMap<usize, Vec<usize>> = HashMap::new();

        for (constraint_id, constraint) in constraints.iter().enumerate() {
            let wires = self.extract_wire_refs(constraint);
            for wire in wires {
                wire_to_constraints
                    .entry(wire)
                    .or_default()
                    .push(constraint_id);
            }
        }

        // Create edges between constraints that share wires
        for constraint_ids in wire_to_constraints.values() {
            for i in 0..constraint_ids.len() {
                for j in i + 1..constraint_ids.len() {
                    let c1 = constraint_ids[i];
                    let c2 = constraint_ids[j];
                    // Add bidirectional edges
                    graph.add_constraint_edge(c1, c2);
                    graph.add_constraint_edge(c2, c1);
                }
            }
        }
    }

    /// Analyze coverage and compute uncovered paths
    pub fn analyze_coverage(
        &self,
        graph: &mut DependencyGraph,
        coverage: &CoverageMap,
    ) -> DependencyCoverageStats {
        graph.compute_uncovered_paths(coverage, self.max_path_depth);
        graph.coverage_stats(coverage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dependency_graph_creation() {
        let mut graph = DependencyGraph::new(5, 10);

        graph.add_input_influence(0, 0);
        graph.add_input_influence(0, 1);
        graph.add_input_influence(1, 1);
        graph.add_input_influence(1, 2);

        assert_eq!(graph.constraints_for_input(0).len(), 2);
        assert_eq!(graph.constraints_for_input(1).len(), 2);
        assert_eq!(graph.inputs_for_constraint(1).len(), 2);
    }

    #[test]
    fn test_coverage_stats() {
        let mut graph = DependencyGraph::new(3, 5);

        // Setup: input 0 influences constraints 0,1,2
        for c in 0..3 {
            graph.add_input_influence(0, c);
        }
        // Input 1 influences constraints 3,4
        for c in 3..5 {
            graph.add_input_influence(1, c);
        }

        // Coverage: only constraints 0,1 covered
        let mut coverage = CoverageMap::new();
        coverage.record_hit(0);
        coverage.record_hit(1);
        coverage.max_coverage = 5;

        let stats = graph.coverage_stats(&coverage);

        assert_eq!(stats.covered_constraints, 2);
        assert_eq!(stats.total_constraints, 5);
        assert!((stats.constraint_coverage_percent - 40.0).abs() < 0.1);
    }

    #[test]
    fn test_suggest_inputs() {
        let mut graph = DependencyGraph::new(3, 3);

        graph.add_input_influence(0, 0);
        graph.add_input_influence(1, 0);
        graph.add_input_influence(2, 1);

        let inputs = graph.suggest_inputs_for_coverage(0);
        assert_eq!(inputs.len(), 2);
        assert!(inputs.contains(&0));
        assert!(inputs.contains(&1));
    }

    #[test]
    fn test_dot_export() {
        let mut graph = DependencyGraph::new(2, 3);
        graph.add_input_influence(0, 0);
        graph.add_input_influence(1, 1);
        graph.add_constraint_edge(0, 1);

        let dot = graph.to_dot();

        assert!(dot.contains("digraph DependencyGraph"));
        assert!(dot.contains("input_0"));
        assert!(dot.contains("constraint_0"));
    }
}
