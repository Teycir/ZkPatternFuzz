//! Circuit execution abstraction layer
//!
//! Provides a unified interface for executing ZK circuits across different backends.
//! Separates mock execution from real circuit execution for testing and production use.

mod coverage;
mod mock;
mod traits;

pub use coverage::*;
pub use mock::*;
pub use traits::*;

// Re-export CircuitInfo for external use
pub use zk_core::CircuitInfo;

use crate::analysis::{ConstraintChecker, UnknownLookupPolicy};
use zk_core::{FieldElement, Framework};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

/// Options for controlling executor creation (e.g., build directory overrides).
#[derive(Debug, Clone, Default)]
pub struct ExecutorFactoryOptions {
    /// Base directory for build artifacts (per-framework subdirs will be created).
    pub build_dir_base: Option<PathBuf>,
    /// Explicit build directory for Circom.
    pub circom_build_dir: Option<PathBuf>,
    /// Explicit build directory for Noir.
    pub noir_build_dir: Option<PathBuf>,
    /// Explicit build directory for Halo2.
    pub halo2_build_dir: Option<PathBuf>,
    /// Explicit build directory for Cairo.
    pub cairo_build_dir: Option<PathBuf>,
}

impl ExecutorFactoryOptions {
    fn resolve_build_dir(
        &self,
        framework: Framework,
        circuit_path: &str,
        main_component: &str,
    ) -> Option<PathBuf> {
        let specific = match framework {
            Framework::Circom => self.circom_build_dir.as_ref(),
            Framework::Noir => self.noir_build_dir.as_ref(),
            Framework::Halo2 => self.halo2_build_dir.as_ref(),
            Framework::Cairo => self.cairo_build_dir.as_ref(),
            Framework::Mock => None,
        };

        if let Some(path) = specific {
            return Some(path.clone());
        }

        let base = self.build_dir_base.as_ref()?;
        let mut dir = base.clone();
        dir.push(framework_dir_name(framework));
        dir.push(derive_circuit_build_name(circuit_path, main_component));
        Some(dir)
    }
}

fn framework_dir_name(framework: Framework) -> &'static str {
    match framework {
        Framework::Circom => "circom",
        Framework::Noir => "noir",
        Framework::Halo2 => "halo2",
        Framework::Cairo => "cairo",
        Framework::Mock => "mock",
    }
}

fn derive_circuit_build_name(circuit_path: &str, main_component: &str) -> String {
    let path = Path::new(circuit_path);
    let name = if path.is_dir() {
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("circuit")
            .to_string()
    } else {
        path.file_stem()
            .or_else(|| path.file_name())
            .and_then(|s| s.to_str())
            .unwrap_or("circuit")
            .to_string()
    };

    let mut combined = name;
    if !main_component.is_empty() && !combined.contains(main_component) {
        combined = format!("{}_{}", combined, main_component);
    }

    sanitize_component(&combined)
}

fn sanitize_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }

    if out.is_empty() {
        "circuit".to_string()
    } else {
        out
    }
}

/// Factory for creating circuit executors based on framework type
pub struct ExecutorFactory;

impl ExecutorFactory {
    /// Create an executor for the given framework and circuit
    pub fn create(
        framework: Framework,
        circuit_path: &str,
        main_component: &str,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        Self::create_with_options(
            framework,
            circuit_path,
            main_component,
            &ExecutorFactoryOptions::default(),
        )
    }

    /// Create an executor with explicit factory options (e.g., build dir overrides).
    pub fn create_with_options(
        framework: Framework,
        circuit_path: &str,
        main_component: &str,
        options: &ExecutorFactoryOptions,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        match framework {
            Framework::Mock => Ok(Arc::new(MockCircuitExecutor::new(
                main_component,
                10, // default private inputs
                2,  // default public inputs
            ))),
            Framework::Circom => {
                Self::create_circom_executor(circuit_path, main_component, options)
            }
            Framework::Noir => Self::create_noir_executor(circuit_path, main_component, options),
            Framework::Halo2 => Self::create_halo2_executor(circuit_path, main_component, options),
            Framework::Cairo => Self::create_cairo_executor(circuit_path, main_component, options),
        }
    }

    /// Create a Circom executor
    fn create_circom_executor(
        circuit_path: &str,
        main_component: &str,
        options: &ExecutorFactoryOptions,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        use crate::targets::CircomTarget;

        // Check if circom is available
        match CircomTarget::check_circom_available() {
            Ok(version) => {
                tracing::info!("Using Circom backend: {}", version);
                let build_dir =
                    options.resolve_build_dir(Framework::Circom, circuit_path, main_component);
                let executor = match build_dir {
                    Some(dir) => {
                        CircomExecutor::new_with_build_dir(circuit_path, main_component, dir)?
                    }
                    None => CircomExecutor::new(circuit_path, main_component)?,
                };
                Ok(Arc::new(executor))
            }
            Err(e) => {
                tracing::warn!("Circom not available ({}), using mock executor", e);
                Ok(Arc::new(
                    MockCircuitExecutor::new(main_component, 10, 2)
                        .with_framework(Framework::Circom)
                        .with_circuit_path(circuit_path),
                ))
            }
        }
    }

    /// Create a Noir executor
    fn create_noir_executor(
        circuit_path: &str,
        main_component: &str,
        options: &ExecutorFactoryOptions,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        use crate::targets::NoirTarget;

        match NoirTarget::check_nargo_available() {
            Ok(version) => {
                tracing::info!("Using Noir backend: {}", version);
                let build_dir =
                    options.resolve_build_dir(Framework::Noir, circuit_path, main_component);
                let executor = match build_dir {
                    Some(dir) => NoirExecutor::new_with_build_dir(circuit_path, dir)?,
                    None => NoirExecutor::new(circuit_path)?,
                };
                Ok(Arc::new(executor))
            }
            Err(e) => {
                tracing::warn!("Nargo not available ({}), using mock executor", e);
                Ok(Arc::new(
                    MockCircuitExecutor::new(main_component, 10, 2)
                        .with_framework(Framework::Noir)
                        .with_circuit_path(circuit_path),
                ))
            }
        }
    }

    /// Create a Halo2 executor
    fn create_halo2_executor(
        circuit_path: &str,
        main_component: &str,
        options: &ExecutorFactoryOptions,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        let build_dir = options.resolve_build_dir(Framework::Halo2, circuit_path, main_component);
        let executor = match build_dir {
            Some(dir) => Halo2Executor::new_with_build_dir(circuit_path, main_component, dir)?,
            None => Halo2Executor::new(circuit_path, main_component)?,
        };
        Ok(Arc::new(executor))
    }

    /// Create a Cairo executor
    fn create_cairo_executor(
        circuit_path: &str,
        main_component: &str,
        options: &ExecutorFactoryOptions,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        use crate::targets::CairoTarget;

        match CairoTarget::check_cairo_available() {
            Ok((version, ver_str)) => {
                tracing::info!("Using Cairo backend ({:?}): {}", version, ver_str);
                let build_dir =
                    options.resolve_build_dir(Framework::Cairo, circuit_path, main_component);
                let executor = match build_dir {
                    Some(dir) => CairoExecutor::new_with_build_dir(circuit_path, dir)?,
                    None => CairoExecutor::new(circuit_path)?,
                };
                Ok(Arc::new(executor))
            }
            Err(e) => {
                tracing::warn!("Cairo not available ({}), using mock executor", e);
                Ok(Arc::new(
                    MockCircuitExecutor::new(main_component, 10, 2)
                        .with_framework(Framework::Cairo)
                        .with_circuit_path(circuit_path),
                ))
            }
        }
    }

    /// Create a mock executor for testing
    pub fn create_mock(
        name: &str,
        private_inputs: usize,
        public_inputs: usize,
    ) -> Arc<dyn CircuitExecutor> {
        Arc::new(MockCircuitExecutor::new(
            name,
            private_inputs,
            public_inputs,
        ))
    }
}

/// Circom executor wrapper
pub struct CircomExecutor {
    target: crate::targets::CircomTarget,
    constraints: OnceLock<Vec<ConstraintEquation>>,
}

impl CircomExecutor {
    pub fn new(circuit_path: &str, main_component: &str) -> anyhow::Result<Self> {
        let mut target = crate::targets::CircomTarget::new(circuit_path, main_component)?;
        target.compile()?;
        Ok(Self {
            target,
            constraints: OnceLock::new(),
        })
    }

    pub fn new_with_build_dir(
        circuit_path: &str,
        main_component: &str,
        build_dir: PathBuf,
    ) -> anyhow::Result<Self> {
        let mut target = crate::targets::CircomTarget::new(circuit_path, main_component)?
            .with_build_dir(build_dir);
        target.compile()?;
        Ok(Self {
            target,
            constraints: OnceLock::new(),
        })
    }
}

#[async_trait]
impl CircuitExecutor for CircomExecutor {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn name(&self) -> &str {
        use crate::targets::TargetCircuit;
        self.target.name()
    }

    fn circuit_info(&self) -> CircuitInfo {
        use crate::targets::TargetCircuit;
        CircuitInfo {
            name: self.target.name().to_string(),
            num_constraints: self.target.num_constraints(),
            num_private_inputs: self.target.num_private_inputs(),
            num_public_inputs: self.target.num_public_inputs(),
            num_outputs: 1,
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        use crate::targets::TargetCircuit;
        let start = std::time::Instant::now();

        match self.target.execute(inputs) {
            Ok(outputs) => {
                let coverage = ExecutionCoverage::with_output_hash(&outputs);
                ExecutionResult::success(outputs, coverage)
                    .with_time(start.elapsed().as_micros() as u64)
            }
            Err(e) => ExecutionResult::failure(e.to_string()),
        }
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        use crate::targets::TargetCircuit;
        self.target.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        use crate::targets::TargetCircuit;
        self.target.verify(proof, public_inputs)
    }

    fn constraint_inspector(&self) -> Option<&dyn ConstraintInspector> {
        Some(self)
    }
}

impl ConstraintInspector for CircomExecutor {
    fn get_constraints(&self) -> Vec<ConstraintEquation> {
        self.constraints
            .get_or_init(|| self.target.load_constraints().unwrap_or_default())
            .clone()
    }

    fn check_constraints(&self, witness: &[FieldElement]) -> Vec<ConstraintResult> {
        fn eval_linear(terms: &[(usize, FieldElement)], witness: &[FieldElement]) -> FieldElement {
            let mut acc = FieldElement::zero();
            for (idx, coeff) in terms {
                if let Some(value) = witness.get(*idx) {
                    acc = acc.add(&value.mul(coeff));
                }
            }
            acc
        }

        self.get_constraints()
            .iter()
            .map(|c| {
                let a_val = eval_linear(&c.a_terms, witness);
                let b_val = eval_linear(&c.b_terms, witness);
                let c_val = eval_linear(&c.c_terms, witness);
                let lhs = a_val.mul(&b_val);
                ConstraintResult {
                    constraint_id: c.id,
                    satisfied: lhs == c_val,
                    lhs_value: lhs,
                    rhs_value: c_val,
                }
            })
            .collect()
    }

    fn get_constraint_dependencies(&self) -> Vec<Vec<usize>> {
        self.get_constraints()
            .iter()
            .map(|c| {
                let mut deps: Vec<usize> = c
                    .a_terms
                    .iter()
                    .chain(c.b_terms.iter())
                    .chain(c.c_terms.iter())
                    .map(|(idx, _)| *idx)
                    .collect();
                deps.sort_unstable();
                deps.dedup();
                deps
            })
            .collect()
    }

    fn public_input_indices(&self) -> Vec<usize> {
        self.target.public_input_indices()
    }

    fn private_input_indices(&self) -> Vec<usize> {
        self.target.private_input_indices()
    }

    fn output_indices(&self) -> Vec<usize> {
        self.target.output_signal_indices()
    }
}

/// Noir executor wrapper
pub struct NoirExecutor {
    target: crate::targets::NoirTarget,
}

impl NoirExecutor {
    pub fn new(project_path: &str) -> anyhow::Result<Self> {
        let mut target = crate::targets::NoirTarget::new(project_path)?;
        target.compile()?;
        Ok(Self { target })
    }

    pub fn new_with_build_dir(project_path: &str, build_dir: PathBuf) -> anyhow::Result<Self> {
        let mut target = crate::targets::NoirTarget::new(project_path)?.with_build_dir(build_dir);
        target.compile()?;
        Ok(Self { target })
    }
}

#[async_trait]
impl CircuitExecutor for NoirExecutor {
    fn framework(&self) -> Framework {
        Framework::Noir
    }

    fn name(&self) -> &str {
        use crate::targets::TargetCircuit;
        self.target.name()
    }

    fn circuit_info(&self) -> CircuitInfo {
        use crate::targets::TargetCircuit;
        CircuitInfo {
            name: self.target.name().to_string(),
            num_constraints: self.target.num_constraints(),
            num_private_inputs: self.target.num_private_inputs(),
            num_public_inputs: self.target.num_public_inputs(),
            num_outputs: 1,
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        use crate::targets::TargetCircuit;
        let start = std::time::Instant::now();

        match self.target.execute(inputs) {
            Ok(outputs) => {
                let coverage = ExecutionCoverage::with_output_hash(&outputs);
                ExecutionResult::success(outputs, coverage)
                    .with_time(start.elapsed().as_micros() as u64)
            }
            Err(e) => ExecutionResult::failure(e.to_string()),
        }
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        use crate::targets::TargetCircuit;
        self.target.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        use crate::targets::TargetCircuit;
        self.target.verify(proof, public_inputs)
    }

    fn constraint_inspector(&self) -> Option<&dyn ConstraintInspector> {
        Some(self)
    }
}

impl ConstraintInspector for NoirExecutor {
    fn get_constraints(&self) -> Vec<ConstraintEquation> {
        self.target.load_constraints().unwrap_or_default()
    }

    fn check_constraints(&self, _witness: &[FieldElement]) -> Vec<ConstraintResult> {
        self.get_constraints()
            .iter()
            .map(|c| ConstraintResult {
                constraint_id: c.id,
                satisfied: true,
                lhs_value: FieldElement::one(),
                rhs_value: FieldElement::one(),
            })
            .collect()
    }

    fn get_constraint_dependencies(&self) -> Vec<Vec<usize>> {
        self.get_constraints()
            .iter()
            .map(|c| {
                let mut deps: Vec<usize> = c
                    .a_terms
                    .iter()
                    .chain(c.b_terms.iter())
                    .chain(c.c_terms.iter())
                    .map(|(idx, _)| *idx)
                    .collect();
                deps.sort_unstable();
                deps.dedup();
                deps
            })
            .collect()
    }

    fn public_input_indices(&self) -> Vec<usize> {
        self.target.public_input_indices()
    }

    fn private_input_indices(&self) -> Vec<usize> {
        self.target.private_input_indices()
    }

    fn output_indices(&self) -> Vec<usize> {
        self.target.output_signal_indices()
    }
}

/// Halo2 executor wrapper
pub struct Halo2Executor {
    target: crate::targets::Halo2Target,
}

impl Halo2Executor {
    pub fn new(circuit_path: &str, _main_component: &str) -> anyhow::Result<Self> {
        let mut target = crate::targets::Halo2Target::new(circuit_path)?;
        target.setup()?;
        Ok(Self { target })
    }

    pub fn new_with_build_dir(
        circuit_path: &str,
        _main_component: &str,
        build_dir: PathBuf,
    ) -> anyhow::Result<Self> {
        let mut target = crate::targets::Halo2Target::new(circuit_path)?.with_build_dir(build_dir);
        target.setup()?;
        Ok(Self { target })
    }
}

#[async_trait]
impl CircuitExecutor for Halo2Executor {
    fn framework(&self) -> Framework {
        Framework::Halo2
    }

    fn name(&self) -> &str {
        use crate::targets::TargetCircuit;
        self.target.name()
    }

    fn circuit_info(&self) -> CircuitInfo {
        use crate::targets::TargetCircuit;
        CircuitInfo {
            name: self.target.name().to_string(),
            num_constraints: self.target.num_constraints(),
            num_private_inputs: self.target.num_private_inputs(),
            num_public_inputs: self.target.num_public_inputs(),
            num_outputs: 1,
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        use crate::targets::TargetCircuit;
        let start = std::time::Instant::now();

        match self.target.execute(inputs) {
            Ok(outputs) => {
                let coverage = ExecutionCoverage::with_output_hash(&outputs);
                ExecutionResult::success(outputs, coverage)
                    .with_time(start.elapsed().as_micros() as u64)
            }
            Err(e) => ExecutionResult::failure(e.to_string()),
        }
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        use crate::targets::TargetCircuit;
        self.target.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        use crate::targets::TargetCircuit;
        self.target.verify(proof, public_inputs)
    }

    fn constraint_inspector(&self) -> Option<&dyn ConstraintInspector> {
        Some(self)
    }
}

impl ConstraintInspector for Halo2Executor {
    fn get_constraints(&self) -> Vec<ConstraintEquation> {
        Vec::new()
    }

    fn check_constraints(&self, witness: &[FieldElement]) -> Vec<ConstraintResult> {
        let parsed = self.target.load_plonk_constraints();
        if parsed.constraints.is_empty() {
            return Vec::new();
        }

        let wire_values: std::collections::HashMap<usize, FieldElement> = witness
            .iter()
            .enumerate()
            .map(|(idx, value)| (idx, value.clone()))
            .collect();

        let mut checker =
            ConstraintChecker::new().with_unknown_lookup_policy(UnknownLookupPolicy::FailClosed);
        for (id, table) in parsed.lookup_tables {
            checker.add_table(id, table);
        }

        parsed
            .constraints
            .iter()
            .enumerate()
            .map(|(idx, constraint)| {
                let evaluation = checker.evaluate(constraint, &wire_values);
                ConstraintResult {
                    constraint_id: idx,
                    satisfied: evaluation.satisfied,
                    lhs_value: evaluation.lhs,
                    rhs_value: evaluation.rhs,
                }
            })
            .collect()
    }

    fn get_constraint_dependencies(&self) -> Vec<Vec<usize>> {
        let parsed = self.target.load_plonk_constraints();
        parsed
            .constraints
            .iter()
            .map(|constraint| constraint.wire_dependencies())
            .collect()
    }
}

/// Cairo executor wrapper
pub struct CairoExecutor {
    target: crate::targets::CairoTarget,
}

impl CairoExecutor {
    pub fn new(source_path: &str) -> anyhow::Result<Self> {
        let mut target = crate::targets::CairoTarget::new(source_path)?;
        target.compile()?;
        Ok(Self { target })
    }

    pub fn new_with_build_dir(source_path: &str, build_dir: PathBuf) -> anyhow::Result<Self> {
        let mut target = crate::targets::CairoTarget::new(source_path)?.with_build_dir(build_dir);
        target.compile()?;
        Ok(Self { target })
    }
}

#[async_trait]
impl CircuitExecutor for CairoExecutor {
    fn framework(&self) -> Framework {
        Framework::Cairo
    }

    fn name(&self) -> &str {
        use crate::targets::TargetCircuit;
        self.target.name()
    }

    fn circuit_info(&self) -> CircuitInfo {
        use crate::targets::TargetCircuit;
        CircuitInfo {
            name: self.target.name().to_string(),
            num_constraints: self.target.num_constraints(),
            num_private_inputs: self.target.num_private_inputs(),
            num_public_inputs: self.target.num_public_inputs(),
            num_outputs: 1,
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        use crate::targets::TargetCircuit;
        let start = std::time::Instant::now();

        match self.target.execute(inputs) {
            Ok(outputs) => {
                let coverage = ExecutionCoverage::with_output_hash(&outputs);
                ExecutionResult::success(outputs, coverage)
                    .with_time(start.elapsed().as_micros() as u64)
            }
            Err(e) => ExecutionResult::failure(e.to_string()),
        }
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        use crate::targets::TargetCircuit;
        self.target.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        use crate::targets::TargetCircuit;
        self.target.verify(proof, public_inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_factory_mock() {
        let executor =
            ExecutorFactory::create(Framework::Mock, "test.circom", "TestCircuit").unwrap();

        assert_eq!(executor.name(), "TestCircuit");
        assert_eq!(executor.framework(), Framework::Mock);
    }

    #[test]
    fn test_execution_result() {
        let result =
            ExecutionResult::success(vec![FieldElement::one()], ExecutionCoverage::default());
        assert!(result.success);
        assert!(result.error.is_none());

        let failure = ExecutionResult::failure("test error".to_string());
        assert!(!failure.success);
        assert_eq!(failure.error, Some("test error".to_string()));
    }

    #[test]
    fn test_halo2_plonk_constraint_checking() {
        let json = r#"
        {
          "name": "test",
          "k": 4,
          "advice_columns": 3,
          "fixed_columns": 0,
          "instance_columns": 0,
          "constraints": 2,
          "private_inputs": 3,
          "public_inputs": 0,
          "lookups": 1,
          "tables": {
            "0": { "name": "tiny", "num_columns": 1, "entries": [[2], [3]] }
          },
          "gates": [
            { "a": 1, "b": 2, "c": 3, "q_l": "1", "q_r": "1", "q_o": "-1", "q_m": "0", "q_c": "0" }
          ],
          "lookups": [
            { "table_id": 0, "input": 1 }
          ]
        }
        "#;

        let temp = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        std::fs::write(temp.path(), json).unwrap();

        let executor = Halo2Executor::new(temp.path().to_str().unwrap(), "main").unwrap();
        let inspector = executor.constraint_inspector().unwrap();

        let witness = vec![
            FieldElement::one(),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
            FieldElement::from_u64(5),
        ];

        let results = inspector.check_constraints(&witness);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.satisfied));
    }
}
