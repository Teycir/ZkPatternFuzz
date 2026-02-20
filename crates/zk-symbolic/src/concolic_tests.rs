use super::*;
use zk_core::{CircuitExecutor, CircuitInfo, ExecutionCoverage, ExecutionResult, Framework};

struct DummyExecutor {
    private_inputs: usize,
    public_inputs: usize,
}

impl DummyExecutor {
    fn new(private_inputs: usize, public_inputs: usize) -> Self {
        Self {
            private_inputs,
            public_inputs,
        }
    }
}

impl CircuitExecutor for DummyExecutor {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn name(&self) -> &str {
        "dummy"
    }

    fn circuit_info(&self) -> CircuitInfo {
        CircuitInfo {
            name: "dummy".to_string(),
            num_constraints: 0,
            num_private_inputs: self.private_inputs,
            num_public_inputs: self.public_inputs,
            num_outputs: 0,
        }
    }

    fn execute_sync(&self, _inputs: &[FieldElement]) -> ExecutionResult {
        ExecutionResult::success(Vec::new(), ExecutionCoverage::default())
    }

    fn prove(&self, _witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn verify(&self, _proof: &[u8], _public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        Ok(true)
    }
}

#[test]
fn test_concolic_trace() {
    let mut trace = ConcolicTrace::new(vec![FieldElement::zero(), FieldElement::one()]);

    let constraint = SymbolicConstraint::Eq(
        SymbolicValue::symbol("x"),
        SymbolicValue::concrete(FieldElement::zero()),
    );

    trace.add_branch(constraint, true);
    assert_eq!(trace.branch_points.len(), 1);
    assert!(trace.branch_points[0].taken);
}

#[test]
fn test_concolic_executor_creation() {
    let dummy = Arc::new(DummyExecutor::new(3, 1));
    let executor = ConcolicExecutor::new(dummy);

    assert_eq!(executor.num_inputs, 4); // 3 private + 1 public
}

#[test]
fn test_concolic_integration() {
    let mut integration = ConcolicFuzzerIntegration::new(3);
    assert!(!integration.is_initialized());

    let dummy = Arc::new(DummyExecutor::new(3, 1));
    integration.initialize(dummy);
    assert!(integration.is_initialized());
}
