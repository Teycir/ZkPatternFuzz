//! Mode 3: Chain Runner - Executes chain specs against circuit executors
//!
//! The ChainRunner is responsible for executing a ChainSpec against a set of
//! named CircuitExecutors, producing a ChainTrace that records the full execution.

use super::types::{ChainRunResult, ChainSpec, ChainTrace, InputWiring, StepTrace};
use rand::Rng;
use std::collections::HashMap;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use zk_core::{CircuitExecutor, ExecutionResult, FieldElement};

const MAX_CHAIN_EXECUTORS: usize = 1024;

/// Executes chain specifications against circuit executors
pub struct ChainRunner {
    /// Named executors for different circuits
    pub executors: HashMap<String, Arc<dyn CircuitExecutor>>,
    /// Timeout per step execution
    timeout_per_step: Duration,
    /// Maximum chain length to prevent infinite chains
    max_chain_length: usize,
}

impl ChainRunner {
    fn elapsed_ms(start: Instant) -> u64 {
        start.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    fn execute_step_with_timeout(
        &self,
        executor: Arc<dyn CircuitExecutor>,
        inputs: &[FieldElement],
    ) -> Result<(ExecutionResult, u64), u64> {
        let exec_start = Instant::now();
        if self.timeout_per_step.is_zero() {
            let result = executor.execute_sync(inputs);
            return Ok((result, Self::elapsed_ms(exec_start)));
        }

        let (tx, rx) = mpsc::channel();
        let thread_executor = Arc::clone(&executor);
        let thread_inputs = inputs.to_vec();
        let handle = thread::spawn(move || {
            let result = thread_executor.execute_sync(&thread_inputs);
            if tx.send(result).is_err() {
                tracing::warn!("Step worker finished but result receiver was dropped");
            }
        });

        match rx.recv_timeout(self.timeout_per_step) {
            Ok(result) => match handle.join() {
                Ok(()) => Ok((result, Self::elapsed_ms(exec_start))),
                Err(panic_payload) => Ok((
                    ExecutionResult::failure(format!(
                        "Step execution worker panicked: {}",
                        Self::panic_message(panic_payload)
                    )),
                    Self::elapsed_ms(exec_start),
                )),
            },
            Err(RecvTimeoutError::Timeout) => Err(Self::elapsed_ms(exec_start)),
            Err(RecvTimeoutError::Disconnected) => {
                let failure = match handle.join() {
                    Ok(()) => {
                        "Step execution worker disconnected before sending a result".to_string()
                    }
                    Err(panic_payload) => format!(
                        "Step execution worker panicked: {}",
                        Self::panic_message(panic_payload)
                    ),
                };
                Ok((
                    ExecutionResult::failure(failure),
                    Self::elapsed_ms(exec_start),
                ))
            }
        }
    }

    fn panic_message(payload: Box<dyn std::any::Any + Send + 'static>) -> String {
        if let Some(message) = payload.downcast_ref::<String>() {
            return message.clone();
        }
        if let Some(message) = payload.downcast_ref::<&'static str>() {
            return (*message).to_string();
        }
        "unknown panic payload".to_string()
    }

    /// Create a new chain runner with the given executors
    pub fn new(executors: HashMap<String, Arc<dyn CircuitExecutor>>) -> anyhow::Result<Self> {
        if executors.len() > MAX_CHAIN_EXECUTORS {
            anyhow::bail!(
                "too many chain executors: {} (max {})",
                executors.len(),
                MAX_CHAIN_EXECUTORS
            );
        }
        Ok(Self {
            executors,
            timeout_per_step: Duration::from_secs(30),
            max_chain_length: 100,
        })
    }

    /// Set the timeout per step
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout_per_step = timeout;
        self
    }

    /// Set the maximum chain length
    pub fn with_max_length(mut self, max_length: usize) -> Self {
        self.max_chain_length = max_length;
        self
    }

    /// Add an executor for a circuit
    pub fn add_executor(
        &mut self,
        name: impl Into<String>,
        executor: Arc<dyn CircuitExecutor>,
    ) -> anyhow::Result<()> {
        if self.executors.len() >= MAX_CHAIN_EXECUTORS {
            anyhow::bail!("cannot add executor: reached max {}", MAX_CHAIN_EXECUTORS);
        }
        self.executors.insert(name.into(), executor);
        Ok(())
    }

    /// Execute a chain spec with the given initial inputs
    ///
    /// # Arguments
    ///
    /// * `spec` - The chain specification to execute
    /// * `initial_inputs` - Initial fresh inputs per circuit (keyed by circuit_ref)
    /// * `rng` - Random number generator for fresh input generation
    ///
    /// # Returns
    ///
    /// A ChainRunResult containing the full trace and success/failure status
    pub fn execute(
        &self,
        spec: &ChainSpec,
        initial_inputs: &HashMap<String, Vec<FieldElement>>,
        rng: &mut impl Rng,
    ) -> ChainRunResult {
        let start_time = Instant::now();
        let mut trace = ChainTrace::new(&spec.name);

        if spec.steps.len() > self.max_chain_length {
            tracing::warn!(
                "Chain {} has {} steps, exceeding max of {}",
                spec.name,
                spec.steps.len(),
                self.max_chain_length
            );
            return ChainRunResult::failure(trace, 0);
        }

        for (step_index, step) in spec.steps.iter().enumerate() {
            let step_start = Instant::now();

            // Get the executor for this step's circuit
            let executor = match self.executors.get(&step.circuit_ref) {
                Some(e) => e,
                None => {
                    tracing::warn!(
                        "No executor found for circuit '{}' in chain '{}'",
                        step.circuit_ref,
                        spec.name
                    );
                    let step_trace = StepTrace::failure(
                        step_index,
                        &step.circuit_ref,
                        vec![],
                        format!("Executor not found for circuit '{}'", step.circuit_ref),
                    );
                    trace.add_step(step_trace);
                    return ChainRunResult::failure(trace, step_index);
                }
            };

            // HIGH PRIORITY FIX: Validate expected_inputs/outputs if specified
            let actual_inputs = executor.num_private_inputs() + executor.num_public_inputs();
            if let Some(expected) = step.expected_inputs {
                if actual_inputs != expected {
                    tracing::warn!(
                        "Step {} circuit '{}' has {} inputs, but expected {}",
                        step_index,
                        step.circuit_ref,
                        actual_inputs,
                        expected
                    );
                    let step_trace = StepTrace::failure(
                        step_index,
                        &step.circuit_ref,
                        vec![],
                        format!(
                            "Wiring validation failed: expected {} inputs, circuit has {}",
                            expected, actual_inputs
                        ),
                    );
                    trace.add_step(step_trace);
                    return ChainRunResult::failure(trace, step_index);
                }
            }

            // Resolve inputs for this step
            let inputs = self.resolve_inputs(
                &step.input_wiring,
                &step.circuit_ref,
                executor.num_private_inputs() + executor.num_public_inputs(),
                &trace,
                initial_inputs,
                rng,
            );

            // Execute the circuit with preemptive timeout enforcement.
            // This guarantees the chain contract fails fast instead of waiting for
            // the backend call to eventually return.
            let (result, execution_time_ms) =
                match self.execute_step_with_timeout(Arc::clone(executor), &inputs) {
                    Ok(done) => done,
                    Err(step_time) => {
                        let timeout_ms = self.timeout_per_step.as_millis();
                        tracing::warn!(
                            "Step {} in chain '{}' timed out after {} ms (limit {} ms)",
                            step_index,
                            spec.name,
                            step_time,
                            timeout_ms
                        );
                        let step_trace = StepTrace::failure(
                            step_index,
                            &step.circuit_ref,
                            inputs,
                            format!("Step timed out: exceeded {} ms limit", timeout_ms),
                        )
                        .with_time(step_time);
                        trace.add_step(step_trace);
                        trace.execution_time_ms = Self::elapsed_ms(start_time);
                        return ChainRunResult::failure(trace, step_index);
                    }
                };

            let step_time = Self::elapsed_ms(step_start);
            let timeout_ms = self.timeout_per_step.as_millis();
            if timeout_ms > 0 && u128::from(execution_time_ms) > timeout_ms {
                tracing::warn!(
                    "Step {} in chain '{}' exceeded timeout: {} ms > {} ms",
                    step_index,
                    spec.name,
                    execution_time_ms,
                    timeout_ms
                );
                let step_trace = StepTrace::failure(
                    step_index,
                    &step.circuit_ref,
                    inputs,
                    format!(
                        "Step timed out: execution took {} ms (limit {} ms)",
                        execution_time_ms, timeout_ms
                    ),
                )
                .with_time(step_time);
                trace.add_step(step_trace);
                trace.execution_time_ms = Self::elapsed_ms(start_time);
                return ChainRunResult::failure(trace, step_index);
            }

            if result.success {
                if let Some(expected) = step.expected_outputs {
                    let actual_outputs = result.outputs.len();
                    if actual_outputs != expected {
                        tracing::warn!(
                            "Step {} circuit '{}' produced {} outputs, but expected {}",
                            step_index,
                            step.circuit_ref,
                            actual_outputs,
                            expected
                        );
                        let step_trace = StepTrace::failure(
                            step_index,
                            &step.circuit_ref,
                            inputs,
                            format!(
                                "Output validation failed: expected {} outputs, got {}",
                                expected, actual_outputs
                            ),
                        )
                        .with_time(step_time);
                        trace.add_step(step_trace);
                        trace.execution_time_ms = Self::elapsed_ms(start_time);
                        return ChainRunResult::failure(trace, step_index);
                    }
                }

                let mut step_trace =
                    StepTrace::success(step_index, &step.circuit_ref, inputs, result.outputs);
                step_trace = step_trace.with_time(step_time);

                // Add constraint coverage
                let constraints = if !result.coverage.evaluated_constraints.is_empty() {
                    &result.coverage.evaluated_constraints
                } else {
                    &result.coverage.satisfied_constraints
                };
                if !constraints.is_empty() {
                    step_trace = step_trace.with_constraints(constraints.iter().cloned().collect());
                }

                trace.add_step(step_trace);
            } else {
                let error_msg = match result.error {
                    Some(err) => err,
                    None => format!(
                        "Chain step {} failed without backend error message",
                        step_index
                    ),
                };
                let step_trace =
                    StepTrace::failure(step_index, &step.circuit_ref, inputs, error_msg)
                        .with_time(step_time);

                trace.add_step(step_trace);
                trace.execution_time_ms = Self::elapsed_ms(start_time);
                return ChainRunResult::failure(trace, step_index);
            }
        }

        trace.success = true;
        trace.execution_time_ms = Self::elapsed_ms(start_time);
        ChainRunResult::success(trace)
    }

    /// Resolve inputs for a step based on its wiring configuration
    fn resolve_inputs(
        &self,
        wiring: &InputWiring,
        circuit_ref: &str,
        expected_count: usize,
        trace: &ChainTrace,
        initial_inputs: &HashMap<String, Vec<FieldElement>>,
        rng: &mut impl Rng,
    ) -> Vec<FieldElement> {
        match wiring {
            InputWiring::Fresh => {
                // Check if we have initial inputs for this circuit
                if let Some(inputs) = initial_inputs.get(circuit_ref) {
                    if inputs.len() >= expected_count {
                        return inputs[..expected_count].to_vec();
                    }
                    // Pad with random if not enough
                    let mut result = inputs.clone();
                    while result.len() < expected_count {
                        result.push(FieldElement::random(rng));
                    }
                    return result;
                }
                // Generate fresh random inputs
                (0..expected_count)
                    .map(|_| FieldElement::random(rng))
                    .collect()
            }

            InputWiring::FromPriorOutput { step, mapping } => {
                // Start from any provided seed inputs for this circuit_ref so downstream steps
                // can be executed with a stable baseline (e.g., valid seed witness), then
                // overlay mapped values from the prior step.
                let mut inputs = if let Some(seed) = initial_inputs.get(circuit_ref) {
                    if seed.len() >= expected_count {
                        seed[..expected_count].to_vec()
                    } else {
                        let mut out = seed.clone();
                        while out.len() < expected_count {
                            out.push(FieldElement::random(rng));
                        }
                        out
                    }
                } else {
                    vec![FieldElement::zero(); expected_count]
                };

                // Track which indices have been explicitly mapped (even if value is zero)
                let mapped_indices: std::collections::HashSet<_> =
                    mapping.iter().map(|(_, in_idx)| *in_idx).collect();

                // Get outputs from the prior step
                if let Some(prior_outputs) = trace.step_outputs(*step) {
                    for (out_idx, in_idx) in mapping {
                        if let Some(output) = prior_outputs.get(*out_idx) {
                            if *in_idx < inputs.len() {
                                inputs[*in_idx] = output.clone();
                            }
                        }
                    }
                }

                // If we did not have a baseline seed for this step, fill unmapped inputs with
                // random values. If we did have a baseline, keep it (baseline values are
                // intentional and often required for successful execution).
                if !initial_inputs.contains_key(circuit_ref) {
                    // CRITICAL FIX: Only fill indices that weren't in the mapping
                    // (zero is a valid output value and should not be overwritten)
                    for (i, input) in inputs.iter_mut().enumerate() {
                        if !mapped_indices.contains(&i) {
                            *input = FieldElement::random(rng);
                        }
                    }
                }

                inputs
            }

            InputWiring::Mixed {
                prior,
                fresh_indices,
            } => {
                let mut inputs = vec![FieldElement::zero(); expected_count];
                // Track which indices have been explicitly set (even if value is zero)
                let mut set_indices: std::collections::HashSet<usize> =
                    std::collections::HashSet::new();

                // Fill in values from prior steps
                for (step, out_idx, in_idx) in prior {
                    if let Some(prior_outputs) = trace.step_outputs(*step) {
                        if let Some(output) = prior_outputs.get(*out_idx) {
                            if *in_idx < inputs.len() {
                                inputs[*in_idx] = output.clone();
                                set_indices.insert(*in_idx);
                            }
                        }
                    }
                }

                // Fill fresh indices with random values
                for idx in fresh_indices {
                    if *idx < inputs.len() {
                        inputs[*idx] = FieldElement::random(rng);
                        set_indices.insert(*idx);
                    }
                }

                // CRITICAL FIX: Fill any remaining unset indices with random
                // (only those that were not in prior mapping or fresh_indices)
                for (i, input) in inputs.iter_mut().enumerate() {
                    if !set_indices.contains(&i) {
                        *input = FieldElement::random(rng);
                    }
                }

                inputs
            }

            InputWiring::Constant {
                values,
                fresh_indices,
            } => {
                let mut inputs = vec![FieldElement::zero(); expected_count];
                // Track which indices have been explicitly set (even if value is zero)
                let mut set_indices: std::collections::HashSet<usize> =
                    std::collections::HashSet::new();

                // Fill in constant values
                for (idx, hex_value) in values {
                    if *idx < inputs.len() {
                        if let Ok(fe) = FieldElement::from_hex(hex_value) {
                            inputs[*idx] = fe;
                            set_indices.insert(*idx);
                        }
                    }
                }

                // Fill fresh indices with random values
                for idx in fresh_indices {
                    if *idx < inputs.len() {
                        inputs[*idx] = FieldElement::random(rng);
                        set_indices.insert(*idx);
                    }
                }

                // CRITICAL FIX: Fill any remaining unset indices with random
                // (only those that were not in constants or fresh_indices)
                for (i, input) in inputs.iter_mut().enumerate() {
                    if !set_indices.contains(&i) {
                        *input = FieldElement::random(rng);
                    }
                }

                inputs
            }
        }
    }

    /// Execute multiple chains in parallel (if thread pool available)
    pub fn execute_batch(
        &self,
        specs: &[ChainSpec],
        initial_inputs: &HashMap<String, Vec<FieldElement>>,
        seed: u64,
    ) -> Vec<ChainRunResult> {
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        specs
            .iter()
            .enumerate()
            .map(|(i, spec)| {
                let mut rng = ChaCha8Rng::seed_from_u64(seed.wrapping_add(i as u64));
                self.execute(spec, initial_inputs, &mut rng)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::FixtureCircuitExecutor;
    use std::thread;
    use zk_core::{CircuitInfo, ExecutionResult, Framework};

    struct SlowExecutor {
        inner: FixtureCircuitExecutor,
        delay: Duration,
    }

    impl SlowExecutor {
        fn new(name: &str, num_inputs: usize, num_outputs: usize, delay: Duration) -> Self {
            Self {
                inner: FixtureCircuitExecutor::new(name, num_inputs, 0).with_outputs(num_outputs),
                delay,
            }
        }
    }

    impl CircuitExecutor for SlowExecutor {
        fn framework(&self) -> Framework {
            self.inner.framework()
        }

        fn name(&self) -> &str {
            self.inner.name()
        }

        fn circuit_info(&self) -> CircuitInfo {
            self.inner.circuit_info()
        }

        fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
            thread::sleep(self.delay);
            self.inner.execute_sync(inputs)
        }

        fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
            self.inner.prove(witness)
        }

        fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
            self.inner.verify(proof, public_inputs)
        }
    }

    fn create_fixture_executor(
        name: &str,
        num_inputs: usize,
        num_outputs: usize,
    ) -> Arc<dyn CircuitExecutor> {
        Arc::new(FixtureCircuitExecutor::new(name, num_inputs, 0).with_outputs(num_outputs))
    }

    #[test]
    fn test_chain_runner_fresh_inputs() {
        let mut executors = HashMap::new();
        executors.insert(
            "circuit_a".to_string(),
            create_fixture_executor("circuit_a", 2, 2),
        );
        executors.insert(
            "circuit_b".to_string(),
            create_fixture_executor("circuit_b", 2, 1),
        );

        let runner = ChainRunner::new(executors).expect("failed to create chain runner");

        let spec = ChainSpec::new(
            "test_chain",
            vec![StepSpec::fresh("circuit_a"), StepSpec::fresh("circuit_b")],
        );

        let mut rng = rand::thread_rng();
        let result = runner.execute(&spec, &HashMap::new(), &mut rng);

        assert!(result.completed);
        assert_eq!(result.trace.depth(), 2);
    }

    #[test]
    fn test_chain_runner_wired_inputs() {
        let mut executors = HashMap::new();
        executors.insert(
            "deposit".to_string(),
            create_fixture_executor("deposit", 2, 2),
        );
        executors.insert(
            "withdraw".to_string(),
            create_fixture_executor("withdraw", 2, 1),
        );

        let runner = ChainRunner::new(executors).expect("failed to create chain runner");

        let spec = ChainSpec::new(
            "deposit_withdraw",
            vec![
                StepSpec::fresh("deposit"),
                StepSpec::from_prior("withdraw", 0, vec![(0, 0), (1, 1)]),
            ],
        );

        let mut rng = rand::thread_rng();
        let result = runner.execute(&spec, &HashMap::new(), &mut rng);

        assert!(result.completed);
        assert_eq!(result.trace.depth(), 2);

        // Verify the wiring worked: withdraw's inputs should match deposit's outputs
        let deposit_outputs = result.trace.step_outputs(0).unwrap();
        let withdraw_inputs = result.trace.step_inputs(1).unwrap();

        assert_eq!(withdraw_inputs[0], deposit_outputs[0]);
        assert_eq!(withdraw_inputs[1], deposit_outputs[1]);
    }

    #[test]
    fn test_chain_runner_missing_executor() {
        let executors = HashMap::new(); // Empty
        let runner = ChainRunner::new(executors).expect("failed to create chain runner");

        let spec = ChainSpec::new("test_chain", vec![StepSpec::fresh("nonexistent")]);

        let mut rng = rand::thread_rng();
        let result = runner.execute(&spec, &HashMap::new(), &mut rng);

        assert!(!result.completed);
        assert_eq!(result.failed_at, Some(0));
    }

    #[test]
    fn test_chain_runner_validates_expected_outputs() {
        let mut executors = HashMap::new();
        executors.insert(
            "circuit_a".to_string(),
            create_fixture_executor("circuit_a", 2, 1),
        );

        let runner = ChainRunner::new(executors).expect("failed to create chain runner");
        let mut step = StepSpec::fresh("circuit_a");
        step.expected_outputs = Some(2);
        let spec = ChainSpec::new("outputs_contract", vec![step]);

        let mut rng = rand::thread_rng();
        let result = runner.execute(&spec, &HashMap::new(), &mut rng);

        assert!(!result.completed);
        assert_eq!(result.failed_at, Some(0));
        assert!(result.trace.steps[0]
            .error
            .as_ref()
            .expect("missing step error")
            .contains("expected 2 outputs"));
    }

    #[test]
    fn test_chain_runner_enforces_step_timeout() {
        let mut executors = HashMap::new();
        executors.insert(
            "slow".to_string(),
            Arc::new(SlowExecutor::new("slow", 2, 1, Duration::from_millis(25)))
                as Arc<dyn CircuitExecutor>,
        );
        let runner = ChainRunner::new(executors)
            .expect("failed to create chain runner")
            .with_timeout(Duration::from_millis(5));
        let spec = ChainSpec::new("timeout_contract", vec![StepSpec::fresh("slow")]);

        let mut rng = rand::thread_rng();
        let result = runner.execute(&spec, &HashMap::new(), &mut rng);

        assert!(!result.completed);
        assert_eq!(result.failed_at, Some(0));
        assert!(result.trace.steps[0]
            .error
            .as_ref()
            .expect("missing step error")
            .contains("timed out"));
    }

    #[test]
    fn test_chain_runner_timeout_is_preemptive() {
        let mut executors = HashMap::new();
        executors.insert(
            "slow".to_string(),
            Arc::new(SlowExecutor::new("slow", 2, 1, Duration::from_millis(300)))
                as Arc<dyn CircuitExecutor>,
        );
        let runner = ChainRunner::new(executors)
            .expect("failed to create chain runner")
            .with_timeout(Duration::from_millis(20));
        let spec = ChainSpec::new("timeout_preemptive", vec![StepSpec::fresh("slow")]);

        let mut rng = rand::thread_rng();
        let wall_start = std::time::Instant::now();
        let result = runner.execute(&spec, &HashMap::new(), &mut rng);
        let wall_elapsed = wall_start.elapsed();

        assert!(!result.completed);
        assert_eq!(result.failed_at, Some(0));
        assert!(
            wall_elapsed < Duration::from_millis(200),
            "preemptive timeout should return quickly; elapsed {:?}",
            wall_elapsed
        );
    }

    use super::super::types::StepSpec;
}
