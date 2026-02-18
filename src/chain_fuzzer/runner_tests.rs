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

    #[test]
    fn test_chain_runner_rejects_invalid_from_prior_step_reference() {
        let mut executors = HashMap::new();
        executors.insert("a".to_string(), create_fixture_executor("a", 2, 2));
        executors.insert("b".to_string(), create_fixture_executor("b", 2, 1));
        let runner = ChainRunner::new(executors).expect("failed to create chain runner");

        // Step 1 references step 3, which does not exist.
        let spec = ChainSpec::new(
            "invalid_wiring_step",
            vec![
                StepSpec::fresh("a"),
                StepSpec::from_prior("b", 3, vec![(0, 0)]),
            ],
        );
        let mut rng = rand::thread_rng();
        let result = runner.execute(&spec, &HashMap::new(), &mut rng);

        assert!(!result.completed);
        assert_eq!(result.failed_at, Some(1));
        assert!(result.trace.steps[1]
            .error
            .as_ref()
            .expect("missing error")
            .contains("references step 3"));
    }

    #[test]
    fn test_chain_runner_rejects_invalid_from_prior_output_index() {
        let mut executors = HashMap::new();
        executors.insert("a".to_string(), create_fixture_executor("a", 2, 1));
        executors.insert("b".to_string(), create_fixture_executor("b", 2, 1));
        let runner = ChainRunner::new(executors).expect("failed to create chain runner");

        // Step 0 emits one output; step 1 requests output index 4.
        let spec = ChainSpec::new(
            "invalid_wiring_output",
            vec![
                StepSpec::fresh("a"),
                StepSpec::from_prior("b", 0, vec![(4, 0)]),
            ],
        );
        let mut rng = rand::thread_rng();
        let result = runner.execute(&spec, &HashMap::new(), &mut rng);

        assert!(!result.completed);
        assert_eq!(result.failed_at, Some(1));
        assert!(result.trace.steps[1]
            .error
            .as_ref()
            .expect("missing error")
            .contains("has only 1 outputs"));
    }

    use super::super::types::StepSpec;
