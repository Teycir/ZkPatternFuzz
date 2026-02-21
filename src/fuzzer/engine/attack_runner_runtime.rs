use super::attack_runner::OptionValueExt;
use super::attack_runner_budget::strict_attack_floor;
use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) async fn run_verification_fuzzing_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::verification::VerificationFuzzer;

        let configured_malleability_tests = config
            .get("malleability_tests")
            .and_then(|v| v.as_u64())
            .or_value(1000) as usize;
        let configured_malformed_tests = config
            .get("malformed_tests")
            .and_then(|v| v.as_u64())
            .or_value(1000) as usize;
        let configured_edge_case_tests = config
            .get("edge_case_tests")
            .and_then(|v| v.as_u64())
            .or_value(500) as usize;
        let malleability_tests = self.bounded_attack_units(
            configured_malleability_tests,
            1,
            "verification_malleability_tests_cap",
            "verification.malleability_tests",
        );
        let malformed_tests = self.bounded_attack_units(
            configured_malformed_tests,
            1,
            "verification_malformed_tests_cap",
            "verification.malformed_tests",
        );
        let edge_case_tests = self.bounded_attack_units(
            configured_edge_case_tests,
            1,
            "verification_edge_case_tests_cap",
            "verification.edge_case_tests",
        );
        let mutation_rate = config
            .get("mutation_rate")
            .and_then(|v| v.as_f64())
            .or_value(0.05);

        tracing::info!(
            "Running verification fuzzing: malleability={}, malformed={}, edge_cases={}",
            malleability_tests,
            malformed_tests,
            edge_case_tests
        );

        let fuzzer = VerificationFuzzer::new()
            .with_malleability_tests(malleability_tests)
            .with_malformed_tests(malformed_tests)
            .with_edge_case_tests(edge_case_tests)
            .with_mutation_rate(mutation_rate);

        let findings = {
            let rng = self.core.rng_mut();
            fuzzer.fuzz(&self.executor, rng)
        };

        if !findings.is_empty() {
            self.with_findings_write(|store| store.extend(findings.iter().cloned()))?;
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        Ok(())
    }

    pub(super) async fn run_witness_fuzzing_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::witness::WitnessFuzzer;

        let configured_determinism_tests = config
            .get("determinism_tests")
            .and_then(|v| v.as_u64())
            .or_value(100) as usize;
        let configured_timing_tests = config
            .get("timing_tests")
            .and_then(|v| v.as_u64())
            .or_value(500) as usize;
        let configured_stress_tests = config
            .get("stress_tests")
            .and_then(|v| v.as_u64())
            .or_value(1000) as usize;
        let determinism_tests = self.bounded_attack_units(
            configured_determinism_tests,
            1,
            "witness_determinism_tests_cap",
            "witness.determinism_tests",
        );
        let timing_tests = self.bounded_attack_units(
            configured_timing_tests,
            1,
            "witness_timing_tests_cap",
            "witness.timing_tests",
        );
        let stress_tests = self.bounded_attack_units(
            configured_stress_tests,
            1,
            "witness_stress_tests_cap",
            "witness.stress_tests",
        );
        let timing_threshold_us = config
            .get("timing_threshold_us")
            .and_then(|v| v.as_u64())
            .or_value(10_000);
        let timing_cv_threshold = config
            .get("timing_cv_threshold")
            .and_then(|v| v.as_f64())
            .or_value(0.5);

        tracing::info!(
            "Running witness fuzzing: determinism={}, timing={}, stress={}",
            determinism_tests,
            timing_tests,
            stress_tests
        );

        let fuzzer = WitnessFuzzer::new()
            .with_determinism_tests(determinism_tests)
            .with_timing_tests(timing_tests)
            .with_stress_tests(stress_tests)
            .with_timing_threshold_us(timing_threshold_us)
            .with_timing_cv_threshold(timing_cv_threshold);

        let findings = {
            let rng = self.core.rng_mut();
            fuzzer.fuzz(&self.executor, rng)
        };

        if !findings.is_empty() {
            self.with_findings_write(|store| store.extend(findings.iter().cloned()))?;
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        Ok(())
    }

    pub(super) async fn run_differential_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::differential::report::DifferentialReport;
        use crate::differential::{DifferentialConfig, DifferentialFuzzer};
        use std::collections::{HashMap, HashSet};

        let configured_num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .or_value(500) as usize;
        let num_tests = self.bounded_attack_units(
            configured_num_tests,
            1,
            "differential_num_tests_cap",
            "differential.num_tests",
        );
        let compare_coverage = config
            .get("compare_coverage")
            .and_then(|v| v.as_bool())
            .or_value(true);
        let compare_timing = config
            .get("compare_timing")
            .and_then(|v| v.as_bool())
            .or_value(true);
        let timing_tolerance_percent = config
            .get("timing_tolerance_percent")
            .and_then(|v| v.as_f64())
            .or_value(50.0);
        let timing_min_us = config
            .get("timing_min_us")
            .and_then(|v| v.as_u64())
            .or_value(2_000);
        let timing_abs_threshold_us = config
            .get("timing_abs_threshold_us")
            .and_then(|v| v.as_u64())
            .or_value(5_000);
        let coverage_min_constraints = config
            .get("coverage_min_constraints")
            .and_then(|v| v.as_u64())
            .or_value(16) as usize;
        let coverage_jaccard_threshold = config
            .get("coverage_jaccard_threshold")
            .and_then(|v| v.as_f64())
            .or_value(0.5);
        let coverage_abs_delta_threshold = config
            .get("coverage_abs_delta_threshold")
            .and_then(|v| v.as_u64())
            .or_value(200) as usize;
        let coverage_rel_delta_threshold = config
            .get("coverage_rel_delta_threshold")
            .and_then(|v| v.as_f64())
            .or_value(0.25);

        let cross_backend_section = config.get("cross_backend");
        let cross_backend_enabled = cross_backend_section
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .or_value(false);
        let configured_cross_backend_samples = cross_backend_section
            .and_then(|v| v.get("sample_count"))
            .and_then(|v| v.as_u64())
            .or_value(100) as usize;
        let cross_backend_samples = self.bounded_attack_units(
            configured_cross_backend_samples,
            1,
            "differential_cross_backend_sample_count_cap",
            "differential.cross_backend.sample_count",
        );
        let cross_backend_tolerance_bits = cross_backend_section
            .and_then(|v| v.get("tolerance_bits"))
            .and_then(|v| v.as_u64())
            .or_value(0) as usize;

        tracing::info!("Running differential fuzzing with {} tests", num_tests);

        let parse_framework = |name: &str| -> Option<Framework> {
            match name.to_lowercase().as_str() {
                "circom" => Some(Framework::Circom),
                "noir" => Some(Framework::Noir),
                "halo2" => Some(Framework::Halo2),
                "cairo" => Some(Framework::Cairo),
                _ => None,
            }
        };

        let backends: Vec<Framework> =
            if let Some(seq) = config.get("backends").and_then(|v| v.as_sequence()) {
                seq.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(parse_framework)
                    .collect()
            } else {
                vec![self.config.campaign.target.framework]
            };

        // Optional per-backend circuit paths
        let mut backend_paths: HashMap<Framework, String> = HashMap::new();
        if let Some(map) = config.get("backend_paths").and_then(|v| v.as_mapping()) {
            for (k, v) in map {
                if let (Some(key), Some(path)) = (k.as_str(), v.as_str()) {
                    if let Some(framework) = parse_framework(key) {
                        backend_paths.insert(framework, path.to_string());
                    }
                }
            }
        }

        let mut unique = HashSet::new();
        let mut selected_backends = Vec::new();
        for backend in backends {
            if unique.insert(backend) {
                selected_backends.push(backend);
            }
        }

        if selected_backends.len() < 2 {
            anyhow::bail!(
                "Differential fuzzing requires at least two configured backends; got {}",
                selected_backends.len()
            );
        }

        let mut diff_fuzzer = DifferentialFuzzer::new(DifferentialConfig {
            num_tests,
            backends: selected_backends.clone(),
            compare_coverage,
            compare_proofs: false,
            timing_tolerance_percent,
            timing_min_us,
            timing_abs_threshold_us,
            coverage_min_constraints,
            coverage_jaccard_threshold,
            coverage_abs_delta_threshold,
            coverage_rel_delta_threshold,
            compare_timing,
        });

        // Add executors for each backend.
        let mut active_backends = Vec::new();
        let mut cross_backend_execs: Vec<Arc<dyn CircuitExecutor>> = Vec::new();
        for backend in &selected_backends {
            let circuit_path = backend_paths
                .get(backend)
                .map(|s| s.as_str())
                .or_else_value(|| {
                    self.config
                        .campaign
                        .target
                        .circuit_path
                        .to_str()
                        .or_value("")
                });

            let executor = ExecutorFactory::create_with_options(
                *backend,
                circuit_path,
                &self.config.campaign.target.main_component,
                &self.executor_factory_options,
            )
            .map_err(|e| anyhow::anyhow!("Failed to initialize backend {:?}: {}", backend, e))?;
            if cross_backend_enabled && cross_backend_execs.len() < 2 {
                cross_backend_execs.push(executor.clone());
            }
            diff_fuzzer.add_executor(*backend, executor);
            active_backends.push(*backend);
        }

        if active_backends.len() < 2 {
            anyhow::bail!(
                "Differential fuzzing requires at least two active backends; got {}",
                active_backends.len()
            );
        }

        if cross_backend_enabled {
            if cross_backend_execs.len() >= 2 {
                self.run_cross_backend_differential(
                    cross_backend_execs[0].clone(),
                    cross_backend_execs[1].clone(),
                    cross_backend_samples,
                    cross_backend_tolerance_bits,
                    progress,
                )?;
            } else {
                anyhow::bail!(
                    "Cross-backend differential enabled but fewer than two active executors are available"
                );
            }
        }

        let mut test_cases = Vec::with_capacity(num_tests);
        for _ in 0..num_tests {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping differential attack witness generation early: wall-clock timeout reached"
                );
                break;
            }
            test_cases.push(self.generate_random_test_case());
        }

        let results = diff_fuzzer.run(&test_cases);

        // Create differential report
        let report = DifferentialReport::new(
            &self.config.campaign.name,
            active_backends.clone(),
            results.clone(),
            diff_fuzzer.stats().clone(),
        );

        if report.has_critical_issues() {
            tracing::warn!(
                "Differential fuzzing found {} critical issues",
                report.critical_findings().len()
            );
        }

        tracing::info!("{}", report.summary());

        if !results.is_empty() {
            let findings: Vec<Finding> = results
                .into_iter()
                .map(|result| Finding {
                    attack_type: AttackType::Differential,
                    severity: Severity::Medium,
                    description: format!("Differential discrepancy: {:?}", result.severity),
                    poc: super::ProofOfConcept {
                        witness_a: result.input,
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: None,
                })
                .collect();
            self.with_findings_write(|store| store.extend(findings.iter().cloned()))?;
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding("MEDIUM", &finding.description);
                }
            }
        }

        if let Some(p) = progress {
            for _ in 0..num_tests {
                p.inc();
            }
        }

        Ok(())
    }

    pub(super) fn run_cross_backend_differential(
        &self,
        executor_a: Arc<dyn CircuitExecutor>,
        executor_b: Arc<dyn CircuitExecutor>,
        sample_count: usize,
        tolerance_bits: usize,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::CrossBackendDifferential;

        if sample_count == 0 {
            anyhow::bail!("Cross-backend differential requires sample_count > 0");
        }

        let witnesses = self.collect_corpus_inputs(sample_count.max(1));
        if witnesses.is_empty() {
            anyhow::bail!(
                "Cross-backend differential requires corpus witnesses, but none are available"
            );
        }

        let oracle = CrossBackendDifferential::new()
            .with_sample_count(sample_count)
            .with_tolerance_bits(tolerance_bits);

        let findings = oracle.run(executor_a.as_ref(), executor_b.as_ref(), &witnesses);
        self.record_custom_findings(findings, AttackType::Differential, progress)?;
        Ok(())
    }

    pub(super) async fn run_circuit_composition_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::multi_circuit::composition::{CompositionTester, CompositionType};
        use crate::multi_circuit::{CircuitChain, MultiCircuitFuzzer};

        let configured_num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .or_value(200) as usize;
        let num_tests = self.bounded_attack_units(
            configured_num_tests,
            1,
            "circuit_composition_num_tests_cap",
            "circuit_composition.num_tests",
        );

        tracing::info!(
            "Running circuit composition fuzzing with {} tests",
            num_tests
        );

        // Create composition tester
        let mut composition_tester = CompositionTester::new(CompositionType::Parallel);
        composition_tester.add_circuit(self.executor.clone());

        // Create circuit chain for chained execution testing
        let mut chain = CircuitChain::new();
        chain.add("main", self.executor.clone());

        // Test chain execution with random inputs
        for _ in 0..num_tests.min(10) {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping circuit composition smoke checks early: wall-clock timeout reached"
                );
                break;
            }
            let inputs: Vec<FieldElement> = {
                let rng = self.core.rng_mut();
                (0..self.executor.num_private_inputs())
                    .map(|_| FieldElement::random(rng))
                    .collect()
            };

            let chain_result = chain.execute(&inputs);
            if !chain_result.success {
                tracing::debug!(
                    "Chain execution failed at step: {:?}",
                    chain_result.steps.last().map(|s| &s.circuit_name)
                );
            }
        }

        // Test composition with vulnerability detection
        let vulnerabilities = composition_tester.check_vulnerabilities();
        for vuln in &vulnerabilities {
            tracing::warn!(
                "Composition vulnerability: {:?} - {}",
                vuln.vuln_type,
                vuln.description
            );
        }

        let mut multi_fuzzer =
            MultiCircuitFuzzer::new(crate::multi_circuit::MultiCircuitConfig::default());

        multi_fuzzer.add_circuit("main", self.executor.clone());

        let findings = {
            let rng = self.core.rng_mut();
            multi_fuzzer.run(rng)
        };

        if !findings.is_empty() {
            self.with_findings_write(|store| store.extend(findings.iter().cloned()))?;
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        if let Some(p) = progress {
            for _ in 0..num_tests {
                p.inc();
            }
        }

        Ok(())
    }

    pub(super) async fn run_information_leakage_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::analysis::taint::TaintAnalyzer;

        let configured_num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .or_value(300) as usize;
        let num_tests = self.bounded_attack_units(
            configured_num_tests,
            1,
            "information_leakage_num_tests_cap",
            "information_leakage.num_tests",
        );

        tracing::info!(
            "Running information leakage detection with {} tests",
            num_tests
        );

        let inspector = match self.executor.constraint_inspector() {
            Some(inspector) => inspector,
            None => {
                anyhow::bail!(
                    "Information leakage attack requires constraint inspector, but none is available"
                );
            }
        };

        let public_indices = inspector.public_input_indices();
        let private_indices = inspector.private_input_indices();
        let output_indices = inspector.output_indices();

        if private_indices.is_empty() {
            anyhow::bail!(
                "Information leakage attack requires private inputs, but none were discovered"
            );
        }

        let constraints = inspector.get_constraints();
        if constraints.is_empty() {
            anyhow::bail!(
                "Information leakage attack requires constraint data, but inspector returned none"
            );
        }

        let mut analyzer = TaintAnalyzer::new(public_indices.len(), private_indices.len());
        if !public_indices.is_empty() || !private_indices.is_empty() {
            analyzer.initialize_inputs_with_indices(&public_indices, &private_indices);
        } else {
            analyzer.initialize_inputs();
        }
        if !output_indices.is_empty() {
            analyzer.mark_outputs(&output_indices);
        } else {
            analyzer.mark_outputs_from_constraints(&constraints);
        }
        analyzer.propagate_constraints(&constraints);

        let findings = analyzer.to_findings();
        if !findings.is_empty() {
            self.with_findings_write(|store| store.extend(findings.iter().cloned()))?;
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        if let Some(p) = progress {
            for _ in 0..num_tests {
                p.inc();
            }
        }

        Ok(())
    }

    pub(super) async fn run_timing_sidechannel_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::analysis::profiling::Profiler;

        let configured_num_samples = config
            .get("num_samples")
            .and_then(|v| v.as_u64())
            .or_value(1000) as usize;
        let num_samples = self.bounded_attack_units(
            configured_num_samples,
            1,
            "timing_sidechannel_num_samples_cap",
            "timing_sidechannel.num_samples",
        );

        tracing::info!(
            "Running timing side-channel detection with {} samples",
            num_samples
        );

        let profiler = Profiler::new().with_samples(num_samples);
        let profile = {
            let rng = self.core.rng_mut();
            profiler.profile(&self.executor, rng)
        };

        if profile.execution_stats.has_timing_variation() {
            let finding = Finding {
                attack_type: AttackType::TimingSideChannel,
                severity: Severity::Medium,
                description: format!(
                    "Timing side-channel detected: execution time varies significantly (CV: {:.2}%)",
                    (profile.execution_stats.std_dev_us / profile.execution_stats.mean_us) * 100.0
                ),
                poc: super::ProofOfConcept {
                    witness_a: vec![],
                    witness_b: None,
                    public_inputs: vec![],
                    proof: None,
                },
                location: None,
            };

            self.with_findings_write(|store| store.push(finding.clone()))?;
            if let Some(p) = progress {
                p.log_finding("MEDIUM", &finding.description);
            }
        }

        if let Some(p) = progress {
            for _ in 0..num_samples {
                p.inc();
            }
        }

        Ok(())
    }

    pub(super) async fn run_recursive_proof_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::multi_circuit::recursive::{RecursionResult, RecursiveTester};

        let configured_num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .or_value(100) as usize;
        let configured_num_tests = strict_attack_floor(
            &self.config.campaign.parameters.additional,
            configured_num_tests,
            256,
            "metamorphic.num_tests",
        );
        let num_tests = self.bounded_attack_units(
            configured_num_tests,
            1,
            "recursive_proof_num_tests_cap",
            "recursive_proof.num_tests",
        );

        let max_depth = config.get("max_depth").and_then(|v| v.as_u64()).or_value(3) as usize;

        tracing::info!(
            "Running recursive proof fuzzing with {} tests, max depth {}",
            num_tests,
            max_depth
        );

        let tester = RecursiveTester::new(max_depth).with_verifier(self.executor.clone());

        for _ in 0..num_tests {
            if self.wall_clock_timeout_reached() {
                tracing::warn!("Stopping recursive proof attack early: wall-clock timeout reached");
                break;
            }
            let test_case = self.generate_random_test_case();
            let result = tester.test_recursion(&test_case.inputs, max_depth);

            match result {
                RecursionResult::VerificationFailed { depth, error } => {
                    let finding = Finding {
                        attack_type: AttackType::RecursiveProof,
                        severity: Severity::High,
                        description: format!(
                            "Recursive verification failed at depth {}: {}",
                            depth, error
                        ),
                        poc: super::ProofOfConcept {
                            witness_a: test_case.inputs.clone(),
                            witness_b: None,
                            public_inputs: vec![],
                            proof: None,
                        },
                        location: None,
                    };

                    self.with_findings_write(|store| store.push(finding.clone()))?;
                    if let Some(p) = progress {
                        p.log_finding("HIGH", &finding.description);
                    }
                }
                RecursionResult::Error(err) => {
                    tracing::warn!("Recursive test error: {}", err);
                }
                _ => {}
            }

            if let Some(p) = progress {
                p.inc();
            }
        }

        Ok(())
    }
}
