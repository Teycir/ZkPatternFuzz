//! Core fuzzing engine with coverage-guided execution
//!
//! This module provides the main fuzzing engine that coordinates
//! test case generation, execution, coverage tracking, and attack detection.

use super::{Finding, FieldElement, TestCase, TestMetadata, mutate_field_element, bn254_modulus_bytes};
use crate::analysis::symbolic::{SymbolicFuzzerIntegration, SymbolicConfig, VulnerabilityPattern};
use crate::config::*;
use crate::corpus::{CorpusEntry, SharedCorpus, create_corpus};
use crate::executor::{CircuitExecutor, ExecutorFactory, SharedCoverageTracker, create_coverage_tracker};
use crate::progress::{FuzzingStats, ProgressReporter};
use crate::reporting::FuzzReport;

use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use rayon::prelude::*;
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use std::time::Instant;

/// Enhanced fuzzer engine with coverage-guided fuzzing and symbolic execution
pub struct FuzzingEngine {
    config: FuzzConfig,
    executor: Arc<dyn CircuitExecutor>,
    corpus: SharedCorpus,
    coverage: SharedCoverageTracker,
    findings: Arc<std::sync::RwLock<Vec<Finding>>>,
    rng: StdRng,
    stats: Arc<std::sync::RwLock<FuzzingStats>>,
    execution_count: AtomicU64,
    workers: usize,
    /// Symbolic execution integration for guided test generation
    symbolic: Option<SymbolicFuzzerIntegration>,
}

impl FuzzingEngine {
    /// Create a new fuzzing engine
    pub fn new(config: FuzzConfig, seed: Option<u64>, workers: usize) -> anyhow::Result<Self> {
        let rng = match seed {
            Some(s) => StdRng::seed_from_u64(s),
            None => StdRng::from_entropy(),
        };

        // Create executor based on framework
        let executor = ExecutorFactory::create(
            config.campaign.target.framework,
            config.campaign.target.circuit_path.to_str().unwrap_or(""),
            &config.campaign.target.main_component,
        )?;

        let num_constraints = executor.num_constraints().max(100);
        let coverage = create_coverage_tracker(num_constraints);
        let corpus = create_corpus(10000);

        // Initialize symbolic execution integration
        let num_inputs = config.inputs.len().max(1);
        let symbolic = Some(SymbolicFuzzerIntegration::new(num_inputs).with_config(
            SymbolicConfig {
                max_paths: 100,
                max_depth: 20,
                solver_timeout_ms: 2000,
                generate_boundary_tests: true,
                solutions_per_path: 2,
            }
        ));

        Ok(Self {
            config,
            executor,
            corpus,
            coverage,
            findings: Arc::new(std::sync::RwLock::new(Vec::new())),
            rng,
            stats: Arc::new(std::sync::RwLock::new(FuzzingStats::default())),
            execution_count: AtomicU64::new(0),
            workers,
            symbolic,
        })
    }

    /// Run the fuzzing campaign
    pub async fn run(&mut self, progress: Option<&ProgressReporter>) -> anyhow::Result<FuzzReport> {
        let start_time = Instant::now();

        tracing::info!("Starting fuzzing campaign: {}", self.config.campaign.name);
        tracing::info!("Circuit: {} ({:?})", 
            self.executor.name(), 
            self.executor.framework()
        );
        tracing::info!("Workers: {}", self.workers);

        // Check for underconstrained circuit
        if self.executor.is_likely_underconstrained() {
            tracing::warn!(
                "Circuit appears underconstrained (DOF = {})",
                self.executor.circuit_info().degrees_of_freedom()
            );
        }

        // Seed corpus
        self.seed_corpus()?;
        tracing::info!("Seeded corpus with {} initial test cases", self.corpus.len());

        // Run attacks
        for attack_config in &self.config.attacks.clone() {
            if let Some(p) = progress {
                p.log_attack_start(&format!("{:?}", attack_config.attack_type));
            }

            let findings_before = self.findings.read().unwrap().len();

            match attack_config.attack_type {
                AttackType::Underconstrained => {
                    self.run_underconstrained_attack(&attack_config.config, progress).await?;
                }
                AttackType::Soundness => {
                    self.run_soundness_attack(&attack_config.config, progress).await?;
                }
                AttackType::ArithmeticOverflow => {
                    self.run_arithmetic_attack(&attack_config.config, progress).await?;
                }
                AttackType::Collision => {
                    self.run_collision_attack(&attack_config.config, progress).await?;
                }
                AttackType::Boundary => {
                    self.run_boundary_attack(&attack_config.config, progress).await?;
                }
                _ => {
                    tracing::warn!("Attack type {:?} not yet implemented", attack_config.attack_type);
                }
            }

            let findings_after = self.findings.read().unwrap().len();
            let new_findings = findings_after - findings_before;

            if let Some(p) = progress {
                p.log_attack_complete(&format!("{:?}", attack_config.attack_type), new_findings);
            }
        }

        // Generate report
        let elapsed = start_time.elapsed();
        let findings = self.findings.read().unwrap().clone();

        tracing::info!(
            "Fuzzing complete: {} findings in {:.2}s",
            findings.len(),
            elapsed.as_secs_f64()
        );

        Ok(self.generate_report(findings, elapsed.as_secs()))
    }

    /// Seed the corpus with initial interesting values
    fn seed_corpus(&mut self) -> anyhow::Result<()> {
        // Add zero case
        self.add_to_corpus(self.create_test_case_with_value(FieldElement::zero()));

        // Add one case
        self.add_to_corpus(self.create_test_case_with_value(FieldElement::one()));

        // Add interesting values from input specs
        for input in &self.config.inputs {
            for interesting in &input.interesting {
                if let Ok(fe) = FieldElement::from_hex(interesting) {
                    self.add_to_corpus(self.create_test_case_with_value(fe));
                }
            }
        }

        // Add field boundary values
        let boundary_values = vec![
            "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000", // p - 1
            "0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000", // (p-1)/2
        ];

        for hex in boundary_values {
            if let Ok(fe) = FieldElement::from_hex(hex) {
                self.add_to_corpus(self.create_test_case_with_value(fe));
            }
        }

        // Generate seeds from symbolic execution
        let symbolic_test_cases = if let Some(ref mut symbolic) = self.symbolic {
            tracing::info!("Generating symbolic execution seeds...");
            
            let mut test_cases = Vec::new();
            
            // Generate initial seeds using symbolic solver
            let symbolic_seeds = symbolic.generate_seeds(20);
            let expected_len = self.config.inputs.len();
            for inputs in symbolic_seeds {
                if inputs.len() == expected_len {
                    test_cases.push(TestCase {
                        inputs,
                        expected_output: None,
                        metadata: TestMetadata::default(),
                    });
                }
            }

            // Generate vulnerability-targeted test cases
            let vuln_patterns = vec![
                VulnerabilityPattern::OverflowBoundary,
                VulnerabilityPattern::ZeroDivision,
                VulnerabilityPattern::BitDecomposition { bits: 8 },
                VulnerabilityPattern::BitDecomposition { bits: 64 },
            ];

            for pattern in vuln_patterns {
                let targeted_tests = symbolic.generate_vulnerability_tests(pattern);
                for inputs in targeted_tests {
                    if inputs.len() >= expected_len {
                        let truncated: Vec<_> = inputs.into_iter()
                            .take(expected_len)
                            .collect();
                        test_cases.push(TestCase {
                            inputs: truncated,
                            expected_output: None,
                            metadata: TestMetadata::default(),
                        });
                    }
                }
            }

            let stats = symbolic.stats();
            tracing::info!(
                "Symbolic execution: {} paths explored, {} tests generated",
                stats.paths_explored,
                stats.tests_generated
            );
            
            test_cases
        } else {
            Vec::new()
        };
        
        // Add symbolic test cases to corpus
        for test_case in symbolic_test_cases {
            self.add_to_corpus(test_case);
        }

        // Add random cases
        for _ in 0..10 {
            let test_case = self.generate_random_test_case();
            self.add_to_corpus(test_case);
        }

        Ok(())
    }

    fn add_to_corpus(&self, test_case: TestCase) {
        let result = self.executor.execute_sync(&test_case.inputs);
        let coverage_hash = result.coverage.coverage_hash;

        let entry = CorpusEntry::new(test_case, coverage_hash);
        self.corpus.add(entry);

        // Record coverage
        self.coverage.record_execution(&result.coverage.satisfied_constraints);
    }

    fn create_test_case_with_value(&self, value: FieldElement) -> TestCase {
        let inputs: Vec<FieldElement> = self.config.inputs.iter()
            .map(|_| value.clone())
            .collect();

        TestCase {
            inputs,
            expected_output: None,
            metadata: TestMetadata::default(),
        }
    }

    fn generate_random_test_case(&mut self) -> TestCase {
        let inputs: Vec<FieldElement> = self.config.inputs.iter()
            .map(|_| FieldElement::random(&mut self.rng))
            .collect();

        TestCase {
            inputs,
            expected_output: None,
            metadata: TestMetadata::default(),
        }
    }

    fn generate_test_case(&mut self) -> TestCase {
        // Try to get from corpus and mutate
        if let Some(entry) = self.corpus.get_random(&mut self.rng) {
            let mutated_inputs: Vec<FieldElement> = entry.test_case.inputs.iter()
                .map(|input| {
                    if self.rng.gen::<f64>() < 0.3 {
                        mutate_field_element(input, &mut self.rng)
                    } else {
                        input.clone()
                    }
                })
                .collect();

            TestCase {
                inputs: mutated_inputs,
                expected_output: None,
                metadata: TestMetadata {
                    generation: entry.test_case.metadata.generation + 1,
                    ..Default::default()
                },
            }
        } else {
            self.generate_random_test_case()
        }
    }

    /// Execute test case and update coverage
    /// 
    /// Note: There's a potential race condition between checking is_new and
    /// adding to corpus. However, the corpus.add() method has its own
    /// duplicate detection which prevents actual duplicates. The worst case
    /// is that we might miss adding a test case that another thread added
    /// first with the same coverage, which is acceptable behavior.
    fn execute_and_track(&self, test_case: &TestCase) -> crate::executor::ExecutionResult {
        let result = self.executor.execute_sync(&test_case.inputs);
        self.execution_count.fetch_add(1, Ordering::Relaxed);

        // Track coverage - record_execution is already thread-safe
        let is_new = self.coverage.record_execution(&result.coverage.satisfied_constraints);

        // Add to corpus if new coverage discovered
        // The corpus.add() method has built-in deduplication, so even if
        // another thread adds the same coverage between our check and add,
        // we won't get duplicates (add returns false for duplicates)
        if is_new && result.success {
            let entry = CorpusEntry::new(test_case.clone(), result.coverage.coverage_hash)
                .with_new_coverage();
            // add() returns false if entry already exists, preventing duplicates
            let _ = self.corpus.add(entry);
        }

        result
    }

    /// Run underconstrained circuit detection with parallel execution
    async fn run_underconstrained_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        let witness_pairs: usize = config
            .get("witness_pairs")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000) as usize;

        tracing::info!("Testing {} witness pairs for underconstrained circuits", witness_pairs);

        // Generate test cases
        let test_cases: Vec<TestCase> = (0..witness_pairs)
            .map(|_| self.generate_test_case())
            .collect();

        // Execute in parallel and collect outputs
        let executor = self.executor.clone();
        let results: Vec<_> = test_cases.par_iter()
            .map(|tc| {
                let result = executor.execute_sync(&tc.inputs);
                (tc.clone(), result)
            })
            .collect();

        // Group by output hash to find collisions
        let mut output_map: std::collections::HashMap<Vec<u8>, Vec<TestCase>> = 
            std::collections::HashMap::new();

        for (test_case, result) in results {
            if result.success {
                let output_hash = self.hash_output(&result.outputs);
                output_map.entry(output_hash).or_default().push(test_case);
            }

            if let Some(p) = progress {
                p.inc();
            }
        }

        // Check for collisions
        for (_hash, witnesses) in output_map {
            if witnesses.len() > 1 && self.witnesses_are_different(&witnesses) {
                let finding = Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: Severity::Critical,
                    description: format!(
                        "Found {} different witnesses producing identical output",
                        witnesses.len()
                    ),
                    poc: super::ProofOfConcept {
                        witness_a: witnesses[0].inputs.clone(),
                        witness_b: Some(witnesses[1].inputs.clone()),
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: None,
                };

                self.findings.write().unwrap().push(finding.clone());

                if let Some(p) = progress {
                    p.log_finding("CRITICAL", &finding.description);
                }
            }
        }

        Ok(())
    }

    async fn run_soundness_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        let forge_attempts: usize = config
            .get("forge_attempts")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000) as usize;

        let mutation_rate: f64 = config
            .get("mutation_rate")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.1);

        tracing::info!("Attempting {} proof forgeries", forge_attempts);

        for _ in 0..forge_attempts {
            let valid_case = self.generate_test_case();
            let valid_proof = self.executor.prove(&valid_case.inputs)?;

            // Mutate inputs
            let mutated_inputs: Vec<FieldElement> = valid_case.inputs.iter()
                .map(|input| {
                    if self.rng.gen::<f64>() < mutation_rate {
                        mutate_field_element(input, &mut self.rng)
                    } else {
                        input.clone()
                    }
                })
                .collect();

            // Try to verify with mutated inputs
            if self.executor.verify(&valid_proof, &mutated_inputs)? {
                let finding = Finding {
                    attack_type: AttackType::Soundness,
                    severity: Severity::Critical,
                    description: "Proof verified with mutated inputs - soundness violation!".to_string(),
                    poc: super::ProofOfConcept {
                        witness_a: valid_case.inputs,
                        witness_b: Some(mutated_inputs),
                        public_inputs: vec![],
                        proof: Some(valid_proof),
                    },
                    location: None,
                };

                self.findings.write().unwrap().push(finding.clone());

                if let Some(p) = progress {
                    p.log_finding("CRITICAL", &finding.description);
                }
            }

            if let Some(p) = progress {
                p.inc();
            }
        }

        Ok(())
    }

    async fn run_arithmetic_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        let test_values = config
            .get("test_values")
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec![
                "0".to_string(),
                "1".to_string(),
                "p-1".to_string(),
                "p".to_string(),
            ]);

        tracing::info!("Testing {} arithmetic edge cases", test_values.len());

        let field_modulus = self.get_field_modulus();

        for value in test_values {
            let expanded = match crate::config::parser::expand_value_placeholder(&value, &field_modulus) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!("Skipping invalid arithmetic test value '{}': {}", value, e);
                    continue;
                }
            };
            let mut fe_bytes = [0u8; 32];
            let start = 32_usize.saturating_sub(expanded.len());
            fe_bytes[start..].copy_from_slice(&expanded[..expanded.len().min(32)]);
            let fe = FieldElement(fe_bytes);

            let test_case = self.create_test_case_with_value(fe);
            let result = self.execute_and_track(&test_case);

            if result.success && self.detect_overflow_indicator(&result.outputs) {
                let finding = Finding {
                    attack_type: AttackType::ArithmeticOverflow,
                    severity: Severity::High,
                    description: format!("Potential arithmetic overflow with value: {}", value),
                    poc: super::ProofOfConcept {
                        witness_a: test_case.inputs,
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: None,
                };

                self.findings.write().unwrap().push(finding.clone());

                if let Some(p) = progress {
                    p.log_finding("HIGH", &finding.description);
                }
            }

            if let Some(p) = progress {
                p.inc();
            }
        }

        Ok(())
    }

    async fn run_collision_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        let samples: usize = config
            .get("samples")
            .and_then(|v| v.as_u64())
            .unwrap_or(10000) as usize;

        tracing::info!("Running collision detection with {} samples", samples);

        // Generate and execute in parallel
        let test_cases: Vec<TestCase> = (0..samples)
            .map(|_| self.generate_test_case())
            .collect();

        let executor = self.executor.clone();
        let results: Vec<_> = test_cases.par_iter()
            .map(|tc| {
                let result = executor.execute_sync(&tc.inputs);
                (tc.clone(), result)
            })
            .collect();

        let mut hash_map: std::collections::HashMap<Vec<u8>, TestCase> = 
            std::collections::HashMap::new();

        for (test_case, result) in results {
            if result.success {
                let output_hash = self.hash_output(&result.outputs);

                if let Some(existing) = hash_map.get(&output_hash) {
                    if existing.inputs != test_case.inputs {
                        let finding = Finding {
                            attack_type: AttackType::Collision,
                            severity: Severity::Critical,
                            description: "Found collision: different inputs produce same output".to_string(),
                            poc: super::ProofOfConcept {
                                witness_a: existing.inputs.clone(),
                                witness_b: Some(test_case.inputs),
                                public_inputs: vec![],
                                proof: None,
                            },
                            location: None,
                        };

                        self.findings.write().unwrap().push(finding.clone());

                        if let Some(p) = progress {
                            p.log_finding("CRITICAL", &finding.description);
                        }
                    }
                } else {
                    hash_map.insert(output_hash, test_case);
                }
            }

            if let Some(p) = progress {
                p.inc();
            }
        }

        Ok(())
    }

    async fn run_boundary_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        let test_values = config
            .get("test_values")
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec![
                "0".to_string(),
                "1".to_string(),
                "p-1".to_string(),
            ]);

        tracing::info!("Testing {} boundary values", test_values.len());

        let field_modulus = self.get_field_modulus();

        for value in test_values {
            let expanded = match crate::config::parser::expand_value_placeholder(&value, &field_modulus) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!("Skipping invalid boundary test value '{}': {}", value, e);
                    continue;
                }
            };
            let mut fe_bytes = [0u8; 32];
            let start = 32_usize.saturating_sub(expanded.len());
            fe_bytes[start..].copy_from_slice(&expanded[..expanded.len().min(32)]);
            let fe = FieldElement(fe_bytes);

            let test_case = self.create_test_case_with_value(fe);
            let _ = self.execute_and_track(&test_case);

            if let Some(p) = progress {
                p.inc();
            }
        }

        Ok(())
    }

    fn hash_output(&self, output: &[FieldElement]) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        for fe in output {
            hasher.update(fe.0);
        }
        hasher.finalize().to_vec()
    }

    fn witnesses_are_different(&self, witnesses: &[TestCase]) -> bool {
        if witnesses.len() < 2 {
            return false;
        }

        for i in 0..witnesses.len() {
            for j in (i + 1)..witnesses.len() {
                if witnesses[i].inputs != witnesses[j].inputs {
                    return true;
                }
            }
        }
        false
    }

    fn get_field_modulus(&self) -> [u8; 32] {
        // Use centralized field constants
        bn254_modulus_bytes()
    }

    fn detect_overflow_indicator(&self, output: &[FieldElement]) -> bool {
        for fe in output {
            let is_near_zero = fe.0.iter().take(30).all(|&b| b == 0);
            let is_near_max = fe.0.iter().take(30).all(|&b| b == 0xff);
            if is_near_zero || is_near_max {
                return true;
            }
        }
        false
    }

    fn generate_report(&self, findings: Vec<Finding>, duration: u64) -> FuzzReport {
        let mut report = FuzzReport::new(
            self.config.campaign.name.clone(),
            findings,
            crate::fuzzer::CoverageMap {
                constraint_hits: std::collections::HashMap::new(),
                edge_coverage: self.coverage.unique_constraints_hit() as u64,
                max_coverage: self.executor.num_constraints() as u64,
            },
            self.config.reporting.clone(),
        );
        report.duration_seconds = duration;
        report.statistics.total_executions = self.execution_count.load(Ordering::Relaxed);
        report
    }

    /// Get current statistics
    pub fn stats(&self) -> FuzzingStats {
        FuzzingStats {
            executions: self.execution_count.load(Ordering::Relaxed),
            crashes: self.findings.read().unwrap().len() as u64,
            coverage_percentage: self.coverage.coverage_percentage(),
            unique_crashes: self.findings.read().unwrap().len() as u64,
            corpus_size: self.corpus.len(),
            new_coverage_count: self.coverage.new_coverage_count(),
            ..Default::default()
        }
    }
}
