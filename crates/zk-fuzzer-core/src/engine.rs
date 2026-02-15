//! Generic core fuzzing engine utilities.

use crate::corpus::{storage as corpus_storage, CorpusEntry, SharedCorpus};
use crate::coverage::SharedCoverageTracker;
use crate::mutators::mutate_field_element;
use crate::oracle::BugOracle;
use crate::power_schedule::{PowerScheduler, TestCaseMetrics};
use crate::structure_aware::{Splicer, StructureAwareMutator};
use crate::FuzzingStats;
use anyhow::{anyhow, Result};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};
use std::time::{Duration, Instant};
use zk_core::{CircuitExecutor, ExecutionResult, FieldElement, Finding, TestCase, TestMetadata};

/// Core engine state shared by higher-level orchestrators.
pub struct FuzzingEngineCore {
    corpus: SharedCorpus,
    coverage: SharedCoverageTracker,
    rng: StdRng,
    stats: Arc<RwLock<FuzzingStats>>,
    execution_count: AtomicU64,
    power_scheduler: PowerScheduler,
    structure_mutator: StructureAwareMutator,
    start_time: Option<Instant>,
    avg_exec_time: Arc<RwLock<Duration>>,
    findings: Arc<RwLock<Vec<Finding>>>,
    input_count: usize,
    oracles: Vec<Box<dyn BugOracle>>,
    constraint_count_cache: Option<usize>,
}

impl FuzzingEngineCore {
    pub fn builder() -> FuzzingEngineCoreBuilder {
        FuzzingEngineCoreBuilder::new()
    }

    pub fn new(
        seed: Option<u64>,
        input_count: usize,
        corpus: SharedCorpus,
        coverage: SharedCoverageTracker,
        power_scheduler: PowerScheduler,
        structure_mutator: StructureAwareMutator,
        oracles: Vec<Box<dyn BugOracle>>,
    ) -> Self {
        Self::builder()
            .seed(seed)
            .input_count(input_count)
            .corpus(corpus)
            .coverage(coverage)
            .power_scheduler(power_scheduler)
            .structure_mutator(structure_mutator)
            .oracles(oracles)
            .build()
            .expect("FuzzingEngineCore::new should have all required fields")
    }

    pub fn set_start_time(&mut self, start_time: Instant) {
        self.start_time = Some(start_time);
    }

    pub fn corpus(&self) -> &SharedCorpus {
        &self.corpus
    }

    pub fn coverage(&self) -> &SharedCoverageTracker {
        &self.coverage
    }

    pub fn rng_mut(&mut self) -> &mut StdRng {
        &mut self.rng
    }

    pub fn findings(&self) -> Arc<RwLock<Vec<Finding>>> {
        self.findings.clone()
    }

    pub fn execution_count(&self) -> u64 {
        self.execution_count.load(Ordering::Relaxed)
    }

    pub fn stats(&self) -> FuzzingStats {
        if let Ok(stats) = self.stats.read() {
            stats.clone()
        } else {
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

    pub fn update_power_scheduler_globals(&mut self) {
        let avg_time = self
            .avg_exec_time
            .read()
            .map(|t| *t)
            .unwrap_or(Duration::from_micros(100));
        let total_edges = self.coverage.unique_constraints_hit() as u64;
        self.power_scheduler.update_globals(avg_time, total_edges);
    }

    pub fn create_test_case_with_value(&self, value: FieldElement) -> TestCase {
        let inputs: Vec<FieldElement> = (0..self.input_count).map(|_| value.clone()).collect();

        TestCase {
            inputs,
            expected_output: None,
            metadata: TestMetadata::default(),
        }
    }

    pub fn generate_random_test_case(&mut self) -> TestCase {
        let inputs: Vec<FieldElement> = (0..self.input_count)
            .map(|_| FieldElement::random(&mut self.rng))
            .collect();

        TestCase {
            inputs,
            expected_output: None,
            metadata: TestMetadata::default(),
        }
    }

    pub fn generate_test_case(&mut self) -> TestCase {
        if let Some(entry) = self.corpus.get_random(&mut self.rng) {
            let metrics = TestCaseMetrics {
                selection_count: entry.execution_count,
                new_coverage_count: if entry.discovered_new_coverage { 1 } else { 0 },
                findings_count: 0,
                avg_execution_time: Duration::from_micros(100),
                path_frequency: 1,
                generation: entry.test_case.metadata.generation as u32,
                depth: entry.test_case.metadata.generation as u32,
                time_since_finding: self
                    .start_time
                    .map(|t| t.elapsed())
                    .unwrap_or(Duration::ZERO),
            };

            let energy = self.power_scheduler.calculate_energy(&metrics);
            let mutation_strategy = self.rng.gen_range(0..100);

            let mutated_inputs = if mutation_strategy < 40 {
                self.structure_mutator
                    .mutate(&entry.test_case.inputs, &mut self.rng)
            } else if mutation_strategy < 70 {
                entry
                    .test_case
                    .inputs
                    .iter()
                    .map(|input| {
                        if self.rng.gen::<f64>() < 0.3 {
                            mutate_field_element(input, &mut self.rng)
                        } else {
                            input.clone()
                        }
                    })
                    .collect()
            } else if mutation_strategy < 85 {
                if let Some(other) = self.corpus.get_random(&mut self.rng) {
                    if self.rng.gen::<f64>() < 0.5 {
                        Splicer::splice(
                            &entry.test_case.inputs,
                            &other.test_case.inputs,
                            &mut self.rng,
                        )
                    } else {
                        Splicer::insert(
                            &entry.test_case.inputs,
                            &other.test_case.inputs,
                            &mut self.rng,
                        )
                    }
                } else {
                    entry.test_case.inputs.clone()
                }
            } else {
                let mut inputs = entry.test_case.inputs.clone();
                let num_mutations = self.rng.gen_range(1..=energy.min(10));
                for _ in 0..num_mutations {
                    let idx = self.rng.gen_range(0..inputs.len().max(1));
                    if idx < inputs.len() {
                        inputs[idx] = mutate_field_element(&inputs[idx], &mut self.rng);
                    }
                }
                inputs
            };

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

    pub fn add_to_corpus(&self, executor: &dyn CircuitExecutor, test_case: TestCase) {
        let result = executor.execute_sync(&test_case.inputs);
        let coverage_hash = result.coverage.coverage_hash;

        let entry = CorpusEntry::new(test_case, coverage_hash);
        self.corpus.add(entry);

        if result.coverage.satisfied_constraints.is_empty()
            && result.coverage.evaluated_constraints.is_empty()
        {
            self.coverage
                .record_coverage_hash(result.coverage.coverage_hash);
        } else {
            self.coverage.record_execution(&result.coverage);
        }
    }

    pub fn execute_and_track(
        &mut self,
        executor: &dyn CircuitExecutor,
        test_case: &TestCase,
    ) -> ExecutionResult {
        let exec_start = Instant::now();
        let mut result = executor.execute_sync(&test_case.inputs);
        let exec_time = exec_start.elapsed();

        self.execution_count.fetch_add(1, Ordering::Relaxed);

        if let Ok(mut avg_time) = self.avg_exec_time.write() {
            let current_avg_micros = avg_time.as_micros() as f64;
            let new_exec_micros = exec_time.as_micros() as f64;
            let updated_avg = current_avg_micros * 0.9 + new_exec_micros * 0.1;
            *avg_time = Duration::from_micros(updated_avg as u64);
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.executions = self.execution_count.load(Ordering::Relaxed);
            stats.corpus_size = self.corpus.len();
            stats.crashes = self.findings.read().unwrap().len() as u64;
            stats.unique_crashes = self.findings.read().unwrap().len() as u64;
            stats.coverage_percentage = self.coverage.coverage_percentage();
            if let Some(start) = self.start_time {
                stats.update_exec_rate(start);
            }
        }

        let is_new = if result.coverage.satisfied_constraints.is_empty()
            && result.coverage.evaluated_constraints.is_empty()
        {
            self.coverage
                .record_coverage_hash(result.coverage.coverage_hash)
        } else {
            self.coverage.record_execution(&result.coverage)
        };

        if is_new {
            result.coverage.mark_new_coverage();
        }

        if is_new && result.success {
            let entry = CorpusEntry::new(test_case.clone(), result.coverage.coverage_hash)
                .with_new_coverage();
            if self.corpus.add(entry) {
                if let Ok(mut stats) = self.stats.write() {
                    stats.new_coverage_count += 1;
                }
            }
        }

        if result.success {
            let needs_constraint_count = self
                .oracles
                .iter()
                .any(|oracle| oracle.requires_constraint_count());
            let constraint_count = if needs_constraint_count {
                if self.constraint_count_cache.is_none() {
                    let count = if let Some(inspector) = executor.constraint_inspector() {
                        let constraints = inspector.get_constraints();
                        if constraints.is_empty() {
                            executor.num_constraints()
                        } else {
                            constraints.len()
                        }
                    } else {
                        executor.num_constraints()
                    };
                    self.constraint_count_cache = Some(count);
                }
                self.constraint_count_cache
            } else {
                None
            };

            let oracle_findings = self.run_oracles(test_case, &result.outputs, constraint_count);
            if !oracle_findings.is_empty() {
                let mut findings = self.findings.write().unwrap();
                findings.extend(oracle_findings);
            }
        }

        result
    }

    pub fn execute_and_learn(
        &mut self,
        executor: &dyn CircuitExecutor,
        test_case: &TestCase,
    ) -> ExecutionResult {
        let result = self.execute_and_track(executor, test_case);

        if result.success {
            self.learn_mutation_patterns(test_case, &result);
        }

        result
    }

    pub fn check_proof_forgery(
        &mut self,
        original_inputs: &[FieldElement],
        mutated_inputs: &[FieldElement],
        proof: &[u8],
        verified: bool,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for oracle in &mut self.oracles {
            if let Some(finding) =
                oracle.check_with_verification(original_inputs, mutated_inputs, proof, verified)
            {
                tracing::warn!(
                    "Oracle '{}' detected issue: {}",
                    oracle.name(),
                    finding.description
                );
                findings.push(finding);
            }
        }

        if !findings.is_empty() {
            let mut stored = self.findings.write().unwrap();
            stored.extend(findings.clone());
        }

        findings
    }

    pub fn export_corpus(&self, output_dir: &std::path::Path) -> anyhow::Result<usize> {
        let entries = self.corpus.all_entries();
        corpus_storage::export_interesting_cases(&entries, output_dir)
    }

    fn run_oracles(
        &mut self,
        test_case: &TestCase,
        outputs: &[FieldElement],
        constraint_count: Option<usize>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for oracle in &mut self.oracles {
            if let Some(count) = constraint_count {
                if oracle.requires_constraint_count() {
                    if let Some(finding) = oracle.check_with_count(test_case, count) {
                        tracing::warn!(
                            "Oracle '{}' detected issue: {}",
                            oracle.name(),
                            finding.description
                        );
                        findings.push(finding);
                    }
                    continue;
                }
            }

            if let Some(finding) = oracle.check(test_case, outputs) {
                tracing::warn!(
                    "Oracle '{}' detected issue: {}",
                    oracle.name(),
                    finding.description
                );
                findings.push(finding);
            }
        }
        findings
    }

    fn learn_mutation_patterns(&mut self, test_case: &TestCase, result: &ExecutionResult) {
        if result.success && !result.outputs.is_empty() {
            for (i, input) in test_case.inputs.iter().enumerate() {
                let pattern_name = format!("input_{}", i);
                self.structure_mutator
                    .learn_pattern(&pattern_name, vec![input.clone()]);
            }
        }
    }
}

pub struct FuzzingEngineCoreBuilder {
    seed: Option<u64>,
    input_count: Option<usize>,
    corpus: Option<SharedCorpus>,
    coverage: Option<SharedCoverageTracker>,
    power_scheduler: Option<PowerScheduler>,
    structure_mutator: Option<StructureAwareMutator>,
    oracles: Vec<Box<dyn BugOracle>>,
    constraint_count_cache: Option<usize>,
}

impl Default for FuzzingEngineCoreBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FuzzingEngineCoreBuilder {
    pub fn new() -> Self {
        Self {
            seed: None,
            input_count: None,
            corpus: None,
            coverage: None,
            power_scheduler: None,
            structure_mutator: None,
            oracles: Vec::new(),
            constraint_count_cache: None,
        }
    }

    pub fn seed(mut self, seed: Option<u64>) -> Self {
        self.seed = seed;
        self
    }

    pub fn input_count(mut self, input_count: usize) -> Self {
        self.input_count = Some(input_count);
        self
    }

    pub fn corpus(mut self, corpus: SharedCorpus) -> Self {
        self.corpus = Some(corpus);
        self
    }

    pub fn coverage(mut self, coverage: SharedCoverageTracker) -> Self {
        self.coverage = Some(coverage);
        self
    }

    pub fn power_scheduler(mut self, power_scheduler: PowerScheduler) -> Self {
        self.power_scheduler = Some(power_scheduler);
        self
    }

    pub fn structure_mutator(mut self, structure_mutator: StructureAwareMutator) -> Self {
        self.structure_mutator = Some(structure_mutator);
        self
    }

    pub fn oracles(mut self, oracles: Vec<Box<dyn BugOracle>>) -> Self {
        self.oracles = oracles;
        self
    }

    pub fn add_oracle(mut self, oracle: Box<dyn BugOracle>) -> Self {
        self.oracles.push(oracle);
        self
    }

    pub fn build(self) -> Result<FuzzingEngineCore> {
        let corpus = self.corpus.ok_or_else(|| anyhow!("missing corpus"))?;
        let coverage = self.coverage.ok_or_else(|| anyhow!("missing coverage"))?;
        let power_scheduler = self
            .power_scheduler
            .ok_or_else(|| anyhow!("missing power_scheduler"))?;
        let structure_mutator = self
            .structure_mutator
            .ok_or_else(|| anyhow!("missing structure_mutator"))?;
        let input_count = self
            .input_count
            .ok_or_else(|| anyhow!("missing input_count"))?;

        let rng = match self.seed {
            Some(s) => StdRng::seed_from_u64(s),
            None => StdRng::from_entropy(),
        };

        Ok(FuzzingEngineCore {
            corpus,
            coverage,
            rng,
            stats: Arc::new(RwLock::new(FuzzingStats::default())),
            execution_count: AtomicU64::new(0),
            power_scheduler,
            structure_mutator,
            start_time: None,
            avg_exec_time: Arc::new(RwLock::new(Duration::from_micros(100))),
            findings: Arc::new(RwLock::new(Vec::new())),
            input_count: input_count.max(1),
            oracles: self.oracles,
            constraint_count_cache: self.constraint_count_cache,
        })
    }
}
