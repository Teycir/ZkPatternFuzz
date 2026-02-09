//! Batch Verification Bypass Attack Detection (Phase 3: Milestone 3.3)
//!
//! Detects vulnerabilities in batched proof verification systems that could allow
//! invalid proofs to pass verification when combined with valid proofs.
//!
//! # Attack Patterns
//!
//! ## Batch Mixing
//! Mix valid and invalid proofs in a batch to exploit verification shortcuts
//! that don't properly validate all proofs individually.
//!
//! ## Aggregation Forgery
//! Forge aggregated proofs from valid individual proofs by exploiting
//! weaknesses in aggregation schemes (Groth16, Plonk, SnarkPack).
//!
//! ## Cross-Circuit Batch Analysis
//! Batch proofs from different circuits to detect verification bypass
//! vulnerabilities in heterogeneous batching systems.
//!
//! ## Randomness Reuse Detection
//! Detect cases where randomness is reused across batch elements,
//! potentially allowing extraction of secrets or proof forgery.
//!
//! # Usage
//!
//! ```rust,ignore
//! use zk_fuzzer::attacks::batch_verification::{BatchVerificationAttack, BatchVerificationConfig};
//!
//! let config = BatchVerificationConfig::default();
//! let mut attack = BatchVerificationAttack::new(config);
//!
//! // Run attack against batch verifier
//! let findings = attack.run(&executor, &inputs)?;
//! ```
//!
//! # References
//!
//! - SnarkPack: https://eprint.iacr.org/2021/529
//! - Groth16 Batch Verification: https://eprint.iacr.org/2020/811
//! - Plonk Aggregation: https://eprint.iacr.org/2022/1234

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for batch verification attack detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerificationConfig {
    /// Batch sizes to test
    pub batch_sizes: Vec<usize>,
    /// Number of batch mixing tests to run
    pub batch_mixing_tests: usize,
    /// Number of aggregation forgery attempts
    pub aggregation_forgery_tests: usize,
    /// Number of cross-circuit batch tests
    pub cross_circuit_tests: usize,
    /// Number of randomness reuse correlation tests
    pub randomness_reuse_tests: usize,
    /// Enable batch mixing detection
    pub detect_batch_mixing: bool,
    /// Enable aggregation forgery detection
    pub detect_aggregation_forgery: bool,
    /// Enable cross-circuit batch analysis
    pub detect_cross_circuit_batch: bool,
    /// Enable randomness reuse detection
    pub detect_randomness_reuse: bool,
    /// Aggregation methods to test
    pub aggregation_methods: Vec<AggregationMethod>,
    /// Positions in batch to insert invalid proofs
    pub invalid_positions: Vec<InvalidPosition>,
    /// Correlation threshold for randomness reuse detection
    pub correlation_threshold: f64,
    /// Timeout per test in milliseconds
    pub timeout_ms: u64,
    /// Random seed for reproducibility
    pub seed: Option<u64>,
}

impl Default for BatchVerificationConfig {
    fn default() -> Self {
        Self {
            batch_sizes: vec![2, 4, 8, 16, 32],
            batch_mixing_tests: 500,
            aggregation_forgery_tests: 1000,
            cross_circuit_tests: 100,
            randomness_reuse_tests: 500,
            detect_batch_mixing: true,
            detect_aggregation_forgery: true,
            detect_cross_circuit_batch: true,
            detect_randomness_reuse: true,
            aggregation_methods: vec![
                AggregationMethod::NaiveBatch,
                AggregationMethod::SnarkPack,
                AggregationMethod::Groth16Aggregation,
                AggregationMethod::PlonkAggregation,
                AggregationMethod::Halo2Aggregation,
            ],
            invalid_positions: vec![
                InvalidPosition::First,
                InvalidPosition::Last,
                InvalidPosition::Middle,
                InvalidPosition::Random,
            ],
            correlation_threshold: 0.8,
            timeout_ms: 30000,
            seed: None,
        }
    }
}

// ============================================================================
// Vulnerability Types
// ============================================================================

/// Types of batch verification vulnerabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BatchVulnerabilityType {
    /// Invalid proof passes when mixed with valid proofs
    BatchMixingBypass,
    /// Aggregated proof can be forged from individual proofs
    AggregationForgery,
    /// Cross-circuit batching allows verification bypass
    CrossCircuitBypass,
    /// Randomness is reused across batch elements
    RandomnessReuse,
    /// Batch size boundary allows bypass
    BatchSizeBoundary,
    /// Ordering dependency in batch verification
    OrderingDependency,
    /// Subset of batch can be verified as whole
    SubsetForgery,
    /// Malleable aggregated proof
    AggregationMalleability,
    /// Invalid proof index masking
    IndexMasking,
    /// Accumulator manipulation in batch
    AccumulatorManipulation,
}

impl BatchVulnerabilityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BatchMixingBypass => "batch_mixing_bypass",
            Self::AggregationForgery => "aggregation_forgery",
            Self::CrossCircuitBypass => "cross_circuit_bypass",
            Self::RandomnessReuse => "randomness_reuse",
            Self::BatchSizeBoundary => "batch_size_boundary",
            Self::OrderingDependency => "ordering_dependency",
            Self::SubsetForgery => "subset_forgery",
            Self::AggregationMalleability => "aggregation_malleability",
            Self::IndexMasking => "index_masking",
            Self::AccumulatorManipulation => "accumulator_manipulation",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::BatchMixingBypass => Severity::Critical,
            Self::AggregationForgery => Severity::Critical,
            Self::CrossCircuitBypass => Severity::Critical,
            Self::RandomnessReuse => Severity::High,
            Self::BatchSizeBoundary => Severity::High,
            Self::OrderingDependency => Severity::Medium,
            Self::SubsetForgery => Severity::Critical,
            Self::AggregationMalleability => Severity::High,
            Self::IndexMasking => Severity::High,
            Self::AccumulatorManipulation => Severity::Critical,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::BatchMixingBypass => {
                "Invalid proof passes verification when mixed with valid proofs in a batch"
            }
            Self::AggregationForgery => {
                "Aggregated proof can be forged without valid individual proofs"
            }
            Self::CrossCircuitBypass => {
                "Proofs from different circuits bypass verification when batched"
            }
            Self::RandomnessReuse => {
                "Randomness is reused across batch elements, potentially leaking secrets"
            }
            Self::BatchSizeBoundary => "Batch size boundary condition allows verification bypass",
            Self::OrderingDependency => {
                "Proof ordering affects batch verification result incorrectly"
            }
            Self::SubsetForgery => {
                "Subset of proofs can be verified as if they were the entire batch"
            }
            Self::AggregationMalleability => {
                "Aggregated proof can be transformed into a different valid proof"
            }
            Self::IndexMasking => "Invalid proof index is masked by other proofs in batch",
            Self::AccumulatorManipulation => {
                "Batch accumulator can be manipulated to accept invalid proofs"
            }
        }
    }
}

// ============================================================================
// Aggregation Methods
// ============================================================================

/// Supported aggregation methods for testing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AggregationMethod {
    /// Naive batch verification (verify each proof independently)
    NaiveBatch,
    /// SnarkPack aggregation scheme
    SnarkPack,
    /// Groth16 batch verification
    Groth16Aggregation,
    /// Plonk aggregation scheme
    PlonkAggregation,
    /// Halo2 proof aggregation
    Halo2Aggregation,
}

impl AggregationMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NaiveBatch => "naive_batch",
            Self::SnarkPack => "snarkpack",
            Self::Groth16Aggregation => "groth16_aggregation",
            Self::PlonkAggregation => "plonk_aggregation",
            Self::Halo2Aggregation => "halo2_aggregation",
        }
    }
}

// ============================================================================
// Invalid Position Types
// ============================================================================

/// Position to insert invalid proof in batch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InvalidPosition {
    /// First position in batch
    First,
    /// Last position in batch
    Last,
    /// Middle position in batch
    Middle,
    /// Random position in batch
    Random,
    /// Multiple random positions
    MultipleRandom,
}

impl InvalidPosition {
    pub fn get_indices(&self, batch_size: usize, rng: &mut ChaCha8Rng) -> Vec<usize> {
        match self {
            Self::First => vec![0],
            Self::Last => vec![batch_size.saturating_sub(1)],
            Self::Middle => vec![batch_size / 2],
            Self::Random => vec![rng.gen_range(0..batch_size)],
            Self::MultipleRandom => {
                let count = rng.gen_range(1..=batch_size / 2);
                let mut indices: Vec<usize> = (0..batch_size).collect();
                indices.shuffle(rng);
                indices.truncate(count);
                indices
            }
        }
    }
}

// Extend rand::seq::SliceRandom trait usage
use rand::seq::SliceRandom;

// ============================================================================
// Batch Proof Structures
// ============================================================================

/// Represents a single proof in a batch
#[derive(Debug, Clone)]
pub struct BatchProof {
    /// Proof identifier
    pub id: String,
    /// Public inputs for this proof
    pub public_inputs: Vec<FieldElement>,
    /// Proof data (serialized)
    pub proof_data: Vec<u8>,
    /// Whether this proof is known to be valid
    pub is_valid: bool,
    /// Circuit reference (for cross-circuit batching)
    pub circuit_ref: Option<String>,
}

/// Represents a batch of proofs
#[derive(Debug, Clone)]
pub struct ProofBatch {
    /// Proofs in the batch
    pub proofs: Vec<BatchProof>,
    /// Batch metadata
    pub metadata: HashMap<String, String>,
    /// Aggregation method used
    pub aggregation_method: AggregationMethod,
}

/// Result of batch verification
#[derive(Debug, Clone)]
pub struct BatchVerificationResult {
    /// Whether the batch passed verification
    pub passed: bool,
    /// Individual proof results (if available)
    pub individual_results: Vec<bool>,
    /// Verification time in milliseconds
    pub verification_time_ms: u64,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

// ============================================================================
// Batch Verification Finding
// ============================================================================

/// Proof of concept for batch verification findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProofOfConcept {
    /// Inputs that triggered the vulnerability
    pub inputs: Vec<FieldElement>,
    /// Description of how to reproduce
    pub description: String,
}

/// A finding from batch verification attack detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerificationFinding {
    /// Type of vulnerability found
    pub vulnerability_type: BatchVulnerabilityType,
    /// Batch size where vulnerability was found
    pub batch_size: usize,
    /// Position(s) of invalid proof(s) in batch
    pub invalid_positions: Vec<usize>,
    /// Aggregation method where vulnerability was found
    pub aggregation_method: AggregationMethod,
    /// Public inputs that triggered the vulnerability
    pub trigger_inputs: Vec<Vec<FieldElement>>,
    /// Severity of the finding
    pub severity: Severity,
    /// Detailed description
    pub description: String,
    /// Proof of concept data
    pub poc: Option<BatchProofOfConcept>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
}

impl BatchVerificationFinding {
    /// Convert to a generic Finding
    pub fn to_finding(&self) -> Finding {
        // Create ProofOfConcept from trigger_inputs
        let poc = ProofOfConcept {
            witness_a: self.trigger_inputs.first().cloned().unwrap_or_default(),
            witness_b: self.trigger_inputs.get(1).cloned(),
            public_inputs: Vec::new(),
            proof: None,
        };

        Finding {
            attack_type: AttackType::BatchVerification,
            severity: self.severity,
            description: self.description.clone(),
            poc,
            location: Some(format!(
                "batch_size={}, positions={:?}, method={}",
                self.batch_size,
                self.invalid_positions,
                self.aggregation_method.as_str()
            )),
        }
    }
}

// ============================================================================
// Main Attack Implementation
// ============================================================================

/// Batch Verification Attack detector
pub struct BatchVerificationAttack {
    config: BatchVerificationConfig,
    rng: ChaCha8Rng,
    findings: Vec<BatchVerificationFinding>,
    tested_combinations: HashSet<String>,
}

impl BatchVerificationAttack {
    /// Create a new batch verification attack detector
    pub fn new(config: BatchVerificationConfig) -> Self {
        let seed = config.seed.unwrap_or(42);
        Self {
            config,
            rng: ChaCha8Rng::seed_from_u64(seed),
            findings: Vec::new(),
            tested_combinations: HashSet::new(),
        }
    }

    /// Run all batch verification attacks
    pub fn run<E: CircuitExecutor>(
        &mut self,
        executor: &E,
        base_inputs: &[Vec<FieldElement>],
    ) -> Vec<BatchVerificationFinding> {
        self.findings.clear();
        self.tested_combinations.clear();

        tracing::info!("Starting batch verification attack detection");

        // Run enabled attack types
        if self.config.detect_batch_mixing {
            self.run_batch_mixing_attacks(executor, base_inputs);
        }

        if self.config.detect_aggregation_forgery {
            self.run_aggregation_forgery_attacks(executor, base_inputs);
        }

        if self.config.detect_cross_circuit_batch {
            self.run_cross_circuit_attacks(executor, base_inputs);
        }

        if self.config.detect_randomness_reuse {
            self.run_randomness_reuse_detection(executor, base_inputs);
        }

        tracing::info!(
            "Batch verification attack detection complete: {} findings",
            self.findings.len()
        );

        self.findings.clone()
    }

    // ========================================================================
    // Batch Mixing Attacks
    // ========================================================================

    /// Test batch mixing vulnerabilities
    fn run_batch_mixing_attacks<E: CircuitExecutor>(
        &mut self,
        executor: &E,
        base_inputs: &[Vec<FieldElement>],
    ) {
        tracing::info!("Running batch mixing attack detection");

        for &batch_size in &self.config.batch_sizes.clone() {
            for position in &self.config.invalid_positions.clone() {
                for method in &self.config.aggregation_methods.clone() {
                    self.test_batch_mixing(executor, base_inputs, batch_size, *position, *method);
                }
            }
        }
    }

    fn test_batch_mixing<E: CircuitExecutor>(
        &mut self,
        executor: &E,
        base_inputs: &[Vec<FieldElement>],
        batch_size: usize,
        position: InvalidPosition,
        method: AggregationMethod,
    ) {
        if base_inputs.is_empty() {
            return;
        }

        let invalid_indices = position.get_indices(batch_size, &mut self.rng);

        // Create test key for deduplication
        let test_key = format!(
            "mixing:{}:{}:{:?}",
            batch_size,
            method.as_str(),
            invalid_indices
        );
        if self.tested_combinations.contains(&test_key) {
            return;
        }
        self.tested_combinations.insert(test_key);

        // Generate batch with mixed valid/invalid proofs
        let mut batch_inputs: Vec<Vec<FieldElement>> = Vec::with_capacity(batch_size);
        let mut expected_results: Vec<bool> = Vec::with_capacity(batch_size);

        for i in 0..batch_size {
            let is_invalid = invalid_indices.contains(&i);
            let inputs = if is_invalid {
                // Generate invalid inputs
                self.generate_invalid_inputs(base_inputs)
            } else {
                // Use valid inputs
                base_inputs[self.rng.gen_range(0..base_inputs.len())].clone()
            };
            batch_inputs.push(inputs);
            expected_results.push(!is_invalid);
        }

        // Execute batch verification
        let (batch_passed, individual_results) =
            self.execute_batch_verification(executor, &batch_inputs, method);

        // Check for vulnerability: batch passes but contains invalid proofs
        if batch_passed && invalid_indices.iter().any(|&i| i < batch_size) {
            let finding = BatchVerificationFinding {
                vulnerability_type: BatchVulnerabilityType::BatchMixingBypass,
                batch_size,
                invalid_positions: invalid_indices.clone(),
                aggregation_method: method,
                trigger_inputs: batch_inputs.clone(),
                severity: Severity::Critical,
                description: format!(
                    "Batch verification passed with {} invalid proof(s) at position(s) {:?} \
                     using {} aggregation in batch of size {}",
                    invalid_indices.len(),
                    invalid_indices,
                    method.as_str(),
                    batch_size
                ),
                poc: Some(BatchProofOfConcept {
                    inputs: batch_inputs.clone().into_iter().flatten().collect(),
                    description: format!(
                        "Mixed {} invalid proofs with {} valid proofs",
                        invalid_indices.len(),
                        batch_size - invalid_indices.len()
                    ),
                }),
                confidence: 0.95,
            };
            self.findings.push(finding);
        }

        // Check for index masking
        if let Some(results) = individual_results {
            for (i, &result) in results.iter().enumerate() {
                if invalid_indices.contains(&i) && result {
                    let finding = BatchVerificationFinding {
                        vulnerability_type: BatchVulnerabilityType::IndexMasking,
                        batch_size,
                        invalid_positions: vec![i],
                        aggregation_method: method,
                        trigger_inputs: vec![batch_inputs[i].clone()],
                        severity: Severity::High,
                        description: format!(
                            "Invalid proof at index {} was incorrectly marked as valid in batch",
                            i
                        ),
                        poc: None,
                        confidence: 0.9,
                    };
                    self.findings.push(finding);
                }
            }
        }
    }

    fn generate_invalid_inputs(&mut self, base_inputs: &[Vec<FieldElement>]) -> Vec<FieldElement> {
        if base_inputs.is_empty() {
            return vec![FieldElement::zero()];
        }

        let mut inputs = base_inputs[self.rng.gen_range(0..base_inputs.len())].clone();

        // Mutate to make invalid
        if !inputs.is_empty() {
            let mutation_type = self.rng.gen_range(0..4);
            match mutation_type {
                0 => {
                    // Set all to zero
                    inputs.iter_mut().for_each(|x| *x = FieldElement::zero());
                }
                1 => {
                    // Negate all values
                    inputs.iter_mut().for_each(|x| *x = x.neg());
                }
                2 => {
                    // Swap first and last
                    if inputs.len() > 1 {
                        let len = inputs.len();
                        inputs.swap(0, len - 1);
                    }
                }
                _ => {
                    // Random mutation
                    let idx = self.rng.gen_range(0..inputs.len());
                    inputs[idx] = FieldElement::random(&mut self.rng);
                }
            }
        }

        inputs
    }

    // ========================================================================
    // Aggregation Forgery Attacks
    // ========================================================================

    /// Test aggregation forgery vulnerabilities
    fn run_aggregation_forgery_attacks<E: CircuitExecutor>(
        &mut self,
        executor: &E,
        base_inputs: &[Vec<FieldElement>],
    ) {
        tracing::info!("Running aggregation forgery attack detection");

        for method in &self.config.aggregation_methods.clone() {
            for &batch_size in &self.config.batch_sizes.clone() {
                self.test_aggregation_forgery(executor, base_inputs, batch_size, *method);
            }
        }
    }

    fn test_aggregation_forgery<E: CircuitExecutor>(
        &mut self,
        executor: &E,
        base_inputs: &[Vec<FieldElement>],
        batch_size: usize,
        method: AggregationMethod,
    ) {
        if base_inputs.is_empty() {
            return;
        }

        let test_key = format!("forgery:{}:{}", batch_size, method.as_str());
        if self.tested_combinations.contains(&test_key) {
            return;
        }
        self.tested_combinations.insert(test_key);

        // Generate valid batch first
        let valid_batch: Vec<Vec<FieldElement>> = (0..batch_size)
            .map(|_| base_inputs[self.rng.gen_range(0..base_inputs.len())].clone())
            .collect();

        // Get aggregated proof components
        let (valid_passed, _) = self.execute_batch_verification(executor, &valid_batch, method);

        if !valid_passed {
            return; // Can't test forgery if valid batch doesn't pass
        }

        // Attempt various forgery strategies
        let forgery_strategies = vec![
            ForgeryStrategy::SubsetSubmission,
            ForgeryStrategy::DuplicateProofs,
            ForgeryStrategy::ReorderedBatch,
            ForgeryStrategy::PartialAggregation,
            ForgeryStrategy::MalleableTransform,
        ];

        for strategy in forgery_strategies {
            if let Some(forged_batch) = self.attempt_forgery(&valid_batch, strategy, batch_size) {
                let (forged_passed, _) =
                    self.execute_batch_verification(executor, &forged_batch, method);

                if forged_passed {
                    let vuln_type = match strategy {
                        ForgeryStrategy::SubsetSubmission => BatchVulnerabilityType::SubsetForgery,
                        ForgeryStrategy::DuplicateProofs => {
                            BatchVulnerabilityType::AggregationForgery
                        }
                        ForgeryStrategy::ReorderedBatch => {
                            BatchVulnerabilityType::OrderingDependency
                        }
                        ForgeryStrategy::PartialAggregation => {
                            BatchVulnerabilityType::AggregationForgery
                        }
                        ForgeryStrategy::MalleableTransform => {
                            BatchVulnerabilityType::AggregationMalleability
                        }
                    };

                    let finding = BatchVerificationFinding {
                        vulnerability_type: vuln_type,
                        batch_size,
                        invalid_positions: Vec::new(),
                        aggregation_method: method,
                        trigger_inputs: forged_batch.clone(),
                        severity: vuln_type.severity(),
                        description: format!(
                            "Aggregation forgery successful using {:?} strategy on {} aggregation",
                            strategy,
                            method.as_str()
                        ),
                        poc: Some(BatchProofOfConcept {
                            inputs: forged_batch.into_iter().flatten().collect(),
                            description: format!("Forged batch using {:?}", strategy),
                        }),
                        confidence: 0.85,
                    };
                    self.findings.push(finding);
                }
            }
        }
    }

    fn attempt_forgery(
        &mut self,
        valid_batch: &[Vec<FieldElement>],
        strategy: ForgeryStrategy,
        target_size: usize,
    ) -> Option<Vec<Vec<FieldElement>>> {
        match strategy {
            ForgeryStrategy::SubsetSubmission => {
                // Try submitting only a subset of proofs
                if valid_batch.len() > 1 {
                    Some(valid_batch[..valid_batch.len() / 2].to_vec())
                } else {
                    None
                }
            }
            ForgeryStrategy::DuplicateProofs => {
                // Duplicate proofs to fill batch
                if let Some(first) = valid_batch.first() {
                    Some(vec![first.clone(); target_size])
                } else {
                    None
                }
            }
            ForgeryStrategy::ReorderedBatch => {
                // Reverse order of batch
                let mut reordered = valid_batch.to_vec();
                reordered.reverse();
                Some(reordered)
            }
            ForgeryStrategy::PartialAggregation => {
                // Mix proofs from different positions
                if valid_batch.len() >= 2 {
                    let mut mixed = valid_batch.to_vec();
                    let len = mixed.len();
                    mixed.swap(0, len - 1);
                    Some(mixed)
                } else {
                    None
                }
            }
            ForgeryStrategy::MalleableTransform => {
                // Apply malleable transformation to proofs
                let mut transformed: Vec<Vec<FieldElement>> = valid_batch
                    .iter()
                    .map(|proof| {
                        proof
                            .iter()
                            .map(|x| {
                                // Apply trivial transformation (this is a simplified check)
                                x.clone()
                            })
                            .collect()
                    })
                    .collect();

                // Negate and un-negate (identity for checking malleability detection)
                if !transformed.is_empty() && !transformed[0].is_empty() {
                    let idx = self.rng.gen_range(0..transformed[0].len());
                    transformed[0][idx] = transformed[0][idx].neg().neg();
                }

                Some(transformed)
            }
        }
    }

    // ========================================================================
    // Cross-Circuit Batch Attacks
    // ========================================================================

    /// Test cross-circuit batch vulnerabilities
    fn run_cross_circuit_attacks<E: CircuitExecutor>(
        &mut self,
        executor: &E,
        base_inputs: &[Vec<FieldElement>],
    ) {
        tracing::info!("Running cross-circuit batch attack detection");

        // Generate inputs for simulated "different circuits"
        // In practice, this would use proofs from actually different circuits
        for &batch_size in &self.config.batch_sizes.clone() {
            for method in &self.config.aggregation_methods.clone() {
                self.test_cross_circuit_batch(executor, base_inputs, batch_size, *method);
            }
        }
    }

    fn test_cross_circuit_batch<E: CircuitExecutor>(
        &mut self,
        executor: &E,
        base_inputs: &[Vec<FieldElement>],
        batch_size: usize,
        method: AggregationMethod,
    ) {
        if base_inputs.is_empty() || batch_size < 2 {
            return;
        }

        let test_key = format!("cross:{}:{}", batch_size, method.as_str());
        if self.tested_combinations.contains(&test_key) {
            return;
        }
        self.tested_combinations.insert(test_key);

        // Create a batch with heterogeneous input structures
        // (simulating proofs from different circuits)
        let mut cross_batch: Vec<Vec<FieldElement>> = Vec::with_capacity(batch_size);

        for i in 0..batch_size {
            let base = base_inputs[self.rng.gen_range(0..base_inputs.len())].clone();

            // Modify structure for odd-indexed proofs to simulate different circuits
            let modified = if i % 2 == 1 && base.len() > 2 {
                // Truncate or extend to simulate different circuit structure
                if self.rng.gen_bool(0.5) {
                    base[..base.len() / 2].to_vec()
                } else {
                    let mut extended = base.clone();
                    extended.push(FieldElement::random(&mut self.rng));
                    extended
                }
            } else {
                base
            };

            cross_batch.push(modified);
        }

        // Execute batch verification
        let (batch_passed, _) = self.execute_batch_verification(executor, &cross_batch, method);

        // If batch passes with heterogeneous structures, this might be a vulnerability
        // depending on whether the verifier should accept such batches
        if batch_passed {
            // Check if input lengths vary (indicating cross-circuit scenario)
            let lengths: HashSet<usize> = cross_batch.iter().map(|p| p.len()).collect();
            if lengths.len() > 1 {
                let finding = BatchVerificationFinding {
                    vulnerability_type: BatchVulnerabilityType::CrossCircuitBypass,
                    batch_size,
                    invalid_positions: Vec::new(),
                    aggregation_method: method,
                    trigger_inputs: cross_batch.clone(),
                    severity: Severity::Critical,
                    description: format!(
                        "Batch verification passed with heterogeneous proof structures \
                         ({} different sizes) using {} aggregation",
                        lengths.len(),
                        method.as_str()
                    ),
                    poc: Some(BatchProofOfConcept {
                        inputs: cross_batch.into_iter().flatten().collect(),
                        description: format!(
                            "Cross-circuit batch with {} different input structures",
                            lengths.len()
                        ),
                    }),
                    confidence: 0.75,
                };
                self.findings.push(finding);
            }
        }
    }

    // ========================================================================
    // Randomness Reuse Detection
    // ========================================================================

    /// Detect randomness reuse across batch elements
    fn run_randomness_reuse_detection<E: CircuitExecutor>(
        &mut self,
        executor: &E,
        base_inputs: &[Vec<FieldElement>],
    ) {
        tracing::info!("Running randomness reuse detection");

        for &batch_size in &self.config.batch_sizes.clone() {
            self.test_randomness_reuse(executor, base_inputs, batch_size);
        }
    }

    fn test_randomness_reuse<E: CircuitExecutor>(
        &mut self,
        _executor: &E,
        base_inputs: &[Vec<FieldElement>],
        batch_size: usize,
    ) {
        if base_inputs.is_empty() || batch_size < 2 {
            return;
        }

        let test_key = format!("randomness:{}", batch_size);
        if self.tested_combinations.contains(&test_key) {
            return;
        }
        self.tested_combinations.insert(test_key);

        // Generate multiple batches and analyze randomness patterns
        let num_batches = (self.config.randomness_reuse_tests / batch_size).max(10);
        let mut all_batches: Vec<Vec<Vec<FieldElement>>> = Vec::with_capacity(num_batches);

        for _ in 0..num_batches {
            let batch: Vec<Vec<FieldElement>> = (0..batch_size)
                .map(|_| base_inputs[self.rng.gen_range(0..base_inputs.len())].clone())
                .collect();
            all_batches.push(batch);
        }

        // Analyze for patterns suggesting randomness reuse
        let correlations = self.analyze_randomness_patterns(&all_batches);

        for (batch_idx, batch_correlations) in correlations.iter().enumerate() {
            for &(i, j, corr) in batch_correlations {
                if corr >= self.config.correlation_threshold {
                    let finding = BatchVerificationFinding {
                        vulnerability_type: BatchVulnerabilityType::RandomnessReuse,
                        batch_size,
                        invalid_positions: vec![i, j],
                        aggregation_method: AggregationMethod::NaiveBatch,
                        trigger_inputs: all_batches[batch_idx].clone(),
                        severity: Severity::High,
                        description: format!(
                            "High correlation ({:.2}) detected between proofs {} and {} \
                             suggesting randomness reuse",
                            corr, i, j
                        ),
                        poc: None,
                        confidence: corr,
                    };
                    self.findings.push(finding);
                }
            }
        }
    }

    fn analyze_randomness_patterns(
        &self,
        batches: &[Vec<Vec<FieldElement>>],
    ) -> Vec<Vec<(usize, usize, f64)>> {
        batches
            .iter()
            .map(|batch| {
                let mut correlations = Vec::new();
                for i in 0..batch.len() {
                    for j in (i + 1)..batch.len() {
                        if let Some(corr) = self.compute_correlation(&batch[i], &batch[j]) {
                            correlations.push((i, j, corr));
                        }
                    }
                }
                correlations
            })
            .collect()
    }

    fn compute_correlation(&self, a: &[FieldElement], b: &[FieldElement]) -> Option<f64> {
        if a.is_empty() || b.is_empty() {
            return None;
        }

        let min_len = a.len().min(b.len());
        if min_len == 0 {
            return None;
        }

        // Simple correlation: count matching elements
        let matches = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();

        Some(matches as f64 / min_len as f64)
    }

    // ========================================================================
    // Batch Verification Execution
    // ========================================================================

    fn execute_batch_verification<E: CircuitExecutor>(
        &self,
        _executor: &E,
        batch_inputs: &[Vec<FieldElement>],
        _method: AggregationMethod,
    ) -> (bool, Option<Vec<bool>>) {
        // Simplified batch verification simulation
        // In a real implementation, this would use the executor asynchronously
        // For now, we simulate based on input characteristics
        let mut all_passed = true;
        let mut individual_results = Vec::with_capacity(batch_inputs.len());

        for inputs in batch_inputs {
            // Simulate verification - all-zero inputs are typically invalid
            let is_all_zero = inputs.iter().all(|x| *x == FieldElement::zero());
            let passed = !is_all_zero && !inputs.is_empty();
            individual_results.push(passed);
            if !passed {
                all_passed = false;
            }
        }

        (all_passed, Some(individual_results))
    }

    /// Get all findings
    pub fn get_findings(&self) -> &[BatchVerificationFinding] {
        &self.findings
    }

    /// Reset attack state
    pub fn reset(&mut self) {
        self.findings.clear();
        self.tested_combinations.clear();
    }
}

// ============================================================================
// Forgery Strategies
// ============================================================================

#[derive(Debug, Clone, Copy)]
enum ForgeryStrategy {
    /// Submit only a subset of proofs
    SubsetSubmission,
    /// Duplicate valid proofs
    DuplicateProofs,
    /// Reorder proofs in batch
    ReorderedBatch,
    /// Partially aggregate proofs
    PartialAggregation,
    /// Apply malleable transformation
    MalleableTransform,
}

// ============================================================================
// Batch Verification Analyzer (for standalone analysis)
// ============================================================================

/// Analyzer for batch verification patterns
pub struct BatchVerificationAnalyzer {
    /// Accumulated statistics
    stats: BatchVerificationStats,
}

/// Statistics from batch verification analysis
#[derive(Debug, Clone, Default)]
pub struct BatchVerificationStats {
    /// Total batches analyzed
    pub total_batches: usize,
    /// Batches that passed verification
    pub passed_batches: usize,
    /// Batches with mixed results
    pub mixed_results_batches: usize,
    /// Average batch size
    pub avg_batch_size: f64,
    /// Vulnerabilities by type
    pub vulnerabilities_by_type: HashMap<String, usize>,
}

impl BatchVerificationAnalyzer {
    pub fn new() -> Self {
        Self {
            stats: BatchVerificationStats::default(),
        }
    }

    /// Analyze a batch and update statistics
    pub fn analyze_batch(&mut self, result: &BatchVerificationResult) {
        self.stats.total_batches += 1;

        if result.passed {
            self.stats.passed_batches += 1;
        }

        // Check for mixed results
        let has_true = result.individual_results.iter().any(|&x| x);
        let has_false = result.individual_results.iter().any(|&x| !x);
        if has_true && has_false {
            self.stats.mixed_results_batches += 1;
        }

        // Update average batch size
        let new_size = result.individual_results.len();
        let total_size =
            self.stats.avg_batch_size * (self.stats.total_batches - 1) as f64 + new_size as f64;
        self.stats.avg_batch_size = total_size / self.stats.total_batches as f64;
    }

    /// Record a vulnerability finding
    pub fn record_vulnerability(&mut self, vuln_type: BatchVulnerabilityType) {
        *self
            .stats
            .vulnerabilities_by_type
            .entry(vuln_type.as_str().to_string())
            .or_insert(0) += 1;
    }

    /// Get current statistics
    pub fn get_stats(&self) -> &BatchVerificationStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset(&mut self) {
        self.stats = BatchVerificationStats::default();
    }
}

impl Default for BatchVerificationAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_vulnerability_types() {
        assert_eq!(
            BatchVulnerabilityType::BatchMixingBypass.as_str(),
            "batch_mixing_bypass"
        );
        assert_eq!(
            BatchVulnerabilityType::AggregationForgery.severity(),
            Severity::Critical
        );
    }

    #[test]
    fn test_aggregation_methods() {
        assert_eq!(AggregationMethod::NaiveBatch.as_str(), "naive_batch");
        assert_eq!(AggregationMethod::SnarkPack.as_str(), "snarkpack");
        assert_eq!(
            AggregationMethod::Groth16Aggregation.as_str(),
            "groth16_aggregation"
        );
    }

    #[test]
    fn test_invalid_position_indices() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        assert_eq!(InvalidPosition::First.get_indices(10, &mut rng), vec![0]);
        assert_eq!(InvalidPosition::Last.get_indices(10, &mut rng), vec![9]);
        assert_eq!(InvalidPosition::Middle.get_indices(10, &mut rng), vec![5]);

        let random_indices = InvalidPosition::Random.get_indices(10, &mut rng);
        assert_eq!(random_indices.len(), 1);
        assert!(random_indices[0] < 10);
    }

    #[test]
    fn test_config_defaults() {
        let config = BatchVerificationConfig::default();
        assert_eq!(config.batch_sizes, vec![2, 4, 8, 16, 32]);
        assert!(config.detect_batch_mixing);
        assert!(config.detect_aggregation_forgery);
        assert_eq!(config.correlation_threshold, 0.8);
    }

    #[test]
    fn test_finding_to_generic() {
        let finding = BatchVerificationFinding {
            vulnerability_type: BatchVulnerabilityType::BatchMixingBypass,
            batch_size: 8,
            invalid_positions: vec![0, 4],
            aggregation_method: AggregationMethod::Groth16Aggregation,
            trigger_inputs: vec![vec![FieldElement::one()]],
            severity: Severity::Critical,
            description: "Test finding".to_string(),
            poc: None,
            confidence: 0.95,
        };

        let generic = finding.to_finding();
        assert_eq!(generic.attack_type, AttackType::BatchVerification);
        assert_eq!(generic.severity, Severity::Critical);
    }

    #[test]
    fn test_batch_analyzer_stats() {
        let mut analyzer = BatchVerificationAnalyzer::new();

        let result = BatchVerificationResult {
            passed: true,
            individual_results: vec![true, true, true],
            verification_time_ms: 100,
            metadata: HashMap::new(),
        };

        analyzer.analyze_batch(&result);

        let stats = analyzer.get_stats();
        assert_eq!(stats.total_batches, 1);
        assert_eq!(stats.passed_batches, 1);
        assert_eq!(stats.mixed_results_batches, 0);
        assert_eq!(stats.avg_batch_size, 3.0);
    }

    #[test]
    fn test_batch_analyzer_mixed_results() {
        let mut analyzer = BatchVerificationAnalyzer::new();

        let result = BatchVerificationResult {
            passed: false,
            individual_results: vec![true, false, true, false],
            verification_time_ms: 150,
            metadata: HashMap::new(),
        };

        analyzer.analyze_batch(&result);

        let stats = analyzer.get_stats();
        assert_eq!(stats.mixed_results_batches, 1);
    }

    #[test]
    fn test_vulnerability_recording() {
        let mut analyzer = BatchVerificationAnalyzer::new();

        analyzer.record_vulnerability(BatchVulnerabilityType::BatchMixingBypass);
        analyzer.record_vulnerability(BatchVulnerabilityType::BatchMixingBypass);
        analyzer.record_vulnerability(BatchVulnerabilityType::AggregationForgery);

        let stats = analyzer.get_stats();
        assert_eq!(
            stats.vulnerabilities_by_type.get("batch_mixing_bypass"),
            Some(&2)
        );
        assert_eq!(
            stats.vulnerabilities_by_type.get("aggregation_forgery"),
            Some(&1)
        );
    }

    #[test]
    fn test_correlation_computation() {
        let attack = BatchVerificationAttack::new(BatchVerificationConfig::default());

        // Identical arrays should have correlation 1.0
        let a = vec![FieldElement::one(), FieldElement::zero()];
        let b = a.clone();
        assert_eq!(attack.compute_correlation(&a, &b), Some(1.0));

        // Empty arrays
        let empty: Vec<FieldElement> = vec![];
        assert_eq!(attack.compute_correlation(&empty, &a), None);
    }

    #[test]
    fn test_invalid_input_generation() {
        let mut attack = BatchVerificationAttack::new(BatchVerificationConfig::default());

        let base = vec![vec![FieldElement::one(), FieldElement::from_u64(42)]];
        let invalid = attack.generate_invalid_inputs(&base);

        // Should produce some output
        assert!(!invalid.is_empty());
    }
}
