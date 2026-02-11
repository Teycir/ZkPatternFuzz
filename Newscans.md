Novel Scanner Implementation Guide
Detailed implementation plan for 7 new security scanners in ZkPatternFuzz, ordered by priority.

P0-1: Proof Malleability Scanner
File: src/attacks/proof_malleability.rs (~350 LOC)

Goal: Detect if mutated proofs still verify — attacks the verifier, not the prover.

Data Structures
rust
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};
use rand::Rng;
/// Types of proof mutations to attempt
#[derive(Debug, Clone, Copy)]
pub enum ProofMutation {
    /// Flip random bits in the proof
    BitFlip { byte_index: usize, bit_mask: u8 },
    /// Negate a 32-byte scalar (s → p - s)
    ScalarNegation { offset: usize },
    /// Swap two 32-byte chunks (e.g., swap proof elements)
    ChunkSwap { offset_a: usize, offset_b: usize },
    /// Zero out a 32-byte chunk
    ZeroChunk { offset: usize },
    /// Duplicate first proof element over second
    DuplicateElement { src_offset: usize, dst_offset: usize },
    /// Add 1 to a scalar field element
    ScalarIncrement { offset: usize },
    /// Truncate proof by N bytes
    Truncate { keep_bytes: usize },
}
/// Result of a single malleability test
#[derive(Debug, Clone)]
pub struct MalleabilityResult {
    pub mutation: ProofMutation,
    pub original_proof: Vec<u8>,
    pub mutated_proof: Vec<u8>,
    pub verified: bool,        // Did the mutated proof verify?
    pub public_inputs: Vec<FieldElement>,
}
pub struct ProofMalleabilityScanner {
    /// Number of random bit-flip mutations per proof
    random_mutations: usize,
    /// Whether to test structured mutations (negate, swap, zero)
    structured_mutations: bool,
    /// Number of valid proofs to generate before mutating
    proof_samples: usize,
}
Core Algorithm
rust
impl ProofMalleabilityScanner {
    pub fn run(
        &self,
        executor: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for witness in witnesses.iter().take(self.proof_samples) {
            // Step 1: Generate a valid proof
            let proof = match executor.prove(witness) {
                Ok(p) => p,
                Err(_) => continue,
            };
            // Step 2: Extract public inputs from witness
            let info = executor.circuit_info();
            let public_inputs: Vec<FieldElement> =
                witness[..info.num_public_inputs].to_vec();
            // Step 3: Verify the original proof passes
            match executor.verify(&proof, &public_inputs) {
                Ok(true) => {},
                _ => continue, // Skip if original doesn't verify
            }
            // Step 4: Generate and test mutations
            let mutations = self.generate_mutations(&proof);
            for mutation in mutations {
                let mutated = self.apply_mutation(&proof, &mutation);
                if mutated == proof { continue; } // Skip no-ops
                match executor.verify(&mutated, &public_inputs) {
                    Ok(true) => {
                        // CRITICAL: Mutated proof verified!
                        findings.push(Finding {
                            attack_type: AttackType::Soundness,
                            severity: Severity::Critical,
                            description: format!(
                                "Proof malleability: {:?} on {}-byte proof still verifies",
                                mutation, proof.len()
                            ),
                            poc: ProofOfConcept {
                                original_witness: Some(witness.clone()),
                                original_proof: Some(proof.clone()),
                                mutated_proof: Some(mutated),
                                public_inputs: Some(public_inputs.clone()),
                                ..Default::default()
                            },
                            location: None,
                        });
                    }
                    _ => {} // Expected: mutation rejected
                }
            }
        }
        findings
    }
    fn generate_mutations(&self, proof: &[u8]) -> Vec<ProofMutation> {
        let mut mutations = Vec::new();
        let mut rng = rand::thread_rng();
        // Structured mutations (always run)
        if self.structured_mutations {
            let chunk_count = proof.len() / 32;
            for i in 0..chunk_count {
                mutations.push(ProofMutation::ScalarNegation { offset: i * 32 });
                mutations.push(ProofMutation::ZeroChunk { offset: i * 32 });
                mutations.push(ProofMutation::ScalarIncrement { offset: i * 32 });
                for j in (i+1)..chunk_count {
                    mutations.push(ProofMutation::ChunkSwap {
                        offset_a: i * 32, offset_b: j * 32,
                    });
                }
            }
            // Truncation tests
            for keep in [32, 64, 128, proof.len() - 1] {
                if keep < proof.len() {
                    mutations.push(ProofMutation::Truncate { keep_bytes: keep });
                }
            }
        }
        // Random bit flips
        for _ in 0..self.random_mutations {
            let byte_idx = rng.gen_range(0..proof.len());
            let bit = 1u8 << rng.gen_range(0..8);
            mutations.push(ProofMutation::BitFlip {
                byte_index: byte_idx, bit_mask: bit,
            });
        }
        mutations
    }
    fn apply_mutation(&self, proof: &[u8], mutation: &ProofMutation) -> Vec<u8> {
        let mut mutated = proof.to_vec();
        match mutation {
            ProofMutation::BitFlip { byte_index, bit_mask } => {
                if *byte_index < mutated.len() {
                    mutated[*byte_index] ^= bit_mask;
                }
            }
            ProofMutation::ScalarNegation { offset } => {
                // Negate the 32-byte scalar: s → field_modulus - s
                if offset + 32 <= mutated.len() {
                    let modulus = zk_fuzzer_core::constants::bn254_modulus_bytes();
                    let mut scalar = [0u8; 32];
                    scalar.copy_from_slice(&mutated[*offset..*offset+32]);
                    // p - s (big-endian subtraction)
                    let s = num_bigint::BigUint::from_bytes_be(&scalar);
                    let p = num_bigint::BigUint::from_bytes_be(&modulus);
                    if s > num_bigint::BigUint::from(0u32) {
                        let neg = &p - &s;
                        let bytes = neg.to_bytes_be();
                        let start = 32 - bytes.len();
                        mutated[*offset..*offset+32].fill(0);
                        mutated[*offset+start..*offset+32].copy_from_slice(&bytes);
                    }
                }
            }
            ProofMutation::ChunkSwap { offset_a, offset_b } => {
                if offset_a + 32 <= mutated.len() && offset_b + 32 <= mutated.len() {
                    let (a, b) = if offset_a < offset_b {
                        let (left, right) = mutated.split_at_mut(*offset_b);
                        (&mut left[*offset_a..*offset_a+32], &mut right[..32])
                    } else {
                        let (left, right) = mutated.split_at_mut(*offset_a);
                        (&mut right[..32], &mut left[*offset_b..*offset_b+32])
                    };
                    a.swap_with_slice(b);
                }
            }
            ProofMutation::ZeroChunk { offset } => {
                if offset + 32 <= mutated.len() {
                    mutated[*offset..*offset+32].fill(0);
                }
            }
            ProofMutation::ScalarIncrement { offset } => {
                if offset + 32 <= mutated.len() {
                    // Add 1 to big-endian scalar
                    for i in (0..32).rev() {
                        let (val, overflow) = mutated[*offset + i].overflowing_add(1);
                        mutated[*offset + i] = val;
                        if !overflow { break; }
                    }
                }
            }
            ProofMutation::Truncate { keep_bytes } => {
                mutated.truncate(*keep_bytes);
            }
            ProofMutation::DuplicateElement { src_offset, dst_offset } => {
                if src_offset + 32 <= mutated.len() && dst_offset + 32 <= mutated.len() {
                    let src: Vec<u8> = mutated[*src_offset..*src_offset+32].to_vec();
                    mutated[*dst_offset..*dst_offset+32].copy_from_slice(&src);
                }
            }
        }
        mutated
    }
}
Engine Integration
In 
engine.rs
, add after the existing attack dispatch:

rust
// In FuzzingEngine::run_campaign() or equivalent
fn run_proof_malleability_attack(&self) -> Vec<Finding> {
    let scanner = ProofMalleabilityScanner::new()
        .with_proof_samples(10)
        .with_random_mutations(100)
        .with_structured_mutations(true);
    let witnesses = self.corpus.read().unwrap()
        .get_interesting_witnesses(10);
    scanner.run(self.executor.as_ref(), &witnesses)
}
Registration
In 
src/attacks/mod.rs
, add:

rust
pub mod proof_malleability;
pub use proof_malleability::ProofMalleabilityScanner;
P0-2: Determinism Oracle
File: src/attacks/determinism.rs (~120 LOC)

Goal: Detect non-deterministic circuit execution.

Implementation
rust
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};
pub struct DeterminismOracle {
    /// Number of times to re-execute each witness
    repetitions: usize,
    /// Number of witnesses to test
    sample_count: usize,
}
impl Default for DeterminismOracle {
    fn default() -> Self {
        Self { repetitions: 5, sample_count: 50 }
    }
}
impl DeterminismOracle {
    pub fn new() -> Self { Self::default() }
    pub fn with_repetitions(mut self, n: usize) -> Self {
        self.repetitions = n; self
    }
    pub fn run(
        &self,
        executor: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (w_idx, witness) in witnesses.iter().take(self.sample_count).enumerate() {
            let baseline = executor.execute_sync(witness);
            if !baseline.success { continue; }
            for rep in 1..self.repetitions {
                let result = executor.execute_sync(witness);
                // Check output equality
                if result.outputs != baseline.outputs {
                    findings.push(Finding {
                        attack_type: AttackType::Soundness,
                        severity: Severity::Critical,
                        description: format!(
                            "Non-deterministic execution: witness {} produced different \
                             outputs on repetition {} vs baseline. \
                             Baseline: {:?}, Got: {:?}",
                            w_idx, rep,
                            &baseline.outputs[..baseline.outputs.len().min(3)],
                            &result.outputs[..result.outputs.len().min(3)]
                        ),
                        poc: ProofOfConcept {
                            original_witness: Some(witness.clone()),
                            ..Default::default()
                        },
                        location: None,
                    });
                    break; // One finding per witness is enough
                }
                // Check success flag consistency
                if result.success != baseline.success {
                    findings.push(Finding {
                        attack_type: AttackType::Soundness,
                        severity: Severity::Critical,
                        description: format!(
                            "Non-deterministic constraint satisfaction: witness {} \
                             succeeded={} on baseline but succeeded={} on rep {}",
                            w_idx, baseline.success, result.success, rep
                        ),
                        poc: ProofOfConcept {
                            original_witness: Some(witness.clone()),
                            ..Default::default()
                        },
                        location: None,
                    });
                    break;
                }
            }
        }
        findings
    }
}
Engine Integration
rust
fn run_determinism_check(&self) -> Vec<Finding> {
    let oracle = DeterminismOracle::new().with_repetitions(5);
    let witnesses = self.corpus.read().unwrap().get_witnesses(50);
    oracle.run(self.executor.as_ref(), &witnesses)
}
P1-1: Frozen Wire Detector
File: src/attacks/frozen_wire.rs (~200 LOC)

Goal: Find wires that never change value across diverse inputs.

Implementation
rust
use std::collections::{HashMap, HashSet};
use zk_core::{AttackType, CircuitExecutor, ConstraintInspector, FieldElement, Finding, Severity};
pub struct FrozenWireDetector {
    /// Minimum executions before flagging
    min_samples: usize,
    /// Exclude wires known to be constants (e.g., wire 0 = 1 in R1CS)
    known_constants: HashSet<usize>,
}
impl Default for FrozenWireDetector {
    fn default() -> Self {
        Self {
            min_samples: 100,
            known_constants: HashSet::from([0]), // Wire 0 is always 1 in R1CS
        }
    }
}
impl FrozenWireDetector {
    pub fn run(
        &self,
        executor: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        // Track unique values seen per output index
        let mut value_sets: HashMap<usize, HashSet<[u8; 32]>> = HashMap::new();
        for witness in witnesses.iter().take(self.min_samples) {
            let result = executor.execute_sync(witness);
            if !result.success { continue; }
            for (idx, output) in result.outputs.iter().enumerate() {
                value_sets.entry(idx)
                    .or_insert_with(HashSet::new)
                    .insert(output.0);
            }
        }
        // Also inspect constraints if available
        let constraint_wires = executor.constraint_inspector()
            .map(|inspector| {
                let constraints = inspector.get_constraints();
                let mut used_wires: HashSet<usize> = HashSet::new();
                for c in &constraints {
                    for (wire, _) in &c.a_terms { used_wires.insert(*wire); }
                    for (wire, _) in &c.b_terms { used_wires.insert(*wire); }
                    for (wire, _) in &c.c_terms { used_wires.insert(*wire); }
                }
                used_wires
            });
        let mut findings = Vec::new();
        for (idx, values) in &value_sets {
            if self.known_constants.contains(idx) { continue; }
            if values.len() == 1 {
                let frozen_value = values.iter().next().unwrap();
                let is_zero = frozen_value.iter().all(|b| *b == 0);
                let is_one = {
                    let mut one = [0u8; 32];
                    one[31] = 1;
                    frozen_value == &one
                };
                // Frozen at zero is more suspicious than frozen at one
                let severity = if is_zero {
                    Severity::Medium
                } else if is_one {
                    Severity::Low
                } else {
                    Severity::Medium // Frozen at arbitrary constant
                };
                // Check if the wire participates in any constraint
                let _constrained = constraint_wires.as_ref()
                    .map(|wires| wires.contains(idx))
                    .unwrap_or(true);
                findings.push(Finding {
                    attack_type: AttackType::Underconstrained,
                    severity,
                    description: format!(
                        "Output wire {} is frozen: same value across {} executions. \
                         Value={} (zero={}, one={}). May indicate dead code or \
                         redundant constraint.",
                        idx, self.min_samples, hex::encode(frozen_value),
                        is_zero, is_one
                    ),
                    poc: Default::default(),
                    location: None,
                });
            }
        }
        findings
    }
}
P1-2: Nullifier Replay Scanner
File: src/attacks/nullifier_replay.rs (~280 LOC)

Goal: Test if the same nullifier can be used with different private inputs to produce valid proofs.

Implementation
rust
use rand::Rng;
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};
/// Heuristic for identifying nullifier wire indices
pub struct NullifierHeuristic;
impl NullifierHeuristic {
    /// Detect probable nullifier wires from circuit metadata/labels
    pub fn detect(executor: &dyn CircuitExecutor) -> Vec<usize> {
        let info = executor.circuit_info();
        let mut candidates = Vec::new();
        // Strategy 1: Look at wire labels for "nullifier", "nonce", "serial"
        if let Some(inspector) = executor.constraint_inspector() {
            let constraints = inspector.get_constraints();
            for c in &constraints {
                if let Some(desc) = &c.description {
                    let lower = desc.to_lowercase();
                    if lower.contains("nullifier") || lower.contains("serial")
                        || lower.contains("nonce") {
                        for (wire, _) in &c.a_terms {
                            candidates.push(*wire);
                        }
                    }
                }
            }
        }
        // Strategy 2: If no labels, assume first public output is nullifier
        // (common pattern in Tornado Cash, Semaphore, etc.)
        if candidates.is_empty() && info.num_public_inputs > 0 {
            candidates.push(0); // First public input position
        }
        candidates.sort_unstable();
        candidates.dedup();
        candidates
    }
}
pub struct NullifierReplayScanner {
    /// Number of different private input sets to try per nullifier
    replay_attempts: usize,
    /// Manually specified nullifier indices (overrides heuristic)
    nullifier_indices: Option<Vec<usize>>,
}
impl Default for NullifierReplayScanner {
    fn default() -> Self {
        Self { replay_attempts: 50, nullifier_indices: None }
    }
}
impl NullifierReplayScanner {
    pub fn with_nullifier_indices(mut self, indices: Vec<usize>) -> Self {
        self.nullifier_indices = Some(indices); self
    }
    pub fn run(
        &self,
        executor: &dyn CircuitExecutor,
        base_witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        let info = executor.circuit_info();
        let nullifier_wires = self.nullifier_indices.clone()
            .unwrap_or_else(|| NullifierHeuristic::detect(executor));
        if nullifier_wires.is_empty() { return Vec::new(); }
        let mut findings = Vec::new();
        let mut rng = rand::thread_rng();
        for base in base_witnesses.iter().take(10) {
            let base_result = executor.execute_sync(base);
            if !base_result.success { continue; }
            // Extract the nullifier value from the base execution
            let nullifier_values: Vec<(usize, FieldElement)> = nullifier_wires.iter()
                .filter(|&&idx| idx < base.len())
                .map(|&idx| (idx, base[idx].clone()))
                .collect();
            // Try different private inputs but keep nullifier the same
            let mut successful_replays = 0;
            for _ in 0..self.replay_attempts {
                let mut modified = base.clone();
                // Randomize all non-nullifier private inputs
                for (i, elem) in modified.iter_mut().enumerate() {
                    let is_nullifier = nullifier_values.iter().any(|(idx, _)| *idx == i);
                    let is_public = i < info.num_public_inputs;
                    if !is_nullifier && !is_public {
                        // Randomize this private input
                        let mut bytes = [0u8; 32];
                        rng.fill(&mut bytes);
                        bytes[0] &= 0x1F; // Keep in field
                        *elem = FieldElement(bytes);
                    }
                }
                let replay_result = executor.execute_sync(&modified);
                if replay_result.success
                    && replay_result.outputs == base_result.outputs
                    && modified != *base
                {
                    successful_replays += 1;
                    if successful_replays == 1 {
                        // Report with concrete PoC
                        findings.push(Finding {
                            attack_type: AttackType::Collision,
                            severity: Severity::Critical,
                            description: format!(
                                "Nullifier replay: {} different private inputs produce \
                                 identical outputs with same nullifier at wire(s) {:?}. \
                                 Circuit may allow double-spending.",
                                successful_replays, nullifier_wires
                            ),
                            poc: ProofOfConcept {
                                original_witness: Some(base.clone()),
                                secondary_witness: Some(modified),
                                ..Default::default()
                            },
                            location: None,
                        });
                    }
                }
            }
        }
        findings
    }
}
P1-3: Cross-Backend Differential Oracle
File: src/attacks/cross_backend.rs (~250 LOC)

Goal: Compare circuit execution across two different backends; differences indicate bugs.

Implementation
rust
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};
pub struct CrossBackendDifferential {
    /// Number of witnesses to compare
    sample_count: usize,
    /// Tolerance for output comparison (0 = exact match required)
    tolerance_bits: usize,
}
impl CrossBackendDifferential {
    pub fn run(
        &self,
        executor_a: &dyn CircuitExecutor,
        executor_b: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let info_a = executor_a.circuit_info();
        let info_b = executor_b.circuit_info();
        // Pre-check: compare circuit metadata
        if info_a.num_constraints != info_b.num_constraints {
            findings.push(Finding {
                attack_type: AttackType::Soundness,
                severity: Severity::Medium,
                description: format!(
                    "Constraint count mismatch: {} ({}) vs {} ({})",
                    executor_a.name(), info_a.num_constraints,
                    executor_b.name(), info_b.num_constraints
                ),
                poc: Default::default(),
                location: None,
            });
        }
        // Execute same witnesses on both backends
        for (idx, witness) in witnesses.iter().take(self.sample_count).enumerate() {
            let result_a = executor_a.execute_sync(witness);
            let result_b = executor_b.execute_sync(witness);
            // Compare success/failure
            if result_a.success != result_b.success {
                findings.push(Finding {
                    attack_type: AttackType::Soundness,
                    severity: Severity::Critical,
                    description: format!(
                        "Acceptance divergence on witness {}: {} accepts={}, {} accepts={}",
                        idx, executor_a.name(), result_a.success,
                        executor_b.name(), result_b.success
                    ),
                    poc: ProofOfConcept {
                        original_witness: Some(witness.clone()),
                        ..Default::default()
                    },
                    location: None,
                });
                continue;
            }
            if !result_a.success { continue; } // Both rejected
            // Compare outputs
            if result_a.outputs.len() != result_b.outputs.len() {
                findings.push(Finding {
                    attack_type: AttackType::Soundness,
                    severity: Severity::High,
                    description: format!(
                        "Output count mismatch on witness {}: {} has {} outputs, {} has {}",
                        idx, executor_a.name(), result_a.outputs.len(),
                        executor_b.name(), result_b.outputs.len()
                    ),
                    poc: ProofOfConcept {
                        original_witness: Some(witness.clone()),
                        ..Default::default()
                    },
                    location: None,
                });
                continue;
            }
            for (out_idx, (a, b)) in result_a.outputs.iter()
                .zip(result_b.outputs.iter()).enumerate()
            {
                if a != b {
                    let hamming = a.0.iter().zip(b.0.iter())
                        .map(|(x, y)| (x ^ y).count_ones() as usize)
                        .sum::<usize>();
                    findings.push(Finding {
                        attack_type: AttackType::Soundness,
                        severity: Severity::Critical,
                        description: format!(
                            "Output divergence on witness {}, output {}: \
                             {} vs {} (Hamming distance: {} bits). \
                             At least one backend has a bug.",
                            idx, out_idx, executor_a.name(),
                            executor_b.name(), hamming
                        ),
                        poc: ProofOfConcept {
                            original_witness: Some(witness.clone()),
                            ..Default::default()
                        },
                        location: None,
                    });
                }
            }
        }
        findings
    }
}
Engine Integration
rust
// Only run when config specifies multiple backends for the same circuit
fn run_cross_backend_differential(&self) -> Vec<Finding> {
    let backends = self.config.backend_targets(); // e.g., [circom, noir]
    if backends.len() < 2 { return Vec::new(); }
    let executor_a = self.create_executor(&backends[0])?;
    let executor_b = self.create_executor(&backends[1])?;
    let witnesses = self.corpus.read().unwrap().get_witnesses(100);
    CrossBackendDifferential::new()
        .run(executor_a.as_ref(), executor_b.as_ref(), &witnesses)
}
P2-1: Input Canonicalization Checker
File: src/attacks/canonicalization.rs (~200 LOC)

Goal: Test if non-canonical input representations are handled correctly.

Implementation
rust
use num_bigint::BigUint;
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};
use zk_fuzzer_core::constants::bn254_modulus_bytes;
pub struct CanonicalizationChecker {
    /// Test x vs x+p (field wrap)
    test_field_wrap: bool,
    /// Test x vs p-x (additive inverse)
    test_additive_inverse: bool,
    /// Test negative zero (p itself)
    test_negative_zero: bool,
}
impl CanonicalizationChecker {
    pub fn run(
        &self,
        executor: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        let modulus = bn254_modulus_bytes();
        let p = BigUint::from_bytes_be(&modulus);
        let mut findings = Vec::new();
        for (w_idx, witness) in witnesses.iter().take(20).enumerate() {
            let baseline = executor.execute_sync(witness);
            if !baseline.success { continue; }
            // For each input position, try non-canonical variants
            for input_idx in 0..witness.len() {
                let x = BigUint::from_bytes_be(&witness[input_idx].0);
                // Test 1: x + p (should be equivalent to x in field arithmetic)
                if self.test_field_wrap {
                    let x_plus_p = &x + &p;
                    if let Some(fe) = to_field_element(&x_plus_p) {
                        let mut modified = witness.clone();
                        modified[input_idx] = fe;
                        let result = executor.execute_sync(&modified);
                        // If circuit accepts x+p with SAME output → may be correct
                        // If circuit accepts x+p with DIFFERENT output → bug!
                        // If circuit rejects x+p → good (proper canonicalization)
                        if result.success && result.outputs != baseline.outputs {
                            findings.push(Finding {
                                attack_type: AttackType::Boundary,
                                severity: Severity::High,
                                description: format!(
                                    "Non-canonical input accepted with different output: \
                                     input[{}] = x+p produces different result than x. \
                                     Missing modular reduction.",
                                    input_idx
                                ),
                                poc: ProofOfConcept {
                                    original_witness: Some(witness.clone()),
                                    secondary_witness: Some(modified),
                                    ..Default::default()
                                },
                                location: None,
                            });
                        }
                    }
                }
                // Test 2: Replace x with p (should equal 0)
                if self.test_negative_zero && x == BigUint::from(0u32) {
                    if let Some(fe) = to_field_element(&p) {
                        let mut modified = witness.clone();
                        modified[input_idx] = fe;
                        let result = executor.execute_sync(&modified);
                        if result.success && result.outputs != baseline.outputs {
                            findings.push(Finding {
                                attack_type: AttackType::Boundary,
                                severity: Severity::High,
                                description: format!(
                                    "Negative zero (p) treated differently from 0 at \
                                     input[{}]. Circuit does not reduce inputs mod p.",
                                    input_idx
                                ),
                                poc: ProofOfConcept {
                                    original_witness: Some(witness.clone()),
                                    secondary_witness: Some(modified),
                                    ..Default::default()
                                },
                                location: None,
                            });
                        }
                    }
                }
            }
        }
        findings
    }
}
fn to_field_element(value: &BigUint) -> Option<FieldElement> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 { return None; }
    let mut result = [0u8; 32];
    let start = 32 - bytes.len();
    result[start..].copy_from_slice(&bytes);
    Some(FieldElement(result))
}
P2-2: Trusted Setup Poisoning Detector
File: src/attacks/setup_poisoning.rs (~200 LOC)

Goal: Test if proofs from one setup verify under a different verification key.

Implementation
rust
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};
pub struct SetupPoisoningDetector {
    /// Number of cross-verification attempts
    attempts: usize,
}
impl SetupPoisoningDetector {
    /// Run cross-verification between two executor instances with different setups
    ///
    /// executor_a and executor_b should be the same circuit compiled with
    /// different trusted setup parameters (different tau values).
    pub fn run(
        &self,
        executor_a: &dyn CircuitExecutor,
        executor_b: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let info = executor_a.circuit_info();
        for (idx, witness) in witnesses.iter().take(self.attempts).enumerate() {
            // Generate proof with executor A's proving key
            let proof_a = match executor_a.prove(witness) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let public_inputs: Vec<FieldElement> =
                witness[..info.num_public_inputs].to_vec();
            // Verify proof_a with executor B's verification key
            match executor_b.verify(&proof_a, &public_inputs) {
                Ok(true) => {
                    findings.push(Finding {
                        attack_type: AttackType::Soundness,
                        severity: Severity::Critical,
                        description: format!(
                            "Cross-setup verification succeeded: proof from setup A \
                             verified under setup B's key (witness {}). \
                             Trusted setup may be compromised or verification key \
                             is not binding.",
                            idx
                        ),
                        poc: ProofOfConcept {
                            original_witness: Some(witness.clone()),
                            original_proof: Some(proof_a),
                            public_inputs: Some(public_inputs),
                            ..Default::default()
                        },
                        location: None,
                    });
                }
                _ => {} // Expected: cross-setup verification fails
            }
        }
        findings
    }
}
Usage Note
This scanner requires the engine to instantiate two executors from different setup ceremonies. Add a config option:

yaml
# campaign.yaml
trusted_setup_test:
  enabled: true
  ptau_file_a: "pot12_original.ptau"
  ptau_file_b: "pot12_alternative.ptau"
Integration Checklist
Files to Create
File	LOC	Priority
src/attacks/proof_malleability.rs	~350	P0
src/attacks/determinism.rs	~120	P0
src/attacks/frozen_wire.rs	~200	P1
src/attacks/nullifier_replay.rs	~280	P1
src/attacks/cross_backend.rs	~250	P1
src/attacks/canonicalization.rs	~200	P2
src/attacks/setup_poisoning.rs	~200	P2
Files to Modify
File	Changes
src/attacks/mod.rs
Add pub mod for each new scanner
src/fuzzer/engine.rs
Add run_*_attack() methods, wire into campaign dispatch
Cargo.toml
May need num-bigint (already a dependency)
Campaign YAML schema	Add config options for new scanners
Testing Strategy
Each scanner should have:

Unit tests with 
MockCircuitExecutor
 — configure the mock to trigger the vulnerability
Integration test against a known-vulnerable Circom circuit from tests/bench/known_bugs/
False-positive test — run against a well-constrained circuit, expect zero findings