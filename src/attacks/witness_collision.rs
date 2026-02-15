//! Enhanced Witness Collision Detection
//!
//! Finds distinct witnesses that produce identical public outputs,
//! indicating potential under-constraint or missing uniqueness checks.
//!
//! # Concept
//!
//! For secure circuits:
//! - Different valid witnesses should produce different public outputs
//! - OR the equivalence should be expected (e.g., permutation invariance)
//!
//! Finding unexpected collisions indicates:
//! - Missing uniqueness constraints
//! - Under-constrained circuits
//! - Potential double-spend or replay vulnerabilities
//!
//! # Example
//!
//! ```rust,ignore
//! use zk_fuzzer::attacks::witness_collision::WitnessCollisionDetector;
//!
//! let detector = WitnessCollisionDetector::new()
//!     .with_samples(100000);
//!
//! let collisions = detector.run(&executor, &witnesses).await?;
//! ```

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

type WitnessCollisionEntry = (Vec<FieldElement>, Vec<FieldElement>, Vec<FieldElement>);

/// A collision between two witnesses
#[derive(Debug, Clone)]
pub struct WitnessCollision {
    /// First witness
    pub witness_a: Vec<FieldElement>,
    /// Second witness
    pub witness_b: Vec<FieldElement>,
    /// Public inputs associated with the collision
    pub public_inputs: Vec<FieldElement>,
    /// Public input indices used for scoping
    pub public_input_indices: Vec<usize>,
    /// Shared output hash
    pub output_hash: String,
    /// Actual outputs (same for both)
    pub outputs: Vec<FieldElement>,
    /// Whether this collision is expected (equivalence class)
    pub is_expected: bool,
}

/// Equivalence class definition
#[derive(Debug, Clone)]
pub struct EquivalenceClass {
    /// Name of the equivalence class
    pub name: String,
    /// Predicate to check if two witnesses are equivalent
    pub predicate: EquivalencePredicate,
}

/// Types of equivalence predicates
#[derive(Debug, Clone)]
pub enum EquivalencePredicate {
    /// Witnesses differ only in specified indices
    DifferOnlyAt(Vec<usize>),
    /// Witnesses are permutations of each other
    Permutation,
    /// Witnesses are scalar multiples
    ScalarMultiple,
    /// Custom predicate (always returns false for now)
    Custom(String),
}

impl EquivalenceClass {
    /// Check if two witnesses are in this equivalence class
    pub fn are_equivalent(&self, a: &[FieldElement], b: &[FieldElement]) -> bool {
        match &self.predicate {
            EquivalencePredicate::DifferOnlyAt(indices) => {
                if a.len() != b.len() {
                    return false;
                }
                for (i, (va, vb)) in a.iter().zip(b.iter()).enumerate() {
                    if !indices.contains(&i) && va != vb {
                        return false;
                    }
                }
                true
            }
            EquivalencePredicate::Permutation => {
                if a.len() != b.len() {
                    return false;
                }
                let mut sorted_a: Vec<_> = a.iter().map(|f| f.to_bytes()).collect();
                let mut sorted_b: Vec<_> = b.iter().map(|f| f.to_bytes()).collect();
                sorted_a.sort();
                sorted_b.sort();
                sorted_a == sorted_b
            }
            EquivalencePredicate::ScalarMultiple => {
                if a.is_empty() || b.is_empty() || a.len() != b.len() {
                    return false;
                }
                // Find the ratio from first non-zero pair
                let ratio = a
                    .iter()
                    .zip(b.iter())
                    .find(|(va, vb)| !va.is_zero() && !vb.is_zero())
                    .map(|(va, vb)| {
                        // This is a simplified check
                        va.to_bytes() == vb.to_bytes()
                            || va.mul(&FieldElement::from_u64(2)).to_bytes() == vb.to_bytes()
                    });
                match ratio {
                    Some(value) => value,
                    None => false,
                }
            }
            EquivalencePredicate::Custom(_) => false,
        }
    }
}

/// Witness collision detector
pub struct WitnessCollisionDetector {
    /// Number of samples to test
    sample_count: usize,
    /// Expected equivalence classes
    equivalence_classes: Vec<EquivalenceClass>,
    /// Scope collisions to matching public inputs
    scope_public_inputs: bool,
    /// Explicit public input indices (input vector positions)
    public_input_indices: Option<Vec<usize>>,
}

impl Default for WitnessCollisionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl WitnessCollisionDetector {
    /// Create a new detector
    pub fn new() -> Self {
        Self {
            sample_count: 10000,
            equivalence_classes: Vec::new(),
            scope_public_inputs: true,
            public_input_indices: None,
        }
    }

    /// Set sample count
    pub fn with_samples(mut self, count: usize) -> Self {
        self.sample_count = count;
        self
    }

    /// Add an equivalence class
    pub fn with_equivalence_class(mut self, class: EquivalenceClass) -> Self {
        self.equivalence_classes.push(class);
        self
    }

    /// Scope collisions to matching public inputs
    pub fn with_public_input_scope(mut self, enabled: bool) -> Self {
        self.scope_public_inputs = enabled;
        self
    }

    /// Provide explicit public input indices (input vector positions)
    pub fn with_public_input_indices(mut self, indices: Vec<usize>) -> Self {
        self.public_input_indices = Some(indices);
        self
    }

    /// Compute hash of outputs
    fn hash_outputs(&self, outputs: &[FieldElement]) -> String {
        let mut hasher = Sha256::new();
        for output in outputs {
            hasher.update(output.to_bytes());
        }
        let result = hasher.finalize();
        hex::encode(&result[..16])
    }

    fn hash_outputs_with_public_inputs(
        &self,
        outputs: &[FieldElement],
        public_inputs: &[FieldElement],
    ) -> String {
        let mut hasher = Sha256::new();
        for output in outputs {
            hasher.update(output.to_bytes());
        }
        for input in public_inputs {
            hasher.update(input.to_bytes());
        }
        let result = hasher.finalize();
        hex::encode(&result[..16])
    }

    /// Check if a collision is expected
    fn is_expected_collision(&self, a: &[FieldElement], b: &[FieldElement]) -> bool {
        for class in &self.equivalence_classes {
            if class.are_equivalent(a, b) {
                return true;
            }
        }
        false
    }

    /// Run collision detection
    pub async fn run(
        &self,
        executor: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<WitnessCollision> {
        let mut output_map: HashMap<String, WitnessCollisionEntry> = HashMap::new();
        let mut collisions = Vec::new();
        let num_public = executor.num_public_inputs();
        let explicit_public_indices = self.public_input_indices.as_ref();
        let default_public_indices: Vec<usize> = (0..num_public).collect();

        // Memory safety: cap witness storage at 10k to prevent OOM
        const MAX_STORED_WITNESSES: usize = 10_000;
        let safe_sample_count = self.sample_count.min(MAX_STORED_WITNESSES);

        // Execute all witnesses and collect outputs
        for witness in witnesses.iter().take(safe_sample_count) {
            let result = executor.execute(witness).await;
            if result.success {
                let indices_used: Vec<usize> = if let Some(indices) = explicit_public_indices {
                    indices.clone()
                } else {
                    default_public_indices.clone()
                };

                let public_inputs = if self.scope_public_inputs {
                    indices_used
                        .iter()
                        .filter_map(|&idx| witness.get(idx).cloned())
                        .collect()
                } else {
                    Vec::new()
                };
                let hash = if self.scope_public_inputs && !public_inputs.is_empty() {
                    self.hash_outputs_with_public_inputs(&result.outputs, &public_inputs)
                } else {
                    self.hash_outputs(&result.outputs)
                };

                if let Some((existing_witness, existing_outputs, existing_public)) =
                    output_map.get(&hash)
                {
                    if existing_witness == witness {
                        continue;
                    }
                    // Found a collision!
                    let is_expected = self.is_expected_collision(existing_witness, witness);

                    if !is_expected {
                        collisions.push(WitnessCollision {
                            witness_a: existing_witness.clone(),
                            witness_b: witness.clone(),
                            public_inputs: existing_public.clone(),
                            public_input_indices: indices_used.clone(),
                            output_hash: hash.clone(),
                            outputs: existing_outputs.clone(),
                            is_expected: false,
                        });
                    }
                } else {
                    output_map.insert(hash, (witness.clone(), result.outputs, public_inputs));
                }
            }
        }

        collisions
    }

    /// Run with generated witnesses
    pub async fn run_with_generation(
        &self,
        executor: &dyn CircuitExecutor,
        generator: impl Fn(&mut rand::rngs::ThreadRng) -> Vec<FieldElement>,
    ) -> Vec<WitnessCollision> {
        // Memory safety: cap witness generation at 10k to prevent OOM
        const MAX_STORED_WITNESSES: usize = 10_000;
        let safe_sample_count = self.sample_count.min(MAX_STORED_WITNESSES);

        let mut rng = rand::thread_rng();
        let witnesses: Vec<Vec<FieldElement>> = (0..safe_sample_count)
            .map(|_| generator(&mut rng))
            .collect();

        self.run(executor, &witnesses).await
    }

    /// Convert collisions to findings
    pub fn to_findings(&self, collisions: &[WitnessCollision]) -> Vec<Finding> {
        collisions.iter()
            .filter(|c| !c.is_expected)
            .map(|c| {
                Finding {
                    attack_type: AttackType::WitnessCollision,
                    severity: Severity::Critical,
                    description: format!(
                        "Witness collision detected: two distinct witnesses produce identical \
                         outputs (hash: {}). Public input indices: {:?}. This indicates missing uniqueness constraints.",
                        c.output_hash, c.public_input_indices
                    ),
                    poc: ProofOfConcept {
                        witness_a: c.witness_a.clone(),
                        witness_b: Some(c.witness_b.clone()),
                        public_inputs: c.public_inputs.clone(),
                        proof: None,
                    },
                    location: None,
                }
            })
            .collect()
    }

    /// Analyze collision patterns
    pub fn analyze_patterns(&self, collisions: &[WitnessCollision]) -> CollisionAnalysis {
        let mut analysis = CollisionAnalysis {
            total_collisions: collisions.len(),
            unexpected_collisions: collisions.iter().filter(|c| !c.is_expected).count(),
            differing_indices: HashMap::new(),
        };

        // Find which indices tend to differ in collisions
        for collision in collisions {
            for (i, (a, b)) in collision
                .witness_a
                .iter()
                .zip(collision.witness_b.iter())
                .enumerate()
            {
                if a != b {
                    *analysis.differing_indices.entry(i).or_insert(0) += 1;
                }
            }
        }

        analysis
    }
}

/// Analysis of collision patterns
#[derive(Debug, Clone)]
pub struct CollisionAnalysis {
    /// Total number of collisions found
    pub total_collisions: usize,
    /// Number of unexpected collisions
    pub unexpected_collisions: usize,
    /// Which input indices differ most often in collisions
    pub differing_indices: HashMap<usize, usize>,
}

impl CollisionAnalysis {
    /// Get the most commonly differing indices
    pub fn most_differing_indices(&self, top_n: usize) -> Vec<(usize, usize)> {
        let mut sorted: Vec<_> = self
            .differing_indices
            .iter()
            .map(|(&i, &c)| (i, c))
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(top_n);
        sorted
    }
}

/// Statistics from collision detection
#[derive(Debug, Clone, Default)]
pub struct WitnessCollisionStats {
    pub witnesses_tested: usize,
    pub unique_outputs: usize,
    pub collisions_found: usize,
    pub unexpected_collisions: usize,
    pub collision_rate: f64,
}

impl WitnessCollisionDetector {
    /// Compute statistics
    pub fn stats(
        &self,
        collisions: &[WitnessCollision],
        witnesses_tested: usize,
    ) -> WitnessCollisionStats {
        let unexpected = collisions.iter().filter(|c| !c.is_expected).count();
        WitnessCollisionStats {
            witnesses_tested,
            unique_outputs: witnesses_tested - collisions.len(),
            collisions_found: collisions.len(),
            unexpected_collisions: unexpected,
            collision_rate: if witnesses_tested > 0 {
                collisions.len() as f64 / witnesses_tested as f64
            } else {
                0.0
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equivalence_differ_only_at() {
        let class = EquivalenceClass {
            name: "test".to_string(),
            predicate: EquivalencePredicate::DifferOnlyAt(vec![1]),
        };

        let a = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
        ];
        let b = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(99), // Different at index 1
            FieldElement::from_u64(3),
        ];
        let c = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
            FieldElement::from_u64(99), // Different at index 2 (not allowed)
        ];

        assert!(class.are_equivalent(&a, &b));
        assert!(!class.are_equivalent(&a, &c));
    }

    #[test]
    fn test_equivalence_permutation() {
        let class = EquivalenceClass {
            name: "permutation".to_string(),
            predicate: EquivalencePredicate::Permutation,
        };

        let a = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
        ];
        let b = vec![
            FieldElement::from_u64(3),
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
        ];
        let c = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
            FieldElement::from_u64(4),
        ];

        assert!(class.are_equivalent(&a, &b));
        assert!(!class.are_equivalent(&a, &c));
    }

    #[test]
    fn test_collision_detection() {
        let detector = WitnessCollisionDetector::new().with_samples(1000);

        let collision = WitnessCollision {
            witness_a: vec![FieldElement::from_u64(1)],
            witness_b: vec![FieldElement::from_u64(2)],
            public_inputs: vec![],
            public_input_indices: vec![],
            output_hash: "abc123".to_string(),
            outputs: vec![FieldElement::from_u64(42)],
            is_expected: false,
        };

        let findings = detector.to_findings(&[collision]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].attack_type, AttackType::WitnessCollision);
    }

    #[test]
    fn test_collision_analysis() {
        let detector = WitnessCollisionDetector::new();

        let collisions = vec![
            WitnessCollision {
                witness_a: vec![FieldElement::from_u64(1), FieldElement::from_u64(2)],
                witness_b: vec![FieldElement::from_u64(1), FieldElement::from_u64(3)],
                public_inputs: vec![],
                public_input_indices: vec![],
                output_hash: "hash1".to_string(),
                outputs: vec![],
                is_expected: false,
            },
            WitnessCollision {
                witness_a: vec![FieldElement::from_u64(1), FieldElement::from_u64(4)],
                witness_b: vec![FieldElement::from_u64(1), FieldElement::from_u64(5)],
                public_inputs: vec![],
                public_input_indices: vec![],
                output_hash: "hash2".to_string(),
                outputs: vec![],
                is_expected: false,
            },
        ];

        let analysis = detector.analyze_patterns(&collisions);

        assert_eq!(analysis.total_collisions, 2);
        let differing = match analysis.differing_indices.get(&1) {
            Some(value) => *value,
            None => 0,
        };
        assert_eq!(differing, 2);
    }
}
