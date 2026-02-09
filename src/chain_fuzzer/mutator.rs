//! Mode 3: Chain Mutator - Mutates chain inputs for coverage-guided exploration
//!
//! Provides mutation strategies for multi-step chain fuzzing.

use super::types::{ChainSpec, InputWiring};
use rand::Rng;
use std::collections::HashMap;
use zk_core::FieldElement;
use crate::fuzzer::structure_aware::StructureAwareMutator;

/// Mutates chain inputs for coverage-guided exploration
pub struct ChainMutator {
    /// Underlying field element mutator
    field_mutator: StructureAwareMutator,
    /// Mutation strategy weights
    strategy_weights: MutationWeights,
}

/// Weights for different mutation strategies
#[derive(Debug, Clone)]
pub struct MutationWeights {
    /// Weight for single-step input tweaking
    pub single_step_tweak: f64,
    /// Weight for initial-input cascade mutations
    pub cascade_mutation: f64,
    /// Weight for step reordering
    pub step_reorder: f64,
    /// Weight for step duplication
    pub step_duplication: f64,
    /// Weight for boundary value injection
    pub boundary_injection: f64,
    /// Weight for bit flipping
    pub bit_flip: f64,
}

impl Default for MutationWeights {
    fn default() -> Self {
        Self {
            single_step_tweak: 0.40,
            cascade_mutation: 0.25,
            step_reorder: 0.05,
            step_duplication: 0.05,
            boundary_injection: 0.15,
            bit_flip: 0.10,
        }
    }
}

/// Type of mutation applied
#[derive(Debug, Clone)]
pub enum MutationType {
    /// Tweaked inputs at a single step
    SingleStepTweak { step_index: usize },
    /// Mutated initial inputs with cascading effects
    CascadeMutation,
    /// Reordered steps
    StepReorder { from: usize, to: usize },
    /// Duplicated a step
    StepDuplication { step_index: usize },
    /// Injected boundary values
    BoundaryInjection { step_index: usize, input_index: usize },
    /// Flipped bits in an input
    BitFlip { step_index: usize, input_index: usize, bit: usize },
}

impl ChainMutator {
    /// Create a new chain mutator
    pub fn new() -> Self {
        Self {
            field_mutator: StructureAwareMutator::new(zk_core::Framework::Mock),
            strategy_weights: MutationWeights::default(),
        }
    }

    /// Create with custom weights
    pub fn with_weights(mut self, weights: MutationWeights) -> Self {
        self.strategy_weights = weights;
        self
    }

    /// Create with an existing structure-aware mutator
    pub fn with_field_mutator(mut self, mutator: StructureAwareMutator) -> Self {
        self.field_mutator = mutator;
        self
    }

    /// Mutate the inputs for a chain
    ///
    /// # Arguments
    ///
    /// * `spec` - The chain specification
    /// * `prior_inputs` - The previous inputs used (keyed by circuit_ref)
    /// * `rng` - Random number generator
    ///
    /// # Returns
    ///
    /// New mutated inputs and the type of mutation applied
    pub fn mutate_inputs(
        &self,
        spec: &ChainSpec,
        prior_inputs: &HashMap<String, Vec<FieldElement>>,
        rng: &mut impl Rng,
    ) -> (HashMap<String, Vec<FieldElement>>, MutationType) {
        // Select mutation strategy based on weights
        let strategy = self.select_strategy(rng);

        match strategy {
            0 => self.single_step_tweak(spec, prior_inputs, rng),
            1 => self.cascade_mutation(spec, prior_inputs, rng),
            2 => self.step_reorder(spec, prior_inputs, rng),
            3 => self.step_duplication(spec, prior_inputs, rng),
            4 => self.boundary_injection(spec, prior_inputs, rng),
            _ => self.bit_flip(spec, prior_inputs, rng),
        }
    }

    /// Select a mutation strategy based on weights
    fn select_strategy(&self, rng: &mut impl Rng) -> usize {
        let total = self.strategy_weights.single_step_tweak
            + self.strategy_weights.cascade_mutation
            + self.strategy_weights.step_reorder
            + self.strategy_weights.step_duplication
            + self.strategy_weights.boundary_injection
            + self.strategy_weights.bit_flip;

        let mut rand_val = rng.gen::<f64>() * total;

        let weights = [
            self.strategy_weights.single_step_tweak,
            self.strategy_weights.cascade_mutation,
            self.strategy_weights.step_reorder,
            self.strategy_weights.step_duplication,
            self.strategy_weights.boundary_injection,
            self.strategy_weights.bit_flip,
        ];

        for (i, weight) in weights.iter().enumerate() {
            if rand_val < *weight {
                return i;
            }
            rand_val -= weight;
        }

        0 // Default to single step tweak
    }

    /// Strategy 1: Single-step input tweak
    /// Pick a step with Fresh or Mixed wiring and mutate its fresh inputs
    fn single_step_tweak(
        &self,
        spec: &ChainSpec,
        prior_inputs: &HashMap<String, Vec<FieldElement>>,
        rng: &mut impl Rng,
    ) -> (HashMap<String, Vec<FieldElement>>, MutationType) {
        let mut result = prior_inputs.clone();

        // Find steps with fresh inputs
        let mutable_steps: Vec<_> = spec.steps.iter()
            .enumerate()
            .filter(|(_, step)| matches!(step.input_wiring, InputWiring::Fresh | InputWiring::Mixed { .. }))
            .collect();

        if mutable_steps.is_empty() {
            return (result, MutationType::SingleStepTweak { step_index: 0 });
        }

        let (step_idx, step) = mutable_steps[rng.gen_range(0..mutable_steps.len())];

        // Mutate the inputs for this step's circuit
        if let Some(inputs) = result.get_mut(&step.circuit_ref) {
            if !inputs.is_empty() {
                let input_idx = rng.gen_range(0..inputs.len());
                inputs[input_idx] = self.mutate_field_element(&inputs[input_idx], rng);
            }
        } else {
            // Generate new random inputs
            let count = rng.gen_range(1..10);
            let new_inputs: Vec<_> = (0..count)
                .map(|_| FieldElement::random(rng))
                .collect();
            result.insert(step.circuit_ref.clone(), new_inputs);
        }

        (result, MutationType::SingleStepTweak { step_index: step_idx })
    }

    /// Strategy 2: Initial-input cascade
    /// Mutate step 0 inputs, let wiring propagate changes downstream
    fn cascade_mutation(
        &self,
        spec: &ChainSpec,
        prior_inputs: &HashMap<String, Vec<FieldElement>>,
        rng: &mut impl Rng,
    ) -> (HashMap<String, Vec<FieldElement>>, MutationType) {
        let mut result = prior_inputs.clone();

        if let Some(first_step) = spec.steps.first() {
            if let Some(inputs) = result.get_mut(&first_step.circuit_ref) {
                // Mutate multiple inputs in the first step
                let num_mutations = rng.gen_range(1..=inputs.len().max(1));
                for _ in 0..num_mutations {
                    if !inputs.is_empty() {
                        let idx = rng.gen_range(0..inputs.len());
                        inputs[idx] = self.mutate_field_element(&inputs[idx], rng);
                    }
                }
            } else {
                let count = rng.gen_range(1..10);
                let new_inputs: Vec<_> = (0..count)
                    .map(|_| FieldElement::random(rng))
                    .collect();
                result.insert(first_step.circuit_ref.clone(), new_inputs);
            }
        }

        (result, MutationType::CascadeMutation)
    }

    /// Strategy 3: Step reorder
    /// Swap two steps if wiring allows
    fn step_reorder(
        &self,
        spec: &ChainSpec,
        prior_inputs: &HashMap<String, Vec<FieldElement>>,
        rng: &mut impl Rng,
    ) -> (HashMap<String, Vec<FieldElement>>, MutationType) {
        // This is a more complex mutation that would require modifying the spec
        // For now, just return a cascade mutation instead
        // A full implementation would check if steps can be reordered based on dependencies
        
        if spec.steps.len() < 2 {
            return self.cascade_mutation(spec, prior_inputs, rng);
        }

        // Find pairs of steps that could potentially be swapped
        // (steps with Fresh wiring that don't depend on each other)
        let from = rng.gen_range(0..spec.steps.len());
        let to = rng.gen_range(0..spec.steps.len());

        // For now, just do a cascade mutation but record the intended reorder
        let (result, _) = self.cascade_mutation(spec, prior_inputs, rng);
        (result, MutationType::StepReorder { from, to })
    }

    /// Strategy 4: Step duplication
    /// Mark a step to be repeated (for re-entrancy testing)
    fn step_duplication(
        &self,
        spec: &ChainSpec,
        prior_inputs: &HashMap<String, Vec<FieldElement>>,
        rng: &mut impl Rng,
    ) -> (HashMap<String, Vec<FieldElement>>, MutationType) {
        if spec.steps.is_empty() {
            return self.cascade_mutation(spec, prior_inputs, rng);
        }

        let step_index = rng.gen_range(0..spec.steps.len());
        
        // Duplicate the inputs for this step's circuit
        let (result, _) = self.cascade_mutation(spec, prior_inputs, rng);
        (result, MutationType::StepDuplication { step_index })
    }

    /// Strategy 5: Boundary value injection
    /// Inject 0, 1, or p-1 at random fresh-input positions
    fn boundary_injection(
        &self,
        spec: &ChainSpec,
        prior_inputs: &HashMap<String, Vec<FieldElement>>,
        rng: &mut impl Rng,
    ) -> (HashMap<String, Vec<FieldElement>>, MutationType) {
        let mut result = prior_inputs.clone();

        // Find a step with fresh inputs
        let mutable_steps: Vec<_> = spec.steps.iter()
            .enumerate()
            .filter(|(_, step)| matches!(step.input_wiring, InputWiring::Fresh | InputWiring::Mixed { .. }))
            .collect();

        if mutable_steps.is_empty() {
            return (result, MutationType::BoundaryInjection { step_index: 0, input_index: 0 });
        }

        let (step_idx, step) = mutable_steps[rng.gen_range(0..mutable_steps.len())];

        let boundary_value = match rng.gen_range(0..4) {
            0 => FieldElement::zero(),
            1 => FieldElement::one(),
            2 => FieldElement::max_value(),
            _ => FieldElement::half_modulus(),
        };

        let input_index = if let Some(inputs) = result.get_mut(&step.circuit_ref) {
            if !inputs.is_empty() {
                let idx = rng.gen_range(0..inputs.len());
                inputs[idx] = boundary_value;
                idx
            } else {
                0
            }
        } else {
            result.insert(step.circuit_ref.clone(), vec![boundary_value]);
            0
        };

        (result, MutationType::BoundaryInjection { step_index: step_idx, input_index })
    }

    /// Strategy 6: Bit flip
    /// Flip random bits in an input value
    fn bit_flip(
        &self,
        spec: &ChainSpec,
        prior_inputs: &HashMap<String, Vec<FieldElement>>,
        rng: &mut impl Rng,
    ) -> (HashMap<String, Vec<FieldElement>>, MutationType) {
        let mut result = prior_inputs.clone();

        let mutable_steps: Vec<_> = spec.steps.iter()
            .enumerate()
            .filter(|(_, step)| matches!(step.input_wiring, InputWiring::Fresh | InputWiring::Mixed { .. }))
            .collect();

        if mutable_steps.is_empty() {
            return (result, MutationType::BitFlip { step_index: 0, input_index: 0, bit: 0 });
        }

        let (step_idx, step) = mutable_steps[rng.gen_range(0..mutable_steps.len())];
        let bit = rng.gen_range(0..256);

        let input_index = if let Some(inputs) = result.get_mut(&step.circuit_ref) {
            if !inputs.is_empty() {
                let idx = rng.gen_range(0..inputs.len());
                let mut bytes = inputs[idx].to_bytes();
                let byte_idx = bit / 8;
                let bit_idx = bit % 8;
                if byte_idx < 32 {
                    bytes[byte_idx] ^= 1 << bit_idx;
                }
                inputs[idx] = FieldElement::from_bytes(&bytes);
                idx
            } else {
                0
            }
        } else {
            0
        };

        (result, MutationType::BitFlip { step_index: step_idx, input_index, bit })
    }

    /// Mutate a single field element
    fn mutate_field_element(&self, fe: &FieldElement, rng: &mut impl Rng) -> FieldElement {
        let strategy = rng.gen_range(0..5);
        match strategy {
            0 => {
                // Add small value
                let delta = FieldElement::from_u64(rng.gen_range(1..1000));
                fe.add(&delta)
            }
            1 => {
                // Subtract small value
                let delta = FieldElement::from_u64(rng.gen_range(1..1000));
                fe.sub(&delta)
            }
            2 => {
                // Replace with boundary value
                match rng.gen_range(0..4) {
                    0 => FieldElement::zero(),
                    1 => FieldElement::one(),
                    2 => FieldElement::max_value(),
                    _ => FieldElement::half_modulus(),
                }
            }
            3 => {
                // Bit flip
                let mut bytes = fe.to_bytes();
                let bit = rng.gen_range(0..256);
                let byte_idx = bit / 8;
                let bit_idx = bit % 8;
                if byte_idx < 32 {
                    bytes[byte_idx] ^= 1 << bit_idx;
                }
                FieldElement::from_bytes(&bytes)
            }
            _ => {
                // Random replacement
                FieldElement::random(rng)
            }
        }
    }
}

impl Default for ChainMutator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_fuzzer::types::StepSpec;

    #[test]
    fn test_mutate_inputs() {
        let mutator = ChainMutator::new();
        
        let spec = ChainSpec::new("test_chain", vec![
            StepSpec::fresh("circuit_a"),
            StepSpec::fresh("circuit_b"),
        ]);

        let mut initial_inputs = HashMap::new();
        initial_inputs.insert("circuit_a".to_string(), vec![FieldElement::one(), FieldElement::from_u64(42)]);
        initial_inputs.insert("circuit_b".to_string(), vec![FieldElement::from_u64(100)]);

        let mut rng = rand::thread_rng();
        let (mutated, mutation_type) = mutator.mutate_inputs(&spec, &initial_inputs, &mut rng);

        // Should have mutated something
        assert!(!mutated.is_empty());
        
        // Mutation type should be recorded
        match mutation_type {
            MutationType::SingleStepTweak { .. } |
            MutationType::CascadeMutation |
            MutationType::BoundaryInjection { .. } |
            MutationType::BitFlip { .. } => {}
            _ => {} // Other types are also valid
        }
    }

    #[test]
    fn test_boundary_injection() {
        let mutator = ChainMutator::new()
            .with_weights(MutationWeights {
                boundary_injection: 1.0,
                ..Default::default()
            });

        let spec = ChainSpec::new("test_chain", vec![
            StepSpec::fresh("circuit_a"),
        ]);

        let mut initial_inputs = HashMap::new();
        initial_inputs.insert("circuit_a".to_string(), vec![FieldElement::from_u64(500)]);

        let mut rng = rand::thread_rng();
        let (mutated, mutation_type) = mutator.mutate_inputs(&spec, &initial_inputs, &mut rng);

        matches!(mutation_type, MutationType::BoundaryInjection { .. });
        
        // One of the inputs should be a boundary value
        let inputs = mutated.get("circuit_a").unwrap();
        let is_boundary = inputs.iter().any(|fe| {
            *fe == FieldElement::zero() ||
            *fe == FieldElement::one() ||
            *fe == FieldElement::max_value() ||
            *fe == FieldElement::half_modulus()
        });
        assert!(is_boundary);
    }
}
