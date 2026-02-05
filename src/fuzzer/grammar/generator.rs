//! Test case generator based on grammar DSL

use super::InputGrammar;
use zk_core::{FieldElement, TestCase, TestMetadata};
use rand::Rng;

/// Grammar-based test case generator
pub struct GrammarGenerator {
    grammar: InputGrammar,
    generation_count: u64,
}

impl GrammarGenerator {
    /// Create new generator with grammar
    pub fn new(grammar: InputGrammar) -> Self {
        Self {
            grammar,
            generation_count: 0,
        }
    }

    /// Generate a new test case
    pub fn generate(&mut self, rng: &mut impl Rng) -> TestCase {
        self.generation_count += 1;
        self.grammar.generate(rng)
    }

    /// Generate test case with specific strategy
    pub fn generate_with_strategy(
        &mut self,
        strategy: GenerationStrategy,
        rng: &mut impl Rng,
    ) -> TestCase {
        match strategy {
            GenerationStrategy::Random => self.generate(rng),
            GenerationStrategy::Boundary => self.generate_boundary(),
            GenerationStrategy::Interesting => self.generate_interesting(rng),
            GenerationStrategy::AllZeros => self.generate_all_zeros(),
            GenerationStrategy::AllMax => self.generate_all_max(),
        }
    }

    /// Generate boundary test case
    fn generate_boundary(&mut self) -> TestCase {
        self.generation_count += 1;
        let mut inputs = Vec::new();

        for spec in &self.grammar.inputs {
            let count = spec.flattened_count();
            for i in 0..count {
                // Cycle through boundary values
                let value = match i % 4 {
                    0 => FieldElement::zero(),
                    1 => FieldElement::one(),
                    2 => FieldElement::max_value(),
                    _ => FieldElement::half_modulus(),
                };
                inputs.push(value);
            }
        }

        TestCase {
            inputs,
            expected_output: None,
            metadata: TestMetadata {
                generation: self.generation_count as usize,
                mutation_history: vec!["boundary".to_string()],
                coverage_bits: 0,
            },
        }
    }

    /// Generate test case from interesting values
    fn generate_interesting(&mut self, rng: &mut impl Rng) -> TestCase {
        self.generation_count += 1;
        let mut inputs = Vec::new();

        for spec in &self.grammar.inputs {
            let count = spec.flattened_count();
            for _ in 0..count {
                if !spec.interesting.is_empty() {
                    let idx = rng.gen_range(0..spec.interesting.len());
                    if let Ok(fe) = FieldElement::from_hex(&spec.interesting[idx]) {
                        inputs.push(fe);
                        continue;
                    }
                }
                // Fall back to random
                inputs.push(FieldElement::random(rng));
            }
        }

        TestCase {
            inputs,
            expected_output: None,
            metadata: TestMetadata {
                generation: self.generation_count as usize,
                mutation_history: vec!["interesting".to_string()],
                coverage_bits: 0,
            },
        }
    }

    /// Generate all-zeros test case
    fn generate_all_zeros(&mut self) -> TestCase {
        self.generation_count += 1;
        let count = self.grammar.input_count();

        TestCase {
            inputs: vec![FieldElement::zero(); count],
            expected_output: None,
            metadata: TestMetadata {
                generation: self.generation_count as usize,
                mutation_history: vec!["all_zeros".to_string()],
                coverage_bits: 0,
            },
        }
    }

    /// Generate all-max test case
    fn generate_all_max(&mut self) -> TestCase {
        self.generation_count += 1;
        let count = self.grammar.input_count();

        TestCase {
            inputs: vec![FieldElement::max_value(); count],
            expected_output: None,
            metadata: TestMetadata {
                generation: self.generation_count as usize,
                mutation_history: vec!["all_max".to_string()],
                coverage_bits: 0,
            },
        }
    }

    /// Mutate a test case
    pub fn mutate(&self, test_case: &TestCase, rng: &mut impl Rng) -> TestCase {
        self.grammar.mutate(test_case, rng)
    }

    /// Get generation count
    pub fn generation_count(&self) -> u64 {
        self.generation_count
    }

    /// Get grammar reference
    pub fn grammar(&self) -> &InputGrammar {
        &self.grammar
    }
}

/// Strategy for test case generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationStrategy {
    /// Fully random inputs
    Random,
    /// Use boundary values (0, 1, max, half_max)
    Boundary,
    /// Use interesting values from grammar
    Interesting,
    /// All zeros
    AllZeros,
    /// All max values
    AllMax,
}

// InputSpec::flattened_count is defined in mod.rs

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::standard;

    #[test]
    fn test_generator_strategies() {
        let grammar = standard::range_proof(64);
        let mut gen = GrammarGenerator::new(grammar);
        let mut rng = rand::thread_rng();

        let random = gen.generate_with_strategy(GenerationStrategy::Random, &mut rng);
        assert!(!random.inputs.is_empty());

        let boundary = gen.generate_with_strategy(GenerationStrategy::Boundary, &mut rng);
        assert!(
            boundary.inputs[0].is_zero()
                || boundary.inputs[0].is_one()
                || boundary.inputs[0] == FieldElement::max_value()
        );

        let zeros = gen.generate_with_strategy(GenerationStrategy::AllZeros, &mut rng);
        assert!(zeros.inputs.iter().all(|fe| fe.is_zero()));

        let max = gen.generate_with_strategy(GenerationStrategy::AllMax, &mut rng);
        assert!(max.inputs.iter().all(|fe| fe.0 == FieldElement::max_value().0));
    }

    #[test]
    fn test_generation_count() {
        let grammar = standard::range_proof(64);
        let mut gen = GrammarGenerator::new(grammar);
        let mut rng = rand::thread_rng();

        assert_eq!(gen.generation_count(), 0);
        gen.generate(&mut rng);
        assert_eq!(gen.generation_count(), 1);
        gen.generate(&mut rng);
        assert_eq!(gen.generation_count(), 2);
    }
}
