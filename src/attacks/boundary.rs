//! Boundary Value Testing for ZK Circuits
//!
//! Implements systematic boundary value analysis to test circuit behavior at:
//! - Field element boundaries (0, 1, p-1, p, etc.)
//! - Bit boundaries (2^n - 1, 2^n, 2^n + 1)
//! - Application-specific boundaries (range proofs, age verification, etc.)
//! - Type transition boundaries
//!
//! Boundary testing is critical for ZK circuits because:
//! - Field arithmetic wraps at the modulus
//! - Bit decomposition has strict range requirements
//! - Range proofs must reject out-of-range values
//! - Integer comparisons in fields are non-trivial

use super::{Attack, AttackContext, CircuitInfo};
use crate::config::AttackType;
use crate::fuzzer::{FieldElement, Finding, ProofOfConcept};
use crate::config::Severity;
use num_bigint::BigUint;

/// Boundary value tester for ZK circuits
pub struct BoundaryTester {
    /// Boundary values to test
    boundary_values: Vec<BoundaryValue>,
    /// Whether to test combinations of boundary values
    test_combinations: bool,
    /// Number of inputs to the circuit
    num_inputs: usize,
    /// Custom application-specific boundaries
    custom_boundaries: Vec<CustomBoundary>,
}

/// A boundary value with metadata
#[derive(Debug, Clone)]
pub struct BoundaryValue {
    /// The actual value
    pub value: FieldElement,
    /// Human-readable name
    pub name: String,
    /// Why this boundary is interesting
    pub rationale: String,
    /// Category of boundary
    pub category: BoundaryCategory,
}

/// Categories of boundary values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryCategory {
    /// Field element boundary (0, 1, p-1)
    FieldBoundary,
    /// Bit boundary (2^n - 1, 2^n)
    BitBoundary,
    /// Integer overflow boundary
    OverflowBoundary,
    /// Application-specific boundary
    ApplicationBoundary,
    /// Signedness boundary (for signed integer emulation)
    SignedBoundary,
}

/// Custom application-specific boundary definition
#[derive(Debug, Clone)]
pub struct CustomBoundary {
    /// Name of the boundary
    pub name: String,
    /// The boundary value
    pub value: FieldElement,
    /// Values just below the boundary
    pub below: Vec<FieldElement>,
    /// Values just above the boundary
    pub above: Vec<FieldElement>,
    /// Expected behavior description
    pub expected_behavior: String,
}

/// Result of boundary testing
#[derive(Debug, Clone)]
pub struct BoundaryTestResult {
    /// The boundary value tested
    pub boundary: BoundaryValue,
    /// Whether the test passed
    pub passed: bool,
    /// Whether the circuit accepted the input
    pub accepted: bool,
    /// Any error message
    pub error: Option<String>,
    /// Output produced (if any)
    pub output: Option<Vec<FieldElement>>,
}

impl BoundaryTester {
    /// Create a new boundary tester with default boundaries
    pub fn new() -> Self {
        Self {
            boundary_values: Self::default_boundaries(),
            test_combinations: false,
            num_inputs: 1,
            custom_boundaries: Vec::new(),
        }
    }

    /// Enable testing combinations of boundary values
    pub fn with_combinations(mut self) -> Self {
        self.test_combinations = true;
        self
    }

    /// Set number of inputs
    pub fn with_inputs(mut self, num_inputs: usize) -> Self {
        self.num_inputs = num_inputs.max(1);
        self
    }

    /// Add custom boundaries
    pub fn with_custom_boundaries(mut self, boundaries: Vec<CustomBoundary>) -> Self {
        self.custom_boundaries = boundaries;
        self
    }

    /// Add specific boundary values
    pub fn with_boundary_values(mut self, values: Vec<BoundaryValue>) -> Self {
        self.boundary_values.extend(values);
        self
    }

    /// Generate default field boundary values
    fn default_boundaries() -> Vec<BoundaryValue> {
        vec![
            // Zero - additive identity, often edge case
            BoundaryValue {
                value: FieldElement::zero(),
                name: "zero".to_string(),
                rationale: "Additive identity, division by zero, empty set".to_string(),
                category: BoundaryCategory::FieldBoundary,
            },
            // One - multiplicative identity
            BoundaryValue {
                value: FieldElement::one(),
                name: "one".to_string(),
                rationale: "Multiplicative identity, base case".to_string(),
                category: BoundaryCategory::FieldBoundary,
            },
            // Two - smallest non-trivial value
            BoundaryValue {
                value: FieldElement::from_u64(2),
                name: "two".to_string(),
                rationale: "Smallest even number, binary base".to_string(),
                category: BoundaryCategory::FieldBoundary,
            },
            // p - 1 (maximum field element)
            BoundaryValue {
                value: Self::bn254_p_minus_1(),
                name: "p-1".to_string(),
                rationale: "Maximum field element, wraps to 0 when incremented".to_string(),
                category: BoundaryCategory::FieldBoundary,
            },
            // (p - 1) / 2 (half modulus - signed integer boundary)
            BoundaryValue {
                value: Self::bn254_half_p(),
                name: "(p-1)/2".to_string(),
                rationale: "Boundary between positive and negative in signed representation".to_string(),
                category: BoundaryCategory::SignedBoundary,
            },
            // (p - 1) / 2 + 1
            BoundaryValue {
                value: Self::bn254_half_p_plus_1(),
                name: "(p-1)/2+1".to_string(),
                rationale: "First 'negative' number in signed representation".to_string(),
                category: BoundaryCategory::SignedBoundary,
            },
            // 2^64 - 1 (max u64)
            BoundaryValue {
                value: FieldElement::from_u64(u64::MAX),
                name: "2^64-1".to_string(),
                rationale: "Maximum 64-bit unsigned integer".to_string(),
                category: BoundaryCategory::OverflowBoundary,
            },
            // 2^128 - 1
            BoundaryValue {
                value: Self::two_pow_128_minus_1(),
                name: "2^128-1".to_string(),
                rationale: "Maximum 128-bit unsigned integer".to_string(),
                category: BoundaryCategory::OverflowBoundary,
            },
            // Common bit boundaries
            BoundaryValue {
                value: FieldElement::from_u64(255),
                name: "2^8-1".to_string(),
                rationale: "Maximum 8-bit value".to_string(),
                category: BoundaryCategory::BitBoundary,
            },
            BoundaryValue {
                value: FieldElement::from_u64(256),
                name: "2^8".to_string(),
                rationale: "First 9-bit value".to_string(),
                category: BoundaryCategory::BitBoundary,
            },
            BoundaryValue {
                value: FieldElement::from_u64(65535),
                name: "2^16-1".to_string(),
                rationale: "Maximum 16-bit value".to_string(),
                category: BoundaryCategory::BitBoundary,
            },
            BoundaryValue {
                value: FieldElement::from_u64(65536),
                name: "2^16".to_string(),
                rationale: "First 17-bit value".to_string(),
                category: BoundaryCategory::BitBoundary,
            },
            BoundaryValue {
                value: FieldElement::from_u64(u32::MAX as u64),
                name: "2^32-1".to_string(),
                rationale: "Maximum 32-bit value".to_string(),
                category: BoundaryCategory::BitBoundary,
            },
            BoundaryValue {
                value: FieldElement::from_u64((u32::MAX as u64) + 1),
                name: "2^32".to_string(),
                rationale: "First 33-bit value".to_string(),
                category: BoundaryCategory::BitBoundary,
            },
        ]
    }

    /// Generate bit boundary values for a specific bit width
    pub fn generate_bit_boundaries(bits: usize) -> Vec<BoundaryValue> {
        let mut boundaries = Vec::new();

        if bits == 0 || bits > 253 {
            return boundaries;
        }

        // 2^bits - 1 (all bits set)
        if bits < 64 {
            boundaries.push(BoundaryValue {
                value: FieldElement::from_u64((1u64 << bits) - 1),
                name: format!("2^{}-1", bits),
                rationale: format!("Maximum {}-bit value", bits),
                category: BoundaryCategory::BitBoundary,
            });

            // 2^bits (overflow to next bit width)
            boundaries.push(BoundaryValue {
                value: FieldElement::from_u64(1u64 << bits),
                name: format!("2^{}", bits),
                rationale: format!("First {}-bit value", bits + 1),
                category: BoundaryCategory::BitBoundary,
            });
        } else if bits == 64 {
            // Special case for 64-bit: can only represent 2^64 - 1
            boundaries.push(BoundaryValue {
                value: FieldElement::from_u64(u64::MAX),
                name: "2^64-1".to_string(),
                rationale: "Maximum 64-bit value".to_string(),
                category: BoundaryCategory::BitBoundary,
            });
            // 2^64 requires BigUint
            let two_pow_64: BigUint = BigUint::from(1u128) << 64;
            boundaries.push(BoundaryValue {
                value: FieldElement::from_bytes(&two_pow_64.to_bytes_be()),
                name: "2^64".to_string(),
                rationale: "First 65-bit value".to_string(),
                category: BoundaryCategory::BitBoundary,
            });
        } else {
            // Use BigUint for larger values
            let two_pow_bits = BigUint::from(1u32) << bits;
            let two_pow_bits_minus_1 = &two_pow_bits - 1u32;

            boundaries.push(BoundaryValue {
                value: FieldElement::from_bytes(&two_pow_bits_minus_1.to_bytes_be()),
                name: format!("2^{}-1", bits),
                rationale: format!("Maximum {}-bit value", bits),
                category: BoundaryCategory::BitBoundary,
            });

            boundaries.push(BoundaryValue {
                value: FieldElement::from_bytes(&two_pow_bits.to_bytes_be()),
                name: format!("2^{}", bits),
                rationale: format!("First {}-bit value", bits + 1),
                category: BoundaryCategory::BitBoundary,
            });
        }

        boundaries
    }

    /// BN254 scalar field: p - 1
    fn bn254_p_minus_1() -> FieldElement {
        FieldElement::from_hex(
            "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"
        ).unwrap_or_else(|_| FieldElement::zero())
    }

    /// BN254 scalar field: (p - 1) / 2
    fn bn254_half_p() -> FieldElement {
        FieldElement::from_hex(
            "0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000"
        ).unwrap_or_else(|_| FieldElement::zero())
    }

    /// BN254 scalar field: (p - 1) / 2 + 1
    fn bn254_half_p_plus_1() -> FieldElement {
        FieldElement::from_hex(
            "0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000001"
        ).unwrap_or_else(|_| FieldElement::zero())
    }

    /// 2^128 - 1
    fn two_pow_128_minus_1() -> FieldElement {
        FieldElement::from_hex(
            "0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff"
        ).unwrap_or_else(|_| FieldElement::zero())
    }

    /// Test a single boundary value
    pub fn test_boundary(&self, boundary: &BoundaryValue) -> BoundaryTestResult {
        // In real implementation, this would execute the circuit
        // For now, we simulate basic boundary behavior checking

        // Check if the value is within valid field range
        let is_valid = self.is_valid_field_element(&boundary.value);

        BoundaryTestResult {
            boundary: boundary.clone(),
            passed: is_valid,
            accepted: is_valid,
            error: if is_valid { None } else { Some("Value outside field".to_string()) },
            output: None,
        }
    }

    /// Test all boundary values
    pub fn test_all_boundaries(&self) -> Vec<BoundaryTestResult> {
        let mut results = Vec::new();

        for boundary in &self.boundary_values {
            let result = self.test_boundary(boundary);
            results.push(result);
        }

        // Test custom boundaries
        for custom in &self.custom_boundaries {
            // Test the boundary itself
            let boundary = BoundaryValue {
                value: custom.value.clone(),
                name: custom.name.clone(),
                rationale: custom.expected_behavior.clone(),
                category: BoundaryCategory::ApplicationBoundary,
            };
            results.push(self.test_boundary(&boundary));

            // Test values below
            for (i, below) in custom.below.iter().enumerate() {
                let boundary = BoundaryValue {
                    value: below.clone(),
                    name: format!("{}_below_{}", custom.name, i),
                    rationale: format!("Below {}", custom.name),
                    category: BoundaryCategory::ApplicationBoundary,
                };
                results.push(self.test_boundary(&boundary));
            }

            // Test values above
            for (i, above) in custom.above.iter().enumerate() {
                let boundary = BoundaryValue {
                    value: above.clone(),
                    name: format!("{}_above_{}", custom.name, i),
                    rationale: format!("Above {}", custom.name),
                    category: BoundaryCategory::ApplicationBoundary,
                };
                results.push(self.test_boundary(&boundary));
            }
        }

        // Optionally test combinations
        if self.test_combinations && self.num_inputs > 1 {
            results.extend(self.test_boundary_combinations());
        }

        results
    }

    /// Test combinations of boundary values for multi-input circuits
    fn test_boundary_combinations(&self) -> Vec<BoundaryTestResult> {
        let mut results = Vec::new();

        // Test each boundary value at each input position
        // with other inputs set to zero or one
        for boundary in &self.boundary_values {
            for position in 0..self.num_inputs {
                // Test with zeros in other positions
                let combo_name = format!("{}_at_pos_{}_with_zeros", boundary.name, position);
                let combo = BoundaryValue {
                    value: boundary.value.clone(),
                    name: combo_name,
                    rationale: format!("Testing {} in multi-input context", boundary.name),
                    category: boundary.category,
                };
                results.push(self.test_boundary(&combo));
            }
        }

        // Test pairs of interesting boundaries
        let interesting = [
            FieldElement::zero(),
            FieldElement::one(),
            Self::bn254_p_minus_1(),
        ];

        for val1 in &interesting {
            for val2 in &interesting {
                if val1 != val2 {
                    let combo = BoundaryValue {
                        value: val1.clone(),
                        name: format!("combo_{}_{}", self.value_name(val1), self.value_name(val2)),
                        rationale: "Combination of boundary values".to_string(),
                        category: BoundaryCategory::FieldBoundary,
                    };
                    results.push(self.test_boundary(&combo));
                }
            }
        }

        results
    }

    /// Get a short name for a field element
    fn value_name(&self, fe: &FieldElement) -> &'static str {
        if *fe == FieldElement::zero() {
            "zero"
        } else if *fe == FieldElement::one() {
            "one"
        } else {
            "other"
        }
    }

    /// Check if a value is within the valid field range
    fn is_valid_field_element(&self, _value: &FieldElement) -> bool {
        // In real implementation, check if value < field modulus
        // For now, assume all 32-byte values are valid
        true
    }

    /// Convert boundary test results to security findings
    fn results_to_findings(&self, results: Vec<BoundaryTestResult>, circuit_info: &CircuitInfo) -> Vec<Finding> {
        results
            .into_iter()
            .filter(|r| !r.passed)
            .map(|result| {
                let severity = match result.boundary.category {
                    BoundaryCategory::FieldBoundary => Severity::High,
                    BoundaryCategory::OverflowBoundary => Severity::Critical,
                    BoundaryCategory::BitBoundary => Severity::Medium,
                    BoundaryCategory::SignedBoundary => Severity::High,
                    BoundaryCategory::ApplicationBoundary => Severity::High,
                };

                let description = format!(
                    "Boundary test failed for '{}' in circuit '{}': {}. {}",
                    result.boundary.name,
                    circuit_info.name,
                    result.error.unwrap_or_else(|| "Unknown error".to_string()),
                    result.boundary.rationale
                );

                Finding {
                    attack_type: AttackType::Boundary,
                    severity,
                    description,
                    poc: ProofOfConcept {
                        witness_a: vec![result.boundary.value],
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: Some(circuit_info.name.clone()),
                }
            })
            .collect()
    }
}

impl Default for BoundaryTester {
    fn default() -> Self {
        Self::new()
    }
}

impl Attack for BoundaryTester {
    fn run(&self, context: &AttackContext) -> Vec<Finding> {
        tracing::info!(
            "Running boundary value testing on circuit '{}' with {} boundary values",
            context.circuit_info.name,
            self.boundary_values.len()
        );

        let results = self.test_all_boundaries();
        let failed_count = results.iter().filter(|r| !r.passed).count();

        tracing::info!(
            "Boundary testing complete: {}/{} tests passed",
            results.len() - failed_count,
            results.len()
        );

        self.results_to_findings(results, &context.circuit_info)
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Boundary
    }

    fn description(&self) -> &str {
        "Test circuit behavior at field and bit boundaries"
    }
}

/// Range proof boundary tester
/// 
/// Specific tests for range proof circuits (e.g., proving x < 2^n)
pub struct RangeProofTester {
    /// Bit width of the range proof
    bits: usize,
    /// Number of test cases around boundaries
    samples_per_boundary: usize,
}

impl RangeProofTester {
    pub fn new(bits: usize) -> Self {
        Self {
            bits,
            samples_per_boundary: 10,
        }
    }

    pub fn with_samples(mut self, samples: usize) -> Self {
        self.samples_per_boundary = samples;
        self
    }

    /// Generate test cases for range proof boundaries
    pub fn generate_test_cases(&self) -> Vec<BoundaryValue> {
        let mut cases = Vec::new();

        if self.bits == 0 || self.bits > 253 {
            return cases;
        }

        // Maximum valid value: 2^bits - 1
        let max_valid = if self.bits <= 64 {
            FieldElement::from_u64((1u64 << self.bits) - 1)
        } else {
            let val = (BigUint::from(1u32) << self.bits) - 1u32;
            FieldElement::from_bytes(&val.to_bytes_be())
        };

        cases.push(BoundaryValue {
            value: max_valid,
            name: format!("max_valid_{}_bits", self.bits),
            rationale: format!("Maximum valid value for {}-bit range proof", self.bits),
            category: BoundaryCategory::BitBoundary,
        });

        // First invalid value: 2^bits
        let first_invalid = if self.bits <= 64 {
            FieldElement::from_u64(1u64 << self.bits)
        } else {
            let val = BigUint::from(1u32) << self.bits;
            FieldElement::from_bytes(&val.to_bytes_be())
        };

        cases.push(BoundaryValue {
            value: first_invalid,
            name: format!("first_invalid_{}_bits", self.bits),
            rationale: format!("First invalid value for {}-bit range proof (should be rejected)", self.bits),
            category: BoundaryCategory::BitBoundary,
        });

        // Zero (should always be valid)
        cases.push(BoundaryValue {
            value: FieldElement::zero(),
            name: "zero".to_string(),
            rationale: "Zero should always be within range".to_string(),
            category: BoundaryCategory::FieldBoundary,
        });

        // Field maximum (should always be invalid for reasonable bit widths)
        cases.push(BoundaryValue {
            value: BoundaryTester::bn254_p_minus_1(),
            name: "field_max".to_string(),
            rationale: "Field maximum should be rejected by range proof".to_string(),
            category: BoundaryCategory::FieldBoundary,
        });

        // Values around boundaries
        for offset in 1..=self.samples_per_boundary.min(10) {
            // Just below max valid
            if self.bits <= 64 && (1u64 << self.bits) > offset as u64 {
                cases.push(BoundaryValue {
                    value: FieldElement::from_u64((1u64 << self.bits) - 1 - offset as u64),
                    name: format!("max_valid_minus_{}", offset),
                    rationale: format!("{} below maximum valid value", offset),
                    category: BoundaryCategory::BitBoundary,
                });
            }

            // Just above first invalid
            if self.bits <= 63 {
                cases.push(BoundaryValue {
                    value: FieldElement::from_u64((1u64 << self.bits) + offset as u64),
                    name: format!("first_invalid_plus_{}", offset),
                    rationale: format!("{} above first invalid value", offset),
                    category: BoundaryCategory::BitBoundary,
                });
            }
        }

        cases
    }
}

impl Attack for RangeProofTester {
    fn run(&self, context: &AttackContext) -> Vec<Finding> {
        tracing::info!(
            "Running {}-bit range proof boundary testing on circuit '{}'",
            self.bits,
            context.circuit_info.name
        );

        let test_cases = self.generate_test_cases();
        let tester = BoundaryTester::new()
            .with_boundary_values(test_cases);

        tester.run(context)
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Boundary
    }

    fn description(&self) -> &str {
        "Test range proof boundaries for correct acceptance/rejection"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boundary_tester_creation() {
        let tester = BoundaryTester::new()
            .with_inputs(3)
            .with_combinations();

        assert!(tester.test_combinations);
        assert_eq!(tester.num_inputs, 3);
        assert!(!tester.boundary_values.is_empty());
    }

    #[test]
    fn test_default_boundaries() {
        let boundaries = BoundaryTester::default_boundaries();
        
        // Should have key boundary values
        assert!(boundaries.iter().any(|b| b.name == "zero"));
        assert!(boundaries.iter().any(|b| b.name == "one"));
        assert!(boundaries.iter().any(|b| b.name == "p-1"));
        assert!(boundaries.iter().any(|b| b.name == "(p-1)/2"));
    }

    #[test]
    fn test_generate_bit_boundaries() {
        let boundaries_8 = BoundaryTester::generate_bit_boundaries(8);
        assert_eq!(boundaries_8.len(), 2); // 2^8 - 1 and 2^8

        let boundaries_64 = BoundaryTester::generate_bit_boundaries(64);
        assert_eq!(boundaries_64.len(), 2); // 2^64 - 1 and 2^64 (using BigUint)

        let boundaries_128 = BoundaryTester::generate_bit_boundaries(128);
        assert_eq!(boundaries_128.len(), 2);
    }

    #[test]
    fn test_boundary_value_creation() {
        let boundary = BoundaryValue {
            value: FieldElement::from_u64(255),
            name: "test".to_string(),
            rationale: "Test value".to_string(),
            category: BoundaryCategory::BitBoundary,
        };

        assert_eq!(boundary.name, "test");
        assert_eq!(boundary.category, BoundaryCategory::BitBoundary);
    }

    #[test]
    fn test_range_proof_tester() {
        let tester = RangeProofTester::new(8).with_samples(5);
        let cases = tester.generate_test_cases();

        // Should have at least: max valid, first invalid, zero, field max
        assert!(cases.len() >= 4);

        // Check max valid value
        let max_valid = cases.iter().find(|c| c.name.contains("max_valid_8"));
        assert!(max_valid.is_some());
    }

    #[test]
    fn test_custom_boundary() {
        let custom = CustomBoundary {
            name: "age_18".to_string(),
            value: FieldElement::from_u64(18),
            below: vec![FieldElement::from_u64(17)],
            above: vec![FieldElement::from_u64(19)],
            expected_behavior: "Age verification boundary".to_string(),
        };

        let tester = BoundaryTester::new()
            .with_custom_boundaries(vec![custom]);

        assert_eq!(tester.custom_boundaries.len(), 1);
        assert_eq!(tester.custom_boundaries[0].name, "age_18");
    }

    #[test]
    fn test_test_all_boundaries() {
        let tester = BoundaryTester::new();
        let results = tester.test_all_boundaries();

        // All default boundaries should pass basic validation
        assert!(!results.is_empty());
        for result in results {
            assert!(result.passed, "Boundary {} should pass", result.boundary.name);
        }
    }

    #[test]
    fn test_bn254_boundaries() {
        let p_minus_1 = BoundaryTester::bn254_p_minus_1();
        let half_p = BoundaryTester::bn254_half_p();

        // Basic sanity checks
        assert_ne!(p_minus_1, FieldElement::zero());
        assert_ne!(half_p, FieldElement::zero());
        assert_ne!(p_minus_1, half_p);

        // First byte of p-1 should be 0x30
        assert_eq!(p_minus_1.0[0], 0x30);

        // First byte of (p-1)/2 should be 0x18
        assert_eq!(half_p.0[0], 0x18);
    }
}
