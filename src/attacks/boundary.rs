//! Boundary Value Testing for ZK Circuits
//!
//! Implements systematic boundary value analysis to test circuit behavior at:
//! - Field element boundaries (0, 1, p-1, p, etc.)
//! - Bit boundaries (2^n - 1, 2^n, 2^n + 1)
//! - Application-specific boundaries (range proofs, age verification, etc.)
//! - Type transition boundaries
//! - Overflow/underflow detection
//!
//! # Theory
//!
//! Boundary value analysis is particularly important in ZK circuits because:
//! 1. Field arithmetic wraps around at the modulus p
//! 2. Range checks may be missing or incorrectly implemented
//! 3. Bit decomposition constraints may not cover edge cases
//! 4. Integer operations may overflow without proper checks
//!
//! # Usage
//!
//! ```ignore
//! let tester = BoundaryTester::new()
//!     .with_field_boundaries(true)
//!     .with_bit_boundaries(vec![8, 16, 32, 64, 128, 253])
//!     .with_overflow_detection(true)
//!     .with_range_testing(0, 1000);
//!
//! let findings = tester.run(&context);
//! ```

use super::{Attack, AttackContext};
use crate::config::{AttackType, Severity};
use crate::fuzzer::{FieldElement, Finding, ProofOfConcept, bn254_modulus_bytes};
use num_bigint::BigUint;
use std::collections::HashMap;

/// Boundary value categories for organized testing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoundaryCategory {
    /// Field element boundaries (0, 1, p-1, p)
    FieldElement,
    /// Bit-level boundaries (2^n - 1, 2^n, 2^n + 1)
    BitBoundary,
    /// Common integer ranges (u8, u16, u32, u64 max values)
    IntegerRange,
    /// Application-specific ranges (age, balance, etc.)
    ApplicationRange,
    /// Sign boundary around (p-1)/2
    SignBoundary,
    /// Zero and near-zero values
    NearZero,
    /// Values near field modulus
    NearModulus,
}

/// Result of a single boundary test
#[derive(Debug, Clone)]
pub struct BoundaryTestResult {
    /// The boundary value tested
    pub value: FieldElement,
    /// Human-readable description of this boundary
    pub description: String,
    /// Category of this boundary test
    pub category: BoundaryCategory,
    /// Whether the circuit accepted this input
    pub accepted: bool,
    /// Whether acceptance was expected
    pub expected_acceptance: Option<bool>,
    /// Any anomaly detected (unexpected behavior, errors, etc.)
    pub anomaly: Option<String>,
}

/// Summary of boundary testing campaign
#[derive(Debug, Clone, Default)]
pub struct BoundaryTestSummary {
    /// Total tests run
    pub total_tests: usize,
    /// Tests where circuit accepted input
    pub accepted_count: usize,
    /// Tests where circuit rejected input
    pub rejected_count: usize,
    /// Tests with anomalies
    pub anomaly_count: usize,
    /// Tests by category
    pub by_category: HashMap<BoundaryCategory, usize>,
    /// Detected vulnerabilities
    pub vulnerabilities: Vec<BoundaryVulnerability>,
}

/// A boundary-related vulnerability
#[derive(Debug, Clone)]
pub struct BoundaryVulnerability {
    pub category: BoundaryCategory,
    pub severity: Severity,
    pub description: String,
    pub test_value: FieldElement,
    pub expected: String,
    pub actual: String,
}

/// Range specification for application-specific boundary testing
#[derive(Debug, Clone)]
pub struct RangeSpec {
    /// Minimum allowed value
    pub min: BigUint,
    /// Maximum allowed value  
    pub max: BigUint,
    /// Human-readable name for this range
    pub name: String,
}

impl RangeSpec {
    /// Create a new range specification
    pub fn new(name: &str, min: u64, max: u64) -> Self {
        Self {
            min: BigUint::from(min),
            max: BigUint::from(max),
            name: name.to_string(),
        }
    }

    /// Generate boundary test values for this range
    pub fn boundary_values(&self) -> Vec<(FieldElement, String)> {
        let mut values = Vec::new();

        // At minimum
        if let Some(fe) = biguint_to_field_element(&self.min) {
            values.push((fe, format!("{} minimum ({})", self.name, self.min)));
        }

        // Below minimum (if min > 0)
        if self.min > BigUint::from(0u32) {
            let below_min = &self.min - BigUint::from(1u32);
            if let Some(fe) = biguint_to_field_element(&below_min) {
                values.push((fe, format!("{} below minimum ({})", self.name, below_min)));
            }
        }

        // At maximum
        if let Some(fe) = biguint_to_field_element(&self.max) {
            values.push((fe, format!("{} maximum ({})", self.name, self.max)));
        }

        // Above maximum
        let above_max = &self.max + BigUint::from(1u32);
        if let Some(fe) = biguint_to_field_element(&above_max) {
            values.push((fe, format!("{} above maximum ({})", self.name, above_max)));
        }

        // Middle of range
        let mid = (&self.min + &self.max) / BigUint::from(2u32);
        if let Some(fe) = biguint_to_field_element(&mid) {
            values.push((fe, format!("{} middle ({})", self.name, mid)));
        }

        values
    }
}

/// Convert BigUint to FieldElement
fn biguint_to_field_element(value: &BigUint) -> Option<FieldElement> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return None;
    }
    
    let mut result = [0u8; 32];
    let start = 32 - bytes.len();
    result[start..].copy_from_slice(&bytes);
    Some(FieldElement(result))
}

/// Boundary value tester for comprehensive edge case analysis
pub struct BoundaryTester {
    /// Whether to test field element boundaries
    test_field_boundaries: bool,
    /// Bit widths to test boundaries for
    bit_widths: Vec<u32>,
    /// Whether to test integer type boundaries (u8, u16, etc.)
    test_integer_boundaries: bool,
    /// Custom test values (symbolic or numeric)
    custom_values: Vec<String>,
    /// Application-specific ranges to test
    ranges: Vec<RangeSpec>,
    /// Whether to test for overflow/underflow behavior
    test_overflow: bool,
    /// Whether to test sign boundary (p-1)/2
    test_sign_boundary: bool,
    /// Whether to generate arithmetic combinations
    test_arithmetic_combinations: bool,
}

impl Default for BoundaryTester {
    fn default() -> Self {
        Self {
            test_field_boundaries: true,
            bit_widths: vec![8, 16, 32, 64, 128, 252, 253, 254],
            test_integer_boundaries: true,
            custom_values: vec![
                "0".to_string(),
                "1".to_string(),
                "p-1".to_string(),
            ],
            ranges: Vec::new(),
            test_overflow: true,
            test_sign_boundary: true,
            test_arithmetic_combinations: true,
        }
    }
}

impl BoundaryTester {
    /// Create a new boundary tester with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable/disable field element boundary testing
    pub fn with_field_boundaries(mut self, enabled: bool) -> Self {
        self.test_field_boundaries = enabled;
        self
    }

    /// Set bit widths to test
    pub fn with_bit_widths(mut self, widths: Vec<u32>) -> Self {
        self.bit_widths = widths;
        self
    }

    /// Add custom test values
    pub fn with_custom_values(mut self, values: Vec<String>) -> Self {
        self.custom_values = values;
        self
    }

    /// Add application-specific range
    pub fn with_range(mut self, range: RangeSpec) -> Self {
        self.ranges.push(range);
        self
    }

    /// Enable/disable overflow testing
    pub fn with_overflow_testing(mut self, enabled: bool) -> Self {
        self.test_overflow = enabled;
        self
    }

    /// Enable/disable sign boundary testing
    pub fn with_sign_boundary_testing(mut self, enabled: bool) -> Self {
        self.test_sign_boundary = enabled;
        self
    }

    /// Enable/disable arithmetic combination testing
    pub fn with_arithmetic_combinations(mut self, enabled: bool) -> Self {
        self.test_arithmetic_combinations = enabled;
        self
    }

    /// Get all configured test values as strings
    pub fn test_values(&self) -> &[String] {
        &self.custom_values
    }

    /// Generate all boundary test values with descriptions
    pub fn generate_all_test_values(&self) -> Vec<(FieldElement, String, BoundaryCategory)> {
        let mut values = Vec::new();

        // Field element boundaries
        if self.test_field_boundaries {
            values.extend(self.generate_field_boundaries());
        }

        // Bit boundaries for each width
        for &width in &self.bit_widths {
            values.extend(self.generate_bit_boundaries(width));
        }

        // Integer type boundaries
        if self.test_integer_boundaries {
            values.extend(self.generate_integer_boundaries());
        }

        // Sign boundary
        if self.test_sign_boundary {
            values.extend(self.generate_sign_boundaries());
        }

        // Application-specific ranges
        for range in &self.ranges {
            for (fe, desc) in range.boundary_values() {
                values.push((fe, desc, BoundaryCategory::ApplicationRange));
            }
        }

        // Overflow/underflow test values
        if self.test_overflow {
            values.extend(self.generate_overflow_values());
        }

        // Arithmetic combinations (a op b where a, b are boundary values)
        if self.test_arithmetic_combinations {
            values.extend(self.generate_arithmetic_combinations());
        }

        values
    }

    /// Generate field element boundary values
    fn generate_field_boundaries(&self) -> Vec<(FieldElement, String, BoundaryCategory)> {
        let modulus = bn254_modulus_bytes();
        let p = BigUint::from_bytes_be(&modulus);
        
        let mut values = Vec::new();

        // Zero
        values.push((
            FieldElement::zero(),
            "Zero (minimum field element)".to_string(),
            BoundaryCategory::FieldElement,
        ));

        // One
        values.push((
            FieldElement::one(),
            "One".to_string(),
            BoundaryCategory::FieldElement,
        ));

        // Two
        values.push((
            FieldElement::from_u64(2),
            "Two".to_string(),
            BoundaryCategory::FieldElement,
        ));

        // p - 1 (maximum field element)
        let p_minus_1 = &p - BigUint::from(1u32);
        if let Some(fe) = biguint_to_field_element(&p_minus_1) {
            values.push((
                fe,
                "p-1 (maximum field element)".to_string(),
                BoundaryCategory::FieldElement,
            ));
        }

        // p - 2
        let p_minus_2 = &p - BigUint::from(2u32);
        if let Some(fe) = biguint_to_field_element(&p_minus_2) {
            values.push((
                fe,
                "p-2".to_string(),
                BoundaryCategory::FieldElement,
            ));
        }

        // p (should wrap to 0)
        if let Some(fe) = biguint_to_field_element(&p) {
            values.push((
                fe,
                "p (field modulus, should wrap to 0)".to_string(),
                BoundaryCategory::FieldElement,
            ));
        }

        // p + 1 (should wrap to 1)
        let p_plus_1 = &p + BigUint::from(1u32);
        if let Some(fe) = biguint_to_field_element(&p_plus_1) {
            values.push((
                fe,
                "p+1 (should wrap to 1)".to_string(),
                BoundaryCategory::FieldElement,
            ));
        }

        values
    }

    /// Generate bit-width boundary values
    fn generate_bit_boundaries(&self, bits: u32) -> Vec<(FieldElement, String, BoundaryCategory)> {
        let mut values = Vec::new();

        if bits >= 256 {
            return values; // Too large
        }

        // 2^n - 1 (all bits set)
        let all_bits_set = (BigUint::from(1u32) << bits) - BigUint::from(1u32);
        if let Some(fe) = biguint_to_field_element(&all_bits_set) {
            values.push((
                fe,
                format!("2^{} - 1 (all {} bits set)", bits, bits),
                BoundaryCategory::BitBoundary,
            ));
        }

        // 2^n (single bit overflow)
        let power_of_two = BigUint::from(1u32) << bits;
        if let Some(fe) = biguint_to_field_element(&power_of_two) {
            values.push((
                fe,
                format!("2^{} (bit overflow boundary)", bits),
                BoundaryCategory::BitBoundary,
            ));
        }

        // 2^n + 1
        let power_plus_one = (BigUint::from(1u32) << bits) + BigUint::from(1u32);
        if let Some(fe) = biguint_to_field_element(&power_plus_one) {
            values.push((
                fe,
                format!("2^{} + 1", bits),
                BoundaryCategory::BitBoundary,
            ));
        }

        // 2^(n-1) (highest bit set, useful for sign interpretation)
        if bits > 0 {
            let half_power = BigUint::from(1u32) << (bits - 1);
            if let Some(fe) = biguint_to_field_element(&half_power) {
                values.push((
                    fe,
                    format!("2^{} (sign bit for {}-bit)", bits - 1, bits),
                    BoundaryCategory::BitBoundary,
                ));
            }
        }

        values
    }

    /// Generate integer type boundary values
    fn generate_integer_boundaries(&self) -> Vec<(FieldElement, String, BoundaryCategory)> {
        vec![
            // u8 boundaries
            (FieldElement::from_u64(u8::MAX as u64), "u8::MAX (255)".to_string(), BoundaryCategory::IntegerRange),
            (FieldElement::from_u64(256), "u8::MAX + 1 (256)".to_string(), BoundaryCategory::IntegerRange),
            
            // u16 boundaries
            (FieldElement::from_u64(u16::MAX as u64), "u16::MAX (65535)".to_string(), BoundaryCategory::IntegerRange),
            (FieldElement::from_u64(65536), "u16::MAX + 1 (65536)".to_string(), BoundaryCategory::IntegerRange),
            
            // u32 boundaries
            (FieldElement::from_u64(u32::MAX as u64), "u32::MAX".to_string(), BoundaryCategory::IntegerRange),
            (FieldElement::from_u64(u32::MAX as u64 + 1), "u32::MAX + 1".to_string(), BoundaryCategory::IntegerRange),
            
            // u64 boundaries
            (FieldElement::from_u64(u64::MAX), "u64::MAX".to_string(), BoundaryCategory::IntegerRange),
        ]
    }

    /// Generate sign boundary values (around (p-1)/2)
    fn generate_sign_boundaries(&self) -> Vec<(FieldElement, String, BoundaryCategory)> {
        let modulus = bn254_modulus_bytes();
        let p = BigUint::from_bytes_be(&modulus);
        let half = (&p - BigUint::from(1u32)) / BigUint::from(2u32);

        let mut values = Vec::new();

        // (p-1)/2
        if let Some(fe) = biguint_to_field_element(&half) {
            values.push((
                fe,
                "(p-1)/2 (sign boundary)".to_string(),
                BoundaryCategory::SignBoundary,
            ));
        }

        // (p-1)/2 + 1
        let half_plus_1 = &half + BigUint::from(1u32);
        if let Some(fe) = biguint_to_field_element(&half_plus_1) {
            values.push((
                fe,
                "(p-1)/2 + 1 (above sign boundary)".to_string(),
                BoundaryCategory::SignBoundary,
            ));
        }

        // (p-1)/2 - 1
        if half > BigUint::from(0u32) {
            let half_minus_1 = &half - BigUint::from(1u32);
            if let Some(fe) = biguint_to_field_element(&half_minus_1) {
                values.push((
                    fe,
                    "(p-1)/2 - 1 (below sign boundary)".to_string(),
                    BoundaryCategory::SignBoundary,
                ));
            }
        }

        values
    }

    /// Generate overflow/underflow test values
    fn generate_overflow_values(&self) -> Vec<(FieldElement, String, BoundaryCategory)> {
        let modulus = bn254_modulus_bytes();
        let p = BigUint::from_bytes_be(&modulus);
        
        let mut values = Vec::new();

        // Values that cause overflow when added to themselves
        // x + x = 2x, which overflows if x > p/2
        let overflow_point = &p / BigUint::from(2u32) + BigUint::from(1u32);
        if let Some(fe) = biguint_to_field_element(&overflow_point) {
            values.push((
                fe,
                "Overflow point (2x > p)".to_string(),
                BoundaryCategory::NearModulus,
            ));
        }

        // Values near the modulus (last 10 values before p)
        for i in 1u32..=10 {
            let near_p = &p - BigUint::from(i);
            if let Some(fe) = biguint_to_field_element(&near_p) {
                values.push((
                    fe,
                    format!("p - {} (near modulus)", i),
                    BoundaryCategory::NearModulus,
                ));
            }
        }

        // Small values that might underflow
        for i in 0u64..5 {
            values.push((
                FieldElement::from_u64(i),
                format!("Small value {} (potential underflow)", i),
                BoundaryCategory::NearZero,
            ));
        }

        values
    }

    /// Generate arithmetic combinations of boundary values
    fn generate_arithmetic_combinations(&self) -> Vec<(FieldElement, String, BoundaryCategory)> {
        let modulus = bn254_modulus_bytes();
        let p = BigUint::from_bytes_be(&modulus);
        let p_minus_1 = &p - BigUint::from(1u32);
        
        let mut values = Vec::new();

        // (p-1) + 1 = p = 0 (mod p) - addition overflow
        if let Some(fe) = biguint_to_field_element(&p) {
            values.push((
                fe,
                "(p-1) + 1 = 0 (addition wrap)".to_string(),
                BoundaryCategory::NearModulus,
            ));
        }

        // (p-1) + (p-1) = 2p - 2 = p - 2 (mod p)
        let double_max = &p_minus_1 + &p_minus_1;
        let reduced = &double_max % &p;
        if let Some(fe) = biguint_to_field_element(&reduced) {
            values.push((
                fe,
                "(p-1) + (p-1) mod p (double max)".to_string(),
                BoundaryCategory::NearModulus,
            ));
        }

        // (p-1) * (p-1) mod p
        let squared_max = (&p_minus_1 * &p_minus_1) % &p;
        if let Some(fe) = biguint_to_field_element(&squared_max) {
            values.push((
                fe,
                "(p-1)^2 mod p (squared max)".to_string(),
                BoundaryCategory::NearModulus,
            ));
        }

        // Powers of 2 that are close to p
        // Find the largest 2^n < p
        let mut power = BigUint::from(1u32);
        let mut exp = 0u32;
        while &power < &p {
            power <<= 1;
            exp += 1;
        }
        power >>= 1;
        exp -= 1;
        
        if let Some(fe) = biguint_to_field_element(&power) {
            values.push((
                fe,
                format!("2^{} (largest power of 2 < p)", exp),
                BoundaryCategory::BitBoundary,
            ));
        }

        // p - 2^exp (distance from largest power of 2)
        let diff = &p - &power;
        if let Some(fe) = biguint_to_field_element(&diff) {
            values.push((
                fe,
                format!("p - 2^{}", exp),
                BoundaryCategory::NearModulus,
            ));
        }

        values
    }

    /// Check if a circuit properly rejects values outside expected ranges
    pub fn check_range_enforcement(
        &self,
        accepts_value: impl Fn(&FieldElement) -> bool,
        range: &RangeSpec,
    ) -> Vec<BoundaryVulnerability> {
        let mut vulnerabilities = Vec::new();

        for (fe, desc) in range.boundary_values() {
            let value = BigUint::from_bytes_be(&fe.to_bytes());
            let should_accept = value >= range.min && value <= range.max;
            let did_accept = accepts_value(&fe);

            if should_accept != did_accept {
                vulnerabilities.push(BoundaryVulnerability {
                    category: BoundaryCategory::ApplicationRange,
                    severity: if did_accept && !should_accept {
                        Severity::High // Accepting invalid values is more serious
                    } else {
                        Severity::Medium
                    },
                    description: format!(
                        "Range enforcement issue for {}: {}",
                        range.name, desc
                    ),
                    test_value: fe,
                    expected: if should_accept { "accept" } else { "reject" }.to_string(),
                    actual: if did_accept { "accepted" } else { "rejected" }.to_string(),
                });
            }
        }

        vulnerabilities
    }
}

impl Attack for BoundaryTester {
    fn run(&self, context: &AttackContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for circuits that might have boundary issues
        if context.circuit_info.num_constraints < context.circuit_info.num_private_inputs {
            findings.push(Finding {
                attack_type: AttackType::Boundary,
                severity: Severity::Medium,
                description: format!(
                    "Circuit '{}' has fewer constraints ({}) than private inputs ({}) - \
                     boundary checking may be incomplete",
                    context.circuit_info.name,
                    context.circuit_info.num_constraints,
                    context.circuit_info.num_private_inputs
                ),
                poc: ProofOfConcept::default(),
                location: None,
            });
        }

        // Warn about unconstrained degrees of freedom
        let dof = context.circuit_info.degrees_of_freedom();
        if dof > 0 {
            findings.push(Finding {
                attack_type: AttackType::Boundary,
                severity: Severity::Low,
                description: format!(
                    "Circuit '{}' has {} degrees of freedom - some inputs may not be \
                     properly range-checked",
                    context.circuit_info.name,
                    dof
                ),
                poc: ProofOfConcept::default(),
                location: None,
            });
        }

        // Check constraint density
        let density = context.circuit_info.constraint_density();
        if density < 1.0 {
            findings.push(Finding {
                attack_type: AttackType::Boundary,
                severity: Severity::Info,
                description: format!(
                    "Low constraint density ({:.2}) in '{}' - consider adding range checks",
                    density,
                    context.circuit_info.name
                ),
                poc: ProofOfConcept::default(),
                location: None,
            });
        }

        findings
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Boundary
    }

    fn description(&self) -> &str {
        "Test circuit behavior at field element, bit, and application boundaries"
    }
}

/// Common range specifications for ZK applications
pub mod common_ranges {
    use super::RangeSpec;

    /// Standard u8 range (0-255)
    pub fn u8_range() -> RangeSpec {
        RangeSpec::new("u8", 0, 255)
    }

    /// Standard u16 range (0-65535)
    pub fn u16_range() -> RangeSpec {
        RangeSpec::new("u16", 0, 65535)
    }

    /// Standard u32 range
    pub fn u32_range() -> RangeSpec {
        RangeSpec::new("u32", 0, u32::MAX as u64)
    }

    /// Age verification (0-150 years)
    pub fn age_range() -> RangeSpec {
        RangeSpec::new("age", 0, 150)
    }

    /// Percentage (0-100)
    pub fn percentage_range() -> RangeSpec {
        RangeSpec::new("percentage", 0, 100)
    }

    /// Unix timestamp (reasonable range: 2000-2100)
    pub fn timestamp_range() -> RangeSpec {
        RangeSpec::new("timestamp", 946684800, 4102444800)
    }

    /// Ethereum balance in wei (up to 1 billion ETH)
    pub fn eth_balance_range() -> RangeSpec {
        RangeSpec::new("eth_balance", 0, 1_000_000_000 * 10u64.pow(18))
    }

    /// Merkle tree depth (typically 0-32)
    pub fn merkle_depth_range() -> RangeSpec {
        RangeSpec::new("merkle_depth", 0, 32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boundary_tester_default() {
        let tester = BoundaryTester::new();
        assert!(tester.test_field_boundaries);
        assert!(tester.test_overflow);
        assert!(!tester.bit_widths.is_empty());
    }

    #[test]
    fn test_generate_field_boundaries() {
        let tester = BoundaryTester::new();
        let values = tester.generate_field_boundaries();
        
        // Should include 0, 1, p-1, p
        assert!(values.len() >= 4);
        
        // Check zero is included
        assert!(values.iter().any(|(fe, _, _)| *fe == FieldElement::zero()));
        
        // Check one is included
        assert!(values.iter().any(|(fe, _, _)| *fe == FieldElement::one()));
    }

    #[test]
    fn test_generate_bit_boundaries() {
        let tester = BoundaryTester::new();
        let values = tester.generate_bit_boundaries(8);
        
        // Should include 2^8-1=255, 2^8=256, 2^8+1=257, 2^7=128
        assert!(values.len() >= 4);
        
        // Check 255 is included
        let has_255 = values.iter().any(|(fe, _, _)| {
            *fe == FieldElement::from_u64(255)
        });
        assert!(has_255);
    }

    #[test]
    fn test_generate_integer_boundaries() {
        let tester = BoundaryTester::new();
        let values = tester.generate_integer_boundaries();
        
        // Should have u8, u16, u32, u64 boundaries
        assert!(values.len() >= 4);
    }

    #[test]
    fn test_generate_all_test_values() {
        let tester = BoundaryTester::new()
            .with_bit_widths(vec![8, 16]);
        
        let values = tester.generate_all_test_values();
        assert!(!values.is_empty());
        
        // Check we have different categories
        let categories: std::collections::HashSet<_> = values.iter()
            .map(|(_, _, cat)| cat)
            .collect();
        assert!(categories.len() >= 2);
    }

    #[test]
    fn test_range_spec_boundary_values() {
        let range = common_ranges::age_range();
        let values = range.boundary_values();
        
        // Should include min, max, below min, above max, middle
        assert!(values.len() >= 4);
    }

    #[test]
    fn test_biguint_to_field_element() {
        let small = BigUint::from(42u32);
        let fe = biguint_to_field_element(&small).unwrap();
        assert_eq!(fe, FieldElement::from_u64(42));
        
        // Test zero
        let zero = BigUint::from(0u32);
        let fe_zero = biguint_to_field_element(&zero).unwrap();
        assert_eq!(fe_zero, FieldElement::zero());
    }

    #[test]
    fn test_check_range_enforcement() {
        let tester = BoundaryTester::new();
        let range = common_ranges::percentage_range(); // 0-100
        
        // Mock circuit that only accepts values <= 50
        let accepts = |fe: &FieldElement| {
            let bytes = fe.to_bytes();
            let value = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
            value <= 50
        };
        
        let vulnerabilities = tester.check_range_enforcement(accepts, &range);
        
        // Should find vulnerability at max (100) and above max (101)
        // since our mock only accepts <= 50
        assert!(!vulnerabilities.is_empty());
    }

    #[test]
    fn test_common_ranges() {
        assert_eq!(common_ranges::u8_range().max, BigUint::from(255u32));
        assert_eq!(common_ranges::percentage_range().max, BigUint::from(100u32));
        assert_eq!(common_ranges::age_range().max, BigUint::from(150u32));
    }

    #[test]
    fn test_overflow_values() {
        let tester = BoundaryTester::new().with_overflow_testing(true);
        let values = tester.generate_overflow_values();
        
        // Should have near-modulus and near-zero values
        assert!(!values.is_empty());
        
        let has_near_modulus = values.iter()
            .any(|(_, _, cat)| *cat == BoundaryCategory::NearModulus);
        let has_near_zero = values.iter()
            .any(|(_, _, cat)| *cat == BoundaryCategory::NearZero);
        
        assert!(has_near_modulus);
        assert!(has_near_zero);
    }

    #[test]
    fn test_sign_boundaries() {
        let tester = BoundaryTester::new().with_sign_boundary_testing(true);
        let values = tester.generate_sign_boundaries();
        
        // Should have (p-1)/2 and surrounding values
        assert!(values.len() >= 2);
        assert!(values.iter().all(|(_, _, cat)| *cat == BoundaryCategory::SignBoundary));
    }
}
