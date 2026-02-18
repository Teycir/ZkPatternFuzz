//! Near-Miss Detection
//!
//! Detects when an oracle is "almost" triggered, indicating promising
//! mutation directions. Near-misses are used by the adaptive scheduler
//! to prioritize attacks and suggest interesting values.
//!
//! # Types of Near-Misses
//!
//! - **Almost out of range**: Value is close to boundary
//! - **Almost collision**: Hash outputs have high similarity
//! - **Almost invariant violation**: Assertion is close to failing
//! - **Almost constraint bypass**: Constraint is barely satisfied
//!
//! # Example
//!
//! ```rust,ignore
//! use zk_fuzzer::fuzzer::near_miss::NearMissDetector;
//!
//! let detector = NearMissDetector::new()
//!     .with_range_threshold(0.1)
//!     .with_collision_threshold(0.9);
//!
//! let near_misses = detector.detect(&result, &expected);
//! ```

use std::collections::HashMap;
use zk_core::FieldElement;

/// Configuration for near-miss detection
#[derive(Debug, Clone)]
pub struct NearMissConfig {
    /// Threshold for range near-miss (fraction of range)
    pub range_threshold: f64,
    /// Threshold for collision near-miss (Hamming similarity)
    pub collision_threshold: f64,
    /// Threshold for invariant near-miss (relative difference)
    pub invariant_threshold: f64,
    /// Threshold for constraint near-miss
    pub constraint_threshold: f64,
}

impl Default for NearMissConfig {
    fn default() -> Self {
        Self {
            range_threshold: 0.05,       // Within 5% of boundary
            collision_threshold: 0.9,    // 90% similar bits
            invariant_threshold: 0.01,   // Within 1% of violation
            constraint_threshold: 0.001, // Very close to zero
        }
    }
}

/// A detected near-miss
#[derive(Debug, Clone)]
pub struct NearMiss {
    /// Type of near-miss
    pub miss_type: NearMissType,
    /// Distance to triggering (0.0 = triggered, 1.0 = far)
    pub distance: f64,
    /// Wire or constraint index involved
    pub location: Option<usize>,
    /// Value that caused the near-miss
    pub value: Option<FieldElement>,
    /// Suggested mutation to trigger
    pub suggestion: Option<String>,
}

impl NearMiss {
    /// Check if this is a "close" near-miss
    pub fn is_close(&self) -> bool {
        self.distance < 0.1
    }

    /// Convert to the adaptive scheduler's NearMissEvent
    pub fn to_event(&self) -> super::adaptive_attack_scheduler::NearMissEvent {
        super::adaptive_attack_scheduler::NearMissEvent {
            event_type: match &self.miss_type {
                NearMissType::AlmostOutOfRange { .. } => {
                    super::adaptive_attack_scheduler::NearMissType::AlmostOutOfRange
                }
                NearMissType::AlmostCollision { .. } => {
                    super::adaptive_attack_scheduler::NearMissType::AlmostCollision
                }
                NearMissType::AlmostInvariantViolation { .. } => {
                    super::adaptive_attack_scheduler::NearMissType::AlmostInvariantViolation
                }
                NearMissType::AlmostConstraintBypass => {
                    super::adaptive_attack_scheduler::NearMissType::AlmostConstraintBypass
                }
            },
            distance: self.distance,
            description: match self.suggestion.clone() {
                Some(value) => value,
                None => format!("{:?}", self.miss_type),
            },
        }
    }
}

/// Types of near-misses
#[derive(Debug, Clone)]
pub enum NearMissType {
    /// Value is close to range boundary
    AlmostOutOfRange {
        value: FieldElement,
        boundary: FieldElement,
        is_upper: bool,
    },
    /// Hash outputs are very similar
    AlmostCollision {
        hash_a: Vec<u8>,
        hash_b: Vec<u8>,
        hamming_similarity: f64,
    },
    /// Invariant assertion is close to failing
    AlmostInvariantViolation {
        expected: FieldElement,
        actual: FieldElement,
        invariant_name: Option<String>,
    },
    /// Constraint evaluation is very close to zero
    AlmostConstraintBypass,
}

/// Near-miss detector
pub struct NearMissDetector {
    config: NearMissConfig,
    /// Known range constraints
    range_constraints: HashMap<usize, RangeConstraint>,
    /// Known invariants
    invariants: Vec<InvariantSpec>,
}

/// A range constraint for a wire
#[derive(Debug, Clone)]
pub struct RangeConstraint {
    pub wire_index: usize,
    pub min_value: Option<FieldElement>,
    pub max_value: Option<FieldElement>,
    pub bit_length: Option<usize>,
}

/// An invariant specification
#[derive(Debug, Clone)]
pub struct InvariantSpec {
    pub name: String,
    pub expected_wire: usize,
    pub actual_wire: usize,
}

impl Default for NearMissDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl NearMissDetector {
    /// Create a new near-miss detector
    pub fn new() -> Self {
        Self {
            config: NearMissConfig::default(),
            range_constraints: HashMap::new(),
            invariants: Vec::new(),
        }
    }

    /// Set configuration
    pub fn with_config(mut self, config: NearMissConfig) -> Self {
        self.config = config;
        self
    }

    /// Add a range constraint
    pub fn with_range_constraint(mut self, constraint: RangeConstraint) -> Self {
        self.range_constraints
            .insert(constraint.wire_index, constraint);
        self
    }

    /// Add an invariant
    pub fn with_invariant(mut self, spec: InvariantSpec) -> Self {
        self.invariants.push(spec);
        self
    }

    /// Detect near-misses in a witness
    pub fn detect(&self, witness: &[FieldElement]) -> Vec<NearMiss> {
        let mut near_misses = Vec::new();

        // Check range constraints
        for (wire_idx, constraint) in &self.range_constraints {
            if let Some(value) = witness.get(*wire_idx) {
                if let Some(nm) = self.check_range_near_miss(value, constraint) {
                    near_misses.push(nm);
                }
            }
        }

        // Check invariants
        for invariant in &self.invariants {
            let expected = witness.get(invariant.expected_wire);
            let actual = witness.get(invariant.actual_wire);

            if let (Some(exp), Some(act)) = (expected, actual) {
                if let Some(nm) = self.check_invariant_near_miss(exp, act, &invariant.name) {
                    near_misses.push(nm);
                }
            }
        }

        near_misses
    }

    /// Check for range near-miss
    fn check_range_near_miss(
        &self,
        value: &FieldElement,
        constraint: &RangeConstraint,
    ) -> Option<NearMiss> {
        // Check against min value
        if let Some(ref min_val) = constraint.min_value {
            let diff = self.field_difference(value, min_val);
            if diff < self.config.range_threshold {
                return Some(NearMiss {
                    miss_type: NearMissType::AlmostOutOfRange {
                        value: value.clone(),
                        boundary: min_val.clone(),
                        is_upper: false,
                    },
                    distance: diff,
                    location: Some(constraint.wire_index),
                    value: Some(value.clone()),
                    suggestion: Some(format!("Value is {:.3}% from min boundary", diff * 100.0)),
                });
            }
        }

        // Check against bit length
        if let Some(bit_length) = constraint.bit_length {
            let max_value = if bit_length < 64 {
                (1u64 << bit_length) - 1
            } else {
                u64::MAX
            };

            if let Some(val_u64) = value.to_u64() {
                let distance_from_max = if val_u64 >= max_value {
                    0.0
                } else {
                    (max_value - val_u64) as f64 / max_value as f64
                };

                if distance_from_max < self.config.range_threshold {
                    return Some(NearMiss {
                        miss_type: NearMissType::AlmostOutOfRange {
                            value: value.clone(),
                            boundary: FieldElement::from_u64(max_value),
                            is_upper: true,
                        },
                        distance: distance_from_max,
                        location: Some(constraint.wire_index),
                        value: Some(value.clone()),
                        suggestion: Some(format!(
                            "Try value >= 2^{} (currently {:.1}% from boundary)",
                            bit_length,
                            distance_from_max * 100.0
                        )),
                    });
                }
            }
        }

        // Check against explicit max
        if let Some(ref max_val) = constraint.max_value {
            let diff = self.field_difference(value, max_val);
            if diff < self.config.range_threshold {
                return Some(NearMiss {
                    miss_type: NearMissType::AlmostOutOfRange {
                        value: value.clone(),
                        boundary: max_val.clone(),
                        is_upper: true,
                    },
                    distance: diff,
                    location: Some(constraint.wire_index),
                    value: Some(value.clone()),
                    suggestion: Some(format!("Value is {:.3}% from max boundary", diff * 100.0)),
                });
            }
        }

        None
    }

    /// Check for invariant near-miss
    fn check_invariant_near_miss(
        &self,
        expected: &FieldElement,
        actual: &FieldElement,
        name: &str,
    ) -> Option<NearMiss> {
        if expected == actual {
            return None; // Invariant holds, no near-miss
        }

        let diff = self.field_difference(expected, actual);

        if diff < self.config.invariant_threshold {
            return Some(NearMiss {
                miss_type: NearMissType::AlmostInvariantViolation {
                    expected: expected.clone(),
                    actual: actual.clone(),
                    invariant_name: Some(name.to_string()),
                },
                distance: diff,
                location: None,
                value: Some(actual.clone()),
                suggestion: Some(format!(
                    "Invariant '{}' is {:.3}% from violation",
                    name,
                    diff * 100.0
                )),
            });
        }

        None
    }

    /// Calculate relative difference between field elements using arithmetic distance
    fn field_difference(&self, a: &FieldElement, b: &FieldElement) -> f64 {
        let a_u64 = a.to_u64().unwrap_or(0);
        let b_u64 = b.to_u64().unwrap_or(0);
        
        if a_u64 == b_u64 {
            return 0.0;
        }
        
        let diff = a_u64.abs_diff(b_u64) as f64;
        let max_val = a_u64.max(b_u64).max(1) as f64;
        diff / max_val
    }

    /// Detect collision near-miss between two hashes
    pub fn check_collision_near_miss(&self, hash_a: &[u8], hash_b: &[u8]) -> Option<NearMiss> {
        if hash_a.len() != hash_b.len() {
            return None;
        }

        let total_bits = hash_a.len() * 8;
        let matching_bits: usize = hash_a
            .iter()
            .zip(hash_b.iter())
            .map(|(a, b)| (!(a ^ b)).count_ones() as usize)
            .sum();

        let similarity = matching_bits as f64 / total_bits as f64;

        if similarity >= self.config.collision_threshold {
            return Some(NearMiss {
                miss_type: NearMissType::AlmostCollision {
                    hash_a: hash_a.to_vec(),
                    hash_b: hash_b.to_vec(),
                    hamming_similarity: similarity,
                },
                distance: 1.0 - similarity,
                location: None,
                value: None,
                suggestion: Some(format!(
                    "Hashes are {:.1}% similar (collision at 100%)",
                    similarity * 100.0
                )),
            });
        }

        None
    }

    /// Detect near-misses from constraint evaluation
    pub fn check_constraint_near_miss(&self, result: &FieldElement) -> Option<NearMiss> {
        // Constraint should evaluate to zero; check if very close
        if let Some(val) = result.to_u64() {
            if val == 0 {
                return None; // Constraint satisfied
            }

            // Check if close to zero (as fraction of field)
            let distance = val as f64 / (1u64 << 63) as f64;

            if distance < self.config.constraint_threshold {
                return Some(NearMiss {
                    miss_type: NearMissType::AlmostConstraintBypass,
                    distance,
                    location: None,
                    value: Some(result.clone()),
                    suggestion: Some(format!("Constraint evaluation is {:.6} (should be 0)", val)),
                });
            }
        }

        None
    }
}

/// Statistics from near-miss detection
#[derive(Debug, Clone, Default)]
pub struct NearMissStats {
    pub total_detected: usize,
    pub close_misses: usize,
    pub by_type: HashMap<String, usize>,
}

impl NearMissDetector {
    /// Compute statistics from near-misses
    pub fn stats(&self, near_misses: &[NearMiss]) -> NearMissStats {
        let mut by_type: HashMap<String, usize> = HashMap::new();

        for nm in near_misses {
            let type_name = match &nm.miss_type {
                NearMissType::AlmostOutOfRange { .. } => "range",
                NearMissType::AlmostCollision { .. } => "collision",
                NearMissType::AlmostInvariantViolation { .. } => "invariant",
                NearMissType::AlmostConstraintBypass => "constraint",
            };
            *by_type.entry(type_name.to_string()).or_insert(0) += 1;
        }

        NearMissStats {
            total_detected: near_misses.len(),
            close_misses: near_misses.iter().filter(|nm| nm.is_close()).count(),
            by_type,
        }
    }
}

#[cfg(test)]
#[path = "near_miss_tests.rs"]
mod tests;
