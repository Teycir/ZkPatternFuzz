//! Type definitions for grammar DSL

// Re-export main types from parent module
// Additional type utilities can be added here

use super::{EntropyLevel, InputType};

impl InputType {
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            InputType::Field => "BN254 scalar field element",
            InputType::Bool => "Boolean (0 or 1)",
            InputType::Array => "Fixed-length array",
            InputType::MerklePath => "Merkle proof path with elements and indices",
            InputType::Nullifier => "High-entropy nullifier value",
            InputType::Commitment => "Cryptographic commitment",
            InputType::Signature => "EdDSA signature (R, s)",
            InputType::Bytes => "Raw byte array",
        }
    }

    /// Check if type is composite (has sub-elements)
    pub fn is_composite(&self) -> bool {
        matches!(
            self,
            InputType::Array | InputType::MerklePath | InputType::Signature
        )
    }
}

impl EntropyLevel {
    /// Get approximate bit count for entropy level
    pub fn bit_count(&self) -> usize {
        match self {
            EntropyLevel::Low => 16,    // ~65k values
            EntropyLevel::Medium => 64, // 64-bit randomness
            EntropyLevel::High => 254,  // Full field element
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_type_description() {
        assert!(!InputType::Field.description().is_empty());
        assert!(!InputType::MerklePath.description().is_empty());
    }

    #[test]
    fn test_composite_types() {
        assert!(!InputType::Field.is_composite());
        assert!(InputType::Array.is_composite());
        assert!(InputType::MerklePath.is_composite());
    }

    #[test]
    fn test_entropy_bit_count() {
        assert!(EntropyLevel::Low.bit_count() < EntropyLevel::Medium.bit_count());
        assert!(EntropyLevel::Medium.bit_count() < EntropyLevel::High.bit_count());
    }
}
