//! Centralized field constants for ZK circuits
//!
//! This module provides consistent field modulus values to avoid
//! inconsistencies across different parts of the codebase.

/// BN254 scalar field modulus (also known as alt_bn128 or bn256)
/// p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
pub const BN254_MODULUS: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

/// BN254 scalar field modulus minus one (p - 1)
/// Useful for boundary testing
pub const BN254_MODULUS_MINUS_ONE: &str =
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";

/// Half of BN254 modulus: (p - 1) / 2
/// Useful for sign-related testing
pub const BN254_HALF_MODULUS: &str =
    "183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000";

/// Get the BN254 modulus as a 32-byte array
pub fn bn254_modulus_bytes() -> [u8; 32] {
    let mut modulus = [0u8; 32];
    if let Ok(decoded) = hex::decode(BN254_MODULUS) {
        modulus.copy_from_slice(&decoded);
    }
    modulus
}

/// Get the BN254 modulus minus one as a 32-byte array
pub fn bn254_modulus_minus_one_bytes() -> [u8; 32] {
    let mut modulus = [0u8; 32];
    if let Ok(decoded) = hex::decode(BN254_MODULUS_MINUS_ONE) {
        modulus.copy_from_slice(&decoded);
    }
    modulus
}

/// Supported field types for ZK circuits
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FieldType {
    /// BN254 (alt_bn128) scalar field - most common for Ethereum
    #[default]
    Bn254,
    /// BLS12-381 scalar field - used in Zcash, Ethereum 2.0
    Bls12_381,
    /// Pasta curves (Pallas/Vesta) - used in Halo2
    Pasta,
    /// Goldilocks field - used in Plonky2
    Goldilocks,
}

impl FieldType {
    /// Get the modulus for this field type as a hex string
    pub fn modulus_hex(&self) -> &'static str {
        match self {
            FieldType::Bn254 => BN254_MODULUS,
            FieldType::Bls12_381 => {
                "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
            }
            FieldType::Pasta => "40000000000000000000000000000000224698fc094cf91b992d30ed00000001",
            FieldType::Goldilocks => "ffffffff00000001",
        }
    }

    /// Get the modulus minus one for this field type as a hex string
    pub fn modulus_minus_one_hex(&self) -> &'static str {
        match self {
            FieldType::Bn254 => BN254_MODULUS_MINUS_ONE,
            FieldType::Bls12_381 => {
                "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"
            }
            FieldType::Pasta => "40000000000000000000000000000000224698fc094cf91b992d30ed00000000",
            FieldType::Goldilocks => "ffffffff00000000",
        }
    }

    /// Get interesting boundary values for fuzzing this field
    pub fn boundary_values(&self) -> Vec<&'static str> {
        match self {
            FieldType::Bn254 => vec![
                "0000000000000000000000000000000000000000000000000000000000000000", // 0
                "0000000000000000000000000000000000000000000000000000000000000001", // 1
                "0000000000000000000000000000000000000000000000000000000000000002", // 2
                BN254_HALF_MODULUS,                                                 // (p-1)/2
                BN254_MODULUS_MINUS_ONE,                                            // p-1
                BN254_MODULUS, // p (should wrap)
            ],
            _ => vec![
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000001",
                self.modulus_minus_one_hex(),
                self.modulus_hex(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bn254_modulus_bytes() {
        let bytes = bn254_modulus_bytes();
        assert_eq!(bytes[0], 0x30);
        assert_eq!(bytes[31], 0x01);
    }

    #[test]
    fn test_bn254_modulus_minus_one_bytes() {
        let bytes = bn254_modulus_minus_one_bytes();
        assert_eq!(bytes[0], 0x30);
        assert_eq!(bytes[31], 0x00);
    }

    #[test]
    fn test_field_type_boundary_values() {
        let bn254 = FieldType::Bn254;
        let boundaries = bn254.boundary_values();
        assert!(boundaries.len() >= 4);
    }
}
