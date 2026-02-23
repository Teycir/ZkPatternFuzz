//! Centralized field constants for ZK circuits
//!
//! This module provides consistent field modulus values to avoid
//! inconsistencies across different parts of the codebase.

use zk_core::constants::{
    bn254_modulus_bytes as core_bn254_modulus_bytes,
    bn254_modulus_minus_one_bytes as core_bn254_modulus_minus_one_bytes,
    BN254_SCALAR_HALF_MODULUS_HEX, BN254_SCALAR_MODULUS_HEX, BN254_SCALAR_MODULUS_MINUS_ONE_HEX,
};

/// BN254 scalar field modulus (also known as alt_bn128 or bn256).
/// Canonical value is defined in `zk_core::constants`.
pub const BN254_MODULUS: &str = BN254_SCALAR_MODULUS_HEX;

/// BN254 scalar field modulus minus one (p - 1)
/// Useful for boundary testing
pub const BN254_MODULUS_MINUS_ONE: &str = BN254_SCALAR_MODULUS_MINUS_ONE_HEX;

/// Half of BN254 modulus: (p - 1) / 2
/// Useful for sign-related testing
pub const BN254_HALF_MODULUS: &str = BN254_SCALAR_HALF_MODULUS_HEX;

/// Get the BN254 modulus as a 32-byte array
pub fn bn254_modulus_bytes() -> [u8; 32] {
    core_bn254_modulus_bytes()
}

/// Get the BN254 modulus minus one as a 32-byte array
pub fn bn254_modulus_minus_one_bytes() -> [u8; 32] {
    core_bn254_modulus_minus_one_bytes()
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
    /// Get the modulus as a 32-byte big-endian array for this field type.
    pub fn modulus_bytes(&self) -> [u8; 32] {
        let mut modulus = [0u8; 32];
        let hex_str = self.modulus_hex();
        if let Ok(decoded) = hex::decode(hex_str) {
            let start = 32usize.saturating_sub(decoded.len());
            let copy_len = decoded.len().min(32);
            modulus[start..start + copy_len].copy_from_slice(&decoded[..copy_len]);
        }
        modulus
    }

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
#[path = "constants_tests.rs"]
mod tests;
