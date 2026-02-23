use num_bigint::BigUint;
use std::sync::OnceLock;

/// BN254 scalar modulus in decimal form.
pub const BN254_SCALAR_MODULUS_DECIMAL: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// BN254 scalar modulus in big-endian hex (without 0x prefix).
pub const BN254_SCALAR_MODULUS_HEX: &str =
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

/// BN254 scalar modulus minus one in decimal form.
pub const BN254_SCALAR_MODULUS_MINUS_ONE_DECIMAL: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495616";

/// BN254 scalar modulus minus one in big-endian hex (without 0x prefix).
pub const BN254_SCALAR_MODULUS_MINUS_ONE_HEX: &str =
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";

/// BN254 scalar modulus plus one in decimal form.
pub const BN254_SCALAR_MODULUS_PLUS_ONE_DECIMAL: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495618";

/// (p - 1) / 2 for BN254 scalar field in big-endian hex.
pub const BN254_SCALAR_HALF_MODULUS_HEX: &str =
    "183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000";

/// BN254 scalar modulus bytes in big-endian format.
pub const BN254_SCALAR_MODULUS_BYTES: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// BN254 scalar modulus minus one bytes in big-endian format.
pub const BN254_SCALAR_MODULUS_MINUS_ONE_BYTES: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00,
];

/// Returns the BN254 scalar modulus as `BigUint`.
pub fn bn254_modulus_biguint() -> &'static BigUint {
    static MODULUS: OnceLock<BigUint> = OnceLock::new();
    MODULUS.get_or_init(|| {
        BigUint::parse_bytes(BN254_SCALAR_MODULUS_DECIMAL.as_bytes(), 10)
            .expect("BN254 modulus constant must parse")
    })
}

/// Returns `p - 1` for BN254 scalar field as `BigUint`.
pub fn bn254_modulus_minus_one_biguint() -> &'static BigUint {
    static MODULUS_MINUS_ONE: OnceLock<BigUint> = OnceLock::new();
    MODULUS_MINUS_ONE.get_or_init(|| {
        BigUint::parse_bytes(BN254_SCALAR_MODULUS_MINUS_ONE_DECIMAL.as_bytes(), 10)
            .expect("BN254 modulus minus one constant must parse")
    })
}

/// Returns BN254 scalar modulus bytes in big-endian format.
pub fn bn254_modulus_bytes() -> [u8; 32] {
    BN254_SCALAR_MODULUS_BYTES
}

/// Returns BN254 scalar modulus minus one bytes in big-endian format.
pub fn bn254_modulus_minus_one_bytes() -> [u8; 32] {
    BN254_SCALAR_MODULUS_MINUS_ONE_BYTES
}
