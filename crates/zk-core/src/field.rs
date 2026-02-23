use num_bigint::BigUint;
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::OnceLock;

fn bn254_modulus() -> &'static BigUint {
    static MODULUS: OnceLock<BigUint> = OnceLock::new();
    MODULUS.get_or_init(|| {
        BigUint::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .expect("BN254 modulus constant must parse")
    })
}

/// Field element representation (32 bytes for bn254)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct FieldElement(pub [u8; 32]);

// Custom serde implementation to serialize as hex string
impl Serialize for FieldElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for FieldElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FieldElement::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl FieldElement {
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn one() -> Self {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        Self(bytes)
    }

    /// Maximum field value (p - 1 for BN254 scalar field)
    pub fn max_value() -> Self {
        // BN254 scalar field: p - 1
        match Self::from_hex("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000") {
            Ok(value) => value,
            Err(err) => panic!("Invalid hardcoded BN254 max_value constant: {}", err),
        }
    }

    /// Half of the field modulus: (p - 1) / 2
    pub fn half_modulus() -> Self {
        match Self::from_hex("0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000") {
            Ok(value) => value,
            Err(err) => panic!("Invalid hardcoded BN254 half_modulus constant: {}", err),
        }
    }

    pub fn random(rng: &mut impl Rng) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        let value = BigUint::from_bytes_be(&bytes) % bn254_modulus();
        Self::from_bytes(&value.to_bytes_be())
    }

    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }

    /// Deprecated: Use from_u64() instead for clarity
    #[deprecated(
        since = "0.2.0",
        note = "Use from_u64() instead for explicit type conversion"
    )]
    pub fn from(value: u64) -> Self {
        Self::from_u64(value)
    }

    /// Create from raw bytes (big-endian, padded to 32 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut result = [0u8; 32];
        let start = 32usize.saturating_sub(bytes.len());
        let copy_len = bytes.len().min(32);
        result[start..start + copy_len].copy_from_slice(&bytes[..copy_len]);
        Self(result)
    }

    /// Get raw bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Field addition (mod p) using BN254 arithmetic.
    pub fn add(&self, other: &Self) -> Self {
        let a = BigUint::from_bytes_be(&self.0);
        let b = BigUint::from_bytes_be(&other.0);
        let result = (a + b) % bn254_modulus();

        let result_bytes = result.to_bytes_be();
        Self::from_bytes(&result_bytes)
    }

    /// Field subtraction (mod p) using BN254 arithmetic.
    pub fn sub(&self, other: &Self) -> Self {
        let a = BigUint::from_bytes_be(&self.0);
        let b = BigUint::from_bytes_be(&other.0);
        let modulus = bn254_modulus();

        // (a - b + p) % p to handle underflow
        let result = if a >= b {
            (a - b) % modulus
        } else {
            (modulus - (b - a) % modulus) % modulus
        };

        let result_bytes = result.to_bytes_be();
        Self::from_bytes(&result_bytes)
    }

    /// Convert to a decimal string representation
    pub fn to_decimal_string(&self) -> String {
        use num_bigint::BigUint;
        BigUint::from_bytes_be(&self.0).to_str_radix(10)
    }

    /// Field multiplication (mod p) using BN254 arithmetic.
    pub fn mul(&self, other: &Self) -> Self {
        let a = BigUint::from_bytes_be(&self.0);
        let b = BigUint::from_bytes_be(&other.0);
        let result = (a * b) % bn254_modulus();

        let result_bytes = result.to_bytes_be();
        Self::from_bytes(&result_bytes)
    }

    /// Parse a hex string into a FieldElement
    ///
    /// # Errors
    /// Returns an error if:
    /// - The hex string is invalid
    /// - The decoded value exceeds 32 bytes (silently truncating large values
    ///   could hide bugs in test configurations)
    pub fn from_hex(hex_str: &str) -> anyhow::Result<Self> {
        let clean = match hex_str.strip_prefix("0x") {
            Some(value) => value,
            None => hex_str,
        };
        let clean = match clean.strip_prefix("0X") {
            Some(value) => value,
            None => clean,
        };
        let decoded = hex::decode(clean)?;

        // Reject values that are too large instead of silently truncating
        if decoded.len() > 32 {
            anyhow::bail!(
                "Hex value too long: {} bytes (max 32). Value: 0x{}...",
                decoded.len(),
                &clean[..clean.len().min(16)]
            );
        }

        let mut bytes = [0u8; 32];
        let start = 32 - decoded.len();
        bytes[start..].copy_from_slice(&decoded);
        Ok(Self(bytes))
    }

    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Check if the field element is zero
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Check if the field element is one
    pub fn is_one(&self) -> bool {
        self.0 == FieldElement::one().0
    }

    /// Field negation: -x mod p
    pub fn neg(&self) -> Self {
        FieldElement::zero().sub(self)
    }

    /// Convert to BigUint for large number operations
    pub fn to_biguint(&self) -> num_bigint::BigUint {
        num_bigint::BigUint::from_bytes_be(&self.0)
    }

    /// Try to convert to u64 if the value fits
    pub fn to_u64(&self) -> Option<u64> {
        use num_traits::ToPrimitive;

        let big_value = BigUint::from_bytes_be(&self.0);
        big_value.to_u64()
    }
}

#[cfg(test)]
#[path = "field_tests.rs"]
mod tests;
