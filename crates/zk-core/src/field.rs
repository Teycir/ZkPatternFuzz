use rand::Rng;

/// Field element representation (32 bytes for bn254)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct FieldElement(pub [u8; 32]);

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
        Self::from_hex("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000")
            .unwrap_or_else(|_| Self::zero())
    }

    /// Half of the field modulus: (p - 1) / 2
    pub fn half_modulus() -> Self {
        Self::from_hex("0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000")
            .unwrap_or_else(|_| Self::zero())
    }

    pub fn random(rng: &mut impl Rng) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        Self(bytes)
    }

    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
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

    /// Field addition (mod p) - simplified for mock purposes
    pub fn add(&self, other: &Self) -> Self {
        use num_bigint::BigUint;
        let modulus = BigUint::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap();

        let a = BigUint::from_bytes_be(&self.0);
        let b = BigUint::from_bytes_be(&other.0);
        let result = (a + b) % &modulus;

        let result_bytes = result.to_bytes_be();
        Self::from_bytes(&result_bytes)
    }

    /// Field subtraction (mod p) - simplified for mock purposes
    pub fn sub(&self, other: &Self) -> Self {
        use num_bigint::BigUint;
        let modulus = BigUint::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap();

        let a = BigUint::from_bytes_be(&self.0);
        let b = BigUint::from_bytes_be(&other.0);

        // (a - b + p) % p to handle underflow
        let result = if a >= b {
            (a - b) % &modulus
        } else {
            (&modulus - (b - a) % &modulus) % &modulus
        };

        let result_bytes = result.to_bytes_be();
        Self::from_bytes(&result_bytes)
    }

    /// Convert to a decimal string representation
    pub fn to_decimal_string(&self) -> String {
        use num_bigint::BigUint;
        BigUint::from_bytes_be(&self.0).to_str_radix(10)
    }

    /// Field multiplication (mod p) - simplified for mock purposes
    pub fn mul(&self, other: &Self) -> Self {
        use num_bigint::BigUint;
        let modulus = BigUint::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap();

        let a = BigUint::from_bytes_be(&self.0);
        let b = BigUint::from_bytes_be(&other.0);
        let result = (a * b) % &modulus;

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
        let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let clean = clean.strip_prefix("0X").unwrap_or(clean);
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
}
