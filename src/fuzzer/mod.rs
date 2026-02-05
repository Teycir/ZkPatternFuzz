//! Core fuzzing engine for ZK circuits

mod constants;
mod mutators;
mod oracle;
mod engine;
mod power_schedule;
mod structure_aware;

pub use constants::*;
pub use mutators::*;
pub use oracle::*;
pub use engine::FuzzingEngine;

use crate::config::*;
use crate::progress::ProgressReporter;
use crate::reporting::FuzzReport;
use rand::Rng;
use std::collections::HashMap;

/// Main fuzzer engine
pub struct ZkFuzzer {
    config: FuzzConfig,
    seed: Option<u64>,
}

/// A single test case with inputs
#[derive(Debug, Clone)]
pub struct TestCase {
    pub inputs: Vec<FieldElement>,
    pub expected_output: Option<Vec<FieldElement>>,
    pub metadata: TestMetadata,
}

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
        ).unwrap();
        
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
        ).unwrap();
        
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
        ).unwrap();
        
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
}

/// Metadata about a test case
#[derive(Debug, Clone, Default)]
pub struct TestMetadata {
    pub generation: usize,
    pub mutation_history: Vec<String>,
    pub coverage_bits: u64,
}

/// A security finding
#[derive(Debug, Clone)]
pub struct Finding {
    pub attack_type: AttackType,
    pub severity: Severity,
    pub description: String,
    pub poc: ProofOfConcept,
    pub location: Option<String>,
}

/// Proof of concept for reproducing a finding
#[derive(Debug, Clone, Default)]
pub struct ProofOfConcept {
    pub witness_a: Vec<FieldElement>,
    pub witness_b: Option<Vec<FieldElement>>,
    pub public_inputs: Vec<FieldElement>,
    pub proof: Option<Vec<u8>>,
}

/// Coverage tracking
#[derive(Debug, Clone, Default)]
pub struct CoverageMap {
    pub constraint_hits: HashMap<usize, u64>,
    pub edge_coverage: u64,
    pub max_coverage: u64,
}

impl CoverageMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_hit(&mut self, constraint_id: usize) {
        *self.constraint_hits.entry(constraint_id).or_insert(0) += 1;
        self.edge_coverage = self.constraint_hits.len() as u64;
    }

    pub fn coverage_percentage(&self) -> f64 {
        if self.max_coverage == 0 {
            0.0
        } else {
            (self.edge_coverage as f64 / self.max_coverage as f64) * 100.0
        }
    }
}

impl ZkFuzzer {
    /// Create a new fuzzer with the given configuration
    pub fn new(config: FuzzConfig, seed: Option<u64>) -> Self {
        Self {
            config,
            seed,
        }
    }

    /// Create and run using the new engine with progress reporting
    pub async fn run_with_progress(
        config: FuzzConfig,
        seed: Option<u64>,
        workers: usize,
        verbose: bool,
    ) -> anyhow::Result<FuzzReport> {
        // Calculate total iterations for progress bar
        let total: u64 = config.attacks.iter().map(|a| {
            a.config.get("witness_pairs").and_then(|v| v.as_u64()).unwrap_or(1000)
            + a.config.get("forge_attempts").and_then(|v| v.as_u64()).unwrap_or(0)
            + a.config.get("samples").and_then(|v| v.as_u64()).unwrap_or(0)
        }).sum();

        let progress = ProgressReporter::new(&config.campaign.name, total.max(1000), verbose);

        let mut engine = FuzzingEngine::new(config, seed, workers)?;
        let report = engine.run(Some(&progress)).await?;

        progress.finish(&engine.stats());

        Ok(report)
    }

    /// Run the fuzzing campaign
    pub async fn run(&mut self) -> anyhow::Result<FuzzReport> {
        let mut engine = FuzzingEngine::new(self.config.clone(), self.seed, 1)?;
        engine.run(None).await
    }
}
