use crate::FieldElement;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Supported ZK frameworks
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Framework {
    Circom,
    Noir,
    Halo2,
    Cairo,
}

/// Supported attack types
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AttackType {
    Underconstrained,
    Soundness,
    ArithmeticOverflow,
    ConstraintBypass,
    TrustedSetup,
    WitnessLeakage,
    ReplayAttack,
    Collision,
    Boundary,
    BitDecomposition,
    Malleability,
    // New attack types for enhanced fuzzing
    /// Proof verification fuzzing
    VerificationFuzzing,
    /// Witness generation fuzzing
    WitnessFuzzing,
    /// Differential testing across backends
    Differential,
    /// Information leakage detection
    InformationLeakage,
    /// Timing side-channel detection
    TimingSideChannel,
    /// Multi-circuit composition testing
    CircuitComposition,
    /// Recursive proof testing
    RecursiveProof,
    // Phase 4: Novel oracle attack types
    /// Constraint inference - detect missing constraints
    ConstraintInference,
    /// Metamorphic testing - transform-based oracles
    Metamorphic,
    /// Constraint slice - dependency cone mutation
    ConstraintSlice,
    /// Spec inference - auto-learn properties and violate them
    SpecInference,
    /// Enhanced witness collision detection
    WitnessCollision,
    // Phase 3: DeFi and Protocol attack types
    /// MEV extraction detection (ordering, sandwich, arbitrage)
    Mev,
    /// Front-running vulnerability detection
    FrontRunning,
    /// zkEVM-specific attack detection
    ZkEvm,
    /// Batch verification bypass attacks (Phase 3.3)
    BatchVerification,
}

/// Severity levels for findings
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single test case with inputs
#[derive(Debug, Clone)]
pub struct TestCase {
    pub inputs: Vec<FieldElement>,
    pub expected_output: Option<Vec<FieldElement>>,
    pub metadata: TestMetadata,
}

/// Metadata about a test case
#[derive(Debug, Clone, Default)]
pub struct TestMetadata {
    pub generation: usize,
    pub mutation_history: Vec<String>,
    pub coverage_bits: u64,
}

/// Phase 3C: Classification of finding types for proper categorization
///
/// This enum distinguishes between different classes of findings,
/// helping to properly categorize and prioritize issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingClass {
    /// Oracle detected a semantic bug (highest confidence)
    OracleViolation,
    /// YAML invariant was violated by circuit-accepted witness
    InvariantViolation,
    /// Executor panicked or returned abnormal exit
    Crash,
    /// Execution exceeded timeout (potential DoS)
    Hang,
    /// Unconfirmed hint requiring manual review
    Heuristic,
}

impl Default for FindingClass {
    fn default() -> Self {
        Self::Heuristic
    }
}

impl std::fmt::Display for FindingClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingClass::OracleViolation => write!(f, "Oracle Violation"),
            FindingClass::InvariantViolation => write!(f, "Invariant Violation"),
            FindingClass::Crash => write!(f, "Crash"),
            FindingClass::Hang => write!(f, "Hang"),
            FindingClass::Heuristic => write!(f, "Heuristic"),
        }
    }
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

impl Finding {
    /// Phase 3C: Classify this finding based on its characteristics
    pub fn classify(&self) -> FindingClass {
        let desc_lower = self.description.to_lowercase();

        if desc_lower.contains("hang") || desc_lower.contains("timeout") {
            FindingClass::Hang
        } else if desc_lower.contains("crash") || desc_lower.contains("panic") {
            FindingClass::Crash
        } else if desc_lower.contains("invariant") && desc_lower.contains("violated") {
            FindingClass::InvariantViolation
        } else if desc_lower.contains("oracle") || !self.poc.witness_a.is_empty() {
            FindingClass::OracleViolation
        } else {
            FindingClass::Heuristic
        }
    }
}

impl serde::Serialize for Finding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Finding", 5)?;
        state.serialize_field("attack_type", &format!("{:?}", self.attack_type))?;
        state.serialize_field("severity", &self.severity)?;
        state.serialize_field("description", &self.description)?;
        state.serialize_field("location", &self.location)?;
        state.serialize_field(
            "poc_witness_a",
            &self
                .poc
                .witness_a
                .iter()
                .map(|fe| fe.to_hex())
                .collect::<Vec<_>>(),
        )?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for Finding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            AttackType,
            Severity,
            Description,
            Location,
            PocWitnessA,
        }

        struct FindingVisitor;

        impl<'de> Visitor<'de> for FindingVisitor {
            type Value = Finding;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Finding")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Finding, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut attack_type: Option<String> = None;
                let mut severity: Option<Severity> = None;
                let mut description: Option<String> = None;
                let mut location: Option<Option<String>> = None;
                let mut poc_witness_a: Option<Vec<String>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::AttackType => {
                            attack_type = Some(map.next_value()?);
                        }
                        Field::Severity => {
                            severity = Some(map.next_value()?);
                        }
                        Field::Description => {
                            description = Some(map.next_value()?);
                        }
                        Field::Location => {
                            location = Some(map.next_value()?);
                        }
                        Field::PocWitnessA => {
                            poc_witness_a = Some(map.next_value()?);
                        }
                    }
                }

                let attack_type_str =
                    attack_type.ok_or_else(|| de::Error::missing_field("attack_type"))?;
                let parsed_attack_type = match attack_type_str.as_str() {
                    "Underconstrained" => AttackType::Underconstrained,
                    "Soundness" => AttackType::Soundness,
                    "ArithmeticOverflow" => AttackType::ArithmeticOverflow,
                    "ConstraintBypass" => AttackType::ConstraintBypass,
                    "TrustedSetup" => AttackType::TrustedSetup,
                    "WitnessLeakage" => AttackType::WitnessLeakage,
                    "ReplayAttack" => AttackType::ReplayAttack,
                    "Collision" => AttackType::Collision,
                    "Boundary" => AttackType::Boundary,
                    "BitDecomposition" => AttackType::BitDecomposition,
                    "Malleability" => AttackType::Malleability,
                    "VerificationFuzzing" => AttackType::VerificationFuzzing,
                    "WitnessFuzzing" => AttackType::WitnessFuzzing,
                    "Differential" => AttackType::Differential,
                    "InformationLeakage" => AttackType::InformationLeakage,
                    "TimingSideChannel" => AttackType::TimingSideChannel,
                    "CircuitComposition" => AttackType::CircuitComposition,
                    "RecursiveProof" => AttackType::RecursiveProof,
                    "ConstraintInference" => AttackType::ConstraintInference,
                    "Metamorphic" => AttackType::Metamorphic,
                    "ConstraintSlice" => AttackType::ConstraintSlice,
                    "SpecInference" => AttackType::SpecInference,
                    "WitnessCollision" => AttackType::WitnessCollision,
                    _ => {
                        return Err(de::Error::unknown_variant(
                            &attack_type_str,
                            &[
                                "Underconstrained",
                                "Soundness",
                                "ArithmeticOverflow",
                                "ConstraintBypass",
                                "TrustedSetup",
                                "WitnessLeakage",
                                "ReplayAttack",
                                "Collision",
                                "Boundary",
                                "BitDecomposition",
                                "Malleability",
                                "VerificationFuzzing",
                                "WitnessFuzzing",
                                "Differential",
                                "InformationLeakage",
                                "TimingSideChannel",
                                "CircuitComposition",
                                "RecursiveProof",
                                "ConstraintInference",
                                "Metamorphic",
                                "ConstraintSlice",
                                "SpecInference",
                                "WitnessCollision",
                            ],
                        ))
                    }
                };

                let witness_a: Vec<FieldElement> = poc_witness_a
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|hex| FieldElement::from_hex(hex).ok())
                    .collect();

                Ok(Finding {
                    attack_type: parsed_attack_type,
                    severity: severity.ok_or_else(|| de::Error::missing_field("severity"))?,
                    description: description
                        .ok_or_else(|| de::Error::missing_field("description"))?,
                    location: location.unwrap_or(None),
                    poc: ProofOfConcept {
                        witness_a,
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                })
            }
        }

        const FIELDS: &[&str] = &[
            "attack_type",
            "severity",
            "description",
            "location",
            "poc_witness_a",
        ];
        deserializer.deserialize_struct("Finding", FIELDS, FindingVisitor)
    }
}

/// Proof of concept for reproducing a finding
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
