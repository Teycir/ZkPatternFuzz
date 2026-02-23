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
    /// Advanced side-channel analysis (cache/power/memory patterns)
    SidechannelAdvanced,
    /// Post-quantum security posture analysis
    QuantumResistance,
    /// Advanced privacy-leakage analysis
    PrivacyAdvanced,
    /// Advanced DeFi/protocol-level analysis
    DefiAdvanced,
    /// Circom-specific static linting checks
    CircomStaticLint,
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
    pub class: Option<FindingClass>,
    pub location: Option<String>,
}

impl Finding {
    /// Phase 3C: Classify this finding based on its characteristics
    pub fn classify(&self) -> FindingClass {
        if let Some(class) = self.class {
            return class;
        }
        self.infer_class_from_content()
    }

    fn infer_class_from_content(&self) -> FindingClass {
        let desc_lower = self.description.to_lowercase();
        let has_cross_witness_evidence = self
            .poc
            .witness_b
            .as_ref()
            .map(|witness| !witness.is_empty())
            .unwrap_or(false);

        if desc_lower.contains("hang") || desc_lower.contains("timeout") {
            FindingClass::Hang
        } else if desc_lower.contains("crash") || desc_lower.contains("panic") {
            FindingClass::Crash
        } else if desc_lower.contains("invariant") && desc_lower.contains("violated") {
            FindingClass::InvariantViolation
        } else if has_cross_witness_evidence
            || desc_lower.contains("oracle violation")
            || desc_lower.contains("oracle-confirmed")
        {
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
        let mut state = serializer.serialize_struct("Finding", 9)?;
        state.serialize_field("attack_type", &self.attack_type)?;
        state.serialize_field("severity", &self.severity)?;
        state.serialize_field("description", &self.description)?;
        state.serialize_field("class", &self.classify())?;
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
        state.serialize_field(
            "poc_witness_b",
            &self.poc.witness_b.as_ref().map(|witness| {
                witness
                    .iter()
                    .map(|fe| fe.to_hex())
                    .collect::<Vec<String>>()
            }),
        )?;
        state.serialize_field(
            "poc_public_inputs",
            &self
                .poc
                .public_inputs
                .iter()
                .map(|fe| fe.to_hex())
                .collect::<Vec<_>>(),
        )?;
        state.serialize_field("poc_proof", &self.poc.proof)?;
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
            Class,
            Location,
            PocWitnessA,
            PocWitnessB,
            PocPublicInputs,
            PocProof,
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
                let mut class: Option<FindingClass> = None;
                let mut location: Option<Option<String>> = None;
                let mut poc_witness_a: Option<Vec<String>> = None;
                let mut poc_witness_b: Option<Option<Vec<String>>> = None;
                let mut poc_public_inputs: Option<Vec<String>> = None;
                let mut poc_proof: Option<Option<Vec<u8>>> = None;

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
                        Field::Class => {
                            class = Some(map.next_value()?);
                        }
                        Field::Location => {
                            location = Some(map.next_value()?);
                        }
                        Field::PocWitnessA => {
                            poc_witness_a = Some(map.next_value()?);
                        }
                        Field::PocWitnessB => {
                            poc_witness_b = Some(map.next_value()?);
                        }
                        Field::PocPublicInputs => {
                            poc_public_inputs = Some(map.next_value()?);
                        }
                        Field::PocProof => {
                            poc_proof = Some(map.next_value()?);
                        }
                    }
                }

                let attack_type_str =
                    attack_type.ok_or_else(|| de::Error::missing_field("attack_type"))?;
                let parsed_attack_type = parse_attack_type_compat(&attack_type_str)?;

                let witness_a = poc_witness_a.unwrap_or_default();
                let mut parsed_witness_a: Vec<FieldElement> = Vec::with_capacity(witness_a.len());
                for hex in &witness_a {
                    let field = FieldElement::from_hex_checked(hex).map_err(|e| {
                        de::Error::custom(format!("invalid poc.witness_a element '{}': {}", hex, e))
                    })?;
                    parsed_witness_a.push(field);
                }

                let parsed_witness_b = match poc_witness_b.unwrap_or(None) {
                    Some(witness_b) => {
                        let mut parsed: Vec<FieldElement> = Vec::with_capacity(witness_b.len());
                        for hex in &witness_b {
                            let field = FieldElement::from_hex_checked(hex).map_err(|e| {
                                de::Error::custom(format!(
                                    "invalid poc.witness_b element '{}': {}",
                                    hex, e
                                ))
                            })?;
                            parsed.push(field);
                        }
                        Some(parsed)
                    }
                    None => None,
                };

                let public_inputs = poc_public_inputs.unwrap_or_default();
                let mut parsed_public_inputs: Vec<FieldElement> =
                    Vec::with_capacity(public_inputs.len());
                for hex in &public_inputs {
                    let field = FieldElement::from_hex_checked(hex).map_err(|e| {
                        de::Error::custom(format!(
                            "invalid poc.public_inputs element '{}': {}",
                            hex, e
                        ))
                    })?;
                    parsed_public_inputs.push(field);
                }

                Ok(Finding {
                    attack_type: parsed_attack_type,
                    severity: severity.ok_or_else(|| de::Error::missing_field("severity"))?,
                    description: description
                        .ok_or_else(|| de::Error::missing_field("description"))?,
                    class,
                    location: location.unwrap_or_default(),
                    poc: ProofOfConcept {
                        witness_a: parsed_witness_a,
                        witness_b: parsed_witness_b,
                        public_inputs: parsed_public_inputs,
                        proof: poc_proof.unwrap_or(None),
                    },
                })
            }
        }

        const FIELDS: &[&str] = &[
            "attack_type",
            "severity",
            "description",
            "class",
            "location",
            "poc_witness_a",
            "poc_witness_b",
            "poc_public_inputs",
            "poc_proof",
        ];
        deserializer.deserialize_struct("Finding", FIELDS, FindingVisitor)
    }
}

fn parse_attack_type_compat<E: serde::de::Error>(raw: &str) -> Result<AttackType, E> {
    use serde::de::value::{Error as ValueError, StrDeserializer};

    if let Ok(parsed) = AttackType::deserialize(StrDeserializer::<ValueError>::new(raw)) {
        return Ok(parsed);
    }

    let normalized = to_snake_case(raw);
    AttackType::deserialize(StrDeserializer::<ValueError>::new(normalized.as_str())).map_err(|_| {
        E::custom(format!(
            "unsupported attack_type '{}'; expected snake_case or PascalCase variant",
            raw
        ))
    })
}

fn to_snake_case(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 8);
    for (idx, ch) in raw.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if idx > 0 && !out.ends_with('_') {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Proof of concept for reproducing a finding
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProofOfConcept {
    pub witness_a: Vec<FieldElement>,
    pub witness_b: Option<Vec<FieldElement>>,
    pub public_inputs: Vec<FieldElement>,
    pub proof: Option<Vec<u8>>,
}

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;

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
