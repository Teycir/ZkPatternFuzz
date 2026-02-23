//! Formal Verification Integration
//!
//! Provides integration with formal verification tools:
//! - Lean 4 proof export
//! - Coq proof export  
//! - Property extraction from circuits
//! - Proof obligation generation

pub mod bridge;
pub mod coq;
pub mod lean;
pub mod properties;

pub use bridge::{
    export_formal_bridge_artifacts, import_formal_invariants_from_file, FormalBridgeArtifacts,
    FormalBridgeOptions,
};
pub use coq::CoqExporter;
pub use lean::LeanExporter;
pub use properties::{CircuitProperty, PropertyExtractor};

use crate::analysis::symbolic::SymbolicConstraint;
use std::path::Path;
use zk_core::constants::BN254_SCALAR_MODULUS_DECIMAL;
use zk_core::ConstraintEquation;

/// Target proof system
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSystem {
    Lean4,
    Coq,
}

/// A proof obligation that needs to be verified
#[derive(Debug, Clone)]
pub struct ProofObligation {
    /// Name/identifier for this obligation
    pub name: String,
    /// Description of what's being proven
    pub description: String,
    /// The property to verify
    pub property: CircuitProperty,
    /// Whether this is a safety or liveness property
    pub property_type: PropertyType,
    /// Constraints involved
    pub constraints: Vec<SymbolicConstraint>,
    /// Variables involved
    pub variables: Vec<String>,
    /// Assumed preconditions
    pub preconditions: Vec<SymbolicConstraint>,
    /// Expected postconditions
    pub postconditions: Vec<SymbolicConstraint>,
}

/// Type of property
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyType {
    /// Safety: something bad never happens
    Safety,
    /// Liveness: something good eventually happens
    Liveness,
    /// Soundness: invalid statements cannot be proven
    Soundness,
    /// Completeness: all valid statements can be proven
    Completeness,
    /// Zero-knowledge: proof reveals nothing beyond validity
    ZeroKnowledge,
}

/// Result of proof generation
#[derive(Debug, Clone)]
pub struct ProofResult {
    /// Generated proof code
    pub code: String,
    /// File extension
    pub extension: &'static str,
    /// Whether proof was successfully generated
    pub success: bool,
    /// Proof system used
    pub system: ProofSystem,
    /// Dependencies required
    pub dependencies: Vec<String>,
    /// Any warnings
    pub warnings: Vec<String>,
}

/// Trait for proof exporters
pub trait ProofExporter {
    /// Get the target proof system
    fn system(&self) -> ProofSystem;

    /// Export a single proof obligation
    fn export_obligation(&self, obligation: &ProofObligation) -> ProofResult;

    /// Export multiple obligations as a proof module
    fn export_module(&self, name: &str, obligations: &[ProofObligation]) -> ProofResult;

    /// Export circuit constraints as a theorem
    fn export_circuit(&self, name: &str, constraints: &[ConstraintEquation]) -> ProofResult;

    /// Generate a proof skeleton
    fn generate_skeleton(&self, obligation: &ProofObligation) -> String;
}

/// Configuration for formal verification export
#[derive(Debug, Clone)]
pub struct FormalConfig {
    /// Target proof system
    pub system: ProofSystem,
    /// Output directory
    pub output_dir: String,
    /// Generate proof skeletons
    pub generate_skeletons: bool,
    /// Include comments in generated code
    pub include_comments: bool,
    /// Field modulus to use
    pub field_modulus: String,
    /// Custom imports to include
    pub custom_imports: Vec<String>,
}

impl Default for FormalConfig {
    fn default() -> Self {
        Self {
            system: ProofSystem::Lean4,
            output_dir: "./proofs".to_string(),
            generate_skeletons: true,
            include_comments: true,
            field_modulus: BN254_SCALAR_MODULUS_DECIMAL.to_string(),
            custom_imports: Vec::new(),
        }
    }
}

/// Main formal verification manager
pub struct FormalVerificationManager {
    config: FormalConfig,
    /// Extracted properties
    properties: Vec<CircuitProperty>,
    /// Generated proof obligations
    obligations: Vec<ProofObligation>,
    /// Lean exporter
    lean_exporter: LeanExporter,
    /// Coq exporter
    coq_exporter: CoqExporter,
}

impl FormalVerificationManager {
    pub fn new(config: FormalConfig) -> Self {
        let lean_exporter = LeanExporter::new(&config.field_modulus);
        let coq_exporter = CoqExporter::new(&config.field_modulus);

        Self {
            config,
            properties: Vec::new(),
            obligations: Vec::new(),
            lean_exporter,
            coq_exporter,
        }
    }

    /// Extract properties from circuit constraints
    pub fn extract_properties(&mut self, constraints: &[ConstraintEquation]) {
        let extractor = PropertyExtractor::new();
        self.properties = extractor.extract_all(constraints);
    }

    /// Generate proof obligations from properties
    pub fn generate_obligations(&mut self) {
        for (i, property) in self.properties.iter().enumerate() {
            let obligation = ProofObligation {
                name: format!("obligation_{}", i),
                description: format!("{:?}", property),
                property: property.clone(),
                property_type: Self::classify_property(property),
                constraints: Vec::new(),
                variables: property.variables().iter().cloned().collect(),
                preconditions: property.preconditions(),
                postconditions: property.postconditions(),
            };
            self.obligations.push(obligation);
        }
    }

    /// Classify a property type
    fn classify_property(property: &CircuitProperty) -> PropertyType {
        match property {
            CircuitProperty::ConstraintSatisfied { .. } => PropertyType::Soundness,
            CircuitProperty::NonZero { .. } => PropertyType::Safety,
            CircuitProperty::Range { .. } => PropertyType::Safety,
            CircuitProperty::Boolean { .. } => PropertyType::Safety,
            CircuitProperty::Unique { .. } => PropertyType::Soundness,
            CircuitProperty::Deterministic { .. } => PropertyType::Completeness,
        }
    }

    /// Export proofs to the target system
    pub fn export(&self) -> Vec<ProofResult> {
        let exporter: &dyn ProofExporter = match self.config.system {
            ProofSystem::Lean4 => &self.lean_exporter,
            ProofSystem::Coq => &self.coq_exporter,
        };

        let mut results = Vec::new();

        // Export each obligation
        for obligation in &self.obligations {
            let result = exporter.export_obligation(obligation);
            results.push(result);
        }

        results
    }

    /// Export as a complete proof module
    pub fn export_module(&self, name: &str) -> ProofResult {
        let exporter: &dyn ProofExporter = match self.config.system {
            ProofSystem::Lean4 => &self.lean_exporter,
            ProofSystem::Coq => &self.coq_exporter,
        };

        exporter.export_module(name, &self.obligations)
    }

    /// Export circuit constraints
    pub fn export_circuit(&self, name: &str, constraints: &[ConstraintEquation]) -> ProofResult {
        let exporter: &dyn ProofExporter = match self.config.system {
            ProofSystem::Lean4 => &self.lean_exporter,
            ProofSystem::Coq => &self.coq_exporter,
        };

        exporter.export_circuit(name, constraints)
    }

    /// Write proofs to output directory
    pub fn write_to_disk(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.config.output_dir)?;

        let results = self.export();
        for (i, result) in results.iter().enumerate() {
            let filename = format!("proof_{}.{}", i, result.extension);
            let path = Path::new(&self.config.output_dir).join(filename);
            std::fs::write(path, &result.code)?;
        }

        // Also write the complete module
        let module_result = self.export_module("Circuit");
        let module_path =
            Path::new(&self.config.output_dir).join(format!("Circuit.{}", module_result.extension));
        std::fs::write(module_path, &module_result.code)?;

        Ok(())
    }

    /// Get properties
    pub fn properties(&self) -> &[CircuitProperty] {
        &self.properties
    }

    /// Get obligations
    pub fn obligations(&self) -> &[ProofObligation] {
        &self.obligations
    }
}

/// Generate a soundness proof for a circuit
pub fn generate_soundness_proof(
    circuit_name: &str,
    constraints: &[ConstraintEquation],
    system: ProofSystem,
) -> ProofResult {
    match system {
        ProofSystem::Lean4 => {
            let exporter = LeanExporter::new(BN254_SCALAR_MODULUS_DECIMAL);
            exporter.export_circuit(circuit_name, constraints)
        }
        ProofSystem::Coq => {
            let exporter = CoqExporter::new(BN254_SCALAR_MODULUS_DECIMAL);
            exporter.export_circuit(circuit_name, constraints)
        }
    }
}
