//! Circuit execution abstraction layer
//!
//! Provides a unified interface for executing ZK circuits across different backends.

pub mod batch_verifier;
mod coverage;
mod fixture;
mod isolated;
mod traits;

pub use batch_verifier::*;
pub use coverage::*;
pub use fixture::*;
pub use isolated::*;
pub use traits::*;

// Re-export CircuitInfo for external use
pub use zk_core::CircuitInfo;

use crate::analysis::constraint_types::LinearCombination;
use crate::analysis::{
    AcirOpcode, BlackBoxOp, ConstraintChecker, ExtendedConstraint, RangeMethod,
    UnknownLookupPolicy, WireRef,
};
use crate::targets::TargetCircuit;
use anyhow::Context as _;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use zk_core::{FieldElement, Framework};

/// Options for controlling executor creation (e.g., build directory overrides).
#[derive(Debug, Clone)]
pub struct ExecutorFactoryOptions {
    /// Base directory for build artifacts (per-framework subdirs will be created).
    pub build_dir_base: Option<PathBuf>,
    /// Explicit build directory for Circom.
    pub circom_build_dir: Option<PathBuf>,
    /// Explicit build directory for Noir.
    pub noir_build_dir: Option<PathBuf>,
    /// Explicit build directory for Halo2.
    pub halo2_build_dir: Option<PathBuf>,
    /// Explicit build directory for Cairo.
    pub cairo_build_dir: Option<PathBuf>,
    /// Additional include paths for Circom (-l)
    pub circom_include_paths: Vec<PathBuf>,
    /// Auto-generate proving/verification keys for Circom (required for prove/verify)
    pub circom_auto_setup_keys: bool,
    /// Optional path to a powers of tau file for Circom Groth16 setup
    pub circom_ptau_path: Option<PathBuf>,
    /// Optional path to snarkjs CLI (binary or JS file)
    pub circom_snarkjs_path: Option<PathBuf>,
    /// If true, reuse existing Circom build artifacts (r1cs/wasm) when present
    /// instead of recompiling on every executor creation. This is critical
    /// for per-exec isolation performance.
    pub circom_skip_compile_if_artifacts: bool,
    /// If true, skip per-execution full constraint evaluation for Circom targets.
    ///
    /// This can dramatically improve throughput on large circuits, at the cost of:
    /// - no constraint-level coverage metrics
    /// - weaker signal for constraint-driven attacks/oracles
    ///
    /// Evidence-mode campaigns that only need outputs/invariants may enable this.
    pub circom_skip_constraint_check: bool,
    /// If true, Circom witness generation enforces internal constraint sanity checks.
    ///
    /// This ensures `ExecutionResult.success` means the witness satisfied circuit constraints,
    /// even when `circom_skip_constraint_check` is enabled to skip expensive host-side
    /// per-constraint coverage evaluation.
    pub circom_witness_sanity_check: bool,
    /// If true, fail with an error when real backend tooling is missing.
    pub strict_backend: bool,
}

impl Default for ExecutorFactoryOptions {
    fn default() -> Self {
        Self {
            build_dir_base: None,
            circom_build_dir: None,
            noir_build_dir: None,
            halo2_build_dir: None,
            cairo_build_dir: None,
            circom_include_paths: Vec::new(),
            circom_auto_setup_keys: false,
            circom_ptau_path: None,
            circom_snarkjs_path: None,
            circom_skip_compile_if_artifacts: false,
            circom_skip_constraint_check: false,
            circom_witness_sanity_check: true,
            strict_backend: true,
        }
    }
}

impl ExecutorFactoryOptions {
    /// Create options with strict backend mode enabled
    ///
    /// In strict mode, the factory will error if a real backend is not available
    /// instead of substituting alternative execution paths.
    pub fn strict() -> Self {
        Self {
            strict_backend: true,
            ..Self::default()
        }
    }

    fn resolve_build_dir(
        &self,
        framework: Framework,
        circuit_path: &str,
        main_component: &str,
    ) -> Option<PathBuf> {
        let specific = match framework {
            Framework::Circom => self.circom_build_dir.as_ref(),
            Framework::Noir => self.noir_build_dir.as_ref(),
            Framework::Halo2 => self.halo2_build_dir.as_ref(),
            Framework::Cairo => self.cairo_build_dir.as_ref(),
        };

        if let Some(path) = specific {
            return Some(path.clone());
        }

        let base = self.build_dir_base.as_ref()?;
        let mut dir = base.clone();
        dir.push(framework_dir_name(framework));
        dir.push(derive_circuit_build_name(circuit_path, main_component));
        Some(dir)
    }
}

fn framework_dir_name(framework: Framework) -> &'static str {
    match framework {
        Framework::Circom => "circom",
        Framework::Noir => "noir",
        Framework::Halo2 => "halo2",
        Framework::Cairo => "cairo",
    }
}

fn derive_circuit_build_name(circuit_path: &str, main_component: &str) -> String {
    let path = Path::new(circuit_path);
    let name = if path.is_dir() {
        match path.file_name().and_then(|s| s.to_str()) {
            Some(value) => value.to_string(),
            None => "circuit".to_string(),
        }
    } else {
        match path
            .file_stem()
            .or_else(|| path.file_name())
            .and_then(|s| s.to_str())
        {
            Some(value) => value.to_string(),
            None => "circuit".to_string(),
        }
    };

    let mut combined = name;
    if !main_component.is_empty() && !combined.contains(main_component) {
        combined = format!("{}_{}", combined, main_component);
    }

    // Include a short hash of the full path + main component so two different circuits with the
    // same filename (in different directories) never collide in `build_dir_base/`.
    let hash = short_stable_hash(circuit_path, main_component);
    sanitize_component(&format!("{}__{}", combined, hash))
}

fn short_stable_hash(circuit_path: &str, main_component: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(circuit_path.as_bytes());
    hasher.update(b"|");
    hasher.update(main_component.as_bytes());
    let digest = hasher.finalize();

    // 6 bytes => 12 hex chars, enough to avoid practical collisions while keeping paths short.
    hex::encode(&digest[..6])
}

fn sanitize_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }

    if out.is_empty() {
        "circuit".to_string()
    } else {
        out
    }
}

fn coverage_from_results(results: Vec<ConstraintResult>) -> Option<ExecutionCoverage> {
    if results.is_empty() {
        return None;
    }
    let mut satisfied = Vec::new();
    let mut evaluated = Vec::new();
    let mut value_buckets = Vec::with_capacity(results.len());
    for result in results {
        evaluated.push(result.constraint_id);
        if result.satisfied {
            satisfied.push(result.constraint_id);
        }
        let lhs_bucket = value_bucket_for(&result.lhs_value.0);
        let rhs_bucket = value_bucket_for(&result.rhs_value.0);
        let bucket = lhs_bucket.wrapping_add(rhs_bucket);
        value_buckets.push((result.constraint_id, bucket));
    }
    let mut coverage = ExecutionCoverage::with_constraints(satisfied, evaluated);
    coverage.value_buckets = value_buckets;
    Some(coverage)
}

fn value_bucket_for(value_bytes: &[u8]) -> u8 {
    if value_bytes.is_empty() {
        return 0;
    }
    let first_nonzero = value_bytes.iter().position(|&b| b != 0);
    let first_nonzero = match first_nonzero {
        Some(value) => value,
        None => value_bytes.len(),
    };
    let index_bucket = if first_nonzero > u8::MAX as usize {
        u8::MAX
    } else {
        first_nonzero as u8
    };
    let byte = match value_bytes.get(first_nonzero).copied() {
        Some(byte) => byte,
        None => return index_bucket,
    };
    index_bucket.wrapping_add(byte)
}

/// Upper bound for synthetic witness vector size when mapping backend wire indices.
///
/// This prevents untrusted or corrupted metadata from forcing unbounded allocations.
const MAX_SYNTHETIC_WITNESS_WIRES: usize = 1_000_000;

fn lc_to_terms(lc: &LinearCombination) -> Vec<(usize, FieldElement)> {
    lc.terms
        .iter()
        .map(|(wire, coeff)| (wire.index, coeff.clone()))
        .collect()
}

fn equation_from_deps(id: usize, deps: &[usize], description: &str) -> ConstraintEquation {
    if deps.is_empty() {
        return ConstraintEquation {
            id,
            a_terms: Vec::new(),
            b_terms: Vec::new(),
            c_terms: Vec::new(),
            description: Some(description.to_string()),
        };
    }

    let output = deps[0];
    let inputs = deps
        .iter()
        .skip(1)
        .map(|idx| (*idx, FieldElement::one()))
        .collect();

    ConstraintEquation {
        id,
        a_terms: inputs,
        b_terms: Vec::new(),
        c_terms: vec![(output, FieldElement::one())],
        description: Some(description.to_string()),
    }
}

fn constraint_to_equation(id: usize, constraint: &ExtendedConstraint) -> ConstraintEquation {
    match constraint {
        ExtendedConstraint::R1CS(r1cs) => ConstraintEquation {
            id,
            a_terms: lc_to_terms(&r1cs.a),
            b_terms: lc_to_terms(&r1cs.b),
            c_terms: lc_to_terms(&r1cs.c),
            description: Some("r1cs".to_string()),
        },
        ExtendedConstraint::PlonkGate(gate) => ConstraintEquation {
            id,
            a_terms: vec![(gate.a.index, FieldElement::one())],
            b_terms: vec![(gate.b.index, FieldElement::one())],
            c_terms: vec![(gate.c.index, FieldElement::one())],
            description: Some("plonk_gate".to_string()),
        },
        ExtendedConstraint::CustomGate(custom) => {
            let mut deps = Vec::new();
            for term in &custom.polynomial.terms {
                for (wire, _) in &term.variables {
                    deps.push(wire.index);
                }
            }
            deps.sort_unstable();
            deps.dedup();
            equation_from_deps(id, &deps, "custom_gate")
        }
        ExtendedConstraint::Lookup(lookup) => ConstraintEquation {
            id,
            a_terms: lookup
                .additional_inputs
                .iter()
                .map(|w| (w.index, FieldElement::one()))
                .collect(),
            b_terms: Vec::new(),
            c_terms: vec![(lookup.input.index, FieldElement::one())],
            description: Some("lookup".to_string()),
        },
        ExtendedConstraint::Range(range) => {
            let mut input_terms = Vec::new();
            if let RangeMethod::BitDecomposition { bit_wires } = &range.method {
                input_terms.extend(bit_wires.iter().map(|w| (w.index, FieldElement::one())));
            } else {
                input_terms.push((range.wire.index, FieldElement::one()));
            }

            ConstraintEquation {
                id,
                a_terms: input_terms,
                b_terms: Vec::new(),
                c_terms: vec![(range.wire.index, FieldElement::one())],
                description: Some("range".to_string()),
            }
        }
        ExtendedConstraint::Polynomial(poly) => {
            let mut deps = Vec::new();
            for term in &poly.terms {
                for (wire, _) in &term.variables {
                    deps.push(wire.index);
                }
            }
            deps.sort_unstable();
            deps.dedup();
            equation_from_deps(id, &deps, "polynomial")
        }
        ExtendedConstraint::AcirOpcode(op) => match op {
            AcirOpcode::Arithmetic { a, b, c, .. } => ConstraintEquation {
                id,
                a_terms: lc_to_terms(a),
                b_terms: lc_to_terms(b),
                c_terms: lc_to_terms(c),
                description: Some("acir_arithmetic".to_string()),
            },
            AcirOpcode::BlackBox(op) => {
                let mut deps: Vec<usize> = match op {
                    BlackBoxOp::SHA256 { inputs, outputs }
                    | BlackBoxOp::Blake2s { inputs, outputs }
                    | BlackBoxOp::Blake3 { inputs, outputs }
                    | BlackBoxOp::Keccak256 { inputs, outputs }
                    | BlackBoxOp::Pedersen { inputs, outputs }
                    | BlackBoxOp::FixedBaseScalarMul { inputs, outputs }
                    | BlackBoxOp::RecursiveAggregation { inputs, outputs } => inputs
                        .iter()
                        .map(|w| w.index)
                        .chain(outputs.iter().map(|w| w.index))
                        .collect(),
                    BlackBoxOp::SchnorrVerify { inputs, output }
                    | BlackBoxOp::EcdsaSecp256k1 { inputs, output } => inputs
                        .iter()
                        .map(|w| w.index)
                        .chain(std::iter::once(output.index))
                        .collect(),
                    BlackBoxOp::Range { input, .. } => vec![input.index],
                };
                deps.sort_unstable();
                deps.dedup();
                equation_from_deps(id, &deps, "acir_blackbox")
            }
            AcirOpcode::MemoryOp { address, value, .. } => {
                let deps = vec![address.index, value.index];
                equation_from_deps(id, &deps, "acir_memory")
            }
            AcirOpcode::Brillig { inputs, outputs } => {
                let deps: Vec<usize> = inputs
                    .iter()
                    .map(|w| w.index)
                    .chain(outputs.iter().map(|w| w.index))
                    .collect();
                equation_from_deps(id, &deps, "acir_brillig")
            }
            AcirOpcode::Range { input, .. } => equation_from_deps(id, &[input.index], "acir_range"),
        },
        ExtendedConstraint::AirConstraint(_) => ConstraintEquation {
            id,
            a_terms: Vec::new(),
            b_terms: Vec::new(),
            c_terms: Vec::new(),
            description: Some("air".to_string()),
        },
        ExtendedConstraint::Boolean { wire } => ConstraintEquation {
            id,
            a_terms: vec![(wire.index, FieldElement::one())],
            b_terms: Vec::new(),
            c_terms: vec![(wire.index, FieldElement::one())],
            description: Some("boolean".to_string()),
        },
        ExtendedConstraint::Equal { a, b } => ConstraintEquation {
            id,
            a_terms: vec![(b.index, FieldElement::one())],
            b_terms: Vec::new(),
            c_terms: vec![(a.index, FieldElement::one())],
            description: Some("equal".to_string()),
        },
        ExtendedConstraint::Add { a, b, c } => ConstraintEquation {
            id,
            a_terms: vec![(a.index, FieldElement::one())],
            b_terms: vec![(b.index, FieldElement::one())],
            c_terms: vec![(c.index, FieldElement::one())],
            description: Some("add".to_string()),
        },
        ExtendedConstraint::Mul { a, b, c } => ConstraintEquation {
            id,
            a_terms: vec![(a.index, FieldElement::one())],
            b_terms: vec![(b.index, FieldElement::one())],
            c_terms: vec![(c.index, FieldElement::one())],
            description: Some("mul".to_string()),
        },
        ExtendedConstraint::Constant { wire, .. } => ConstraintEquation {
            id,
            a_terms: Vec::new(),
            b_terms: Vec::new(),
            c_terms: vec![(wire.index, FieldElement::one())],
            description: Some("constant".to_string()),
        },
    }
}

fn insert_wire_label(labels: &mut HashMap<usize, String>, wire: &WireRef) {
    if let Some(name) = &wire.name {
        labels.entry(wire.index).or_insert_with(|| name.clone());
    }
}

fn collect_labels_from_lc(labels: &mut HashMap<usize, String>, lc: &LinearCombination) {
    for (wire, _) in &lc.terms {
        insert_wire_label(labels, wire);
    }
}

fn collect_wire_labels_from_constraint(
    labels: &mut HashMap<usize, String>,
    constraint: &ExtendedConstraint,
) {
    match constraint {
        ExtendedConstraint::R1CS(r1cs) => {
            collect_labels_from_lc(labels, &r1cs.a);
            collect_labels_from_lc(labels, &r1cs.b);
            collect_labels_from_lc(labels, &r1cs.c);
        }
        ExtendedConstraint::PlonkGate(gate) => {
            insert_wire_label(labels, &gate.a);
            insert_wire_label(labels, &gate.b);
            insert_wire_label(labels, &gate.c);
        }
        ExtendedConstraint::CustomGate(custom) => {
            for term in &custom.polynomial.terms {
                for (wire, _) in &term.variables {
                    insert_wire_label(labels, wire);
                }
            }
        }
        ExtendedConstraint::Lookup(lookup) => {
            insert_wire_label(labels, &lookup.input);
            for wire in &lookup.additional_inputs {
                insert_wire_label(labels, wire);
            }
        }
        ExtendedConstraint::Range(range) => {
            insert_wire_label(labels, &range.wire);
            if let RangeMethod::BitDecomposition { bit_wires } = &range.method {
                for wire in bit_wires {
                    insert_wire_label(labels, wire);
                }
            }
        }
        ExtendedConstraint::Polynomial(poly) => {
            for term in &poly.terms {
                for (wire, _) in &term.variables {
                    insert_wire_label(labels, wire);
                }
            }
        }
        ExtendedConstraint::AcirOpcode(op) => match op {
            AcirOpcode::Arithmetic { a, b, c, .. } => {
                collect_labels_from_lc(labels, a);
                collect_labels_from_lc(labels, b);
                collect_labels_from_lc(labels, c);
            }
            AcirOpcode::BlackBox(op) => match op {
                BlackBoxOp::SHA256 { inputs, outputs }
                | BlackBoxOp::Blake2s { inputs, outputs }
                | BlackBoxOp::Blake3 { inputs, outputs }
                | BlackBoxOp::Keccak256 { inputs, outputs }
                | BlackBoxOp::Pedersen { inputs, outputs }
                | BlackBoxOp::FixedBaseScalarMul { inputs, outputs }
                | BlackBoxOp::RecursiveAggregation { inputs, outputs } => {
                    for wire in inputs.iter().chain(outputs.iter()) {
                        insert_wire_label(labels, wire);
                    }
                }
                BlackBoxOp::SchnorrVerify { inputs, output }
                | BlackBoxOp::EcdsaSecp256k1 { inputs, output } => {
                    for wire in inputs {
                        insert_wire_label(labels, wire);
                    }
                    insert_wire_label(labels, output);
                }
                BlackBoxOp::Range { input, .. } => {
                    insert_wire_label(labels, input);
                }
            },
            AcirOpcode::MemoryOp { address, value, .. } => {
                insert_wire_label(labels, address);
                insert_wire_label(labels, value);
            }
            AcirOpcode::Brillig { inputs, outputs } => {
                for wire in inputs.iter().chain(outputs.iter()) {
                    insert_wire_label(labels, wire);
                }
            }
            AcirOpcode::Range { input, .. } => {
                insert_wire_label(labels, input);
            }
        },
        ExtendedConstraint::AirConstraint(_) => {}
        ExtendedConstraint::Boolean { wire } => insert_wire_label(labels, wire),
        ExtendedConstraint::Equal { a, b } => {
            insert_wire_label(labels, a);
            insert_wire_label(labels, b);
        }
        ExtendedConstraint::Add { a, b, c } | ExtendedConstraint::Mul { a, b, c } => {
            insert_wire_label(labels, a);
            insert_wire_label(labels, b);
            insert_wire_label(labels, c);
        }
        ExtendedConstraint::Constant { wire, .. } => insert_wire_label(labels, wire),
    }
}

/// Factory for creating circuit executors based on framework type
pub struct ExecutorFactory;

impl ExecutorFactory {
    /// Create an executor for the given framework and circuit
    pub fn create(
        framework: Framework,
        circuit_path: &str,
        main_component: &str,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        Self::create_with_options(
            framework,
            circuit_path,
            main_component,
            &ExecutorFactoryOptions::default(),
        )
    }

    /// Create an executor with explicit factory options (e.g., build dir overrides).
    pub fn create_with_options(
        framework: Framework,
        circuit_path: &str,
        main_component: &str,
        options: &ExecutorFactoryOptions,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        match framework {
            Framework::Circom => {
                Self::create_circom_executor(circuit_path, main_component, options)
            }
            Framework::Noir => Self::create_noir_executor(circuit_path, main_component, options),
            Framework::Halo2 => Self::create_halo2_executor(circuit_path, main_component, options),
            Framework::Cairo => Self::create_cairo_executor(circuit_path, main_component, options),
        }
    }

    /// Create a Circom executor
    fn create_circom_executor(
        circuit_path: &str,
        main_component: &str,
        options: &ExecutorFactoryOptions,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        use crate::targets::CircomTarget;

        // Check if circom is available
        match CircomTarget::check_circom_available() {
            Ok(version) => {
                tracing::info!("Using Circom backend: {}", version);
                if !options.circom_include_paths.is_empty() {
                    tracing::info!(
                        "Using Circom include paths: {:?}",
                        options.circom_include_paths
                    );
                }
                if let Some(snarkjs_path) = &options.circom_snarkjs_path {
                    tracing::info!("Using snarkjs CLI: {:?}", snarkjs_path);
                }
                let build_dir =
                    options.resolve_build_dir(Framework::Circom, circuit_path, main_component);
                let mut executor = CircomExecutor::new_with_options(
                    circuit_path,
                    main_component,
                    CircomExecutorOptions {
                        build_dir,
                        include_paths: options.circom_include_paths.clone(),
                        ptau_path: options.circom_ptau_path.clone(),
                        snarkjs_path: options.circom_snarkjs_path.clone(),
                        skip_compile_if_artifacts: options.circom_skip_compile_if_artifacts,
                        skip_constraint_check: options.circom_skip_constraint_check,
                        witness_sanity_check: options.circom_witness_sanity_check,
                    },
                )?;
                if options.circom_auto_setup_keys {
                    tracing::info!("Auto-generating Circom proving/verification keys");
                    executor.setup_keys()?;
                }
                Ok(Arc::new(executor))
            }
            Err(e) => {
                anyhow::bail!(
                    "Circom backend required but not available: {}. Install circom and retry.",
                    e
                );
            }
        }
    }

    /// Create a Noir executor
    fn create_noir_executor(
        circuit_path: &str,
        main_component: &str,
        options: &ExecutorFactoryOptions,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        use crate::targets::NoirTarget;

        match NoirTarget::check_nargo_available() {
            Ok(version) => {
                tracing::info!("Using Noir backend: {}", version);
                let build_dir =
                    options.resolve_build_dir(Framework::Noir, circuit_path, main_component);
                let executor = match build_dir {
                    Some(dir) => NoirExecutor::new_with_build_dir(circuit_path, dir)?,
                    None => NoirExecutor::new(circuit_path)?,
                };
                Ok(Arc::new(executor))
            }
            Err(e) => {
                anyhow::bail!(
                    "Noir backend required but not available: {}. Install nargo and retry.",
                    e
                );
            }
        }
    }

    /// Create a Halo2 executor
    fn create_halo2_executor(
        circuit_path: &str,
        main_component: &str,
        options: &ExecutorFactoryOptions,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        let build_dir = options.resolve_build_dir(Framework::Halo2, circuit_path, main_component);
        let executor = match build_dir {
            Some(dir) => Halo2Executor::new_with_build_dir(circuit_path, main_component, dir)?,
            None => Halo2Executor::new(circuit_path, main_component)?,
        };
        Ok(Arc::new(executor))
    }

    /// Create a Cairo executor
    fn create_cairo_executor(
        circuit_path: &str,
        main_component: &str,
        options: &ExecutorFactoryOptions,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        use crate::targets::CairoTarget;

        match CairoTarget::check_cairo_available() {
            Ok((version, ver_str)) => {
                tracing::info!("Using Cairo backend ({:?}): {}", version, ver_str);
                let build_dir =
                    options.resolve_build_dir(Framework::Cairo, circuit_path, main_component);
                let executor = match build_dir {
                    Some(dir) => CairoExecutor::new_with_build_dir(circuit_path, dir)?,
                    None => CairoExecutor::new(circuit_path)?,
                };
                Ok(Arc::new(executor))
            }
            Err(e) => {
                anyhow::bail!(
                    "Cairo backend required but not available: {}. Install cairo/scarb and retry.",
                    e
                );
            }
        }
    }
}

/// Circom executor wrapper
pub struct CircomExecutor {
    target: crate::targets::CircomTarget,
    constraints: OnceLock<Vec<ConstraintEquation>>,
}

#[derive(Debug, Clone)]
pub struct CircomExecutorOptions {
    pub build_dir: Option<PathBuf>,
    pub include_paths: Vec<PathBuf>,
    pub ptau_path: Option<PathBuf>,
    pub snarkjs_path: Option<PathBuf>,
    pub skip_compile_if_artifacts: bool,
    pub skip_constraint_check: bool,
    pub witness_sanity_check: bool,
}

impl Default for CircomExecutorOptions {
    fn default() -> Self {
        Self {
            build_dir: None,
            include_paths: Vec::new(),
            ptau_path: None,
            snarkjs_path: None,
            skip_compile_if_artifacts: false,
            skip_constraint_check: false,
            witness_sanity_check: true,
        }
    }
}

impl CircomExecutor {
    fn default_include_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        match std::env::var("CIRCOM_INCLUDE_PATHS") {
            Ok(raw) => {
                let separator = if cfg!(windows) { ';' } else { ':' };
                for entry in raw.split(separator) {
                    let entry = entry.trim();
                    if !entry.is_empty() {
                        paths.push(PathBuf::from(entry));
                    }
                }
            }
            Err(std::env::VarError::NotPresent) => {}
            Err(e) => panic!("Invalid CIRCOM_INCLUDE_PATHS value: {}", e),
        }

        for candidate in ["third_party", "third_party/node_modules", "node_modules"] {
            let base = PathBuf::from(candidate);
            if base.join("circomlib").exists() {
                paths.push(base);
            }
        }

        paths
    }

    pub fn new(circuit_path: &str, main_component: &str) -> anyhow::Result<Self> {
        let options = CircomExecutorOptions {
            include_paths: Self::default_include_paths(),
            ..CircomExecutorOptions::default()
        };
        Self::new_with_options(circuit_path, main_component, options)
    }

    pub fn new_with_build_dir(
        circuit_path: &str,
        main_component: &str,
        build_dir: PathBuf,
    ) -> anyhow::Result<Self> {
        let options = CircomExecutorOptions {
            build_dir: Some(build_dir),
            ..CircomExecutorOptions::default()
        };
        Self::new_with_options(circuit_path, main_component, options)
    }

    pub fn new_with_options(
        circuit_path: &str,
        main_component: &str,
        options: CircomExecutorOptions,
    ) -> anyhow::Result<Self> {
        let CircomExecutorOptions {
            build_dir,
            mut include_paths,
            ptau_path,
            snarkjs_path,
            skip_compile_if_artifacts,
            skip_constraint_check,
            witness_sanity_check,
        } = options;

        if skip_constraint_check {
            anyhow::bail!(
                "circom_skip_constraint_check=true is disallowed because it disables real constraint coverage"
            );
        }

        if include_paths.is_empty() {
            include_paths = Self::default_include_paths();
        }

        let mut target = crate::targets::CircomTarget::new(circuit_path, main_component)?
            .with_skip_compile_if_artifacts(skip_compile_if_artifacts)
            .with_witness_sanity_check(witness_sanity_check);
        if let Some(dir) = build_dir {
            target = target.with_build_dir(dir);
        }
        if !include_paths.is_empty() {
            target = target.with_include_paths(include_paths);
        }
        if let Some(path) = ptau_path {
            target = target.with_ptau_path(path);
        }
        if let Some(path) = snarkjs_path {
            target = target.with_snarkjs_path(path);
        }
        target.compile()?;

        let constraints = target.load_constraints().with_context(|| {
            format!(
                "Failed to load Circom constraints for '{}' (component '{}')",
                circuit_path, main_component
            )
        })?;
        if constraints.is_empty() {
            anyhow::bail!(
                "No Circom constraints available for '{}' (component '{}'). \
                 Ensure .r1cs and exported constraints are present; real coverage is required.",
                circuit_path,
                main_component
            );
        }

        let constraints_cache = OnceLock::new();
        constraints_cache.set(constraints).map_err(|_| {
            anyhow::anyhow!("Internal error: failed to initialize Circom constraints cache")
        })?;

        Ok(Self {
            target,
            constraints: constraints_cache,
        })
    }

    pub fn setup_keys(&mut self) -> anyhow::Result<()> {
        self.target.setup_keys()
    }
}

#[async_trait]
impl CircuitExecutor for CircomExecutor {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn name(&self) -> &str {
        use crate::targets::TargetCircuit;
        self.target.name()
    }

    fn circuit_info(&self) -> CircuitInfo {
        use crate::targets::TargetCircuit;
        CircuitInfo {
            name: self.target.name().to_string(),
            num_constraints: self.target.num_constraints(),
            num_private_inputs: self.target.num_private_inputs(),
            num_public_inputs: self.target.num_public_inputs(),
            num_outputs: self.target.num_public_inputs().max(1),
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        let start = std::time::Instant::now();
        match self.target.calculate_witness(inputs) {
            Ok(witness) => {
                let outputs = self.target.outputs_from_witness(&witness);
                let coverage = match coverage_from_results(self.check_constraints(&witness)) {
                    Some(coverage) => coverage,
                    None => {
                        return ExecutionResult::failure(
                            "Constraint coverage unavailable: Circom execution requires real constraint checks".to_string(),
                        )
                        .with_time(start.elapsed().as_micros() as u64);
                    }
                };
                ExecutionResult::success(outputs, coverage)
                    .with_time(start.elapsed().as_micros() as u64)
            }
            Err(e) => ExecutionResult::failure(e.to_string()),
        }
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        use crate::targets::TargetCircuit;
        self.target.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        use crate::targets::TargetCircuit;
        self.target.verify(proof, public_inputs)
    }

    fn constraint_inspector(&self) -> Option<&dyn ConstraintInspector> {
        Some(self)
    }

    fn field_modulus(&self) -> [u8; 32] {
        self.target.field_modulus()
    }

    fn field_name(&self) -> &str {
        self.target.field_name()
    }
}

impl ConstraintInspector for CircomExecutor {
    fn get_constraints(&self) -> Vec<ConstraintEquation> {
        self.constraints
            .get()
            .expect("Circom constraints cache not initialized; executor construction must preload constraints")
            .clone()
    }

    fn check_constraints(&self, witness: &[FieldElement]) -> Vec<ConstraintResult> {
        fn eval_linear(terms: &[(usize, FieldElement)], witness: &[FieldElement]) -> FieldElement {
            let mut acc = FieldElement::zero();
            for (idx, coeff) in terms {
                if let Some(value) = witness.get(*idx) {
                    acc = acc.add(&value.mul(coeff));
                }
            }
            acc
        }

        self.get_constraints()
            .iter()
            .map(|c| {
                let a_val = eval_linear(&c.a_terms, witness);
                let b_val = eval_linear(&c.b_terms, witness);
                let c_val = eval_linear(&c.c_terms, witness);
                let lhs = a_val.mul(&b_val);
                ConstraintResult {
                    constraint_id: c.id,
                    satisfied: lhs == c_val,
                    lhs_value: lhs,
                    rhs_value: c_val,
                }
            })
            .collect()
    }

    fn get_constraint_dependencies(&self) -> Vec<Vec<usize>> {
        self.get_constraints()
            .iter()
            .map(|c| {
                let mut deps: Vec<usize> = c
                    .a_terms
                    .iter()
                    .chain(c.b_terms.iter())
                    .chain(c.c_terms.iter())
                    .map(|(idx, _)| *idx)
                    .collect();
                deps.sort_unstable();
                deps.dedup();
                deps
            })
            .collect()
    }

    fn public_input_indices(&self) -> Vec<usize> {
        self.target.public_input_indices()
    }

    fn private_input_indices(&self) -> Vec<usize> {
        self.target.private_input_indices()
    }

    fn output_indices(&self) -> Vec<usize> {
        self.target.output_signal_indices()
    }

    fn wire_labels(&self) -> std::collections::HashMap<usize, String> {
        self.target.wire_labels()
    }
}

/// Noir executor wrapper
pub struct NoirExecutor {
    target: crate::targets::NoirTarget,
}

impl NoirExecutor {
    pub fn new(project_path: &str) -> anyhow::Result<Self> {
        let mut target = crate::targets::NoirTarget::new(project_path)?;
        target.compile()?;
        Ok(Self { target })
    }

    pub fn new_with_build_dir(project_path: &str, build_dir: PathBuf) -> anyhow::Result<Self> {
        let mut target = crate::targets::NoirTarget::new(project_path)?.with_build_dir(build_dir);
        target.compile()?;
        Ok(Self { target })
    }

    fn build_witness_with_outputs(
        &self,
        inputs: &[FieldElement],
        outputs: &[FieldElement],
    ) -> anyhow::Result<Vec<FieldElement>> {
        let public = self.target.public_input_indices();
        let private = self.target.private_input_indices();
        let output_indices = self.target.output_signal_indices();

        let max_idx = public
            .iter()
            .chain(private.iter())
            .chain(output_indices.iter())
            .copied()
            .max();
        let max_idx = max_idx.unwrap_or_default();
        if max_idx > MAX_SYNTHETIC_WITNESS_WIRES {
            anyhow::bail!(
                "Noir metadata reported wire index {} above safety cap {}",
                max_idx,
                MAX_SYNTHETIC_WITNESS_WIRES
            );
        }

        let witness_len = max_idx
            .max(1)
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Noir witness length overflow"))?;
        let mut witness = vec![FieldElement::zero(); witness_len];
        witness[0] = FieldElement::one();

        for (idx, wire_idx) in public.iter().chain(private.iter()).enumerate() {
            if idx >= inputs.len() {
                break;
            }
            if *wire_idx < witness.len() {
                witness[*wire_idx] = inputs[idx].clone();
            }
        }

        for (value, wire_idx) in outputs.iter().zip(output_indices.iter()) {
            if *wire_idx < witness.len() {
                witness[*wire_idx] = value.clone();
            }
        }

        Ok(witness)
    }
}

#[async_trait]
impl CircuitExecutor for NoirExecutor {
    fn framework(&self) -> Framework {
        Framework::Noir
    }

    fn name(&self) -> &str {
        use crate::targets::TargetCircuit;
        self.target.name()
    }

    fn circuit_info(&self) -> CircuitInfo {
        use crate::targets::TargetCircuit;
        CircuitInfo {
            name: self.target.name().to_string(),
            num_constraints: self.target.num_constraints(),
            num_private_inputs: self.target.num_private_inputs(),
            num_public_inputs: self.target.num_public_inputs(),
            num_outputs: self.target.num_public_inputs().max(1),
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        use crate::targets::TargetCircuit;
        let start = std::time::Instant::now();

        match self.target.execute(inputs) {
            Ok(outputs) => {
                let coverage = match self.build_witness_with_outputs(inputs, &outputs) {
                    Ok(witness) => match coverage_from_results(self.check_constraints(&witness)) {
                        Some(coverage) => coverage,
                        None => {
                            return ExecutionResult::failure(
                                "Noir constraint coverage unavailable: refusing output-hash fallback".to_string(),
                            )
                            .with_time(start.elapsed().as_micros() as u64);
                        }
                    },
                    Err(err) => {
                        return ExecutionResult::failure(format!(
                            "Noir witness mapping failed for constraint checking: {}",
                            err
                        ))
                        .with_time(start.elapsed().as_micros() as u64);
                    }
                };
                ExecutionResult::success(outputs, coverage)
                    .with_time(start.elapsed().as_micros() as u64)
            }
            Err(e) => ExecutionResult::failure(e.to_string()),
        }
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        use crate::targets::TargetCircuit;
        self.target.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        use crate::targets::TargetCircuit;
        self.target.verify(proof, public_inputs)
    }

    fn constraint_inspector(&self) -> Option<&dyn ConstraintInspector> {
        Some(self)
    }

    fn field_modulus(&self) -> [u8; 32] {
        self.target.field_modulus()
    }

    fn field_name(&self) -> &str {
        self.target.field_name()
    }
}

impl ConstraintInspector for NoirExecutor {
    fn get_constraints(&self) -> Vec<ConstraintEquation> {
        match self.target.load_constraints() {
            Ok(constraints) => constraints,
            Err(err) => {
                tracing::error!("Failed to load Noir constraints: {}", err);
                Vec::new()
            }
        }
    }

    fn check_constraints(&self, witness: &[FieldElement]) -> Vec<ConstraintResult> {
        fn eval_linear(
            terms: &[(usize, FieldElement)],
            witness: &[FieldElement],
        ) -> Option<FieldElement> {
            let mut acc = FieldElement::zero();
            for (idx, coeff) in terms {
                let value = witness.get(*idx)?;
                acc = acc.add(&value.mul(coeff));
            }
            Some(acc)
        }

        let constraints = self.get_constraints();
        if constraints.is_empty() {
            return Vec::new();
        }

        let mut known_indices: HashSet<usize> = self
            .target
            .public_input_indices()
            .into_iter()
            .chain(self.target.private_input_indices())
            .chain(self.target.output_signal_indices())
            .collect();
        known_indices.insert(0);

        let mut results = Vec::new();

        for constraint in constraints {
            let deps: HashSet<usize> = constraint
                .a_terms
                .iter()
                .chain(constraint.b_terms.iter())
                .chain(constraint.c_terms.iter())
                .map(|(idx, _)| *idx)
                .collect();

            if !deps.is_subset(&known_indices) {
                continue;
            }

            let (Some(a_val), Some(b_val), Some(c_val)) = (
                eval_linear(&constraint.a_terms, witness),
                eval_linear(&constraint.b_terms, witness),
                eval_linear(&constraint.c_terms, witness),
            ) else {
                continue;
            };

            let lhs = a_val.mul(&b_val);
            results.push(ConstraintResult {
                constraint_id: constraint.id,
                satisfied: lhs == c_val,
                lhs_value: lhs,
                rhs_value: c_val,
            });
        }

        results
    }

    fn get_constraint_dependencies(&self) -> Vec<Vec<usize>> {
        self.get_constraints()
            .iter()
            .map(|c| {
                let mut deps: Vec<usize> = c
                    .a_terms
                    .iter()
                    .chain(c.b_terms.iter())
                    .chain(c.c_terms.iter())
                    .map(|(idx, _)| *idx)
                    .collect();
                deps.sort_unstable();
                deps.dedup();
                deps
            })
            .collect()
    }

    fn public_input_indices(&self) -> Vec<usize> {
        self.target.public_input_indices()
    }

    fn private_input_indices(&self) -> Vec<usize> {
        self.target.private_input_indices()
    }

    fn output_indices(&self) -> Vec<usize> {
        self.target.output_signal_indices()
    }

    fn wire_labels(&self) -> std::collections::HashMap<usize, String> {
        self.target.wire_labels()
    }
}

/// Halo2 executor wrapper
pub struct Halo2Executor {
    target: crate::targets::Halo2Target,
}

impl Halo2Executor {
    pub fn new(circuit_path: &str, _main_component: &str) -> anyhow::Result<Self> {
        let mut target = crate::targets::Halo2Target::new(circuit_path)?;
        target.setup()?;
        Ok(Self { target })
    }

    pub fn new_with_build_dir(
        circuit_path: &str,
        _main_component: &str,
        build_dir: PathBuf,
    ) -> anyhow::Result<Self> {
        let mut target = crate::targets::Halo2Target::new(circuit_path)?.with_build_dir(build_dir);
        target.setup()?;
        Ok(Self { target })
    }
}

#[async_trait]
impl CircuitExecutor for Halo2Executor {
    fn framework(&self) -> Framework {
        Framework::Halo2
    }

    fn name(&self) -> &str {
        use crate::targets::TargetCircuit;
        self.target.name()
    }

    fn circuit_info(&self) -> CircuitInfo {
        use crate::targets::TargetCircuit;
        CircuitInfo {
            name: self.target.name().to_string(),
            num_constraints: self.target.num_constraints(),
            num_private_inputs: self.target.num_private_inputs(),
            num_public_inputs: self.target.num_public_inputs(),
            num_outputs: 1,
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        use crate::targets::TargetCircuit;
        let start = std::time::Instant::now();

        match self.target.execute(inputs) {
            Ok(outputs) => {
                let coverage = match coverage_from_results(self.check_constraints(inputs)) {
                    Some(value) => value,
                    None => {
                        return ExecutionResult::failure(
                            "Halo2 constraint coverage unavailable: refusing output-hash fallback"
                                .to_string(),
                        )
                        .with_time(start.elapsed().as_micros() as u64);
                    }
                };
                ExecutionResult::success(outputs, coverage)
                    .with_time(start.elapsed().as_micros() as u64)
            }
            Err(e) => ExecutionResult::failure(e.to_string()),
        }
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        use crate::targets::TargetCircuit;
        self.target.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        use crate::targets::TargetCircuit;
        self.target.verify(proof, public_inputs)
    }

    fn constraint_inspector(&self) -> Option<&dyn ConstraintInspector> {
        Some(self)
    }

    fn field_modulus(&self) -> [u8; 32] {
        self.target.field_modulus()
    }

    fn field_name(&self) -> &str {
        self.target.field_name()
    }
}

impl ConstraintInspector for Halo2Executor {
    fn get_constraints(&self) -> Vec<ConstraintEquation> {
        let parsed = self.target.load_plonk_constraints();
        parsed
            .constraints
            .iter()
            .enumerate()
            .map(|(idx, constraint)| constraint_to_equation(idx, constraint))
            .collect()
    }

    fn check_constraints(&self, witness: &[FieldElement]) -> Vec<ConstraintResult> {
        let parsed = self.target.load_plonk_constraints();
        if parsed.constraints.is_empty() {
            return Vec::new();
        }

        let wire_values: std::collections::HashMap<usize, FieldElement> = witness
            .iter()
            .enumerate()
            .map(|(idx, value)| (idx, value.clone()))
            .collect();

        let mut checker =
            ConstraintChecker::new().with_unknown_lookup_policy(UnknownLookupPolicy::FailClosed);
        for (id, table) in parsed.lookup_tables {
            checker.add_table(id, table);
        }

        let mut results = Vec::new();
        for (idx, constraint) in parsed.constraints.iter().enumerate() {
            let deps = constraint.wire_dependencies();
            if deps.iter().any(|d| *d >= witness.len()) {
                continue;
            }

            let evaluation = checker.evaluate(constraint, &wire_values);
            results.push(ConstraintResult {
                constraint_id: idx,
                satisfied: evaluation.satisfied,
                lhs_value: evaluation.lhs,
                rhs_value: evaluation.rhs,
            });
        }

        results
    }

    fn get_constraint_dependencies(&self) -> Vec<Vec<usize>> {
        let parsed = self.target.load_plonk_constraints();
        parsed
            .constraints
            .iter()
            .map(|constraint| constraint.wire_dependencies())
            .collect()
    }

    fn public_input_indices(&self) -> Vec<usize> {
        (0..self.target.num_public_inputs()).collect()
    }

    fn private_input_indices(&self) -> Vec<usize> {
        let start = self.target.num_public_inputs();
        let end = start + self.target.num_private_inputs();
        (start..end).collect()
    }

    fn wire_labels(&self) -> std::collections::HashMap<usize, String> {
        let parsed = self.target.load_plonk_constraints();
        let mut labels = HashMap::new();
        for constraint in &parsed.constraints {
            collect_wire_labels_from_constraint(&mut labels, constraint);
        }
        labels
    }
}

/// Cairo executor wrapper
pub struct CairoExecutor {
    target: crate::targets::CairoTarget,
}

impl CairoExecutor {
    pub fn new(source_path: &str) -> anyhow::Result<Self> {
        let mut target = crate::targets::CairoTarget::new(source_path)?;
        target.compile()?;
        Ok(Self { target })
    }

    pub fn new_with_build_dir(source_path: &str, build_dir: PathBuf) -> anyhow::Result<Self> {
        let mut target = crate::targets::CairoTarget::new(source_path)?.with_build_dir(build_dir);
        target.compile()?;
        Ok(Self { target })
    }
}

#[async_trait]
impl CircuitExecutor for CairoExecutor {
    fn framework(&self) -> Framework {
        Framework::Cairo
    }

    fn name(&self) -> &str {
        use crate::targets::TargetCircuit;
        self.target.name()
    }

    fn circuit_info(&self) -> CircuitInfo {
        use crate::targets::TargetCircuit;
        CircuitInfo {
            name: self.target.name().to_string(),
            num_constraints: self.target.num_constraints(),
            num_private_inputs: self.target.num_private_inputs(),
            num_public_inputs: self.target.num_public_inputs(),
            num_outputs: self.target.num_public_inputs().max(1),
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        use crate::targets::TargetCircuit;
        let start = std::time::Instant::now();

        match self.target.execute(inputs) {
            Ok(outputs) => {
                let coverage = match coverage_from_results(self.check_constraints(inputs)) {
                    Some(value) => value,
                    None => {
                        return ExecutionResult::failure(
                            "Cairo constraint coverage unavailable: refusing output-hash fallback"
                                .to_string(),
                        )
                        .with_time(start.elapsed().as_micros() as u64);
                    }
                };
                ExecutionResult::success(outputs, coverage)
                    .with_time(start.elapsed().as_micros() as u64)
            }
            Err(e) => ExecutionResult::failure(e.to_string()),
        }
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        use crate::targets::TargetCircuit;
        self.target.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        use crate::targets::TargetCircuit;
        self.target.verify(proof, public_inputs)
    }

    fn constraint_inspector(&self) -> Option<&dyn ConstraintInspector> {
        Some(self)
    }

    fn field_modulus(&self) -> [u8; 32] {
        self.target.field_modulus()
    }

    fn field_name(&self) -> &str {
        self.target.field_name()
    }
}

impl ConstraintInspector for CairoExecutor {
    fn get_constraints(&self) -> Vec<ConstraintEquation> {
        Vec::new()
    }

    fn check_constraints(&self, _witness: &[FieldElement]) -> Vec<ConstraintResult> {
        Vec::new()
    }

    fn get_constraint_dependencies(&self) -> Vec<Vec<usize>> {
        Vec::new()
    }

    fn public_input_indices(&self) -> Vec<usize> {
        self.output_indices()
    }

    fn private_input_indices(&self) -> Vec<usize> {
        (0..self.target.num_private_inputs()).collect()
    }

    fn output_indices(&self) -> Vec<usize> {
        let start = self.target.num_private_inputs();
        let end = start + self.target.num_public_inputs();
        (start..end).collect()
    }

    fn wire_labels(&self) -> std::collections::HashMap<usize, String> {
        self.target.wire_labels()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_result() {
        let result =
            ExecutionResult::success(vec![FieldElement::one()], ExecutionCoverage::default());
        assert!(result.success);
        assert!(result.error.is_none());

        let failure = ExecutionResult::failure("test error".to_string());
        assert!(!failure.success);
        assert_eq!(failure.error, Some("test error".to_string()));
    }

    #[test]
    fn test_halo2_plonk_constraint_checking() {
        let json = r#"
        {
          "name": "test",
          "k": 4,
          "advice_columns": 3,
          "fixed_columns": 0,
          "instance_columns": 0,
          "constraints": 2,
          "private_inputs": 3,
          "public_inputs": 0,
          "lookups": 1,
          "tables": {
            "0": { "name": "tiny", "num_columns": 1, "entries": [[2], [3]] }
          },
          "gates": [
            { "a": 1, "b": 2, "c": 3, "q_l": "1", "q_r": "1", "q_o": "-1", "q_m": "0", "q_c": "0" }
          ],
          "lookups": [
            { "table_id": 0, "input": 1 }
          ]
        }
        "#;

        let temp = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        std::fs::write(temp.path(), json).unwrap();

        let executor = Halo2Executor::new(temp.path().to_str().unwrap(), "main").unwrap();
        let inspector = executor.constraint_inspector().unwrap();

        let witness = vec![
            FieldElement::one(),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
            FieldElement::from_u64(5),
        ];

        let results = inspector.check_constraints(&witness);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.satisfied));
    }

    #[test]
    fn test_halo2_constraint_checks_with_json_spec() {
        let json = r#"
        {
          "name": "test",
          "k": 4,
          "advice_columns": 3,
          "fixed_columns": 0,
          "instance_columns": 0,
          "constraints": 2,
          "private_inputs": 3,
          "public_inputs": 0,
          "lookups": 1,
          "tables": {
            "0": { "name": "tiny", "num_columns": 1, "entries": [[2], [3]] }
          },
          "gates": [
            { "a": 1, "b": 2, "c": 3, "q_l": "1", "q_r": "1", "q_o": "-1", "q_m": "0", "q_c": "0" }
          ],
          "lookups": [
            { "table_id": 0, "input": 1 }
          ]
        }
        "#;

        let temp = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        std::fs::write(temp.path(), json).unwrap();

        let executor = Halo2Executor::new(temp.path().to_str().unwrap(), "main").unwrap();
        let inputs = vec![
            FieldElement::one(),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
            FieldElement::from_u64(5),
        ];

        let result = executor.execute_sync(&inputs);
        assert!(result.success);

        let inspector = executor.constraint_inspector().unwrap();
        let checks = inspector.check_constraints(&inputs);
        assert_eq!(checks.len(), 2);
        assert!(checks.iter().all(|c| c.satisfied));
    }
}
