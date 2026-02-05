//! Complex Constraint Types for ZK Circuits
//!
//! Supports constraint types beyond basic R1CS:
//! - Lookup tables (Plookup, Caulk)
//! - Custom gates (PLONK)
//! - Range constraints
//! - Polynomial constraints
//! - ACIR opcodes

use crate::fuzzer::FieldElement;
use num_bigint::BigUint;
use std::collections::HashMap;

use super::symbolic::{SymbolicConstraint, SymbolicValue};

#[cfg(feature = "acir-bytecode")]
use {base64::Engine, flate2::read::GzDecoder, std::io::Read};

const DEFAULT_LOOKUP_ROW_LIMIT: usize = 256;

/// Extended constraint types for different proving systems
#[derive(Debug, Clone)]
pub enum ExtendedConstraint {
    /// Standard R1CS: A * B = C
    R1CS(R1CSConstraint),

    /// PLONK custom gate: q_L*a + q_R*b + q_O*c + q_M*a*b + q_C = 0
    PlonkGate(PlonkGate),

    /// Custom gate expressed as a named polynomial
    CustomGate(CustomGateConstraint),

    /// Lookup constraint: value is in table
    Lookup(LookupConstraint),

    /// Range constraint: 0 <= value < 2^bits
    Range(RangeConstraint),

    /// Polynomial constraint: P(x1, x2, ...) = 0
    Polynomial(PolynomialConstraint),

    /// ACIR opcode (Noir)
    AcirOpcode(AcirOpcode),

    /// Cairo AIR constraint
    AirConstraint(AirConstraint),

    /// Boolean constraint: x ∈ {0, 1}
    Boolean { wire: WireRef },

    /// Equality constraint: a = b
    Equal { a: WireRef, b: WireRef },

    /// Addition gate: a + b = c
    Add { a: WireRef, b: WireRef, c: WireRef },

    /// Multiplication gate: a * b = c
    Mul { a: WireRef, b: WireRef, c: WireRef },

    /// Constant constraint: wire = constant
    Constant { wire: WireRef, value: FieldElement },
}

/// Reference to a wire/signal in the circuit
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WireRef {
    /// Wire index
    pub index: usize,
    /// Optional name
    pub name: Option<String>,
}

impl WireRef {
    pub fn new(index: usize) -> Self {
        Self { index, name: None }
    }

    pub fn named(index: usize, name: &str) -> Self {
        Self {
            index,
            name: Some(name.to_string()),
        }
    }
}

/// R1CS constraint: A * B = C
#[derive(Debug, Clone)]
pub struct R1CSConstraint {
    /// Linear combination A
    pub a: LinearCombination,
    /// Linear combination B
    pub b: LinearCombination,
    /// Linear combination C
    pub c: LinearCombination,
}

/// Linear combination of wires: Σ (coeff_i * wire_i)
#[derive(Debug, Clone, Default)]
pub struct LinearCombination {
    pub terms: Vec<(WireRef, FieldElement)>,
}

impl LinearCombination {
    pub fn new() -> Self {
        Self { terms: Vec::new() }
    }

    pub fn add_term(&mut self, wire: WireRef, coeff: FieldElement) {
        self.terms.push((wire, coeff));
    }

    pub fn constant(value: FieldElement) -> Self {
        let mut lc = Self::new();
        lc.add_term(WireRef::new(0), value); // Wire 0 is typically 1
        lc
    }

    /// Evaluate the linear combination with given wire values
    pub fn evaluate(&self, wire_values: &HashMap<usize, FieldElement>) -> FieldElement {
        let mut result = FieldElement::zero();
        for (wire, coeff) in &self.terms {
            if let Some(value) = wire_values.get(&wire.index) {
                result = result.add(&value.mul(coeff));
            }
        }
        result
    }
}

/// PLONK gate: q_L*a + q_R*b + q_O*c + q_M*a*b + q_C = 0
#[derive(Debug, Clone)]
pub struct PlonkGate {
    /// Left wire
    pub a: WireRef,
    /// Right wire
    pub b: WireRef,
    /// Output wire
    pub c: WireRef,
    /// Left selector
    pub q_l: FieldElement,
    /// Right selector
    pub q_r: FieldElement,
    /// Output selector
    pub q_o: FieldElement,
    /// Multiplication selector
    pub q_m: FieldElement,
    /// Constant selector
    pub q_c: FieldElement,
    /// Optional custom selectors
    pub custom_selectors: Vec<FieldElement>,
}

impl PlonkGate {
    /// Create an addition gate: a + b = c
    pub fn addition(a: WireRef, b: WireRef, c: WireRef) -> Self {
        Self {
            a,
            b,
            c,
            q_l: FieldElement::one(),
            q_r: FieldElement::one(),
            q_o: FieldElement::one().neg(),
            q_m: FieldElement::zero(),
            q_c: FieldElement::zero(),
            custom_selectors: Vec::new(),
        }
    }

    /// Create a multiplication gate: a * b = c
    pub fn multiplication(a: WireRef, b: WireRef, c: WireRef) -> Self {
        Self {
            a,
            b,
            c,
            q_l: FieldElement::zero(),
            q_r: FieldElement::zero(),
            q_o: FieldElement::one().neg(),
            q_m: FieldElement::one(),
            q_c: FieldElement::zero(),
            custom_selectors: Vec::new(),
        }
    }

    /// Create a constant gate: a = constant
    pub fn constant(a: WireRef, value: FieldElement) -> Self {
        Self {
            a: a.clone(),
            b: WireRef::new(0),
            c: WireRef::new(0),
            q_l: FieldElement::one(),
            q_r: FieldElement::zero(),
            q_o: FieldElement::zero(),
            q_m: FieldElement::zero(),
            q_c: value.neg(),
            custom_selectors: Vec::new(),
        }
    }

    /// Check if gate is satisfied
    pub fn check(&self, wire_values: &HashMap<usize, FieldElement>) -> bool {
        let a = wire_values.get(&self.a.index).cloned().unwrap_or_default();
        let b = wire_values.get(&self.b.index).cloned().unwrap_or_default();
        let c = wire_values.get(&self.c.index).cloned().unwrap_or_default();

        // q_L*a + q_R*b + q_O*c + q_M*a*b + q_C
        let result = self
            .q_l
            .mul(&a)
            .add(&self.q_r.mul(&b))
            .add(&self.q_o.mul(&c))
            .add(&self.q_m.mul(&a).mul(&b))
            .add(&self.q_c);

        result.is_zero()
    }
}

/// Custom gate expressed as a named polynomial constraint
#[derive(Debug, Clone)]
pub struct CustomGateConstraint {
    pub name: String,
    pub polynomial: PolynomialConstraint,
}

impl CustomGateConstraint {
    pub fn new(name: &str, polynomial: PolynomialConstraint) -> Self {
        Self {
            name: name.to_string(),
            polynomial,
        }
    }
}

/// Lookup constraint: ensure value is in a lookup table
#[derive(Debug, Clone)]
pub struct LookupConstraint {
    /// Wire containing the value to look up
    pub input: WireRef,
    /// Table identifier
    pub table_id: usize,
    /// Table contents (if known)
    pub table: Option<LookupTable>,
    /// Whether this is a vector lookup (multiple columns)
    pub is_vector_lookup: bool,
    /// Additional input wires for vector lookups
    pub additional_inputs: Vec<WireRef>,
}

/// Lookup table definition
#[derive(Debug, Clone)]
pub struct LookupTable {
    /// Table name/identifier
    pub name: String,
    /// Number of columns
    pub num_columns: usize,
    /// Table entries (row-major)
    pub entries: Vec<Vec<FieldElement>>,
}

impl LookupTable {
    pub fn new(name: &str, num_columns: usize) -> Self {
        Self {
            name: name.to_string(),
            num_columns,
            entries: Vec::new(),
        }
    }

    /// Create a range table for values 0..n
    pub fn range_table(bits: usize) -> Self {
        let mut table = Self::new(&format!("range_{}", bits), 1);
        let max = 1u64 << bits;
        for i in 0..max {
            table.entries.push(vec![FieldElement::from_u64(i)]);
        }
        table
    }

    /// Create an XOR table for n-bit values
    pub fn xor_table(bits: usize) -> Self {
        let mut table = Self::new(&format!("xor_{}", bits), 3);
        let max = 1u64 << bits;
        for a in 0..max {
            for b in 0..max {
                table.entries.push(vec![
                    FieldElement::from_u64(a),
                    FieldElement::from_u64(b),
                    FieldElement::from_u64(a ^ b),
                ]);
            }
        }
        table
    }

    /// Check if values are in table
    pub fn contains(&self, values: &[FieldElement]) -> bool {
        if values.len() != self.num_columns {
            return false;
        }
        self.entries.iter().any(|row| row == values)
    }
}

/// Range constraint: 0 <= value < 2^bits
#[derive(Debug, Clone)]
pub struct RangeConstraint {
    /// Wire to constrain
    pub wire: WireRef,
    /// Number of bits
    pub bits: usize,
    /// Implementation method
    pub method: RangeMethod,
}

/// Method for implementing range constraints
#[derive(Debug, Clone)]
pub enum RangeMethod {
    /// Bit decomposition
    BitDecomposition { bit_wires: Vec<WireRef> },
    /// Lookup table
    Lookup { table_id: usize },
    /// Plookup-style
    Plookup,
    /// Caulk-style
    Caulk,
}

/// General polynomial constraint: P(x1, x2, ...) = 0
#[derive(Debug, Clone)]
pub struct PolynomialConstraint {
    /// Polynomial terms
    pub terms: Vec<PolynomialTerm>,
    /// Degree of the polynomial
    pub degree: usize,
}

/// A term in a polynomial: coeff * x1^e1 * x2^e2 * ...
#[derive(Debug, Clone)]
pub struct PolynomialTerm {
    /// Coefficient
    pub coefficient: FieldElement,
    /// Variable exponents: (wire_index, exponent)
    pub variables: Vec<(WireRef, usize)>,
}

/// ACIR opcode (from Noir)
#[derive(Debug, Clone)]
pub enum AcirOpcode {
    /// Arithmetic expression
    Arithmetic {
        a: LinearCombination,
        b: LinearCombination,
        c: LinearCombination,
        q_m: FieldElement,
        q_c: FieldElement,
    },
    /// BlackBox function call
    BlackBox(BlackBoxOp),
    /// Memory operation
    MemoryOp {
        block_id: usize,
        op_type: MemoryOpType,
        address: WireRef,
        value: WireRef,
    },
    /// Brillig (unconstrained) code
    Brillig {
        inputs: Vec<WireRef>,
        outputs: Vec<WireRef>,
    },
    /// Range constraint (explicit opcode)
    Range { input: WireRef, bits: usize },
}

/// BlackBox operations in ACIR
#[derive(Debug, Clone)]
pub enum BlackBoxOp {
    SHA256 {
        inputs: Vec<WireRef>,
        outputs: Vec<WireRef>,
    },
    Blake2s {
        inputs: Vec<WireRef>,
        outputs: Vec<WireRef>,
    },
    Blake3 {
        inputs: Vec<WireRef>,
        outputs: Vec<WireRef>,
    },
    Keccak256 {
        inputs: Vec<WireRef>,
        outputs: Vec<WireRef>,
    },
    Pedersen {
        inputs: Vec<WireRef>,
        outputs: Vec<WireRef>,
    },
    SchnorrVerify {
        inputs: Vec<WireRef>,
        output: WireRef,
    },
    EcdsaSecp256k1 {
        inputs: Vec<WireRef>,
        output: WireRef,
    },
    FixedBaseScalarMul {
        inputs: Vec<WireRef>,
        outputs: Vec<WireRef>,
    },
    RecursiveAggregation {
        inputs: Vec<WireRef>,
        outputs: Vec<WireRef>,
    },
    Range {
        input: WireRef,
        bits: usize,
    },
}

/// Memory operation type
#[derive(Debug, Clone)]
pub enum MemoryOpType {
    Read,
    Write,
    Init,
}

/// Cairo AIR constraint
#[derive(Debug, Clone)]
pub struct AirConstraint {
    /// Constraint expression over trace polynomials
    pub expression: AirExpression,
    /// Domain of the constraint
    pub domain: AirDomain,
}

/// AIR expression types
#[derive(Debug, Clone)]
pub enum AirExpression {
    /// Trace column access
    Column { index: usize, offset: i32 },
    /// Constant value
    Constant(FieldElement),
    /// Addition
    Add(Box<AirExpression>, Box<AirExpression>),
    /// Multiplication
    Mul(Box<AirExpression>, Box<AirExpression>),
    /// Subtraction
    Sub(Box<AirExpression>, Box<AirExpression>),
    /// Negation
    Neg(Box<AirExpression>),
}

/// AIR constraint domain
#[derive(Debug, Clone)]
pub enum AirDomain {
    /// Applies to all rows
    All,
    /// Applies to first row
    First,
    /// Applies to last row
    Last,
    /// Applies to transition (row i to row i+1)
    Transition,
}

/// Parsed constraint set with optional lookup tables
#[derive(Debug, Clone, Default)]
pub struct ParsedConstraintSet {
    pub constraints: Vec<ExtendedConstraint>,
    pub lookup_tables: HashMap<usize, LookupTable>,
}

/// Parser for constraint representations
pub struct ConstraintParser;

impl ConstraintParser {
    /// Parse R1CS constraints from a string representation
    pub fn parse_r1cs(_content: &str) -> Vec<ExtendedConstraint> {
        // TODO: Implement R1CS parsing
        Vec::new()
    }

    /// Parse PLONK constraints
    pub fn parse_plonk(content: &str) -> Vec<ExtendedConstraint> {
        Self::parse_plonk_with_tables(content).constraints
    }

    /// Parse PLONK constraints, returning lookup tables separately
    pub fn parse_plonk_with_tables(content: &str) -> ParsedConstraintSet {
        if let Some(json) = parse_json_from_text(
            content,
            &["gates", "lookups", "tables", "custom_gates", "constraints"],
        ) {
            return parse_plonk_json(&json);
        }

        parse_plonk_text(content)
    }

    /// Parse ACIR from Noir
    pub fn parse_acir(bytes: &[u8]) -> Vec<ExtendedConstraint> {
        Self::parse_acir_with_tables(bytes).constraints
    }

    /// Parse ACIR from Noir, returning lookup tables separately
    pub fn parse_acir_with_tables(bytes: &[u8]) -> ParsedConstraintSet {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return ParsedConstraintSet::default();
        };

        if let Some(json) = parse_json_from_text(
            text,
            &["opcodes", "constraints", "program", "functions", "bytecode"],
        ) {
            if json_has_any_key(
                &json,
                &[
                    "opcodes",
                    "constraints",
                    "program",
                    "functions",
                    "tables",
                    "lookup_tables",
                ],
            ) {
                return parse_acir_json(&json);
            }

            if json.get("bytecode").is_some() {
                if let Some(decoded) = parse_acir_bytecode(&json) {
                    return decoded;
                }
            }
        }

        parse_acir_text(text)
    }

    /// Parse Cairo AIR constraints
    pub fn parse_air(content: &str) -> Vec<ExtendedConstraint> {
        Self::parse_air_with_tables(content).constraints
    }

    /// Parse Cairo AIR constraints, returning lookup tables separately
    pub fn parse_air_with_tables(content: &str) -> ParsedConstraintSet {
        if let Some(json) = parse_json_from_text(content, &["constraints", "air", "polynomials"]) {
            return parse_air_json(&json);
        }

        parse_air_text(content)
    }
}

/// Policy for handling unknown lookup tables
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownLookupPolicy {
    /// Treat missing tables as a failed constraint
    FailClosed,
    /// Treat missing tables as satisfied (best-effort)
    FailOpen,
}

/// Result of evaluating a constraint
#[derive(Debug, Clone)]
pub struct ConstraintEvaluation {
    pub lhs: FieldElement,
    pub rhs: FieldElement,
    pub satisfied: bool,
}

/// Constraint checker that supports all constraint types
pub struct ConstraintChecker {
    /// Lookup tables
    lookup_tables: HashMap<usize, LookupTable>,
    unknown_lookup_policy: UnknownLookupPolicy,
}

impl ConstraintChecker {
    pub fn new() -> Self {
        Self {
            lookup_tables: HashMap::new(),
            unknown_lookup_policy: UnknownLookupPolicy::FailClosed,
        }
    }

    pub fn with_unknown_lookup_policy(mut self, policy: UnknownLookupPolicy) -> Self {
        self.unknown_lookup_policy = policy;
        self
    }

    /// Add a lookup table
    pub fn add_table(&mut self, id: usize, table: LookupTable) {
        self.lookup_tables.insert(id, table);
    }

    /// Check if a constraint is satisfied
    pub fn check(
        &self,
        constraint: &ExtendedConstraint,
        wire_values: &HashMap<usize, FieldElement>,
    ) -> bool {
        match constraint {
            ExtendedConstraint::R1CS(r1cs) => {
                let a = r1cs.a.evaluate(wire_values);
                let b = r1cs.b.evaluate(wire_values);
                let c = r1cs.c.evaluate(wire_values);
                a.mul(&b) == c
            }
            ExtendedConstraint::PlonkGate(gate) => gate.check(wire_values),
            ExtendedConstraint::CustomGate(custom) => {
                self.check_polynomial(&custom.polynomial, wire_values)
            }
            ExtendedConstraint::Lookup(lookup) => self.check_lookup(lookup, wire_values),
            ExtendedConstraint::Range(range) => self.check_range(range, wire_values),
            ExtendedConstraint::Polynomial(poly) => self.check_polynomial(poly, wire_values),
            ExtendedConstraint::Boolean { wire } => {
                if let Some(value) = wire_values.get(&wire.index) {
                    value.is_zero() || value.is_one()
                } else {
                    false
                }
            }
            ExtendedConstraint::Equal { a, b } => {
                let a_val = wire_values.get(&a.index);
                let b_val = wire_values.get(&b.index);
                match (a_val, b_val) {
                    (Some(av), Some(bv)) => av == bv,
                    _ => false,
                }
            }
            ExtendedConstraint::Add { a, b, c } => {
                let a_val = wire_values.get(&a.index).cloned().unwrap_or_default();
                let b_val = wire_values.get(&b.index).cloned().unwrap_or_default();
                let c_val = wire_values.get(&c.index).cloned().unwrap_or_default();
                a_val.add(&b_val) == c_val
            }
            ExtendedConstraint::Mul { a, b, c } => {
                let a_val = wire_values.get(&a.index).cloned().unwrap_or_default();
                let b_val = wire_values.get(&b.index).cloned().unwrap_or_default();
                let c_val = wire_values.get(&c.index).cloned().unwrap_or_default();
                a_val.mul(&b_val) == c_val
            }
            ExtendedConstraint::Constant { wire, value } => {
                if let Some(wire_val) = wire_values.get(&wire.index) {
                    wire_val == value
                } else {
                    false
                }
            }
            ExtendedConstraint::AcirOpcode(op) => self.check_acir_opcode(op, wire_values),
            ExtendedConstraint::AirConstraint(_) => true, // Not yet supported: treat as satisfied
        }
    }

    /// Evaluate a constraint, returning the lhs/rhs values and satisfaction
    pub fn evaluate(
        &self,
        constraint: &ExtendedConstraint,
        wire_values: &HashMap<usize, FieldElement>,
    ) -> ConstraintEvaluation {
        match constraint {
            ExtendedConstraint::R1CS(r1cs) => {
                let a = r1cs.a.evaluate(wire_values);
                let b = r1cs.b.evaluate(wire_values);
                let c = r1cs.c.evaluate(wire_values);
                let lhs = a.mul(&b);
                let rhs = c;
                ConstraintEvaluation {
                    satisfied: lhs == rhs,
                    lhs,
                    rhs,
                }
            }
            ExtendedConstraint::PlonkGate(gate) => {
                let a = wire_values.get(&gate.a.index).cloned().unwrap_or_default();
                let b = wire_values.get(&gate.b.index).cloned().unwrap_or_default();
                let c = wire_values.get(&gate.c.index).cloned().unwrap_or_default();
                let lhs = gate
                    .q_l
                    .mul(&a)
                    .add(&gate.q_r.mul(&b))
                    .add(&gate.q_o.mul(&c))
                    .add(&gate.q_m.mul(&a).mul(&b))
                    .add(&gate.q_c);
                let rhs = FieldElement::zero();
                ConstraintEvaluation {
                    satisfied: lhs.is_zero(),
                    lhs,
                    rhs,
                }
            }
            ExtendedConstraint::CustomGate(custom) => {
                let lhs = evaluate_polynomial(&custom.polynomial, wire_values);
                let rhs = FieldElement::zero();
                ConstraintEvaluation {
                    satisfied: lhs.is_zero(),
                    lhs,
                    rhs,
                }
            }
            ExtendedConstraint::Polynomial(poly) => {
                let lhs = evaluate_polynomial(poly, wire_values);
                let rhs = FieldElement::zero();
                ConstraintEvaluation {
                    satisfied: lhs.is_zero(),
                    lhs,
                    rhs,
                }
            }
            ExtendedConstraint::Lookup(lookup) => {
                let satisfied = self.check_lookup(lookup, wire_values);
                ConstraintEvaluation {
                    satisfied,
                    lhs: if satisfied {
                        FieldElement::one()
                    } else {
                        FieldElement::zero()
                    },
                    rhs: FieldElement::one(),
                }
            }
            ExtendedConstraint::Range(range) => {
                let satisfied = self.check_range(range, wire_values);
                ConstraintEvaluation {
                    satisfied,
                    lhs: if satisfied {
                        FieldElement::one()
                    } else {
                        FieldElement::zero()
                    },
                    rhs: FieldElement::one(),
                }
            }
            ExtendedConstraint::Boolean { wire } => {
                let satisfied = wire_values
                    .get(&wire.index)
                    .is_some_and(|v| v.is_zero() || v.is_one());
                ConstraintEvaluation {
                    satisfied,
                    lhs: if satisfied {
                        FieldElement::one()
                    } else {
                        FieldElement::zero()
                    },
                    rhs: FieldElement::one(),
                }
            }
            ExtendedConstraint::Equal { a, b } => {
                let lhs = wire_values.get(&a.index).cloned().unwrap_or_default();
                let rhs = wire_values.get(&b.index).cloned().unwrap_or_default();
                ConstraintEvaluation {
                    satisfied: lhs == rhs,
                    lhs,
                    rhs,
                }
            }
            ExtendedConstraint::Add { a, b, c } => {
                let lhs = wire_values
                    .get(&a.index)
                    .cloned()
                    .unwrap_or_default()
                    .add(&wire_values.get(&b.index).cloned().unwrap_or_default());
                let rhs = wire_values.get(&c.index).cloned().unwrap_or_default();
                ConstraintEvaluation {
                    satisfied: lhs == rhs,
                    lhs,
                    rhs,
                }
            }
            ExtendedConstraint::Mul { a, b, c } => {
                let lhs = wire_values
                    .get(&a.index)
                    .cloned()
                    .unwrap_or_default()
                    .mul(&wire_values.get(&b.index).cloned().unwrap_or_default());
                let rhs = wire_values.get(&c.index).cloned().unwrap_or_default();
                ConstraintEvaluation {
                    satisfied: lhs == rhs,
                    lhs,
                    rhs,
                }
            }
            ExtendedConstraint::Constant { wire, value } => {
                let lhs = wire_values.get(&wire.index).cloned().unwrap_or_default();
                let rhs = value.clone();
                ConstraintEvaluation {
                    satisfied: lhs == rhs,
                    lhs,
                    rhs,
                }
            }
            ExtendedConstraint::AcirOpcode(op) => self.evaluate_acir_opcode(op, wire_values),
            ExtendedConstraint::AirConstraint(_) => ConstraintEvaluation {
                satisfied: true,
                lhs: FieldElement::one(),
                rhs: FieldElement::one(),
            },
        }
    }

    fn check_acir_opcode(
        &self,
        op: &AcirOpcode,
        wire_values: &HashMap<usize, FieldElement>,
    ) -> bool {
        match op {
            AcirOpcode::Arithmetic { a, b, c, q_m, q_c } => {
                let value = self.evaluate_acir_arithmetic(a, b, c, q_m, q_c, wire_values);
                value.is_zero()
            }
            AcirOpcode::Range { input, bits } => self.check_range(
                &RangeConstraint {
                    wire: input.clone(),
                    bits: *bits,
                    method: RangeMethod::Plookup,
                },
                wire_values,
            ),
            AcirOpcode::BlackBox(BlackBoxOp::Range { input, bits }) => self.check_range(
                &RangeConstraint {
                    wire: input.clone(),
                    bits: *bits,
                    method: RangeMethod::Plookup,
                },
                wire_values,
            ),
            _ => true,
        }
    }

    fn evaluate_acir_opcode(
        &self,
        op: &AcirOpcode,
        wire_values: &HashMap<usize, FieldElement>,
    ) -> ConstraintEvaluation {
        match op {
            AcirOpcode::Arithmetic { a, b, c, q_m, q_c } => {
                let lhs = self.evaluate_acir_arithmetic(a, b, c, q_m, q_c, wire_values);
                ConstraintEvaluation {
                    satisfied: lhs.is_zero(),
                    lhs,
                    rhs: FieldElement::zero(),
                }
            }
            AcirOpcode::Range { input, bits } => {
                let satisfied = self.check_range(
                    &RangeConstraint {
                        wire: input.clone(),
                        bits: *bits,
                        method: RangeMethod::Plookup,
                    },
                    wire_values,
                );
                ConstraintEvaluation {
                    satisfied,
                    lhs: if satisfied {
                        FieldElement::one()
                    } else {
                        FieldElement::zero()
                    },
                    rhs: FieldElement::one(),
                }
            }
            AcirOpcode::BlackBox(BlackBoxOp::Range { input, bits }) => {
                let satisfied = self.check_range(
                    &RangeConstraint {
                        wire: input.clone(),
                        bits: *bits,
                        method: RangeMethod::Plookup,
                    },
                    wire_values,
                );
                ConstraintEvaluation {
                    satisfied,
                    lhs: if satisfied {
                        FieldElement::one()
                    } else {
                        FieldElement::zero()
                    },
                    rhs: FieldElement::one(),
                }
            }
            _ => ConstraintEvaluation {
                satisfied: true,
                lhs: FieldElement::one(),
                rhs: FieldElement::one(),
            },
        }
    }

    fn evaluate_acir_arithmetic(
        &self,
        a: &LinearCombination,
        b: &LinearCombination,
        c: &LinearCombination,
        q_m: &FieldElement,
        q_c: &FieldElement,
        wire_values: &HashMap<usize, FieldElement>,
    ) -> FieldElement {
        let a_val = a.evaluate(wire_values);
        let b_val = b.evaluate(wire_values);
        let c_val = c.evaluate(wire_values);

        q_m.mul(&a_val)
            .mul(&b_val)
            .add(&a_val)
            .add(&b_val)
            .add(&c_val)
            .add(q_c)
    }

    fn check_lookup(
        &self,
        lookup: &LookupConstraint,
        wire_values: &HashMap<usize, FieldElement>,
    ) -> bool {
        let table = lookup
            .table
            .as_ref()
            .or_else(|| self.lookup_tables.get(&lookup.table_id));

        let Some(table) = table else {
            return matches!(self.unknown_lookup_policy, UnknownLookupPolicy::FailOpen);
        };

        let mut values = Vec::new();
        let input_val = match wire_values.get(&lookup.input.index) {
            Some(v) => v.clone(),
            None => return false,
        };
        values.push(input_val);

        if lookup.is_vector_lookup || !lookup.additional_inputs.is_empty() {
            for wire in &lookup.additional_inputs {
                let val = match wire_values.get(&wire.index) {
                    Some(v) => v.clone(),
                    None => return false,
                };
                values.push(val);
            }
        }

        if table.num_columns != values.len() {
            return false;
        }

        table.contains(&values)
    }

    fn check_range(
        &self,
        range: &RangeConstraint,
        wire_values: &HashMap<usize, FieldElement>,
    ) -> bool {
        let value = match wire_values.get(&range.wire.index) {
            Some(v) => v,
            None => return false,
        };

        match &range.method {
            RangeMethod::BitDecomposition { bit_wires } if !bit_wires.is_empty() => {
                self.check_bit_decomposition(range.bits, value, bit_wires, wire_values)
            }
            RangeMethod::Lookup { table_id } => {
                if let Some(table) = self.lookup_tables.get(table_id) {
                    table.contains(&[value.clone()])
                } else {
                    self.check_numeric_range(value, range.bits)
                }
            }
            RangeMethod::Plookup | RangeMethod::Caulk | RangeMethod::BitDecomposition { .. } => {
                self.check_numeric_range(value, range.bits)
            }
        }
    }

    fn check_bit_decomposition(
        &self,
        bits: usize,
        value: &FieldElement,
        bit_wires: &[WireRef],
        wire_values: &HashMap<usize, FieldElement>,
    ) -> bool {
        let mut sum = BigUint::from(0u8);
        let value_big = field_to_biguint(value);

        for (i, wire) in bit_wires.iter().enumerate() {
            let bit = match wire_values.get(&wire.index) {
                Some(v) => v,
                None => return false,
            };

            if !(bit.is_zero() || bit.is_one()) {
                return false;
            }

            if i >= bits && bit.is_one() {
                return false;
            }

            if bit.is_one() {
                sum += BigUint::from(1u8) << i;
            }
        }

        sum == value_big && sum < (BigUint::from(1u8) << bits)
    }

    fn check_numeric_range(&self, value: &FieldElement, bits: usize) -> bool {
        let value_big = field_to_biguint(value);
        let bound = BigUint::from(1u8) << bits;
        value_big < bound
    }

    fn check_polynomial(
        &self,
        polynomial: &PolynomialConstraint,
        wire_values: &HashMap<usize, FieldElement>,
    ) -> bool {
        let evaluated = evaluate_polynomial(polynomial, wire_values);
        evaluated.is_zero()
    }

    pub fn to_symbolic(&self, constraint: &ExtendedConstraint) -> Option<SymbolicConstraint> {
        self.to_symbolic_with_options(constraint, &SymbolicConversionOptions::default())
    }

    pub fn to_symbolic_with_options(
        &self,
        constraint: &ExtendedConstraint,
        options: &SymbolicConversionOptions,
    ) -> Option<SymbolicConstraint> {
        constraint.to_symbolic_with_tables(&self.lookup_tables, options)
    }
}

/// Options controlling how extended constraints are lowered into symbolic form.
#[derive(Debug, Clone)]
pub struct SymbolicConversionOptions {
    /// Maximum number of lookup rows to expand into symbolic disjunctions
    pub lookup_row_limit: usize,
}

impl Default for SymbolicConversionOptions {
    fn default() -> Self {
        Self {
            lookup_row_limit: DEFAULT_LOOKUP_ROW_LIMIT,
        }
    }
}

impl ExtendedConstraint {
    pub fn to_symbolic_with_tables(
        &self,
        tables: &HashMap<usize, LookupTable>,
        options: &SymbolicConversionOptions,
    ) -> Option<SymbolicConstraint> {
        match self {
            ExtendedConstraint::R1CS(r1cs) => {
                let a = linear_combination_to_symbolic(&r1cs.a);
                let b = linear_combination_to_symbolic(&r1cs.b);
                let c = linear_combination_to_symbolic(&r1cs.c);
                Some(SymbolicConstraint::r1cs(a, b, c))
            }
            ExtendedConstraint::PlonkGate(gate) => {
                let a = wire_to_symbolic(&gate.a);
                let b = wire_to_symbolic(&gate.b);
                let c = wire_to_symbolic(&gate.c);

                let mut expr = SymbolicValue::concrete(gate.q_l.clone()).mul(a);
                expr = expr.add(SymbolicValue::concrete(gate.q_r.clone()).mul(b));
                expr = expr.add(SymbolicValue::concrete(gate.q_o.clone()).mul(c));
                expr = expr.add(
                    SymbolicValue::concrete(gate.q_m.clone())
                        .mul(wire_to_symbolic(&gate.a).mul(wire_to_symbolic(&gate.b))),
                );
                expr = expr.add(SymbolicValue::concrete(gate.q_c.clone()));

                Some(SymbolicConstraint::eq(
                    expr,
                    SymbolicValue::concrete(FieldElement::zero()),
                ))
            }
            ExtendedConstraint::CustomGate(custom) => {
                let poly = polynomial_to_symbolic(&custom.polynomial);
                Some(SymbolicConstraint::eq(
                    poly,
                    SymbolicValue::concrete(FieldElement::zero()),
                ))
            }
            ExtendedConstraint::Lookup(lookup) => {
                let table = lookup
                    .table
                    .as_ref()
                    .or_else(|| tables.get(&lookup.table_id))?;

                if table.entries.len() > options.lookup_row_limit {
                    return None;
                }

                let mut inputs = vec![wire_to_symbolic(&lookup.input)];
                if lookup.is_vector_lookup || !lookup.additional_inputs.is_empty() {
                    inputs.extend(lookup.additional_inputs.iter().map(wire_to_symbolic));
                }

                if inputs.len() != table.num_columns {
                    return None;
                }

                let mut row_constraints = Vec::new();
                for row in &table.entries {
                    if row.len() != inputs.len() {
                        continue;
                    }

                    let mut conjuncts = Vec::new();
                    for (input, value) in inputs.iter().zip(row.iter()) {
                        conjuncts.push(SymbolicConstraint::eq(
                            input.clone(),
                            SymbolicValue::concrete(value.clone()),
                        ));
                    }

                    row_constraints.push(fold_and(conjuncts));
                }

                Some(fold_or(row_constraints))
            }
            ExtendedConstraint::Range(range) => {
                let wire_val = wire_to_symbolic(&range.wire);

                if let RangeMethod::BitDecomposition { bit_wires } = &range.method {
                    if !bit_wires.is_empty() && range.bits < 255 {
                        let mut sum = SymbolicValue::concrete(FieldElement::zero());
                        let mut constraints = Vec::new();

                        for (i, bit) in bit_wires.iter().enumerate() {
                            if i >= 255 {
                                return Some(SymbolicConstraint::range(
                                    wire_val,
                                    SymbolicValue::concrete(field_from_biguint(
                                        &(BigUint::from(1u8) << range.bits),
                                    )),
                                ));
                            }

                            let bit_sym = wire_to_symbolic(bit);
                            constraints.push(SymbolicConstraint::boolean(bit_sym.clone()));

                            let coeff = field_from_biguint(&(BigUint::from(1u8) << i));
                            sum = sum.add(SymbolicValue::concrete(coeff).mul(bit_sym));
                        }

                        constraints.push(SymbolicConstraint::eq(wire_val, sum));
                        return Some(fold_and(constraints));
                    }
                }

                if range.bits >= 255 {
                    return Some(SymbolicConstraint::True);
                }

                let bound = field_from_biguint(&(BigUint::from(1u8) << range.bits));
                Some(SymbolicConstraint::range(
                    wire_val,
                    SymbolicValue::concrete(bound),
                ))
            }
            ExtendedConstraint::Polynomial(poly) => {
                let value = polynomial_to_symbolic(poly);
                Some(SymbolicConstraint::eq(
                    value,
                    SymbolicValue::concrete(FieldElement::zero()),
                ))
            }
            ExtendedConstraint::Boolean { wire } => {
                Some(SymbolicConstraint::boolean(wire_to_symbolic(wire)))
            }
            ExtendedConstraint::Equal { a, b } => Some(SymbolicConstraint::eq(
                wire_to_symbolic(a),
                wire_to_symbolic(b),
            )),
            ExtendedConstraint::Add { a, b, c } => Some(SymbolicConstraint::eq(
                wire_to_symbolic(a).add(wire_to_symbolic(b)),
                wire_to_symbolic(c),
            )),
            ExtendedConstraint::Mul { a, b, c } => Some(SymbolicConstraint::r1cs(
                wire_to_symbolic(a),
                wire_to_symbolic(b),
                wire_to_symbolic(c),
            )),
            ExtendedConstraint::Constant { wire, value } => Some(SymbolicConstraint::eq(
                wire_to_symbolic(wire),
                SymbolicValue::concrete(value.clone()),
            )),
            ExtendedConstraint::AcirOpcode(op) => match op {
                AcirOpcode::Arithmetic { a, b, c, q_m, q_c } => {
                    let a_sym = linear_combination_to_symbolic(a);
                    let b_sym = linear_combination_to_symbolic(b);
                    let c_sym = linear_combination_to_symbolic(c);

                    let mut expr =
                        SymbolicValue::concrete(q_m.clone()).mul(a_sym.clone().mul(b_sym.clone()));
                    expr = expr.add(a_sym);
                    expr = expr.add(b_sym);
                    expr = expr.add(c_sym);
                    expr = expr.add(SymbolicValue::concrete(q_c.clone()));

                    Some(SymbolicConstraint::eq(
                        expr,
                        SymbolicValue::concrete(FieldElement::zero()),
                    ))
                }
                AcirOpcode::Range { input, bits } => {
                    if *bits >= 255 {
                        return Some(SymbolicConstraint::True);
                    }
                    let bound = field_from_biguint(&(BigUint::from(1u8) << bits));
                    Some(SymbolicConstraint::range(
                        wire_to_symbolic(input),
                        SymbolicValue::concrete(bound),
                    ))
                }
                AcirOpcode::BlackBox(BlackBoxOp::Range { input, bits }) => {
                    if *bits >= 255 {
                        return Some(SymbolicConstraint::True);
                    }
                    let bound = field_from_biguint(&(BigUint::from(1u8) << bits));
                    Some(SymbolicConstraint::range(
                        wire_to_symbolic(input),
                        SymbolicValue::concrete(bound),
                    ))
                }
                _ => None,
            },
            ExtendedConstraint::AirConstraint(_) => None,
        }
    }

    /// Collect wire indices referenced by this constraint
    pub fn wire_dependencies(&self) -> Vec<usize> {
        let mut deps = Vec::new();

        let mut collect_lc = |lc: &LinearCombination| {
            for (wire, _) in &lc.terms {
                if wire.index != 0 {
                    deps.push(wire.index);
                }
            }
        };

        match self {
            ExtendedConstraint::R1CS(r1cs) => {
                collect_lc(&r1cs.a);
                collect_lc(&r1cs.b);
                collect_lc(&r1cs.c);
            }
            ExtendedConstraint::PlonkGate(gate) => {
                deps.push(gate.a.index);
                deps.push(gate.b.index);
                deps.push(gate.c.index);
            }
            ExtendedConstraint::CustomGate(custom) => {
                for term in &custom.polynomial.terms {
                    for (wire, _) in &term.variables {
                        if wire.index != 0 {
                            deps.push(wire.index);
                        }
                    }
                }
            }
            ExtendedConstraint::Lookup(lookup) => {
                deps.push(lookup.input.index);
                for wire in &lookup.additional_inputs {
                    deps.push(wire.index);
                }
            }
            ExtendedConstraint::Range(range) => {
                deps.push(range.wire.index);
                if let RangeMethod::BitDecomposition { bit_wires } = &range.method {
                    for wire in bit_wires {
                        deps.push(wire.index);
                    }
                }
            }
            ExtendedConstraint::Polynomial(poly) => {
                for term in &poly.terms {
                    for (wire, _) in &term.variables {
                        if wire.index != 0 {
                            deps.push(wire.index);
                        }
                    }
                }
            }
            ExtendedConstraint::AcirOpcode(op) => match op {
                AcirOpcode::Arithmetic { a, b, c, .. } => {
                    collect_lc(a);
                    collect_lc(b);
                    collect_lc(c);
                }
                AcirOpcode::BlackBox(op) => match op {
                    BlackBoxOp::SHA256 { inputs, outputs }
                    | BlackBoxOp::Blake2s { inputs, outputs }
                    | BlackBoxOp::Blake3 { inputs, outputs }
                    | BlackBoxOp::Keccak256 { inputs, outputs }
                    | BlackBoxOp::Pedersen { inputs, outputs }
                    | BlackBoxOp::FixedBaseScalarMul { inputs, outputs }
                    | BlackBoxOp::RecursiveAggregation { inputs, outputs } => {
                        deps.extend(inputs.iter().map(|w| w.index));
                        deps.extend(outputs.iter().map(|w| w.index));
                    }
                    BlackBoxOp::SchnorrVerify { inputs, output }
                    | BlackBoxOp::EcdsaSecp256k1 { inputs, output } => {
                        deps.extend(inputs.iter().map(|w| w.index));
                        deps.push(output.index);
                    }
                    BlackBoxOp::Range { input, .. } => {
                        deps.push(input.index);
                    }
                },
                AcirOpcode::MemoryOp { address, value, .. } => {
                    deps.push(address.index);
                    deps.push(value.index);
                }
                AcirOpcode::Brillig { inputs, outputs } => {
                    deps.extend(inputs.iter().map(|w| w.index));
                    deps.extend(outputs.iter().map(|w| w.index));
                }
                AcirOpcode::Range { input, .. } => {
                    deps.push(input.index);
                }
            },
            ExtendedConstraint::AirConstraint(_) => {}
            ExtendedConstraint::Boolean { wire } => deps.push(wire.index),
            ExtendedConstraint::Equal { a, b } => {
                deps.push(a.index);
                deps.push(b.index);
            }
            ExtendedConstraint::Add { a, b, c } | ExtendedConstraint::Mul { a, b, c } => {
                deps.push(a.index);
                deps.push(b.index);
                deps.push(c.index);
            }
            ExtendedConstraint::Constant { wire, .. } => deps.push(wire.index),
        }

        deps.sort_unstable();
        deps.dedup();
        deps
    }
}

fn field_to_biguint(value: &FieldElement) -> BigUint {
    BigUint::from_bytes_be(&value.to_bytes())
}

fn field_from_biguint(value: &BigUint) -> FieldElement {
    FieldElement::from_bytes(&value.to_bytes_be())
}

fn field_pow(base: &FieldElement, exp: usize) -> FieldElement {
    if exp == 0 {
        return FieldElement::one();
    }

    let mut result = FieldElement::one();
    let mut base_acc = base.clone();
    let mut e = exp;

    while e > 0 {
        if e & 1 == 1 {
            result = result.mul(&base_acc);
        }
        e >>= 1;
        if e > 0 {
            base_acc = base_acc.mul(&base_acc);
        }
    }

    result
}

fn evaluate_polynomial(
    polynomial: &PolynomialConstraint,
    wire_values: &HashMap<usize, FieldElement>,
) -> FieldElement {
    let mut acc = FieldElement::zero();

    for term in &polynomial.terms {
        let mut term_value = term.coefficient.clone();
        for (wire, exp) in &term.variables {
            let base = wire_values.get(&wire.index).cloned().unwrap_or_default();
            let power = field_pow(&base, *exp);
            term_value = term_value.mul(&power);
        }
        acc = acc.add(&term_value);
    }

    acc
}

fn wire_to_symbolic(wire: &WireRef) -> SymbolicValue {
    if wire.index == 0 {
        return SymbolicValue::concrete(FieldElement::one());
    }

    if let Some(name) = &wire.name {
        SymbolicValue::symbol(name)
    } else {
        SymbolicValue::symbol(&format!("wire_{}", wire.index))
    }
}

fn linear_combination_to_symbolic(lc: &LinearCombination) -> SymbolicValue {
    let mut acc = SymbolicValue::concrete(FieldElement::zero());

    for (wire, coeff) in &lc.terms {
        if wire.index == 0 {
            acc = acc.add(SymbolicValue::concrete(coeff.clone()));
            continue;
        }

        let term = SymbolicValue::concrete(coeff.clone()).mul(wire_to_symbolic(wire));
        acc = acc.add(term);
    }

    acc
}

fn symbolic_pow(base: SymbolicValue, exp: usize) -> SymbolicValue {
    if exp == 0 {
        return SymbolicValue::concrete(FieldElement::one());
    }

    let mut result = base.clone();
    for _ in 1..exp {
        result = result.mul(base.clone());
    }
    result
}

fn polynomial_to_symbolic(poly: &PolynomialConstraint) -> SymbolicValue {
    let mut acc = SymbolicValue::concrete(FieldElement::zero());

    for term in &poly.terms {
        let mut term_val = SymbolicValue::concrete(term.coefficient.clone());
        for (wire, exp) in &term.variables {
            let base = wire_to_symbolic(wire);
            term_val = term_val.mul(symbolic_pow(base, *exp));
        }
        acc = acc.add(term_val);
    }

    acc
}

fn fold_and(mut constraints: Vec<SymbolicConstraint>) -> SymbolicConstraint {
    let mut iter = constraints.drain(..);
    match iter.next() {
        Some(first) => iter.fold(first, |acc, c| acc.and(c)),
        None => SymbolicConstraint::True,
    }
}

fn fold_or(mut constraints: Vec<SymbolicConstraint>) -> SymbolicConstraint {
    let mut iter = constraints.drain(..);
    match iter.next() {
        Some(first) => iter.fold(first, |acc, c| acc.or(c)),
        None => SymbolicConstraint::False,
    }
}

fn json_has_any_key(value: &serde_json::Value, keys: &[&str]) -> bool {
    if keys.is_empty() {
        return true;
    }
    let Some(obj) = value.as_object() else {
        return false;
    };
    keys.iter().any(|key| obj.contains_key(*key))
}

fn parse_json_from_text(content: &str, expected_keys: &[&str]) -> Option<serde_json::Value> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(content) {
        return Some(value);
    }

    let mut fallback = None;
    for (idx, ch) in content.char_indices() {
        if ch != '{' && ch != '[' {
            continue;
        }

        let slice = &content[idx..];
        let mut de = serde_json::Deserializer::from_str(slice).into_iter::<serde_json::Value>();
        if let Some(Ok(value)) = de.next() {
            if json_has_any_key(&value, expected_keys) {
                return Some(value);
            }
            if fallback.is_none() {
                fallback = Some(value);
            }
        }
    }

    fallback
}

fn collect_wire_refs(value: &serde_json::Value, output: &mut Vec<WireRef>) {
    if let Some(wire) = parse_wire_ref_value(value) {
        output.push(wire);
        return;
    }

    if let Some(arr) = value.as_array() {
        for entry in arr {
            if let Some(wire) = parse_wire_ref_value(entry) {
                output.push(wire);
            }
        }
        return;
    }

    if let Some(obj) = value.as_object() {
        if let Some(inner) = obj
            .get("wires")
            .or_else(|| obj.get("inputs"))
            .or_else(|| obj.get("values"))
        {
            collect_wire_refs(inner, output);
        }
    }
}

fn parse_lookup_inputs(lookup: &serde_json::Value) -> Vec<WireRef> {
    let mut inputs = Vec::new();
    for key in [
        "inputs",
        "input",
        "values",
        "columns",
        "exprs",
        "expressions",
        "wires",
        "cells",
    ] {
        if let Some(val) = lookup.get(key) {
            collect_wire_refs(val, &mut inputs);
        }
    }
    inputs
}

fn parse_plonk_json(value: &serde_json::Value) -> ParsedConstraintSet {
    let mut set = ParsedConstraintSet::default();

    let mut add_tables = |tables: &serde_json::Value| match tables {
        serde_json::Value::Array(entries) => {
            for table_val in entries {
                if let Some((id, table)) = parse_lookup_table_value(table_val, None) {
                    set.lookup_tables.entry(id).or_insert(table);
                }
            }
        }
        serde_json::Value::Object(map) => {
            for (key, table_val) in map {
                if let Ok(id) = key.parse::<usize>() {
                    if let Some((_, table)) = parse_lookup_table_value(table_val, Some(id)) {
                        set.lookup_tables.entry(id).or_insert(table);
                    }
                } else if let Some((id, table)) = parse_lookup_table_value(table_val, None) {
                    set.lookup_tables.entry(id).or_insert(table);
                }
            }
        }
        _ => {}
    };

    for key in [
        "tables",
        "lookup_tables",
        "lookupTables",
        "fixed_tables",
        "lookup_table",
    ] {
        if let Some(tables) = value.get(key) {
            add_tables(tables);
        }
    }

    let mut gate_values: Vec<&serde_json::Value> = Vec::new();

    if let Some(gates) = value.get("gates") {
        match gates {
            serde_json::Value::Array(arr) => gate_values.extend(arr.iter()),
            serde_json::Value::Object(obj) => gate_values.extend(obj.values()),
            _ => {}
        }
    }

    if let Some(constraints) = value.get("constraints") {
        match constraints {
            serde_json::Value::Array(arr) => gate_values.extend(arr.iter()),
            serde_json::Value::Object(obj) => gate_values.extend(obj.values()),
            _ => {}
        }
    }

    if let Some(custom_gates) = value.get("custom_gates") {
        match custom_gates {
            serde_json::Value::Array(arr) => gate_values.extend(arr.iter()),
            serde_json::Value::Object(map) => {
                for (name, gate) in map {
                    if let Some(poly) = parse_polynomial_value(gate) {
                        set.constraints.push(ExtendedConstraint::CustomGate(
                            CustomGateConstraint::new(name, poly),
                        ));
                    } else if let Some(constraint) = parse_plonk_gate_value(gate) {
                        set.constraints.push(constraint);
                    }
                }
            }
            _ => {}
        }
    }

    for gate in gate_values {
        if let Some(constraint) = parse_plonk_gate_value(gate) {
            set.constraints.push(constraint);
        }
    }

    if let Some(lookups) = value.get("lookups") {
        let mut lookup_values: Vec<&serde_json::Value> = Vec::new();
        match lookups {
            serde_json::Value::Array(arr) => lookup_values.extend(arr.iter()),
            serde_json::Value::Object(obj) => lookup_values.extend(obj.values()),
            _ => {}
        }

        for lookup in lookup_values {
            let mut table_id = lookup
                .get("table_id")
                .and_then(|v| v.as_u64())
                .or_else(|| lookup.get("table_id").and_then(|v| v.as_u64()))
                .or_else(|| lookup.get("table").and_then(|v| v.as_u64()))
                .or_else(|| {
                    lookup
                        .get("table")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse().ok())
                })
                .or_else(|| lookup.get("id").and_then(|v| v.as_u64()))
                .map(|v| v as usize)
                .unwrap_or(0);

            if let Some(table_val) = lookup.get("table") {
                if let Some((id, table)) = parse_lookup_table_value(
                    table_val,
                    if table_id == 0 { None } else { Some(table_id) },
                ) {
                    table_id = id;
                    set.lookup_tables.entry(id).or_insert(table);
                }
            }

            let inputs = parse_lookup_inputs(lookup);
            if inputs.is_empty() {
                continue;
            }

            let input = inputs[0].clone();
            let additional_inputs = if inputs.len() > 1 {
                inputs[1..].to_vec()
            } else {
                Vec::new()
            };

            let table = set.lookup_tables.get(&table_id).cloned();
            set.constraints
                .push(ExtendedConstraint::Lookup(LookupConstraint {
                    input,
                    table_id,
                    table,
                    is_vector_lookup: !additional_inputs.is_empty(),
                    additional_inputs,
                }));
        }
    }

    set
}

fn parse_plonk_text(content: &str) -> ParsedConstraintSet {
    let mut set = ParsedConstraintSet::default();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let kind = parts.next().unwrap_or("");

        let mut kv = HashMap::new();
        for part in parts {
            if let Some((k, v)) = part.split_once('=') {
                kv.insert(k.to_lowercase(), v.to_string());
            }
        }

        match kind.to_lowercase().as_str() {
            "table" => {
                if let Some(id_str) = kv.get("id") {
                    if let Ok(id) = id_str.parse::<usize>() {
                        let name = kv
                            .get("name")
                            .cloned()
                            .unwrap_or_else(|| format!("table_{}", id));
                        let num_columns = kv
                            .get("columns")
                            .and_then(|v| v.parse::<usize>().ok())
                            .unwrap_or(1);
                        let mut table = LookupTable::new(&name, num_columns);
                        if let Some(entries) = kv.get("entries") {
                            let rows = entries.split(';');
                            for row in rows {
                                let values = row
                                    .split(',')
                                    .filter_map(|s| parse_field_element_str(s))
                                    .collect::<Vec<_>>();
                                if !values.is_empty() {
                                    table.entries.push(values);
                                }
                            }
                        }
                        set.lookup_tables.insert(id, table);
                    }
                }
            }
            "lookup" => {
                let table_id = kv
                    .get("table")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);
                let inputs = kv
                    .get("inputs")
                    .or_else(|| kv.get("input"))
                    .map(|v| {
                        v.split(',')
                            .filter_map(|s| s.parse::<usize>().ok())
                            .map(WireRef::new)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                if inputs.is_empty() {
                    continue;
                }

                let input = inputs[0].clone();
                let additional_inputs = if inputs.len() > 1 {
                    inputs[1..].to_vec()
                } else {
                    Vec::new()
                };

                let table = set.lookup_tables.get(&table_id).cloned();
                set.constraints
                    .push(ExtendedConstraint::Lookup(LookupConstraint {
                        input,
                        table_id,
                        table,
                        is_vector_lookup: !additional_inputs.is_empty(),
                        additional_inputs,
                    }));
            }
            "gate" | "plonk" => {
                if let (Some(a), Some(b), Some(c)) = (
                    kv.get("a").and_then(|v| v.parse::<usize>().ok()),
                    kv.get("b").and_then(|v| v.parse::<usize>().ok()),
                    kv.get("c").and_then(|v| v.parse::<usize>().ok()),
                ) {
                    let gate = PlonkGate {
                        a: WireRef::new(a),
                        b: WireRef::new(b),
                        c: WireRef::new(c),
                        q_l: kv
                            .get("ql")
                            .and_then(|v| parse_field_element_str(v))
                            .unwrap_or_else(FieldElement::zero),
                        q_r: kv
                            .get("qr")
                            .and_then(|v| parse_field_element_str(v))
                            .unwrap_or_else(FieldElement::zero),
                        q_o: kv
                            .get("qo")
                            .and_then(|v| parse_field_element_str(v))
                            .unwrap_or_else(FieldElement::zero),
                        q_m: kv
                            .get("qm")
                            .and_then(|v| parse_field_element_str(v))
                            .unwrap_or_else(FieldElement::zero),
                        q_c: kv
                            .get("qc")
                            .and_then(|v| parse_field_element_str(v))
                            .unwrap_or_else(FieldElement::zero),
                        custom_selectors: Vec::new(),
                    };
                    set.constraints.push(ExtendedConstraint::PlonkGate(gate));
                }
            }
            _ => {}
        }
    }

    set
}

fn parse_acir_json(value: &serde_json::Value) -> ParsedConstraintSet {
    let mut set = ParsedConstraintSet::default();
    let opcode_source = if value.as_array().is_some() {
        Some(value)
    } else {
        value
            .get("opcodes")
            .or_else(|| value.get("constraints"))
            .or_else(|| value.get("program").and_then(|p| p.get("opcodes")))
            .or_else(|| {
                value
                    .get("functions")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.get(0))
                    .and_then(|entry| entry.get("opcodes"))
            })
    };

    let opcodes = opcode_source
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if let Some(tables) = value.get("tables").or_else(|| value.get("lookup_tables")) {
        match tables {
            serde_json::Value::Array(entries) => {
                for table_val in entries {
                    if let Some((id, table)) = parse_lookup_table_value(table_val, None) {
                        set.lookup_tables.entry(id).or_insert(table);
                    }
                }
            }
            serde_json::Value::Object(map) => {
                for (key, table_val) in map {
                    if let Ok(id) = key.parse::<usize>() {
                        if let Some((_, table)) = parse_lookup_table_value(table_val, Some(id)) {
                            set.lookup_tables.entry(id).or_insert(table);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    for opcode in opcodes {
        if let Some(acir) = parse_acir_opcode_value(&opcode) {
            set.constraints.push(ExtendedConstraint::AcirOpcode(acir));
        }
    }

    set
}

#[cfg(feature = "acir-bytecode")]
fn parse_acir_bytecode(value: &serde_json::Value) -> Option<ParsedConstraintSet> {
    let bytecode = value.get("bytecode")?.as_str()?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(bytecode)
        .ok()?;
    let bytes = if raw.starts_with(&[0x1f, 0x8b]) {
        let mut decoder = GzDecoder::new(raw.as_slice());
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).ok()?;
        decoded
    } else {
        raw
    };

    // Attempt to deserialize ACIR bytecode into a Program or Circuit and convert to JSON.
    // This keeps decoding logic centralized in ACIR crates while reusing existing JSON parsing.
    if let Ok(program) = bincode::deserialize::<acir::circuit::Program<acir::FieldElement>>(&bytes)
    {
        let json = serde_json::to_value(program).ok()?;
        return Some(parse_acir_json(&json));
    }

    if let Ok(circuit) = bincode::deserialize::<acir::circuit::Circuit<acir::FieldElement>>(&bytes)
    {
        let json = serde_json::to_value(circuit).ok()?;
        return Some(parse_acir_json(&json));
    }

    None
}

#[cfg(not(feature = "acir-bytecode"))]
fn parse_acir_bytecode(_value: &serde_json::Value) -> Option<ParsedConstraintSet> {
    None
}

fn parse_acir_text(content: &str) -> ParsedConstraintSet {
    let mut set = ParsedConstraintSet::default();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let lower = trimmed.to_lowercase();
        let numbers = extract_numbers(trimmed);

        if lower.contains("range") && numbers.len() >= 2 {
            let wire = WireRef::new(numbers[0]);
            let bits = numbers[1];
            set.constraints
                .push(ExtendedConstraint::AcirOpcode(AcirOpcode::Range {
                    input: wire,
                    bits,
                }));
            continue;
        }

        if (lower.contains("assert_zero") || lower.contains("assertzero")) && numbers.len() >= 1 {
            set.constraints.push(ExtendedConstraint::Constant {
                wire: WireRef::new(numbers[0]),
                value: FieldElement::zero(),
            });
            continue;
        }

        if (lower.contains("assert") || lower.contains("==")) && numbers.len() >= 2 {
            set.constraints.push(ExtendedConstraint::Equal {
                a: WireRef::new(numbers[0]),
                b: WireRef::new(numbers[1]),
            });
        }
    }

    set
}

fn parse_air_json(value: &serde_json::Value) -> ParsedConstraintSet {
    let mut set = ParsedConstraintSet::default();
    let constraints_val = value
        .get("constraints")
        .or_else(|| value.get("air"))
        .or_else(|| value.get("polynomials"));

    let mut entries: Vec<(Option<AirDomain>, &serde_json::Value)> = Vec::new();
    if let Some(constraints) = constraints_val {
        match constraints {
            serde_json::Value::Array(arr) => {
                for entry in arr {
                    entries.push((None, entry));
                }
            }
            serde_json::Value::Object(map) => {
                for (domain_key, list) in map {
                    let domain_override = parse_air_domain_text(domain_key);
                    if let Some(arr) = list.as_array() {
                        for entry in arr {
                            entries.push((domain_override.clone(), entry));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    for (domain_override, entry) in entries {
        let expression = entry
            .get("expression")
            .or_else(|| entry.get("expr"))
            .or_else(|| entry.get("constraint"))
            .or_else(|| entry.get("poly"))
            .map(parse_air_expression_value)
            .unwrap_or_else(|| parse_air_expression_value(entry));

        let domain = entry
            .get("domain")
            .and_then(parse_air_domain)
            .or(domain_override)
            .unwrap_or(AirDomain::All);

        if let Some(expr) = expression {
            set.constraints
                .push(ExtendedConstraint::AirConstraint(AirConstraint {
                    expression: expr,
                    domain,
                }));
        }
    }

    set
}

fn parse_air_text(content: &str) -> ParsedConstraintSet {
    let mut set = ParsedConstraintSet::default();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let (expr_part, domain_part) = if let Some((expr, domain)) = trimmed.split_once('@') {
            (expr.trim(), Some(domain.trim()))
        } else {
            (trimmed, None)
        };

        let expression = parse_air_expression_text(expr_part);
        let domain = domain_part
            .and_then(parse_air_domain_text)
            .unwrap_or(AirDomain::All);

        if let Some(expr) = expression {
            set.constraints
                .push(ExtendedConstraint::AirConstraint(AirConstraint {
                    expression: expr,
                    domain,
                }));
        }
    }

    set
}

fn parse_plonk_wire_triplet(value: &serde_json::Value) -> Option<(WireRef, WireRef, WireRef)> {
    if let Some(arr) = value.as_array() {
        if arr.len() >= 3 {
            return Some((
                parse_wire_ref_value(&arr[0])?,
                parse_wire_ref_value(&arr[1])?,
                parse_wire_ref_value(&arr[2])?,
            ));
        }
    }

    let obj = value.as_object()?;

    if let Some(arr) = obj
        .get("wires")
        .or_else(|| obj.get("cells"))
        .or_else(|| obj.get("columns"))
        .or_else(|| obj.get("inputs"))
        .and_then(|v| v.as_array())
    {
        if arr.len() >= 3 {
            return Some((
                parse_wire_ref_value(&arr[0])?,
                parse_wire_ref_value(&arr[1])?,
                parse_wire_ref_value(&arr[2])?,
            ));
        }
    }

    if let Some(wires_obj) = obj.get("wires").and_then(|v| v.as_object()) {
        if let (Some(a), Some(b), Some(c)) =
            (wires_obj.get("a"), wires_obj.get("b"), wires_obj.get("c"))
        {
            return Some((
                parse_wire_ref_value(a)?,
                parse_wire_ref_value(b)?,
                parse_wire_ref_value(c)?,
            ));
        }
    }

    let a = obj
        .get("a")
        .or_else(|| obj.get("lhs"))
        .or_else(|| obj.get("left"))
        .or_else(|| obj.get("l"))?;
    let b = obj
        .get("b")
        .or_else(|| obj.get("rhs"))
        .or_else(|| obj.get("right"))
        .or_else(|| obj.get("r"))?;
    let c = obj
        .get("c")
        .or_else(|| obj.get("out"))
        .or_else(|| obj.get("output"))
        .or_else(|| obj.get("o"))?;

    Some((
        parse_wire_ref_value(a)?,
        parse_wire_ref_value(b)?,
        parse_wire_ref_value(c)?,
    ))
}

fn parse_selector_value(value: &serde_json::Value, keys: &[&str]) -> Option<FieldElement> {
    for key in keys {
        if let Some(val) = value.get(*key) {
            if let Some(fe) = parse_field_element_value(val) {
                return Some(fe);
            }
        }
    }
    None
}

fn parse_selector_array(value: &serde_json::Value) -> Option<[FieldElement; 5]> {
    let arr = value.as_array()?;
    if arr.len() < 5 {
        return None;
    }
    let mut coeffs = [
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
    ];
    for (idx, slot) in coeffs.iter_mut().enumerate().take(5) {
        if let Some(fe) = parse_field_element_value(&arr[idx]) {
            *slot = fe;
        }
    }
    Some(coeffs)
}

fn parse_plonk_gate_value(value: &serde_json::Value) -> Option<ExtendedConstraint> {
    let obj = value.as_object()?;

    if obj.contains_key("polynomial") || obj.contains_key("terms") {
        let poly = parse_polynomial_value(value)?;
        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("custom_gate");
        return Some(ExtendedConstraint::CustomGate(CustomGateConstraint::new(
            name, poly,
        )));
    }

    let (a, b, c) = parse_plonk_wire_triplet(value)?;

    let selectors = obj
        .get("selectors")
        .or_else(|| obj.get("selector"))
        .unwrap_or(value);

    let (q_l, q_r, q_o, q_m, q_c) = if let Some(coeffs) = selectors
        .get("coeffs")
        .or_else(|| selectors.get("coefficients"))
        .and_then(parse_selector_array)
    {
        (
            coeffs[0].clone(),
            coeffs[1].clone(),
            coeffs[2].clone(),
            coeffs[3].clone(),
            coeffs[4].clone(),
        )
    } else {
        (
            parse_selector_value(selectors, &["q_l", "ql", "qL"])
                .unwrap_or_else(FieldElement::zero),
            parse_selector_value(selectors, &["q_r", "qr", "qR"])
                .unwrap_or_else(FieldElement::zero),
            parse_selector_value(selectors, &["q_o", "qo", "qO"])
                .unwrap_or_else(FieldElement::zero),
            parse_selector_value(selectors, &["q_m", "qm", "qM"])
                .unwrap_or_else(FieldElement::zero),
            parse_selector_value(selectors, &["q_c", "qc", "qC"])
                .unwrap_or_else(FieldElement::zero),
        )
    };

    let gate = PlonkGate {
        a,
        b,
        c,
        q_l,
        q_r,
        q_o,
        q_m,
        q_c,
        custom_selectors: Vec::new(),
    };

    Some(ExtendedConstraint::PlonkGate(gate))
}

fn parse_lookup_table_value(
    value: &serde_json::Value,
    fallback_id: Option<usize>,
) -> Option<(usize, LookupTable)> {
    if let Some(array) = value.as_array() {
        let id = fallback_id?;
        let mut rows = Vec::new();
        let mut max_cols = 0usize;

        for row in array {
            let mut parsed_row = Vec::new();
            if let Some(values) = row.as_array() {
                for val in values {
                    if let Some(fe) = parse_field_element_value(val) {
                        parsed_row.push(fe);
                    }
                }
            } else if let Some(obj) = row.as_object() {
                if let Some(values) = obj.get("values").and_then(|v| v.as_array()) {
                    for val in values {
                        if let Some(fe) = parse_field_element_value(val) {
                            parsed_row.push(fe);
                        }
                    }
                } else if let Some(val) = obj.get("value").and_then(parse_field_element_value) {
                    parsed_row.push(val);
                }
            } else if let Some(fe) = parse_field_element_value(row) {
                parsed_row.push(fe);
            }

            if !parsed_row.is_empty() {
                max_cols = max_cols.max(parsed_row.len());
                rows.push(parsed_row);
            }
        }

        let num_columns = max_cols.max(1);
        let name = format!("table_{}", id);
        let mut table = LookupTable::new(&name, num_columns);
        table.entries = rows;
        return Some((id, table));
    }

    let obj = value.as_object()?;
    let id = obj
        .get("id")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .or(fallback_id)?;

    let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("lookup");
    let num_columns = obj
        .get("num_columns")
        .and_then(|v| v.as_u64())
        .or_else(|| obj.get("columns").and_then(|v| v.as_u64()))
        .map(|v| v as usize)
        .unwrap_or(1);

    let mut table = LookupTable::new(name, num_columns);

    if let Some(entries) = obj
        .get("entries")
        .or_else(|| obj.get("rows"))
        .or_else(|| obj.get("data"))
        .and_then(|v| v.as_array())
    {
        for row in entries {
            if let Some(values) = row.as_array() {
                let parsed = values
                    .iter()
                    .filter_map(parse_field_element_value)
                    .collect::<Vec<_>>();
                if !parsed.is_empty() {
                    table.entries.push(parsed);
                }
            }
        }
    }

    if table.entries.is_empty() && num_columns == 1 {
        if let Some(values) = obj.get("values").and_then(|v| v.as_array()) {
            for val in values {
                if let Some(fe) = parse_field_element_value(val) {
                    table.entries.push(vec![fe]);
                }
            }
        }
    }

    Some((id, table))
}

fn parse_acir_opcode_value(value: &serde_json::Value) -> Option<AcirOpcode> {
    if let Some(obj) = value.as_object() {
        if obj.len() == 1 {
            if let Some((key, inner)) = obj.iter().next() {
                return parse_acir_opcode_named(key, inner);
            }
        }

        if let Some(kind) = obj
            .get("type")
            .or_else(|| obj.get("opcode"))
            .and_then(|v| v.as_str())
        {
            return parse_acir_opcode_named(kind, value);
        }
    }

    None
}

fn parse_acir_opcode_named(name: &str, value: &serde_json::Value) -> Option<AcirOpcode> {
    let key = name.to_lowercase();

    match key.as_str() {
        "arithmetic" | "arith" => {
            let a =
                parse_linear_combination_value(value.get("a").unwrap_or(&serde_json::Value::Null))
                    .unwrap_or_default();
            let b =
                parse_linear_combination_value(value.get("b").unwrap_or(&serde_json::Value::Null))
                    .unwrap_or_default();
            let c =
                parse_linear_combination_value(value.get("c").unwrap_or(&serde_json::Value::Null))
                    .unwrap_or_default();
            let q_m =
                parse_field_element_value(value.get("q_m").unwrap_or(&serde_json::Value::Null))
                    .unwrap_or_else(FieldElement::zero);
            let q_c =
                parse_field_element_value(value.get("q_c").unwrap_or(&serde_json::Value::Null))
                    .unwrap_or_else(FieldElement::zero);

            Some(AcirOpcode::Arithmetic { a, b, c, q_m, q_c })
        }
        "range" | "range_check" | "rangecheck" => {
            let input = parse_wire_ref_value(value.get("input")?)?;
            let bits = value.get("bits").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            Some(AcirOpcode::Range { input, bits })
        }
        "blackbox" | "blackboxfunccall" | "black_box" | "blackbox_func_call" => {
            let name = value
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let inputs = value
                .get("inputs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(parse_wire_ref_value)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let outputs = value
                .get("outputs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(parse_wire_ref_value)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let op = match name.to_lowercase().as_str() {
                "sha256" => BlackBoxOp::SHA256 { inputs, outputs },
                "blake2s" => BlackBoxOp::Blake2s { inputs, outputs },
                "blake3" => BlackBoxOp::Blake3 { inputs, outputs },
                "keccak256" => BlackBoxOp::Keccak256 { inputs, outputs },
                "pedersen" => BlackBoxOp::Pedersen { inputs, outputs },
                "schnorrverify" => BlackBoxOp::SchnorrVerify {
                    inputs,
                    output: outputs.get(0).cloned().unwrap_or_else(|| WireRef::new(0)),
                },
                "ecdsasecp256k1" => BlackBoxOp::EcdsaSecp256k1 {
                    inputs,
                    output: outputs.get(0).cloned().unwrap_or_else(|| WireRef::new(0)),
                },
                _ => BlackBoxOp::Range {
                    input: outputs.get(0).cloned().unwrap_or_else(|| WireRef::new(0)),
                    bits: 0,
                },
            };

            Some(AcirOpcode::BlackBox(op))
        }
        "memoryop" | "memory" | "memop" => {
            let block_id = value.get("block_id").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let op_type = match value
                .get("op_type")
                .and_then(|v| v.as_str())
                .unwrap_or("read")
                .to_lowercase()
                .as_str()
            {
                "write" => MemoryOpType::Write,
                "init" => MemoryOpType::Init,
                _ => MemoryOpType::Read,
            };
            let address = parse_wire_ref_value(value.get("address")?)?;
            let value_wire = parse_wire_ref_value(value.get("value")?)?;
            Some(AcirOpcode::MemoryOp {
                block_id,
                op_type,
                address,
                value: value_wire,
            })
        }
        "brillig" => {
            let inputs = value
                .get("inputs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(parse_wire_ref_value)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let outputs = value
                .get("outputs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(parse_wire_ref_value)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            Some(AcirOpcode::Brillig { inputs, outputs })
        }
        _ => None,
    }
}

fn parse_air_expression_value(value: &serde_json::Value) -> Option<AirExpression> {
    if let Some(expr) = value.as_str() {
        return parse_air_expression_text(expr);
    }
    parse_air_expression(value)
}

fn parse_air_expression(value: &serde_json::Value) -> Option<AirExpression> {
    if let Some(expr) = value.as_str() {
        return parse_air_expression_text(expr);
    }

    if let Some(arr) = value.as_array() {
        if let Some(op) = arr.get(0).and_then(|v| v.as_str()) {
            let lower = op.to_lowercase();
            match lower.as_str() {
                "add" | "sum" if arr.len() >= 3 => {
                    let left = parse_air_expression(&arr[1])?;
                    let right = parse_air_expression(&arr[2])?;
                    return Some(AirExpression::Add(Box::new(left), Box::new(right)));
                }
                "mul" | "product" if arr.len() >= 3 => {
                    let left = parse_air_expression(&arr[1])?;
                    let right = parse_air_expression(&arr[2])?;
                    return Some(AirExpression::Mul(Box::new(left), Box::new(right)));
                }
                "sub" if arr.len() >= 3 => {
                    let left = parse_air_expression(&arr[1])?;
                    let right = parse_air_expression(&arr[2])?;
                    return Some(AirExpression::Sub(Box::new(left), Box::new(right)));
                }
                "neg" if arr.len() >= 2 => {
                    let inner = parse_air_expression(&arr[1])?;
                    return Some(AirExpression::Neg(Box::new(inner)));
                }
                _ => {}
            }
        }
    }

    if let Some(obj) = value.as_object() {
        if let Some(op) = obj
            .get("op")
            .or_else(|| obj.get("operator"))
            .and_then(|v| v.as_str())
        {
            let lower = op.to_lowercase();
            match lower.as_str() {
                "add" | "sum" => {
                    let left = obj
                        .get("lhs")
                        .or_else(|| obj.get("left"))
                        .and_then(parse_air_expression)?;
                    let right = obj
                        .get("rhs")
                        .or_else(|| obj.get("right"))
                        .and_then(parse_air_expression)?;
                    return Some(AirExpression::Add(Box::new(left), Box::new(right)));
                }
                "mul" | "product" => {
                    let left = obj
                        .get("lhs")
                        .or_else(|| obj.get("left"))
                        .and_then(parse_air_expression)?;
                    let right = obj
                        .get("rhs")
                        .or_else(|| obj.get("right"))
                        .and_then(parse_air_expression)?;
                    return Some(AirExpression::Mul(Box::new(left), Box::new(right)));
                }
                "sub" => {
                    let left = obj
                        .get("lhs")
                        .or_else(|| obj.get("left"))
                        .and_then(parse_air_expression)?;
                    let right = obj
                        .get("rhs")
                        .or_else(|| obj.get("right"))
                        .and_then(parse_air_expression)?;
                    return Some(AirExpression::Sub(Box::new(left), Box::new(right)));
                }
                "neg" => {
                    let inner = obj
                        .get("value")
                        .or_else(|| obj.get("expr"))
                        .and_then(parse_air_expression)?;
                    return Some(AirExpression::Neg(Box::new(inner)));
                }
                _ => {}
            }
        }

        if let Some(col_val) = obj.get("column").or_else(|| obj.get("col")) {
            if let Some(index) = col_val.as_u64() {
                let offset = obj.get("offset").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                return Some(AirExpression::Column {
                    index: index as usize,
                    offset,
                });
            }
            if let Some(col_obj) = col_val.as_object() {
                let index = col_obj.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let offset = col_obj.get("offset").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                return Some(AirExpression::Column { index, offset });
            }
        }

        if let Some(constant) = obj
            .get("constant")
            .or_else(|| obj.get("value"))
            .and_then(parse_field_element_value)
        {
            return Some(AirExpression::Constant(constant));
        }

        if obj.len() == 1 {
            if let Some((key, inner)) = obj.iter().next() {
                return match key.to_lowercase().as_str() {
                    "column" => {
                        let index =
                            inner.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                        let offset =
                            inner.get("offset").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                        Some(AirExpression::Column { index, offset })
                    }
                    "constant" => parse_field_element_value(inner).map(AirExpression::Constant),
                    "add" => parse_binary_air_expression(inner, AirExpression::Add),
                    "mul" => parse_binary_air_expression(inner, AirExpression::Mul),
                    "sub" => parse_binary_air_expression(inner, AirExpression::Sub),
                    "neg" => {
                        parse_air_expression(inner).map(|expr| AirExpression::Neg(Box::new(expr)))
                    }
                    _ => None,
                };
            }
        }

        if let Some(kind) = obj.get("type").and_then(|v| v.as_str()) {
            return match kind.to_lowercase().as_str() {
                "column" => {
                    let index = obj.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                    let offset = obj.get("offset").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                    Some(AirExpression::Column { index, offset })
                }
                "constant" => obj
                    .get("value")
                    .and_then(parse_field_element_value)
                    .map(AirExpression::Constant),
                "add" => parse_binary_air_expression(value, AirExpression::Add),
                "mul" => parse_binary_air_expression(value, AirExpression::Mul),
                "sub" => parse_binary_air_expression(value, AirExpression::Sub),
                "neg" => obj
                    .get("value")
                    .and_then(parse_air_expression)
                    .map(|expr| AirExpression::Neg(Box::new(expr))),
                _ => None,
            };
        }
    }

    parse_field_element_value(value).map(AirExpression::Constant)
}

fn parse_binary_air_expression(
    value: &serde_json::Value,
    ctor: fn(Box<AirExpression>, Box<AirExpression>) -> AirExpression,
) -> Option<AirExpression> {
    if let Some(arr) = value.as_array() {
        if arr.len() >= 2 {
            let left = parse_air_expression(&arr[0])?;
            let right = parse_air_expression(&arr[1])?;
            return Some(ctor(Box::new(left), Box::new(right)));
        }
    }

    let obj = value.as_object()?;
    let left = obj
        .get("lhs")
        .or_else(|| obj.get("left"))
        .and_then(parse_air_expression)?;
    let right = obj
        .get("rhs")
        .or_else(|| obj.get("right"))
        .and_then(parse_air_expression)?;
    Some(ctor(Box::new(left), Box::new(right)))
}

fn parse_air_domain(value: &serde_json::Value) -> Option<AirDomain> {
    if let Some(domain) = value.as_str() {
        return parse_air_domain_text(domain);
    }
    None
}

fn parse_air_domain_text(domain: &str) -> Option<AirDomain> {
    match domain.trim().to_lowercase().as_str() {
        "all" => Some(AirDomain::All),
        "first" => Some(AirDomain::First),
        "last" => Some(AirDomain::Last),
        "transition" => Some(AirDomain::Transition),
        _ => None,
    }
}

fn parse_air_expression_text(input: &str) -> Option<AirExpression> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(idx) = trimmed.find('+') {
        let left = parse_air_expression_text(&trimmed[..idx])?;
        let right = parse_air_expression_text(&trimmed[idx + 1..])?;
        return Some(AirExpression::Add(Box::new(left), Box::new(right)));
    }
    if let Some(idx) = trimmed.find('*') {
        let left = parse_air_expression_text(&trimmed[..idx])?;
        let right = parse_air_expression_text(&trimmed[idx + 1..])?;
        return Some(AirExpression::Mul(Box::new(left), Box::new(right)));
    }
    if let Some(idx) = trimmed.find('-') {
        if idx > 0 {
            let left = parse_air_expression_text(&trimmed[..idx])?;
            let right = parse_air_expression_text(&trimmed[idx + 1..])?;
            return Some(AirExpression::Sub(Box::new(left), Box::new(right)));
        }
    }

    if trimmed.starts_with("col(") {
        let inner = trimmed.trim_start_matches("col(").trim_end_matches(')');
        let mut parts = inner.split(',');
        let index = parts
            .next()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let offset = parts
            .next()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .unwrap_or(0);
        return Some(AirExpression::Column { index, offset });
    }

    if trimmed.starts_with("const(") {
        let inner = trimmed.trim_start_matches("const(").trim_end_matches(')');
        return parse_field_element_str(inner).map(AirExpression::Constant);
    }

    parse_field_element_str(trimmed).map(AirExpression::Constant)
}

fn parse_field_element_value(value: &serde_json::Value) -> Option<FieldElement> {
    match value {
        serde_json::Value::String(s) => parse_field_element_str(s),
        serde_json::Value::Number(num) => num.as_u64().map(FieldElement::from_u64),
        serde_json::Value::Object(obj) => {
            if let Some(hex) = obj.get("hex").and_then(|v| v.as_str()) {
                return parse_field_element_str(hex);
            }
            if let Some(dec) = obj.get("dec").and_then(|v| v.as_str()) {
                return parse_field_element_str(dec);
            }
            None
        }
        _ => None,
    }
}

fn parse_field_element_str(input: &str) -> Option<FieldElement> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (negative, value_str) = if let Some(rest) = trimmed.strip_prefix('-') {
        (true, rest)
    } else {
        (false, trimmed)
    };

    let mut fe = if value_str.starts_with("0x") || value_str.starts_with("0X") {
        FieldElement::from_hex(value_str).ok()?
    } else {
        let value = BigUint::parse_bytes(value_str.as_bytes(), 10)?;
        FieldElement::from_bytes(&value.to_bytes_be())
    };

    if negative {
        fe = fe.neg();
    }

    Some(fe)
}

fn parse_wire_ref_value(value: &serde_json::Value) -> Option<WireRef> {
    match value {
        serde_json::Value::Number(num) => num.as_u64().map(|v| WireRef::new(v as usize)),
        serde_json::Value::String(s) => {
            if let Ok(index) = s.parse::<usize>() {
                return Some(WireRef::new(index));
            }
            if let Some(stripped) = s.strip_prefix("wire_") {
                if let Ok(index) = stripped.parse::<usize>() {
                    return Some(WireRef::new(index));
                }
            }
            if let Some(stripped) = s.strip_prefix("witness_") {
                if let Ok(index) = stripped.parse::<usize>() {
                    return Some(WireRef::new(index));
                }
            }
            if let Some(stripped) = s.strip_prefix('w') {
                if let Ok(index) = stripped.parse::<usize>() {
                    return Some(WireRef::new(index));
                }
            }
            if let Some((_, idx)) = s.split_once(':') {
                if let Ok(index) = idx.parse::<usize>() {
                    return Some(WireRef::new(index));
                }
            }
            let lower = s.to_lowercase();
            if lower.starts_with("witness") || lower.starts_with("wire") {
                if let Some(first) = extract_numbers(&lower).first() {
                    return Some(WireRef::new(*first));
                }
            }
            None
        }
        serde_json::Value::Object(obj) => {
            if let Some(idx) = obj.get("Witness").and_then(|v| v.as_u64()) {
                return Some(WireRef::new(idx as usize));
            }
            if let Some(idx) = obj.get("witness").and_then(|v| v.as_u64()) {
                return Some(WireRef::new(idx as usize));
            }
            if let Some(idx) = obj.get("wire").and_then(|v| v.as_u64()) {
                return Some(WireRef::new(idx as usize));
            }
            if let Some(idx) = obj.get("signal").and_then(|v| v.as_u64()) {
                return Some(WireRef::new(idx as usize));
            }
            let index = obj.get("index").and_then(|v| v.as_u64())? as usize;
            let name = obj.get("name").and_then(|v| v.as_str());
            Some(WireRef {
                index,
                name: name.map(|s| s.to_string()),
            })
        }
        _ => None,
    }
}

fn parse_linear_combination_value(value: &serde_json::Value) -> Option<LinearCombination> {
    if let Some(array) = value.as_array() {
        let mut lc = LinearCombination::new();
        for term in array {
            if let Some(pair) = term.as_array() {
                if pair.len() >= 2 {
                    if let (Some(wire), Some(coeff)) = (
                        parse_wire_ref_value(&pair[0]),
                        parse_field_element_value(&pair[1]),
                    ) {
                        lc.add_term(wire, coeff);
                    } else if let (Some(wire), Some(coeff)) = (
                        parse_wire_ref_value(&pair[1]),
                        parse_field_element_value(&pair[0]),
                    ) {
                        lc.add_term(wire, coeff);
                    }
                }
            } else if let Some(obj) = term.as_object() {
                let wire = obj
                    .get("wire")
                    .or_else(|| obj.get("witness"))
                    .or_else(|| obj.get("index"))
                    .or_else(|| obj.get("signal"))
                    .and_then(parse_wire_ref_value)?;
                let coeff = obj
                    .get("coeff")
                    .or_else(|| obj.get("coef"))
                    .or_else(|| obj.get("coefficient"))
                    .or_else(|| obj.get("value"))
                    .and_then(parse_field_element_value)?;
                lc.add_term(wire, coeff);
            }
        }
        return Some(lc);
    }

    if let Some(obj) = value.as_object() {
        if let Some(inner) = obj
            .get("linear_combination")
            .or_else(|| obj.get("lc"))
            .or_else(|| obj.get("expression"))
        {
            return parse_linear_combination_value(inner);
        }

        if let Some(terms) = obj.get("terms").and_then(|v| v.as_array()) {
            let mut lc = LinearCombination::new();
            for term in terms {
                if let Some(pair) = term.as_array() {
                    if pair.len() >= 2 {
                        if let (Some(wire), Some(coeff)) = (
                            parse_wire_ref_value(&pair[0]),
                            parse_field_element_value(&pair[1]),
                        ) {
                            lc.add_term(wire, coeff);
                        } else if let (Some(wire), Some(coeff)) = (
                            parse_wire_ref_value(&pair[1]),
                            parse_field_element_value(&pair[0]),
                        ) {
                            lc.add_term(wire, coeff);
                        }
                    }
                } else if let Some(obj) = term.as_object() {
                    let wire = obj
                        .get("wire")
                        .or_else(|| obj.get("witness"))
                        .or_else(|| obj.get("index"))
                        .or_else(|| obj.get("signal"))
                        .and_then(parse_wire_ref_value)?;
                    let coeff = obj
                        .get("coeff")
                        .or_else(|| obj.get("coef"))
                        .or_else(|| obj.get("coefficient"))
                        .or_else(|| obj.get("value"))
                        .and_then(parse_field_element_value)?;
                    lc.add_term(wire, coeff);
                }
            }

            if let Some(constant) = obj
                .get("const")
                .or_else(|| obj.get("constant"))
                .and_then(parse_field_element_value)
            {
                lc.add_term(WireRef::new(0), constant);
            }

            return Some(lc);
        }
    }

    None
}

fn parse_polynomial_value(value: &serde_json::Value) -> Option<PolynomialConstraint> {
    let obj = value.as_object()?;
    let terms_val = obj.get("terms").and_then(|v| v.as_array())?;
    let degree = obj.get("degree").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let mut terms = Vec::new();

    for term_val in terms_val {
        let term_obj = term_val.as_object()?;
        let coefficient = term_obj
            .get("coeff")
            .or_else(|| term_obj.get("coefficient"))
            .and_then(parse_field_element_value)
            .unwrap_or_else(FieldElement::zero);

        let mut variables = Vec::new();
        if let Some(vars) = term_obj
            .get("vars")
            .or_else(|| term_obj.get("variables"))
            .and_then(|v| v.as_array())
        {
            for var in vars {
                if let Some(pair) = var.as_array() {
                    if pair.len() >= 2 {
                        let wire = parse_wire_ref_value(&pair[0])?;
                        let exp = pair[1].as_u64().unwrap_or(1) as usize;
                        variables.push((wire, exp));
                    }
                } else if let Some(obj) = var.as_object() {
                    let wire = obj.get("wire").and_then(parse_wire_ref_value)?;
                    let exp = obj.get("exp").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
                    variables.push((wire, exp));
                }
            }
        }

        terms.push(PolynomialTerm {
            coefficient,
            variables,
        });
    }

    Some(PolynomialConstraint { terms, degree })
}

fn extract_numbers(input: &str) -> Vec<usize> {
    let mut numbers = Vec::new();
    let mut current = String::new();

    for ch in input.chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
        } else if !current.is_empty() {
            if let Ok(num) = current.parse::<usize>() {
                numbers.push(num);
            }
            current.clear();
        }
    }

    if !current.is_empty() {
        if let Ok(num) = current.parse::<usize>() {
            numbers.push(num);
        }
    }

    numbers
}

impl Default for ConstraintChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_plonk_gate_addition() {
        let gate = PlonkGate::addition(WireRef::new(1), WireRef::new(2), WireRef::new(3));
        let mut wires = HashMap::new();
        wires.insert(1, FieldElement::from_u64(5));
        wires.insert(2, FieldElement::from_u64(7));
        wires.insert(3, FieldElement::from_u64(12));

        assert!(gate.check(&wires));

        wires.insert(3, FieldElement::from_u64(11));
        assert!(!gate.check(&wires));
    }

    #[test]
    fn test_lookup_vector_constraint() {
        let mut table = LookupTable::new("pair", 2);
        table
            .entries
            .push(vec![FieldElement::from_u64(1), FieldElement::from_u64(2)]);

        let lookup = LookupConstraint {
            input: WireRef::new(1),
            table_id: 0,
            table: Some(table),
            is_vector_lookup: true,
            additional_inputs: vec![WireRef::new(2)],
        };

        let mut wires = HashMap::new();
        wires.insert(1, FieldElement::from_u64(1));
        wires.insert(2, FieldElement::from_u64(2));

        let checker = ConstraintChecker::new();
        assert!(checker.check(&ExtendedConstraint::Lookup(lookup), &wires));
    }

    #[test]
    fn test_range_numeric() {
        let range = RangeConstraint {
            wire: WireRef::new(1),
            bits: 4,
            method: RangeMethod::Plookup,
        };

        let mut wires = HashMap::new();
        wires.insert(1, FieldElement::from_u64(15));

        let checker = ConstraintChecker::new();
        assert!(checker.check(&ExtendedConstraint::Range(range.clone()), &wires));

        wires.insert(1, FieldElement::from_u64(16));
        assert!(!checker.check(&ExtendedConstraint::Range(range), &wires));
    }

    #[test]
    fn test_range_bit_decomposition() {
        let range = RangeConstraint {
            wire: WireRef::new(1),
            bits: 4,
            method: RangeMethod::BitDecomposition {
                bit_wires: vec![
                    WireRef::new(2),
                    WireRef::new(3),
                    WireRef::new(4),
                    WireRef::new(5),
                ],
            },
        };

        let mut wires = HashMap::new();
        wires.insert(1, FieldElement::from_u64(5)); // 0101
        wires.insert(2, FieldElement::one()); // bit0
        wires.insert(3, FieldElement::zero()); // bit1
        wires.insert(4, FieldElement::one()); // bit2
        wires.insert(5, FieldElement::zero()); // bit3

        let checker = ConstraintChecker::new();
        assert!(checker.check(&ExtendedConstraint::Range(range.clone()), &wires));

        wires.insert(5, FieldElement::one()); // set bit3 -> value 13
        assert!(!checker.check(&ExtendedConstraint::Range(range), &wires));
    }

    #[test]
    fn test_polynomial_constraint() {
        let poly = PolynomialConstraint {
            terms: vec![
                PolynomialTerm {
                    coefficient: FieldElement::one(),
                    variables: vec![(WireRef::new(1), 2)], // x^2
                },
                PolynomialTerm {
                    coefficient: FieldElement::one(),
                    variables: vec![(WireRef::new(2), 1)], // y
                },
                PolynomialTerm {
                    coefficient: FieldElement::from_u64(5).neg(),
                    variables: vec![], // -5
                },
            ],
            degree: 2,
        };

        let mut wires = HashMap::new();
        wires.insert(1, FieldElement::from_u64(2));
        wires.insert(2, FieldElement::from_u64(1));

        let checker = ConstraintChecker::new();
        assert!(checker.check(&ExtendedConstraint::Polynomial(poly), &wires));
    }

    #[test]
    fn test_unknown_lookup_policy() {
        let lookup = LookupConstraint {
            input: WireRef::new(1),
            table_id: 42,
            table: None,
            is_vector_lookup: false,
            additional_inputs: Vec::new(),
        };

        let mut wires = HashMap::new();
        wires.insert(1, FieldElement::from_u64(1));

        let checker = ConstraintChecker::new();
        assert!(!checker.check(&ExtendedConstraint::Lookup(lookup.clone()), &wires));

        let checker =
            ConstraintChecker::new().with_unknown_lookup_policy(UnknownLookupPolicy::FailOpen);
        assert!(checker.check(&ExtendedConstraint::Lookup(lookup), &wires));
    }

    #[test]
    fn test_parse_plonk_json() {
        let json = r#"
        {
          "tables": {
            "0": { "name": "range_4", "num_columns": 1, "entries": [[0], [1], [2], [3]] }
          },
          "gates": [
            { "a": 1, "b": 2, "c": 3, "q_l": "1", "q_r": "1", "q_o": "-1", "q_m": "0", "q_c": "0" }
          ],
          "lookups": [
            { "table_id": 0, "input": 1 }
          ]
        }
        "#;

        let parsed = ConstraintParser::parse_plonk_with_tables(json);
        assert_eq!(parsed.lookup_tables.len(), 1);
        assert_eq!(parsed.constraints.len(), 2);
    }

    #[test]
    fn test_parse_plonk_json_embedded() {
        let json = r#"
        log: begin
        { "gates": { "add": { "wires": [1, 2, 3], "selectors": { "q_l": "1", "q_r": "1", "q_o": "-1" } } } }
        log: end
        "#;

        let parsed = ConstraintParser::parse_plonk_with_tables(json);
        assert_eq!(parsed.constraints.len(), 1);
        assert!(matches!(
            parsed.constraints[0],
            ExtendedConstraint::PlonkGate(_)
        ));
    }

    #[test]
    fn test_parse_plonk_lookup_inline_table() {
        let json = r#"
        {
          "lookups": [
            { "table": { "id": 7, "columns": 1, "values": ["2", "3"] }, "inputs": [ { "Witness": 1 } ] }
          ]
        }
        "#;

        let parsed = ConstraintParser::parse_plonk_with_tables(json);
        assert_eq!(parsed.lookup_tables.len(), 1);
        assert_eq!(parsed.constraints.len(), 1);
    }

    #[test]
    fn test_parse_acir_json() {
        let json = r#"
        {
          "opcodes": [
            { "Arithmetic": { "a": [[1, "1"]], "b": [[2, "1"]], "c": [[3, "1"]], "q_m": "1", "q_c": "0" } },
            { "Range": { "input": 4, "bits": 8 } }
          ]
        }
        "#;

        let parsed = ConstraintParser::parse_acir_with_tables(json.as_bytes());
        assert_eq!(parsed.constraints.len(), 2);
        assert!(matches!(
            parsed.constraints[0],
            ExtendedConstraint::AcirOpcode(_)
        ));
    }

    #[test]
    fn test_parse_acir_json_variants() {
        let json = r#"
        {
          "opcodes": [
            { "type": "arithmetic", "a": { "terms": [ { "witness": 1, "coeff": "1" } ] },
              "b": { "terms": [ { "witness": 2, "coeff": "1" } ] },
              "c": { "terms": [ { "witness": 3, "coeff": "1" } ] },
              "q_m": "1", "q_c": "0" },
            { "opcode": "range_check", "input": { "Witness": 4 }, "bits": 8 }
          ]
        }
        "#;

        let parsed = ConstraintParser::parse_acir_with_tables(json.as_bytes());
        assert_eq!(parsed.constraints.len(), 2);
    }

    #[test]
    fn test_parse_air_json() {
        let json = r#"
        {
          "constraints": [
            { "expression": { "Add": [ { "Column": { "index": 0, "offset": 0 } }, { "Constant": "1" } ] }, "domain": "Transition" }
          ]
        }
        "#;

        let parsed = ConstraintParser::parse_air_with_tables(json);
        assert_eq!(parsed.constraints.len(), 1);
        assert!(matches!(
            parsed.constraints[0],
            ExtendedConstraint::AirConstraint(_)
        ));
    }

    #[test]
    fn test_parse_air_json_variants() {
        let json = r#"
        {
          "constraints": {
            "transition": [
              { "expr": "col(0,0) + const(1)" }
            ]
          }
        }
        "#;

        let parsed = ConstraintParser::parse_air_with_tables(json);
        assert_eq!(parsed.constraints.len(), 1);
        assert!(matches!(
            parsed.constraints[0],
            ExtendedConstraint::AirConstraint(_)
        ));
    }
}
