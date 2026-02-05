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
        let result = self.q_l.mul(&a)
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
    Brillig { inputs: Vec<WireRef>, outputs: Vec<WireRef> },
}

/// BlackBox operations in ACIR
#[derive(Debug, Clone)]
pub enum BlackBoxOp {
    SHA256 { inputs: Vec<WireRef>, outputs: Vec<WireRef> },
    Blake2s { inputs: Vec<WireRef>, outputs: Vec<WireRef> },
    Blake3 { inputs: Vec<WireRef>, outputs: Vec<WireRef> },
    Keccak256 { inputs: Vec<WireRef>, outputs: Vec<WireRef> },
    Pedersen { inputs: Vec<WireRef>, outputs: Vec<WireRef> },
    SchnorrVerify { inputs: Vec<WireRef>, output: WireRef },
    EcdsaSecp256k1 { inputs: Vec<WireRef>, output: WireRef },
    FixedBaseScalarMul { inputs: Vec<WireRef>, outputs: Vec<WireRef> },
    RecursiveAggregation { inputs: Vec<WireRef>, outputs: Vec<WireRef> },
    Range { input: WireRef, bits: usize },
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

/// Parser for constraint representations
pub struct ConstraintParser;

impl ConstraintParser {
    /// Parse R1CS constraints from a string representation
    pub fn parse_r1cs(_content: &str) -> Vec<ExtendedConstraint> {
        // TODO: Implement R1CS parsing
        Vec::new()
    }

    /// Parse PLONK constraints
    pub fn parse_plonk(_content: &str) -> Vec<ExtendedConstraint> {
        // TODO: Implement PLONK parsing
        Vec::new()
    }

    /// Parse ACIR from Noir
    pub fn parse_acir(_bytes: &[u8]) -> Vec<ExtendedConstraint> {
        // TODO: Implement ACIR parsing
        Vec::new()
    }

    /// Parse Cairo AIR constraints
    pub fn parse_air(_content: &str) -> Vec<ExtendedConstraint> {
        // TODO: Implement AIR parsing
        Vec::new()
    }
}

/// Constraint checker that supports all constraint types
pub struct ConstraintChecker {
    /// Lookup tables
    lookup_tables: HashMap<usize, LookupTable>,
}

impl ConstraintChecker {
    pub fn new() -> Self {
        Self {
            lookup_tables: HashMap::new(),
        }
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
            ExtendedConstraint::AcirOpcode(_) | ExtendedConstraint::AirConstraint(_) => {
                true // Not yet supported: treat as satisfied
            }
        }
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
            return true; // Unknown table: assume satisfied
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
                expr = expr.add(SymbolicValue::concrete(gate.q_m.clone()).mul(
                    wire_to_symbolic(&gate.a).mul(wire_to_symbolic(&gate.b)),
                ));
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
                                    SymbolicValue::concrete(
                                        field_from_biguint(&(BigUint::from(1u8) << range.bits)),
                                    ),
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
            ExtendedConstraint::Add { a, b, c } => {
                Some(SymbolicConstraint::eq(
                    wire_to_symbolic(a).add(wire_to_symbolic(b)),
                    wire_to_symbolic(c),
                ))
            }
            ExtendedConstraint::Mul { a, b, c } => Some(SymbolicConstraint::r1cs(
                wire_to_symbolic(a),
                wire_to_symbolic(b),
                wire_to_symbolic(c),
            )),
            ExtendedConstraint::Constant { wire, value } => Some(SymbolicConstraint::eq(
                wire_to_symbolic(wire),
                SymbolicValue::concrete(value.clone()),
            )),
            ExtendedConstraint::AcirOpcode(_) | ExtendedConstraint::AirConstraint(_) => None,
        }
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
        table.entries.push(vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
        ]);

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
}
