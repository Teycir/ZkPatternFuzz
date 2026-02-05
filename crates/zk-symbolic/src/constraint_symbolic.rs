//! Symbolic lowering for extended constraints.

use std::collections::HashMap;

use num_bigint::BigUint;
use zk_core::FieldElement;
use zk_constraints::constraint_types::{
    AcirOpcode, BlackBoxOp, ConstraintChecker, ExtendedConstraint, LinearCombination, LookupTable,
    PolynomialConstraint, RangeMethod, WireRef,
};

use crate::executor::{SymbolicConstraint, SymbolicValue};

const DEFAULT_LOOKUP_ROW_LIMIT: usize = 256;

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

/// Extension trait for lowering extended constraints into symbolic form.
pub trait ExtendedConstraintSymbolicExt {
    fn to_symbolic_with_tables(
        &self,
        tables: &HashMap<usize, LookupTable>,
        options: &SymbolicConversionOptions,
    ) -> Option<SymbolicConstraint>;
}

impl ExtendedConstraintSymbolicExt for ExtendedConstraint {
    fn to_symbolic_with_tables(
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
}

/// Extension trait for converting constraints via a ConstraintChecker.
pub trait ConstraintCheckerSymbolicExt {
    fn to_symbolic(&self, constraint: &ExtendedConstraint) -> Option<SymbolicConstraint>;

    fn to_symbolic_with_options(
        &self,
        constraint: &ExtendedConstraint,
        options: &SymbolicConversionOptions,
    ) -> Option<SymbolicConstraint>;
}

impl ConstraintCheckerSymbolicExt for ConstraintChecker {
    fn to_symbolic(&self, constraint: &ExtendedConstraint) -> Option<SymbolicConstraint> {
        self.to_symbolic_with_options(constraint, &SymbolicConversionOptions::default())
    }

    fn to_symbolic_with_options(
        &self,
        constraint: &ExtendedConstraint,
        options: &SymbolicConversionOptions,
    ) -> Option<SymbolicConstraint> {
        constraint.to_symbolic_with_tables(self.lookup_tables(), options)
    }
}

fn field_from_biguint(value: &BigUint) -> FieldElement {
    FieldElement::from_bytes(&value.to_bytes_be())
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
