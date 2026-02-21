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
        { "gates": { "add": { "wires": [1, 2, 3], "selectors": { "q_l": "1", "q_r": "1", "q_o": "-1", "q_m": "0", "q_c": "0" } } } }
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
            { "table": { "id": 7, "name": "inline_lookup", "columns": 1, "values": ["2", "3"] }, "inputs": [ { "Witness": 1 } ] }
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

#[cfg(feature = "acir-bytecode")]
#[test]
fn test_decode_legacy_bincode_roundtrip() {
    #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct DemoPayload {
        a: u32,
        b: String,
    }

    let expected = DemoPayload {
        a: 7,
        b: "legacy".to_string(),
    };

    let encoded = bincode::serde::encode_to_vec(&expected, bincode::config::legacy())
        .expect("legacy bincode encoding should succeed");
    let decoded = decode_legacy_bincode::<DemoPayload>(&encoded);

    assert_eq!(decoded, Some(expected));
}

#[cfg(feature = "acir-bytecode")]
#[test]
fn test_decode_legacy_bincode_rejects_invalid_payload() {
    let decoded = decode_legacy_bincode::<serde_json::Value>(&[0xFF, 0x00, 0x01]);
    assert!(decoded.is_none());
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
