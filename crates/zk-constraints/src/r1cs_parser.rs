//! Binary R1CS format parser for Circom circuits
//!
//! Parses .r1cs binary files produced by Circom compiler.
//! Format specification: https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md
//!
//! This enables direct analysis of real ZK circuits without requiring
//! the full Circom toolchain at runtime.

use anyhow::{anyhow, Context, Result};
use num_bigint::BigUint;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use zk_core::FieldElement;

/// R1CS constraint: (A·w) * (B·w) = (C·w)
#[derive(Debug, Clone)]
pub struct R1CSConstraint {
    /// Signal index -> coefficient for A
    pub a: Vec<(usize, BigUint)>,
    /// Signal index -> coefficient for B
    pub b: Vec<(usize, BigUint)>,
    /// Signal index -> coefficient for C
    pub c: Vec<(usize, BigUint)>,
}

impl R1CSConstraint {
    /// Check if this constraint involves any of the given wire indices
    pub fn involves_wires(&self, wire_indices: &HashSet<usize>) -> bool {
        self.a.iter().any(|(idx, _)| wire_indices.contains(idx))
            || self.b.iter().any(|(idx, _)| wire_indices.contains(idx))
            || self.c.iter().any(|(idx, _)| wire_indices.contains(idx))
    }

    /// Get all wire indices used in this constraint
    pub fn wire_indices(&self) -> HashSet<usize> {
        let mut indices = HashSet::new();
        for (idx, _) in &self.a {
            indices.insert(*idx);
        }
        for (idx, _) in &self.b {
            indices.insert(*idx);
        }
        for (idx, _) in &self.c {
            indices.insert(*idx);
        }
        indices
    }

    /// Check if constraint is trivial (e.g., 0 = 0)
    pub fn is_trivial(&self) -> bool {
        self.a.is_empty() && self.b.is_empty() && self.c.is_empty()
    }

    /// Convert to our internal ExtendedConstraint format
    pub fn to_extended(&self) -> crate::constraint_types::ExtendedConstraint {
        use crate::constraint_types::LinearCombination;
        use crate::constraint_types::{ExtendedConstraint, R1CSConstraint as InternalR1CS, WireRef};

        let convert_terms = |terms: &[(usize, BigUint)]| -> LinearCombination {
            let mut lc = LinearCombination::new();
            for (idx, coeff) in terms {
                let fe = biguint_to_field_element(coeff);
                lc.add_term(WireRef::new(*idx), fe);
            }
            lc
        };

        ExtendedConstraint::R1CS(InternalR1CS {
            a: convert_terms(&self.a),
            b: convert_terms(&self.b),
            c: convert_terms(&self.c),
        })
    }
}

/// Complete R1CS representation parsed from binary file
#[derive(Debug)]
pub struct R1CS {
    /// Field size (typically BN254 scalar field)
    pub field_size: BigUint,
    /// Number of field element bytes (32 for BN254)
    pub field_bytes: usize,
    /// Total number of wires/signals
    pub num_wires: usize,
    /// Number of public outputs
    pub num_public_outputs: usize,
    /// Number of public inputs
    pub num_public_inputs: usize,
    /// Number of private inputs
    pub num_private_inputs: usize,
    /// Number of labels (for debugging)
    pub num_labels: u64,
    /// All constraints
    pub constraints: Vec<R1CSConstraint>,
    /// Wire/signal names (if available from .sym file)
    pub wire_names: Vec<String>,
    /// Whether custom gates are used (Ultra/Turbo PLONK)
    pub custom_gates_used: bool,
}

/// BN254 scalar field modulus
const BN254_MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

impl R1CS {
    /// Parse .r1cs binary file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path.as_ref())
            .with_context(|| format!("Failed to open R1CS file: {:?}", path.as_ref()))?;
        let mut reader = BufReader::new(file);
        Self::parse(&mut reader)
    }

    /// Parse from a reader
    pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        // Read magic number "r1cs" (0x72316373)
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != b"r1cs" {
            return Err(anyhow!(
                "Invalid R1CS file: bad magic (expected 'r1cs', got {:?})",
                magic
            ));
        }

        // Read version (4 bytes, little-endian)
        let version = read_u32_le(reader)?;
        if version != 1 {
            return Err(anyhow!(
                "Unsupported R1CS version: {} (only v1 supported)",
                version
            ));
        }

        // Read number of sections
        let num_sections = read_u32_le(reader)?;

        let mut r1cs = R1CS {
            field_size: BigUint::from(0u32),
            field_bytes: 32,
            num_wires: 0,
            num_public_outputs: 0,
            num_public_inputs: 0,
            num_private_inputs: 0,
            num_labels: 0,
            constraints: Vec::new(),
            wire_names: Vec::new(),
            custom_gates_used: false,
        };

        // Two-pass parsing: First collect section locations, then parse in correct order
        // This handles R1CS files where sections appear in different orders
        let mut section_info: Vec<(u32, u64, u64)> = Vec::with_capacity(num_sections as usize);
        
        for _ in 0..num_sections {
            let section_type = read_u32_le(reader)?;
            let section_size = read_u64_le(reader)?;
            let section_start = reader.stream_position()?;
            
            section_info.push((section_type, section_start, section_size));
            
            // Skip to next section
            reader.seek(SeekFrom::Start(section_start + section_size))?;
        }
        
        // Parse header section first (type 1) - needed for field_bytes and num_constraints
        for &(section_type, section_start, _section_size) in &section_info {
            if section_type == 1 {
                reader.seek(SeekFrom::Start(section_start))?;
                parse_header_section(reader, &mut r1cs)?;
                break;
            }
        }
        
        // Parse remaining sections
        for &(section_type, section_start, section_size) in &section_info {
            reader.seek(SeekFrom::Start(section_start))?;
            
            match section_type {
                1 => {} // Already parsed
                2 => parse_constraints_section(reader, &mut r1cs)?,
                3 => parse_wire2label_section(reader, &mut r1cs, section_size)?,
                4 => parse_custom_gates_section(reader, &mut r1cs)?,
                _ => {
                    tracing::debug!("Skipping unknown section type: {}", section_type);
                }
            }
        }

        // Validate parsed data
        r1cs.validate()?;

        tracing::info!(
            "Parsed R1CS: {} constraints, {} wires, {} public inputs, {} private inputs",
            r1cs.constraints.len(),
            r1cs.num_wires,
            r1cs.num_public_inputs,
            r1cs.num_private_inputs
        );

        Ok(r1cs)
    }

    /// Validate the parsed R1CS
    fn validate(&self) -> Result<()> {
        if self.num_wires == 0 {
            return Err(anyhow!("Invalid R1CS: zero wires"));
        }

        // Check field size is BN254
        let bn254_modulus = BigUint::parse_bytes(BN254_MODULUS.as_bytes(), 10)
            .ok_or_else(|| anyhow!("Failed to parse BN254 modulus"))?;

        if self.field_size != bn254_modulus {
            tracing::warn!("Non-BN254 field detected. Field size: {}", self.field_size);
        }

        Ok(())
    }

    /// Get input wire indices (public outputs, public inputs, private inputs)
    /// Wire 0 is always constant 1 in Circom R1CS
    pub fn input_wire_indices(&self) -> Vec<usize> {
        let total_inputs =
            self.num_public_outputs + self.num_public_inputs + self.num_private_inputs;

        // Wire 0 is always constant 1
        // Wires 1..total_inputs+1 are inputs
        (1..=total_inputs).collect()
    }

    /// Get only public input wire indices
    pub fn public_input_indices(&self) -> Vec<usize> {
        let start = 1 + self.num_public_outputs;
        let end = start + self.num_public_inputs;
        (start..end).collect()
    }

    /// Get only private input wire indices
    pub fn private_input_indices(&self) -> Vec<usize> {
        let start = 1 + self.num_public_outputs + self.num_public_inputs;
        let end = start + self.num_private_inputs;
        (start..end).collect()
    }

    /// Extract constraints that directly involve input wires
    pub fn input_constraints(&self) -> Vec<&R1CSConstraint> {
        let input_indices: HashSet<_> = self.input_wire_indices().into_iter().collect();

        self.constraints
            .iter()
            .filter(|c| c.involves_wires(&input_indices))
            .collect()
    }

    /// Get constraint density (constraints per signal)
    pub fn constraint_density(&self) -> f64 {
        if self.num_wires == 0 {
            return 0.0;
        }
        self.constraints.len() as f64 / self.num_wires as f64
    }

    /// Check if circuit might be underconstrained
    pub fn is_likely_underconstrained(&self) -> bool {
        let total_inputs = self.num_public_inputs + self.num_private_inputs;
        total_inputs > self.constraints.len()
    }

    /// Convert all constraints to extended format for symbolic analysis
    pub fn to_extended_constraints(&self) -> Vec<crate::constraint_types::ExtendedConstraint> {
        self.constraints.iter().map(|c| c.to_extended()).collect()
    }

    /// Get wire name by index (if available)
    pub fn wire_name(&self, index: usize) -> Option<&str> {
        self.wire_names.get(index).map(|s| s.as_str())
    }
}

// ============================================================================
// Section Parsers
// ============================================================================

fn parse_header_section<R: Read>(reader: &mut R, r1cs: &mut R1CS) -> Result<()> {
    // Field size (variable length based on first 4 bytes)
    let field_bytes = read_u32_le(reader)? as usize;
    r1cs.field_bytes = field_bytes;

    // Read field modulus
    let mut field_bytes_vec = vec![0u8; field_bytes];
    reader.read_exact(&mut field_bytes_vec)?;
    r1cs.field_size = BigUint::from_bytes_le(&field_bytes_vec);

    // Read wire counts
    r1cs.num_wires = read_u32_le(reader)? as usize;
    r1cs.num_public_outputs = read_u32_le(reader)? as usize;
    r1cs.num_public_inputs = read_u32_le(reader)? as usize;
    r1cs.num_private_inputs = read_u32_le(reader)? as usize;
    r1cs.num_labels = read_u64_le(reader)?;

    // Number of constraints (used to pre-allocate)
    let num_constraints = read_u32_le(reader)? as usize;
    r1cs.constraints = Vec::with_capacity(num_constraints);

    tracing::debug!(
        "R1CS Header: {} wires, {} constraints, field bytes: {}",
        r1cs.num_wires,
        num_constraints,
        field_bytes
    );

    Ok(())
}

fn parse_constraints_section<R: Read>(reader: &mut R, r1cs: &mut R1CS) -> Result<()> {
    let num_constraints = r1cs.constraints.capacity();

    for i in 0..num_constraints {
        // Parse A, B, C linear combinations
        let a = read_linear_combination(reader, r1cs.field_bytes)?;
        let b = read_linear_combination(reader, r1cs.field_bytes)?;
        let c = read_linear_combination(reader, r1cs.field_bytes)?;

        r1cs.constraints.push(R1CSConstraint { a, b, c });

        if i > 0 && i % 10000 == 0 {
            tracing::debug!("Parsed {}/{} constraints", i, num_constraints);
        }
    }

    Ok(())
}

fn read_linear_combination<R: Read>(
    reader: &mut R,
    field_bytes: usize,
) -> Result<Vec<(usize, BigUint)>> {
    let num_terms = read_u32_le(reader)? as usize;
    let mut terms = Vec::with_capacity(num_terms);

    for _ in 0..num_terms {
        let wire_idx = read_u32_le(reader)? as usize;

        // Read field element coefficient
        let mut coeff_bytes = vec![0u8; field_bytes];
        reader.read_exact(&mut coeff_bytes)?;
        let coeff = BigUint::from_bytes_le(&coeff_bytes);

        // Skip zero coefficients
        if coeff != BigUint::from(0u32) {
            terms.push((wire_idx, coeff));
        }
    }

    Ok(terms)
}

fn parse_wire2label_section<R: Read + Seek>(
    reader: &mut R,
    _r1cs: &mut R1CS,
    section_size: u64,
) -> Result<()> {
    // This section maps wire indices to label IDs
    // For now, we just skip it as wire names come from .sym file
    let start = reader.stream_position()?;
    reader.seek(SeekFrom::Start(start + section_size))?;
    Ok(())
}

fn parse_custom_gates_section<R: Read + Seek>(reader: &mut R, r1cs: &mut R1CS) -> Result<()> {
    // Custom gates section indicates Ultra/Turbo PLONK features
    r1cs.custom_gates_used = true;

    // Read custom gate count
    let num_gates = read_u32_le(reader)?;
    tracing::debug!("R1CS has {} custom gates", num_gates);

    // Skip the rest for now - we focus on R1CS constraints
    // Future: parse custom gate definitions for enhanced analysis
    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

fn read_u32_le<R: Read>(reader: &mut R) -> Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64_le<R: Read>(reader: &mut R) -> Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Convert BigUint to our FieldElement (truncates to 32 bytes)
fn biguint_to_field_element(n: &BigUint) -> FieldElement {
    // FieldElement uses big-endian byte order; BigUint is value-based,
    // so convert to big-endian and pad to 32 bytes.
    FieldElement::from_bytes(&n.to_bytes_be())
}

// ============================================================================
// Symbol File Parser (.sym)
// ============================================================================

/// Parse Circom .sym file for wire names
pub fn parse_sym_file<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path.as_ref())
        .with_context(|| format!("Failed to read .sym file: {:?}", path.as_ref()))?;

    let mut names = Vec::new();

    for line in content.lines() {
        // Format: wireIdx,labelIdx,componentName.signalName
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 3 {
            let name = parts[2..].join(","); // Handle commas in names
            names.push(name);
        }
    }

    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Create a minimal valid R1CS binary for testing
    fn create_test_r1cs() -> Vec<u8> {
        let mut data = Vec::new();

        // Magic: "r1cs"
        data.extend_from_slice(b"r1cs");

        // Version: 1
        data.extend_from_slice(&1u32.to_le_bytes());

        // Number of sections: 2 (header + constraints)
        data.extend_from_slice(&2u32.to_le_bytes());

        // Section 1: Header (type=1)
        data.extend_from_slice(&1u32.to_le_bytes());
        // Section size (we'll calculate this)
        let header_size = 4 + 32 + 4 * 4 + 8 + 4; // field_bytes + field + counts + labels + num_constraints
        data.extend_from_slice(&(header_size as u64).to_le_bytes());

        // Field bytes: 32
        data.extend_from_slice(&32u32.to_le_bytes());

        // Field modulus (BN254)
        let modulus = BigUint::parse_bytes(BN254_MODULUS.as_bytes(), 10).unwrap();
        let mut mod_bytes = modulus.to_bytes_le();
        mod_bytes.resize(32, 0);
        data.extend_from_slice(&mod_bytes);

        // Wire counts
        data.extend_from_slice(&10u32.to_le_bytes()); // num_wires
        data.extend_from_slice(&1u32.to_le_bytes()); // num_public_outputs
        data.extend_from_slice(&2u32.to_le_bytes()); // num_public_inputs
        data.extend_from_slice(&3u32.to_le_bytes()); // num_private_inputs
        data.extend_from_slice(&10u64.to_le_bytes()); // num_labels
        data.extend_from_slice(&1u32.to_le_bytes()); // num_constraints

        // Section 2: Constraints (type=2)
        data.extend_from_slice(&2u32.to_le_bytes());

        // One simple constraint: wire_1 * wire_2 = wire_3
        // A: 1 term (wire_1, coeff=1)
        // B: 1 term (wire_2, coeff=1)
        // C: 1 term (wire_3, coeff=1)
        let constraint_size = (4 + 4 + 32) * 3; // 3 linear combinations, each with 1 term
        data.extend_from_slice(&(constraint_size as u64).to_le_bytes());

        // A: wire_1 * 1
        data.extend_from_slice(&1u32.to_le_bytes()); // num_terms
        data.extend_from_slice(&1u32.to_le_bytes()); // wire_idx
        let mut one = [0u8; 32];
        one[0] = 1;
        data.extend_from_slice(&one);

        // B: wire_2 * 1
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&one);

        // C: wire_3 * 1
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&one);

        data
    }

    #[test]
    fn test_parse_r1cs_binary() {
        let data = create_test_r1cs();
        let mut cursor = Cursor::new(data);

        let r1cs = R1CS::parse(&mut cursor).expect("Should parse test R1CS");

        assert_eq!(r1cs.num_wires, 10);
        assert_eq!(r1cs.num_public_inputs, 2);
        assert_eq!(r1cs.num_private_inputs, 3);
        assert_eq!(r1cs.num_public_outputs, 1);
        assert_eq!(r1cs.constraints.len(), 1);

        // Check constraint structure
        let c = &r1cs.constraints[0];
        assert_eq!(c.a.len(), 1);
        assert_eq!(c.b.len(), 1);
        assert_eq!(c.c.len(), 1);
        assert_eq!(c.a[0].0, 1); // wire_1
        assert_eq!(c.b[0].0, 2); // wire_2
        assert_eq!(c.c[0].0, 3); // wire_3
    }

    #[test]
    fn test_input_wire_indices() {
        let data = create_test_r1cs();
        let mut cursor = Cursor::new(data);
        let r1cs = R1CS::parse(&mut cursor).unwrap();

        let input_indices = r1cs.input_wire_indices();
        // Should be 1..=6 (1 public output + 2 public inputs + 3 private inputs)
        assert_eq!(input_indices, vec![1, 2, 3, 4, 5, 6]);

        let public_indices = r1cs.public_input_indices();
        assert_eq!(public_indices, vec![2, 3]); // After public output

        let private_indices = r1cs.private_input_indices();
        assert_eq!(private_indices, vec![4, 5, 6]);
    }

    #[test]
    fn test_constraint_to_extended() {
        let constraint = R1CSConstraint {
            a: vec![(1, BigUint::from(1u32))],
            b: vec![(2, BigUint::from(1u32))],
            c: vec![(3, BigUint::from(1u32))],
        };

        let extended = constraint.to_extended();

        // Should be an R1CS constraint
        match extended {
            crate::ExtendedConstraint::R1CS(_) => (),
            _ => panic!("Expected R1CS constraint"),
        }
    }

    #[test]
    fn test_biguint_to_field_element_endianness() {
        let one = BigUint::from(1u32);
        let fe = biguint_to_field_element(&one);
        assert_eq!(fe, FieldElement::from_u64(1));
    }

    #[test]
    fn test_generate_smt_inputs_simple_r1cs() {
        let modulus = BigUint::parse_bytes(BN254_MODULUS.as_bytes(), 10).unwrap();

        let c1 = R1CSConstraint {
            // x * 1 = 2
            a: vec![(1, BigUint::from(1u32))],
            b: vec![(0, BigUint::from(1u32))],
            c: vec![(0, BigUint::from(2u32))],
        };

        let c2 = R1CSConstraint {
            // y * 1 = 3
            a: vec![(2, BigUint::from(1u32))],
            b: vec![(0, BigUint::from(1u32))],
            c: vec![(0, BigUint::from(3u32))],
        };

        let c3 = R1CSConstraint {
            // (x + y) * 1 = 5
            a: vec![(1, BigUint::from(1u32)), (2, BigUint::from(1u32))],
            b: vec![(0, BigUint::from(1u32))],
            c: vec![(0, BigUint::from(5u32))],
        };

        let r1cs = R1CS {
            field_size: modulus.clone(),
            field_bytes: 32,
            num_wires: 3,
            num_public_outputs: 0,
            num_public_inputs: 1,
            num_private_inputs: 1,
            num_labels: 0,
            constraints: vec![c1, c2, c3],
            wire_names: Vec::new(),
            custom_gates_used: false,
        };

        let solutions = crate::r1cs_to_smt::generate_constraint_guided_inputs(&r1cs, 2, 2000);
        assert!(!solutions.is_empty(), "Expected at least one solution");

        fn eval_lc(terms: &[(usize, BigUint)], wires: &[BigUint], modulus: &BigUint) -> BigUint {
            let mut acc = BigUint::from(0u32);
            for (idx, coeff) in terms {
                let value = wires.get(*idx).cloned().unwrap_or_default();
                let term = (coeff * value) % modulus;
                acc = (acc + term) % modulus;
            }
            acc
        }

        for inputs in solutions {
            assert_eq!(inputs.len(), 2);

            let mut wires = vec![BigUint::from(1u32); r1cs.num_wires];
            wires[1] = inputs[0].to_biguint();
            wires[2] = inputs[1].to_biguint();

            for constraint in &r1cs.constraints {
                let a = eval_lc(&constraint.a, &wires, &modulus);
                let b = eval_lc(&constraint.b, &wires, &modulus);
                let c = eval_lc(&constraint.c, &wires, &modulus);
                let lhs = (a * b) % &modulus;
                assert_eq!(lhs, c, "Generated inputs should satisfy constraints");
            }
        }
    }

    #[test]
    fn test_invalid_magic() {
        let mut data = create_test_r1cs();
        data[0] = b'x'; // Corrupt magic

        let mut cursor = Cursor::new(data);
        let result = R1CS::parse(&mut cursor);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("bad magic"));
    }
}
