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
        use crate::constraint_types::{
            ExtendedConstraint, R1CSConstraint as InternalR1CS, WireRef,
        };

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
        let mut reader = BufReader::with_capacity(1 << 20, file);
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
    let mut coeff_buf = vec![0u8; field_bytes];

    for _ in 0..num_terms {
        let wire_idx = read_u32_le(reader)? as usize;

        // Read field element coefficient
        reader.read_exact(&mut coeff_buf)?;
        let mut nonzero = false;
        for byte in &coeff_buf {
            if *byte != 0 {
                nonzero = true;
                break;
            }
        }
        if !nonzero {
            continue;
        }

        let coeff = BigUint::from_bytes_le(&coeff_buf);
        terms.push((wire_idx, coeff));
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
///
/// The .sym format is: `wireIdx,labelIdx,componentName.signalName`
/// We index names by wireIdx so that `wire_name(idx)` returns the
/// correct signal name for each wire.
pub fn parse_sym_file<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path.as_ref())
        .with_context(|| format!("Failed to read .sym file: {:?}", path.as_ref()))?;

    let mut max_idx: usize = 0;
    let mut entries: Vec<(usize, String)> = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Format: wireIdx,labelIdx,componentName.signalName
        let parts: Vec<&str> = line.splitn(3, ',').collect();
        if parts.len() >= 3 {
            if let Ok(wire_idx) = parts[0].parse::<usize>() {
                let name = parts[2].to_string();
                max_idx = max_idx.max(wire_idx);
                entries.push((wire_idx, name));
            }
        }
    }

    let mut names = vec![String::new(); max_idx + 1];
    for (idx, name) in entries {
        names[idx] = name;
    }

    Ok(names)
}

#[cfg(test)]
#[path = "r1cs_parser_tests.rs"]
mod tests;
