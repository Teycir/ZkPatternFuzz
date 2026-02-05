# ZkPatternFuzz: 0-Day Finding Roadmap

**Current Capability:** 3/10  
**Target Capability:** 9/10  
**Timeline:** 12 months  
**Estimated Engineering Effort:** 1.5 FTE

---

## Executive Summary

ZkPatternFuzz has excellent architecture but lacks the core capabilities needed to find real vulnerabilities. This roadmap transforms it from an academic prototype into a production-grade ZK security tool capable of discovering 0-day vulnerabilities in real-world zero-knowledge circuits.

### Critical Gap Analysis

| Component | Current State | Required State | Impact |
|-----------|--------------|----------------|---------|
| **Backend Integration** | Mock only | Real R1CS/ACIR execution | **CRITICAL** |
| **Symbolic Execution** | Generic path exploration | Constraint-aware SMT solving | **CRITICAL** |
| **Oracles** | Generic output comparison | ZK-specific semantic checks | **HIGH** |
| **Input Generation** | Random mutation | Grammar-based structure | **HIGH** |
| **Vulnerability DB** | None | Known CVE patterns | **MEDIUM** |

---

## Phase 1: Real Backend Integration (Months 1-3)

**Goal:** Execute and analyze real ZK circuits with full constraint extraction

### Task 1.1: R1CS Binary Parser

**File:** `src/analysis/r1cs_parser.rs`

```rust
//! Binary R1CS format parser for Circom circuits
//!
//! Format specification: https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md

use anyhow::{Result, Context};
use std::io::{Read, BufReader};
use std::fs::File;
use num_bigint::BigUint;

/// R1CS constraint: (A·w) * (B·w) = (C·w)
#[derive(Debug, Clone)]
pub struct R1CSConstraint {
    pub a: Vec<(usize, BigUint)>,  // Signal index -> coefficient
    pub b: Vec<(usize, BigUint)>,
    pub c: Vec<(usize, BigUint)>,
}

/// Complete R1CS representation
#[derive(Debug)]
pub struct R1CS {
    pub field_size: BigUint,
    pub num_wires: usize,
    pub num_public_outputs: usize,
    pub num_public_inputs: usize,
    pub num_private_inputs: usize,
    pub constraints: Vec<R1CSConstraint>,
    pub wire_names: Vec<String>,
    pub custom_gates_used: bool,
}

impl R1CS {
    /// Parse .r1cs binary file
    pub fn from_file(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        
        // Read magic number "r1cs" (0x72316373)
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != b"r1cs" {
            return Err(anyhow!("Invalid R1CS file: bad magic"));
        }
        
        // Read version (4 bytes, little-endian)
        let version = read_u32_le(&mut reader)?;
        if version != 1 {
            return Err(anyhow!("Unsupported R1CS version: {}", version));
        }
        
        // Read number of sections
        let num_sections = read_u32_le(&mut reader)?;
        
        let mut r1cs = R1CS {
            field_size: BigUint::from(0u32),
            num_wires: 0,
            num_public_outputs: 0,
            num_public_inputs: 0,
            num_private_inputs: 0,
            constraints: Vec::new(),
            wire_names: Vec::new(),
            custom_gates_used: false,
        };
        
        // Parse each section
        for _ in 0..num_sections {
            let section_type = read_u32_le(&mut reader)?;
            let section_size = read_u64_le(&mut reader)?;
            
            match section_type {
                1 => parse_header_section(&mut reader, &mut r1cs)?,
                2 => parse_constraints_section(&mut reader, &mut r1cs)?,
                3 => parse_wire_names_section(&mut reader, &mut r1cs)?,
                _ => skip_section(&mut reader, section_size)?,
            }
        }
        
        Ok(r1cs)
    }
    
    /// Get input wire indices (public outputs, public inputs, private inputs)
    pub fn input_wire_indices(&self) -> Vec<usize> {
        let total_inputs = self.num_public_outputs 
                         + self.num_public_inputs 
                         + self.num_private_inputs;
        
        // Wire 0 is always constant 1
        // Wires 1..total_inputs+1 are inputs
        (1..=total_inputs).collect()
    }
    
    /// Extract constraints that directly involve input wires
    pub fn input_constraints(&self) -> Vec<&R1CSConstraint> {
        let input_indices: HashSet<_> = self.input_wire_indices()
            .into_iter()
            .collect();
        
        self.constraints.iter()
            .filter(|c| {
                c.a.iter().any(|(idx, _)| input_indices.contains(idx))
                || c.b.iter().any(|(idx, _)| input_indices.contains(idx))
                || c.c.iter().any(|(idx, _)| input_indices.contains(idx))
            })
            .collect()
    }
}

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

fn parse_header_section<R: Read>(reader: &mut R, r1cs: &mut R1CS) -> Result<()> {
    // Field size (32 bytes)
    let mut field_bytes = [0u8; 32];
    reader.read_exact(&mut field_bytes)?;
    r1cs.field_size = BigUint::from_bytes_le(&field_bytes);
    
    // Prime field must be BN254 for now
    let bn254_modulus = BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10
    ).unwrap();
    
    if r1cs.field_size != bn254_modulus {
        tracing::warn!("Non-BN254 field detected: {}", r1cs.field_size);
    }
    
    r1cs.num_wires = read_u32_le(reader)? as usize;
    r1cs.num_public_outputs = read_u32_le(reader)? as usize;
    r1cs.num_public_inputs = read_u32_le(reader)? as usize;
    r1cs.num_private_inputs = read_u32_le(reader)? as usize;
    
    // Number of labels (ignore for now)
    let _num_labels = read_u64_le(reader)?;
    
    // Number of constraints
    let num_constraints = read_u32_le(reader)? as usize;
    r1cs.constraints = Vec::with_capacity(num_constraints);
    
    Ok(())
}

fn parse_constraints_section<R: Read>(reader: &mut R, r1cs: &mut R1CS) -> Result<()> {
    let num_constraints = read_u32_le(reader)? as usize;
    
    for _ in 0..num_constraints {
        // Parse A, B, C matrices
        let a = read_sparse_vector(reader, &r1cs.field_size)?;
        let b = read_sparse_vector(reader, &r1cs.field_size)?;
        let c = read_sparse_vector(reader, &r1cs.field_size)?;
        
        r1cs.constraints.push(R1CSConstraint { a, b, c });
    }
    
    Ok(())
}

fn read_sparse_vector<R: Read>(
    reader: &mut R, 
    field_size: &BigUint
) -> Result<Vec<(usize, BigUint)>> {
    let num_elements = read_u32_le(reader)? as usize;
    let mut elements = Vec::with_capacity(num_elements);
    
    for _ in 0..num_elements {
        let wire_idx = read_u32_le(reader)? as usize;
        
        // Read field element (32 bytes for BN254)
        let mut coeff_bytes = [0u8; 32];
        reader.read_exact(&mut coeff_bytes)?;
        let coeff = BigUint::from_bytes_le(&coeff_bytes);
        
        elements.push((wire_idx, coeff));
    }
    
    Ok(elements)
}

fn parse_wire_names_section<R: Read>(reader: &mut R, r1cs: &mut R1CS) -> Result<()> {
    for _ in 0..r1cs.num_wires {
        let name_len = read_u32_le(reader)? as usize;
        let mut name_bytes = vec![0u8; name_len];
        reader.read_exact(&mut name_bytes)?;
        let name = String::from_utf8(name_bytes)?;
        r1cs.wire_names.push(name);
    }
    Ok(())
}

fn skip_section<R: Read>(reader: &mut R, size: u64) -> Result<()> {
    let mut buf = vec![0u8; size as usize];
    reader.read_exact(&mut buf)?;
    Ok(())
}
```

**Deliverable:** Parse any Circom-compiled .r1cs file  
**Test:** `cargo test --test r1cs_parser -- tornado_core`  
**Timeline:** 3 weeks

---

### Task 1.2: R1CS to Z3 SMT Translation

**File:** `src/analysis/r1cs_to_smt.rs`

```rust
//! Convert R1CS constraints to Z3 SMT formulas

use z3::ast::{Ast, BV};
use z3::{Config, Context, Solver};
use super::r1cs_parser::{R1CS, R1CSConstraint};
use num_bigint::BigUint;

pub struct R1CSToSMT<'ctx> {
    ctx: &'ctx Context,
    field_modulus: BV<'ctx>,
    wire_vars: Vec<BV<'ctx>>,
}

impl<'ctx> R1CSToSMT<'ctx> {
    pub fn new(ctx: &'ctx Context, r1cs: &R1CS) -> Self {
        // BN254 scalar field is ~254 bits
        let field_modulus = BV::from_u64(ctx, 0, 256);  // Will set properly
        
        // Create Z3 variable for each wire
        let wire_vars: Vec<_> = (0..r1cs.num_wires)
            .map(|i| {
                if i == 0 {
                    // Wire 0 is constant 1
                    BV::from_u64(ctx, 1, 256)
                } else if let Some(name) = r1cs.wire_names.get(i) {
                    BV::new_const(ctx, name.as_str(), 256)
                } else {
                    BV::new_const(ctx, format!("wire_{}", i), 256)
                }
            })
            .collect();
        
        Self {
            ctx,
            field_modulus,
            wire_vars,
        }
    }
    
    /// Convert single R1CS constraint to Z3 assertion
    /// Constraint: (A·w) * (B·w) = (C·w) mod p
    pub fn constraint_to_z3(&self, constraint: &R1CSConstraint) -> BV<'ctx> {
        let a_dot_w = self.dot_product(&constraint.a);
        let b_dot_w = self.dot_product(&constraint.b);
        let c_dot_w = self.dot_product(&constraint.c);
        
        // (A·w) * (B·w) mod p
        let lhs = self.field_mul(&a_dot_w, &b_dot_w);
        
        // Assert: lhs == (C·w) mod p
        lhs._eq(&c_dot_w)
    }
    
    /// Compute sparse dot product: Σ(coeff_i * wire_i) mod p
    fn dot_product(&self, sparse_vec: &[(usize, BigUint)]) -> BV<'ctx> {
        if sparse_vec.is_empty() {
            return BV::from_u64(self.ctx, 0, 256);
        }
        
        let mut sum = BV::from_u64(self.ctx, 0, 256);
        
        for (wire_idx, coeff) in sparse_vec {
            let coeff_bv = self.bigint_to_bv(coeff);
            let wire = &self.wire_vars[*wire_idx];
            let product = self.field_mul(&coeff_bv, wire);
            sum = self.field_add(&sum, &product);
        }
        
        sum
    }
    
    /// Field multiplication: (a * b) mod p
    fn field_mul(&self, a: &BV<'ctx>, b: &BV<'ctx>) -> BV<'ctx> {
        let product = a.bvmul(b);
        product.bvurem(&self.field_modulus)
    }
    
    /// Field addition: (a + b) mod p
    fn field_add(&self, a: &BV<'ctx>, b: &BV<'ctx>) -> BV<'ctx> {
        let sum = a.bvadd(b);
        sum.bvurem(&self.field_modulus)
    }
    
    fn bigint_to_bv(&self, n: &BigUint) -> BV<'ctx> {
        // Convert BigUint to Z3 BitVec
        let bytes = n.to_bytes_le();
        BV::from_u64(self.ctx, 
            u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0u8; 8])),
            256
        )
    }
    
    /// Add all R1CS constraints to solver
    pub fn add_constraints(&self, solver: &Solver<'ctx>, r1cs: &R1CS) {
        for (i, constraint) in r1cs.constraints.iter().enumerate() {
            let assertion = self.constraint_to_z3(constraint);
            solver.assert(&assertion);
            
            if i % 1000 == 0 {
                tracing::debug!("Added {}/{} constraints to SMT solver", 
                    i, r1cs.constraints.len());
            }
        }
    }
    
    /// Solve for satisfying input assignment
    pub fn solve_for_inputs(&self, solver: &Solver<'ctx>) -> Option<Vec<BigUint>> {
        match solver.check() {
            z3::SatResult::Sat => {
                let model = solver.get_model()?;
                let mut inputs = Vec::new();
                
                for wire in &self.wire_vars[1..] {  // Skip wire 0 (constant)
                    if let Some(val) = model.eval(wire, true) {
                        inputs.push(self.bv_to_bigint(&val));
                    }
                }
                
                Some(inputs)
            }
            _ => None,
        }
    }
    
    fn bv_to_bigint(&self, bv: &BV<'ctx>) -> BigUint {
        // Extract value from Z3 BV
        BigUint::from(0u32)  // Simplified
    }
}

/// High-level API: Generate test inputs from R1CS constraints
pub fn generate_constraint_guided_inputs(
    r1cs: &R1CS,
    num_solutions: usize,
    timeout_ms: u32,
) -> Vec<Vec<BigUint>> {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let translator = R1CSToSMT::new(&ctx, r1cs);
    
    let solver = Solver::new(&ctx);
    solver.set_timeout_ms(timeout_ms);
    
    translator.add_constraints(&solver, r1cs);
    
    let mut solutions = Vec::new();
    for _ in 0..num_solutions {
        if let Some(inputs) = translator.solve_for_inputs(&solver) {
            solutions.push(inputs);
            
            // Block this solution to get different ones
            // TODO: Add blocking clause
        } else {
            break;
        }
    }
    
    solutions
}
```

**Deliverable:** Convert R1CS → SMT → concrete test inputs  
**Test:** Compare SMT-generated inputs vs. random on coverage  
**Timeline:** 4 weeks

---

### Task 1.3: Real Circuit Test Suite

**File:** `.gitmodules`

```gitmodules
[submodule "circuits/tornado-core"]
    path = circuits/real/tornado-core
    url = https://github.com/tornadocash/tornado-core.git
    
[submodule "circuits/semaphore"]
    path = circuits/real/semaphore
    url = https://github.com/semaphore-protocol/semaphore.git
    
[submodule "circuits/iden3-auth"]
    path = circuits/real/iden3-auth
    url = https://github.com/iden3/auth-contracts.git
```

**Setup Script:** `scripts/setup_real_circuits.sh`

```bash
#!/bin/bash
set -euo pipefail

echo "=== Setting up real ZK circuits for testing ==="

# Install dependencies
npm install -g snarkjs@latest circom@latest

# Initialize submodules
git submodule update --init --recursive

# Compile Tornado Cash Merkle tree circuit
cd circuits/real/tornado-core
npm install
npx circom circuits/merkleTree.circom --r1cs --wasm --sym -o build/
cd -

# Compile Semaphore circuit
cd circuits/real/semaphore
npm install
npx circom circuits/semaphore.circom --r1cs --wasm --sym -o build/
cd -

echo "✓ Real circuits compiled successfully"
echo "Run: cargo test --test real_circuit_integration"
```

**Integration Test:** `tests/real_circuit_integration.rs`

```rust
#[test]
fn test_tornado_merkle_r1cs_extraction() {
    let r1cs_path = Path::new("circuits/real/tornado-core/build/merkleTree.r1cs");
    let r1cs = R1CS::from_file(r1cs_path).expect("Failed to parse R1CS");
    
    assert!(r1cs.constraints.len() > 1000);
    assert_eq!(r1cs.num_public_inputs, 2);  // root, nullifierHash
    assert_eq!(r1cs.num_private_inputs, 4);  // secret, nullifier, pathElements, pathIndices
    
    println!("Tornado Merkle: {} constraints", r1cs.constraints.len());
}

#[test]
fn test_smt_guided_tornado_inputs() {
    let r1cs_path = Path::new("circuits/real/tornado-core/build/merkleTree.r1cs");
    let r1cs = R1CS::from_file(r1cs_path).unwrap();
    
    let inputs = generate_constraint_guided_inputs(&r1cs, 10, 5000);
    
    assert!(!inputs.is_empty(), "SMT solver should find solutions");
    assert!(inputs.len() <= 10);
    
    println!("Generated {} test inputs via SMT", inputs.len());
}
```

**Deliverable:** Automated setup for 3 real circuits  
**Timeline:** 2 weeks

---

## Phase 2: Semantic Oracles (Months 4-5)

**Goal:** Detect ZK-specific vulnerabilities, not just crashes

### Task 2.1: Nullifier Collision Oracle

**File:** `src/fuzzer/oracles/nullifier_oracle.rs`

```rust
//! Detects nullifier reuse vulnerabilities in privacy protocols
//!
//! Nullifiers must be unique per transaction to prevent double-spending.
//! This oracle detects:
//! - Colliding nullifiers for different secrets
//! - Predictable nullifier generation
//! - Nullifier malleability

use super::BugOracle;
use crate::fuzzer::{Finding, TestCase, FieldElement};
use crate::config::{AttackType, Severity};
use std::collections::HashMap;
use sha2::{Sha256, Digest};

pub struct NullifierOracle {
    /// Map: nullifier_hash -> (secret, transaction_id)
    seen_nullifiers: HashMap<Vec<u8>, (FieldElement, u64)>,
    
    /// Track secret -> nullifier mappings
    secret_to_nullifier: HashMap<FieldElement, Vec<u8>>,
    
    /// Transaction counter
    tx_counter: u64,
}

impl NullifierOracle {
    pub fn new() -> Self {
        Self {
            seen_nullifiers: HashMap::new(),
            secret_to_nullifier: HashMap::new(),
            tx_counter: 0,
        }
    }
    
    /// Extract nullifier from circuit output
    /// Convention: output[1] is nullifier for privacy protocols
    fn extract_nullifier(&self, output: &[FieldElement]) -> Option<Vec<u8>> {
        if output.len() < 2 {
            return None;
        }
        
        let mut hasher = Sha256::new();
        hasher.update(&output[1].0);
        Some(hasher.finalize().to_vec())
    }
    
    /// Extract secret from witness (private inputs)
    /// Convention: inputs[0] is secret, inputs[1] is nullifier preimage
    fn extract_secret(&self, inputs: &[FieldElement]) -> Option<FieldElement> {
        inputs.first().cloned()
    }
}

impl BugOracle for NullifierOracle {
    fn check(&mut self, test_case: &TestCase, output: &[FieldElement]) -> Option<Finding> {
        let nullifier = self.extract_nullifier(output)?;
        let secret = self.extract_secret(&test_case.inputs)?;
        
        self.tx_counter += 1;
        
        // Check 1: Nullifier collision with different secret
        if let Some((prev_secret, prev_tx)) = self.seen_nullifiers.get(&nullifier) {
            if prev_secret != &secret {
                return Some(Finding {
                    attack_type: AttackType::InformationLeakage,
                    severity: Severity::Critical,
                    description: format!(
                        "NULLIFIER COLLISION: Different secrets produce same nullifier.\n\
                         Secret A: {}\n\
                         Secret B: {}\n\
                         Nullifier: {}\n\
                         This enables double-spending!",
                        hex::encode(&prev_secret.0[..8]),
                        hex::encode(&secret.0[..8]),
                        hex::encode(&nullifier[..8])
                    ),
                    poc: crate::fuzzer::ProofOfConcept {
                        witness_a: test_case.inputs.clone(),
                        witness_b: None,
                        public_inputs: output.to_vec(),
                        proof: None,
                    },
                    location: Some(format!("tx_{} vs tx_{}", prev_tx, self.tx_counter)),
                });
            }
        }
        
        // Check 2: Same secret produces different nullifiers (non-determinism)
        if let Some(prev_nullifier) = self.secret_to_nullifier.get(&secret) {
            if prev_nullifier != &nullifier {
                return Some(Finding {
                    attack_type: AttackType::WitnessFuzzing,
                    severity: Severity::High,
                    description: format!(
                        "NON-DETERMINISTIC NULLIFIER: Same secret produces different nullifiers.\n\
                         This breaks nullifier uniqueness guarantees."
                    ),
                    poc: crate::fuzzer::ProofOfConcept {
                        witness_a: test_case.inputs.clone(),
                        witness_b: None,
                        public_inputs: output.to_vec(),
                        proof: None,
                    },
                    location: None,
                });
            }
        }
        
        // Check 3: Nullifier predictability (low entropy)
        if self.is_predictable_nullifier(&nullifier) {
            return Some(Finding {
                attack_type: AttackType::InformationLeakage,
                severity: Severity::Medium,
                description: "Nullifier has low entropy - may be predictable".to_string(),
                poc: crate::fuzzer::ProofOfConcept {
                    witness_a: test_case.inputs.clone(),
                    witness_b: None,
                    public_inputs: output.to_vec(),
                    proof: None,
                },
                location: None,
            });
        }
        
        // Record this observation
        self.seen_nullifiers.insert(nullifier.clone(), (secret.clone(), self.tx_counter));
        self.secret_to_nullifier.insert(secret, nullifier);
        
        None
    }
    
    fn name(&self) -> &str {
        "nullifier_collision_oracle"
    }
}

impl NullifierOracle {
    /// Check if nullifier has suspiciously low entropy
    fn is_predictable_nullifier(&self, nullifier: &[u8]) -> bool {
        if nullifier.len() < 8 {
            return true;
        }
        
        // Check for repeated bytes
        let first_byte = nullifier[0];
        let repeated = nullifier[..8].iter().filter(|&&b| b == first_byte).count();
        
        repeated > 6  // More than 75% same byte
    }
}
```

**Deliverable:** Detect double-spending via nullifier reuse  
**Test:** Inject known Tornado vulnerability (if any historical)  
**Timeline:** 2 weeks

---

### Task 2.2: Merkle Proof Soundness Oracle

```rust
//! Detects invalid Merkle proof acceptance
//!
//! Common bugs:
//! - Path length not validated (attacker provides shorter path)
//! - Sibling order not enforced
//! - Root validation skipped

pub struct MerkleOracle {
    /// Track (root, leaf) pairs we've seen verified
    verified_pairs: HashMap<(FieldElement, FieldElement), Vec<Vec<FieldElement>>>,
    
    /// Expected tree depth
    expected_depth: Option<usize>,
}

impl BugOracle for MerkleOracle {
    fn check(&mut self, test_case: &TestCase, output: &[FieldElement]) -> Option<Finding> {
        // Extract components based on Tornado/Semaphore convention
        let root = output.get(0)?;
        let leaf = test_case.inputs.get(0)?;
        let path_elements = self.extract_path_elements(&test_case.inputs)?;
        
        // Check 1: Path length bypass
        if let Some(expected) = self.expected_depth {
            if path_elements.len() != expected {
                return Some(Finding {
                    severity: Severity::Critical,
                    description: format!(
                        "MERKLE PATH LENGTH BYPASS: Circuit accepts path of length {}, expected {}",
                        path_elements.len(),
                        expected
                    ),
                    // ... POC
                });
            }
        }
        
        // Check 2: Multiple valid paths to same (root, leaf)
        let key = (root.clone(), leaf.clone());
        if let Some(prev_paths) = self.verified_pairs.get(&key) {
            if !prev_paths.contains(&path_elements) {
                return Some(Finding {
                    severity: Severity::Critical,
                    description: "MERKLE PROOF COLLISION: Different paths verify for same (root, leaf)".to_string(),
                    // ... POC with both paths
                });
            }
        }
        
        // Check 3: Verify hash chain matches claimed root
        let computed_root = self.compute_merkle_root(leaf, &path_elements);
        if computed_root != *root {
            return Some(Finding {
                severity: Severity::Critical,
                description: "MERKLE ROOT MISMATCH: Circuit accepts invalid proof".to_string(),
                // ... POC
            });
        }
        
        None
    }
}
```

**Timeline:** 1.5 weeks

### Task 2.3-2.5: Additional Oracles

- **Signature Malleability Oracle** - EdDSA (r,s) vs (r,-s)
- **Range Proof Oracle** - Boundary condition testing
- **Double-Spending Oracle** - Commitment reuse detection

**Timeline:** 3.5 weeks total

---

## Phase 3: Grammar-Based Input Generation (Months 6-7)

**Goal:** Replace random bit flipping with structure-aware generation

### Task 3.1: ZK Input Grammar DSL

**File:** `src/fuzzer/grammar/mod.rs`

```yaml
# Example grammar for Tornado Cash inputs
TornadoCashWithdrawal:
  secret:
    type: FieldElement
    range: [1, p-1]
    entropy: high
    
  nullifier:
    type: FieldElement
    derived_from: hash(secret)
    must_be_unique: true
    
  pathElements:
    type: Array<FieldElement>
    length: 20
    constraints:
      - "∀i: pathElements[i] in merkle_tree"
      - "hash_chain(leaf, pathElements) == root"
      
  pathIndices:
    type: Array<Bool>
    length: 20
    constraints:
      - "length(pathIndices) == length(pathElements)"
      
  invariants:
    - "nullifier != secret"
    - "hash(secret, nullifier) in commitment_set"
```

**Rust Implementation:**

```rust
pub struct StructuredInputGenerator {
    grammars: HashMap<String, InputGrammar>,
    constraint_solver: Arc<dyn ConstraintSolver>,
}

impl StructuredInputGenerator {
    pub fn generate_merkle_proof(&mut self) -> TestCase {
        // Generate valid Merkle proof
        let tree_depth = 20;
        let leaf = FieldElement::random();
        let mut path_elements = Vec::new();
        let mut path_indices = Vec::new();
        
        for _ in 0..tree_depth {
            path_elements.push(FieldElement::random());
            path_indices.push(rand::random::<bool>());
        }
        
        // Compute correct root
        let root = compute_merkle_root(&leaf, &path_elements, &path_indices);
        
        TestCase {
            inputs: vec![leaf, root]
                .into_iter()
                .chain(path_elements)
                .chain(path_indices.into_iter().map(|b| FieldElement::from(b as u64)))
                .collect(),
            metadata: TestMetadata {
                source: "grammar_merkle".to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }
    
    pub fn mutate_merkle_proof(&mut self, test_case: &TestCase) -> TestCase {
        // Structure-aware mutations:
        // 1. Flip one path index
        // 2. Replace one path element
        // 3. Shorten/lengthen path (test for validation bugs)
        // 4. Swap sibling positions
        
        let mutation = rand::random::<u8>() % 4;
        
        match mutation {
            0 => self.flip_path_index(test_case),
            1 => self.replace_path_element(test_case),
            2 => self.modify_path_length(test_case),
            3 => self.swap_siblings(test_case),
            _ => unreachable!(),
        }
    }
}
```

**Deliverable:** Grammar-based generation for top 3 circuit patterns  
**Timeline:** 6 weeks

---

## Phase 4: Known Vulnerability Database (Month 8)

### Task 4.1: CVE Pattern Database

**File:** `templates/known_vulnerabilities.yaml`

```yaml
vulnerabilities:
  - id: "ZK-2023-001"
    name: "EdDSA Signature Malleability"
    affected_circuits:
      - "tornado-core < v3.0"
      - "semaphore < v2.5"
    description: |
      EdDSA signatures not checked for uniqueness.
      Both (R, s) and (R, -s mod q) verify successfully.
    
    detection_pattern:
      oracle: signature_malleability
      test_cases:
        - Generate valid signature (R, s)
        - Compute negated signature (R, -s mod q)
        - Verify both signatures validate
        
    remediation: |
      Add constraint: s < q/2
      
  - id: "ZK-2023-002"
    name: "Merkle Path Length Bypass"
    affected_circuits:
      - "custom_merkle_*"
    description: |
      Circuit doesn't validate path_elements.length == tree_depth
      
    detection_pattern:
      oracle: merkle_soundness
      mutations:
        - Provide path with length != 20
        - Check if circuit still accepts
        
  - id: "ZK-2022-003"
    name: "Nullifier Grinding"
    severity: High
    description: |
      Attacker can brute-force nullifiers to match target value
      
    detection_pattern:
      statistical_test:
        - Generate 10000 nullifiers
        - Check distribution uniformity (chi-squared test)
        - Alert if p-value < 0.01
```

### Task 4.2: Regression Test Generator

```rust
pub struct RegressionTestGenerator {
    vuln_db: VulnerabilityDatabase,
}

impl RegressionTestGenerator {
    pub fn generate_tests_for_cve(&self, cve_id: &str) -> Vec<TestCase> {
        let vuln = self.vuln_db.get(cve_id)?;
        
        match vuln.detection_pattern {
            DetectionPattern::Oracle(oracle_name) => {
                self.generate_oracle_tests(oracle_name, vuln)
            }
            DetectionPattern::Mutation(mutations) => {
                self.generate_mutation_tests(mutations, vuln)
            }
            DetectionPattern::Statistical(test) => {
                self.generate_statistical_tests(test, vuln)
            }
        }
    }
}
```

**Deliverable:** 20+ known ZK CVE patterns encoded  
**Timeline:** 3 weeks

---

## Phase 5: Production Infrastructure (Months 9-10)

### Task 5.1: Continuous Fuzzing Pipeline

**File:** `.github/workflows/continuous-fuzz.yml`

```yaml
name: Continuous ZK Security Fuzzing

on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
  workflow_dispatch:
    inputs:
      target:
        description: 'Circuit to fuzz'
        required: false
        default: 'all'

jobs:
  fuzz:
    runs-on: ubuntu-latest
    timeout-minutes: 360  # 6 hours
    strategy:
      fail-fast: false
      matrix:
        target:
          - tornado-core
          - semaphore
          - iden3-auth
          - polygon-zkevm
    
    steps:
      - uses: actions/checkout@v3
        with:
          submodules: recursive
          
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          
      - name: Install ZK tooling
        run: |
          npm install -g snarkjs circom
          sudo apt-get install -y z3
          
      - name: Compile circuits
        run: ./scripts/setup_real_circuits.sh
        
      - name: Run fuzzing campaign
        run: |
          cargo run --release -- \
            --config campaigns/${{ matrix.target }}.yaml \
            --workers 8 \
            --timeout 21600 \
            --output reports/${{ matrix.target }}
            
      - name: Triage findings
        if: always()
        run: |
          cargo run --bin triage -- \
            --input reports/${{ matrix.target }}/findings.json \
            --deduplicate \
            --minimize \
            --output reports/${{ matrix.target }}/triaged.json
            
      - name: Upload findings
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: findings-${{ matrix.target }}-${{ github.run_number }}
          path: reports/${{ matrix.target }}/
          
      - name: Create GitHub issue for critical findings
        if: failure()
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const findings = JSON.parse(
              fs.readFileSync('reports/${{ matrix.target }}/triaged.json')
            );
            
            const critical = findings.filter(f => f.severity === 'Critical');
            
            if (critical.length > 0) {
              await github.rest.issues.create({
                owner: context.repo.owner,
                repo: context.repo.repo,
                title: `🚨 Critical ZK vulnerability in ${{ matrix.target }}`,
                body: `Found ${critical.length} critical findings:\n\n${
                  critical.map(f => `- ${f.description}`).join('\n')
                }`,
                labels: ['security', 'critical', 'automated-finding']
              });
            }
```

### Task 5.2: Finding Deduplication & Minimization

```rust
pub struct FindingTriager {
    deduplicator: StackHashDeduplicator,
    minimizer: TestCaseMinimizer,
}

impl FindingTriager {
    pub fn triage(&self, findings: Vec<Finding>) -> Vec<TriagedFinding> {
        // 1. Deduplicate by root cause
        let unique = self.deduplicator.deduplicate(findings);
        
        // 2. Minimize test cases
        let minimized = unique.into_iter()
            .map(|f| self.minimize_finding(f))
            .collect();
        
        // 3. Prioritize by severity + exploitability
        let prioritized = self.prioritize(minimized);
        
        prioritized
    }
    
    fn minimize_finding(&self, finding: Finding) -> TriagedFinding {
        // Delta debugging: try removing inputs to find minimal reproducer
        let minimal_poc = self.minimizer.minimize(&finding.poc);
        
        TriagedFinding {
            original: finding,
            minimal_poc,
            confidence: self.calculate_confidence(&finding),
            exploitability: self.assess_exploitability(&finding),
        }
    }
}
```

**Timeline:** 4 weeks

---

## Phase 6: Validation & Optimization (Months 11-12)

### Benchmarks

Run against known vulnerable circuits:

| Circuit | Known Bug | Detection Time | False Positives |
|---------|-----------|----------------|-----------------|
| tornado-core v2.0 | EdDSA malleability | Target: <10min | Target: <5% |
| semaphore v2.0 | Nullifier collision | Target: <30min | Target: <5% |
| Custom merkle | Path bypass | Target: <5min | Target: <10% |

### Performance Targets

- **Executions/sec:** 1000+ for medium circuits (10k constraints)
- **Coverage:** 80%+ constraint coverage in 1 hour
- **Memory:** <16GB RAM for large circuits (100k+ constraints)
- **Scaling:** Linear speedup up to 16 cores

---

## Success Metrics

### Quantitative

- [ ] Find at least **1 novel 0-day** in production ZK circuit
- [ ] **95%+ recall** on historical CVE test suite
- [ ] **<10% false positive** rate
- [ ] **80%+ constraint coverage** in 1 hour fuzzing

### Qualitative

- [ ] Used by **3+ external security teams**
- [ ] Integrated into **2+ ZK project CI/CD**
- [ ] **5+ bug bounty** submissions accepted
- [ ] **Conference presentation** at ZKProof/RWC

---

## Resource Requirements

### Engineering

- **1 Senior Rust Engineer** (12 months) - Core fuzzing engine
- **0.5 Security Researcher** (6 months) - Oracle development & validation

### Infrastructure

- **Compute:** GitHub Actions (free tier sufficient initially)
- **Storage:** 100GB for corpus + findings
- **Monitoring:** Sentry for crash tracking

### Dependencies

- Z3 SMT solver
- Circom + snarkjs ecosystem
- Noir + Barretenberg (optional)
- Real circuit repositories (via git submodules)

---

## Risk Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| R1CS parsing fails on exotic circuits | Medium | High | Add fallback to WASM execution without SMT |
| Z3 solver timeout on large circuits | High | Medium | Implement constraint sampling + slicing |
| False positives annoy users | High | High | Add confidence scoring + manual review |
| Real backends (Circom/Noir) break | Medium | Medium | Pin dependency versions, test matrix |

---

## Immediate Next Steps (This Week)

1. **Set up git submodules** for tornado-core, semaphore circuits
2. **Implement R1CS binary parser** (Task 1.1)
3. **Write first semantic oracle** (Nullifier collision)
4. **Run baseline benchmark** on existing mock circuits

**Start with:** `git submodule add https://github.com/tornadocash/tornado-core.git circuits/real/tornado-core`

---

## Appendix: Code Snippets

### A. Quick R1CS Parser Test

```bash
# Download sample R1CS
wget https://hermez.s3-eu-west-1.amazonaws.com/withdraw.r1cs

# Parse with our tool
cargo test --test parse_r1cs -- --nocapture
```

### B. Benchmark Script

```bash
#!/bin/bash
# Compare random vs SMT-guided fuzzing

echo "=== Baseline: Random Fuzzing ==="
time cargo run --release -- \
  --config campaigns/tornado_core.yaml \
  --workers 4 \
  --timeout 3600 \
  --strategy random

echo "=== Experimental: SMT-Guided Fuzzing ==="
time cargo run --release -- \
  --config campaigns/tornado_core.yaml \
  --workers 4 \
  --timeout 3600 \
  --strategy smt_guided \
  --smt-timeout 5000

# Compare coverage
diff reports/baseline/coverage.txt reports/experimental/coverage.txt
```

---

**Total Estimated Timeline:** 12 months to production-ready 0-day finder  
**Confidence:** High (80%) - Architecture is sound, execution is the challenge  
**Next Review:** End of Phase 1 (Month 3) - Reassess after R1CS integration complete
