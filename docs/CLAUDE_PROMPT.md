# ZK Circuit Fuzzing Campaign Generator

This document contains the prompt template for Claude Opus to analyze ZK circuits and generate optimized YAML fuzzing campaigns.

## How to Use

1. **Copy the prompt below**
2. **Paste your circuit code** where indicated
3. **Submit to Claude Opus**
4. **Review and save** the generated YAML configuration
5. **Run ZkPatternFuzz** with the configuration

---

## Prompt Template

```
# ZK Circuit Fuzzing Campaign Generator

You are a ZK security expert specializing in zero-knowledge circuit vulnerabilities. Your task is to analyze the provided circuit and generate an optimized YAML fuzzing campaign for ZkPatternFuzz.

## Circuit Code

```{LANGUAGE}
{PASTE_YOUR_CIRCUIT_CODE_HERE}
```

## Analysis Tasks

Perform the following analysis steps:

### 1. Identify Circuit Type
Classify the circuit into one or more categories:
- Merkle tree / inclusion proof
- Nullifier / commitment scheme
- Range proof / bit decomposition
- Signature verification (EdDSA, ECDSA, Schnorr)
- Hash function
- Arithmetic circuit
- Privacy protocol (mixer, vote)
- Other: [specify]

### 2. Extract Inputs
List all public and private inputs with their types:
- Input name
- Type (field, array<field>, bool, array<bool>)
- Public or private
- Inferred constraints (nonzero, range, on_curve)

### 3. Detect Patterns
Identify common ZK patterns:
- Bit decomposition (Num2Bits, Bits2Num)
- Hash functions (Poseidon, MiMC, Pedersen, SHA256)
- Merkle path verification
- Range checks (LessThan, GreaterThan)
- EdDSA/ECDSA verification
- Nullifier computation
- Commitment schemes

### 4. Infer Invariants
What properties must hold?
- Mathematical relations (e.g., root == merkle(leaf, path))
- Range constraints (e.g., value < 2^64)
- Uniqueness (e.g., unique(nullifier))
- Binary constraints (e.g., bits[i] ∈ {0,1})

### 5. Suggest Attacks
Which vulnerability classes are most relevant?
- Underconstrained (missing constraints)
- Soundness (proof forgery)
- Collision (hash/nullifier)
- Arithmetic overflow
- Bit decomposition bypass
- Signature malleability
- Replay attacks

### 6. Generate Test Values
Identify interesting boundary values:
- Zero, one
- Maximum values (2^n - 1, 2^n, p-1)
- Edge cases specific to the circuit
- Known problematic values

## Output Format

Generate a complete YAML campaign following this structure:

```yaml
# AI-Generated Campaign for [CIRCUIT_NAME]
campaign:
  name: "[Descriptive name]"
  version: "2.0"
  target:
    framework: "[circom|noir|halo2|cairo]"
    circuit_path: "[path to circuit]"
    main_component: "[main component name]"
  
  parameters:
    field: "[bn254|bls12-381]"
    max_constraints: [estimated count]
    timeout_seconds: [appropriate timeout]

includes:
  - "templates/traits/base.yaml"
  - [additional trait templates based on patterns]

target_traits:
  [detected traits]

invariants:
  [inferred invariants with severity]

schedule:
  [phased attack schedule]

attacks:
  [configured attacks with descriptions]

inputs:
  [all detected inputs with fuzz strategies]

mutations:
  [relevant mutations based on circuit type]

reporting:
  output_dir: "./reports/[circuit_name]"
  formats: ["json", "markdown", "sarif"]
  include_poc: true
```

## Important Notes

1. **Be specific**: Use actual signal names from the circuit
2. **Prioritize critical paths**: Focus attacks on security-critical components
3. **Include edge cases**: Generate comprehensive boundary test values
4. **Set realistic timeouts**: Based on circuit complexity
5. **Document reasoning**: Add comments explaining choices

## Example Analysis

For a Merkle tree circuit, you might detect:
- Pattern: MerkleProof with Poseidon hash
- Inputs: leaf, pathElements[20], pathIndices[20], root
- Invariants: 
  - pathIndices must be binary
  - computed root must equal public root
- Attacks: underconstrained (path indices), collision (root)
- Boundary values: depth=0, depth=20, all-left path, all-right path

Now analyze the provided circuit and generate the optimal fuzzing configuration.
```

---

## Quick Reference: Attack Types

| Attack Type | Use When | Config Keys |
|-------------|----------|-------------|
| `underconstrained` | Always | `witness_pairs`, `compare_outputs`, `focus_on` |
| `soundness` | Privacy circuits | `forge_attempts`, `mutation_rate` |
| `collision` | Hash/Merkle circuits | `samples`, `target_output` |
| `arithmetic_overflow` | Arithmetic ops | `test_values` |
| `boundary` | Range checks | `test_values` |
| `constraint_inference` | Complex circuits | `categories`, `confidence_threshold` |
| `metamorphic` | Transform-based | `transforms` |
| `witness_collision` | Uniqueness checks | `samples`, `equivalence_check` |
| `spec_inference` | Unknown specs | `sample_count` |

## Quick Reference: Invariant Types

| Type | Oracle | Use Case |
|------|--------|----------|
| `constraint` | `must_hold` | Mathematical relations |
| `range` | `constraint_check` | Bound checking |
| `uniqueness` | `must_hold` | Collision resistance |
| `metamorphic` | `differential` | Transform invariance |

---

## Sample Outputs

### Merkle Tree Circuit

```yaml
campaign:
  name: "MerkleProof Security Audit"
  version: "2.0"
  target:
    framework: "circom"
    circuit_path: "./circuits/merkle.circom"
    main_component: "MerkleProof"

includes:
  - "templates/traits/merkle.yaml"

invariants:
  - name: "path_binary"
    relation: "∀i: pathIndices[i] ∈ {0,1}"
    oracle: must_hold
    severity: "critical"

attacks:
  - type: "underconstrained"
    config:
      witness_pairs: 2000
      focus_on: ["pathIndices"]
```

### Nullifier Circuit

```yaml
campaign:
  name: "Nullifier Security Audit"
  version: "2.0"
  target:
    framework: "circom"
    circuit_path: "./circuits/nullifier.circom"
    main_component: "Withdraw"

includes:
  - "templates/traits/nullifier.yaml"

invariants:
  - name: "nullifier_unique"
    relation: "unique(nullifierHash)"
    oracle: must_hold
    severity: "critical"

attacks:
  - type: "collision"
    config:
      samples: 100000
      target_output: "nullifierHash"
```

---

## Validation

After generating YAML, validate with:

```bash
cargo run -- validate ./campaigns/generated.yaml
```

Run the fuzzer:

```bash
cargo run --release -- --config ./campaigns/generated.yaml --workers 4
```
