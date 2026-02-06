# AI-Assisted YAML Generation Workflow

This guide explains how to use Claude Opus (or other LLMs) to automatically generate optimized fuzzing campaigns for ZK circuits.

## Overview

**Before (Manual):**
```
1. Read circuit code (30 min)
2. Understand ZK patterns (1 hour)
3. Write YAML by hand (1 hour)
4. Debug YAML errors (30 min)
Total: 3+ hours
```

**After (AI-Assisted):**
```
1. Upload circuit to Claude
2. Copy generated YAML
3. Run fuzzer
Total: 5 minutes
```

---

## Step-by-Step Guide

### Step 1: Prepare Your Circuit

Ensure your circuit file is complete and compilable:

```circom
// my_circuit.circom
pragma circom 2.0.0;

include "circomlib/poseidon.circom";

template MyMerkleProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output root;
    
    // ... implementation
}

component main = MyMerkleProof(20);
```

### Step 2: Open Claude Opus

Navigate to [claude.ai](https://claude.ai) and start a new conversation.

### Step 3: Submit the Analysis Prompt

Copy the prompt template from [CLAUDE_PROMPT.md](./CLAUDE_PROMPT.md) and paste your circuit code where indicated:

```
# ZK Circuit Fuzzing Campaign Generator

You are a ZK security expert...

## Circuit Code

```circom
// Paste your entire circuit here
template MyMerkleProof(levels) {
    ...
}
```

## Analysis Tasks
...
```

### Step 4: Review the Generated YAML

Claude will produce a complete YAML configuration. Review it for:

- ✅ Correct circuit path and component name
- ✅ Appropriate attacks for the circuit type
- ✅ All inputs correctly identified
- ✅ Reasonable timeout and iteration counts
- ✅ Relevant invariants

### Step 4b: Chain YAMLs for Edge Cases (v2 Includes)

ZkPatternFuzz supports YAML v2 `includes`, so you can chain multiple templates and
AI-generated overlays for complex edge cases:

```yaml
includes:
  - "templates/traits/base.yaml"
  - "templates/traits/merkle.yaml"
  - "templates/traits/hash.yaml"
  - "campaigns/edge_cases/overflow.yaml"
  - "campaigns/edge_cases/pathology.yaml"
```

This lets Opus generate a circuit-specific campaign, while you layer on extra
templates for uncommon failure modes.

### Step 5: Save and Validate

Save the YAML to your campaigns directory:

```bash
# Save the output
cat > campaigns/my_circuit.yaml << 'EOF'
# [Paste Claude's output here]
EOF

# Validate the configuration
cargo run -- validate campaigns/my_circuit.yaml
```

### Step 6: Run the Fuzzer

```bash
cargo run --release -- --config campaigns/my_circuit.yaml --workers 4 --seed 42
```

---

## Template Selection

Based on the circuit type, Claude will include appropriate trait templates:

| Circuit Type | Templates Used |
|--------------|----------------|
| Merkle Tree | `merkle.yaml`, `hash.yaml` |
| Nullifier | `nullifier.yaml`, `hash.yaml` |
| Range Proof | `range.yaml` |
| Signature | `signature.yaml`, `hash.yaml` |
| Generic | `base.yaml` |

---

## Pre-built Templates

For common circuit patterns, you can also use pre-built templates directly:

```bash
# Merkle tree circuits
cp templates/ai_assisted/merkle_tree.yaml campaigns/my_merkle.yaml
# Edit to fill in {{VARIABLES}}

# Nullifier circuits
cp templates/ai_assisted/nullifier.yaml campaigns/my_nullifier.yaml

# Range proof circuits
cp templates/ai_assisted/range_proof.yaml campaigns/my_range.yaml

# Signature circuits
cp templates/ai_assisted/signature.yaml campaigns/my_signature.yaml
```

## Notes on v2 Features

- `includes` lets you chain N YAML files in order (later files extend/override).
- `profiles` provide reusable parameter sets (e.g., Merkle depth).
- `invariants` and `schedule` are supported and loaded by the config resolver.

---

## Programmatic Generation

You can also generate campaigns programmatically using the config generator:

```rust
use zk_fuzzer::config::generator::ConfigGenerator;

fn main() -> anyhow::Result<()> {
    let generator = ConfigGenerator::new();
    
    // Generate from circuit file
    let config = generator.generate_from_file("circuit.circom")?;
    
    // Serialize to YAML
    let yaml = serde_yaml::to_string(&config)?;
    std::fs::write("campaign.yaml", yaml)?;
    
    Ok(())
}
```

---

## Best Practices

### 1. Provide Complete Circuits

Include all dependencies and imports. Claude needs the full context to understand the circuit.

### 2. Specify the Framework

If using Noir, Halo2, or Cairo, mention it explicitly:

```
This is a Noir circuit (not Circom):

```rust
fn main(x: Field, y: pub Field) {
    ...
}
```

### 3. Include Comments

Circuit comments help Claude understand the intended behavior:

```circom
// This template verifies a Merkle inclusion proof
// The leaf should be a hash of (nullifier, secret)
template MerkleProof(levels) {
```

### 4. Review Invariants

Claude may infer invariants that aren't actually required. Remove false positives:

```yaml
# Keep this - it's a real requirement
- name: "path_binary"
  relation: "∀i: pathIndices[i] ∈ {0,1}"
  severity: "critical"

# Remove this if not applicable to your circuit
# - name: "optional_constraint"
#   relation: "..."
```

### 5. Adjust Attack Budgets

For large circuits, increase iterations and timeouts:

```yaml
campaign:
  parameters:
    timeout_seconds: 3600  # 1 hour for complex circuits
    max_iterations: 100000

attacks:
  - type: "collision"
    config:
      samples: 500000  # More samples for larger state space
```

---

## Troubleshooting

### "Circuit file not found"

Update `circuit_path` to the correct relative or absolute path:

```yaml
target:
  circuit_path: "./circuits/merkle.circom"  # Relative to working directory
```

### "Unknown input: xyz"

Claude may have guessed input names. Update to match your circuit:

```yaml
inputs:
  - name: "leaf"       # Match your actual signal name
    type: "field"
```

### "Attack type not supported"

Remove or replace unsupported attack types:

```yaml
attacks:
  # Remove unsupported
  # - type: "custom_attack"
  
  # Use supported equivalent
  - type: "underconstrained"
```

---

## Integration with CI/CD

Automate campaign generation in your CI pipeline:

```yaml
# .github/workflows/security.yml
name: ZK Security Audit

on:
  push:
    paths:
      - 'circuits/**'

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Generate Campaign
        run: |
          # Use config generator
          cargo run --bin yaml-generator -- \
            --circuit circuits/main.circom \
            --output campaigns/generated.yaml
      
      - name: Run Fuzzer
        run: |
          cargo run --release -- \
            --config campaigns/generated.yaml \
            --seed 42 \
            --workers 4
      
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: reports/
```

---

## FAQ

**Q: Can I use GPT-4 instead of Claude?**

A: Yes, the prompt works with any capable LLM. Claude Opus is recommended for complex circuits due to its larger context window.

**Q: How do I handle multi-file circuits?**

A: Concatenate all relevant files in the prompt, or focus on the main template with key dependencies.

**Q: Should I include circomlib in the prompt?**

A: No, just reference the includes. Claude knows standard library templates.

**Q: How accurate are the generated configurations?**

A: Typically 80-90% accurate. Always review and adjust attack priorities based on your specific security concerns.
