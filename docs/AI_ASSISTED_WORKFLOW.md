# AI-Assisted Workflow Guide

This guide shows how to use AI (Claude Opus, GPT-4, etc.) to automatically generate ZkPatternFuzz campaign configurations from circuit code.

## Overview

```
Circuit Code → AI Analysis → YAML Config → ZkPatternFuzz → Vulnerability Report
```

## Simplest Method: Point AI to Your Repo

### Using Claude Desktop / ChatGPT with File Access

1. **Open Claude Desktop or ChatGPT**

2. **Give it your repo path:**

```
I have ZkPatternFuzz cloned at /path/to/ZkPatternFuzz

I want to fuzz this circuit: /path/to/my-circuit/circuit.circom

Please:
1. Read the ZkPatternFuzz documentation and examples
2. Analyze my circuit
3. Generate a campaign YAML config
4. Tell me the exact command to run
```

3. **AI will:**
   - Read `README.md`, `TUTORIAL.md`, example YAMLs from `tests/campaigns/`
   - Analyze your circuit code
   - Generate complete YAML config
   - Provide run command

4. **Copy-paste and run:**

```bash
cd /path/to/ZkPatternFuzz
cargo run --release -- --config /path/to/generated/campaign.yaml
```

### Using Claude with @-mentions (Recommended)

If using Claude with MCP or file access:

```
@ZkPatternFuzz I want to fuzz @my-circuit.circom

Generate a campaign YAML using examples from @tests/campaigns/
```

Claude will:
- Read the entire repo context
- Use example campaigns as templates
- Generate optimized config for your circuit

### Example Prompt

```
I have ZkPatternFuzz at ~/repos/ZkPatternFuzz

My circuit is at ~/my-project/circuits/token.circom:

[PASTE CIRCUIT CODE]

Please:
1. Read ~/repos/ZkPatternFuzz/tests/campaigns/mock_merkle_audit.yaml as a template
2. Read ~/repos/ZkPatternFuzz/docs/AI_ASSISTED_WORKFLOW.md for the schema
3. Generate a campaign YAML for my circuit
4. Save it to ~/my-project/campaign.yaml
5. Give me the command to run the fuzzer
```

AI Response:
```yaml
# Generated campaign.yaml
campaign:
  name: "Token Circuit Audit"
  ...
```

Run with:
```bash
cd ~/repos/ZkPatternFuzz
cargo run --release -- --config ~/my-project/campaign.yaml
```

## Quick Start

### 1. Prepare Your Circuit

Have your ZK circuit code ready:
- **Circom**: `.circom` files
- **Noir**: `.nr` files  
- **Halo2**: `.rs` files
- **Cairo**: `.cairo` files

### 2. Use AI to Generate YAML

#### Option A: Claude (Anthropic)

```bash
# Using Claude API
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-opus-4-20250514",
    "max_tokens": 4096,
    "messages": [{
      "role": "user",
      "content": "Generate a ZkPatternFuzz YAML config for this circuit:\n\n[PASTE CIRCUIT CODE]\n\nUse the schema from: https://github.com/yourusername/ZkPatternFuzz/blob/main/docs/AI_ASSISTED_WORKFLOW.md#yaml-schema"
    }]
  }' > campaign.yaml
```

#### Option B: ChatGPT (OpenAI)

```bash
# Using OpenAI API
curl https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [{
      "role": "user",
      "content": "Generate ZkPatternFuzz YAML for this circuit:\n\n[PASTE CIRCUIT CODE]"
    }]
  }' > campaign.yaml
```

#### Option C: Manual (Web Interface)

1. Go to Claude.ai or ChatGPT
2. Paste the prompt template below
3. Copy the generated YAML
4. Save as `campaign.yaml`

### 3. Run ZkPatternFuzz

```bash
cargo run --release -- --config campaign.yaml
```

### 4. Review Results

```bash
# Check reports directory
ls -la reports/

# View JSON report
cat reports/report.json | jq

# View Markdown report
cat reports/report.md
```

## AI Prompt Template

Copy this prompt and replace `[CIRCUIT_CODE]` with your actual circuit:

```
You are a ZK circuit security expert. Analyze this circuit and generate a ZkPatternFuzz campaign YAML configuration.

CIRCUIT CODE:
```
[PASTE YOUR CIRCUIT CODE HERE]
```

REQUIREMENTS:
1. Identify all input variables (private and public)
2. Determine appropriate attack types based on circuit logic
3. Suggest fuzzing strategies for each input
4. Include interesting edge case values
5. Generate complete YAML following the schema below

YAML SCHEMA:
```yaml
campaign:
  name: "Descriptive Circuit Name"
  version: "1.0"
  target:
    framework: "circom|noir|halo2|cairo"
    circuit_path: "./path/to/circuit"
    main_component: "MainComponentName"
  parameters:
    field: "bn254"
    max_constraints: 100000
    timeout_seconds: 60

attacks:
  - type: "underconstrained"
    description: "Find multiple valid witnesses"
    config:
      witness_pairs: 1000
  
  - type: "soundness"
    description: "Attempt proof forgery"
    config:
      forge_attempts: 500
  
  - type: "arithmetic_overflow"
    description: "Test field arithmetic edge cases"
    config:
      test_values: ["0", "1", "p-1"]
  
  - type: "collision"
    description: "Find hash collisions"
    config:
      samples: 100000

inputs:
  - name: "inputName"
    type: "field|array<field>|bool|array<bool>"
    fuzz_strategy: "random|interesting_values|mutation"
    constraints: ["nonzero"]  # optional
    interesting: ["0x0", "0x1", "0xdead"]  # optional
    length: 10  # for arrays only

reporting:
  output_dir: "./reports"
  formats: ["json", "markdown", "sarif"]
  include_poc: true
```

ATTACK TYPES:
- underconstrained: Multiple valid witnesses
- soundness: Proof forgery attempts
- arithmetic_overflow: Field overflow/underflow
- collision: Hash/nullifier collisions
- boundary: Edge case values
- witness_validation: Witness consistency

FUZZ STRATEGIES:
- random: Random field elements
- interesting_values: Predefined edge cases
- mutation: Mutate from corpus
- exhaustive_if_small: Enumerate small domains

Generate the complete YAML configuration now.
```

## YAML Schema Reference

### Complete Schema

```yaml
campaign:
  name: string                    # Campaign name
  version: string                 # Version (e.g., "1.0")
  target:
    framework: enum               # circom|noir|halo2|cairo|mock
    circuit_path: path            # Path to circuit file
    main_component: string        # Main component/function name
  parameters:                     # Optional
    field: string                 # Field type (default: "bn254")
    max_constraints: int          # Max constraints (default: 100000)
    timeout_seconds: int          # Timeout (default: 60)

attacks:                          # At least one required
  - type: enum                    # Attack type (see below)
    description: string           # What this tests
    config: object                # Attack-specific config (flexible)

inputs:                           # At least one required
  - name: string                  # Input variable name
    type: string                  # field|array<field>|bool|array<bool>
    fuzz_strategy: enum           # random|interesting_values|mutation|exhaustive_if_small
    constraints: [string]         # Optional: ["nonzero", "range:0-100"]
    interesting: [string]         # Optional: ["0x0", "0x1"]
    length: int                   # Required for arrays

mutations:                        # Optional
  - name: string                  # Mutation name
    probability: float            # 0.0-1.0
    operations: [string]          # Optional: ["add_one", "negate"]
    use_values: [string]          # Optional: ["zero", "one"]
    max_stacked_mutations: int    # Optional

oracles:                          # Optional
  - name: string                  # Oracle name
    severity: enum                # info|low|medium|high|critical
    description: string           # What it detects

reporting:                        # Optional
  output_dir: path                # Default: "./reports"
  formats: [string]               # ["json", "markdown", "sarif"]
  include_poc: bool               # Default: true
  crash_reproduction: bool        # Default: true
```

### Attack Types

| Type | Description | Config Example |
|------|-------------|----------------|
| `underconstrained` | Multiple valid witnesses | `witness_pairs: 1000` |
| `soundness` | Proof forgery | `forge_attempts: 500` |
| `arithmetic_overflow` | Field arithmetic bugs | `test_values: ["0", "p-1"]` |
| `collision` | Hash collisions | `samples: 100000` |
| `boundary` | Edge case values | `test_boundaries: true` |
| `witness_validation` | Witness consistency | `validation_rounds: 100` |

### Input Types

| Type | Description | Example |
|------|-------------|---------|
| `field` | Single field element | `type: "field"` |
| `array<field>` | Array of field elements | `type: "array<field>", length: 10` |
| `bool` | Boolean (0 or 1) | `type: "bool"` |
| `array<bool>` | Array of booleans | `type: "array<bool>", length: 8` |

### Fuzz Strategies

| Strategy | Description | Best For |
|----------|-------------|----------|
| `random` | Random values | General fuzzing |
| `interesting_values` | Predefined edge cases | Known vulnerabilities |
| `mutation` | Mutate from corpus | Coverage-guided |
| `exhaustive_if_small` | Enumerate all values | Small domains (<1000) |

## Example: Circom Merkle Tree

### Input Circuit (merkle.circom)

```circom
template MerkleProof(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    
    signal output valid;
    
    component hashers[levels];
    signal hashes[levels + 1];
    hashes[0] <== leaf;
    
    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== pathIndices[i] ? pathElements[i] : hashes[i];
        hashers[i].inputs[1] <== pathIndices[i] ? hashes[i] : pathElements[i];
        hashes[i + 1] <== hashers[i].out;
    }
    
    valid <== (hashes[levels] === root);
}
```

### AI-Generated YAML

```yaml
campaign:
  name: "Merkle Tree Proof Verification Audit"
  version: "1.0"
  target:
    framework: "circom"
    circuit_path: "./circuits/merkle.circom"
    main_component: "MerkleProof"
  parameters:
    field: "bn254"
    max_constraints: 50000
    timeout_seconds: 120

attacks:
  - type: "underconstrained"
    description: "Find different leaves that produce same root"
    config:
      witness_pairs: 2000
      compare_outputs: true

  - type: "soundness"
    description: "Forge valid proof for invalid leaf"
    config:
      forge_attempts: 1000
      mutation_rate: 0.2

  - type: "collision"
    description: "Find hash collisions in Poseidon"
    config:
      samples: 100000

  - type: "boundary"
    description: "Test edge cases in path indices"
    config:
      test_boundaries: true

inputs:
  - name: "leaf"
    type: "field"
    fuzz_strategy: "interesting_values"
    interesting:
      - "0x0"
      - "0x1"
      - "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

  - name: "root"
    type: "field"
    fuzz_strategy: "random"
    constraints: ["nonzero"]

  - name: "pathElements"
    type: "array<field>"
    length: 10
    fuzz_strategy: "mutation"

  - name: "pathIndices"
    type: "array<bool>"
    length: 10
    fuzz_strategy: "random"

mutations:
  - name: "bit_flip"
    probability: 0.3

  - name: "arithmetic"
    operations: ["add_one", "sub_one", "negate"]
    probability: 0.2

  - name: "boundary"
    use_values: ["zero", "one", "max_field"]
    probability: 0.2

reporting:
  output_dir: "./reports/merkle_audit"
  formats: ["json", "markdown", "sarif"]
  include_poc: true
  crash_reproduction: true
```

## Tips for Better AI-Generated Configs

### 1. Provide Context

```
This is a Merkle tree circuit for privacy-preserving transactions.
It verifies that a leaf is part of a tree with a given root.
Focus on: path validation, hash collision resistance, and proof forgery.
```

### 2. Specify Constraints

```
The circuit has these constraints:
- pathIndices must be boolean (0 or 1)
- pathElements length must match tree depth
- root must be non-zero
```

### 3. Mention Known Vulnerabilities

```
Common issues in similar circuits:
- Underconstrained path selection
- Missing range checks on indices
- Hash function weaknesses
```

### 4. Request Specific Attacks

```
Focus on these attack vectors:
1. Proof forgery with invalid leaves
2. Path manipulation attacks
3. Hash collision attempts
```

## Troubleshooting

### AI generates invalid YAML

**Problem**: Syntax errors or missing fields

**Solution**: 
```bash
# Validate YAML
cargo run -- --config campaign.yaml --dry-run
```

### Circuit path not found

**Problem**: `circuit_path` doesn't exist

**Solution**: Update path in YAML or use `mock` framework for testing:
```yaml
target:
  framework: "mock"  # Uses mock executor
```

### Too many/few attacks

**Problem**: AI over/under-generates attacks

**Solution**: Edit YAML manually, keep 2-5 most relevant attacks

### Input types mismatch

**Problem**: AI guesses wrong input types

**Solution**: Check circuit signature and fix types:
```yaml
inputs:
  - name: "myArray"
    type: "array<field>"  # Not just "field"
    length: 10            # Must specify length
```

## Advanced: Automated Pipeline

### Bash Script

```bash
#!/bin/bash
# generate_and_fuzz.sh

CIRCUIT=$1
API_KEY=$2

# Generate YAML using Claude
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $API_KEY" \
  -H "content-type: application/json" \
  -d "{
    \"model\": \"claude-opus-4-20250514\",
    \"max_tokens\": 4096,
    \"messages\": [{
      \"role\": \"user\",
      \"content\": \"Generate ZkPatternFuzz YAML for: $(cat $CIRCUIT)\"
    }]
  }" | jq -r '.content[0].text' > campaign.yaml

# Validate
cargo run -- --config campaign.yaml --dry-run

# Run fuzzer
cargo run --release -- --config campaign.yaml

# Open report
xdg-open reports/report.md
```

Usage:
```bash
chmod +x generate_and_fuzz.sh
./generate_and_fuzz.sh circuit.circom $ANTHROPIC_API_KEY
```

### Python Script

```python
#!/usr/bin/env python3
import anthropic
import sys

def generate_yaml(circuit_path, api_key):
    with open(circuit_path) as f:
        circuit_code = f.read()
    
    client = anthropic.Anthropic(api_key=api_key)
    
    message = client.messages.create(
        model="claude-opus-4-20250514",
        max_tokens=4096,
        messages=[{
            "role": "user",
            "content": f"Generate ZkPatternFuzz YAML for:\n\n{circuit_code}"
        }]
    )
    
    yaml_content = message.content[0].text
    
    with open("campaign.yaml", "w") as f:
        f.write(yaml_content)
    
    print("✓ Generated campaign.yaml")

if __name__ == "__main__":
    generate_yaml(sys.argv[1], sys.argv[2])
```

Usage:
```bash
python3 generate_yaml.py circuit.circom $ANTHROPIC_API_KEY
cargo run -- --config campaign.yaml
```

## Resources

- [Campaign Examples](../tests/campaigns/) - Pre-built YAML configs
- [YAML Schema](../src/config/mod.rs) - Full schema definition
- [Attack Types](../src/attacks/) - Attack implementation details
- [Tutorial](TUTORIAL.md) - Step-by-step guide

## Support

If AI-generated configs don't work:

1. Validate with `--dry-run`
2. Check [example campaigns](../tests/campaigns/)
3. Open an issue with circuit + generated YAML
4. Use `mock` framework for testing

## License

Same as ZkPatternFuzz - BSL 1.1 (converts to Apache 2.0 in 2028)
