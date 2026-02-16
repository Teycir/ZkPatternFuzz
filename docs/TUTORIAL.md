# ZkPatternFuzz Tutorial

Complete guide to fuzzing zero-knowledge circuits with ZkPatternFuzz.

## Table of Contents

1. [Installation](#installation)
2. [Your First Fuzzing Campaign](#your-first-fuzzing-campaign)
3. [Understanding the Results](#understanding-the-results)
4. [Testing Real Circuits](#testing-real-circuits)
5. [Advanced Techniques](#advanced-techniques)
6. [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites

```bash
# Install Rust (1.70+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Z3 SMT solver
# macOS
brew install z3

# Ubuntu/Debian
sudo apt-get install z3

# Or build from source
git clone https://github.com/Z3Prover/z3.git
cd z3
python scripts/mk_make.py
cd build
make
sudo make install
```

### Build ZkPatternFuzz

```bash
git clone https://github.com/yourusername/ZkPatternFuzz.git
cd ZkPatternFuzz
cargo build --release
```

Verify installation:
```bash
./target/release/zk-fuzzer --help
```

## Your First Fuzzing Campaign

### Step 1: Generate a Sample Configuration

```bash
cargo run --release -- init --output my_first_campaign.yaml --framework circom
```

This creates `my_first_campaign.yaml`:

```yaml
campaign:
  name: "Sample Circom Audit"
  version: "1.0"
  target:
    framework: "circom"
    circuit_path: "./circuits/example.circom"
    main_component: "Main"
  parameters:
    field: "bn254"
    max_constraints: 100000
    timeout_seconds: 300

attacks:
  - type: underconstrained
    description: "Find inputs that satisfy constraints but produce wrong outputs"
    config:
      witness_pairs: 1000
      # public_input_names: ["input1"]
      # fixed_public_inputs: ["0x01"]

inputs:
  - name: "input1"
    type: "field"
    fuzz_strategy: random
    constraints:
      - "nonzero"

reporting:
  output_dir: "./reports"
  formats:
    - json
    - markdown
  include_poc: true
```

### Optional: New Scanner Configs (2026-02)

These scanners are opt-in and live under the parent attack's `config` section.

```yaml
attacks:
  - type: soundness
    description: "Proof malleability + determinism + trusted setup"
    config:
      proof_malleability:
        enabled: true
        proof_samples: 10
        random_mutations: 100
        structured_mutations: true
      determinism:
        enabled: true
        repetitions: 5
        sample_count: 50
      trusted_setup_test:
        enabled: true
        attempts: 10
        ptau_file_a: "pot12_original.ptau"
        ptau_file_b: "pot12_alternative.ptau"

  - type: underconstrained
    description: "Frozen wire detector"
    config:
      frozen_wire:
        enabled: true
        min_samples: 100
        known_constants: [0]

  - type: collision
    description: "Nullifier replay"
    config:
      nullifier_replay:
        enabled: true
        replay_attempts: 50
        base_samples: 10

  - type: boundary
    description: "Input canonicalization"
    config:
      canonicalization:
        enabled: true
        sample_count: 20
        test_field_wrap: true
        test_negative_zero: true
        test_additive_inverse: false

  - type: differential
    description: "Cross-backend differential"
    config:
      backends: ["circom", "noir"]
      cross_backend:
        enabled: true
        sample_count: 100
        tolerance_bits: 0
```

### Step 2: Run Your First Campaign

```bash
cargo run --release -- --config my_first_campaign.yaml
```

You'll see output like:
```
╔═══════════════════════════════════════════════════════════╗
║              ZK-FUZZER v0.1.0                             ║
║       Zero-Knowledge Proof Security Tester                ║
╠═══════════════════════════════════════════════════════════╣
║  Campaign: Sample Mock Audit                              ║
║  Target:   Mock                                           ║
║  Attacks:  4 configured                                   ║
║  Inputs:   1 defined                                      ║
╚═══════════════════════════════════════════════════════════╝

[INFO] Loading campaign from: my_first_campaign.yaml
[INFO] Circuit has 100 constraints, density: 0.50, DOF: 0
[INFO] Seeded corpus with 10 initial test cases
[INFO] Running attack: underconstrained
[INFO] Completed 1000 executions, coverage: 85.2%
```

### Step 3: Review Results

Check the generated reports:
```bash
ls -la reports/
# report.json      - Machine-readable findings
# report.md        - Human-readable summary
# corpus/          - Interesting test cases
```

View the markdown report:
```bash
cat reports/report.md
```

## Understanding the Results

### Report Structure

#### JSON Report (`report.json`)
```json
{
  "campaign_name": "Sample Mock Audit",
  "timestamp": "2024-02-04T12:00:00Z",
  "findings": [
    {
      "attack_type": "Underconstrained",
      "severity": "High",
      "description": "Circuit accepts multiple valid witnesses",
      "location": "constraint_42",
      "poc": {
        "witness_a": ["0x1234...", "0x5678..."],
        "witness_b": ["0xabcd...", "0xef01..."]
      }
    }
  ],
  "statistics": {
    "total_executions": 1000,
    "coverage_percentage": 85.2,
    "findings_by_severity": {
      "High": 1,
      "Medium": 3
    }
  }
}
```

#### Markdown Report (`report.md`)
Human-readable with:
- Executive summary
- Findings with severity
- Proof-of-concept test cases
- Recommendations

### Severity Levels

| Level | Meaning | Action |
|-------|---------|--------|
| **Critical** | Immediate security risk | Fix immediately |
| **High** | Significant vulnerability | Fix before deployment |
| **Medium** | Potential issue | Review and fix |
| **Low** | Minor concern | Consider fixing |
| **Info** | Informational | No action needed |

### Common Findings

#### Underconstrained Circuit
```
[HIGH] Underconstrained
Circuit accepts multiple valid witnesses for the same public inputs.
This means constraints are missing, allowing proof malleability.

PoC: Two different witnesses produce valid proofs:
  Witness A: [0x1, 0x2, 0x3]
  Witness B: [0x1, 0x5, 0x3]  # Different middle value!
```

**Fix**: Add constraints to uniquely determine all intermediate values.

#### Arithmetic Overflow
```
[MEDIUM] Arithmetic Overflow
Field arithmetic wraps around at modulus, causing unexpected behavior.

PoC: Input near field modulus causes overflow:
  Input: 0xffffffffffffffffffffffffffffffff...
```

**Fix**: Add range checks to ensure values stay within expected bounds.

## Testing Real Circuits

### Circom Example

#### Step 1: Install Circom

```bash
# Install circom
git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
sudo cp target/release/circom /usr/local/bin/

# Install snarkjs
npm install -g snarkjs
```

#### Step 2: Create a Simple Circuit

`circuits/multiplier.circom`:
```circom
pragma circom 2.0.0;

template Multiplier() {
    signal input a;
    signal input b;
    signal output c;
    
    c <== a * b;
}

component main = Multiplier();
```

#### Step 3: Configure Campaign

`circom_campaign.yaml`:
```yaml
campaign:
  name: "Multiplier Circuit Audit"
  version: "1.0"
  target:
    framework: circom
    circuit_path: "./circuits/multiplier.circom"
    main_component: "Multiplier"

attacks:
  - type: underconstrained
    config:
      witness_pairs: 500
      # Optional: fix public inputs explicitly (recommended when inputs are interleaved)
      # public_input_names: ["a"]          # or public_input_positions: [0]
      # fixed_public_inputs: ["0x01"]
  - type: arithmetic_overflow
    config:
      test_values: ["0", "1", "p-1", "p"]

inputs:
  - name: "a"
    type: "field"
    fuzz_strategy: random
  - name: "b"
    type: "field"
    fuzz_strategy: interesting_values
    interesting: ["0x0", "0x1", "0xFFFF"]

reporting:
  output_dir: "./reports/multiplier"
  formats: ["json", "markdown"]
```

#### Step 4: Run Fuzzing

```bash
cargo run --release -- --config circom_campaign.yaml --workers 4
```

### Noir Example

#### Step 1: Install Noir

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup
```

#### Step 2: Create Noir Project

```bash
nargo new my_circuit
cd my_circuit
```

Edit `src/main.nr`:
```rust
fn main(x: pub Field, y: Field) -> Field {
    x * y
}
```

#### Step 3: Configure Campaign

`noir_campaign.yaml`:
```yaml
campaign:
  name: "Noir Circuit Audit"
  version: "1.0"
  target:
    framework: noir
    circuit_path: "./my_circuit"
    main_component: "main"

attacks:
  - type: underconstrained
    config:
      witness_pairs: 1000
      # public_input_names: ["x"]

inputs:
  - name: "x"
    type: "field"
    fuzz_strategy: random
  - name: "y"
    type: "field"
    fuzz_strategy: mutation

reporting:
  output_dir: "./reports/noir"
  formats: ["json", "markdown", "sarif"]
```

#### Step 4: Run Fuzzing

```bash
cargo run --release -- --config noir_campaign.yaml
```

## Advanced Techniques

### Constraint-Guided Seeding

Enable Z3-based constraint solving for targeted seed generation:

```yaml
campaign:
  parameters:
    additional:
      constraint_guided_enabled: true
      constraint_guided_max_depth: 200
      constraint_guided_max_paths: 100
      constraint_guided_solver_timeout_ms: 5000
```

This generates inputs that explore specific constraint paths before fuzzing.

### Differential Testing

Compare implementations across backends:

```yaml
differential:
  enabled: true
  backends: ["circom", "noir"]
  tolerance: 0.0001
```

Detects discrepancies between equivalent circuits.

### Corpus Management

Optimize test case storage:

```yaml
corpus:
  enabled: true
  minimize: true
  max_size: 10000
  save_interesting: true
```

### Power Scheduling

Choose scheduling strategy:

```yaml
campaign:
  parameters:
    power_schedule: "MMOPT"  # FAST, COE, EXPLORE, MMOPT, RARE, SEEK
```

- **FAST**: Prioritize fast-executing tests
- **EXPLORE**: Maximize new coverage
- **MMOPT**: Balanced (recommended)

### Custom Attack Patterns

Create reusable patterns in `templates/attack_patterns.yaml`:

```yaml
patterns:
  - name: "merkle_tree_audit"
    attacks:
      - type: underconstrained
        config:
          witness_pairs: 2000
      - type: collision
        config:
          samples: 10000
    inputs:
      - name: "leaf"
        type: "field"
        fuzz_strategy: random
      - name: "pathElements"
        type: "field[]"
        length: 20
        fuzz_strategy: interesting_values
```

Use in campaigns:
```yaml
campaign:
  template: "merkle_tree_audit"
```

## Troubleshooting

### Issue: Backend Not Found

```
Error: circom not found in PATH
```

**Solution**: Install the backend tools:
```bash
# Circom
cargo install circom

# Noir
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash

# Halo2 (Rust-based, no separate install needed)

# Cairo
curl -L https://github.com/starkware-libs/cairo/releases/download/v2.0.0/release-x86_64-unknown-linux-musl.tar.gz | tar xz
```

If you want to enforce real backends only, set:
```yaml
campaign:
  parameters:
    additional:
      strict_backend: true
```

### Issue: Low Coverage

```
Coverage: 15%
```

**Solutions**:
1. Increase iterations:
   ```yaml
   attacks:
     - type: underconstrained
       config:
         witness_pairs: 5000  # Increase from 1000
   ```

2. Enable constraint-guided seeding:
   ```yaml
   campaign:
     parameters:
       additional:
         constraint_guided_enabled: true
   ```

3. Add more input strategies:
   ```yaml
   inputs:
     - name: "input1"
       fuzz_strategy: mutation  # Try different strategies
   ```

### Issue: Out of Memory

```
Error: Cannot allocate memory
```

**Solutions**:
1. Reduce workers:
   ```bash
   cargo run --release -- --config campaign.yaml --workers 2
   ```

2. Limit corpus size:
   ```yaml
   corpus:
     max_size: 1000  # Reduce from 10000
   ```

3. Disable corpus persistence:
   ```yaml
   corpus:
     enabled: false
   ```

### Issue: Compilation Fails

```
Error: Failed to compile circuit
```

**Solutions**:
1. Check circuit syntax
2. Verify backend version compatibility
3. Run dry-run to validate config:
   ```bash
   cargo run --release -- --config campaign.yaml --dry-run
   ```

### Issue: No Findings

This is good! But to verify the fuzzer is working:

1. Test with a known vulnerable circuit
2. Check coverage is increasing
3. Enable verbose logging:
   ```bash
   RUST_LOG=debug cargo run --release -- --config campaign.yaml
   ```

## Best Practices

### 1. Start Small
Begin with a small real circuit, then scale to production circuits.

### 2. Use Deterministic Seeds
For reproducible results:
```bash
cargo run --release -- --config campaign.yaml --seed 12345
```

### 3. Incremental Testing
Test components individually before full circuit.

### 4. Review All Findings
Even "Info" level findings can indicate design issues.

### 5. Combine with Manual Review
Fuzzing finds bugs but doesn't prove absence. Use with formal verification.

### 6. Save Corpus
Reuse interesting test cases across campaigns:
```yaml
corpus:
  enabled: true
  save_interesting: true
```

### 7. CI/CD Integration
Run fuzzing in continuous integration:
```bash
cargo run --release -- --config campaign.yaml --quiet --workers 2
```

## Next Steps

- Read [ARCHITECTURE.md](../ARCHITECTURE.md) for internals
- Explore [example campaigns](../tests/campaigns/)
- Check [CONTRIBUTING.md](../CONTRIBUTING.md) to add features
- Join discussions for questions

## Resources

- [Circom Tutorial](https://docs.circom.io/getting-started/installation/)
- [Noir Book](https://noir-lang.org/docs)
- [ZK Security Best Practices](https://blog.trailofbits.com/tag/zero-knowledge-proofs/)
- [0xPARC ZK Bug Tracker](https://github.com/0xPARC/zk-bug-tracker)

Happy fuzzing! 🚀
