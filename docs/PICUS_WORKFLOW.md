# Picus Integration Workflow Guide

This document provides practical examples of using Picus with ZkPatternFuzz.

---

## Quick Reference

### Basic Picus Verification
```bash
# Verify a circuit with default settings (60s timeout)
./scripts/zeroday_workflow.sh verify circuits/merkle.circom

# Increase timeout for complex circuits (5 minutes)
./scripts/zeroday_workflow.sh verify circuits/complex_hash.circom \
  --timeout 300000

# Save JSON output
./scripts/zeroday_workflow.sh verify circuits/merkle.circom \
  --output reports/picus_merkle.json
```

---

## Complete Workflow Example

### Scenario: Audit Tornado Cash Withdraw Circuit

```bash
# Step 1: SKIM - Fast heuristic scan
./scripts/zeroday_workflow.sh skim /path/to/tornado-core

# Output: reports/zk0d/skimmer/candidate_invariants.yaml
# Review and create campaign YAML with invariants

# Step 2: EVIDENCE - Fuzzing with invariants
./scripts/zeroday_workflow.sh evidence campaigns/tornado_withdraw.yaml \
  --iterations 50000 \
  --timeout 1800 \
  --seed 42

# Output: reports/tornado/report.json
# Suppose we found:
#   - Finding #1: Under-constraint in Merkle path validation
#   - Finding #2: Nullifier collision hint
#   - Finding #3: Signature malleability

# Step 3: VERIFY - Formal proof for under-constraint findings
./scripts/zeroday_workflow.sh verify \
  /path/to/tornado-core/circuits/merkleTree.circom \
  --timeout 300000 \
  --output reports/picus_merkle.json

# Check exit code and output:
# Exit 9 = UNSAFE (FORMALLY CONFIRMED ✅)
# Exit 0 = SAFE (likely false positive ❌)
# Exit 10 = UNKNOWN (inconclusive)

# Step 4: TRIAGE - Update findings
# Finding #1: FORMALLY CONFIRMED (Picus unsafe)
# Finding #2: CONFIRMED (ZkPatternFuzz only, collision oracle)
# Finding #3: CONFIRMED (ZkPatternFuzz only, signature oracle)

# Step 5: DEEP - Edge case hunting
./scripts/zeroday_workflow.sh deep campaigns/tornado_withdraw.yaml \
  --iterations 100000 \
  --timeout 3600
```

---

## Interpreting Picus Results

### Result: SAFE (Exit 0)
```
The circuit is properly constrained
Exiting Picus with the code 0
```

**Meaning:**
- No under-constraint bug found
- Formal guarantee (assuming solver is sound)
- If ZkPatternFuzz found an under-constraint issue, it's likely a false positive

**Action:**
- Downgrade ZkPatternFuzz finding to **NOT CONFIRMED**
- Document in report: "Picus formal verification returned SAFE"

---

### Result: UNSAFE (Exit 9)
```
The circuit is underconstrained
Counterexample:
  inputs:
    main.pathIndices[0]: 2
    main.pathIndices[1]: 0
  first possible outputs:
    main.root: 12345
  second possible outputs:
    main.root: 12345
Exiting Picus with the code 9
```

**Meaning:**
- Under-constraint bug **formally proven**
- Zero false positive guarantee
- Counterexample shows concrete inputs that violate uniqueness

**Action:**
- Upgrade finding to **FORMALLY CONFIRMED**
- Extract counterexample for PoC
- High priority for remediation

---

### Result: UNKNOWN (Exit 10)
```
Cannot determine whether the circuit is properly constrained
Exiting Picus with the code 0
```

**Meaning:**
- SMT solver timed out or got stuck
- No conclusion (neither safe nor unsafe)

**Action:**
- Try increasing `--timeout`
- Try different solver (`--solver z3` instead of `cvc5`)
- Keep ZkPatternFuzz finding as **LIKELY** (unverified)
- Consider manual review or circuit simplification

---

## Cross-Validation Matrix

| ZkPatternFuzz | Picus | Final Status | Confidence |
|---------------|-------|--------------|------------|
| Under-constraint hint | `unsafe` | **FORMALLY CONFIRMED** | 100% ✅ |
| Under-constraint found | `unsafe` | **FORMALLY CONFIRMED** | 100% ✅ |
| Under-constraint found | `safe` | **NOT CONFIRMED** | 0% (false positive) ❌ |
| Under-constraint found | `unknown` | **LIKELY** | 70% ⚠️ |
| No finding | `unsafe` | **FORMALLY CONFIRMED** | 100% (fuzzer missed) ✅ |
| Other attack type | N/A | **CONFIRMED** | 90% (Picus only checks under-constraint) |

---

## Advanced Usage

### Batch Verification of Multiple Circuits
```bash
#!/bin/bash
# verify_all_circuits.sh

CIRCUITS_DIR="$1"
OUTPUT_DIR="reports/picus_batch"

mkdir -p "$OUTPUT_DIR"

for circuit in "$CIRCUITS_DIR"/*.circom; do
    name=$(basename "$circuit" .circom)
    echo "Verifying: $name"
    
    ./scripts/zeroday_workflow.sh verify "$circuit" \
        --timeout 300000 \
        --output "$OUTPUT_DIR/${name}_picus.json" \
        > "$OUTPUT_DIR/${name}_picus.log" 2>&1
    
    exit_code=$?
    
    case $exit_code in
        0)  echo "  ✅ SAFE" ;;
        9)  echo "  ❌ UNSAFE (BUG FOUND!)" ;;
        10) echo "  ⚠️  UNKNOWN" ;;
    esac
done
```

### Integration with CI/CD
```yaml
# .github/workflows/zk_security.yml
name: ZK Security Testing

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Install dependencies
        run: |
          cargo install --path .
          # Install Picus
          
      - name: Run ZkPatternFuzz
        run: |
          ./scripts/zeroday_workflow.sh evidence \
            campaigns/ci_campaign.yaml \
            --iterations 10000
      
      - name: Run Picus verification
        run: |
          for circuit in circuits/*.circom; do
            ./scripts/zeroday_workflow.sh verify "$circuit" \
              --timeout 180000
          done
      
      - name: Upload reports
        uses: actions/upload-artifact@v2
        with:
          name: security-reports
          path: reports/
```

---

## Performance Tips

### When Picus is Slow/Stuck

1. **Split large circuits into smaller pieces**
   ```bash
   # Instead of verifying entire withdraw.circom
   # Verify individual templates:
   ./scripts/zeroday_workflow.sh verify circuits/merkle_subtree.circom
   ./scripts/zeroday_workflow.sh verify circuits/nullifier_gen.circom
   ```

2. **Use incremental timeout strategy**
   ```bash
   # Start with 60s
   ./scripts/zeroday_workflow.sh verify circuit.circom --timeout 60000
   
   # If unknown, try 5 minutes
   ./scripts/zeroday_workflow.sh verify circuit.circom --timeout 300000
   
   # If still unknown, try 30 minutes (max recommended)
   ./scripts/zeroday_workflow.sh verify circuit.circom --timeout 1800000
   ```

3. **Try both solvers**
   ```bash
   # CVC5 (better for finite fields, default)
   ./scripts/zeroday_workflow.sh verify circuit.circom --solver cvc5
   
   # Z3 (sometimes faster for different constraint shapes)
   ./scripts/zeroday_workflow.sh verify circuit.circom --solver z3
   ```

---

## Example: Real CVE Verification

### CVE-2021-002: Merkle Sibling Order Ambiguity

**ZkPatternFuzz finding:**
```yaml
- type: underconstrained
  description: "pathIndices not constrained to binary"
  witness:
    pathIndices: [2, 0, 0, ...]  # Non-binary value!
```

**Picus verification:**
```bash
./scripts/zeroday_workflow.sh verify \
  benchmarks/buggy-mix/tornado-core/merkleTree.circom \
  --timeout 120000
```

**Expected output:**
```
The circuit is underconstrained
Counterexample:
  inputs:
    main.pathIndices[0]: 2  # Confirms non-binary value
  first possible outputs:
    main.root: 0x123abc...
  second possible outputs:
    main.root: 0x123abc...  # Same root, different witness!
Exiting Picus with the code 9
```

**Conclusion:** **FORMALLY CONFIRMED CVE** ✅

---

## Troubleshooting

### Error: Picus not found
```
[ERROR] Picus not found at: /tmp/Picus/run-picus
```

**Solution:**
```bash
# Install Picus
cd /tmp && git clone https://github.com/Veridise/Picus.git
cd Picus && raco pkg install --auto

# Or set custom location
export PICUS_DIR=/path/to/Picus
./scripts/zeroday_workflow.sh verify circuit.circom
```

### Error: circom not found
```
circom: command not found
```

**Solution:**
```bash
# Install Circom
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
git clone https://github.com/iden3/circom.git
cd circom && cargo build --release
sudo cp target/release/circom /usr/local/bin/
```

---

## See Also

- [VERIDISE_INTEGRATION.md](../VERIDISE_INTEGRATION.md) - Installation guide
- [AI_PENTEST_RULES.md](AI_PENTEST_RULES.md) - Classification rules
- [QUICKSTART_0DAY.md](QUICKSTART_0DAY.md) - Quick start guide
- [Picus GitHub](https://github.com/Veridise/Picus) - Upstream documentation
