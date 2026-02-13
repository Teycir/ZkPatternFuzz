# ZkPatternFuzz Validation Targets - Download Complete

**Status:** ✅ Successfully downloaded and integrated  
**Date:** February 13, 2026  
**Location:** `/home/teycir/Repos/ZkPatternFuzz/targets/`

---

## Downloaded Datasets

### 1. zkBugs (zkSecurity)
- **Repository:** https://github.com/zksecurity/zkbugs
- **Size:** 359 MB
- **Vulnerabilities:** 110 reproducible bugs
- **Path:** `targets/zkbugs/`

#### Breakdown by DSL:
| DSL | Count | Description |
|-----|-------|-------------|
| Circom | 41 | Most popular ZK circuit language |
| Halo2 | 35 | Rust-based ZK framework |
| Cairo | 8 | StarkNet's language |
| Bellperson | 7 | Filecoin's Rust ZK library |
| Arkworks | 5 | Rust ZK ecosystem |
| PIL | 2 | Polygon's intermediate language |
| Gnark | 1 | Go ZK library |
| Plonky3 | 8 | Polygon's PlonK implementation |
| Risc0 | 3 | RISC-V zkVM |

#### Key Vulnerabilities Available:
1. **Reclaim Protocol ChaCha20** - Unsound left rotation gadget
2. **Self.xyz** - Multiple under-constrained circuits (Merkle tree, country check)
3. **Iden3 Circomlib** - MIMC hash assigned but not constrained
4. **Semaphore Protocol** - Various soundness issues
5. **Dark Forest** - Missing bit length checks
6. **Risc0** - Underconstrained division in zkVM
7. **Filecoin** - Missing public input constraints

### 2. 0xPARC ZK Bug Tracker
- **Repository:** https://github.com/0xPARC/zk-bug-tracker
- **Stars:** 713
- **Bugs Documented:** 27 major bugs with detailed analysis
- **Path:** `targets/zk-bug-tracker/`

#### Notable Bugs:
1. **Tornado Cash** - Nullifier reuse vulnerability
2. **Semaphore** - Missing smart contract range check
3. **Dark Forest** - Missing bit length check
4. **Circom-Pairing** - Missing output check constraint
5. **Aztec 2.0** - Nondeterministic nullifier
6. **MACI 1.0** - Under-constrained circuit
7. **Polygon zkEVM** - Multiple missing constraints
8. **ZK Email** - Email address spoofing vulnerability

### 3. User's zk0d Targets
- **Source:** External drive `/media/elements/Repos/zk0d`
- **Circuits:** Semaphore, wrapper circuits
- **Path:** `targets/zk0d/`

#### Contents:
- `semaphore_20.circom` - Semaphore identity protocol circuit
- `wrappers/` - Circuit wrapper files for testing
- `zk0d_targets.yaml` - Campaign configuration template

---

## Generated Integration Outputs

### 1. Validation Targets JSON
**File:** `tests/validation/validation_targets.json`

Contains 125 validation targets with:
- Unique IDs
- Vulnerability types
- Circuit paths
- Configuration metadata
- Severity levels

### 2. Campaign Configurations
**Directory:** `tests/validation/campaigns/`

Generated 110 campaign YAML files for zkBugs vulnerabilities:
- Pre-configured attack types based on vulnerability class
- Evidence mode enabled
- Timeout settings (600s default)
- Framework-specific configurations

**Sample Campaign:**
```yaml
campaign:
  name: "Validation: Unsound Left Rotation"
  version: "1.0"
  target:
    framework: circom
    circuit_path: "/home/teycir/Repos/ZkPatternFuzz/targets/zkbugs/..."
  parameters:
    additional:
      evidence_mode: true
      strict_backend: true
      timeout_seconds: 600
attacks:
  - type: underconstrained
    config:
      witness_pairs: 5000
      max_execution_time_ms: 300000
```

### 3. Dataset Report
**File:** `tests/validation/dataset_report.json`

Machine-readable report with:
- Generation timestamp
- Total target count
- Breakdown by DSL
- Breakdown by vulnerability type
- Breakdown by source
- Sample targets (first 100)

### 4. Summary Markdown
**File:** `tests/validation/dataset_summary.md`

Human-readable summary showing:
- 125 total targets
- 109 Under-Constrained vulnerabilities (87%)
- 56 Circom circuits (45%)
- 35 Halo2 circuits (28%)

---

## How to Use the Validation Data

### 1. Run Validation Against zkBugs

```bash
cd /home/teycir/Repos/ZkPatternFuzz

# Run single campaign
python3 scripts/validate_zkbugs.py \
    --target tests/validation/campaigns/reclaimprotocol_circom-chacha20_zksecurity_unsound_left_rotation.yaml \
    --output reports/validation/

# Run all campaigns
python3 scripts/validate_all.py \
    --dataset tests/validation/campaigns/ \
    --output reports/validation/full_report.json
```

### 2. Check Detection Rate

```bash
# Count total targets
total=$(jq '. | length' tests/validation/validation_targets.json)
echo "Total targets: $total"

# Count by DSL
jq 'group_by(.dsl) | map({dsl: .[0].dsl, count: length})' \
    tests/validation/validation_targets.json

# Count by vulnerability type
jq 'group_by(.vulnerability_type) | map({type: .[0].vulnerability_type, count: length})' \
    tests/validation/validation_targets.json
```

### 3. Generate Validation Report

```bash
# After running campaigns
cargo run --bin validation_report -- \
    --campaigns tests/validation/campaigns/ \
    --results reports/validation/ \
    --output docs/VALIDATION_RESULTS.md
```

---

## Validation Targets Summary

### By Severity
- **Critical:** 109 targets (87%)
- **High:** 16 targets (13%)

### By Vulnerability Type
- **Under-Constrained:** 109 (87%)
- **Computational Issues:** 6 (5%)
- **Fiat-Shamir Issue:** 2 (2%)
- **Backend Issue:** 1 (1%)
- **Over-Constrained:** 1 (1%)

### By Source
- **zkBugs:** 110 targets (88%)
- **0xPARC:** 9 targets (7%)
- **zk0d:** 6 targets (5%)

---

## Integration Script

**File:** `scripts/integrate_validation_datasets.py`

This script:
1. Parses zkBugs dataset (110 vulnerabilities)
2. Parses 0xPARC tracker (9 major bugs)
3. Parses user's zk0d targets (6 circuits)
4. Generates campaign configurations
5. Exports validation targets JSON
6. Creates summary reports

**Run it again anytime:**
```bash
python3 scripts/integrate_validation_datasets.py
```

---

## Next Steps

### 1. Fix CVE Regression Tests (CRITICAL)
Update `src/cve/mod.rs` to actually execute circuits instead of returning `passed: true` unconditionally.

### 2. Run Validation Suite
```bash
# Test against 15 ground truth circuits first
./tests/scripts/ground_truth_validation.sh

# Then run against full zkBugs dataset (110 targets)
python3 scripts/validate_all.py --dataset tests/validation/campaigns/
```

### 3. Measure Metrics
Target minimums:
- Detection Rate: ≥80%
- False Positive Rate: ≤15%
- True Positives: 100+ bugs

### 4. Generate Report
Update README with real metrics from validation runs.

---

## File Locations Summary

```
/home/teycir/Repos/ZkPatternFuzz/
├── targets/
│   ├── zkbugs/                    # 110 vulnerabilities (359MB)
│   ├── zk-bug-tracker/            # 0xPARC dataset
│   └── zk0d/                      # Your targets (semaphore, etc.)
├── tests/
│   └── validation/
│       ├── validation_targets.json    # 125 targets metadata
│       ├── campaigns/                 # 110 YAML configs
│       ├── dataset_report.json        # Machine-readable report
│       └── dataset_summary.md         # Human-readable summary
└── scripts/
    └── integrate_validation_datasets.py   # Integration script
```

---

## References

- **zkBugs:** https://github.com/zksecurity/zkbugs
- **0xPARC Tracker:** https://github.com/0xPARC/zk-bug-tracker
- **zkBugs Website:** https://bugs.zksecurity.xyz/
- **Validation Framework Doc:** `docs/VALIDATION_FRAMEWORK.md`

---

**You now have 125 real-world vulnerability targets ready for validation!**
