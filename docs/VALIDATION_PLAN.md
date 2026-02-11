# ZkPatternFuzz Validation Testing Plan

## Objective
Validate ZkPatternFuzz's real-world effectiveness by measuring detection rates against known vulnerabilities and false-positive rates on safe circuits.

## Test Suites

### 1. 0xPARC ZK Bug Tracker Dataset
**Source:** https://github.com/0xPARC/zk-bug-tracker

**Setup:**
```bash
# Clone dataset
git clone https://github.com/0xPARC/zk-bug-tracker.git tests/datasets/0xparc-bugs/

# Extract vulnerable circuits
mkdir -p tests/datasets/0xparc-bugs/circuits/
# Parse markdown files to extract circuit code
```

**Target Bugs (Priority):**
- **Tornado Cash nullifier reuse** (underconstrained)
- **Semaphore double-signaling** (underconstrained)
- **Dark Forest range check bypass** (arithmetic_overflow)
- **Aztec nullifier collision** (collision)
- **Iden3 authentication bypass** (soundness)
- **zkSync state transition bug** (differential)
- **Polygon zkEVM boundary bug** (boundary)

**Campaigns:**
```yaml
# tests/campaigns/validation/0xparc_tornado_nullifier.yaml
campaign:
  name: "0xPARC: Tornado Cash Nullifier Reuse"
  version: "1.0"
  target:
    framework: "circom"
    circuit_path: "tests/datasets/0xparc-bugs/circuits/tornado_nullifier.circom"
  parameters:
    additional:
      evidence_mode: true
      strict_backend: true

attacks:
  - type: underconstrained
    config:
      witness_pairs: 5000
      public_input_names: ["root", "nullifier"]
```

**Metrics:**
- **Detection Rate:** `detected_bugs / total_bugs`
- **Time to Detection:** median time to first finding
- **Confidence Distribution:** % of findings at each confidence level

**Expected Results:**
- Detection rate: ≥90% (target from README)
- False negatives: ≤10%
- Mean time to detection: <5 minutes per bug

---

### 2. Safe Circuits (False Positive Benchmark)

**Location:** `tests/safe_circuits/`

**Circuits to Create:**
```
tests/safe_circuits/
├── merkle_proof_correct.circom      # Properly constrained Merkle proof
├── nullifier_unique.circom          # Correct nullifier uniqueness
├── range_proof_64bit.circom         # Proper range check
├── ecdsa_signature_valid.circom     # Correct signature verification
├── poseidon_hash_correct.circom     # Proper hash implementation
└── commitment_binding.circom        # Correct commitment scheme
```

**Campaigns:**
```yaml
# tests/campaigns/validation/safe_circuits_benchmark.yaml
campaign:
  name: "False Positive Benchmark"
  version: "1.0"
  target:
    framework: "circom"
    circuit_path: "tests/safe_circuits/{circuit}.circom"
  parameters:
    timeout_seconds: 600
    additional:
      evidence_mode: true
      min_evidence_confidence: "medium"

attacks:
  - type: underconstrained
    config:
      witness_pairs: 10000
  - type: soundness
    config:
      mutation_attempts: 5000
  - type: arithmetic_overflow
  - type: collision
    config:
      sample_count: 10000
  - type: boundary
```

**Metrics:**
- **False Positive Rate:** `false_findings / total_runs`
- **Per-Attack FPR:** breakdown by attack type
- **Confidence Correlation:** do false positives cluster at LOW confidence?

**Expected Results:**
- Overall FPR: <10% (target from README)
- HIGH/CRITICAL confidence FPR: <2%
- LOW confidence FPR: <20% (acceptable for triage)

---

### 3. Ground Truth Circuits

**Location:** `tests/ground_truth_circuits/`

**Structure:**
```
tests/ground_truth_circuits/
├── vulnerable/
│   ├── underconstrained_merkle.circom       # Known bug: accepts multiple witnesses
│   ├── missing_range_check.circom           # Known bug: overflow possible
│   ├── nullifier_collision.circom           # Known bug: collision exists
│   └── metadata.json                        # Expected findings
└── safe/
    ├── merkle_correct.circom
    ├── range_check_correct.circom
    └── metadata.json
```

**Metadata Format:**
```json
{
  "circuit": "underconstrained_merkle.circom",
  "expected_findings": [
    {
      "attack_type": "underconstrained",
      "severity": "critical",
      "description": "Accepts multiple witnesses for same root",
      "poc_inputs": [
        {"leaf": "0x1", "pathIndices": [0, 0]},
        {"leaf": "0x2", "pathIndices": [0, 0]}
      ]
    }
  ]
}
```

**Test Script:**
```bash
#!/bin/bash
# tests/scripts/ground_truth_validation.sh

for circuit in tests/ground_truth_circuits/vulnerable/*.circom; do
    name=$(basename "$circuit" .circom)
    cargo run --release -- \
        --config "tests/campaigns/validation/ground_truth_${name}.yaml" \
        --output "reports/validation/ground_truth/${name}.json"
    
    # Compare findings against metadata
    python3 tests/scripts/validate_findings.py \
        "reports/validation/ground_truth/${name}.json" \
        "tests/ground_truth_circuits/vulnerable/metadata.json"
done
```

**Metrics:**
- **True Positive Rate:** detected expected findings
- **False Negative Rate:** missed expected findings
- **Precision:** relevant findings / total findings
- **Recall:** detected findings / expected findings

---

### 4. CVE Validation

**Location:** `src/cve/` (existing module)

**Target CVEs:**
```
src/cve/
├── mod.rs                    # CVE registry
├── cve_2023_tornado.rs       # Tornado Cash nullifier bug
├── cve_2023_semaphore.rs     # Semaphore double-signal
├── cve_2024_darkforest.rs    # Dark Forest range check
├── cve_2024_aztec.rs         # Aztec nullifier collision
└── cve_2024_polygon.rs       # Polygon zkEVM boundary
```

**Implementation:**
```rust
// src/cve/mod.rs
pub struct CVETestCase {
    pub id: String,
    pub description: String,
    pub circuit_path: PathBuf,
    pub expected_attack: AttackType,
    pub poc_inputs: Vec<FieldElement>,
}

pub fn get_cve_suite() -> Vec<CVETestCase> {
    vec![
        cve_2023_tornado::test_case(),
        cve_2023_semaphore::test_case(),
        cve_2024_darkforest::test_case(),
        cve_2024_aztec::test_case(),
        cve_2024_polygon::test_case(),
    ]
}
```

**Test Integration:**
```rust
// tests/cve_validation.rs
#[test]
fn test_cve_detection_rate() {
    let cve_suite = get_cve_suite();
    let mut detected = 0;
    
    for cve in &cve_suite {
        let config = create_cve_campaign(&cve);
        let findings = run_campaign(config);
        
        if findings.iter().any(|f| f.attack_type == cve.expected_attack) {
            detected += 1;
            println!("✓ Detected: {}", cve.id);
        } else {
            println!("✗ Missed: {}", cve.id);
        }
    }
    
    let detection_rate = detected as f64 / cve_suite.len() as f64;
    println!("CVE Detection Rate: {:.1}%", detection_rate * 100.0);
    
    assert!(detection_rate >= 0.90, "Detection rate below 90% threshold");
}
```

**Campaigns:**
```yaml
# tests/campaigns/validation/cve_suite.yaml
campaign:
  name: "CVE Validation Suite"
  version: "1.0"
  parameters:
    additional:
      evidence_mode: true
      strict_backend: true
      min_evidence_confidence: "high"

# Run all CVE test cases
attacks:
  - type: underconstrained
    config:
      witness_pairs: 5000
  - type: soundness
  - type: arithmetic_overflow
  - type: collision
  - type: boundary
```

**Metrics:**
- **CVE Detection Rate:** detected CVEs / total CVEs
- **Time to Detection:** per CVE
- **Confidence Level:** per CVE finding

---

## Execution Plan

### Phase 1: Setup (Week 1)
```bash
# 1. Create directory structure
mkdir -p tests/datasets/0xparc-bugs/circuits/
mkdir -p tests/safe_circuits/
mkdir -p tests/ground_truth_circuits/{vulnerable,safe}/
mkdir -p tests/campaigns/validation/
mkdir -p reports/validation/{0xparc,safe,ground_truth,cve}/

# 2. Extract 0xPARC bugs
python3 tests/scripts/extract_0xparc_bugs.py

# 3. Create safe circuits
# (Manual implementation of 6 safe circuits)

# 4. Create ground truth circuits
# (Manual implementation with metadata)

# 5. Implement CVE test cases in src/cve/
```

### Phase 2: 0xPARC Dataset (Week 2)
```bash
# Run against all 0xPARC bugs
for bug in tests/datasets/0xparc-bugs/circuits/*.circom; do
    cargo run --release -- \
        --config "tests/campaigns/validation/0xparc_template.yaml" \
        --circuit "$bug" \
        --output "reports/validation/0xparc/$(basename $bug .circom).json"
done

# Aggregate results
python3 tests/scripts/aggregate_0xparc_results.py \
    reports/validation/0xparc/ \
    > reports/validation/0xparc_summary.md
```

### Phase 3: False Positive Benchmark (Week 3)
```bash
# Run against safe circuits
./tests/scripts/safe_circuits_benchmark.sh

# Generate FPR report
python3 tests/scripts/calculate_fpr.py \
    reports/validation/safe/ \
    > reports/validation/false_positive_report.md
```

### Phase 4: Ground Truth Validation (Week 3)
```bash
# Run ground truth suite
./tests/scripts/ground_truth_validation.sh

# Validate findings
python3 tests/scripts/validate_findings.py \
    reports/validation/ground_truth/ \
    tests/ground_truth_circuits/vulnerable/metadata.json \
    > reports/validation/ground_truth_report.md
```

### Phase 5: CVE Validation (Week 4)
```bash
# Run CVE test suite
cargo test --test cve_validation -- --nocapture

# Generate CVE report
cargo run --bin cve_report -- \
    --output reports/validation/cve_detection_report.md
```

### Phase 6: Publication (Week 4)
```bash
# Aggregate all results
python3 tests/scripts/generate_validation_report.py \
    reports/validation/ \
    > docs/VALIDATION_RESULTS.md

# Update README with results
# Commit and publish
```

---

## Deliverables

### 1. Test Artifacts
- [ ] `tests/datasets/0xparc-bugs/` - Extracted circuits
- [ ] `tests/safe_circuits/` - 6+ safe circuits
- [ ] `tests/ground_truth_circuits/` - Labeled vulnerable/safe circuits
- [ ] `src/cve/` - 5+ CVE test cases
- [ ] `tests/campaigns/validation/` - Campaign configs

### 2. Test Scripts
- [ ] `tests/scripts/extract_0xparc_bugs.py`
- [ ] `tests/scripts/safe_circuits_benchmark.sh`
- [ ] `tests/scripts/ground_truth_validation.sh`
- [ ] `tests/scripts/validate_findings.py`
- [ ] `tests/scripts/aggregate_0xparc_results.py`
- [ ] `tests/scripts/calculate_fpr.py`
- [ ] `tests/scripts/generate_validation_report.py`

### 3. Reports
- [ ] `reports/validation/0xparc_summary.md` - Detection rates per bug
- [ ] `reports/validation/false_positive_report.md` - FPR breakdown
- [ ] `reports/validation/ground_truth_report.md` - Precision/recall
- [ ] `reports/validation/cve_detection_report.md` - CVE results
- [ ] `docs/VALIDATION_RESULTS.md` - Consolidated report

### 4. Documentation Updates
- [ ] README.md - Add validation results section
- [ ] CHANGELOG.md - Document validation milestone
- [ ] ARCHITECTURE.md - Reference validation methodology

---

## Success Criteria

### Minimum Viable Results
- ✅ 0xPARC detection rate: ≥80%
- ✅ False positive rate: ≤15%
- ✅ CVE detection rate: ≥80%
- ✅ Ground truth precision: ≥85%

### Target Results (README Claims)
- 🎯 0xPARC detection rate: ≥90%
- 🎯 False positive rate: <10%
- 🎯 CVE detection rate: ≥90%
- 🎯 Ground truth precision: ≥90%

### Stretch Goals
- 🚀 0xPARC detection rate: ≥95%
- 🚀 False positive rate: <5%
- 🚀 CVE detection rate: 100%
- 🚀 Mean time to detection: <3 minutes

---

## Risk Mitigation

### Risk: 0xPARC circuits not extractable
**Mitigation:** Manually implement simplified versions of documented bugs

### Risk: False positive rate too high
**Mitigation:** 
- Tune evidence mode thresholds
- Improve oracle validation
- Add circuit-specific heuristics

### Risk: CVE circuits unavailable
**Mitigation:** Create synthetic reproductions from CVE descriptions

### Risk: Detection rate below target
**Mitigation:**
- Increase fuzzing iterations
- Add attack-specific tuning
- Implement missing attack patterns

---

## Timeline

| Week | Phase | Deliverables |
|------|-------|--------------|
| 1 | Setup | Directory structure, safe circuits, CVE stubs |
| 2 | 0xPARC | Dataset extraction, campaign runs, results |
| 3 | FPR + Ground Truth | Safe circuit runs, ground truth validation |
| 4 | CVE + Publication | CVE tests, consolidated report, README update |

**Total Duration:** 4 weeks

**Effort:** ~40-60 hours (1-1.5 weeks full-time)

---

## Automation

### CI Integration
```yaml
# .github/workflows/validation.yml
name: Validation Tests

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly
  workflow_dispatch:

jobs:
  validation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run CVE suite
        run: cargo test --test cve_validation
      - name: Run ground truth
        run: ./tests/scripts/ground_truth_validation.sh
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: validation-results
          path: reports/validation/
```

### Regression Detection
```rust
// tests/validation_regression.rs
#[test]
fn test_detection_rate_regression() {
    let current_rate = run_cve_suite();
    let baseline_rate = 0.90; // From last validation
    
    assert!(
        current_rate >= baseline_rate - 0.05,
        "Detection rate regressed: {:.1}% < {:.1}%",
        current_rate * 100.0,
        baseline_rate * 100.0
    );
}
```

---

## Publication Format

### README Update
```markdown
## Validation Results

ZkPatternFuzz has been validated against real-world vulnerabilities:

| Metric | Result | Target |
|--------|--------|--------|
| 0xPARC Bug Detection | 92.3% (12/13) | ≥90% |
| CVE Detection Rate | 100% (5/5) | ≥90% |
| False Positive Rate | 7.2% | <10% |
| Ground Truth Precision | 91.4% | ≥90% |

**Confirmed Detections:**
- ✅ Tornado Cash nullifier reuse (CVE-2023-XXXX)
- ✅ Semaphore double-signaling (CVE-2023-YYYY)
- ✅ Dark Forest range check bypass (CVE-2024-ZZZZ)
- ✅ Aztec nullifier collision (CVE-2024-AAAA)
- ✅ Polygon zkEVM boundary bug (CVE-2024-BBBB)

See [VALIDATION_RESULTS.md](docs/VALIDATION_RESULTS.md) for full report.
```

### Academic Paper (Optional)
- Title: "ZkPatternFuzz: Automated Security Testing for Zero-Knowledge Circuits"
- Sections: Methodology, Results, Case Studies, Comparison with Manual Audits
- Venue: IEEE S&P, USENIX Security, or arXiv preprint
