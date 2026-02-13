# ZkPatternFuzz Validation Framework: A Comprehensive Guide

**Version:** 1.0  
**Date:** February 13, 2026  
**Purpose:** Build rigorous, evidence-based validation for ZK circuit fuzzing effectiveness

---

## Executive Summary

This document provides a detailed roadmap for validating ZkPatternFuzz's effectiveness against real-world ZK vulnerabilities. Based on analysis of:

- **110 real vulnerabilities** from zkSecurity's zkBugs dataset
- **Academic benchmarks** (zkFuzz found 66 bugs including 38 zero-days in 354 circuits)
- **Industry validation approaches** (Picus, Circomspect, Veridise)
- **0xPARC bug tracker** community dataset

**Key Finding:** The current validation plan is structurally sound but **critically incomplete**. The CVE regression tests return `passed: true` unconditionally, and no real validation has been performed.

---

## Part 1: Real-World Vulnerability Datasets

### 1.1 zkSecurity zkBugs Dataset (PRIMARY SOURCE)

**Repository:** https://github.com/zksecurity/zkbugs  
**Website:** https://bugs.zksecurity.xyz/  
**License:** MIT  
**Bugs:** 110 reproducible vulnerabilities

#### Dataset Breakdown by DSL

| DSL | Count | Severity Distribution |
|-----|-------|----------------------|
| Circom | 41 | Critical: 18, High: 15, Medium: 8 |
| Halo2 | 35 | Critical: 12, High: 14, Medium: 9 |
| Cairo | 8 | Critical: 3, High: 3, Medium: 2 |
| Bellperson | 7 | Critical: 4, High: 2, Medium: 1 |
| Arkworks | 5 | Critical: 2, High: 2, Medium: 1 |
| PIL | 2 | Critical: 1, High: 1 |
| Gnark | 1 | Critical: 1 |
| Plonky3 | 8 | Critical: 3, High: 3, Medium: 2 |
| Risc0 | 3 | Critical: 2, High: 1 |

#### Vulnerability Categories

| Category | Count | % of Total | Detection Difficulty |
|----------|-------|------------|---------------------|
| Under-Constrained | 67 | 60.9% | Medium |
| Over-Constrained | 15 | 13.6% | Hard |
| Soundness | 42 | 38.2% | Medium-Hard |
| Assigned but Unconstrained | 12 | 10.9% | Easy |
| Wrong Translation | 23 | 20.9% | Hard |
| Missing Constraint | 31 | 28.2% | Medium |

#### Key Vulnerabilities to Prioritize

**Critical - Must Detect:**

1. **iden3/circomlib - MIMC Hash Assigned But Not Constrained**
   - Type: Assigned but Unconstrained
   - Impact: Soundness failure
   - Location: `mimc.circom`
   - Reproducible: Yes
   - Commands: `./zkbugs_exploit.sh`

2. **reclaimprotocol/circom-chacha20 - Unsound Left Rotation**
   - Type: Under-Constrained
   - Impact: Soundness
   - Root Cause: Wrong translation of logic into constraints
   - Line: 39-45
   - Reproducible: Yes

3. **lurk-lab/lurk-rs - Multiple Under-Constrained Outputs**
   - Type: Under-Constrained
   - Impact: Soundness
   - Root Cause: Wrong translation
   - Count: 4 related bugs

4. **0xPARC StealthDrop - Nondeterministic Nullifier**
   - Type: Under-Constrained / Nondeterministic
   - Impact: Double-spending
   - Root Cause: ECDSA signatures used as nullifier (malleable)

### 1.2 0xPARC ZK Bug Tracker

**Repository:** https://github.com/0xPARC/zk-bug-tracker  
**Stars:** 713  
**Status:** Community-maintained

#### Notable Bugs from Tracker

| Bug | Project | Type | Status |
|-----|---------|------|--------|
| Tornado Cash Nullifier Reuse | Tornado Cash | Underconstrained | Fixed |
| Semaphore Double-Signaling | Semaphore | Underconstrained | Fixed |
| Dark Forest Range Check | Dark Forest | Arithmetic | Fixed |
| Aztec Nullifier Collision | Aztec | Collision | Fixed |
| Iden3 Authentication Bypass | Iden3 | Soundness | Fixed |
| zkSync State Transition | zkSync | Differential | Fixed |
| Polygon zkEVM Boundary | Polygon | Boundary | Fixed |

### 1.3 Academic Datasets

#### SoK Paper Dataset (USENIX Security 2024)

**Paper:** "SoK: What Don't We Know? Understanding Security Vulnerabilities in SNARKs"  
**Authors:** Stefanos Chaliasos et al.  
**Dataset:** https://docs.google.com/spreadsheets/d/1E97ulMufitGSKo_Dy09KYGv-aBcLPXtlN5QUpwyv66A/

**Key Statistics:**
- 95% of documented vulnerabilities arise from underconstrained programs
- Most common bug class: Missing constraints (38%)
- Second most common: Wrong constraint translation (27%)

#### zkFuzz Evaluation Dataset (IEEE S&P 2026)

**Paper:** "zkFuzz: Foundation and Framework for Effective Fuzzing of Zero-Knowledge Circuits"  
**Authors:** Takahashi et al., Columbia University  
**Results:**
- **354 real-world circuits** tested
- **66 bugs found** (including 38 zero-days)
- **18 confirmed by developers**
- **6 fixed**
- **11 under-constrained bugs in zk-regex alone**
- **30-300% more bugs** than prior tools
- **Zero false positives**

**Target Projects:**
- zk-regex (zkEmail)
- Circomlib
- Various production ZK circuits

---

## Part 2: Validation Methodology

### 2.1 Industry-Standard Validation Approaches

#### Approach A: zkFuzz (Columbia University)

**Methodology:**
1. **Trace-Constraint Consistency Test (TCCT)** - Formal foundation
2. **Joint input and program mutation**
3. **Evolutionary fuzzing with min-sum fitness function**
4. **354 circuit benchmark**
5. **Zero-day discovery as validation**

**Key Innovation:**
- Detects BOTH under-constrained AND over-constrained bugs
- Mutates witness computation to find inconsistencies
- No false positives (mathematically verified)

**Validation Claims:**
- "30-300% more bugs than prior tools"
- "Found 66 bugs including 38 zero-days"
- "Zero false positives"

#### Approach B: Picus (Veridise)

**Methodology:**
1. **Automated formal verification**
2. **Underconstrained circuit detection**
3. **SMT solver with circuit-specific optimizations**
4. **Determinism verification**

**Validation:**
- Used by RISC Zero for zkVM verification
- Integrated into CI/CD pipelines
- Claims "provable assurance"

**Limitations:**
- Scalability issues with large circuits
- Timeout on complex production circuits

#### Approach C: Circomspect (Trail of Bits)

**Methodology:**
1. **Static analysis with linter capabilities**
2. **Pattern-based detection**
3. **9 analysis passes** (now 14+)
4. **Integration with Sindri CLI**

**Validation:**
- Real bugs found in production (Tornado Cash 2019)
- Industry adoption
- No formal detection rate metrics published

#### Approach D: Circuzz (TU Munich)

**Methodology:**
1. **Metamorphic testing**
2. **Circuit transformation oracles**
3. **Semantics-preserving mutations**
4. **Cross-pipeline differential testing**

**Results:**
- **16 logic bugs found** across 4 ZK pipelines
- **15 already fixed by developers**
- **3 soundness bugs**
- **7 completeness bugs**
- **6 transformation bugs**

**Targets:**
- Circom
- Corset
- Gnark
- Noir

### 2.2 Recommended Validation Framework for ZkPatternFuzz

Based on analysis of successful approaches, we recommend a **hybrid validation framework**:

#### Phase 1: Ground Truth Suite (Week 1-2)

**Objective:** Establish baseline detection capability on known vulnerabilities

**Sources:**
1. zkSecurity zkBugs (subset of 20-30 bugs)
2. 0xPARC tracker (all 7 major bugs)
3. Synthetic bugs for edge cases

**Structure:**
```
tests/validation/ground_truth/
├── vulnerable/
│   ├── circom/
│   │   ├── mimc_unconstrained/      # From zkBugs
│   │   ├── chacha20_rotation/       # From zkBugs
│   │   └── tornado_nullifier/       # From 0xPARC
│   ├── halo2/
│   │   └── [5-10 vulnerabilities]
│   └── metadata.json                # Expected findings
└── safe/
    ├── circom/
    │   └── [5 properly constrained circuits]
    └── metadata.json
```

**Metrics:**
- **True Positive Rate (TPR):** detected / total_vulnerable
- **False Negative Rate (FNR):** missed / total_vulnerable
- **False Positive Rate (FPR):** false_alarms / total_safe
- **Precision:** true_positives / total_findings
- **Recall:** true_positives / (true_positives + false_negatives)
- **F1 Score:** 2 * (precision * recall) / (precision + recall)

**Target Thresholds:**
| Metric | Minimum | Target | Stretch |
|--------|---------|--------|---------|
| TPR | 80% | 90% | 95% |
| FNR | <20% | <10% | <5% |
| FPR | <15% | <10% | <5% |
| Precision | 85% | 90% | 95% |
| Recall | 80% | 90% | 95% |
| F1 Score | 0.82 | 0.90 | 0.95 |

#### Phase 2: zkBugs Integration (Week 3-4)

**Objective:** Test against 110 real, reproducible vulnerabilities

**Implementation:**
```bash
# Clone zkBugs dataset
git clone https://github.com/zksecurity/zkbugs.git tests/datasets/zkbugs

# Create integration harness
for bug in tests/datasets/zkbugs/dataset/*/*/*; do
    # Parse config.json
    # Extract circuit path, vulnerability type
    # Run ZkPatternFuzz
    # Compare findings to expected
done
```

**Expected Results by DSL:**

| DSL | Bugs | Minimum Detected | Target | Stretch |
|-----|------|-----------------|--------|---------|
| Circom | 41 | 33 (80%) | 37 (90%) | 39 (95%) |
| Halo2 | 35 | 28 (80%) | 32 (91%) | 33 (94%) |
| Cairo | 8 | 6 (75%) | 7 (88%) | 8 (100%) |
| Others | 26 | 20 (77%) | 23 (88%) | 24 (92%) |
| **Total** | **110** | **87 (79%)** | **99 (90%)** | **104 (95%)** |

#### Phase 3: Cross-Tool Comparison (Week 5)

**Objective:** Compare detection rates with other tools

**Tools to Compare:**
1. zkFuzz (Columbia) - Academic benchmark
2. Picus (Veridise) - Formal verification
3. Circomspect (Trail of Bits) - Static analysis
4. Circuzz (TU Munich) - Metamorphic testing

**Methodology:**
1. Select 20 common circuits
2. Run all tools
3. Measure:
   - Detection rate per tool
   - Overlap in findings (agreement)
   - Unique findings per tool
   - Execution time
   - False positive rate

**Success Criteria:**
- ZkPatternFuzz should match or exceed zkFuzz detection rate
- FPR should be competitive with Picus (<5%)
- Execution time should be reasonable (<10x slower than static analysis)

#### Phase 4: Real-World Bug Bounty Validation (Ongoing)

**Objective:** Find new bugs in production to prove effectiveness

**Target Projects:**
1. zkEmail (zk-regex components)
2. New Circom projects
3. ZK identity protocols
4. ZK voting systems

**Success Metrics:**
- **6-month target:** 3 confirmed bugs
- **12-month target:** 10 confirmed bugs
- **Bug bounty earnings:** $25K+

---

## Part 3: Critical Fixes Required

### 3.1 Fix CVE Regression Tests (CRITICAL)

**Current State:**
```rust
// src/cve/mod.rs:286
pub fn run(&self) -> RegressionTestResult {
    // ... placeholder implementation
    RegressionTestResult {
        cve_id: self.cve_id.clone(),
        passed: true,  // ❌ ALWAYS PASSES
        test_results: vec![],
        execution_time_ms: 0,
    }
}
```

**Required Fix:**
```rust
pub fn run(&self) -> RegressionTestResult {
    let circuit_path = Path::new(&self.circuit_path);
    
    // 1. Verify circuit exists
    if !circuit_path.exists() {
        return RegressionTestResult {
            cve_id: self.cve_id.clone(),
            passed: false,
            error: Some(format!("Circuit not found: {}", self.circuit_path)),
            test_results: vec![],
            execution_time_ms: 0,
        };
    }
    
    // 2. Execute circuit with test cases
    let mut test_results = Vec::new();
    let mut all_passed = true;
    
    for test_case in &self.test_cases {
        let start = Instant::now();
        let result = self.execute_test_case(test_case);
        let elapsed = start.elapsed().as_millis() as u64;
        
        // 3. Verify finding matches expected
        let passed = self.validate_finding(&result, test_case);
        
        test_results.push(TestCaseResult {
            name: test_case.name.clone(),
            passed,
            execution_time_ms: elapsed,
            finding: result.finding,
            error: result.error,
        });
        
        if !passed {
            all_passed = false;
        }
    }
    
    RegressionTestResult {
        cve_id: self.cve_id.clone(),
        passed: all_passed,
        error: None,
        test_results,
        execution_time_ms: test_results.iter().map(|t| t.execution_time_ms).sum(),
    }
}
```

### 3.2 Implement Real Evidence Mode

**Current Issue:** Evidence mode claims strict backend verification but lacks proof-of-concept generation.

**Required:**
1. Generate concrete witnesses for all findings
2. Create reproducible PoC bundles
3. Cryptographic proof generation where applicable
4. Invariant violation demonstration

### 3.3 Fix Attack Implementations

From `docs/ROADMAP.md`:

**High Priority Fixes:**
1. `unused_signal_analysis()` - returns empty vectors instead of findings
2. `weak_constraint_analysis()` - heuristic-only, no execution
3. `SoundnessTester.run()` - only checks DOF ratio, doesn't attempt actual proof forgery
4. `CollisionDetector.run()` - doesn't wire into engine pipeline
5. `BoundaryTester.run()` - doesn't actually execute circuits

**Success Criteria:**
All attacks must:
- Execute circuits through real backends
- Generate concrete witnesses
- Produce verifiable evidence
- Not rely solely on static heuristics

---

## Part 4: Detailed Implementation Guide

### 4.1 Ground Truth Circuit Catalog

We recommend implementing these 15 circuits as ground truth:

#### Category 1: Underconstrained (5 circuits)

**1. Merkle Path Index Unconstrained**
```circom
// Vulnerable: path indices not binary constrained
template MerkleTreeInsecure(levels) {
    signal input leaf;
    signal input pathIndices[levels];  // ❌ Not constrained to {0,1}
    signal input pathElements[levels];
    signal output root;
    
    // ...
}
```

**2. MIMC Assigned But Not Constrained**
```circom
// Vulnerable: signal assigned with <-- not constrained
template MiMCInsecure() {
    signal input x;
    signal output y;
    
    y <-- x^7 + x^3 + x;  // ❌ No constraint enforcing this
}
```

**3. Rotation Gadget Underconstrained**
```circom
// Vulnerable: rotation parts not bit-constrained
template RotateLeft32Insecure(bits) {
    signal input in;
    signal output out;
    signal part1;
    signal part2;
    
    part1 <-- in >> (32 - bits);  // ❌ Unconstrained
    part2 <-- in << bits;          // ❌ Unconstrained
    out <== part1 + part2;
}
```

**4. Nullifier Collision**
```circom
// Vulnerable: weak nullifier computation
template NullifierInsecure() {
    signal input secret;
    signal input nonce;
    signal output nullifier;
    
    nullifier <== secret + nonce;  // ❌ Not binding, collisions possible
}
```

**5. Range Check Bypass**
```circom
// Vulnerable: range check on wrong value
template RangeCheckInsecure(n) {
    signal input value;
    signal output inRange;
    
    component lt = LessThan(n);
    lt.in[0] <== value;
    lt.in[1] <== 2**n;
    
    inRange <== lt.out;
    // ❌ 'value' itself is never constrained
}
```

#### Category 2: Soundness (3 circuits)

**6. EdDSA Signature Malleability**
```circom
// Vulnerable: S component not range-checked
template EdDSAVerifyInsecure() {
    signal input S;
    signal input R[2];
    signal input A[2];
    signal input msg;
    
    // ❌ Missing: S < L (curve order)
    // Allows signature malleability
}
```

**7. Division by Zero**
```circom
// Vulnerable: no zero check on divisor
template DivisionInsecure() {
    signal input dividend;
    signal input divisor;
    signal output quotient;
    
    quotient <-- dividend / divisor;
    quotient * divisor === dividend;  // ❌ Satisfied when divisor=0, quotient=any
}
```

**8. Non-Binary Bit Extraction**
```circom
// Vulnerable: bit not constrained to {0,1}
template BitExtractInsecure() {
    signal input value;
    signal output bit;
    
    bit <-- value & 1;  // ❌ No constraint that bit ∈ {0,1}
}
```

#### Category 3: Arithmetic (3 circuits)

**9. Field Overflow**
```circom
// Vulnerable: overflow in field operations
template OverflowInsecure() {
    signal input a;
    signal input b;
    signal output c;
    
    c <== a + b;  // ❌ No range check, can overflow field
}
```

**10. Phantom Overflow**
```circom
// Vulnerable: intermediate overflow
template PhantomOverflow() {
    signal input a;
    signal input b;
    signal input c;
    signal output d;
    
    d <== (a * b) * c;  // ❌ a*b can overflow before final result
}
```

**11. Negative Input Handling**
```circom
// Vulnerable: negative inputs wrap around
template NegativeInsecure() {
    signal input x;
    signal output y;
    
    y <== x * x;  // ❌ Negative x wraps to large positive
}
```

#### Category 4: Safe Circuits (4 circuits)

**12. Proper Merkle Tree**
```circom
// Safe: all indices binary constrained
template MerkleTreeSecure(levels) {
    signal input leaf;
    signal input pathIndices[levels];
    signal input pathElements[levels];
    signal output root;
    
    // ✅ Constrain indices to binary
    for (var i = 0; i < levels; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;
    }
    // ...
}
```

**13. Proper Range Check**
```circom
// Safe: value properly constrained
template RangeCheckSecure(n) {
    signal input value;
    signal output inRange;
    
    // ✅ Constrain value to n bits
    component bits = Num2Bits(n);
    bits.in <== value;
    
    component lt = LessThan(n);
    lt.in[0] <== value;
    lt.in[1] <== 2**n;
    inRange <== lt.out;
}
```

**14. Proper Nullifier**
```circom
// Safe: collision-resistant nullifier
template NullifierSecure() {
    signal input secret;
    signal input nonce;
    signal output nullifier;
    
    // ✅ Use Poseidon hash
    component hash = Poseidon(2);
    hash.inputs[0] <== secret;
    hash.inputs[1] <== nonce;
    nullifier <== hash.out;
}
```

**15. Proper Division**
```circom
// Safe: divisor checked for zero
template DivisionSecure() {
    signal input dividend;
    signal input divisor;
    signal output quotient;
    signal output isZero;
    
    // ✅ Check divisor is not zero
    isZero <== IsZero()(divisor);
    isZero === 0;  // Enforce non-zero
    
    quotient <-- dividend / divisor;
    quotient * divisor === dividend;
}
```

### 4.2 Test Harness Implementation

```rust
// tests/validation_harness.rs

use std::path::Path;
use zk_fuzzer::{FuzzerConfig, ValidationResult};

pub struct GroundTruthTest {
    pub circuit_path: String,
    pub expected_attack: AttackType,
    pub expected_severity: Severity,
    pub timeout_seconds: u64,
}

impl GroundTruthTest {
    pub fn run(&self) -> ValidationResult {
        let config = FuzzerConfig::new(&self.circuit_path)
            .with_evidence_mode(true)
            .with_timeout(self.timeout_seconds);
        
        let findings = run_fuzzer(config);
        
        // Check if expected finding was detected
        let detected = findings.iter().any(|f| {
            f.attack_type == self.expected_attack &&
            f.severity == self.expected_severity
        });
        
        ValidationResult {
            circuit: self.circuit_path.clone(),
            expected_attack: self.expected_attack,
            detected,
            findings,
            execution_time_ms: 0,
        }
    }
}

#[test]
fn test_ground_truth_suite() {
    let tests = vec![
        GroundTruthTest {
            circuit_path: "tests/ground_truth/vulnerable/merkle_insecure.circom".to_string(),
            expected_attack: AttackType::Underconstrained,
            expected_severity: Severity::Critical,
            timeout_seconds: 300,
        },
        // ... more tests
    ];
    
    let mut passed = 0;
    let mut failed = 0;
    
    for test in tests {
        let result = test.run();
        if result.detected {
            passed += 1;
            println!("✓ {}", result.circuit);
        } else {
            failed += 1;
            println!("✗ {} - Expected {:?}", 
                result.circuit, result.expected_attack);
        }
    }
    
    let detection_rate = passed as f64 / (passed + failed) as f64;
    println!("\nDetection Rate: {:.1}%", detection_rate * 100.0);
    
    assert!(detection_rate >= 0.90, 
        "Detection rate {:.1}% below 90% threshold", 
        detection_rate * 100.0);
}
```

### 4.3 zkBugs Integration Script

```python
#!/usr/bin/env python3
# scripts/validate_zkbugs.py

import json
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class BugResult:
    bug_id: str
    dsl: str
    project: str
    vulnerability: str
    detected: bool
    execution_time_ms: int
    findings: List[dict]
    error: Optional[str] = None

def load_bug_config(bug_path: Path) -> dict:
    """Load bug configuration from JSON."""
    config_path = bug_path / "config.json"
    with open(config_path) as f:
        return json.load(f)

def run_zkpatternfuzz(circuit_path: Path, bug_config: dict) -> BugResult:
    """Run ZkPatternFuzz against a bug circuit."""
    
    # Build campaign config
    campaign = {
        "campaign": {
            "name": f"zkBugs: {bug_config['Id']}",
            "target": {
                "framework": bug_config["DSL"].lower(),
                "circuit_path": str(circuit_path)
            },
            "parameters": {
                "additional": {
                    "evidence_mode": True,
                    "strict_backend": True
                }
            }
        },
        "attacks": get_attacks_for_vulnerability(bug_config["Vulnerability"])
    }
    
    # Write campaign
    campaign_path = Path("/tmp/campaign.yaml")
    with open(campaign_path, 'w') as f:
        yaml.dump(campaign, f)
    
    # Run fuzzer
    result = subprocess.run(
        ["cargo", "run", "--release", "--", 
         "--config", str(campaign_path),
         "--output", "/tmp/result.json"],
        capture_output=True,
        text=True,
        timeout=600
    )
    
    if result.returncode != 0:
        return BugResult(
            bug_id=bug_config["Id"],
            dsl=bug_config["DSL"],
            project=bug_config["Project"],
            vulnerability=bug_config["Vulnerability"],
            detected=False,
            execution_time_ms=0,
            findings=[],
            error=result.stderr
        )
    
    # Parse results
    with open("/tmp/result.json") as f:
        findings = json.load(f)
    
    # Check if expected vulnerability was detected
    detected = any(
        f["attack_type"] == bug_config["Vulnerability"]
        for f in findings
    )
    
    return BugResult(
        bug_id=bug_config["Id"],
        dsl=bug_config["DSL"],
        project=bug_config["Project"],
        vulnerability=bug_config["Vulnerability"],
        detected=detected,
        execution_time_ms=0,
        findings=findings
    )

def get_attacks_for_vulnerability(vuln_type: str) -> List[dict]:
    """Map vulnerability type to attack configurations."""
    mapping = {
        "Under-Constrained": [
            {"type": "underconstrained", "config": {"witness_pairs": 5000}},
        ],
        "Over-Constrained": [
            {"type": "soundness"},
        ],
        "Soundness": [
            {"type": "soundness"},
            {"type": "underconstrained"},
        ],
        # ... more mappings
    }
    return mapping.get(vuln_type, [{"type": "underconstrained"}])

def main():
    """Run validation against zkBugs dataset."""
    zkbugs_path = Path("tests/datasets/zkbugs/dataset")
    
    results = []
    
    # Iterate over all bugs
    for dsl_dir in zkbugs_path.iterdir():
        if not dsl_dir.is_dir():
            continue
            
        for project_dir in dsl_dir.iterdir():
            if not project_dir.is_dir():
                continue
                
            for repo_dir in project_dir.iterdir():
                if not repo_dir.is_dir():
                    continue
                    
                for bug_dir in repo_dir.iterdir():
                    if not bug_dir.is_dir():
                        continue
                    
                    print(f"Testing: {bug_dir.name}")
                    
                    try:
                        config = load_bug_config(bug_dir)
                        result = run_zkpatternfuzz(bug_dir, config)
                        results.append(result)
                        
                        status = "✓" if result.detected else "✗"
                        print(f"  {status} {config['Vulnerability']}")
                        
                    except Exception as e:
                        print(f"  ✗ Error: {e}")
    
    # Generate report
    generate_report(results)

def generate_report(results: List[BugResult]):
    """Generate validation report."""
    
    total = len(results)
    detected = sum(1 for r in results if r.detected)
    detection_rate = detected / total if total > 0 else 0
    
    # Break down by DSL
    by_dsl = {}
    for r in results:
        if r.dsl not in by_dsl:
            by_dsl[r.dsl] = {"total": 0, "detected": 0}
        by_dsl[r.dsl]["total"] += 1
        if r.detected:
            by_dsl[r.dsl]["detected"] += 1
    
    # Break down by vulnerability type
    by_vuln = {}
    for r in results:
        if r.vulnerability not in by_vuln:
            by_vuln[r.vulnerability] = {"total": 0, "detected": 0}
        by_vuln[r.vulnerability]["total"] += 1
        if r.detected:
            by_vuln[r.vulnerability]["detected"] += 1
    
    report = f"""
# ZkPatternFuzz zkBugs Validation Report

Generated: {datetime.now().isoformat()}

## Summary

| Metric | Value |
|--------|-------|
| Total Bugs Tested | {total} |
| Detected | {detected} |
| Detection Rate | {detection_rate*100:.1f}% |

## By DSL

| DSL | Total | Detected | Rate |
|-----|-------|----------|------|
"""
    
    for dsl, stats in sorted(by_dsl.items()):
        rate = stats["detected"] / stats["total"] * 100
        report += f"| {dsl} | {stats['total']} | {stats['detected']} | {rate:.1f}% |\n"
    
    report += "\n## By Vulnerability Type\n\n| Type | Total | Detected | Rate |\n|------|-------|----------|------|\n"
    
    for vuln, stats in sorted(by_vuln.items()):
        rate = stats["detected"] / stats["total"] * 100
        report += f"| {vuln} | {stats['total']} | {stats['detected']} | {rate:.1f}% |\n"
    
    report += "\n## Detailed Results\n\n"
    
    for r in results:
        status = "✓" if r.detected else "✗"
        report += f"{status} [{r.dsl}] {r.bug_id}: {r.vulnerability}\n"
        if r.error:
            report += f"  Error: {r.error}\n"
    
    # Write report
    report_path = Path("reports/validation/zkbugs_report.md")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, 'w') as f:
        f.write(report)
    
    print(f"\nReport written to: {report_path}")
    print(f"Overall Detection Rate: {detection_rate*100:.1f}%")

if __name__ == "__main__":
    main()
```

---

## Part 5: Success Metrics & Benchmarks

### 5.1 Minimum Viable Product (MVP)

**Must achieve before claiming "validated":**

| Metric | Minimum | Evidence Required |
|--------|---------|-------------------|
| Ground Truth Detection | ≥80% | 12/15 test circuits |
| zkBugs Detection | ≥75% | 83/110 real bugs |
| False Positive Rate | ≤15% | <15% on 20 safe circuits |
| CVE Tests | 100% passing | All 5 CVE test cases execute and validate |
| Evidence Mode | Functional | All findings include witness + PoC |

### 5.2 Competitive Benchmark

**Must match or exceed:**

| Tool | Detection Rate | FPR | Notes |
|------|----------------|-----|-------|
| zkFuzz | 18.7% (66/354) | 0% | Found 38 zero-days |
| Circuzz | N/A | N/A | 16 bugs in pipelines |
| Picus | High | Very Low | Formal verification |
| **ZkPatternFuzz Target** | **≥25%** | **<10%** | **Goal: Find 10+ new bugs** |

### 5.3 Industry Acceptance

**Signals of real-world effectiveness:**

1. **Bug Bounty Confirmations:**
   - 3 confirmed bugs in 6 months
   - $10K+ in bounty payouts

2. **Audit Firm Adoption:**
   - Used by 2+ audit firms
   - Referenced in audit reports

3. **Academic Citation:**
   - Cited in 2+ peer-reviewed papers
   - Compared favorably to other tools

4. **Production Integration:**
   - Used by 3+ production ZK projects
   - CI/CD integration examples

---

## Part 6: Timeline & Milestones

### Week 1-2: Foundation

**Deliverables:**
- [ ] Fix CVE regression tests (stop returning `passed: true`)
- [ ] Implement 15 ground truth circuits
- [ ] Create validation harness
- [ ] Set up CI/CD for validation

**Success Criteria:**
- All CVE tests actually execute
- Ground truth circuits compile
- Validation harness runs end-to-end

### Week 3-4: zkBugs Integration

**Deliverables:**
- [ ] Integrate 110 zkBugs vulnerabilities
- [ ] Achieve 75%+ detection rate
- [ ] Generate detailed report
- [ ] Fix any gaps in attack implementations

**Success Criteria:**
- 83+ bugs detected
- Report published
- All attack types validated

### Week 5-6: False Positive Optimization

**Deliverables:**
- [ ] Create 20 safe circuits
- [ ] Measure FPR
- [ ] Tune evidence mode thresholds
- [ ] Optimize for FPR < 10%

**Success Criteria:**
- FPR measured and documented
- Tuning guidelines established
- Confidence scoring validated

### Week 7-8: Documentation & Publication

**Deliverables:**
- [ ] Complete VALIDATION_RESULTS.md
- [ ] Update README with real metrics
- [ ] Publish comparison with other tools
- [ ] Submit to conferences (optional)

**Success Criteria:**
- All documentation updated
- Real metrics published
- Tool ready for public use

---

## Part 7: Risk Mitigation

### Risk 1: Low Detection Rate

**Mitigation:**
- Start with known-bug corpus
- Debug each missed bug individually
- Add attack patterns as needed
- Consider hybrid approach (static + dynamic)

### Risk 2: High False Positive Rate

**Mitigation:**
- Implement strict evidence mode
- Require multiple oracles to agree
- Add circuit-specific heuristics
- Allow user-configurable thresholds

### Risk 3: Scalability Issues

**Mitigation:**
- Test on circuits of various sizes
- Implement timeout handling
- Add progress reporting
- Support parallel execution

### Risk 4: Tool Comparison Unfavorable

**Mitigation:**
- Focus on unique capabilities
- Highlight multi-backend support
- Emphasize evidence generation
- Target specific use cases

---

## Part 8: Conclusion

ZkPatternFuzz has a **solid architectural foundation** but **lacks validation**. This document provides:

1. **Real vulnerability datasets** (110 bugs from zkBugs)
2. **Ground truth circuits** (15 circuits to implement)
3. **Validation methodology** (based on successful tools)
4. **Implementation scripts** (Python/Rust harness)
5. **Success metrics** (80% detection, <15% FPR)
6. **Timeline** (8 weeks to validation)

**Next Steps:**
1. Fix CVE regression tests immediately
2. Implement ground truth circuits
3. Run against zkBugs dataset
4. Measure and publish real metrics

**Remember:** A tool without validation is just a prototype. The goal is **evidence-based credibility**.

---

## Appendix A: References

### Papers
1. "zkFuzz: Foundation and Framework for Effective Fuzzing of Zero-Knowledge Circuits" (IEEE S&P 2026)
2. "SoK: What Don't We Know? Understanding Security Vulnerabilities in SNARKs" (USENIX Security 2024)
3. "Automated Detection of Under-Constrained Circuits in Zero-Knowledge Proofs" (PLDI 2023)
4. "Fuzzing Processing Pipelines for Zero-Knowledge Circuits" (CCS 2025)

### Tools
1. zkBugs: https://github.com/zksecurity/zkbugs
2. 0xPARC Bug Tracker: https://github.com/0xPARC/zk-bug-tracker
3. Picus: https://veridise.com/security/tools/zk-tool/
4. Circomspect: https://github.com/trailofbits/circomspect
5. Circuzz: https://github.com/Rigorous-Software-Engineering/circuzz

### Datasets
1. zkBugs Dataset: 110 vulnerabilities
2. SoK Dataset: Comprehensive vulnerability database
3. 0xPARC Tracker: Community-maintained bugs

---

## Appendix B: Vulnerability Taxonomy

Based on analysis of 110 real bugs:

| Category | % | Description | Detection Approach |
|----------|---|-------------|-------------------|
| Under-Constrained | 60.9% | Multiple witnesses accepted | Witness collision oracle |
| Assigned but Unconstrained | 10.9% | Signal assigned, not constrained | Constraint analysis |
| Wrong Translation | 20.9% | Logic-constraint mismatch | Differential testing |
| Missing Constraint | 28.2% | Constraint omitted | Static analysis + fuzzing |
| Over-Constrained | 13.6% | Valid witnesses rejected | Soundness testing |

---

*Document prepared for ZkPatternFuzz validation initiative.*
*Last updated: February 13, 2026*
