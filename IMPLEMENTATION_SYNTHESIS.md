# ZkPatternFuzz Implementation Synthesis Plan

**Status**: 75% Complete (Updated 2026-02-06)  
**Target**: Industry-leading ZK vulnerability discovery (9.9/10)  
**Timeline**: 12-16 weeks  
**Effort**: 1.5 FTE

## Executive Summary

This synthesis consolidates 5 roadmap documents into a unified implementation plan. ZkPatternFuzz has a strong foundation (CVE database, semantic oracles, grammar DSL, R1CS parser, SMT translation) but needs critical enhancements to find 0-day vulnerabilities in production circuits.

### Current State Analysis

**Strengths (Completed)**:
- ✅ R1CS binary parser (695 LOC)
- ✅ SMT translation engine (313 LOC)
- ✅ 4 semantic oracles (Nullifier, Merkle, Range, Commitment)
- ✅ CVE database with 9 documented vulnerabilities
- ✅ 21 regression tests + 219 library tests = 240 tests passing
- ✅ Grammar-based input generation (3 standard grammars)
- ✅ Finding deduplication and confidence scoring
- ✅ Compiled .r1cs files available for testing

**Critical Gaps**:
- ⚠️ No constraint inference engine (finds missing constraints)
- ⚠️ No ML-based knowledge transfer across circuits
- ⚠️ No automatic exploit generation
- ⚠️ Limited real-circuit validation
- ⚠️ No continuous fuzzing infrastructure
- ⚠️ Git submodules not initialized

---

## Phase 0: Foundation Hardening (Week 0-1)

**Goal**: Eliminate mock fallbacks and establish reproducible baseline

### Task 0.1: Strict Real-Backend Enforcement
**Priority**: CRITICAL  
**Effort**: 2 days

- Add `--no-mock-fallback` flag to CLI
- Fail fast if real backends unavailable
- Update error messages to guide toolchain installation

**Files**:
- `src/main.rs`: Add CLI flag
- `src/targets/backend.rs`: Add validation mode
- `src/executor/mod.rs`: Check backend availability

### Task 0.2: Benchmark Circuit Set
**Priority**: HIGH  
**Effort**: 3 days

- Define 5 canonical benchmark circuits with expected properties
- Document pass/fail criteria for each
- Pin toolchain versions (Circom 2.1.x, Noir 0.x, etc.)
- Initialize git submodules: `tornado-core`, `semaphore`, `iden3-auth`

**Files**:
- `tests/benchmarks/` (NEW): Benchmark definitions
- `BENCHMARK_SPEC.md` (NEW): Documentation
- `.github/workflows/benchmarks.yml`: CI integration

**Exit Criteria**:
- ✅ Validation runs fail if mock backend used
- ✅ 5 benchmark circuits compile and run
- ✅ Git submodules initialized

---

## Phase 1: Constraint-Guided Fuzzing (Week 1-3)

**Goal**: Replace output-hash coverage with constraint-level coverage

### Task 1.1: Populate Real Constraint Coverage
**Priority**: CRITICAL  
**Effort**: 5 days

**Implementation**:

```rust
// src/coverage/constraints.rs
impl ExecutionCoverage {
    pub fn with_constraints(
        execution_result: &ExecutionResult,
        r1cs: &R1CS,
    ) -> Self {
        let mut satisfied = HashSet::new();
        
        for (idx, constraint) in r1cs.constraints.iter().enumerate() {
            if evaluate_constraint(constraint, &execution_result.witness) {
                satisfied.insert(idx);
            }
        }
        
        Self {
            satisfied_constraints: satisfied,
            total_constraints: r1cs.constraints.len(),
            // ... existing fields
        }
    }
}
```

**Files**:
- `src/coverage/constraints.rs`: Implement constraint tracking
- `src/executor/circom.rs`: Populate coverage for Circom
- `src/executor/noir.rs`: Populate coverage for Noir
- `src/reporting/coverage.rs`: Report constraint coverage

### Task 1.2: Constraint-Guided Input Generation (YAML)
**Priority**: HIGH  
**Effort**: 7 days

**YAML Syntax**:

```yaml
campaign:
  name: "SMT-Guided Audit"
  target:
    framework: "circom"
    circuit_path: "./circuit.circom"
  
  constraint_analysis:
    enabled: true
    r1cs_path: "./build/circuit.r1cs"
    sym_path: "./build/circuit.sym"
    solver_timeout_ms: 5000

inputs:
  - name: "secret"
    type: "field"
    fuzz_strategy: "constraint_guided"
    constraint_guided:
      target_signals: ["main.secret", "main.nullifier"]
      coverage_target: "maximize"
      solutions_per_path: 5
      solver: "z3"
```

**Files**:
- `src/config/mod.rs`: Add `ConstraintAnalysisConfig`
- `src/fuzzer/constraint_guided_gen.rs` (NEW): SMT-based generator
- `src/fuzzer/engine.rs`: Integrate with fuzzing loop

**Exit Criteria**:
- ✅ Coverage reports show constraint hits (not just output hashes)
- ✅ SMT-guided fuzzing covers 30%+ more constraints than random
- ✅ YAML campaigns support `fuzz_strategy: "constraint_guided"`

---

## Phase 2: Breakthrough Innovation - Constraint Inversion (Week 3-6)

**Goal**: Find bugs in **missing** constraints (not wrong constraints)

### Task 2.1: Constraint Inference Engine
**Priority**: CRITICAL (9.9/10 differentiator)  
**Effort**: 10 days

**Concept**: Automatically infer what constraints *should* exist based on circuit semantics

**Implementation**:

```rust
// src/analysis/constraint_inference.rs (NEW FILE - ~500 LOC)

pub struct ConstraintInferenceEngine {
    r1cs: R1CS,
    wire_names: Vec<String>,
    inference_rules: Vec<Box<dyn InferenceRule>>,
}

pub trait InferenceRule {
    fn infer(&self, r1cs: &R1CS, wire_names: &[String]) -> Vec<ImpliedConstraint>;
}

pub struct ImpliedConstraint {
    pub description: String,
    pub category: ConstraintCategory,
    pub confidence: f64,
}

pub enum ConstraintCategory {
    BitDecompositionRoundTrip,
    MerklePathValidation,
    NullifierUniqueness,
    RangeEnforcement,
    SignatureMalleability,
    InformationLeak,
}

// Inference rules
pub struct BitDecompositionInference;
pub struct MerklePathInference;
pub struct NullifierInference;
pub struct RangeProofInference;
pub struct SignatureMalleabilityInference;
```

**YAML Configuration**:

```yaml
constraint_inversion:
  enabled: true
  
  inference_engines:
    - type: "semantic_equivalence"
      description: "Bit decomposition must round-trip"
    - type: "information_flow"
      description: "Private data needs commitment"
    - type: "algebraic_invariants"
      description: "Mathematical properties must hold"
    - type: "domain_specific"
      description: "ZK protocol patterns"
  
  violation_fuzzing:
    strategy: "systematic"
    max_violations_per_constraint: 100
  
  categories:
    - type: "bit_decomposition"
      enabled: true
      confidence_threshold: 0.7
    - type: "merkle_path"
      enabled: true
      confidence_threshold: 0.8
```

**Files**:
- `src/analysis/constraint_inference.rs` (NEW): Core engine (~500 LOC)
- `src/config/mod.rs`: Add `ConstraintInversionConfig`
- `src/fuzzer/engine.rs`: Integrate inference + violation fuzzing
- `src/reporting/findings.rs`: Report implied constraint violations

**Test Cases**:

```rust
// tests/constraint_inference_tests.rs (NEW)
#[test]
fn test_bit_decomposition_inference() {
    let r1cs = parse_circuit("tests/circuits/missing_recompose.circom");
    let engine = ConstraintInferenceEngine::new(r1cs);
    let implied = engine.infer_all();
    
    assert!(implied.iter().any(|c| 
        c.category == ConstraintCategory::BitDecompositionRoundTrip
    ));
}
```

**Exit Criteria**:
- ✅ Detects missing bit decomposition recomposition checks
- ✅ Detects unbounded Merkle path indices
- ✅ Detects missing nullifier uniqueness constraints
- ✅ Generates test cases that violate implied constraints
- ✅ Confidence scores ≥ 0.7 for true positives

---

## Phase 3: ML-Based Knowledge Transfer (Week 6-9)

**Goal**: Learn from past audits and transfer knowledge across circuits

### Task 3.1: Circuit Embedding Model
**Priority**: HIGH (9.9/10 differentiator)  
**Effort**: 12 days

**Architecture**:
- Graph Neural Network (GNN) to embed R1CS constraint graphs
- Train on past fuzzing campaigns and audit results
- Predict vulnerability likelihood for new circuits
- Prioritize fuzzing budget based on predictions

**Implementation**:

```python
# ml_models/circuit_embedding.py (NEW FILE - ~300 LOC PyTorch)

import torch
import torch.nn as nn
from torch_geometric.nn import GCNConv, global_mean_pool

class CircuitEmbedding(nn.Module):
    def __init__(self):
        super().__init__()
        self.gnn = GCNConv(in_channels=128, out_channels=256, num_layers=6)
        self.attention = nn.MultiheadAttention(embed_dim=256, num_heads=8)
    
    def forward(self, constraint_graph):
        # R1CS → 512-dim embedding
        node_features = self.extract_node_features(constraint_graph)
        edge_index = self.build_edge_index(constraint_graph)
        
        x = self.gnn(node_features, edge_index)
        attended = self.attention(x, x, x)[0]
        
        return global_mean_pool(attended)

class VulnerabilityPredictor(nn.Module):
    def __init__(self):
        super().__init__()
        self.embedding = CircuitEmbedding()
        self.classifier = nn.Sequential(
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, len(VulnerabilityCategory))
        )
    
    def predict_vulnerabilities(self, r1cs):
        embedding = self.embedding(r1cs)
        logits = self.classifier(embedding)
        return torch.softmax(logits, dim=-1)
```

```rust
// src/ml/predictor.rs (NEW FILE - ~200 LOC Rust with pyo3 bindings)

use pyo3::prelude::*;

pub struct MLVulnerabilityPredictor {
    python_model: PyObject,
}

impl MLVulnerabilityPredictor {
    pub fn new(model_path: &str) -> Result<Self> {
        Python::with_gil(|py| {
            let model_module = py.import("circuit_embedding")?;
            let model = model_module.getattr("VulnerabilityPredictor")?.call0()?;
            model.call_method1("load_weights", (model_path,))?;
            Ok(Self { python_model: model.into() })
        })
    }
    
    pub fn predict(&self, r1cs: &R1CS) -> HashMap<VulnerabilityCategory, f64> {
        // Call Python ML model from Rust
    }
}
```

**YAML Configuration**:

```yaml
machine_learning:
  enabled: true
  model_path: "./ml_models/zkfuzz_v1.pth"
  
  guided_fuzzing:
    min_probability_threshold: 0.3
    budget_allocation: "proportional"
  
  online_learning:
    enabled: true
    positive_feedback_weight: 2.0

# Auto-export training data after each campaign
reporting:
  ml_training_export:
    enabled: true
    export_path: "./ml_training_data/"
```

**Files**:
- `ml_models/circuit_embedding.py` (NEW): PyTorch model (~300 LOC)
- `src/ml/predictor.rs` (NEW): Rust-Python bridge (~200 LOC)
- `src/fuzzer/engine.rs`: Integrate ML-guided prioritization
- `requirements.txt` (NEW): Python dependencies (torch, torch-geometric)

**Training Data Collection**:
- Collect circuit embeddings + vulnerabilities from all campaigns
- Train on synthetic bugs initially
- Fine-tune on real audit findings

**Exit Criteria**:
- ✅ Model predicts vulnerability categories with >70% accuracy
- ✅ ML-guided fuzzing finds bugs 30%+ faster than random
- ✅ Model improves over time with online learning

---

## Phase 4: Automatic Exploit Generation (Week 9-11)

**Goal**: Generate actionable, verified exploits for every finding

### Task 4.1: Exploit Synthesis Engine
**Priority**: HIGH  
**Effort**: 8 days

**Concept**: For each vulnerability, automatically generate:
1. Proof-of-concept code (JavaScript/Python)
2. Attack scenario description
3. Economic impact estimate
4. Remediation code diff
5. Verified working exploit

**Implementation**:

```rust
// src/exploit/generator.rs (NEW FILE - ~400 LOC)

pub struct ExploitGenerator {
    circuit_info: CircuitInfo,
    executor: Arc<dyn CircuitExecutor>,
}

impl ExploitGenerator {
    pub fn generate_exploit(&self, finding: &Finding) -> Result<Exploit> {
        let scenario = self.infer_attack_scenario(finding);
        
        // Generate multi-format PoC
        let circom_test = self.generate_circom_test(finding);
        let js_exploit = self.generate_javascript_exploit(finding, &scenario);
        let markdown = self.generate_markdown_writeup(finding, &scenario);
        let remediation = self.generate_remediation(finding);
        
        Ok(Exploit {
            finding: finding.clone(),
            scenario,
            proof_of_concept: ExploitPoC {
                circom_test,
                javascript: js_exploit,
                markdown,
            },
            remediation,
            verified: false,
        })
    }
    
    fn infer_attack_scenario(&self, finding: &Finding) -> AttackScenario {
        // Use circuit name + components to infer realistic attack
        if self.circuit_info.name.contains("tornado") {
            AttackScenario::PrivacyMixer {
                attack: "Double withdrawal",
                impact: "Drain all deposits",
                severity: "Critical",
            }
        } else if self.circuit_info.name.contains("semaphore") {
            AttackScenario::AnonymousVoting {
                attack: "Vote multiple times",
                impact: "Sybil attack",
                severity: "High",
            }
        } else {
            AttackScenario::Generic { /* ... */ }
        }
    }
    
    fn generate_javascript_exploit(&self, finding: &Finding, scenario: &AttackScenario) -> String {
        format!(r#"
// Exploit for: {}
const snarkjs = require("snarkjs");

async function exploit() {{
    const witnessA = {};
    const witnessB = {};
    
    const proofA = await snarkjs.groth16.fullProve(witnessA, "circuit.wasm", "circuit.zkey");
    const proofB = await snarkjs.groth16.fullProve(witnessB, "circuit.wasm", "circuit.zkey");
    
    if (proofA.publicSignals === proofB.publicSignals) {{
        console.log("✓ EXPLOIT SUCCESSFUL");
    }}
}}
"#, finding.description)
    }
}

pub struct ExploitVerifier;

impl ExploitVerifier {
    pub fn verify_exploit(&self, exploit: &mut Exploit) -> Result<bool> {
        // Actually run the generated exploit code
        let output = std::process::Command::new("node")
            .arg("/tmp/exploit.js")
            .output()?;
        
        exploit.verified = String::from_utf8_lossy(&output.stdout)
            .contains("EXPLOIT SUCCESSFUL");
        
        Ok(exploit.verified)
    }
}
```

**YAML Configuration**:

```yaml
exploit_generation:
  enabled: true
  
  generate:
    - "proof_of_concept"
    - "attack_scenario"
    - "economic_impact_estimate"
    - "remediation_diff"
  
  poc_format:
    - "circom_test_case"
    - "javascript_exploit"
    - "python_exploit"
    - "markdown_writeup"
  
  verify_exploit:
    enabled: true
    run_poc: true
    require_success: true
```

**Files**:
- `src/exploit/generator.rs` (NEW): Exploit synthesis (~400 LOC)
- `src/exploit/verifier.rs` (NEW): Verification engine (~100 LOC)
- `src/reporting/exploit.rs` (NEW): Report formatting
- `templates/exploit_template.js` (NEW): JavaScript PoC template

**Exit Criteria**:
- ✅ Every finding includes generated exploit code
- ✅ >90% of exploits verify successfully
- ✅ Exploits include realistic attack scenarios
- ✅ Remediation diffs are actionable

---

## Phase 5: Semantic Oracle Composition (Week 11-12)

**Goal**: Define complex vulnerability patterns in YAML

### Task 5.1: Oracle DSL
**Priority**: MEDIUM  
**Effort**: 5 days

**YAML Syntax**:

```yaml
semantic_oracles:
  - name: "merkle_soundness"
    type: "merkle"
    config:
      root_signal: "main.root"
      leaf_signal: "main.leaf"
      path_elements_signal: "main.pathElements"
      path_indices_signal: "main.pathIndices"
      expected_tree_depth: 20
    checks:
      - "path_length_bypass"
      - "multiple_valid_paths"
      - "off_path_leaf_injection"
  
  - name: "nullifier_uniqueness"
    type: "composite"
    oracles:
      - { type: "nullifier", config: { signal: "main.nullifierHash" } }
      - { type: "range", config: { signal: "main.amount", max: 1000000 } }
    logic: "AND"
```

**Files**:
- `src/oracle/dsl.rs` (NEW): Parse oracle definitions from YAML
- `src/oracle/composite.rs` (NEW): Combine multiple oracles
- `src/config/mod.rs`: Add `SemanticOracleConfig`

**Exit Criteria**:
- ✅ YAML campaigns can define custom oracles
- ✅ Composite oracles support AND/OR/NOT logic
- ✅ Oracles integrate with fuzzing engine

---

## Phase 6: Differential Testing (Week 12-14)

**Goal**: Find implementation bugs by comparing circuits

### Task 6.1: Multi-Circuit Differential Testing
**Priority**: MEDIUM  
**Effort**: 6 days

**YAML Syntax**:

```yaml
campaign:
  name: "Differential Merkle Audit"
  
  differential_testing:
    enabled: true
    targets:
      - name: "tornado_merkle"
        framework: "circom"
        circuit_path: "./tornado/merkle.circom"
      - name: "semaphore_merkle"
        framework: "circom"
        circuit_path: "./semaphore/merkle.circom"
    
    comparison:
      mode: "semantic_equivalence"
      divergence_oracle: "merkle_soundness"
      
attacks:
  # Same inputs to all circuits
  - type: "differential_merkle"
    config:
      input_sharing: "all"
```

**Files**:
- `src/differential/engine.rs`: Extend for YAML config
- `src/config/mod.rs`: Add `DifferentialTestingConfig`

**Exit Criteria**:
- ✅ YAML campaigns support multi-circuit differential testing
- ✅ Divergence findings reported with circuit pairs

---

## Phase 7: Continuous Fuzzing Infrastructure (Week 14-16)

**Goal**: Deploy production-grade continuous fuzzing

### Task 7.1: CI/CD Integration
**Priority**: HIGH  
**Effort**: 5 days

**Implementation**:

```yaml
# .github/workflows/continuous_fuzzing.yml (NEW)
name: Continuous Fuzzing

on:
  schedule:
    - cron: '0 0 * * *'  # Nightly
  workflow_dispatch:

jobs:
  fuzz_production_circuits:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Initialize submodules
        run: git submodule update --init --recursive
      - name: Run benchmark suite
        run: ./scripts/run_production_benchmarks.sh
      - name: Upload findings
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: findings
          path: reports/
```

**Files**:
- `.github/workflows/continuous_fuzzing.yml` (NEW)
- `scripts/nightly_fuzzing.sh` (NEW)
- `src/reporting/trend.rs` (NEW): Track coverage/findings over time

### Task 7.2: Economic Impact Scoring
**Priority**: MEDIUM  
**Effort**: 3 days

**YAML Configuration**:

```yaml
economic_impact:
  enabled: true
  protocol_context:
    type: "privacy_mixer"
    tvl_usd: 10000000
    transaction_volume_daily: 500
  
  risk_scoring:
    critical: { multiplier: 1.0, label: "Full TVL at risk" }
    high: { multiplier: 0.5, label: "Partial drain possible" }
    medium: { multiplier: 0.1, label: "Privacy leak" }
```

**Files**:
- `src/scoring/economic.rs` (NEW)
- `src/reporting/impact.rs` (NEW)

**Exit Criteria**:
- ✅ Nightly fuzzing runs automatically
- ✅ Coverage trends tracked over time
- ✅ Findings include economic impact estimates
- ✅ Zero manual intervention required

---

## Phase 8: Production Validation (Week 16)

**Goal**: Prove capability on real-world circuits

### Task 8.1: Benchmark Suite Execution
**Priority**: CRITICAL  
**Effort**: 5 days

**Circuits to Test**:
1. **Tornado Cash Merkle Tree** (already compiled: `circuits/compiled/snarkjs_groth16/circuit.r1cs`)
2. **Semaphore** (submodule initialization required)
3. **Iden3 Auth** (`circuits/compiled/iden3_*/` available)
4. **ZK-SNARK Range Proof** (mock available)
5. **Custom Nullifier Circuit** (mock available)

**Validation Metrics**:
- Constraint coverage: SMT-guided vs random
- Vulnerability detection: CVE regression pass rate
- Performance: Inputs/sec, constraint solver latency
- False positive rate: <5%

**Script**:

```bash
#!/bin/bash
# scripts/final_validation.sh (NEW)

echo "=== ZkPatternFuzz Production Validation ==="

# 1. Initialize submodules
git submodule update --init --recursive

# 2. Run on compiled .r1cs files
for circuit in circuits/compiled/*/*.r1cs; do
    echo "Testing $circuit..."
    cargo run --release -- \
        --config campaigns/smt_guided_${circuit}.yaml \
        --output reports/$(basename $circuit).json
done

# 3. Compare SMT vs random
./scripts/compare_strategies.sh

# 4. Generate final report
cargo run --bin report_aggregator -- reports/*.json > VALIDATION_REPORT.md
```

**Exit Criteria**:
- ✅ All 5 benchmark circuits pass
- ✅ SMT-guided fuzzing achieves 30%+ higher constraint coverage
- ✅ CVE regression tests: 21/21 passing
- ✅ False positive rate < 5%
- ✅ Finds at least 1 novel vulnerability (implied constraint bug)

---

## Success Metrics

### Quantitative Targets

| Metric | Baseline | Target | Status |
|--------|----------|--------|--------|
| **Constraint Coverage** | 40% (random) | 70% (SMT-guided) | 🎯 |
| **CVE Regression Rate** | 21/21 (100%) | 21/21 (100%) | ✅ |
| **False Positive Rate** | Unknown | <5% | 🎯 |
| **Novel Vulnerabilities** | 0 | ≥1 (implied constraint) | 🎯 |
| **Exploit Verification** | N/A | >90% | 🎯 |
| **ML Prediction Accuracy** | N/A | >70% | 🎯 |

### Qualitative Goals

- **Industry Differentiation**: Constraint inversion + ML transfer learning are unique capabilities
- **Production Ready**: Runs on real circuits without mock fallbacks
- **Actionable Output**: Every finding includes verified exploit + remediation
- **Continuous Operation**: Nightly fuzzing with zero manual intervention

---

## Risk Mitigation

### Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| SMT solver timeout on large circuits | HIGH | MEDIUM | Constraint pruning, incremental solving |
| ML model overfits to synthetic bugs | MEDIUM | HIGH | Train on real audit data, cross-validation |
| Exploit generation false positives | MEDIUM | HIGH | Mandatory verification step |
| Git submodule circuits fail to compile | MEDIUM | MEDIUM | Pin to known-good commits, fallback to mocks for testing |

### Schedule Risks

| Risk | Mitigation |
|------|------------|
| ML integration takes longer than expected | Prioritize constraint inversion (higher ROI), defer ML to Phase 2 |
| Real circuit compilation issues | Use existing compiled .r1cs files, defer submodule circuits |

---

## Deliverables

### Code Artifacts

1. **Constraint Inference Engine** (`src/analysis/constraint_inference.rs`, ~500 LOC)
2. **ML Vulnerability Predictor** (`ml_models/` + `src/ml/`, ~500 LOC)
3. **Exploit Generator** (`src/exploit/`, ~500 LOC)
4. **YAML Enhancements** (constraint-guided, semantic oracles, differential testing)
5. **CI/CD Workflows** (`.github/workflows/continuous_fuzzing.yml`)
6. **Benchmark Suite** (`tests/benchmarks/`, 5 circuits)

### Documentation

1. **BENCHMARK_SPEC.md**: Benchmark definitions and pass/fail criteria
2. **VALIDATION_REPORT.md**: Final production validation results
3. **ML_MODEL.md**: ML model architecture and training instructions
4. **EXPLOIT_GUIDE.md**: How to interpret and use generated exploits

### Test Coverage

- **Unit Tests**: ~300 (existing 240 + 60 new)
- **Integration Tests**: 25 (existing 21 CVE + 4 new benchmark)
- **End-to-End Tests**: 5 (one per benchmark circuit)

---

## Immediate Next Steps (Week 0)

1. **Initialize git submodules**:
   ```bash
   git submodule update --init --recursive
   ```

2. **Run baseline benchmarks on existing .r1cs files**:
   ```bash
   ./scripts/run_production_benchmarks.sh
   ```

3. **Implement strict no-mock mode**:
   ```bash
   cargo run -- --no-mock-fallback --config campaigns/baseline.yaml
   ```

4. **Begin constraint inference engine**:
   - Create `src/analysis/constraint_inference.rs`
   - Implement `BitDecompositionInference` rule
   - Add test case for missing recomposition constraint

---

## Appendix: File Deletion Plan

The following roadmap files will be **deleted** after synthesis (replaced by this unified plan):

1. `BREAKTHROUGH_INNOVATIONS.md` - Content integrated into Phases 2-4
2. `CORRECTIONS_ROADMAP.md` - Content integrated into Phase 0-1
3. `CUSTOM_PATTERN_GENERATION.md` - Content integrated into Phase 2
4. `YAML_FUZZING_ROADMAP.md` - Content integrated into Phases 1, 5, 6
5. `ZERO_DAY_ROADMAP.md` - Content integrated into all phases

**Retention**: 
- `README.md` - Project overview (unchanged)
- `ARCHITECTURE.md` - System design (unchanged)
- `CONTRIBUTING.md` - Contribution guidelines (unchanged)
- `CHANGELOG.md` - Release history (unchanged)

---

**Document Status**: Living document, updated as implementation progresses  
**Last Updated**: 2026-02-06  
**Next Review**: After Phase 0 completion
