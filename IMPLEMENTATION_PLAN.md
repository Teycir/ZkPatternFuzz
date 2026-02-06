# ZkPatternFuzz: Unknown-Bug Discovery Implementation Plan

**Goal:** Push unknown-bug discovery via YAML-driven, target-tailored campaigns with innovative but implementable techniques.

**Status:** Based on code review of actual implementation (2024)

---

## Phase 1: Reality Check + Baseline (2-3 hours, run in parallel)

### Current Status: 🚧 PARTIAL

**Why This Matters:** Prevents duplicate work, establishes performance baseline, enables regression testing.

**What's Already Implemented:**
- ✅ Core fuzzing engine with coverage tracking (`src/fuzzer/engine.rs`)
- ✅ Multiple attack types (underconstrained, soundness, arithmetic, collision, boundary, verification, witness)
- ✅ Power scheduling (FAST, COE, EXPLORE, MMOPT, RARE, SEEK)
- ✅ Structure-aware mutation
- ✅ Symbolic execution integration with Z3
- ✅ Taint analysis
- ✅ Complexity analysis
- ✅ Corpus management with deduplication
- ✅ Coverage tracking (constraint-level)
- ✅ JSON, Markdown, SARIF reporting
- ✅ Parallel execution with rayon
- ✅ Attack plugin system with dynamic loading
- ✅ Constraint-guided seed generation from R1CS/ACIR
- ✅ Differential fuzzing across backends
- ✅ Multi-circuit composition testing

**What's Missing:**
- ❌ Capability matrix documentation
- ❌ Deterministic baseline campaign for CI
- ❌ Automated verification script

### Tasks (Streamlined)

1. **Capability Matrix** (`docs/CAPABILITY_MATRIX.md`) - **30 min**
   - Auto-generate from code review (already done above)
   - Simple table: Feature | Status | File | Notes
   
2. **Baseline Campaign** (`tests/campaigns/baseline.yaml`) - **1 hour**
   - Copy existing `mock_merkle_audit.yaml`
   - Add deterministic seed, fixed 1000 iterations
   - Run once, record output hash

3. **Verification Script** (`scripts/verify_baseline.sh`) - **15 min**
   ```bash
   #!/bin/bash
   set -e
   OUTPUT=$(cargo run --release -- --config tests/campaigns/baseline.yaml --seed 42 --workers 1)
   HASH=$(echo "$OUTPUT" | sha256sum | cut -d' ' -f1)
   EXPECTED="<hash_from_step_2>"
   [ "$HASH" = "$EXPECTED" ] || { echo "Baseline changed!"; exit 1; }
   ```

### Deliverables (Total: 2-3 hours)
- [ ] `docs/CAPABILITY_MATRIX.md` - Auto-generated table
- [ ] `tests/campaigns/baseline.yaml` - Copy + modify existing
- [ ] `scripts/verify_baseline.sh` - 10 lines of bash

**Can run in parallel with Phase 3 (oracle diversity) or Phase 4 (metamorphic oracles)**

---

## Phase 2: YAML v2 – Target-Tailored Profiles (1–2 weeks)

### Current Status: ❌ NOT STARTED

**Current YAML Schema** (`src/config/mod.rs`):
- ✅ Basic campaign, attacks, inputs, mutations, oracles
- ✅ Flexible `parameters.additional` HashMap for extensions
- ✅ Attack plugin loading via `attack_plugin_dirs`
- ✅ Constraint-guided config via `constraint_guided_*` params
- ❌ No YAML includes/overlays
- ❌ No profile system
- ❌ No explicit invariants
- ❌ No phased scheduling

### Objectives
- Eliminate YAML duplication via includes
- Enable circuit-specific overlays
- Declare invariants explicitly for metamorphic testing
- Add phased attack scheduling

### Schema Extensions

```yaml
# New top-level keys (extend FuzzConfig struct)
includes:
  - "templates/base.yaml"
  - "templates/traits/merkle.yaml"

profiles:
  merkle_default:
    max_depth: 32
    hash_function: "poseidon"
    
target_traits:
  uses_merkle: true
  range_checks: ["u64", "bitlen:252"]
  hash_function: "poseidon"

invariants:
  - name: "root_consistency"
    relation: "root == merkle(leaf, path)"
    oracle: "must_hold"
  - name: "path_binary"
    relation: "∀i: path[i] ∈ {0,1}"
    oracle: "constraint_check"

schedule:
  - phase: "seed"
    duration_sec: 60
    attacks: ["underconstrained"]
  - phase: "deep"
    duration_sec: 600
    attacks: ["soundness", "constraint_bypass"]
```

### Implementation
1. **Config Parser Extensions** (`src/config/mod.rs`, `src/config/v2.rs`)
   - Add `includes`, `profiles`, `target_traits`, `invariants`, `schedule` to `FuzzConfig`
   - YAML include resolution with cycle detection
   - Profile merging with precedence rules
   - Invariant AST parsing (simple DSL or S-expressions)

2. **Trait Templates** (`templates/traits/`)
   - `merkle.yaml` – Merkle tree patterns (path binary, depth bounds)
   - `range.yaml` – Range check patterns (bit decomposition)
   - `hash.yaml` – Hash function patterns (collision resistance)
   - `nullifier.yaml` – Nullifier patterns (uniqueness)
   - `signature.yaml` – Signature patterns (malleability)

3. **Generator** (`src/config/generator.rs`)
   - Parse circuit source to detect patterns
   - Suggest trait overlays based on detected structures
   - Auto-generate invariants from circuit comments/annotations

4. **Phased Scheduler** (`src/fuzzer/phased_scheduler.rs`)
   - Execute attacks in phases with time budgets
   - Carry corpus between phases
   - Early termination on critical findings

### Deliverables
- [ ] `src/config/v2.rs` – Schema v2 extensions
- [ ] `templates/traits/*.yaml` – 5+ trait templates
- [ ] `src/config/generator.rs` – Auto-generator
- [ ] `src/fuzzer/phased_scheduler.rs` – Phase execution
- [ ] Migration guide for v1 → v2

---

## Phase 3: Observability + Coverage (1–2 weeks)

### Current Status: ✅ MOSTLY IMPLEMENTED

**What's Already Implemented:**
- ✅ Constraint-level coverage tracking (`zk-fuzzer-core::coverage`)
- ✅ Coverage-guided fuzzing (power scheduler uses coverage)
- ✅ Taint analysis for dependency tracking (`src/analysis/taint.rs`)
- ✅ Complexity metrics (`src/analysis/complexity.rs`)
- ✅ Progress tracking (`src/progress/mod.rs`)
- ✅ JSON/Markdown/SARIF reports with statistics

**What's Missing:**
- ❌ Explicit witness-dependency graph visualization
- ❌ Oracle diversity metrics
- ❌ Enhanced CLI coverage summary

### Objectives
- Enhance existing coverage with dependency graphs
- Add oracle diversity tracking
- Improve CLI reporting

### New Metrics

#### 1. Witness-Dependency Graph (NEW)
```rust
// src/analysis/dependency.rs
struct DependencyGraph {
    input_influences: HashMap<usize, HashSet<ConstraintId>>,
    constraint_depends: HashMap<ConstraintId, HashSet<usize>>,
    uncovered_paths: Vec<Vec<ConstraintId>>,
}
```

#### 2. Oracle-Diversity Score (NEW)
```rust
// src/fuzzer/oracle_diversity.rs
struct OracleDiversity {
    oracle_types_fired: HashSet<String>,
    unique_violation_patterns: usize,
    diversity_score: f64,
}
```

### Implementation
1. **Dependency Analyzer** (`src/analysis/dependency.rs` - NEW)
   - Build influence graph from constraint inspector
   - Identify uncovered dependency paths
   - Suggest inputs to cover missing paths

2. **Oracle Diversity Tracker** (`src/fuzzer/oracle_diversity.rs` - NEW)
   - Track which oracle types fired
   - Count unique violation patterns
   - Compute diversity score

3. **Enhanced CLI Summary** (`src/reporting/coverage_summary.rs` - NEW)
   ```
   Coverage Summary:
   ├─ Constraints: 1,234 / 2,000 (61.7%)
   ├─ Input Dependencies: 45 / 50 paths (90%)
   ├─ Oracle Diversity: 7 / 12 types (58.3%)
   └─ Uncovered Paths: 5 critical paths
   ```

4. **Integrate into FuzzReport** (`src/reporting/mod.rs`)
   - Add dependency and oracle metrics to statistics
   - Include in JSON/Markdown output

### Deliverables
- [ ] `src/analysis/dependency.rs` – Dependency graph builder
- [ ] `src/fuzzer/oracle_diversity.rs` – Oracle diversity tracker
- [ ] `src/reporting/coverage_summary.rs` – Enhanced CLI view
- [ ] Update `FuzzStatistics` with new metrics

---

## Phase 4: Novel Oracles (3–5 weeks)

### Current Status: 🚧 PARTIAL

**Existing Oracles:**
- ✅ UnderconstrainedOracle (`src/attacks/underconstrained.rs`)
- ✅ ArithmeticOverflowOracle (`src/attacks/arithmetic.rs`)
- ✅ SoundnessTester (`src/attacks/soundness.rs`)
- ✅ CollisionDetector (`src/attacks/collision.rs`)
- ✅ BoundaryTester (`src/attacks/boundary.rs`)
- ✅ VerificationFuzzer (`src/attacks/verification.rs`)
- ✅ WitnessFuzzer (`src/attacks/witness.rs`)

**Missing Novel Oracles:**
- ❌ Metamorphic oracles
- ❌ Differential backend fuzzing (partial - exists but needs enhancement)
- ❌ Constraint slice oracles
- ❌ Spec inference oracles
- ❌ Witness collision beyond expected equivalence

### A. Constraint Inference Engine (NEW - HIGH PRIORITY)

**Concept:** Detect **missing** constraints (not just wrong ones).

**Innovation:** Most fuzzers test existing constraints. This infers what constraints *should* exist based on circuit semantics, then generates inputs that violate the missing constraints.

```rust
// src/attacks/constraint_inference.rs (NEW)
pub struct ConstraintInferenceEngine {
    inference_rules: Vec<Box<dyn InferenceRule>>,
}

pub trait InferenceRule {
    fn infer(&self, inspector: &dyn ConstraintInspector) -> Vec<ImpliedConstraint>;
}

pub enum ConstraintCategory {
    BitDecompositionRoundTrip,  // Decomposed but never recomposed
    MerklePathValidation,        // Path indices unbounded
    NullifierUniqueness,         // No uniqueness enforcement
    RangeEnforcement,            // Missing range checks
}

// Example rule
pub struct BitDecompositionInference;
impl InferenceRule for BitDecompositionInference {
    fn infer(&self, inspector: &dyn ConstraintInspector) -> Vec<ImpliedConstraint> {
        // Find bit decomposition without recomposition
        // Return: "Should have constraint: sum(bits[i] * 2^i) == original"
    }
}
```

**YAML Configuration:**
```yaml
attacks:
  - type: "constraint_inference"
    description: "Find missing constraints"
    config:
      categories:
        - "bit_decomposition"
        - "merkle_path"
        - "nullifier_uniqueness"
      confidence_threshold: 0.7
      generate_violations: true
```

**Implementation:** `src/attacks/constraint_inference.rs` (~400 LOC)
- Analyze constraint graph for common patterns
- Infer missing constraints with confidence scores
- Generate test cases that exploit missing constraints

---

### B. Metamorphic Oracles

**Concept:** Transformations that should preserve/predict output changes.

```yaml
invariants:
  - name: "permutation_invariance"
    type: "metamorphic"
    transform: "permute_inputs([0,1,2] → [2,0,1])"
    expected: "output_unchanged"
    
  - name: "scaling_linearity"
    type: "metamorphic"
    transform: "scale_input(x, k)"
    expected: "output_scaled(k)"
```

**Implementation:** `src/attacks/metamorphic.rs`
- Parse transform specs from YAML
- Apply transformations
- Compare outputs via oracle

---

### C. Differential Backend Fuzzing

**Concept:** Same witness, multiple backends → compare results.

```yaml
differential:
  enabled: true
  backends: ["circom", "noir", "halo2"]
  tolerance: 0.0001
  compare: ["proof_valid", "public_outputs"]
```

**Implementation:** `src/differential/backend_fuzzer.rs`
- Execute witness on all backends
- Detect discrepancies
- Flag backend-specific bugs

---

### D. Constraint Slice Oracles

**Concept:** Slice constraints into dependency cones, mutate within cones.

```rust
struct ConstraintSlicer {
    // Extract cone of constraints affecting public output
    fn slice_to_output(&self, output_idx: usize) -> Vec<ConstraintId>;
    
    // Mutate only within cone
    fn mutate_in_cone(&self, cone: &[ConstraintId]) -> TestCase;
}
```

**Implementation:** `src/attacks/constraint_slice.rs`
- Build backward slice from public outputs
- Targeted mutation within slice
- Detect leaked constraints

---

### E. Spec Inference Oracles

**Concept:** Infer expected relations, actively violate them.

```rust
enum InferredSpec {
    LinearRelation { coeffs: Vec<Fr>, constant: Fr },
    RangeCheck { min: u64, max: u64 },
    BitwiseConstraint { bit_length: usize },
}

impl SpecInferenceOracle {
    fn infer_specs(&self, circuit: &Circuit) -> Vec<InferredSpec>;
    fn generate_violations(&self, spec: &InferredSpec) -> Vec<TestCase>;
}
```

**Implementation:** `src/attacks/spec_inference.rs`
- Sample valid witnesses
- Infer linear/range relations via regression
- Generate violation attempts

---

### F. Witness Collision Oracles

**Concept:** Find distinct witnesses → identical public outputs (beyond expected equivalence).

```rust
struct CollisionDetector {
    equivalence_classes: Vec<EquivalenceClass>,
    
    fn find_unexpected_collisions(&self) -> Vec<(Witness, Witness)>;
}
```

**Implementation:** `src/attacks/witness_collision.rs`
- Hash public outputs
- Detect collisions outside known equivalence
- Flag under-constraint or missing selectors

---

### G. ML-Based Vulnerability Prediction (OPTIONAL - RESEARCH)

**Concept:** Learn from past audits to predict vulnerability locations.

**Architecture:**
- Graph Neural Network (GNN) embeds R1CS constraint graphs
- Train on past fuzzing campaigns + audit results
- Predict vulnerability likelihood for new circuits
- Prioritize fuzzing budget based on predictions

**Implementation:** `src/ml/predictor.rs` + `ml_models/circuit_embedding.py`
- Requires PyTorch + pyo3 bindings
- Needs training data (synthetic bugs initially)
- Online learning from fuzzing results

**Note:** Defer to Phase 2 if time-constrained. Constraint inference has higher ROI.

---

### H. Automatic Exploit Generation (OPTIONAL)

**Concept:** Generate verified JavaScript/Python exploits for every finding.

```rust
// src/reporting/exploit_generator.rs (NEW)
pub struct ExploitGenerator;

impl ExploitGenerator {
    pub fn generate_javascript_exploit(&self, finding: &Finding) -> String {
        // Generate working snarkjs exploit code
        format!(r#"
        const snarkjs = require("snarkjs");
        async function exploit() {{
            const witnessA = {};
            const witnessB = {};
            // ... verify both produce same output
        }}
        "#)
    }
}
```

**Value:** Improves report quality, proves exploitability. Doesn't find more bugs.

---

### Deliverables
- [ ] `src/attacks/constraint_inference.rs` – **Constraint inference (HIGH PRIORITY)**
- [ ] `src/attacks/metamorphic.rs` – Metamorphic oracle
- [ ] Enhance `src/differential/executor.rs` – Backend fuzzer improvements
- [ ] `src/attacks/constraint_slice.rs` – Constraint slicer
- [ ] `src/attacks/spec_inference.rs` – Spec inference oracle
- [ ] `src/attacks/witness_collision.rs` – Enhanced collision detector
- [ ] `src/ml/predictor.rs` – ML predictor (OPTIONAL)
- [ ] `src/reporting/exploit_generator.rs` – Exploit generator (OPTIONAL)
- [ ] Update `AttackType` enum in `zk-core` with new types
- [ ] YAML schema updates for invariants and transforms

---

## Phase 5: Adaptive Scheduler (2–4 weeks)

### Current Status: 🚧 PARTIAL

**What's Already Implemented:**
- ✅ Power scheduler with multiple strategies (`src/fuzzer/power_schedule.rs`)
- ✅ Coverage-guided corpus selection
- ✅ Energy-based test case prioritization
- ✅ Global statistics tracking

**What's Missing:**
- ❌ Attack-level budget reallocation
- ❌ Near-miss detection and reuse
- ❌ YAML suggestion generation

### Objectives
- Add attack-level adaptive scheduling
- Implement near-miss detection
- Generate YAML improvement suggestions

### Architecture

```rust
struct AdaptiveScheduler {
    attack_scores: HashMap<AttackType, f64>,
    near_misses: Vec<TestCase>,
    
    fn update_scores(&mut self, results: &AttackResults);
    fn allocate_budget(&self, total_time: Duration) -> HashMap<AttackType, Duration>;
    fn suggest_yaml_edits(&self) -> Vec<YamlSuggestion>;
}
```

### Scoring Heuristics
- **Coverage gain:** +10 points per new constraint
- **Near-miss:** +5 points (oracle almost triggered)
- **Finding:** +50 points
- **Decay:** -1 point per iteration without progress

### Near-Miss Detection
```rust
enum NearMiss {
    AlmostOutOfRange { value: Fr, threshold: Fr, distance: f64 },
    AlmostCollision { hash1: [u8;32], hash2: [u8;32], hamming: usize },
    AlmostInvariantViolation { expected: Fr, actual: Fr, diff: f64 },
}
```

### YAML Feedback
```yaml
# Auto-generated suggestions
suggestions:
  - add_interesting_value: "0x1fffffffffffffff"  # Near-miss boundary
  - add_invariant: "output[0] < 2^64"  # Inferred from near-violations
  - increase_budget: "soundness"  # High-scoring attack
```

### Implementation
1. **Scheduler** (`src/fuzzer/adaptive_scheduler.rs`)
2. **Near-Miss Detector** (`src/fuzzer/near_miss.rs`)
3. **YAML Suggester** (`src/config/suggester.rs`)

### CLI
```bash
cargo run -- --config campaign.yaml --adaptive
# Output: campaign_suggested.yaml with recommended edits
```

### Deliverables
- [ ] `src/fuzzer/adaptive_attack_scheduler.rs` – Attack-level scheduler
- [ ] `src/fuzzer/near_miss.rs` – Near-miss detector
- [ ] `src/config/suggester.rs` – YAML suggester
- [ ] `--adaptive` CLI flag in `src/main.rs`
- [ ] Integrate with existing power scheduler

---

## Phase 6: Benchmarking + Triage (Ongoing)

### Objectives
- Maintain known-bug suite
- Track time-to-first-bug
- Auto-minimize PoCs

### Current Status: 🚧 PARTIAL

**What's Already Implemented:**
- ✅ Test campaigns in `tests/campaigns/`
- ✅ Integration tests in `tests/`
- ✅ Real circuit integration tests
- ✅ Corpus export functionality
- ✅ Test case minimizer (`src/corpus/minimizer.rs`)

**What's Missing:**
- ❌ Dedicated known-bug benchmark suite
- ❌ Automated benchmark harness
- ❌ Time-to-bug tracking
- ❌ PoC exploit script generator

### Benchmark Suite

```
tests/bench/
├── known_bugs/
│   ├── underconstrained_merkle/
│   │   ├── circuit.circom
│   │   ├── bug_description.md
│   │   └── expected_finding.json
│   ├── range_bypass/
│   ├── nullifier_collision/
│   ├── soundness_violation/
│   └── arithmetic_overflow/
├── harness.rs
└── scoreboard.json
```

### Metrics
```json
{
  "benchmark": "underconstrained_merkle",
  "runs": [
    {
      "version": "0.2.0",
      "time_to_first_bug_sec": 12.4,
      "unique_bugs_found": 1,
      "false_positives": 0
    }
  ]
}
```

### Auto-Minimization
```rust
struct TestCaseMinimizer {
    fn minimize(&self, test: &TestCase, oracle: &dyn Oracle) -> TestCase;
    // Delta-debugging algorithm
}
```

### PoC Generation
```rust
struct PoCGenerator {
    fn generate_exploit(&self, finding: &Finding) -> String;
    // Outputs runnable reproduction script
}
```

### Implementation
1. **Benchmark Harness** (`tests/bench/harness.rs`)
2. **Minimizer** (`src/corpus/minimizer.rs`)
3. **PoC Generator** (`src/reporting/poc_generator.rs`)

### Deliverables
- [ ] 10+ seeded bug circuits in `tests/bench/known_bugs/`
- [ ] `tests/bench/harness.rs` – Automated benchmark runner
- [ ] Enhance `src/corpus/minimizer.rs` – Add delta-debugging
- [ ] `src/reporting/poc_generator.rs` – Exploit script generator
- [ ] `scripts/run_benchmarks.sh` – Benchmark runner
- [ ] CI integration in `.github/workflows/benchmarks.yml`

---

## Summary: Innovative Techniques

| Technique | Innovation | Status | Implementability | Impact |
|-----------|-----------|--------|------------------|--------|
| **Metamorphic Oracles** | ZK-specific invariant testing | ❌ Not Started | High | High – catches logic bugs |
| **Constraint-Graph Mutation** | Coverage-guided at constraint level | ✅ Implemented | High | High – already working |
| **Differential Backend Fuzzing** | Cross-compiler bug detection | 🚧 Partial | High | Medium – needs enhancement |
| **Spec Inference** | Auto-learn circuit properties | ❌ Not Started | Medium | High – finds violations |
| **Witness Collision Detection** | Beyond expected equivalence | 🚧 Partial | High | High – needs enhancement |
| **Adaptive Scheduling** | Budget reallocation via learning | 🚧 Partial | Medium | High – power scheduler exists |
| **Constraint-Guided Seeds** | SMT-based seed generation | ✅ Implemented | High | High – already working |
| **Taint Analysis** | Information flow tracking | ✅ Implemented | High | Medium – already working |

---

## Revised Timeline (Based on Actual Implementation)

| Phase | Duration | Status | Dependencies |
|-------|----------|--------|--------------|
| 1. Reality Check | 1–2 days | 🚧 Partial | None |
| 2. YAML v2 | 1–2 weeks | ❌ Not Started | Phase 1 |
| 3. Observability | 1 week | 🚧 Partial | Phase 1 |
| 4. Novel Oracles | 2–3 weeks | 🚧 Partial | Phase 2, 3 |
| 5. Adaptive Scheduler | 1–2 weeks | 🚧 Partial | Phase 3, 4 |
| 6. Benchmarking | Ongoing | 🚧 Partial | Phase 4 |

**Total:** ~5–9 weeks remaining (significant foundation already exists)

---

## Success Metrics

1. **Bug Discovery Rate:** 2x increase in unique bugs found per hour (baseline: current performance)
2. **False Positive Rate:** <5% of reported findings
3. **Coverage:** >80% constraint coverage on benchmark suite
4. **Time-to-Bug:** <60 seconds for known-bug suite (need to establish baseline)
5. **Adaptivity:** Attack scheduler reallocates >30% of budget based on learning
6. **Oracle Diversity:** >70% of available oracle types fire on complex circuits
7. **Near-Miss Utilization:** >20% of corpus from near-miss mutations

---

## Next Steps (Prioritized)

### Immediate (Week 1)
1. **Phase 1 (2-3 hours):** Capability matrix + baseline (run in parallel with below)
2. **Phase 4A (4-5 days):** **Constraint inference engine (HIGHEST IMPACT)**
3. **Phase 4B (3-4 days):** Metamorphic oracles (needs Phase 2 invariants)
4. **Phase 3 (2 days):** Oracle diversity tracking
5. **Phase 6 (2 days):** 5 known-bug circuits for benchmarking

### Short-term (Week 3-5)
4. **Phase 4:** Implement metamorphic oracles (highest impact)
5. **Phase 4:** Implement spec inference oracles
6. **Phase 5:** Add near-miss detection to existing fuzzer

### Medium-term (Week 6-9)
7. **Phase 2:** Design and implement YAML v2 schema
8. **Phase 3:** Build dependency graph analyzer
9. **Phase 5:** Implement attack-level adaptive scheduler
10. **Phase 6:** Create automated benchmark harness

### Ongoing
- Expand benchmark suite with real-world bugs
- Tune power scheduler parameters
- Optimize constraint-guided seed generation
- Improve differential fuzzing coverage

---

## References

- **AFL:** Coverage-guided fuzzing architecture
- **LibFuzzer:** Corpus management and minimization
- **Echidna:** Property-based testing for smart contracts
- **Trail of Bits:** ZK security research and bug patterns
- **Symbolic Execution:** Z3-based constraint solving

---

**Status:** 📋 Planning Phase  
**Last Updated:** 2024  
**Owner:** ZkPatternFuzz Core Team
