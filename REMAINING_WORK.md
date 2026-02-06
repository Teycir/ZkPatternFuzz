# ZkPatternFuzz: Remaining Work

**Status:** 80% Complete  
**Remaining:** 4-7 weeks  
**Priority:** Constraint Inference Engine (finds 0-day bugs)

---

## Phase 0: AI-Assisted YAML Generation (2-3 days)

### Deliverables
- [ ] `templates/ai_assisted/merkle_tree.yaml` - Merkle tree template
- [ ] `templates/ai_assisted/nullifier.yaml` - Nullifier template
- [ ] `templates/ai_assisted/range_proof.yaml` - Range proof template
- [ ] `templates/ai_assisted/signature.yaml` - Signature template
- [ ] `docs/CLAUDE_PROMPT.md` - Prompt for Claude Opus
- [ ] `docs/AI_WORKFLOW.md` - User guide

**Workflow:** User uploads circuit → Claude generates YAML → Fuzzer runs

---

## Phase 1: Reality Check (2-3 hours)

### Deliverables
- [ ] `docs/CAPABILITY_MATRIX.md` - Feature status table
- [ ] `tests/campaigns/baseline.yaml` - Deterministic baseline
- [ ] `scripts/verify_baseline.sh` - CI verification script

---

## Phase 2: YAML v2 (1-2 weeks)

### Deliverables
- [ ] `src/config/v2.rs` - YAML includes, profiles, invariants, schedule
- [ ] `templates/traits/merkle.yaml` - Merkle patterns
- [ ] `templates/traits/range.yaml` - Range check patterns
- [ ] `templates/traits/hash.yaml` - Hash function patterns
- [ ] `templates/traits/nullifier.yaml` - Nullifier patterns
- [ ] `templates/traits/signature.yaml` - Signature patterns
- [ ] `src/config/generator.rs` - Auto-detect circuit patterns
- [ ] `src/fuzzer/phased_scheduler.rs` - Phased attack execution

---

## Phase 3: Observability (1 week)

### Deliverables
- [ ] `src/analysis/dependency.rs` - Witness-dependency graph
- [ ] `src/fuzzer/oracle_diversity.rs` - Oracle diversity tracker
- [ ] `src/reporting/coverage_summary.rs` - Enhanced CLI summary
- [ ] Update `FuzzStatistics` with new metrics

---

## Phase 4: Novel Oracles (2-3 weeks) ⭐ HIGHEST PRIORITY

### A. Constraint Inference Engine (4-5 days) - **CRITICAL**

**Innovation:** Finds **missing** constraints (not just wrong ones)

```rust
// src/attacks/constraint_inference.rs (NEW - ~400 LOC)
pub struct ConstraintInferenceEngine {
    inference_rules: Vec<Box<dyn InferenceRule>>,
}

pub enum ConstraintCategory {
    BitDecompositionRoundTrip,  // Decomposed but never recomposed
    MerklePathValidation,        // Path indices unbounded
    NullifierUniqueness,         // No uniqueness enforcement
    RangeEnforcement,            // Missing range checks
}
```

**YAML:**
```yaml
attacks:
  - type: "constraint_inference"
    config:
      categories: ["bit_decomposition", "merkle_path", "nullifier_uniqueness"]
      confidence_threshold: 0.7
```

**Deliverable:** `src/attacks/constraint_inference.rs`

---

### B. Metamorphic Oracles (3-4 days)

**Innovation:** Test invariants via transformations

```yaml
invariants:
  - name: "permutation_invariance"
    type: "metamorphic"
    transform: "permute_inputs([0,1,2] → [2,0,1])"
    expected: "output_unchanged"
```

**Deliverable:** `src/attacks/metamorphic.rs`

---

### C. Constraint Slice Oracles (3 days)

**Innovation:** Mutate within dependency cones

```rust
// src/attacks/constraint_slice.rs (NEW)
struct ConstraintSlicer {
    fn slice_to_output(&self, output_idx: usize) -> Vec<ConstraintId>;
    fn mutate_in_cone(&self, cone: &[ConstraintId]) -> TestCase;
}
```

**Deliverable:** `src/attacks/constraint_slice.rs`

---

### D. Spec Inference Oracles (3-4 days)

**Innovation:** Auto-learn circuit properties, generate violations

```rust
// src/attacks/spec_inference.rs (NEW)
enum InferredSpec {
    LinearRelation { coeffs: Vec<Fr>, constant: Fr },
    RangeCheck { min: u64, max: u64 },
    BitwiseConstraint { bit_length: usize },
}
```

**Deliverable:** `src/attacks/spec_inference.rs`

---

### E. Enhanced Witness Collision (2 days)

**Innovation:** Detect collisions beyond expected equivalence

**Deliverable:** Enhance `src/attacks/witness_collision.rs`

---

### F. Differential Backend Enhancement (2 days)

**Innovation:** Better cross-compiler bug detection

**Deliverable:** Enhance `src/differential/executor.rs`

---

### Summary Deliverables
- [ ] `src/attacks/constraint_inference.rs` - **HIGHEST PRIORITY**
- [ ] `src/attacks/metamorphic.rs`
- [ ] `src/attacks/constraint_slice.rs`
- [ ] `src/attacks/spec_inference.rs`
- [ ] Enhance `src/attacks/witness_collision.rs`
- [ ] Enhance `src/differential/executor.rs`
- [ ] Update `AttackType` enum in `zk-core`
- [ ] YAML schema updates

---

## Phase 5: Adaptive Scheduler (1-2 weeks)

### Deliverables
- [ ] `src/fuzzer/adaptive_attack_scheduler.rs` - Attack-level budget reallocation
- [ ] `src/fuzzer/near_miss.rs` - Near-miss detection
- [ ] `src/config/suggester.rs` - YAML suggestion generator
- [ ] `--adaptive` CLI flag in `src/main.rs`

**Features:**
- Reallocate budget to productive attacks
- Detect near-misses (oracle almost triggered)
- Generate YAML improvement suggestions

---

## Timeline

| Phase | Duration | Priority |
|-------|----------|----------|
| 0. AI YAML | 2-3 days | HIGH |
| 1. Baseline | 2-3 hours | MEDIUM |
| 2. YAML v2 | 1-2 weeks | HIGH (needed for Phase 4B) |
| 3. Observability | 1 week | MEDIUM |
| 4A. Constraint Inference | 4-5 days | **CRITICAL** |
| 4B. Metamorphic | 3-4 days | HIGH |
| 4C. Constraint Slice | 3 days | MEDIUM |
| 4D. Spec Inference | 3-4 days | HIGH |
| 4E. Witness Collision | 2 days | MEDIUM |
| 4F. Differential | 2 days | LOW |
| 5. Adaptive Scheduler | 1-2 weeks | MEDIUM |

**Total:** 4-7 weeks

---

## Success Metrics

1. **Constraint Inference:** Detects missing bit decomposition recomposition
2. **Metamorphic Oracles:** Catches invariant violations
3. **Coverage:** >80% constraint coverage on benchmarks
4. **Time-to-Bug:** <60 seconds for known-bug suite
5. **False Positives:** <5%

---

## Immediate Next Steps (Week 1)

1. **Phase 0 (Day 1-3):** Create AI templates + Claude prompt
2. **Phase 1 (2 hours):** Capability matrix + baseline
3. **Phase 4A (Day 4-8):** **Constraint inference engine** ⭐

---

## What's Already Complete ✅

- Core fuzzing engine with coverage tracking
- 7+ attack types (underconstrained, soundness, arithmetic, collision, boundary, verification, witness)
- Power scheduling (6 strategies)
- Symbolic execution with Z3
- Taint analysis
- Constraint-guided seed generation
- Differential fuzzing
- Multi-circuit composition
- **Benchmarking suite (Phase 6)** ✅
- **PoC generator** ✅
- **Delta debugging minimizer** ✅
- **CI workflows** ✅

---

**Focus:** Constraint Inference Engine is the #1 priority - it finds bugs in **missing** constraints, which is where real 0-days hide.
