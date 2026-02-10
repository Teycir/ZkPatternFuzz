# ZkPatternFuzz: Comprehensive Repository Audit Document

**Version:** 0.1.0  
**Repository:** ZkPatternFuzz  
**Language:** Rust (Edition 2021)  
**License:** BSL 1.1 (converts to Apache 2.0 on 2028-02-04)  
**Last Updated:** February 2026  

---

## 1. Executive Summary

ZkPatternFuzz is a **production-grade Zero-Knowledge Proof security testing framework** written in Rust. It provides comprehensive fuzzing, symbolic execution, and formal verification integration for ZK circuits across multiple proving systems (Circom, Noir, Halo2, Cairo).

### Key Metrics
- **~15,000+ lines** of production Rust code
- **300+ library tests** passing
- **18 major milestones** completed
- **92% detection rate** on CVE test suite (25+ vulnerabilities)
- **<10% false positive rate** in evidence mode
- **Multi-backend support:** Circom, Noir, Halo2, Cairo, Mock

### Primary Purpose
Detect vulnerabilities in ZK circuits including:
- Underconstrained circuits (multiple valid witnesses)
- Soundness violations (proof forgery)
- Arithmetic overflow/underflow
- Information leakage
- Verification bypass vulnerabilities

---

## 2. Repository Structure

```
ZkPatternFuzz/
├── Cargo.toml                    # Workspace root manifest
├── Cargo.lock                    # Dependency lock file
├── src/                          # Main source code
│   ├── main.rs                   # CLI entry point
│   ├── lib.rs                    # Library exports
│   ├── errors.rs                 # Error types
│   ├── attacks/                  # Attack implementations
│   ├── analysis/                 # Symbolic execution, taint analysis
│   ├── bin/                      # Binary utilities
│   ├── chain_fuzzer/             # Mode 3: Multi-step chain fuzzing
│   ├── config/                   # YAML configuration parsing
│   ├── corpus/                   # Test case management
│   ├── cve/                      # CVE test suite
│   ├── differential/             # Cross-backend differential testing
│   ├── distributed/              # Distributed fuzzing coordination
│   ├── executor/                 # Circuit execution abstraction
│   ├── formal/                   # Formal verification integration
│   ├── fuzzer/                   # Core fuzzing engine
│   ├── multi_circuit/            # Circuit composition
│   ├── progress/                 # Progress tracking
│   ├── reporting/                # Report generation
│   └── targets/                  # Backend integrations
├── crates/                       # Workspace crates
│   ├── zk-core/                  # Core types and traits
│   ├── zk-constraints/           # Constraint parsing and analysis
│   ├── zk-backends/              # Backend implementations
│   ├── zk-symbolic/              # Symbolic execution engine
│   ├── zk-fuzzer-core/           # Fuzzing engine core
│   ├── zk-attacks/               # Attack implementations
│   └── zk-attacks-plugin-example/# Plugin example
├── campaigns/                    # Campaign configurations
│   ├── examples/                 # Example campaigns
│   ├── templates/                # Reusable templates
│   ├── zk0d/                     # zk0d target campaigns
│   └── zk0d_validation/          # Validation campaigns
├── circuits/                     # Test circuits
├── targets/                      # Target definitions
├── tests/                        # Integration tests
├── docs/                         # Documentation
│   ├── AI_PENTEST_RULES.md       # AI pentest workflow rules
│   └── scan_modes.md             # Scan mode definitions
├── reports/                      # Generated reports
├── benches/                      # Benchmarks
├── benchmarks/                   # Benchmark implementations
├── third_party/                  # Third-party dependencies
├── scripts/                      # Utility scripts
├── README.md                     # Main documentation
├── ARCHITECTURE.md               # Architecture deep-dive
├── ROADMAP.md                    # Development roadmap
├── CHANGELOG.md                  # Version history
├── CONTRIBUTING.md               # Contribution guidelines
└── LICENSE                       # BSL 1.1 license
```

---

## 3. Workspace Architecture

The project uses a **Cargo workspace** with 7 member crates:

### 3.1 Crate Dependencies

```
zk-fuzzer (root)
├── zk-core
├── zk-constraints
├── zk-backends
├── zk-symbolic
├── zk-fuzzer-core
└── zk-attacks

zk-fuzzer-core
├── zk-core
└── zk-attacks

zk-attacks
├── zk-core
└── zk-constraints

zk-symbolic
├── zk-core
└── zk-constraints

zk-constraints
└── zk-core

zk-backends
└── zk-core
```

### 3.2 Crate Responsibilities

| Crate | Purpose | Key Modules |
|-------|---------|-------------|
| **zk-core** | Core types, traits, field arithmetic | `types.rs`, `field.rs`, `executor.rs`, `traits.rs` |
| **zk-constraints** | Constraint parsing (R1CS, ACIR, PLONK) | `r1cs_parser.rs`, `r1cs_to_smt.rs`, `constraint_types.rs` |
| **zk-backends** | Backend integrations | `circom/`, `noir/`, `halo2/`, `cairo/`, `mock/` |
| **zk-symbolic** | Symbolic execution with Z3 | `symbolic_v2.rs`, `constraint_guided.rs`, `concolic.rs` |
| **zk-fuzzer-core** | Fuzzing engine implementation | `engine.rs`, `mutators.rs`, `oracle.rs`, `power_schedule.rs` |
| **zk-attacks** | Attack implementations | `underconstrained.rs`, `soundness.rs`, `collision.rs`, `boundary.rs` |

---

## 4. Core Components Deep Dive

### 4.1 Fuzzing Engine (`src/fuzzer/`)

**Key Files:**
- `engine.rs` - Main fuzzing loop orchestration
- `mutators.rs` - Input mutation strategies
- `oracle.rs` - Bug detection oracles
- `power_schedule.rs` - Test case prioritization
- `structure_aware.rs` - ZK-aware mutations

**Architecture Pattern:** Producer-Consumer with shared state

```rust
FuzzingEngine
├── Corpus (shared, lock-free via Arc<RwLock<>>)
├── CoverageTracker (bitmap-based, atomic)
├── PowerScheduler (energy-based selection)
├── StructureMutator (Merkle paths, signatures)
└── BugOracles (vulnerability detection)
```

**Concurrency Model:**
- Rayon-based parallel execution
- Per-worker RNG with deterministic seeds
- Atomic counters for statistics
- Read-heavy corpus access pattern

### 4.2 Executor Abstraction (`src/executor/`)

**Trait Hierarchy:**
```rust
CircuitExecutor (trait)
├── execute(&self, inputs) -> ExecutionResult
├── prove(&self, witness) -> Result<Proof>
└── verify(&self, proof, public) -> Result<bool>

Implementations:
├── MockCircuitExecutor (testing)
├── CircomTarget (via targets module)
├── NoirTarget (via targets module)
├── Halo2Target (via targets module)
└── CairoTarget (via targets module)
```

**Factory Pattern:**
```rust
ExecutorFactory::create(framework, path, component) -> Arc<dyn CircuitExecutor>
```

### 4.3 Attack Modules (`src/attacks/`)

**15 Production Attack Types:**

| Attack | Detection Method | Status |
|--------|------------------|--------|
| `underconstrained` | Witness pair comparison | ✅ Production |
| `soundness` | Proof forgery attempts | ✅ Production |
| `arithmetic_overflow` | Boundary value testing | ✅ Production |
| `witness_validation` | Consistency checking | ✅ Production |
| `verification` | Malformed proof testing | ✅ Production |
| `collision` | Hash/nullifier collision | ✅ Production |
| `boundary` | Field boundary testing | ✅ Production |
| `differential` | Cross-backend comparison | ✅ Production |
| `circuit_composition` | Chain execution | ✅ Production |
| `recursive_proof` | Recursive verification | ✅ Production |
| `information_leakage` | Taint analysis | ✅ Production |
| `timing_sidechannel` | Timing variation | ✅ Production |
| `constraint_inference` | Pattern learning | ⚠️ Experimental (75% precision) |
| `constraint_slice` | Dependency mutation | ⚠️ Experimental |
| `metamorphic` | Transform-based | ⚠️ Experimental (90% precision) |
| `spec_inference` | Auto-learn properties | ⚠️ Experimental (85% precision) |
| `witness_collision` | Equivalence class | ✅ Production |

**Extension Point:**
```rust
pub trait Attack {
    fn run(&self, context: &AttackContext) -> Vec<Finding>;
}
```

### 4.4 Symbolic Execution (`src/analysis/symbolic.rs`)

**Capabilities:**
- Z3 SMT solver integration
- Constraint extraction from R1CS/ACIR/PLONK
- Path exploration with pruning
- Concolic execution

**Configuration:**
```rust
SymbolicConfig {
    max_depth: 200,              // Constraint layers
    max_paths: 1000,             // Path explosion limit
    solver_timeout_ms: 5000,     // Per-query timeout
    solutions_per_path: 4,       // Solutions per path
    pruning_strategy: DepthBounded,
}
```

**Supported Constraint Types:**
- R1CS (Circom)
- ACIR (Noir)
- PLONK gates (Halo2)
- AIR constraints (Cairo)
- Lookup tables
- Custom gates
- Range constraints
- Polynomial constraints

### 4.5 Coverage Tracking (`src/fuzzer/coverage.rs`)

**Implementation:**
- Bitmap-based tracking (1 bit per constraint)
- Atomic operations for thread safety
- Efficient diff computation
- Coverage-guided corpus selection

**Metrics:**
- Total constraints
- Covered constraints
- Coverage percentage
- Unique paths explored

### 4.6 Power Scheduling (`src/fuzzer/power_schedule.rs`)

**Algorithms:**

| Schedule | Strategy | Best For |
|----------|----------|----------|
| MMOPT | Min-max optimal | General purpose (default) |
| FAST | Fast executions | Large circuits |
| COE | Cut-off exponential | Balanced |
| EXPLORE | Maximize new paths | Deep exploration |
| RARE | Rare cases | Edge cases |
| SEEK | Active seeking | Targeted fuzzing |

---

## 5. Backend Support

### 5.1 Supported Frameworks

| Framework | Proof System | Status | CLI Tools |
|-----------|--------------|--------|-----------|
| **Circom** | Groth16 (R1CS) | ✅ Full | snarkjs, circom |
| **Noir** | Barretenberg (ACIR) | ✅ Full | nargo, bb |
| **Halo2** | PLONK | ✅ Full | cargo, halo2_proofs |
| **Cairo** | STARK | ✅ Full | cairo-compile, stone-prover |
| **Mock** | N/A | ✅ Full | In-process |

### 5.2 Backend Integration Details

**Circom (`src/targets/circom.rs`):**
- Compiles `.circom` → R1CS + WASM
- Uses snarkjs for proving/verification
- Parses constraint count from R1CS binary
- Generates witness via WASM executor
- Supports both js-witnesscalc and wasm witness generation

**Noir (`src/targets/noir.rs`):**
- Compiles via `nargo compile`
- Executes via Barretenberg backend
- Supports ACIR format
- Generates proof via `nargo prove`

**Halo2 (`src/targets/halo2.rs`):**
- Rust-based circuits
- MockProver for testing
- Real proving via halo2_proofs
- Supports custom gates and lookup tables

**Cairo (`src/targets/cairo.rs`):**
- Supports Cairo 0 and Cairo 1
- Uses stone-prover for STARK proofs
- Tracks execution steps
- Supports both legacy and modern syntax

---

## 6. Configuration System

### 6.1 Campaign YAML Structure

```yaml
campaign:
  name: "Audit Campaign"
  version: "1.0"
  target:
    framework: "circom" | "noir" | "halo2" | "cairo" | "mock"
    circuit_path: "./path/to/circuit.circom"
    main_component: "CircuitName"
  parameters:
    field: "bn254"
    max_constraints: 100000
    timeout_seconds: 300
    additional:
      strict_backend: true         # Fail if real backend missing
      mark_fallback: true          # Mark mock fallback usage
      evidence_mode: true          # Strict verification
      oracle_validation: true      # Cross-validate findings

attacks:
  - type: "underconstrained"
    description: "Find multiple witnesses"
    config:
      witness_pairs: 1000
      public_input_names: ["root", "nullifier"]
      fixed_public_inputs: ["0x0", "0x0"]

inputs:
  - name: "input1"
    type: "field"
    fuzz_strategy: "random" | "interesting_values" | "mutation"

reporting:
  output_dir: "./reports"
  formats: ["json", "markdown", "sarif"]
  include_poc: true
```

### 6.2 CLI Commands

```bash
# Run campaign
zk-fuzzer run <campaign.yaml> [--iterations N] [--timeout SEC]

# Evidence mode (requires invariants)
zk-fuzzer evidence <campaign.yaml> [--iterations N]

# Multi-step chain fuzzing (Mode 3)
zk-fuzzer chains <campaign.yaml> [--iterations N] [--timeout SEC]

# Validate config
zk-fuzzer validate <campaign.yaml>

# Minimize corpus
zk-fuzzer minimize <corpus_dir> [--output <dir>]

# Generate sample config
zk-fuzzer init [--output <file>] [--framework <framework>]
```

### 6.3 Profiles

| Profile | Iterations | Use Case |
|---------|------------|----------|
| quick | 10,000 | Fast triage |
| standard | 100,000 | Balanced (default) |
| deep | 1,000,000 | Thorough analysis |
| perf | 5,000,000 | Performance testing |

---

## 7. Three Scan Modes

### 7.1 Mode 1: Fast Skimmer
**Purpose:** Rapid surface coverage to identify obvious issues

**Characteristics:**
- Minimal YAML config
- Broad oracles, low iteration counts
- 5-10 minutes per target
- Output: High-signal findings list

**Use When:**
- First pass on new target
- Triage/comparison of multiple targets

### 7.2 Mode 2: YAML Deeper Searcher
**Purpose:** Deeper fuzzing with targeted oracles

**Characteristics:**
- Target-specific YAML with signals/constraints
- Increased iterations and sampling
- Evidence runs with reproduction

**Use When:**
- Fast Skimmer finds promising areas
- Better signal-to-noise needed

### 7.3 Mode 3: YAML Deepest Searcher (Multi-Step)
**Purpose:** Logic-based 0-day discovery via multi-step chains

**Characteristics:**
- Modular YAML with event chains
- State transitions and cross-invariant checks
- High-confidence PoCs with L_min metrics

**Use When:**
- Logic-based 0-day discovery
- Complex state/multi-step workflows

---

## 8. AI Pentest Workflow

Per `docs/AI_PENTEST_RULES.md`:

### Phase 1: Skimmer
- Rapid pattern identification
- `candidate_invariants.yaml` output
- 3-10 candidate invariants with confidence

### Phase 2: Evidence Mode
- Only with v2 YAML including `invariants`
- Deterministic seed, bounded budget
- Required per finding:
  - Invariant name + relation
  - Witness inputs
  - Reproduction command

### Phase 3: Formal Verification (Picus)
- Run Picus on under-constraint hints
- Mark FORMALLY CONFIRMED if Picus outputs `unsafe`
- Downgrade to LIKELY FALSE POSITIVE if Picus outputs `safe`

### Phase 4: Deep Custom Fuzz
- Edge case hunting (all-zero, max values)
- Custom invariants for bricking scenarios
- Focused mutations

---

## 9. Evidence Mode

**Purpose:** Ensure all findings are cryptographically verified, not heuristic

### Features
- **Backend Verification:** Rejects mock executor
- **Oracle Validation:** Re-executes with fresh oracles
- **Cross-Oracle Correlation:** Groups by attack type
- **Proof-Level Evidence:** Generates cryptographic proofs

### Confidence Levels

| Level | Criteria | Meaning |
|-------|----------|---------|
| CRITICAL | 3+ oracles agree | Cryptographic proof generated |
| HIGH | 2+ oracles agree | Reproducible with mutation testing |
| MEDIUM | 1 oracle + validation | Passes validation |
| LOW | Heuristic only | No cross-validation |

### Canonical Command
```bash
cargo run --release -- evidence <campaign.yaml> \
  --seed 42 \
  --iterations 50000 \
  --timeout 1800 \
  --simple-progress
```

---

## 10. Testing Strategy

### 10.1 Test Categories

**Unit Tests:**
- Individual components in isolation
- Mock dependencies
- Fast execution (<1s per test)

**Integration Tests:**
- End-to-end fuzzing campaigns
- Real backend integration (marked `#[ignore]`)
- Deterministic with fixed seeds

**Realistic Tests:**
- Known vulnerable circuits (CVE suite)
- Regression tests for found bugs
- Performance benchmarks

### 10.2 CVE Test Suite
- **25+ known vulnerabilities**
- **92% detection rate**
- Includes Tornado Cash, Semaphore, Iden3 patterns

### 10.3 Ground Truth Test Suite
- 10 test circuits
- Regression tests
- Documentation

---

## 11. Key Dependencies

```toml
[dependencies]
# ZK Cryptography
ark-ff = "0.4"           # Finite field arithmetic
ark-bn254 = "0.4"        # BN254 curve
ark-relations = "0.4"    # R1CS relations

# Symbolic Execution
z3 = "0.12"              # SMT solver

# Async & Parallelism
tokio = "1.35"           # Async runtime
rayon = "1.8"            # Data parallelism

# Serialization
serde = "1.0"
serde_yaml = "0.9"
serde_json = "1.0"

# Fuzzing
arbitrary = "1.3"
proptest = "1.4"

# CLI & Reporting
clap = "4.4"
tracing = "0.1"
colored = "2.1"
indicatif = "0.17"

# Utilities
rand = "0.8"
sha2 = "0.10"
num-bigint = "0.4"
hex = "0.4"
```

---

## 12. Performance Characteristics

### 12.1 Bottlenecks
1. **Circuit Execution** - Dominates runtime (90%+)
   - Mitigation: Parallel workers, fast mock mode

2. **Corpus Lock Contention** - High with many workers
   - Mitigation: Read-heavy workload, batch updates

3. **Coverage Bitmap Updates** - Atomic operations
   - Mitigation: Per-worker bitmaps, periodic merge

### 12.2 Optimization Strategies

**Light Circuits (<1000 constraints):**
- Use 8+ workers
- Aggressive mutation rate
- Shorter timeouts

**Heavy Circuits (>100k constraints):**
- Use 2-4 workers
- Conservative mutations
- Longer timeouts
- Enable symbolic execution

---

## 13. Extension Points

### 13.1 Adding a New Backend

1. Implement `TargetCircuit` trait in `src/targets/`:
```rust
pub struct MyBackendTarget { }

impl TargetCircuit for MyBackendTarget {
    fn framework(&self) -> Framework { Framework::MyBackend }
    fn execute(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>>;
    fn prove(&self, witness: &[FieldElement]) -> Result<Vec<u8>>;
    fn verify(&self, proof: &[u8], public: &[FieldElement]) -> Result<bool>;
}
```

2. Add to `ExecutorFactory`
3. Update `Framework` enum

### 13.2 Adding a New Attack

1. Create module in `src/attacks/`:
```rust
pub struct MyAttack { config: MyAttackConfig }

impl Attack for MyAttack {
    fn run(&self, context: &AttackContext) -> Vec<Finding> {
        // Implementation
    }
}
```

2. Register in attack dispatcher
3. Add configuration schema to YAML

---

## 14. Known Issues & Limitations

### 14.1 Critical Issues from Code Review

1. **UnderconstrainedAttack Logic Flaw**
   - Hashes all outputs instead of only public interface
   - No check for `result.success` before hashing
   - **Location:** `attacks/underconstrained.rs`

2. **Evidence Confidence Model Inconsistency**
   - Single-oracle findings may be dropped
   - Cross-oracle threshold defaults to 2

3. **Oracle Independence**
   - Correlated oracles inflate confidence scores
   - Need oracle independence checking

4. **Constraint Inference**
   - Uses naive statistics (circular reasoning risk)
   - Uniqueness false positives

5. **Metamorphic Relations**
   - Some domain-inappropriate relations
   - Never trigger or false positive

### 14.2 Experimental Features

| Feature | Precision | Status |
|---------|-----------|--------|
| Constraint Inference | 75% | Needs hardening |
| Metamorphic Testing | 90% | Good |
| Spec Inference | 85% | Good |
| Constraint Slicing | Unknown | Needs validation |

### 14.3 Limitations

- **Scalability:** Unproven on circuits >1M constraints
- **False Positive Rate:** <10% but unknown on new target types
- **Mock Fallback Risk:** If `strict_backend=false`

---

## 15. Development Roadmap Status

### Completed ✅ (18 Milestones)
- Circom/Noir/Halo2/Cairo proof generation
- Mode 3 multi-step fuzzing (CLI + YAML)
- `--resume` flag for corpus persistence
- Config profiles (quick/standard/deep/perf)
- CVE test suite (25+ CVEs, 92% detection)
- False positive analysis (<10% FP rate)
- Benchmark suite (vs Circomspect/Ecne/Picus)
- Automated triage system (6-factor scoring)
- MEV/front-running attacks
- zkEVM-specific attacks
- Batch verification bypass attacks
- Recursive SNARK attacks
- Ground truth test suite

### In Progress 🚧
- Real-circuit coverage automation (Cairo)
- YAML v2 profiles/includes/invariants
- Bug bounty campaigns (Q4 2026)

### Future Targets
- 5+ real 0-day vulnerabilities
- $25K+ bug bounties
- 90%+ detection rate maintained
- Research paper submission

---

## 16. Usage Examples

### Basic Usage
```bash
# Run a fuzzing campaign
cargo run --release -- run tests/campaigns/mock_merkle_audit.yaml

# Evidence mode
cargo run --release -- evidence campaign.yaml --seed 42 --iterations 50000

# Chain fuzzing (Mode 3)
cargo run --release -- chains campaign.yaml --iterations 100000

# With options
cargo run --release -- run campaign.yaml --workers 8 --seed 12345 --verbose
```

### Campaign Configuration Example
```yaml
campaign:
  name: "Merkle Tree Audit"
  version: "1.0"
  target:
    framework: circom
    circuit_path: "./circuits/merkle.circom"
    main_component: "MerkleTreeChecker"
  parameters:
    field: bn254
    timeout_seconds: 300
    additional:
      strict_backend: true
      evidence_mode: true

attacks:
  - type: underconstrained
    config:
      witness_pairs: 1000
      public_input_names: ["root", "nullifier"]

inputs:
  - name: "leaf"
    type: "field"
    fuzz_strategy: random
  - name: "pathElements"
    type: "field[]"
    length: 20

reporting:
  output_dir: "./reports"
  formats: ["json", "markdown"]
```

---

## 17. Security Considerations

### 17.1 What ZkPatternFuzz Detects
- ❌ Underconstrained circuits
- ❌ Missing range checks
- ❌ Arithmetic overflows
- ❌ Information leaks
- ❌ Proof malleability
- ❌ Verification bypass

### 17.2 What It Cannot Prove
- ✅ Absence of bugs (fuzzing is incomplete)
- ✅ Full formal correctness

**Recommendation:** Combine with formal verification for complete assurance.

---

## 18. Contributing

**Quick Start:**
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Make changes and add tests
4. Ensure `cargo test` and `cargo clippy` pass
5. Commit (`git commit -m 'feat: add amazing feature'`)
6. Push (`git push origin feature/amazing-feature`)
7. Open Pull Request

**Areas Needing Help:**
- Cairo real-circuit integration
- YAML v2 profiles/invariants/includes
- Additional attack patterns
- Documentation and examples
- Performance optimizations

---

## 19. References

- [Circom Documentation](https://docs.circom.io/)
- [Noir Documentation](https://noir-lang.org/)
- [Halo2 Documentation](https://zcash.github.io/halo2/)
- [Trail of Bits ZK Security](https://blog.trailofbits.com/tag/zero-knowledge-proofs/)
- [0xPARC ZK Bug Tracker](https://github.com/0xPARC/zk-bug-tracker)

---

## 20. Citation

If you use ZkPatternFuzz in your research:
```
teycirbensoltane.tn
```

---

**End of Document**

*This document provides a comprehensive overview of ZkPatternFuzz for audit and enhancement purposes. For the latest information, refer to the repository's README.md, ARCHITECTURE.md, and ROADMAP.md files.*
