# 0-Day Discovery Quickstart

This guide walks you through finding vulnerabilities in ZK circuits using ZkPatternFuzz.

## Prerequisites

1. **Rust toolchain** (1.70+)
2. **Circom compiler** (2.0+)
3. **snarkjs** (npm install -g snarkjs)
4. **Z3 solver** (apt install z3)

## Quick Start (5 Minutes)

### 1. Build the Fuzzer

```bash
cargo build --release
```

### 2. Pick a Target Repository

Example targets in `/media/elements/Repos/zk0d`:
- `cat3_privacy/tornado-core` - Tornado Cash mixer
- `cat3_privacy/semaphore` - Anonymous signaling
- `cat1_bridges/*` - Cross-chain bridges
- `cat2_rollups/*` - L2 rollups

### 3. Run the Skimmer (Phase 1)

```bash
./scripts/zeroday_workflow.sh skim /path/to/zk/repo
```

This produces:
- `reports/zk0d/skimmer/skimmer_summary.md` - Ranked list of candidate vulnerabilities
- `reports/zk0d/skimmer/candidate_invariants.yaml` - Stub invariants to fill in

### 4. Write Invariants (Manual Step)

Review the skimmer output and add invariants to your campaign YAML:

```yaml
invariants:
  - name: "path_index_binary"
    invariant_type: constraint
    relation: "pathIndices[i] in {0,1}"
    oracle: must_hold
    severity: "critical"
    description: "Merkle path indices must be binary"
```

### 5. Run Evidence Mode (Phase 3)

```bash
./scripts/zeroday_workflow.sh evidence campaigns/zk0d/tornado_withdraw_repo.yaml \
  --iterations 50000 \
  --timeout 1800 \
  --seed 42
```

### 6. Review Findings

Check `reports/zk0d/<target>/`:
- `report.json` - Machine-readable findings
- `report.md` - Human-readable summary
- `corpus/` - Interesting test cases

## Complete Workflow

```
┌──────────────────────────────────────────────────────────────┐
│                    0-DAY DISCOVERY FLOW                       │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. SKIM         ─────────────>  Hints (NOT confirmed)       │
│     ./scripts/zeroday_workflow.sh skim <repo>                │
│                                                              │
│  2. ANALYZE      ─────────────>  Manual invariant writing    │
│     Review hints, write invariants in YAML                   │
│                                                              │
│  3. EVIDENCE     ─────────────>  Bounded deterministic fuzz  │
│     ./scripts/zeroday_workflow.sh evidence <yaml>            │
│                                                              │
│  4. TRIAGE       ─────────────>  Confirm/Reject each finding │
│     Reproduce PoCs, verify invariant violations              │
│                                                              │
│  5. DEEP         ─────────────>  Edge-case hunting           │
│     ./scripts/zeroday_workflow.sh deep <yaml>                │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

## Example: Tornado Cash

### Ready-to-Run Campaign

```bash
# Validate
./target/release/zk-fuzzer validate campaigns/zk0d/tornado_withdraw_repo.yaml

# Run evidence mode
./scripts/zeroday_workflow.sh evidence campaigns/zk0d/tornado_withdraw_repo.yaml \
  --iterations 50000 \
  --timeout 1800
```

### Expected Output

```
════════════════════════════════════════════════════════════
  FUZZING REPORT: zk0d_tornado_withdraw_repo
════════════════════════════════════════════════════════════

STATISTICS
  Total Findings: 8343
  Coverage: 0.00%

FINDINGS BY TYPE
  ConstraintInference: 7743
  Metamorphic: 600
```

## Example: Semaphore

### Ready-to-Run Campaign

```bash
# Validate
./target/release/zk-fuzzer validate campaigns/zk0d/semaphore_repo.yaml

# Run evidence mode
./scripts/zeroday_workflow.sh evidence campaigns/zk0d/semaphore_repo.yaml \
  --iterations 50000 \
  --timeout 1800
```

## Classification Rules

| Status | Criteria |
|--------|----------|
| **CONFIRMED** | Invariant violated + Circuit accepts witness + Reproduction succeeds |
| **NOT CONFIRMED** | Hint only / No reproduction / Internal wires only |

**IMPORTANT:** Never report hints as confirmed findings. See [AI_PENTEST_RULES.md](AI_PENTEST_RULES.md).

## Available Campaigns

| Campaign | Target | Status |
|----------|--------|--------|
| `tornado_withdraw_repo.yaml` | Tornado Cash | ✅ Ready |
| `semaphore_repo.yaml` | Semaphore | ✅ Ready |
| `iden3_authv3_repo.yaml` | Iden3 Auth | ✅ Ready |

## Tips for 0-Day Hunting

### 1. Focus on Security-Critical Signals

- Nullifiers (double-spend prevention)
- Merkle roots (membership proofs)
- Range checks (overflow prevention)
- Signature components (malleability)

### 2. Write Targeted Invariants

```yaml
# Good: Specific, testable
- name: "nullifier_bits_248"
  relation: "nullifier < 2^248"
  severity: "critical"

# Bad: Too vague
- name: "secure_nullifier"
  relation: "nullifier is secure"
```

### 3. Use Edge-Case Values

```yaml
interesting:
  - "0x00"                    # Zero
  - "0x01"                    # One
  - "0x02"                    # Non-binary (for binary checks)
  - "0x30644e72e131a029..."  # Field modulus
```

### 4. Check Binary Constraints

Many circuits expect binary (0/1) values but don't enforce it:

```yaml
- name: "path_index_binary"
  relation: "pathIndices[i] in {0,1}"
  oracle: must_hold
```

## Next Steps

1. **Add custom campaigns** for your target circuits
2. **Expand invariants** based on findings
3. **Run deep fuzzing** with edge-case mutations
4. **Document confirmed findings** with PoCs

See also:
- [CLAUDE_PROMPT.md](CLAUDE_PROMPT.md) - AI-assisted YAML generation
- [AI_PENTEST_RULES.md](AI_PENTEST_RULES.md) - Classification rules
- [TARGETS.md](TARGETS.md) - Available targets
