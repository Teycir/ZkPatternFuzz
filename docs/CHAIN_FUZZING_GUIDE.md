# Chain Fuzzing Guide (Mode 3: Deepest)

**Version:** 1.0  
**Date:** February 2026  
**Status:** Production Ready

---

## Overview

Chain fuzzing (Mode 3) is ZkPatternFuzz's most powerful mode for discovering **protocol-level vulnerabilities** that require multiple circuit executions to trigger. Unlike single-circuit fuzzing, chain fuzzing explores **multi-step sequences** where bugs emerge from the interaction between operations.

## When to Use Chain Fuzzing

Use Mode 3 when targeting:

| Protocol Type | Example | Chain Pattern |
|---------------|---------|---------------|
| Privacy protocols | Tornado Cash | deposit → withdraw |
| Identity systems | Semaphore | register → signal |
| zkEVM rollups | Polygon zkEVM | approve → transferFrom |
| State machines | zkSync | mint → transfer → burn |
| Voting systems | MACI | register → vote → tally |

## Quick Start

```bash
# Run chain fuzzing with default settings
cargo run --release -- chains campaigns/templates/deepest_multistep.yaml

# With custom iterations and timeout
cargo run --release -- chains my_campaign.yaml \
  --iterations 50000 \
  --timeout 1800 \
  --seed 42

# Resume from previous run
cargo run --release -- chains my_campaign.yaml --resume
```

## YAML Schema

### Basic Chain Definition

```yaml
chains:
  - name: "deposit_then_withdraw"
    description: "Verify deposit and withdraw maintain invariants"
    steps:
      - circuit_ref: "deposit"
        input_wiring: fresh
        label: "Initial deposit"
      - circuit_ref: "withdraw"
        input_wiring:
          from_prior_output:
            step: 0
            mapping:
              - [0, 2]   # deposit.out[0] → withdraw.in[2]
              - [1, 3]   # deposit.out[1] → withdraw.in[3]
        label: "Withdrawal using deposit outputs"
    assertions:
      - name: "nullifier_uniqueness"
        relation: "unique(step[*].out[0])"
        severity: "critical"
```

### Multi-Circuit Configuration

When chains use different circuits, specify paths in the `circuits` map:

```yaml
chains:
  - name: "cross_circuit_chain"
    circuits:
      deposit:
        path: "./circuits/deposit.circom"
        main_component: "Deposit"
      withdraw:
        path: "./circuits/withdraw.circom"
        main_component: "Withdraw"
    steps:
      - circuit_ref: "deposit"
        input_wiring: fresh
      - circuit_ref: "withdraw"
        input_wiring:
          from_prior_output:
            step: 0
            mapping:
              - [0, 0]
```

### Input Wiring Types

| Type | Description | YAML Syntax |
|------|-------------|-------------|
| `fresh` | Generate random inputs | `input_wiring: fresh` |
| `from_prior_output` | Use outputs from previous step | `input_wiring: { from_prior_output: { step: 0, mapping: [[0,0]] } }` |
| `mixed` | Combine prior outputs with fresh values | `input_wiring: { mixed: { prior: [[0,0,0]], fresh_indices: [1,2] } }` |
| `constant` | Use fixed values | `input_wiring: { constant: { values: {0: "0x1234"}, fresh_indices: [1] } }` |

### Assertion Syntax

Assertions define invariants that must hold across chain steps:

```yaml
assertions:
  # Equality between steps
  - name: "output_consistency"
    relation: "step[0].out[1] == step[1].in[3]"
    severity: "high"

  # Uniqueness across all steps
  - name: "nullifier_unique"
    relation: "unique(step[*].out[0])"
    severity: "critical"

  # Success requirement
  - name: "must_verify"
    relation: "step[1].success == true"
    severity: "critical"

  # Inequality check
  - name: "different_outputs"
    relation: "step[0].out[0] != step[1].out[0]"
    severity: "medium"
```

## Metrics

Chain fuzzing produces specialized metrics:

| Metric | Description |
|--------|-------------|
| **L_min** | Minimum chain length to reproduce bug |
| **D** | Mean depth of findings (higher = deeper bugs) |
| **P_deep** | Probability of finding requiring L_min ≥ 2 |

### Interpreting Results

```
DEPTH METRICS
  Total Chain Findings:  3
  Mean L_min (D):        2.33
  P(L_min >= 2):         66.7%

DEPTH DISTRIBUTION
  L_min=2: ███████████████ (2)
  L_min=3: ████████ (1)
```

- **High D (>2)**: Fuzzer is finding deep bugs that span multiple operations
- **High P_deep (>50%)**: Most bugs require multi-step sequences to trigger
- **L_min=1**: Bug detectable in single circuit (may not need chain fuzzing)

## Real-World Examples

### Tornado Cash: Deposit → Withdraw

```yaml
chains:
  - name: "tornado_double_spend"
    description: "Attempt nullifier reuse across withdraw operations"
    circuits:
      withdraw:
        path: "./circuits/withdraw.circom"
        main_component: "Withdraw"
    steps:
      - circuit_ref: "withdraw"
        input_wiring: fresh
        label: "First withdrawal"
      - circuit_ref: "withdraw"
        input_wiring:
          from_prior_output:
            step: 0
            mapping:
              - [0, 0]   # Reuse nullifier
        label: "Second withdrawal (should fail)"
    assertions:
      - name: "no_double_spend"
        relation: "step[1].success == false"
        severity: "critical"
        description: "Second withdrawal with same nullifier must fail"
```

### Semaphore: Register → Signal

```yaml
chains:
  - name: "semaphore_identity_chain"
    circuits:
      register:
        path: "./circuits/semaphore.circom"
        main_component: "Register"
      signal:
        path: "./circuits/semaphore.circom"
        main_component: "Signal"
    steps:
      - circuit_ref: "register"
        input_wiring: fresh
      - circuit_ref: "signal"
        input_wiring:
          from_prior_output:
            step: 0
            mapping:
              - [0, 0]   # identity_commitment
              - [1, 1]   # nullifier_hash
    assertions:
      - name: "identity_binding"
        relation: "step[0].out[0] == step[1].in[0]"
        severity: "high"
```

### zkEVM: Approve → TransferFrom

```yaml
chains:
  - name: "erc20_approve_transfer"
    steps:
      - circuit_ref: "approve"
        input_wiring: fresh
        label: "Set allowance"
      - circuit_ref: "transferFrom"
        input_wiring:
          mixed:
            prior:
              - [0, 0, 0]   # spender
              - [0, 1, 1]   # amount
            fresh_indices: [2, 3]  # from, to
        label: "Transfer using allowance"
    assertions:
      - name: "allowance_respected"
        relation: "step[1].in[1] <= step[0].out[1]"
        severity: "critical"
```

## Advanced Configuration

### Schedule for Phased Execution

```yaml
schedule:
  - phase: "chain_seed"
    duration_sec: 120
    attacks: ["underconstrained"]
    early_terminate:
      on_critical_findings: 3

  - phase: "chain_deep"
    duration_sec: 600
    attacks: ["underconstrained", "collision"]
    carry_corpus: true
```

### Performance Tuning

```yaml
campaign:
  parameters:
    additional:
      # Chain-specific settings
      chain_budget_seconds: 600      # Per-chain time budget
      chain_iterations: 5000         # Iterations per chain
      chain_shrink_max_attempts: 100 # Minimization attempts
      
      # General performance
      per_exec_isolation: false      # Faster execution
```

## Troubleshooting

### "Chain mode requires chains: definitions"

Add a `chains:` section to your YAML. See templates in `campaigns/templates/deepest_multistep.yaml`.

### "Circuit not found for circuit_ref"

Ensure each `circuit_ref` in steps has a corresponding entry in the `circuits` map, or use the default `campaign.target.circuit_path`.

### "Input wiring mismatch"

The mapping array `[[output_idx, input_idx]]` must reference valid output/input indices. Check circuit interfaces.

### Low P_deep or no findings

- Increase iterations: `--iterations 100000`
- Increase timeout: `--timeout 3600`
- Add more specific assertions targeting known invariants
- Review input wiring to ensure proper data flow between steps

## Output Files

After running chain fuzzing, reports are saved to:

```
reports/
└── <campaign_name>/
    ├── chain_report.json   # Machine-readable findings
    ├── chain_report.md     # Human-readable report
    ├── report.json         # Standard fuzzing report
    └── report.md           # Standard markdown report
```

## Best Practices

1. **Start with known invariants**: Define assertions based on protocol documentation
2. **Use deterministic seeds**: `--seed 42` for reproducible findings
3. **Profile first**: Run `--profile quick` to validate configuration
4. **Layer depth gradually**: Start with 2-step chains, expand to 3+ if needed
5. **Combine with single-circuit**: Run Mode 2 first to find surface bugs

## Related Documentation

- [TUTORIAL.md](./TUTORIAL.md)
- [Scan Modes Overview](./scan_modes.md)
- [Depth Metrics](./scan_metrics.md)
- [TARGETS.md](./TARGETS.md)
- [Profile Guide](./PROFILES_GUIDE.md)

---

**Need help?** Open an issue on GitHub or check the examples in `campaigns/templates/deepest_multistep.yaml`.
