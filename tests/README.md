# ZK-Fuzzer Test Campaigns

This directory contains fuzzing campaign configurations for testing real-world ZK circuits.

## Real-World Test Targets

The campaigns in this directory target circuits from `/media/elements/Repos/zk0d`, organized by category:

### Privacy Protocols (`cat3_privacy/`)
| Campaign | Target | Priority |
|----------|--------|----------|
| `semaphore_audit.yaml` | Semaphore identity protocol | Critical |
| `tornado_core_audit.yaml` | Tornado Cash mixer | Critical |
| `iden3_auth_audit.yaml` | Iden3 authentication | High |

### Rollup Infrastructure (`cat2_rollups/`)
| Campaign | Target | Priority |
|----------|--------|----------|
| `polygon_zkevm_audit.yaml` | Polygon zkEVM circuits | Critical |

## Running Campaigns

### Quick Start

```bash
# Run a single campaign
cargo run --release -- run tests/campaigns/semaphore_audit.yaml

# Validate configuration without executing
cargo run -- validate tests/campaigns/tornado_core_audit.yaml

# Run with verbose output and custom seed
cargo run --release -- run tests/campaigns/iden3_auth_audit.yaml --verbose --seed 42
```

### Running All Campaigns

```bash
# Run all real-world campaigns
for campaign in tests/campaigns/*_audit.yaml; do
    echo "Running: $campaign"
    cargo run --release -- run "$campaign" --workers 8
done
```

## Campaign Structure

Each campaign YAML follows this structure:

```yaml
campaign:
  name: "Human readable name"
  target:
    framework: circom | noir | halo2
    circuit_path: "/path/to/circuit"
    main_component: "MainComponent"

attacks:
  - type: underconstrained | soundness | collision | arithmetic_overflow | boundary
    description: "What this attack tests"
    config: { ... }

inputs:
  - name: "input_name"
    type: field | array[N] | bytes
    fuzz_strategy: random | mutation | interesting_values
```

## Attack Types

| Attack Type | Description | Severity |
|-------------|-------------|----------|
| `underconstrained` | Finds multiple witnesses for same output | Critical |
| `soundness` | Attempts to forge invalid proofs | Critical |
| `collision` | Searches for hash/output collisions | Critical |
| `arithmetic_overflow` | Tests field arithmetic boundaries | High |
| `boundary` | Tests input/parameter boundaries | Medium |

## Adding New Campaigns

1. Identify the circuit in `/media/elements/Repos/zk0d/`
2. Analyze the circuit's inputs and outputs
3. Create a campaign YAML with appropriate attacks
4. Test with `validate` command first
5. Run and iterate on configuration

## Mock vs Real Execution

Currently, backend integrations fall back to mock execution. To test with real backends:

1. **Circom**: Requires circom compiler and snarkjs
2. **Noir**: Requires Noir compiler (nargo)  
3. **Halo2**: Requires Rust halo2 crate integration

See `src/executor/mod.rs` for backend status.

## Reports

Reports are generated in the configured `output_dir` with:
- `findings.json` - Machine-readable vulnerability data
- `report.md` - Human-readable summary
- `corpus/` - Interesting test cases for further analysis
