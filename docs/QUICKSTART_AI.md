# Quickstart: AI-Assisted Adaptive Fuzzing

This guide shows how to use the **Opus Analyzer** and **Adaptive Orchestrator** to automatically fuzz ZK circuits and catch zero-day vulnerabilities.

## Prerequisites

```bash
cargo build --release
```

## Quick Start (3 Steps)

### Step 1: Point to Your ZK Project

```rust
use zk_fuzzer::fuzzer::AdaptiveOrchestratorBuilder;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let results = AdaptiveOrchestratorBuilder::new()
        .workers(4)
        .max_duration(Duration::from_secs(3600))  // 1 hour
        .zero_day_hunt_mode(true)
        .build()
        .run_adaptive_campaign("/path/to/your/zk/project")
        .await?;

    // Print results
    println!("Circuits analyzed: {}", results.circuits_analyzed);
    println!("Total findings: {}", results.total_findings.len());
    println!("Confirmed zero-days: {}", results.confirmed_zero_days.len());

    for zd in &results.confirmed_zero_days {
        println!("  [{:?}] in {}: {}", 
            zd.hint.category, 
            zd.circuit, 
            zd.finding.description
        );
    }

    Ok(())
}
```

### Step 2: The System Does Everything

1. **Opus scans** your project for `.circom`, `.nr`, `.cairo` files
2. **Detects patterns**: Merkle trees, nullifiers, signatures, hashes
3. **Identifies zero-day hints**: Missing constraints, range check issues
4. **Generates optimized YAML** configs for each circuit
5. **Runs adaptive fuzzing** with dynamic budget reallocation
6. **Reports confirmed vulnerabilities**

### Step 3: Review Results

Check the output directory:

```
./reports/adaptive/
├── configs/           # Generated YAML configurations
│   ├── circuit1.yaml
│   └── circuit2.yaml
├── circuit1/          # Per-circuit reports
│   ├── report.json
│   └── report.md
└── circuit2/
    └── ...
```

## CLI Usage

```bash
# Run adaptive campaign on a project
cargo run --release -- adaptive \
    --project /path/to/zk/project \
    --workers 4 \
    --duration 3600 \
    --output ./reports

# Analyze project without fuzzing
cargo run --release -- analyze \
    --project /path/to/zk/project \
    --output ./configs
```

## What Gets Detected

### Patterns

| Pattern | Attack Priority | Description |
|---------|-----------------|-------------|
| Merkle Tree | Collision | Tests for root collisions |
| Nullifier | Collision | Tests uniqueness |
| Signature | Soundness | Tests for forgery |
| Range Check | Overflow | Tests boundaries |
| Hash Function | Collision | Tests collision resistance |

### Zero-Day Categories

| Category | Confidence | Trigger |
|----------|------------|---------|
| Missing Constraint | 70% | `<--` without `<==` |
| Incorrect Range | 50% | Num2Bits without validation |
| Bit Decomposition | 60% | Missing binary constraint |
| Signature Malleability | 60% | Missing S normalization |
| Nullifier Reuse | 40% | Missing entropy |
| Hash Misuse | 40% | No domain separation |

## Advanced Configuration

```rust
use zk_fuzzer::analysis::OpusConfig;
use zk_fuzzer::fuzzer::adaptive_attack_scheduler::AdaptiveSchedulerConfig;

let config = AdaptiveOrchestratorConfig {
    opus_config: OpusConfig {
        max_files: 50,
        min_zero_day_confidence: 0.3,
        ..Default::default()
    },
    scheduler_config: AdaptiveSchedulerConfig {
        finding_points: 100.0,
        critical_finding_points: 200.0,
        ..Default::default()
    },
    workers: 8,
    max_duration: Duration::from_secs(7200),
    zero_day_hunt_mode: true,
    ..Default::default()
};

let orchestrator = AdaptiveOrchestrator::with_config(config);
```

## Integration with CI/CD

```yaml
# .github/workflows/zk-security.yml
name: ZK Security Audit

on:
  push:
    paths:
      - 'circuits/**'

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Adaptive Fuzzing
        run: |
          cargo run --release -- adaptive \
            --project ./circuits \
            --workers 4 \
            --duration 1800 \
            --output ./reports
      
      - name: Check for Critical Findings
        run: |
          if grep -q '"severity": "Critical"' ./reports/*/report.json; then
            echo "Critical vulnerabilities found!"
            exit 1
          fi
      
      - name: Upload Reports
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: ./reports/
```

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Adaptive Orchestrator                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Opus Analyzer                                                   │
│     ┌─────────┐    ┌─────────────┐    ┌──────────────┐            │
│     │ Scan    │───▶│ Detect      │───▶│ Generate     │            │
│     │ Project │    │ Patterns    │    │ YAML Config  │            │
│     └─────────┘    └─────────────┘    └──────────────┘            │
│           │              │                    │                    │
│           ▼              ▼                    ▼                    │
│     ┌─────────────────────────────────────────────┐               │
│     │          Zero-Day Hints Detection           │               │
│     └─────────────────────────────────────────────┘               │
│                                                                     │
│  2. Adaptive Fuzzing Loop                                          │
│     ┌─────────────┐    ┌─────────────┐    ┌───────────────┐       │
│     │ Run Attack  │───▶│ Check       │───▶│ Reallocate    │       │
│     │ Phase       │    │ Near-Misses │    │ Budget        │       │
│     └─────────────┘    └─────────────┘    └───────────────┘       │
│           │                   │                    │               │
│           └───────────────────┴────────────────────┘               │
│                              │                                      │
│                              ▼                                      │
│     ┌─────────────────────────────────────────────┐               │
│     │          Confirmed Zero-Days                │               │
│     └─────────────────────────────────────────────┘               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Troubleshooting

**No circuits found:**
- Check that circuit files have correct extensions (`.circom`, `.nr`, `.cairo`)
- Ensure project path is correct

**Low coverage:**
- Increase `max_duration`
- Enable symbolic execution in config

**False positives:**
- Increase `min_zero_day_confidence` threshold
- Review and filter YAML suggestions

## Next Steps

1. [Full AI-Assisted Workflow](AI_ASSISTED_WORKFLOW.md)
2. [Claude Prompt for YAML Generation](CLAUDE_PROMPT.md)
3. [Capability Matrix](CAPABILITY_MATRIX.md)
