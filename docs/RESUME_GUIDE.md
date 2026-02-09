# Resume Guide

ZkPatternFuzz supports resuming campaigns from a saved corpus, allowing
long-running campaigns to survive interruptions and enabling incremental
deep exploration.

## Quick Start

```bash
# Initial run
cargo run -- run campaign.yaml --iterations 100000

# Resume from where we left off
cargo run -- run campaign.yaml --resume

# Resume with custom corpus directory
cargo run -- run campaign.yaml --resume --corpus-dir ./my_corpus
```

## How It Works

When a campaign runs, interesting test cases are saved to the corpus directory:

```
reports/
└── <campaign_name>/
    ├── corpus/
    │   ├── testcase_001.json
    │   ├── testcase_002.json
    │   └── ...
    ├── report.json
    └── report.md
```

With `--resume`, the fuzzer:
1. Loads all test cases from the corpus directory
2. Seeds the fuzzing corpus with loaded cases
3. Continues fuzzing from the loaded coverage state
4. Appends new interesting cases to the corpus

## Default Corpus Location

By default, corpus is saved to and loaded from:
```
<output_dir>/corpus/
```

Where `<output_dir>` comes from your campaign YAML:
```yaml
reporting:
  output_dir: "./reports"  # Corpus at ./reports/corpus/
```

## Custom Corpus Directory

Override the default with `--corpus-dir`:

```bash
# Save to a specific location
cargo run -- run campaign.yaml --iterations 50000

# Later, resume with explicit path
cargo run -- run campaign.yaml --resume --corpus-dir ./reports/corpus
```

## Resume Modes

### Evidence Mode

Resume works with evidence mode for long-running verification campaigns:

```bash
# Start evidence collection
cargo run -- evidence campaign.yaml --profile standard

# Resume evidence collection
cargo run -- evidence campaign.yaml --resume --profile deep
```

### Chain Mode

Chain fuzzing has built-in resume support:

```bash
# Chain fuzzing with resume
cargo run -- chains campaign.yaml --resume
```

## Corpus Management

### Viewing Corpus Contents

```bash
# List corpus entries
ls -la reports/corpus/

# View a test case
cat reports/corpus/testcase_001.json
```

### Minimizing Corpus

Remove redundant test cases while preserving coverage:

```bash
cargo run -- minimize ./reports/corpus/ --output ./reports/corpus_min/
```

### Merging Corpora

Combine corpora from multiple runs:

```bash
# Not yet a built-in command, but you can:
cp -r run1/corpus/* merged_corpus/
cp -r run2/corpus/* merged_corpus/
cargo run -- run campaign.yaml --resume --corpus-dir ./merged_corpus
```

## Use Cases

### Overnight Fuzzing

```bash
# Start a long campaign
cargo run -- run campaign.yaml --profile deep --iterations 1000000

# If interrupted (Ctrl+C, system restart), resume:
cargo run -- run campaign.yaml --resume --profile deep
```

### Incremental Analysis

```bash
# Quick pass first
cargo run -- run campaign.yaml --profile quick

# Deeper pass, building on quick results
cargo run -- run campaign.yaml --resume --profile standard

# Deepest pass for maximum coverage
cargo run -- run campaign.yaml --resume --profile deep
```

### Team Collaboration

```bash
# Developer A: initial fuzzing
cargo run -- run campaign.yaml --iterations 100000
# Share: reports/corpus/

# Developer B: continue from A's corpus
cargo run -- run campaign.yaml --resume --corpus-dir ./shared/corpus
```

## Progress Tracking

When resuming, the progress output shows:

```
📂 Resuming from corpus: ./reports/corpus
📥 Loaded 1,234 test cases from corpus
[====================] 100000/100000 iterations

STATISTICS
  Starting coverage: 45.2% (from corpus)
  Final coverage: 67.8%
  New edges discovered: 234
```

## Best Practices

1. **Use consistent seeds**: For reproducibility, use `--seed` when resuming:
   ```bash
   cargo run -- run campaign.yaml --seed 42
   cargo run -- run campaign.yaml --resume --seed 42
   ```

2. **Backup valuable corpora**: Before major changes:
   ```bash
   cp -r reports/corpus reports/corpus_backup_$(date +%Y%m%d)
   ```

3. **Minimize periodically**: Keep corpus lean:
   ```bash
   cargo run -- minimize ./reports/corpus -o ./reports/corpus_clean
   mv ./reports/corpus_clean ./reports/corpus
   ```

4. **Version control corpora**: For important campaigns:
   ```bash
   git add reports/corpus/*.json
   git commit -m "Corpus checkpoint after 500K iterations"
   ```

## Troubleshooting

### "Corpus directory not found"

```
⚠️  Corpus directory not found, starting fresh: ./reports/corpus
```

This means no previous corpus exists. The fuzzer will start fresh.

### Different Configurations

If you resume with different attack types or inputs, the old corpus entries
may not match. The fuzzer will:
- Load what it can
- Skip incompatible entries
- Continue with valid entries plus new exploration

### Seed Mismatch

Using a different seed when resuming changes the mutation sequence. This is
usually fine but may affect exact reproducibility.

## See Also

- [Profiles Guide](./PROFILES_GUIDE.md) - Pre-configured settings
- [Evidence Mode](./EVIDENCE_MODE.md) - Proof generation
- [Chain Fuzzing](./CHAIN_FUZZING_GUIDE.md) - Multi-step fuzzing
