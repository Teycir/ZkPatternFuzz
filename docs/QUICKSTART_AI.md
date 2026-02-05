# Quick Start: AI-Assisted Fuzzing

## One-Command Setup

### Step 1: Clone ZkPatternFuzz
```bash
git clone https://github.com/yourusername/ZkPatternFuzz.git
cd ZkPatternFuzz
cargo build --release
```

### Step 2: Ask AI to Generate Config

**Prompt for Claude/ChatGPT:**

```
I have ZkPatternFuzz cloned locally at: /home/user/ZkPatternFuzz

I want to fuzz this circuit:

[PASTE YOUR CIRCUIT CODE HERE]

Please:
1. Read the example campaigns in /home/user/ZkPatternFuzz/tests/campaigns/
2. Read the schema in /home/user/ZkPatternFuzz/docs/AI_ASSISTED_WORKFLOW.md
3. Generate a complete campaign YAML for my circuit
4. Tell me the exact command to run

Framework: [circom/noir/halo2/cairo]
Circuit path: [path to your circuit file]
```

### Step 3: Run Fuzzer

AI will give you something like:

```bash
cd /home/user/ZkPatternFuzz
cargo run --release -- --config campaign.yaml
```

### Step 4: Check Results

```bash
cat reports/report.md
```

## That's It!

The AI will:
- ✅ Read ZkPatternFuzz docs and examples
- ✅ Analyze your circuit
- ✅ Generate optimized YAML config
- ✅ Provide exact run command

No manual YAML writing needed!

## Example Session

**You:**
```
I have ZkPatternFuzz at ~/ZkPatternFuzz

Fuzz this Circom circuit at ~/circuits/vote.circom:

template Vote() {
    signal input voter;
    signal input choice;
    signal output nullifier;
    
    nullifier <== Poseidon([voter, choice]);
}

Generate campaign YAML and run command.
```

**AI:**
```yaml
# campaign.yaml
campaign:
  name: "Vote Circuit Audit"
  version: "1.0"
  target:
    framework: "circom"
    circuit_path: "~/circuits/vote.circom"
    main_component: "Vote"

attacks:
  - type: "underconstrained"
    description: "Find multiple voters producing same nullifier"
    config:
      witness_pairs: 1000

  - type: "collision"
    description: "Find nullifier collisions"
    config:
      samples: 100000

inputs:
  - name: "voter"
    type: "field"
    fuzz_strategy: "random"

  - name: "choice"
    type: "field"
    fuzz_strategy: "interesting_values"
    interesting: ["0x0", "0x1"]

reporting:
  output_dir: "./reports/vote_audit"
  formats: ["json", "markdown"]
```

Run with:
```bash
cd ~/ZkPatternFuzz
cargo run --release -- --config campaign.yaml
```

**Done!** Check `reports/vote_audit/report.md` for results.

## Tips

### For Claude Desktop Users
Use @-mentions to reference files:
```
@ZkPatternFuzz generate config for @my-circuit.circom
```

### For API Users
Include repo path in system prompt:
```python
system_prompt = """
You have access to ZkPatternFuzz at /path/to/repo.
Read examples from tests/campaigns/ before generating configs.
"""
```

### For Web Interface Users
1. Upload circuit file
2. Paste this guide's URL
3. Ask AI to generate config

## Troubleshooting

**AI can't find files?**
- Use absolute paths: `/home/user/ZkPatternFuzz`
- Or paste file contents directly

**Generated YAML has errors?**
```bash
# Validate before running
cargo run -- --config campaign.yaml --dry-run
```

**Need different attacks?**
Tell AI: "Focus on soundness and collision attacks only"

## Full Documentation

See [AI_ASSISTED_WORKFLOW.md](AI_ASSISTED_WORKFLOW.md) for:
- Complete YAML schema
- All attack types
- Advanced automation
- API integration examples
