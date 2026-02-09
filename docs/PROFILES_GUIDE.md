# Configuration Profiles Guide

ZkPatternFuzz includes embedded configuration profiles that simplify campaign
setup by providing sensible defaults for common use cases.

## Quick Start

```bash
# Fast triage (10K iterations)
cargo run -- run campaign.yaml --profile quick

# Balanced audit (100K iterations, default for evidence mode)
cargo run -- run campaign.yaml --profile standard

# Deep analysis (1M iterations)
cargo run -- evidence campaign.yaml --profile deep
```

## Profile Comparison

| Setting                  | Quick      | Standard   | Deep        |
|--------------------------|------------|------------|-------------|
| `max_iterations`         | 10,000     | 100,000    | 1,000,000   |
| `strict_backend`         | false      | true       | true        |
| `evidence_mode`          | false      | true       | true        |
| `per_exec_isolation`     | false      | false      | true        |
| `constraint_guided`      | false      | true       | true        |
| `symbolic_max_depth`     | 50         | 200        | 1,000       |
| `oracle_validation`      | false      | true       | true        |
| `timeout_per_execution`  | 5s         | 30s        | 60s         |

## Profile Descriptions

### Quick Profile

**Purpose:** Fast exploration for initial triage

**When to use:**
- First pass on a new target
- Quickly identifying obvious issues
- Testing fuzzer configuration
- CI/CD integration with time constraints

**Limitations:**
- May miss deep bugs requiring more iterations
- No evidence generation
- Mock backend allowed (not cryptographically verified)

**Attacks enabled:** `boundary`, `arithmetic_overflow`, `underconstrained`

### Standard Profile

**Purpose:** Balanced fuzzing for production audits

**When to use:**
- Normal audit engagements
- Finding real vulnerabilities with evidence
- Most circuits under 100K constraints

**Features:**
- Evidence mode enabled (proof generation)
- Oracle validation (reduces false positives)
- Cross-oracle correlation
- Constraint-guided exploration

**Attacks enabled:** `underconstrained`, `soundness`, `boundary`, 
`arithmetic_overflow`, `collision`, `witness_validation`

### Deep Profile

**Purpose:** Thorough analysis for critical targets

**When to use:**
- High-value targets (bridges, major protocols)
- Bug bounty hunting
- After standard profile finds interesting areas
- Complex circuits with deep logic

**Features:**
- All attacks enabled
- Maximum symbolic execution depth
- Per-execution isolation (slower but safer)
- Extended timeout for complex circuits

**Attacks enabled:** `all`

## YAML Overrides

Profile settings can be overridden in your campaign YAML:

```yaml
campaign:
  parameters:
    additional:
      # Override profile setting
      max_iterations: 500000  # Use 500K instead of profile default
      symbolic_max_depth: 500  # Custom depth
```

The precedence order is:
1. CLI flags (highest priority)
2. YAML configuration
3. Profile defaults (lowest priority)

## Combining with Resume

Profiles work seamlessly with the `--resume` flag:

```bash
# Start with quick profile
cargo run -- run campaign.yaml --profile quick

# Resume with deeper settings
cargo run -- run campaign.yaml --profile deep --resume
```

## Custom Profiles via YAML

For more control, define profiles in your campaign YAML:

```yaml
profiles:
  my_custom:
    max_iterations: 250000
    strict_backend: true
    evidence_mode: true
    constraint_guided: true

# Activate the profile
active_profile: my_custom
```

## Programmatic Usage

```rust
use zk_fuzzer::config::{ProfileName, EmbeddedProfile, apply_profile};

// Get profile by name
let profile = EmbeddedProfile::by_name(ProfileName::Standard);

// Apply to config
let mut config = FuzzConfig::from_yaml("campaign.yaml")?;
apply_profile(&mut config, ProfileName::Deep);

// Or merge manually
profile.merge_into(&mut config.campaign.parameters.additional);
```

## Profile Selection Guidelines

```
┌─────────────────────────────────────────────────────────────┐
│                    Profile Selection                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  New target?                                                 │
│      └─> Start with QUICK                                   │
│              │                                               │
│              ▼                                               │
│  Found interesting areas?                                    │
│      └─> Switch to STANDARD                                 │
│              │                                               │
│              ▼                                               │
│  Need maximum coverage or bug bounty?                        │
│      └─> Use DEEP                                           │
│                                                              │
│  Evidence for report?                                        │
│      └─> STANDARD or DEEP (both have evidence_mode=true)    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## See Also

- [Resume Guide](./RESUME_GUIDE.md) - Continuing campaigns
- [Evidence Mode](./EVIDENCE_MODE.md) - Generating proof-level evidence
- [Attack Types](./ATTACK_TYPES.md) - Available attack vectors
