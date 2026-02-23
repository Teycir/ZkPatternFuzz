# ZkPatternFuzz Documentation Index

Complete guide to all documentation files, ordered by use case and reading level.

## 🔒 AI Pentest Rule (Read First)

### 0. [AI_PENTEST_RULES.md](AI_PENTEST_RULES.md) - **Required**
**For:** Any AI agent running pentests  
**Contains:**
- Evidence > hints rule
- Skimmer -> evidence -> deep custom phases
- Reporting rules and PoC requirements

**Start here if:** You're starting a new pentest session

### 0b. [scan_modes.md](scan_modes.md) - **Required**
**For:** Any AI agent selecting a scan mode  
**Contains:**
- YAML-only scanner model
- Pattern classes (always-run simple + target-dependent deep)
- Catalog/alias execution guidance and mono/multi compatibility

**Start here if:** You need to pick a scan mode

### 0c. [scan_metrics.md](scan_metrics.md)
**For:** Comparing scan modes and maturity levels  
**Contains:**
- Metrics formulas and definitions
- Mode distinction criteria
- Plain-English summary

**Start here if:** You want to compare modes quantitatively

## 🚀 Getting Started

### 1. [QUICKSTART_AI.md](QUICKSTART_AI.md) - **5 min read**
**For:** Anyone wanting to fuzz a circuit immediately  
**Contains:**
- 3-step setup process
- Single AI prompt template
- Copy-paste ready examples
- Minimal configuration

**Start here if:** You have a circuit and want results fast

---

### 2. [README.md](../README.md) - **10 min read**
**For:** Understanding what ZkPatternFuzz does  
**Contains:**
- Feature overview
- Installation instructions
- Basic usage examples
- Project structure

**Start here if:** You're new to the project

---

### 2b. [BEST_USE_CASES.md](BEST_USE_CASES.md) - **5 min read**
**For:** Choosing the right targets and workflows  
**Contains:**
- Ideal target characteristics
- Recommended workflows by mode
- High-value use cases
- When ZkPatternFuzz is less effective

**Start here if:** You want to pick the most effective use cases quickly

---

## 📚 Detailed Guides

### 3. [VULNERABILITIES.md](VULNERABILITIES.md) - **15 min read**
**For:** Understanding what bugs ZkPatternFuzz can find  
**Contains:**
- 7 critical vulnerability classes
- Real-world examples (Tornado Cash, Semaphore, etc.)
- Detection rates and false positive rates
- Attack configurations for each vulnerability
- Vulnerability statistics

**Start here if:** You want to know what this tool actually finds

---

### 4. [TUTORIAL.md](TUTORIAL.md) - **30 min read**
**For:** Step-by-step learning with hands-on examples  
**Contains:**
- Detailed walkthrough
- Multiple circuit examples
- Common patterns
- Best practices
- Performance tips

**Start here if:** You prefer learning by doing

---

### 5. [TARGETS.md](TARGETS.md) - **Target List**
**For:** Running evidence campaigns on zk0d  
**Contains:**
- Target set for discovery metric
- Batch runner usage

---

### 5b. [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) - **Release Gate**
**For:** RC and production releases  
**Contains:**
- release readiness checklist
- benchmark/stability gate commands
- rollback sign-off requirements

---

### 5c. [TROUBLESHOOTING_PLAYBOOK.md](TROUBLESHOOTING_PLAYBOOK.md) - **Operations Guide**
**For:** Debugging failing runs quickly  
**Contains:**
- keygen failure recovery
- include path fixes
- lock contention mitigation
- timeout tuning and reason-code triage

---

### 5d. [PLUGIN_SYSTEM_GUIDE.md](PLUGIN_SYSTEM_GUIDE.md) - **Plugin Safety Guide**
**For:** Loading external attack plugins safely in strict engagements  
**Contains:**
- plugin discovery path rules
- strict-mode plugin behavior
- production hardening defaults
- troubleshooting for load/registry failures

---

### 5e. [NOIR_BACKEND_TROUBLESHOOTING.md](NOIR_BACKEND_TROUBLESHOOTING.md) - **Noir Ops Guide**
**For:** Diagnosing Noir readiness and integration failures  
**Contains:**
- Noir fast health checks
- common reason-code triage
- single-target repro command path
- readiness lane + gate checklist

---

### 5f. [CAIRO_INTEGRATION_TUTORIAL.md](CAIRO_INTEGRATION_TUTORIAL.md) - **Cairo Integration**
**For:** Wiring Cairo targets into readiness lanes and release gates  
**Contains:**
- Cairo prerequisites and first run
- matrix/alias configuration pattern
- readiness lane execution and artifacts
- promotion criteria into aggregate gate

---

### 5g. [HALO2_REAL_EXECUTION_MIGRATION.md](HALO2_REAL_EXECUTION_MIGRATION.md) - **Halo2 Migration**
**For:** Moving campaigns from testing mode to real Halo2 execution  
**Contains:**
- testing-to-real migration steps
- JSON spec and Cargo target setup
- integration test and lane commands
- common runtime/preflight pitfalls

---

### 5h. [ATTACK_DSL_SPEC.md](ATTACK_DSL_SPEC.md) - **Attack Config Spec**
**For:** Authoring and validating `attacks` DSL in campaign YAML  
**Contains:**
- normative attack schema
- supported attack type vocabulary
- schedule linkage semantics
- validation workflow

---

### 5i. [SEMANTIC_ANALYSIS_OPERATOR_GUIDE.md](SEMANTIC_ANALYSIS_OPERATOR_GUIDE.md) - **Semantic Ops Runbook**
**For:** Running invariants, witness-extension, and Halo2 lookup semantic checks reproducibly  
**Contains:**
- invariant validation + checker commands
- witness-extension regression workflow
- Halo2 Plookup integration test workflow
- semantic signoff checklist

---

## 🤖 AI Integration

### 5.5. [MISTRAL_AI_INTEGRATION.md](MISTRAL_AI_INTEGRATION.md) - **15 min read**
**For:** Using AI-assisted pentesting features   
**Contains:**
- Mistral AI configuration guide
- AI assistance modes explained
- Pattern-based invariant generation
- Result analysis and recommendations
- YAML configuration generation
- Best practices and examples

**Start here if:** You want to enable AI-assisted security analysis

---

## 🏗️ Architecture & Development

### 6. [ARCHITECTURE.md](../ARCHITECTURE.md) - **45 min read**
**For:** Understanding internal design and extending the tool  
**Contains:**
- System architecture
- Module descriptions
- Extension points
- Plugin system
- Data flow diagrams

**Start here if:** You want to contribute or extend ZkPatternFuzz

---

## 📋 Reference

### 7. [CHANGELOG.md](../CHANGELOG.md)
**For:** Version history and release notes  
**Contains:**
- Version history
- New features per release
- Breaking changes
- Migration guides

**Start here if:** You need to know what changed

---

### 8. [CONTRIBUTING.md](../CONTRIBUTING.md)
**For:** Contributing to the project  
**Contains:**
- Development setup
- Code style guidelines
- Testing requirements
- PR process

**Start here if:** You want to contribute code

---

## 🎯 Quick Reference by Use Case

### I want to fuzz a circuit RIGHT NOW
1. Read: [QUICKSTART_AI.md](QUICKSTART_AI.md) (5 min)
2. Run: `cargo build --release`
3. Ask AI to generate YAML
4. Execute: `cargo run -- --config campaign.yaml`

### I want to understand all options
1. Read: [TUTORIAL.md](TUTORIAL.md) (30 min)
2. Reference: Example campaigns in `tests/campaigns/`
3. Customize: Attack types and strategies

### I want to learn by example
1. Read: [TUTORIAL.md](TUTORIAL.md) (30 min)
2. Try: Example campaigns in `tests/campaigns/`
3. Modify: Adapt examples to your circuits

### I want to extend the tool
1. Read: [ARCHITECTURE.md](../ARCHITECTURE.md) (45 min)
2. Study: `src/` module structure
3. Implement: New attack types or backends

### I want to contribute
1. Read: [CONTRIBUTING.md](../CONTRIBUTING.md)
2. Setup: Development environment
3. Submit: Pull request

---

## 📊 Documentation Map

```
docs/
├── INDEX.md (this file)
│   └── Navigation hub for all docs
│
├── scan_modes.md
│   └── YAML scanner model and catalog execution rules
│
├── scan_metrics.md
│   └── Metrics to compare modes and maturity
│
├── QUICKSTART_AI.md ⭐ START HERE
│   └── 3-step setup with AI
│
├── VULNERABILITIES.md
│   └── 7 critical vulnerability classes
│
├── TUTORIAL.md
│   ├── Hands-on examples
│   ├── Best practices
│   └── Performance tips
│
├── RELEASE_CHECKLIST.md
│   └── Release readiness + rollback checklist
│
├── TROUBLESHOOTING_PLAYBOOK.md
│   └── Keygen/includes/locks/timeouts triage
│
├── PLUGIN_SYSTEM_GUIDE.md
│   └── Dynamic plugin discovery, strict behavior, hardening defaults
│
├── NOIR_BACKEND_TROUBLESHOOTING.md
│   └── Noir readiness triage and reason-code diagnostics
│
├── CAIRO_INTEGRATION_TUTORIAL.md
│   └── Cairo target onboarding into readiness lanes
│
├── HALO2_REAL_EXECUTION_MIGRATION.md
│   └── Testing-to-real Halo2 migration workflow
│
├── ATTACK_DSL_SPEC.md
│   └── Campaign attack DSL and validation contract
│
└── (See root directory for more)
    ├── README.md
    ├── ARCHITECTURE.md
    ├── CHANGELOG.md
    ├── CONTRIBUTING.md
    └── LICENSE
```

---

## 🔍 Finding What You Need

### By Topic

**Installation & Setup**
- [README.md](../README.md) - Installation section
- [QUICKSTART_AI.md](QUICKSTART_AI.md) - Quick setup

**Using the Tool**
- [QUICKSTART_AI.md](QUICKSTART_AI.md) - Fastest way to start
- [TUTORIAL.md](TUTORIAL.md) - Detailed walkthrough

**YAML Configuration**
- [tests/campaigns/](../tests/campaigns/) - Real examples
- `cargo run --bin zk0d_config_migrate -- <config.yaml> --check` - Legacy-shape migration check
- [ATTACK_DSL_SPEC.md](ATTACK_DSL_SPEC.md) - Attack schema and type vocabulary

**Attack Types**
- [README.md](../README.md) - Attack type summary
- [src/oracles/](../src/oracles/) - Implementation details
- [ATTACK_DSL_SPEC.md](ATTACK_DSL_SPEC.md) - `attacks` DSL reference

**Development**
- [ARCHITECTURE.md](../ARCHITECTURE.md) - System design
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guide
- [src/](../src/) - Source code

**Troubleshooting**
- [TROUBLESHOOTING_PLAYBOOK.md](TROUBLESHOOTING_PLAYBOOK.md) - Production troubleshooting flows
- [TUTORIAL.md](TUTORIAL.md) - Common issues
- [NOIR_BACKEND_TROUBLESHOOTING.md](NOIR_BACKEND_TROUBLESHOOTING.md) - Noir backend diagnostics
- [HALO2_REAL_EXECUTION_MIGRATION.md](HALO2_REAL_EXECUTION_MIGRATION.md) - Halo2 migration pitfalls

---

## 📖 Reading Paths

### Path 1: "I just want to fuzz" (15 minutes)
```
QUICKSTART_AI.md
    ↓
Ask AI to generate YAML
    ↓
Run fuzzer
    ↓
Done!
```

### Path 2: "I want to understand everything" (2 hours)
```
README.md
    ↓
QUICKSTART_AI.md
    ↓
TUTORIAL.md
    ↓
ARCHITECTURE.md
    ↓
Source code
```

### Path 3: "I want to contribute" (3 hours)
```
README.md
    ↓
ARCHITECTURE.md
    ↓
CONTRIBUTING.md
    ↓
Source code
    ↓
Submit PR
```

### Path 4: "I want to learn by doing" (1 hour)
```
QUICKSTART_AI.md
    ↓
TUTORIAL.md
    ↓
Try examples
    ↓
Modify for your circuits
```

---

## 🎓 Learning Resources

### External Resources

**ZK Fundamentals**
- [Circom Documentation](https://docs.circom.io/)
- [Noir Documentation](https://noir-lang.org/)
- [Halo2 Documentation](https://zcash.github.io/halo2/)
- [Cairo Documentation](https://docs.starkware.co/starkex/index.html)

**Security Testing**
- [AFL Fuzzing](https://github.com/google/AFL)
- [LibFuzzer](https://llvm.org/docs/LibFuzzer.html)
- [Trail of Bits ZK Security](https://blog.trailofbits.com/tag/zero-knowledge-proofs/)

**SMT Solving**
- [Z3 Documentation](https://github.com/Z3Prover/z3)
- [SMT-LIB Standard](http://www.smtlib.org/)

---

## ✅ Checklist: Before You Start

- [ ] Rust 1.70+ installed (`rustc --version`)
- [ ] Z3 SMT solver installed (`z3 --version`)
- [ ] ZkPatternFuzz cloned locally
- [ ] Your circuit code ready (Circom/Noir/Halo2/Cairo)
- [ ] AI access (Claude/ChatGPT) for YAML generation

---

## 🆘 Getting Help

1. **Quick question?** → Check [QUICKSTART_AI.md](QUICKSTART_AI.md)
2. **Configuration issue?** → Read [TUTORIAL.md](TUTORIAL.md)
3. **Want to learn?** → Read [TUTORIAL.md](TUTORIAL.md)
4. **Found a bug?** → Open GitHub issue with circuit + YAML
5. **Want to contribute?** → Read [CONTRIBUTING.md](../CONTRIBUTING.md)

---

## 📝 Document Versions

| Document | Last Updated | Status |
|----------|--------------|--------|
| QUICKSTART_AI.md | 2025-01-XX | ✅ Current |
| TUTORIAL.md | 2025-01-XX | ✅ Current |
| README.md | 2025-01-XX | ✅ Current |
| ARCHITECTURE.md | 2025-01-XX | ✅ Current |

---

## 🔗 Quick Links

- **GitHub:** https://github.com/yourusername/ZkPatternFuzz
- **Issues:** https://github.com/yourusername/ZkPatternFuzz/issues
- **Discussions:** https://github.com/yourusername/ZkPatternFuzz/discussions
- **Examples:** [tests/campaigns/](../tests/campaigns/)
- **Source:** [src/](../src/)

---

**Last Updated:** January 2025  
**License:** BSL 1.1 (converts to Apache 2.0 in 2028)
