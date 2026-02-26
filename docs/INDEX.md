# ZkPatternFuzz Documentation Index

Complete guide to all documentation files, ordered by use case and reading level.

## 🔒 AI Pentest Rule (Read First)

### 0a. [AGENTS.md](../AGENTS.md) - **Session Contract**
**For:** Every new agent session in this repository  
**Contains:**
- mandatory mission (find vulns, then prove exploitability or non-exploitability)
- required step-by-step flow
- definition of done and artifact requirements
- tooling expectations linked to host inventory

**Start here if:** You need per-session execution contract and completion criteria

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

### 1. [README.md](../README.md) - **10 min read**
**For:** Understanding what ZkPatternFuzz does  
**Contains:**
- Feature overview
- Installation instructions
- Basic usage examples
- Project structure

**Start here if:** You're new to the project

---

## 📚 Detailed Guides

### 2. [TUTORIAL.md](TUTORIAL.md) - **30 min read**
**For:** Step-by-step learning with hands-on examples  
**Contains:**
- Detailed walkthrough
- Multiple circuit examples
- Common patterns
- Best practices
- Performance tips

**Start here if:** You prefer learning by doing

---

### 3. [BACKEND_SETUP.md](BACKEND_SETUP.md) - **Backend Installation**
**For:** Installing and configuring ZK backends  
**Contains:**
- Circom/Noir/Halo2/Cairo installation
- Toolchain setup
- Verification steps

---

### 4. [TARGETS.md](TARGETS.md) - **Target Catalog**
**For:** Running evidence campaigns on zk0d  
**Contains:**
- Target set for discovery metric
- Batch runner usage

---

### 5. [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) - **Release Gate**
**For:** RC and production releases  
**Contains:**
- release readiness checklist
- benchmark/stability gate commands
- rollback sign-off requirements

---

### 6. [TROUBLESHOOTING_PLAYBOOK.md](TROUBLESHOOTING_PLAYBOOK.md) - **Operations Guide**
**For:** Debugging failing runs quickly  
**Contains:**
- keygen failure recovery
- include path fixes
- lock contention mitigation
- timeout tuning and reason-code triage

---

### 7. [PLUGIN_SYSTEM_GUIDE.md](PLUGIN_SYSTEM_GUIDE.md) - **Plugin Safety Guide**
**For:** Loading external attack plugins safely in strict engagements  
**Contains:**
- plugin discovery path rules
- strict-mode plugin behavior
- production hardening defaults
- troubleshooting for load/registry failures

---

### 8. [NOIR_BACKEND_TROUBLESHOOTING.md](NOIR_BACKEND_TROUBLESHOOTING.md) - **Noir Ops Guide**
**For:** Diagnosing Noir readiness and integration failures  
**Contains:**
- Noir fast health checks
- common reason-code triage
- single-target repro command path
- readiness lane + gate checklist

---

### 9. [CAIRO_INTEGRATION_TUTORIAL.md](CAIRO_INTEGRATION_TUTORIAL.md) - **Cairo Integration**
**For:** Wiring Cairo targets into readiness lanes and release gates  
**Contains:**
- Cairo prerequisites and first run
- matrix/alias configuration pattern
- readiness lane execution and artifacts
- promotion criteria into aggregate gate

---

### 10. [HALO2_REAL_EXECUTION_MIGRATION.md](HALO2_REAL_EXECUTION_MIGRATION.md) - **Halo2 Migration**
**For:** Moving campaigns from testing mode to real Halo2 execution  
**Contains:**
- testing-to-real migration steps
- JSON spec and Cargo target setup
- integration test and lane commands
- common runtime/preflight pitfalls

---

### 11. [ATTACK_DSL_SPEC.md](ATTACK_DSL_SPEC.md) - **Attack Config Spec**
**For:** Authoring and validating `attacks` DSL in campaign YAML  
**Contains:**
- normative attack schema
- supported attack type vocabulary
- schedule linkage semantics
- validation workflow

---

### 12. [SEMANTIC_ANALYSIS_OPERATOR_GUIDE.md](SEMANTIC_ANALYSIS_OPERATOR_GUIDE.md) - **Semantic Ops Runbook**
**For:** Running invariants, witness-extension, and Halo2 lookup semantic checks reproducibly  
**Contains:**
- invariant validation + checker commands
- witness-extension regression workflow
- Halo2 Plookup integration test workflow
- semantic signoff checklist

---

### 13. [TOOLS_AVAILABLE_ON_HOST.md](TOOLS_AVAILABLE_ON_HOST.md) - **Local Tool Inventory**
**For:** Verifying what vulnerability-discovery and formal/proof tools are actually installed on this workstation  
**Contains:**
- installed vs missing tool status
- resolved binary paths and versions
- usage mapping for discovery vs exploit proof vs non-exploitability proof
- quick recheck commands for manual operations

---

### 14. [ALPHA_OPERATING_PLAYBOOK.md](ALPHA_OPERATING_PLAYBOOK.md) - **Proof Closure Workflow**
**For:** Converting scan output into exploit/non-exploit proof artifacts quickly  
**Contains:**
- alpha definition for this repo
- proof-closure oriented run loop
- deterministic replay artifact scaffolding
- minimal KPI set for usefulness (`proof_closure_rate`, backlog, blocker rate)

---

### 15. [PATTERN_LIBRARY.md](PATTERN_LIBRARY.md) - **Pattern Library**
**For:** Understanding and creating vulnerability patterns  
**Contains:**
- Pattern structure and syntax
- CVE pattern examples
- Pattern contribution guide

---

### 16. [DEFI_ATTACK_GUIDE.md](DEFI_ATTACK_GUIDE.md) - **DeFi Attacks**
**For:** MEV and front-running detection  
**Contains:**
- DeFi-specific attack types
- Configuration examples
- Detection strategies

---

### 17. [INVARIANT_SPEC_SCHEMA.md](INVARIANT_SPEC_SCHEMA.md) - **Invariant Specs**
**For:** Defining circuit invariants  
**Contains:**
- Invariant specification format
- Validation rules
- Examples

---

### 18. [SECURITY_THREAT_MODEL.md](SECURITY_THREAT_MODEL.md) - **Security Model**
**For:** Understanding security assumptions  
**Contains:**
- Trust boundaries
- Threat model
- Security guarantees

---

### 19. [TRIAGE_SYSTEM.md](TRIAGE_SYSTEM.md) - **Triage System**
**For:** Automated finding triage  
**Contains:**
- Triage workflow
- Confidence levels
- False positive handling

---

### 20. [CHAIN_FUZZING_GUIDE.md](CHAIN_FUZZING_GUIDE.md) - **Chain Fuzzing**
**For:** Multi-circuit composition testing  
**Contains:**
- Chain fuzzing concepts
- Configuration examples

---

### 21. [PROFILES_GUIDE.md](PROFILES_GUIDE.md) - **Configuration Profiles**
**For:** Dev/prod profile management  
**Contains:**
- Profile system overview
- Profile customization

---

## 🤖 AI Integration

### 22. AI-Assisted Analysis - **External Workflow**
**For:** Using AI for semantic analysis and vulnerability assessment  
**Contains:**
- Handoff-artifact workflow (ai_ingest_bundle.json, worklists)
- External AI usage model and operator responsibilities
- Practical examples for out-of-band analysis

**Note:** ZkPatternFuzz produces AI-ready artifacts and is designed for external AI analysis by operators.  
Optional `ai_assistant` behavior is local offline heuristic support and must not be treated as proof evidence.

**Start here if:** You want to integrate AI-assisted analysis into your workflow

---

## 🏗️ Architecture & Development

### 23. [ARCHITECTURE.md](../ARCHITECTURE.md) - **45 min read**
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

### 24. [CHANGELOG.md](../CHANGELOG.md)
**For:** Version history and release notes  
**Contains:**
- Version history
- New features per release
- Breaking changes
- Migration guides

**Start here if:** You need to know what changed

---

### 25. [CONTRIBUTING.md](../CONTRIBUTING.md)
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
1. Read: [README.md](../README.md) Quick Start section (5 min)
2. Run: `cargo build --release`
3. Create campaign YAML (see examples in `campaigns/examples/`)
4. Execute: `cargo run -- --config campaign.yaml`

### I want to understand all options
1. Read: [TUTORIAL.md](TUTORIAL.md) (30 min)
2. Read: [ATTACK_DSL_SPEC.md](ATTACK_DSL_SPEC.md) (15 min)
3. Reference: Example campaigns in `campaigns/examples/`

### I want to learn by example
1. Read: [TUTORIAL.md](TUTORIAL.md) (30 min)
2. Try: Example campaigns in `campaigns/examples/`
3. Modify: Adapt examples to your circuits

### I want to extend the tool
1. Read: [ARCHITECTURE.md](../ARCHITECTURE.md) (45 min)
2. Study: `src/` module structure
3. Implement: New attack types or backends

### I want to contribute
1. Read: [CONTRIBUTING.md](../CONTRIBUTING.md)
2. Setup: Development environment
3. Submit: Pull request

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
- [BACKEND_SETUP.md](BACKEND_SETUP.md) - Backend installation

**Using the Tool**
- [README.md](../README.md) - Quick start guide
- [TUTORIAL.md](TUTORIAL.md) - Detailed walkthrough

**YAML Configuration**
- [tests/campaigns/](../tests/campaigns/) - Real examples
- `cargo run --bin validate_yaml -- <config.yaml> --require-invariants` - Strict YAML contract validation
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
README.md (Quick Start)
    ↓
Create campaign YAML
    ↓
Run fuzzer
    ↓
Done!
```

### Path 2: "I want to understand everything" (2 hours)
```
README.md
    ↓
TUTORIAL.md
    ↓
ARCHITECTURE.md
    ↓
Source code
```

### Path 3: "I want to contribute" (2 hours)
```
README.md
    ↓
ARCHITECTURE.md
    ↓
CONTRIBUTING.md
    ↓
Submit PR
```

### Path 4: "I want to learn by doing" (1 hour)
```
README.md (Quick Start)
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

1. **Quick question?** → [README.md](../README.md) Quick Start
2. **Configuration issue?** → [TUTORIAL.md](TUTORIAL.md)
3. **Backend problems?** → [TROUBLESHOOTING_PLAYBOOK.md](TROUBLESHOOTING_PLAYBOOK.md)
4. **Found a bug?** → Open GitHub issue
5. **Want to contribute?** → [CONTRIBUTING.md](../CONTRIBUTING.md)

---

**Last Updated:** February 2026  
**License:** BSL 1.1 (converts to Apache 2.0 in 2028)
