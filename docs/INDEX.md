# ZkPatternFuzz Documentation Index

Complete guide to all documentation files, ordered by use case and reading level.

## 🚀 Getting Started (Start Here)

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

### 4. [AI_ASSISTED_WORKFLOW.md](AI_ASSISTED_WORKFLOW.md) - **20 min read**
**For:** Using AI to generate optimal fuzzing configurations  
**Contains:**
- Complete YAML schema reference
- All attack types explained
- Input type specifications
- Fuzzing strategies
- Real example (Merkle tree)
- Automation scripts (Bash/Python)
- Troubleshooting guide

**Start here if:** You want to understand all configuration options

---

### 5. [TUTORIAL.md](TUTORIAL.md) - **30 min read**
**For:** Step-by-step learning with hands-on examples  
**Contains:**
- Detailed walkthrough
- Multiple circuit examples
- Common patterns
- Best practices
- Performance tips

**Start here if:** You prefer learning by doing

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
1. Read: [AI_ASSISTED_WORKFLOW.md](AI_ASSISTED_WORKFLOW.md) (20 min)
2. Reference: YAML schema section
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
├── QUICKSTART_AI.md ⭐ START HERE
│   └── 3-step setup with AI
│
├── VULNERABILITIES.md
│   └── 7 critical vulnerability classes
│
├── AI_ASSISTED_WORKFLOW.md
│   ├── Complete YAML schema
│   ├── Attack types reference
│   ├── Real examples
│   └── Automation scripts
│
├── TUTORIAL.md
│   ├── Hands-on examples
│   ├── Best practices
│   └── Performance tips
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
- [AI_ASSISTED_WORKFLOW.md](AI_ASSISTED_WORKFLOW.md) - All configuration options
- [TUTORIAL.md](TUTORIAL.md) - Detailed walkthrough

**YAML Configuration**
- [AI_ASSISTED_WORKFLOW.md](AI_ASSISTED_WORKFLOW.md) - Complete schema
- [tests/campaigns/](../tests/campaigns/) - Real examples

**Attack Types**
- [AI_ASSISTED_WORKFLOW.md](AI_ASSISTED_WORKFLOW.md) - Attack types table
- [src/attacks/](../src/attacks/) - Implementation details

**Development**
- [ARCHITECTURE.md](../ARCHITECTURE.md) - System design
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guide
- [src/](../src/) - Source code

**Troubleshooting**
- [AI_ASSISTED_WORKFLOW.md](AI_ASSISTED_WORKFLOW.md) - Troubleshooting section
- [TUTORIAL.md](TUTORIAL.md) - Common issues

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
AI_ASSISTED_WORKFLOW.md
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
2. **Configuration issue?** → See [AI_ASSISTED_WORKFLOW.md](AI_ASSISTED_WORKFLOW.md) troubleshooting
3. **Want to learn?** → Read [TUTORIAL.md](TUTORIAL.md)
4. **Found a bug?** → Open GitHub issue with circuit + YAML
5. **Want to contribute?** → Read [CONTRIBUTING.md](../CONTRIBUTING.md)

---

## 📝 Document Versions

| Document | Last Updated | Status |
|----------|--------------|--------|
| QUICKSTART_AI.md | 2025-01-XX | ✅ Current |
| AI_ASSISTED_WORKFLOW.md | 2025-01-XX | ✅ Current |
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
