# Implementation Priority Matrix

**Quick Reference:** What to build first to maximize 0-day finding capability

---

## Critical Path (Must Have for Real Bug Finding)

These components **block** all downstream work. Without these, the fuzzer cannot find real bugs.

| Priority | Component | Why Critical | Effort | Blocking |
|----------|-----------|--------------|--------|----------|
| **P0** | R1CS Binary Parser | Can't analyze real circuits without this | 3 weeks | Everything |
| **P0** | R1CS → Z3 SMT Translation | Random fuzzing has ~5% success rate vs 60%+ for SMT-guided | 4 weeks | High coverage |
| **P0** | Real Circuit Integration | Can't find bugs in mock circuits | 2 weeks | Validation |

**Start Here:** [Week 1 Guide](QUICK_START_IMPLEMENTATION.md)

---

## High Priority (Force Multipliers)

These components dramatically increase bug-finding effectiveness.

| Priority | Component | Impact on Detection | Effort | Dependencies |
|----------|-----------|---------------------|--------|--------------|
| **P1** | Nullifier Collision Oracle | Catches 40% of privacy protocol bugs | 2 weeks | None |
| **P1** | Merkle Soundness Oracle | Catches 30% of tree-based bugs | 1.5 weeks | None |
| **P1** | Signature Malleability Oracle | Historical: 3 real CVEs | 2 weeks | None |
| **P1** | Grammar-Based Generation | 3-10x better coverage than random | 6 weeks | R1CS parser |

---

## Medium Priority (Productionization)

These make the tool usable for external teams.

| Priority | Component | User Value | Effort | Dependencies |
|----------|-----------|------------|--------|--------------|
| **P2** | Finding Deduplication | Reduces noise from 100s to 10s of bugs | 2 weeks | None |
| **P2** | Test Case Minimization | Makes PoCs actionable (500 bytes vs 50KB) | 2 weeks | None |
| **P2** | CI/CD Integration | Enables continuous fuzzing | 1 week | None |
| **P2** | Confidence Scoring | Prioritizes high-value findings | 1 week | Oracles |

---

## Low Priority (Nice to Have)

These are optimizations and UX improvements.

| Priority | Component | Benefit | Effort | ROI |
|----------|-----------|---------|--------|-----|
| **P3** | Performance Profiling | 10-20% speedup | 2 weeks | Low |
| **P3** | Distributed Fuzzing | Horizontal scaling | 3 weeks | Medium |
| **P3** | Web Dashboard | Better UX | 4 weeks | Low |
| **P3** | ACIR/PLONK Support | Expand to Noir/Halo2 | 6 weeks | Medium |

---

## Implementation Sequence

### Phase 1: Foundation (Months 1-3)
**Goal:** Can fuzz real circuits and detect basic bugs

```
Week 1-2:  R1CS Parser + Real Circuit Setup
Week 3-5:  R1CS → SMT Translation  
Week 6-8:  Circom Integration Testing
Week 9-12: First Semantic Oracle (Nullifier)
```

**Milestone:** Find first bug in Tornado/Semaphore (even if known)

---

### Phase 2: Semantic Detection (Months 4-5)
**Goal:** Detect ZK-specific vulnerabilities

```
Week 13-14: Nullifier Oracle
Week 15-16: Merkle Soundness Oracle
Week 17-18: Signature Malleability Oracle
Week 19-20: Range Proof Oracle
```

**Milestone:** Build oracle suite covering 70% of known ZK bug classes

---

### Phase 3: Advanced Generation (Months 6-7)
**Goal:** Structure-aware fuzzing

```
Week 21-23: Grammar DSL Design
Week 24-26: Merkle/Signature Generators
Week 27-28: Invariant Checking
```

**Milestone:** 3x improvement in coverage vs random fuzzing

---

### Phase 4: Known Bugs DB (Month 8)
**Goal:** Regression detection

```
Week 29-30: CVE Database (20+ patterns)
Week 31-32: Regression Test Suite
```

**Milestone:** 95%+ recall on historical bugs

---

### Phase 5: Production (Months 9-10)
**Goal:** External teams can use it

```
Week 33-35: CI/CD Pipeline
Week 36-37: Triage System
Week 38-40: Documentation & Examples
```

**Milestone:** 3 external teams adopt the tool

---

### Phase 6: Validation (Months 11-12)
**Goal:** Prove effectiveness

```
Week 41-44: Continuous fuzzing campaigns
Week 45-48: Bug bounty submissions
Week 49-52: Performance optimization
```

**Milestone:** Find 1+ novel 0-day in production circuit

---

## Resource Allocation

### Optimal Team

| Role | Allocation | Focus |
|------|-----------|-------|
| Senior Rust Engineer | 100% (12 months) | Core engine, SMT integration |
| Security Researcher | 50% (6 months) | Oracle development, validation |
| DevOps Engineer | 25% (3 months) | CI/CD, infrastructure |

**Total:** 1.75 FTE-years

### Minimum Viable Team

| Role | Allocation | Trade-offs |
|------|-----------|------------|
| Full-Stack Engineer | 100% (12 months) | Slower progress, less security expertise |

**Total:** 1 FTE-year (realistic for solo founder)

---

## Budget Estimates

### Development Costs

| Item | Cost | Notes |
|------|------|-------|
| Engineering salary | $150K | 1 senior engineer @ $150K/year |
| Security researcher | $45K | 0.5 FTE @ $90K/year |
| Infrastructure (AWS) | $2K | CI/CD, storage (12 months) |
| Tooling licenses | $500 | JetBrains, monitoring |
| **Total** | **$197.5K** | For 12-month development |

### ROI Scenarios

| Outcome | Value | Probability |
|---------|-------|-------------|
| Find 1 critical bug in DeFi protocol | $10K-50K bounty | 60% |
| Product adoption by 3+ teams | $100K ARR (SaaS) | 40% |
| Consulting engagements | $50K-200K | 70% |
| Open-source sponsorship | $20K/year | 30% |

**Expected Value:** ~$100K in Year 1

---

## Risk-Adjusted Timeline

### Optimistic (Best Case)

- **R1CS Integration:** 6 weeks
- **First Real Bug:** Month 4
- **Production Ready:** Month 9

### Realistic (Most Likely)

- **R1CS Integration:** 10 weeks
- **First Real Bug:** Month 6
- **Production Ready:** Month 12

### Pessimistic (Worst Case)

- **R1CS Integration:** 16 weeks (technical blockers)
- **First Real Bug:** Month 9 (circuits are harder than expected)
- **Production Ready:** Month 18

**Recommendation:** Plan for realistic, hope for optimistic

---

## Decision Framework: What NOT to Build

### Cut Features

| Feature | Why Skip | Alternative |
|---------|----------|------------|
| Web Dashboard | Low ROI early on | CLI is sufficient |
| Distributed Fuzzing | Premature optimization | Single machine handles 10K exec/sec |
| Halo2/Cairo Support | Different constraint systems | Focus on Circom first |
| Formal Verification | Different approach | Fuzzing finds different bugs |

### When to Build Later

- **Dashboard:** After 3+ external users request it
- **Distributed:** After single-machine becomes bottleneck
- **Other Backends:** After Circom coverage >80%
- **Formal Methods:** After fuzzing approach validated

---

## Metrics Dashboard

### Leading Indicators (Week-by-Week)

```
✅ R1CS parser merged
✅ First SMT-generated input
✅ First semantic oracle passing tests
✅ Tornado circuit integrated
✅ 1-hour fuzzing run completes
```

### Lagging Indicators (Month-by-Month)

```
📊 Month 1:  R1CS parser working
📊 Month 2:  SMT integration complete
📊 Month 3:  >50% coverage on Tornado
📊 Month 4:  3 oracles implemented
📊 Month 5:  First suspected bug found
📊 Month 6:  Bug validated (real or FP)
📊 Month 9:  External team onboarded
📊 Month 12: 1+ novel CVE found
```

---

## Go/No-Go Checkpoints

### Month 3 Review

**Go Criteria:**
- ✅ R1CS parser works on 3+ real circuits
- ✅ SMT solver generates constraint-satisfying inputs
- ✅ >40% coverage on Tornado in 1 hour
- ✅ At least 1 oracle detecting test bugs

**No-Go Signal:**
- ❌ Can't parse R1CS reliably
- ❌ SMT times out on all circuits
- ❌ <20% coverage after 1 hour
- ❌ No oracles working

**Action:** If no-go, pivot to WASM-only approach (skip SMT)

### Month 6 Review

**Go Criteria:**
- ✅ 3+ oracles implemented
- ✅ Grammar-based generation working
- ✅ At least 1 finding (even FP) in real circuit
- ✅ >60% coverage on Tornado

**No-Go Signal:**
- ❌ Only generic oracles (no ZK-specific)
- ❌ Random fuzzing performs as well as structured
- ❌ Zero findings in 100+ hours of fuzzing
- ❌ <40% coverage

**Action:** If no-go, focus on tooling for manual audit instead of automated fuzzing

---

## Success Scorecard

### Quantitative (Required)

| Metric | Target | Stretch | Current |
|--------|--------|---------|---------|
| Constraint coverage | 70% | 85% | - |
| Executions/second | 1000 | 5000 | - |
| False positive rate | <15% | <5% | - |
| Known CVE recall | 90% | 100% | - |
| Novel bugs found | 1 | 3+ | 0 |

### Qualitative (Aspirational)

- [ ] Used by Trail of Bits in real audit
- [ ] Mentioned in ZKProof workshop
- [ ] 100+ GitHub stars
- [ ] Bug bounty payout received
- [ ] Published in academic venue (IEEE S&P / CCS)

---

## Next Actions

### This Week
1. ✅ Read full roadmap
2. 🔲 Set up git submodules for real circuits
3. 🔲 Implement R1CS parser (Day 1-2 of quick start)
4. 🔲 Run first test on Tornado R1CS file

### This Month
1. 🔲 Complete Phase 1 Week 1-4
2. 🔲 R1CS → SMT translation working
3. 🔲 First oracle integrated
4. 🔲 Baseline benchmark documented

### This Quarter
1. 🔲 Complete Phase 1 (Foundation)
2. 🔲 Find first bug (even if known)
3. 🔲 Present at ZK meetup
4. 🔲 Get feedback from 3 ZK researchers

---

## Quick Links

- [12-Month Roadmap](ZERO_DAY_ROADMAP.md) - Comprehensive plan
- [Week 1 Guide](QUICK_START_IMPLEMENTATION.md) - Hands-on start
- [Architecture Docs](ARCHITECTURE.md) - System design
- [Code Review](CODE_REVIEW.md) - Current state assessment

---

**Last Updated:** 2026-02-05  
**Next Review:** Month 3 (after Phase 1 completion)
