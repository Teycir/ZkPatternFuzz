# Automated Triage System

**Phase 2: Milestone 2.4**  
**Status:** ✅ Implemented

The Automated Triage System provides confidence-based ranking and prioritization of findings, reducing false positives and helping auditors focus on high-impact vulnerabilities.

---

## Overview

The triage system processes findings through a pipeline that:

1. **Deduplicates** similar findings
2. **Calculates confidence scores** (0.0-1.0) based on multiple factors
3. **Classifies** findings by confidence level
4. **Prioritizes** findings for review
5. **Generates reports** with actionable insights

---

## Confidence Scoring

Each finding receives a confidence score based on:

| Factor | Weight | Description |
|--------|--------|-------------|
| Base Score | 0.30-0.50 | Based on severity (Critical=0.50, Info=0.30) |
| Cross-Oracle Validation | 0.15 | Multiple oracles agree |
| Picus Verification | 0.25 | Formal verification bonus |
| Reproduction Success | 0.20 | Successfully reproduced |
| Coverage Correlation | 0.10 | High-coverage discovery |
| PoC Quality | 0.10 | Quality of proof-of-concept |

### Score Breakdown Example

```
Base Score (Critical):     0.50
Cross-Oracle Bonus (3):    0.15  (3 oracles detected)
Picus Verified:            0.25
Reproduction (100%):       0.20
Coverage Bonus (85%):      0.07
PoC Quality:               0.07  (witness_a, witness_b, public_inputs)
Quality Penalty:           0.00
───────────────────────────────
Total Confidence:          1.00 (capped)
```

---

## Confidence Levels

| Level | Score Range | Action | Expected FP Rate |
|-------|-------------|--------|------------------|
| **High** | ≥ 0.80 | Auto-report | <5% |
| **Medium** | 0.50-0.79 | Needs review | 5-20% |
| **Low** | < 0.50 | Auto-filtered* | >20% |

*In evidence mode, low-confidence findings are automatically filtered.

---

## Usage

### Basic Pipeline

```rust
use zk_fuzzer::reporting::triage::{TriagePipeline, TriageConfig};

// Create pipeline with default config
let config = TriageConfig::default();
let mut pipeline = TriagePipeline::new(config);

// Add findings from fuzzing
for finding in findings {
    pipeline.add_finding(finding);
}

// Generate report
let report = pipeline.generate_report();

// Access classified findings
println!("High confidence: {}", report.high_confidence.len());
println!("Medium confidence: {}", report.medium_confidence.len());
println!("Low confidence: {}", report.low_confidence.len());
```

### With Oracle Tracking

```rust
// Track which oracle detected each finding
let idx = pipeline.add_finding_with_oracle(finding, "NullifierOracle")?;

// Multiple oracles detected the same issue
pipeline.add_oracle_to_finding(idx, "CollisionOracle");
pipeline.add_oracle_to_finding(idx, "SemanticOracle");
// Confidence increases with each confirming oracle
```

### With Verification

```rust
// Mark finding as formally verified by Picus
pipeline.mark_picus_verified(finding_idx);

// Record reproduction attempts
pipeline.record_reproduction(finding_idx, true);  // Success
pipeline.record_reproduction(finding_idx, true);  // Success
pipeline.record_reproduction(finding_idx, false); // Failure
// Reproduction rate: 66.7%

// Set discovery coverage
pipeline.set_discovery_coverage(finding_idx, 85.0);
```

---

## Configuration

```rust
pub struct TriageConfig {
    /// Threshold for high confidence (default: 0.8)
    pub high_confidence_threshold: f64,
    
    /// Threshold for medium confidence (default: 0.5)
    pub medium_confidence_threshold: f64,
    
    /// Weight for cross-oracle bonus (default: 0.15)
    pub cross_oracle_weight: f64,
    
    /// Weight for Picus verification (default: 0.25)
    pub picus_verification_weight: f64,
    
    /// Weight for reproduction success (default: 0.20)
    pub reproduction_weight: f64,
    
    /// Weight for coverage correlation (default: 0.10)
    pub coverage_weight: f64,
    
    /// Auto-filter low-confidence findings (default: true)
    pub auto_filter_low_confidence: bool,
    
    /// Enable deduplication (default: true)
    pub enable_deduplication: bool,
    
    /// Minimum confidence for evidence mode (default: 0.5)
    pub evidence_mode_min_confidence: f64,
}
```

---

## Report Output

### JSON Report

```json
{
  "high_confidence": [...],
  "medium_confidence": [...],
  "low_confidence": [...],
  "statistics": {
    "total_findings": 42,
    "high_confidence_count": 5,
    "medium_confidence_count": 12,
    "low_confidence_count": 25,
    "filtered_count": 25,
    "average_confidence": 0.58,
    "oracle_diversity": 4,
    "oracles_by_finding_count": {
      "NullifierOracle": 15,
      "MerkleOracle": 12,
      "SemanticOracle": 8,
      "CollisionOracle": 7
    }
  }
}
```

### Markdown Report

```markdown
# Triage Report

## Summary

| Metric | Value |
|--------|-------|
| Total Findings | 42 |
| High Confidence | 5 |
| Medium Confidence | 12 |
| Low Confidence | 25 |
| Average Confidence | 0.58 |
| Oracle Diversity | 4 |

## High Confidence Findings (Auto-Report)

### #1 [Critical] Soundness (Confidence: 0.95)

Critical soundness violation: proof accepted for invalid statement...

**Oracles:** NullifierOracle, CollisionOracle, SemanticOracle
```

---

## Integration with Evidence Mode

In evidence mode, findings are filtered by minimum confidence:

```rust
// Get only findings suitable for evidence mode
let evidence_findings = pipeline.evidence_mode_findings();

// These findings have confidence >= evidence_mode_min_confidence (0.5)
for finding in evidence_findings {
    generate_evidence_bundle(finding);
}
```

---

## Best Practices

### 1. Use Multiple Oracles

Configure multiple oracles for cross-validation. Findings detected by 3+ oracles receive significant confidence bonuses.

### 2. Enable Picus Verification

For under-constraint bugs, run Picus verification. Formally verified findings get the highest confidence boost (+0.25).

### 3. Attempt Reproduction

Record reproduction attempts for all high-priority findings. 100% reproduction rate provides maximum bonus (+0.20).

### 4. Track Coverage

Set discovery coverage for findings. High-coverage discoveries (>50%) receive bonus points.

### 5. Quality PoCs

Include complete proof-of-concept data:
- `witness_a`: Primary witness (+0.03)
- `witness_b`: Differential witness (+0.04)
- `public_inputs`: Public inputs (+0.02)
- `proof`: Generated proof (+0.01)

---

## Metrics for Evaluation

### False Positive Rate by Level

| Level | Target FP Rate | Actual (Benchmark) |
|-------|----------------|-------------------|
| High | <5% | TBD |
| Medium | 5-20% | TBD |
| Low | >20% | TBD |

### Detection Rate

Monitor detection rate across the ground truth test suite to ensure the triage system doesn't filter true positives.

---

## API Reference

### `TriagePipeline`

```rust
impl TriagePipeline {
    fn new(config: TriageConfig) -> Self;
    fn add_finding(&mut self, finding: Finding) -> Option<usize>;
    fn add_finding_with_oracle(&mut self, finding: Finding, oracle: &str) -> Option<usize>;
    fn add_oracle_to_finding(&mut self, idx: usize, oracle: &str);
    fn mark_picus_verified(&mut self, idx: usize);
    fn record_reproduction(&mut self, idx: usize, success: bool);
    fn set_discovery_coverage(&mut self, idx: usize, coverage: f64);
    fn generate_report(&mut self) -> TriageReport;
    fn evidence_mode_findings(&self) -> Vec<&TriagedFinding>;
}
```

### `TriageReport`

```rust
impl TriageReport {
    fn all_findings_by_priority(&self) -> Vec<&TriagedFinding>;
    fn auto_report_findings(&self) -> &[TriagedFinding];
    fn review_findings(&self) -> &[TriagedFinding];
    fn save_to_file(&self, path: &Path) -> Result<()>;
    fn to_markdown(&self) -> String;
}
```

---

## Changelog

- **v0.2.0** (Feb 2026): Initial implementation of automated triage system
  - Confidence scoring with 6 factors
  - Cross-oracle validation
  - Picus verification integration
  - Reproduction tracking
  - Coverage correlation
  - Deduplication
  - Priority ranking
  - JSON/Markdown reporting
