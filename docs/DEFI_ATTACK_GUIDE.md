# DeFi Attack Guide

**Phase 3: Milestone 3.1**  
**Status:** ✅ Implemented

This guide covers MEV (Maximal Extractable Value) and front-running attack detection in ZK circuits used for DeFi applications.

---

## Overview

DeFi protocols using ZK proofs can be vulnerable to:

1. **MEV Attacks** - Extracting value through transaction ordering
2. **Front-Running** - Profiting by acting on observed pending transactions
3. **Sandwich Attacks** - Wrapping victim transactions to extract value
4. **State Leakage** - Inferring private information from public outputs

---

## MEV Attack Detection

### Attack Types

| Type | Description | Severity |
|------|-------------|----------|
| Ordering Dependency | Transaction order affects outcomes | High |
| Sandwich Attack | Front-run + back-run for profit | Critical |
| State Leakage | Private inputs inferable from outputs | High |
| Price Manipulation | Large trades cause excessive slippage | Critical |
| Arbitrage | Cross-circuit price differences | Medium |

### Usage

```rust
use zk_fuzzer::attacks::mev::{MevAttack, MevConfig};

let config = MevConfig {
    ordering_permutations: 100,
    sandwich_attempts: 50,
    profit_threshold: 0.01, // 1% profit threshold
    detect_ordering: true,
    detect_sandwich: true,
    detect_leakage: true,
    ..Default::default()
};

let mut attack = MevAttack::new(config);
let findings = attack.run(&executor, &inputs)?;

for finding in findings {
    println!("Found: {} ({})", finding.description, finding.severity);
}
```

### Configuration Options

```rust
pub struct MevConfig {
    /// Number of ordering permutations to test
    pub ordering_permutations: usize,  // default: 100
    
    /// Number of sandwich attack attempts
    pub sandwich_attempts: usize,      // default: 50
    
    /// Maximum value delta to consider profitable
    pub profit_threshold: f64,         // default: 0.01 (1%)
    
    /// Enable ordering dependency detection
    pub detect_ordering: bool,         // default: true
    
    /// Enable sandwich attack detection  
    pub detect_sandwich: bool,         // default: true
    
    /// Enable state leakage detection
    pub detect_leakage: bool,          // default: true
}
```

---

## Front-Running Attack Detection

### Attack Types

| Type | Description | Severity |
|------|-------------|----------|
| Information Leakage | Outputs reveal private input patterns | High |
| Commitment Bypass | Same commitment from different inputs | Critical |
| Delay Attack | Timing affects outcomes profitably | Medium |
| Predictable Randomness | Input patterns are guessable | Critical |
| Weak Hiding | Similar inputs produce similar outputs | High |

### Usage

```rust
use zk_fuzzer::attacks::front_running::{FrontRunningAttack, FrontRunningConfig};

let config = FrontRunningConfig {
    leakage_tests: 100,
    commitment_tests: 50,
    entropy_threshold: 3.0, // bits
    detect_leakage: true,
    detect_commitment_bypass: true,
    detect_delay_attack: true,
    ..Default::default()
};

let mut attack = FrontRunningAttack::new(config);
let findings = attack.run(&executor, &inputs)?;
```

---

## Price Impact Analysis

For DEX circuits, analyze price impact:

```rust
use zk_fuzzer::attacks::mev::PriceImpactAnalyzer;

let mut analyzer = PriceImpactAnalyzer::new(0.05); // 5% max slippage

// Record trades
for trade in trades {
    analyzer.record(trade.size, trade.price_impact);
}

if let Some(finding) = analyzer.analyze() {
    println!("Price manipulation risk: {}", finding.description);
}
```

---

## Arbitrage Detection

For multi-circuit protocols:

```rust
use zk_fuzzer::attacks::mev::ArbitrageDetector;

let mut detector = ArbitrageDetector::new();

// Record prices from different circuits
detector.record_price("dex_a", 100.0);
detector.record_price("dex_b", 105.0);

let findings = detector.detect_arbitrage(0.02); // 2% min profit
for finding in findings {
    println!("Arbitrage: {}", finding.description);
}
```

---

## State Leakage Analysis

For privacy circuits:

```rust
use zk_fuzzer::attacks::front_running::StateLeakageAnalyzer;

let mut analyzer = StateLeakageAnalyzer::new(50);

// Observe circuit executions
for (private_inputs, outputs) in observations {
    analyzer.observe(private_inputs, outputs);
}

if let Some(finding) = analyzer.analyze() {
    println!("Leakage detected: {}", finding.description);
}
```

---

## Campaign Configuration

Use the DeFi audit template for comprehensive testing:

```yaml
# campaigns/templates/defi_audit.yaml

campaign:
  name: "DeFi Protocol Audit"
  version: "1.0"
  target:
    framework: circom
    circuit_path: "./circuits/swap.circom"
    main_component: "Swap"

attacks:
  # MEV Attacks
  - type: soundness
    description: "MEV: Ordering dependency"
    config:
      attack_subtype: "mev_ordering"
      ordering_permutations: 100
      
  - type: soundness
    description: "MEV: Sandwich attack"
    config:
      attack_subtype: "mev_sandwich"
      sandwich_attempts: 50
      profit_threshold: 0.01

  # Front-Running Attacks
  - type: soundness
    description: "Front-running: Information leakage"
    config:
      attack_subtype: "front_running_leakage"
      entropy_threshold: 3.0

  - type: soundness
    description: "Front-running: Commitment bypass"
    config:
      attack_subtype: "front_running_commitment"
      commitment_tests: 50

  # Standard Attacks
  - type: underconstrained
    description: "Missing constraints"
    
  - type: arithmetic_overflow
    description: "Arithmetic overflow"

invariants:
  # DeFi-specific invariants
  - name: "conservation_of_value"
    relation: "input_amount == output_amount + fee"
    
  - name: "price_bounds"
    relation: "price >= min_price && price <= max_price"
    
  - name: "slippage_limit"
    relation: "abs(executed_price - expected_price) <= max_slippage"
```

---

## Real-World Examples

### Example 1: DEX Swap Circuit

**Vulnerable Pattern:**
```circom
// Price depends on transaction order
signal output price;
price <== reserve_a / reserve_b;  // No slippage protection
```

**Detection:** Ordering dependency attack detects that swapping transaction order changes the final price.

### Example 2: Privacy Mixer

**Vulnerable Pattern:**
```circom
// Commitment reveals deposit size
signal output commitment;
commitment <== poseidon([amount, nullifier]);  // Amount not hidden
```

**Detection:** State leakage analysis shows low output entropy for varying amounts.

### Example 3: Order Book

**Vulnerable Pattern:**
```circom
// Order visibility before execution
signal output order_hash;
order_hash <== hash([price, size, timestamp]);  // Predictable
```

**Detection:** Front-running detection identifies that orders can be predicted before execution.

---

## Mitigation Recommendations

### For Ordering Dependencies

1. Use commit-reveal schemes
2. Implement MEV protection (Flashbots-style)
3. Add randomized execution ordering

### For Information Leakage

1. Add sufficient randomness to outputs
2. Use zero-knowledge range proofs
3. Implement proper hiding commitments

### For Price Manipulation

1. Use time-weighted average prices (TWAP)
2. Implement slippage protection
3. Add circuit breakers for extreme moves

---

## API Reference

### `MevAttack`

```rust
impl MevAttack {
    fn new(config: MevConfig) -> Self;
    fn run(&mut self, executor: &dyn CircuitExecutor, inputs: &[FieldElement]) 
        -> Result<Vec<Finding>>;
}
```

### `FrontRunningAttack`

```rust
impl FrontRunningAttack {
    fn new(config: FrontRunningConfig) -> Self;
    fn run(&mut self, executor: &dyn CircuitExecutor, inputs: &[FieldElement]) 
        -> Result<Vec<Finding>>;
}
```

### `PriceImpactAnalyzer`

```rust
impl PriceImpactAnalyzer {
    fn new(max_slippage: f64) -> Self;
    fn record(&mut self, trade_size: f64, price_impact: f64);
    fn analyze(&self) -> Option<MevTestResult>;
}
```

### `ArbitrageDetector`

```rust
impl ArbitrageDetector {
    fn new() -> Self;
    fn record_price(&mut self, circuit_id: &str, price: f64);
    fn detect_arbitrage(&self, min_profit: f64) -> Vec<MevTestResult>;
}
```

---

## Changelog

- **v0.2.0** (Feb 2026): Initial implementation
  - MEV attack detection (ordering, sandwich, leakage)
  - Front-running attack detection (leakage, commitment, delay)
  - Price impact and arbitrage analyzers
  - DeFi audit campaign template
