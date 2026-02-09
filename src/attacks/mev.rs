//! MEV (Maximal Extractable Value) Attack Detection (Phase 3: Milestone 3.1)
//!
//! Detects vulnerabilities in ZK circuits that could enable MEV extraction:
//! - Ordering dependency: Transaction order affects outcome
//! - Sandwich attacks: Attacker can profit by front-running and back-running
//! - State leakage: Private state can be inferred from public outputs
//!
//! # Attack Patterns
//!
//! ## Ordering Dependency
//! Circuits where the order of inputs affects outputs in exploitable ways.
//! Example: DEX circuits where swap order impacts price.
//!
//! ## Sandwich Attack
//! Circuits where an attacker can insert transactions before and after
//! a victim's transaction to extract value.
//!
//! ## State Leakage
//! Circuits where private inputs can be inferred from public outputs,
//! enabling front-running based on leaked information.
//!
//! # Usage
//!
//! ```rust,ignore
//! use zk_fuzzer::attacks::mev::{MevAttack, MevConfig};
//!
//! let config = MevConfig::default();
//! let mut attack = MevAttack::new(config);
//!
//! // Run attack against circuit executor
//! let findings = attack.run(&executor, &inputs)?;
//! ```

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

/// Configuration for MEV attack detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevConfig {
    /// Number of ordering permutations to test
    pub ordering_permutations: usize,
    /// Number of sandwich attack attempts
    pub sandwich_attempts: usize,
    /// Maximum value delta to consider profitable
    pub profit_threshold: f64,
    /// Enable ordering dependency detection
    pub detect_ordering: bool,
    /// Enable sandwich attack detection
    pub detect_sandwich: bool,
    /// Enable state leakage detection
    pub detect_leakage: bool,
    /// Timeout per test in milliseconds
    pub timeout_ms: u64,
    /// Random seed for reproducibility
    pub seed: Option<u64>,
}

impl Default for MevConfig {
    fn default() -> Self {
        Self {
            ordering_permutations: 100,
            sandwich_attempts: 50,
            profit_threshold: 0.01, // 1% profit threshold
            detect_ordering: true,
            detect_sandwich: true,
            detect_leakage: true,
            timeout_ms: 5000,
            seed: None,
        }
    }
}

/// Result of an MEV attack test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevTestResult {
    /// Type of MEV vulnerability detected
    pub vulnerability_type: MevVulnerabilityType,
    /// Description of the finding
    pub description: String,
    /// Estimated profit potential (if applicable)
    pub profit_potential: Option<f64>,
    /// Witness inputs that trigger the vulnerability
    pub witness: Vec<FieldElement>,
    /// Additional context
    pub context: HashMap<String, String>,
}

/// Types of MEV vulnerabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MevVulnerabilityType {
    /// Transaction ordering affects outcome
    OrderingDependency,
    /// Sandwich attack possible
    SandwichAttack,
    /// Private state leakage enables front-running
    StateLeakage,
    /// Price manipulation through transaction ordering
    PriceManipulation,
    /// Arbitrage opportunity due to circuit design
    Arbitrage,
}

impl MevVulnerabilityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OrderingDependency => "ordering_dependency",
            Self::SandwichAttack => "sandwich_attack",
            Self::StateLeakage => "state_leakage",
            Self::PriceManipulation => "price_manipulation",
            Self::Arbitrage => "arbitrage",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::OrderingDependency => Severity::High,
            Self::SandwichAttack => Severity::Critical,
            Self::StateLeakage => Severity::High,
            Self::PriceManipulation => Severity::Critical,
            Self::Arbitrage => Severity::Medium,
        }
    }
}

/// MEV attack detection engine
pub struct MevAttack {
    config: MevConfig,
    rng: ChaCha8Rng,
    findings: Vec<MevTestResult>,
}

impl MevAttack {
    /// Create a new MEV attack detector
    pub fn new(config: MevConfig) -> Self {
        let seed = config.seed.unwrap_or_else(rand::random);
        Self {
            config,
            rng: ChaCha8Rng::seed_from_u64(seed),
            findings: Vec::new(),
        }
    }

    /// Run MEV attack detection against a circuit executor
    pub fn run(
        &mut self,
        executor: &dyn CircuitExecutor,
        base_inputs: &[FieldElement],
    ) -> anyhow::Result<Vec<Finding>> {
        self.findings.clear();

        if self.config.detect_ordering {
            self.detect_ordering_dependency(executor, base_inputs)?;
        }

        if self.config.detect_sandwich {
            self.detect_sandwich_attack(executor, base_inputs)?;
        }

        if self.config.detect_leakage {
            self.detect_state_leakage(executor, base_inputs)?;
        }

        // Convert to standard findings
        Ok(self.findings.iter().map(|r| r.to_finding()).collect())
    }

    /// Detect ordering dependency vulnerabilities
    fn detect_ordering_dependency(
        &mut self,
        executor: &dyn CircuitExecutor,
        base_inputs: &[FieldElement],
    ) -> anyhow::Result<()> {
        let input_count = base_inputs.len();
        if input_count < 2 {
            return Ok(()); // Need at least 2 inputs for ordering test
        }

        // Generate baseline output
        let baseline_result = executor.execute_sync(base_inputs);
        if !baseline_result.success {
            return Ok(());
        }
        let baseline_outputs = baseline_result.outputs;

        // Test different orderings
        for _ in 0..self.config.ordering_permutations.min(factorial(input_count)) {
            let permuted = self.permute_inputs(base_inputs);
            let permuted_result = executor.execute_sync(&permuted);

            if permuted_result.success {
                // Check if outputs differ significantly
                let difference = self.output_difference(&baseline_outputs, &permuted_result.outputs);
                
                if difference > self.config.profit_threshold {
                    self.findings.push(MevTestResult {
                        vulnerability_type: MevVulnerabilityType::OrderingDependency,
                        description: format!(
                            "Input ordering affects output by {:.2}%. Different input \
                             orderings produce different results, enabling transaction \
                             ordering attacks.",
                            difference * 100.0
                        ),
                        profit_potential: Some(difference),
                        witness: permuted,
                        context: [
                            ("difference".to_string(), format!("{:.4}", difference)),
                        ].into_iter().collect(),
                    });
                    break; // Found one, don't spam
                }
            }
        }

        Ok(())
    }

    /// Detect sandwich attack vulnerabilities
    fn detect_sandwich_attack(
        &mut self,
        executor: &dyn CircuitExecutor,
        victim_inputs: &[FieldElement],
    ) -> anyhow::Result<()> {
        // Simulate sandwich attack pattern:
        // 1. Attacker front-run transaction
        // 2. Victim transaction
        // 3. Attacker back-run transaction

        for _ in 0..self.config.sandwich_attempts {
            // Generate attacker's front-run inputs (slightly modified)
            let front_run = self.generate_front_run(victim_inputs);
            let back_run = self.generate_back_run(victim_inputs);

            // Execute sequence: front_run -> victim -> back_run
            let front_result = executor.execute_sync(&front_run);
            if !front_result.success {
                continue;
            }

            let victim_result = executor.execute_sync(victim_inputs);
            if !victim_result.success {
                continue;
            }

            let back_result = executor.execute_sync(&back_run);
            if !back_result.success {
                continue;
            }

            // Check for profit opportunity
            let attacker_profit = self.calculate_sandwich_profit(
                &front_result.outputs,
                &victim_result.outputs,
                &back_result.outputs,
            );

            if attacker_profit > self.config.profit_threshold {
                self.findings.push(MevTestResult {
                    vulnerability_type: MevVulnerabilityType::SandwichAttack,
                    description: format!(
                        "Sandwich attack possible with {:.2}% profit potential. \
                         Attacker can front-run and back-run victim transactions \
                         to extract value.",
                        attacker_profit * 100.0
                    ),
                    profit_potential: Some(attacker_profit),
                    witness: front_run.into_iter()
                        .chain(victim_inputs.iter().cloned())
                        .chain(back_run)
                        .collect(),
                    context: [
                        ("profit".to_string(), format!("{:.4}", attacker_profit)),
                        ("attack_type".to_string(), "sandwich".to_string()),
                    ].into_iter().collect(),
                });
                break;
            }
        }

        Ok(())
    }

    /// Detect state leakage vulnerabilities
    fn detect_state_leakage(
        &mut self,
        executor: &dyn CircuitExecutor,
        base_inputs: &[FieldElement],
    ) -> anyhow::Result<()> {
        // Check if private inputs can be inferred from outputs
        let num_public = executor.num_public_inputs();
        let num_private = executor.num_private_inputs();

        if num_private == 0 {
            return Ok(()); // No private inputs to leak
        }

        // Strategy: Vary private inputs, check if outputs reveal patterns
        let mut output_patterns: HashMap<String, Vec<Vec<FieldElement>>> = HashMap::new();

        for _ in 0..50 {
            // Generate varied inputs
            let mut inputs = base_inputs.to_vec();
            for i in num_public..inputs.len().min(num_public + num_private) {
                if self.rng.gen_bool(0.5) {
                    inputs[i] = FieldElement::random(&mut self.rng);
                }
            }

            let result = executor.execute_sync(&inputs);
            if result.success {
                // Hash outputs to detect patterns
                let output_hash = self.hash_outputs(&result.outputs);
                output_patterns
                    .entry(output_hash)
                    .or_default()
                    .push(inputs[num_public..].to_vec());
            }
        }

        // Check for low entropy (few unique outputs for many private inputs)
        let unique_outputs = output_patterns.len();
        if unique_outputs < 5 && unique_outputs > 0 {
            // Low output entropy might indicate information leakage
            let leakage_ratio = 50.0 / unique_outputs as f64;
            
            if leakage_ratio > 5.0 {
                self.findings.push(MevTestResult {
                    vulnerability_type: MevVulnerabilityType::StateLeakage,
                    description: format!(
                        "Potential private state leakage detected. Only {} unique outputs \
                         for 50 different private inputs (ratio: {:.1}x). Private inputs \
                         may be inferable from public outputs.",
                        unique_outputs, leakage_ratio
                    ),
                    profit_potential: None,
                    witness: base_inputs.to_vec(),
                    context: [
                        ("unique_outputs".to_string(), unique_outputs.to_string()),
                        ("leakage_ratio".to_string(), format!("{:.1}", leakage_ratio)),
                    ].into_iter().collect(),
                });
            }
        }

        Ok(())
    }

    /// Permute inputs randomly
    fn permute_inputs(&mut self, inputs: &[FieldElement]) -> Vec<FieldElement> {
        let mut permuted: Vec<FieldElement> = inputs.to_vec();
        let n = permuted.len();
        
        // Fisher-Yates shuffle
        for i in (1..n).rev() {
            let j = self.rng.gen_range(0..=i);
            permuted.swap(i, j);
        }
        
        permuted
    }

    /// Generate front-run transaction inputs
    fn generate_front_run(&mut self, victim_inputs: &[FieldElement]) -> Vec<FieldElement> {
        let mut front_run = victim_inputs.to_vec();
        
        // Modify some inputs to be slightly different (front-running strategy)
        for input in front_run.iter_mut() {
            if self.rng.gen_bool(0.3) {
                // Slightly increase or decrease
                *input = input.add(&FieldElement::from_u64(self.rng.gen_range(1..100)));
            }
        }
        
        front_run
    }

    /// Generate back-run transaction inputs
    fn generate_back_run(&mut self, victim_inputs: &[FieldElement]) -> Vec<FieldElement> {
        let mut back_run = victim_inputs.to_vec();
        
        // Modify inputs for back-running (opposite direction)
        for input in back_run.iter_mut() {
            if self.rng.gen_bool(0.3) {
                *input = input.sub(&FieldElement::from_u64(self.rng.gen_range(1..100)));
            }
        }
        
        back_run
    }

    /// Calculate output difference as a ratio
    fn output_difference(&self, a: &[FieldElement], b: &[FieldElement]) -> f64 {
        if a.is_empty() || b.is_empty() {
            return 0.0;
        }

        let mut total_diff = 0u128;
        let mut total_val = 0u128;

        for (x, y) in a.iter().zip(b.iter()) {
            let x_val = x.to_u64().unwrap_or(0) as u128;
            let y_val = y.to_u64().unwrap_or(0) as u128;
            total_diff += (x_val as i128 - y_val as i128).unsigned_abs();
            total_val += x_val.max(1);
        }

        if total_val == 0 {
            return 0.0;
        }

        total_diff as f64 / total_val as f64
    }

    /// Calculate potential profit from sandwich attack
    fn calculate_sandwich_profit(
        &self,
        front_outputs: &[FieldElement],
        victim_outputs: &[FieldElement],
        back_outputs: &[FieldElement],
    ) -> f64 {
        // Simplified profit calculation
        // Real implementation would need circuit-specific logic
        
        if front_outputs.is_empty() || back_outputs.is_empty() {
            return 0.0;
        }

        // Assume first output is "value" being traded
        let front_val = front_outputs.first()
            .and_then(|f| f.to_u64())
            .unwrap_or(0) as f64;
        let back_val = back_outputs.first()
            .and_then(|f| f.to_u64())
            .unwrap_or(0) as f64;
        let victim_val = victim_outputs.first()
            .and_then(|f| f.to_u64())
            .unwrap_or(0) as f64;

        if victim_val == 0.0 {
            return 0.0;
        }

        // Profit = (back - front) / victim
        ((back_val - front_val).abs() / victim_val).min(1.0)
    }

    /// Hash outputs for pattern detection
    fn hash_outputs(&self, outputs: &[FieldElement]) -> String {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        for output in outputs {
            output.to_hex().hash(&mut hasher);
        }
        format!("{:x}", hasher.finish())
    }
}

impl MevTestResult {
    /// Convert to standard Finding
    pub fn to_finding(&self) -> Finding {
        Finding {
            attack_type: AttackType::Soundness, // MEV attacks are soundness-related
            severity: self.vulnerability_type.severity(),
            description: format!(
                "[MEV:{}] {}",
                self.vulnerability_type.as_str().to_uppercase(),
                self.description
            ),
            poc: ProofOfConcept {
                witness_a: self.witness.clone(),
                witness_b: None,
                public_inputs: vec![],
                proof: None,
            },
            location: Some(format!("mev:{}", self.vulnerability_type.as_str())),
        }
    }
}

/// Calculate factorial (for permutation counting)
fn factorial(n: usize) -> usize {
    (1..=n).product()
}

/// Price impact analyzer for DEX circuits
pub struct PriceImpactAnalyzer {
    /// Slippage samples collected
    samples: Vec<(f64, f64)>, // (trade_size, price_impact)
    /// Maximum acceptable slippage
    max_slippage: f64,
}

impl PriceImpactAnalyzer {
    pub fn new(max_slippage: f64) -> Self {
        Self {
            samples: Vec::new(),
            max_slippage,
        }
    }

    /// Record a price impact sample
    pub fn record(&mut self, trade_size: f64, price_impact: f64) {
        self.samples.push((trade_size, price_impact));
    }

    /// Analyze for MEV vulnerability
    pub fn analyze(&self) -> Option<MevTestResult> {
        if self.samples.len() < 10 {
            return None;
        }

        // Check for excessive price impact
        let max_impact = self.samples.iter().map(|(_, i)| *i).fold(0.0, f64::max);
        
        if max_impact > self.max_slippage {
            return Some(MevTestResult {
                vulnerability_type: MevVulnerabilityType::PriceManipulation,
                description: format!(
                    "Excessive price impact detected: {:.2}% (max allowed: {:.2}%). \
                     Large trades cause significant slippage, enabling manipulation.",
                    max_impact * 100.0,
                    self.max_slippage * 100.0
                ),
                profit_potential: Some(max_impact),
                witness: vec![],
                context: [
                    ("max_impact".to_string(), format!("{:.4}", max_impact)),
                    ("samples".to_string(), self.samples.len().to_string()),
                ].into_iter().collect(),
            });
        }

        None
    }
}

/// Arbitrage detector for cross-circuit opportunities
pub struct ArbitrageDetector {
    /// Price observations from different circuits
    prices: HashMap<String, Vec<f64>>,
}

impl ArbitrageDetector {
    pub fn new() -> Self {
        Self {
            prices: HashMap::new(),
        }
    }

    /// Record a price observation from a circuit
    pub fn record_price(&mut self, circuit_id: &str, price: f64) {
        self.prices.entry(circuit_id.to_string()).or_default().push(price);
    }

    /// Detect arbitrage opportunities
    pub fn detect_arbitrage(&self, min_profit: f64) -> Vec<MevTestResult> {
        let mut findings = Vec::new();
        let circuit_ids: Vec<_> = self.prices.keys().collect();

        for i in 0..circuit_ids.len() {
            for j in (i + 1)..circuit_ids.len() {
                let id_a = circuit_ids[i];
                let id_b = circuit_ids[j];

                if let (Some(prices_a), Some(prices_b)) = (self.prices.get(id_a), self.prices.get(id_b)) {
                    // Compare average prices
                    let avg_a: f64 = prices_a.iter().sum::<f64>() / prices_a.len() as f64;
                    let avg_b: f64 = prices_b.iter().sum::<f64>() / prices_b.len() as f64;

                    let diff = (avg_a - avg_b).abs() / avg_a.max(avg_b);
                    
                    if diff > min_profit {
                        findings.push(MevTestResult {
                            vulnerability_type: MevVulnerabilityType::Arbitrage,
                            description: format!(
                                "Arbitrage opportunity between {} and {}: {:.2}% price difference. \
                                 Prices differ enough to enable risk-free profit.",
                                id_a, id_b, diff * 100.0
                            ),
                            profit_potential: Some(diff),
                            witness: vec![],
                            context: [
                                ("circuit_a".to_string(), id_a.clone()),
                                ("circuit_b".to_string(), id_b.clone()),
                                ("price_diff".to_string(), format!("{:.4}", diff)),
                            ].into_iter().collect(),
                        });
                    }
                }
            }
        }

        findings
    }
}

impl Default for ArbitrageDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::MockCircuitExecutor;

    #[test]
    fn test_mev_config_default() {
        let config = MevConfig::default();
        assert_eq!(config.ordering_permutations, 100);
        assert!(config.detect_ordering);
        assert!(config.detect_sandwich);
        assert!(config.detect_leakage);
    }

    #[test]
    fn test_mev_vulnerability_types() {
        assert_eq!(
            MevVulnerabilityType::SandwichAttack.severity(),
            Severity::Critical
        );
        assert_eq!(
            MevVulnerabilityType::OrderingDependency.severity(),
            Severity::High
        );
        assert_eq!(
            MevVulnerabilityType::Arbitrage.severity(),
            Severity::Medium
        );
    }

    #[test]
    fn test_mev_result_to_finding() {
        let result = MevTestResult {
            vulnerability_type: MevVulnerabilityType::SandwichAttack,
            description: "Test sandwich attack".to_string(),
            profit_potential: Some(0.05),
            witness: vec![FieldElement::from_u64(1)],
            context: HashMap::new(),
        };

        let finding = result.to_finding();
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.description.contains("SANDWICH_ATTACK"));
    }

    #[test]
    fn test_permutation() {
        let config = MevConfig {
            seed: Some(42),
            ..Default::default()
        };
        let mut attack = MevAttack::new(config);

        let inputs = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
        ];

        let permuted = attack.permute_inputs(&inputs);
        assert_eq!(permuted.len(), inputs.len());
    }

    #[test]
    fn test_output_difference() {
        let config = MevConfig::default();
        let attack = MevAttack::new(config);

        let a = vec![FieldElement::from_u64(100), FieldElement::from_u64(200)];
        let b = vec![FieldElement::from_u64(110), FieldElement::from_u64(210)];

        let diff = attack.output_difference(&a, &b);
        assert!(diff > 0.0);
        assert!(diff < 1.0);
    }

    #[test]
    fn test_price_impact_analyzer() {
        let mut analyzer = PriceImpactAnalyzer::new(0.05); // 5% max slippage

        // Record trades with increasing price impact, eventually exceeding 5%
        for i in 0..15 {
            // Price impact grows quadratically: 0, 0.5%, 2%, 4.5%, 8%...
            analyzer.record(i as f64 * 100.0, 0.005 * (i as f64).powi(2));
        }

        let finding = analyzer.analyze();
        assert!(finding.is_some(), "Should detect price impact exceeding 5%");
    }

    #[test]
    fn test_arbitrage_detector() {
        let mut detector = ArbitrageDetector::new();

        // Record prices from two circuits
        detector.record_price("dex_a", 100.0);
        detector.record_price("dex_a", 101.0);
        detector.record_price("dex_b", 110.0);
        detector.record_price("dex_b", 111.0);

        let findings = detector.detect_arbitrage(0.05); // 5% min profit
        assert!(!findings.is_empty());
    }
}
