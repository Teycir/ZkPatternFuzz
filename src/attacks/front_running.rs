//! Front-Running Attack Detection (Phase 3: Milestone 3.1)
//!
//! Detects vulnerabilities that enable front-running attacks in ZK circuits:
//! - Transaction visibility: Can transactions be observed before execution?
//! - Predictable outcomes: Can outcomes be predicted from public data?
//! - Time-based attacks: Are there timing vulnerabilities?
//!
//! # Attack Patterns
//!
//! ## Information Leakage
//! Circuits where public outputs reveal too much about private inputs,
//! allowing attackers to predict and front-run transactions.
//!
//! ## Commitment Bypass
//! Circuits with weak commitment schemes that can be opened early.
//!
//! ## Delay Attack
//! Circuits where delaying transaction inclusion is profitable.
//!
//! # Usage
//!
//! ```rust,ignore
//! use zk_fuzzer::attacks::front_running::{FrontRunningAttack, FrontRunningConfig};
//!
//! let config = FrontRunningConfig::default();
//! let mut attack = FrontRunningAttack::new(config);
//!
//! let findings = attack.run(&executor, &inputs)?;
//! ```

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

/// Configuration for front-running attack detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontRunningConfig {
    /// Number of information leakage tests
    pub leakage_tests: usize,
    /// Number of commitment bypass attempts
    pub commitment_tests: usize,
    /// Enable information leakage detection
    pub detect_leakage: bool,
    /// Enable commitment bypass detection
    pub detect_commitment_bypass: bool,
    /// Enable delay attack detection
    pub detect_delay_attack: bool,
    /// Entropy threshold for leakage detection
    pub entropy_threshold: f64,
    /// Random seed for reproducibility
    pub seed: Option<u64>,
}

impl Default for FrontRunningConfig {
    fn default() -> Self {
        Self {
            leakage_tests: 100,
            commitment_tests: 50,
            detect_leakage: true,
            detect_commitment_bypass: true,
            detect_delay_attack: true,
            entropy_threshold: 3.0, // bits
            seed: None,
        }
    }
}

/// Types of front-running vulnerabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FrontRunningVulnerability {
    /// Outputs leak information about private inputs
    InformationLeakage,
    /// Commitment scheme can be bypassed
    CommitmentBypass,
    /// Delayed execution is profitable
    DelayAttack,
    /// Predictable randomness enables front-running
    PredictableRandomness,
    /// Weak hiding property in commitment
    WeakHiding,
}

impl FrontRunningVulnerability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InformationLeakage => "information_leakage",
            Self::CommitmentBypass => "commitment_bypass",
            Self::DelayAttack => "delay_attack",
            Self::PredictableRandomness => "predictable_randomness",
            Self::WeakHiding => "weak_hiding",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::InformationLeakage => Severity::High,
            Self::CommitmentBypass => Severity::Critical,
            Self::DelayAttack => Severity::Medium,
            Self::PredictableRandomness => Severity::Critical,
            Self::WeakHiding => Severity::High,
        }
    }
}

/// Result of a front-running attack test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontRunningResult {
    /// Type of vulnerability detected
    pub vulnerability_type: FrontRunningVulnerability,
    /// Description of the finding
    pub description: String,
    /// Witness inputs that demonstrate the vulnerability
    pub witness: Vec<FieldElement>,
    /// Additional context
    pub context: HashMap<String, String>,
    /// Measured entropy (if applicable)
    pub measured_entropy: Option<f64>,
}

impl FrontRunningResult {
    /// Convert to standard Finding
    pub fn to_finding(&self) -> Finding {
        Finding {
            attack_type: AttackType::Soundness,
            severity: self.vulnerability_type.severity(),
            description: format!(
                "[FRONT_RUNNING:{}] {}",
                self.vulnerability_type.as_str().to_uppercase(),
                self.description
            ),
            poc: ProofOfConcept {
                witness_a: self.witness.clone(),
                witness_b: None,
                public_inputs: vec![],
                proof: None,
            },
            location: Some(format!("front_running:{}", self.vulnerability_type.as_str())),
        }
    }
}

/// Front-running attack detection engine
pub struct FrontRunningAttack {
    config: FrontRunningConfig,
    rng: ChaCha8Rng,
    findings: Vec<FrontRunningResult>,
}

impl FrontRunningAttack {
    /// Create a new front-running attack detector
    pub fn new(config: FrontRunningConfig) -> Self {
        let seed = config.seed.unwrap_or_else(rand::random);
        Self {
            config,
            rng: ChaCha8Rng::seed_from_u64(seed),
            findings: Vec::new(),
        }
    }

    /// Run front-running attack detection
    pub fn run(
        &mut self,
        executor: &dyn CircuitExecutor,
        base_inputs: &[FieldElement],
    ) -> anyhow::Result<Vec<Finding>> {
        self.findings.clear();

        if self.config.detect_leakage {
            self.detect_information_leakage(executor, base_inputs)?;
        }

        if self.config.detect_commitment_bypass {
            self.detect_commitment_bypass(executor, base_inputs)?;
        }

        if self.config.detect_delay_attack {
            self.detect_delay_attack(executor, base_inputs)?;
        }

        Ok(self.findings.iter().map(|r| r.to_finding()).collect())
    }

    /// Detect information leakage vulnerabilities
    fn detect_information_leakage(
        &mut self,
        executor: &dyn CircuitExecutor,
        base_inputs: &[FieldElement],
    ) -> anyhow::Result<()> {
        let num_public = executor.num_public_inputs();
        let num_private = executor.num_private_inputs();

        if num_private == 0 {
            return Ok(());
        }

        // Collect output distributions for varying private inputs
        let mut output_buckets: HashMap<String, usize> = HashMap::new();
        let mut private_input_samples: Vec<Vec<FieldElement>> = Vec::new();

        for _ in 0..self.config.leakage_tests {
            let mut inputs = base_inputs.to_vec();
            
            // Vary only private inputs
            for i in num_public..inputs.len().min(num_public + num_private) {
                inputs[i] = FieldElement::random(&mut self.rng);
            }

            let result = executor.execute_sync(&inputs);
            if result.success {
                let output_key = self.hash_outputs(&result.outputs);
                *output_buckets.entry(output_key).or_insert(0) += 1;
                private_input_samples.push(inputs[num_public..].to_vec());
            }
        }

        // Calculate output entropy
        let total = output_buckets.values().sum::<usize>() as f64;
        let entropy: f64 = output_buckets.values()
            .map(|&count| {
                let p = count as f64 / total;
                if p > 0.0 { -p * p.log2() } else { 0.0 }
            })
            .sum();

        // Low entropy means outputs are predictable from private inputs
        if entropy < self.config.entropy_threshold {
            self.findings.push(FrontRunningResult {
                vulnerability_type: FrontRunningVulnerability::InformationLeakage,
                description: format!(
                    "Low output entropy detected: {:.2} bits (threshold: {:.2}). \
                     Public outputs may reveal private input patterns, enabling \
                     front-running attacks based on output prediction.",
                    entropy, self.config.entropy_threshold
                ),
                witness: base_inputs.to_vec(),
                context: [
                    ("entropy".to_string(), format!("{:.4}", entropy)),
                    ("unique_outputs".to_string(), output_buckets.len().to_string()),
                    ("samples".to_string(), self.config.leakage_tests.to_string()),
                ].into_iter().collect(),
                measured_entropy: Some(entropy),
            });
        }

        // Check for correlation between private inputs and outputs
        self.check_input_output_correlation(&private_input_samples, &output_buckets)?;

        Ok(())
    }

    /// Check for suspicious correlations between inputs and outputs
    fn check_input_output_correlation(
        &mut self,
        samples: &[Vec<FieldElement>],
        _output_buckets: &HashMap<String, usize>,
    ) -> anyhow::Result<()> {
        if samples.len() < 10 {
            return Ok(());
        }

        // Simple correlation check: do outputs cluster by input ranges?
        let mut high_inputs = 0;
        let mut low_inputs = 0;
        let threshold = FieldElement::from_u64(u64::MAX / 2);

        for sample in samples {
            if let Some(first) = sample.first() {
                if first.to_u64() > threshold.to_u64() {
                    high_inputs += 1;
                } else {
                    low_inputs += 1;
                }
            }
        }

        // If inputs cluster strongly, outputs might be predictable
        let ratio = (high_inputs as f64 / (low_inputs.max(1) as f64)).max(
            low_inputs as f64 / (high_inputs.max(1) as f64)
        );

        if ratio > 5.0 {
            self.findings.push(FrontRunningResult {
                vulnerability_type: FrontRunningVulnerability::PredictableRandomness,
                description: format!(
                    "Input distribution shows strong clustering (ratio: {:.1}x). \
                     This may indicate predictable input patterns that enable \
                     front-running based on input guessing.",
                    ratio
                ),
                witness: vec![],
                context: [
                    ("high_inputs".to_string(), high_inputs.to_string()),
                    ("low_inputs".to_string(), low_inputs.to_string()),
                    ("clustering_ratio".to_string(), format!("{:.2}", ratio)),
                ].into_iter().collect(),
                measured_entropy: None,
            });
        }

        Ok(())
    }

    /// Detect commitment bypass vulnerabilities
    fn detect_commitment_bypass(
        &mut self,
        executor: &dyn CircuitExecutor,
        base_inputs: &[FieldElement],
    ) -> anyhow::Result<()> {
        // Test commitment binding: same commitment should require same opening
        let mut commitment_map: HashMap<String, Vec<Vec<FieldElement>>> = HashMap::new();

        for _ in 0..self.config.commitment_tests {
            let mut inputs = base_inputs.to_vec();
            
            // Vary inputs randomly
            for input in inputs.iter_mut() {
                if self.rng.gen_bool(0.3) {
                    *input = FieldElement::random(&mut self.rng);
                }
            }

            let result = executor.execute_sync(&inputs);
            if result.success {
                // First output is typically the commitment
                let commitment_key = result.outputs.first()
                    .map(|f| f.to_hex())
                    .unwrap_or_default();
                
                commitment_map
                    .entry(commitment_key)
                    .or_default()
                    .push(inputs.clone());
            }
        }

        // Check for commitment collisions (same commitment, different inputs)
        for (commitment, input_sets) in &commitment_map {
            if input_sets.len() > 1 {
                // Found multiple inputs producing same commitment
                let first = &input_sets[0];
                let second = &input_sets[1];
                
                if first != second {
                    self.findings.push(FrontRunningResult {
                        vulnerability_type: FrontRunningVulnerability::CommitmentBypass,
                        description: format!(
                            "Commitment collision detected: {} different inputs produce \
                             the same commitment ({}...). This breaks the binding property \
                             and enables commitment forgery attacks.",
                            input_sets.len(),
                            &commitment[..16.min(commitment.len())]
                        ),
                        witness: first.clone(),
                        context: [
                            ("commitment".to_string(), commitment.clone()),
                            ("collision_count".to_string(), input_sets.len().to_string()),
                        ].into_iter().collect(),
                        measured_entropy: None,
                    });
                    break; // One finding is enough
                }
            }
        }

        // Check for weak hiding (similar inputs produce similar commitments)
        self.check_weak_hiding(executor, base_inputs)?;

        Ok(())
    }

    /// Check for weak hiding property in commitments
    fn check_weak_hiding(
        &mut self,
        executor: &dyn CircuitExecutor,
        base_inputs: &[FieldElement],
    ) -> anyhow::Result<()> {
        // Generate pairs of similar inputs
        let mut similar_pairs = Vec::new();

        for _ in 0..20 {
            let inputs_a = base_inputs.to_vec();
            let mut inputs_b = inputs_a.clone();
            
            // Make small modification
            if let Some(input) = inputs_b.first_mut() {
                *input = input.add(&FieldElement::from_u64(1));
            }

            let result_a = executor.execute_sync(&inputs_a);
            let result_b = executor.execute_sync(&inputs_b);

            if result_a.success && result_b.success {
                let output_a = result_a.outputs.first()
                    .and_then(|f| f.to_u64())
                    .unwrap_or(0);
                let output_b = result_b.outputs.first()
                    .and_then(|f| f.to_u64())
                    .unwrap_or(0);
                
                let diff = (output_a as i128 - output_b as i128).unsigned_abs();
                similar_pairs.push(diff);
            }
        }

        if similar_pairs.len() >= 10 {
            // Check if outputs are too similar for similar inputs
            let avg_diff: f64 = similar_pairs.iter().sum::<u128>() as f64 / similar_pairs.len() as f64;
            let max_expected_diff = u64::MAX as f64 * 0.001; // 0.1% of field

            if avg_diff < max_expected_diff {
                self.findings.push(FrontRunningResult {
                    vulnerability_type: FrontRunningVulnerability::WeakHiding,
                    description: format!(
                        "Weak hiding property detected: similar inputs produce similar \
                         outputs (avg diff: {:.0}). This may allow attackers to infer \
                         private inputs from output patterns.",
                        avg_diff
                    ),
                    witness: base_inputs.to_vec(),
                    context: [
                        ("avg_output_diff".to_string(), format!("{:.0}", avg_diff)),
                        ("samples".to_string(), similar_pairs.len().to_string()),
                    ].into_iter().collect(),
                    measured_entropy: None,
                });
            }
        }

        Ok(())
    }

    /// Detect delay attack vulnerabilities
    fn detect_delay_attack(
        &mut self,
        executor: &dyn CircuitExecutor,
        base_inputs: &[FieldElement],
    ) -> anyhow::Result<()> {
        // Check if circuit outputs are time-sensitive
        // This is a heuristic check for circuits that might have timestamp or
        // block number dependencies

        let mut outputs_over_time: Vec<Vec<FieldElement>> = Vec::new();

        // Simulate "time" passing by varying a potential timestamp input
        for time_offset in 0..10 {
            let mut inputs = base_inputs.to_vec();
            
            // Assume last input might be a timestamp
            if let Some(last) = inputs.last_mut() {
                *last = FieldElement::from_u64(time_offset * 100);
            }

            let result = executor.execute_sync(&inputs);
            if result.success {
                outputs_over_time.push(result.outputs);
            }
        }

        if outputs_over_time.len() >= 5 {
            // Check if outputs vary with "time"
            let first_outputs = &outputs_over_time[0];
            let mut time_sensitive = false;

            for outputs in outputs_over_time.iter().skip(1) {
                if outputs != first_outputs {
                    time_sensitive = true;
                    break;
                }
            }

            if time_sensitive {
                self.findings.push(FrontRunningResult {
                    vulnerability_type: FrontRunningVulnerability::DelayAttack,
                    description: "Circuit outputs appear time-sensitive. If transaction \
                         timing affects outcomes, attackers may profit by strategically \
                         delaying or accelerating transaction inclusion.".to_string(),
                    witness: base_inputs.to_vec(),
                    context: [
                        ("time_samples".to_string(), outputs_over_time.len().to_string()),
                    ].into_iter().collect(),
                    measured_entropy: None,
                });
            }
        }

        Ok(())
    }

    /// Hash outputs for comparison
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

/// State leakage analyzer for privacy circuits
pub struct StateLeakageAnalyzer {
    /// Output observations
    observations: Vec<(Vec<FieldElement>, Vec<FieldElement>)>, // (private_inputs, outputs)
    /// Minimum samples for analysis
    min_samples: usize,
}

impl StateLeakageAnalyzer {
    pub fn new(min_samples: usize) -> Self {
        Self {
            observations: Vec::new(),
            min_samples,
        }
    }

    /// Record an observation
    pub fn observe(&mut self, private_inputs: Vec<FieldElement>, outputs: Vec<FieldElement>) {
        self.observations.push((private_inputs, outputs));
    }

    /// Analyze for state leakage
    pub fn analyze(&self) -> Option<FrontRunningResult> {
        if self.observations.len() < self.min_samples {
            return None;
        }

        // Calculate mutual information between inputs and outputs
        let unique_inputs: HashSet<String> = self.observations.iter()
            .map(|(inputs, _)| inputs.iter().map(|f| f.to_hex()).collect::<Vec<_>>().join(","))
            .collect();

        let unique_outputs: HashSet<String> = self.observations.iter()
            .map(|(_, outputs)| outputs.iter().map(|f| f.to_hex()).collect::<Vec<_>>().join(","))
            .collect();

        let input_entropy = (unique_inputs.len() as f64).log2();
        let output_entropy = (unique_outputs.len() as f64).log2();

        // If output entropy is much lower than input entropy, information is being leaked
        if input_entropy > 0.0 && output_entropy / input_entropy < 0.5 {
            return Some(FrontRunningResult {
                vulnerability_type: FrontRunningVulnerability::InformationLeakage,
                description: format!(
                    "State leakage detected: output entropy ({:.2} bits) is much lower \
                     than input entropy ({:.2} bits). Private state can be inferred.",
                    output_entropy, input_entropy
                ),
                witness: vec![],
                context: [
                    ("input_entropy".to_string(), format!("{:.4}", input_entropy)),
                    ("output_entropy".to_string(), format!("{:.4}", output_entropy)),
                    ("leakage_ratio".to_string(), format!("{:.4}", output_entropy / input_entropy)),
                ].into_iter().collect(),
                measured_entropy: Some(output_entropy),
            });
        }

        None
    }
}

impl Default for StateLeakageAnalyzer {
    fn default() -> Self {
        Self::new(50)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_front_running_config_default() {
        let config = FrontRunningConfig::default();
        assert_eq!(config.leakage_tests, 100);
        assert!(config.detect_leakage);
        assert!(config.detect_commitment_bypass);
    }

    #[test]
    fn test_vulnerability_types() {
        assert_eq!(
            FrontRunningVulnerability::CommitmentBypass.severity(),
            Severity::Critical
        );
        assert_eq!(
            FrontRunningVulnerability::InformationLeakage.severity(),
            Severity::High
        );
        assert_eq!(
            FrontRunningVulnerability::DelayAttack.severity(),
            Severity::Medium
        );
    }

    #[test]
    fn test_result_to_finding() {
        let result = FrontRunningResult {
            vulnerability_type: FrontRunningVulnerability::InformationLeakage,
            description: "Test leakage".to_string(),
            witness: vec![FieldElement::from_u64(1)],
            context: HashMap::new(),
            measured_entropy: Some(1.5),
        };

        let finding = result.to_finding();
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.description.contains("INFORMATION_LEAKAGE"));
    }

    #[test]
    fn test_state_leakage_analyzer() {
        let mut analyzer = StateLeakageAnalyzer::new(10);

        // Add observations with low output diversity
        for i in 0..20 {
            let private = vec![FieldElement::from_u64(i)];
            let output = vec![FieldElement::from_u64(i % 3)]; // Only 3 unique outputs
            analyzer.observe(private, output);
        }

        let finding = analyzer.analyze();
        assert!(finding.is_some());
    }
}
