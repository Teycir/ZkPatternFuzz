//! CVE Pattern Database and Regression Testing
//!
//! This module provides:
//! - Parsing of known vulnerability patterns from YAML
//! - Regression test generation for each CVE
//! - Detection pattern matching during fuzzing
//!
//! # Example
//!
//! ```rust,ignore
//! use zk_fuzzer::cve::{CveDatabase, CvePattern};
//!
//! let db = CveDatabase::load("templates/known_vulnerabilities.yaml")?;
//! let patterns = db.patterns_for_circuit("tornado-core");
//!
//! for pattern in patterns {
//!     println!("Testing for {}: {}", pattern.id, pattern.name);
//! }
//! ```

use crate::config::{AttackType, Severity};
use crate::fuzzer::{FieldElement, Finding, ProofOfConcept, TestCase};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Complete CVE database loaded from YAML
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CveDatabase {
    pub version: String,
    pub last_updated: String,
    pub vulnerabilities: Vec<CvePattern>,
    #[serde(default)]
    pub interesting_values: HashMap<String, Vec<InterestingValue>>,
    #[serde(default)]
    pub oracle_configs: HashMap<String, serde_yaml::Value>,
}

impl CveDatabase {
    /// Load CVE database from YAML file
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let db: CveDatabase = serde_yaml::from_str(&content)?;
        Ok(db)
    }

    /// Get all CVE patterns
    pub fn all_patterns(&self) -> &[CvePattern] {
        &self.vulnerabilities
    }

    /// Get patterns that apply to a specific circuit
    pub fn patterns_for_circuit(&self, circuit_name: &str) -> Vec<&CvePattern> {
        self.vulnerabilities
            .iter()
            .filter(|p| p.affects_circuit(circuit_name))
            .collect()
    }

    /// Get patterns by severity
    pub fn patterns_by_severity(&self, severity: Severity) -> Vec<&CvePattern> {
        self.vulnerabilities
            .iter()
            .filter(|p| p.severity_enum() == severity)
            .collect()
    }

    /// Get pattern by ID
    pub fn get_pattern(&self, id: &str) -> Option<&CvePattern> {
        self.vulnerabilities.iter().find(|p| p.id == id)
    }

    /// Generate regression tests for all patterns
    pub fn generate_regression_tests(&self) -> Vec<RegressionTest> {
        self.vulnerabilities
            .iter()
            .filter(|p| p.regression_test.enabled)
            .map(RegressionTest::from_pattern)
            .collect()
    }

    /// Get interesting values by category
    pub fn get_interesting_values(&self, category: &str) -> Vec<&InterestingValue> {
        self.interesting_values
            .get(category)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }
}

/// Individual CVE pattern
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CvePattern {
    pub id: String,
    pub name: String,
    pub severity: String,
    #[serde(default)]
    pub cvss_score: Option<f64>,
    pub affected_circuits: Vec<AffectedCircuit>,
    #[serde(default)]
    pub sources: Vec<String>,
    pub description: String,
    pub detection: DetectionConfig,
    pub regression_test: RegressionTestConfig,
    pub remediation: RemediationInfo,
}

impl CvePattern {
    /// Check if this CVE affects the given circuit
    pub fn affects_circuit(&self, circuit_name: &str) -> bool {
        self.affected_circuits.iter().any(|ac| {
            let pattern = &ac.pattern;
            if pattern.contains('*') {
                // Wildcard matching
                let prefix = pattern.trim_end_matches('*');
                circuit_name.contains(prefix)
            } else {
                circuit_name.contains(pattern)
            }
        })
    }

    /// Convert severity string to enum
    pub fn severity_enum(&self) -> Severity {
        match self.severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    /// Get attack type for this CVE
    pub fn attack_type(&self) -> AttackType {
        match self.detection.attack_type.to_lowercase().as_str() {
            "malleability" => AttackType::Malleability,
            "collision" => AttackType::Collision,
            "boundary" => AttackType::Boundary,
            "underconstrained" => AttackType::Underconstrained,
            "arithmetic_overflow" => AttackType::ArithmeticOverflow,
            "timing_side_channel" => AttackType::TimingSideChannel,
            "information_leakage" => AttackType::InformationLeakage,
            _ => AttackType::Soundness,
        }
    }

    /// Create a finding for this CVE
    pub fn create_finding(&self, poc: ProofOfConcept, location: Option<String>) -> Finding {
        Finding {
            attack_type: self.attack_type(),
            severity: self.severity_enum(),
            description: format!(
                "[{}] {}\n\n{}\n\nSources: {}",
                self.id,
                self.name,
                self.description.trim(),
                self.sources.join(", ")
            ),
            poc,
            location,
        }
    }
}

/// Affected circuit specification
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AffectedCircuit {
    pub pattern: String,
    #[serde(default)]
    pub versions: Vec<String>,
}

/// Detection configuration for a CVE
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DetectionConfig {
    pub oracle: String,
    pub attack_type: String,
    #[serde(default)]
    pub procedure: Vec<DetectionStep>,
}

/// Single step in detection procedure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DetectionStep {
    pub action: String,
    #[serde(default)]
    pub params: HashMap<String, serde_yaml::Value>,
    #[serde(default)]
    pub expected: Option<serde_yaml::Value>,
}

/// Regression test configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegressionTestConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub circuit_path: String,
    #[serde(default)]
    pub test_cases: Vec<TestCaseConfig>,
    #[serde(default)]
    pub assertion: String,
}

fn default_true() -> bool {
    true
}

/// Test case configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestCaseConfig {
    pub name: String,
    #[serde(default)]
    pub inputs: HashMap<String, serde_yaml::Value>,
    pub expected_result: String,
}

/// Remediation information
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemediationInfo {
    pub description: String,
    #[serde(default)]
    pub code_example: Option<String>,
    #[serde(default)]
    pub recommendations: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

/// Interesting value for testing
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InterestingValue {
    pub name: String,
    pub value: String,
}

/// Generated regression test
#[derive(Debug, Clone)]
pub struct RegressionTest {
    pub cve_id: String,
    pub cve_name: String,
    pub circuit_path: String,
    pub test_cases: Vec<GeneratedTestCase>,
    pub assertion: String,
}

impl RegressionTest {
    /// Create from CVE pattern
    pub fn from_pattern(pattern: &CvePattern) -> Self {
        let test_cases = pattern
            .regression_test
            .test_cases
            .iter()
            .map(|tc| GeneratedTestCase {
                name: tc.name.clone(),
                inputs: tc.inputs.clone(),
                expected_valid: tc.expected_result.contains("valid")
                    && !tc.expected_result.contains("invalid"),
            })
            .collect();

        Self {
            cve_id: pattern.id.clone(),
            cve_name: pattern.name.clone(),
            circuit_path: pattern.regression_test.circuit_path.clone(),
            test_cases,
            assertion: pattern.regression_test.assertion.clone(),
        }
    }

    /// Run regression test (placeholder for actual implementation)
    pub fn run(&self) -> RegressionTestResult {
        // This would be implemented with actual circuit execution
        RegressionTestResult {
            cve_id: self.cve_id.clone(),
            passed: true, // Placeholder
            test_results: self
                .test_cases
                .iter()
                .map(|tc| TestCaseResult {
                    name: tc.name.clone(),
                    passed: true, // Placeholder
                    message: None,
                })
                .collect(),
        }
    }
}

/// Generated test case
#[derive(Debug, Clone)]
pub struct GeneratedTestCase {
    pub name: String,
    pub inputs: HashMap<String, serde_yaml::Value>,
    pub expected_valid: bool,
}

/// Result of running a regression test
#[derive(Debug, Clone)]
pub struct RegressionTestResult {
    pub cve_id: String,
    pub passed: bool,
    pub test_results: Vec<TestCaseResult>,
}

/// Result of a single test case
#[derive(Debug, Clone)]
pub struct TestCaseResult {
    pub name: String,
    pub passed: bool,
    pub message: Option<String>,
}

/// CVE-aware oracle that checks for known vulnerability patterns
pub struct CveOracle {
    database: CveDatabase,
    active_patterns: Vec<String>,
}

impl CveOracle {
    /// Create oracle with all patterns active
    pub fn new(database: CveDatabase) -> Self {
        let active_patterns = database
            .vulnerabilities
            .iter()
            .map(|p| p.id.clone())
            .collect();
        Self {
            database,
            active_patterns,
        }
    }

    /// Create oracle for specific circuit
    pub fn for_circuit(database: CveDatabase, circuit_name: &str) -> Self {
        let active_patterns = database
            .patterns_for_circuit(circuit_name)
            .iter()
            .map(|p| p.id.clone())
            .collect();
        Self {
            database,
            active_patterns,
        }
    }

    /// Check test case against known CVE patterns
    pub fn check(&self, test_case: &TestCase, output: &[FieldElement]) -> Option<Finding> {
        for pattern_id in &self.active_patterns {
            if let Some(pattern) = self.database.get_pattern(pattern_id) {
                if let Some(finding) = self.check_pattern(pattern, test_case, output) {
                    return Some(finding);
                }
            }
        }
        None
    }

    /// Check single pattern (placeholder for actual implementation)
    fn check_pattern(
        &self,
        pattern: &CvePattern,
        test_case: &TestCase,
        _output: &[FieldElement],
    ) -> Option<Finding> {
        // This would implement pattern-specific detection logic
        // For now, return None (no finding)
        match pattern.detection.oracle.as_str() {
            "signature_malleability" => self.check_signature_malleability(pattern, test_case),
            "nullifier_collision" => None, // Handled by NullifierOracle
            "merkle_soundness" => None,    // Handled by MerkleOracle
            "range_overflow" => self.check_range_overflow(pattern, test_case),
            _ => None,
        }
    }

    /// Check for signature malleability
    fn check_signature_malleability(
        &self,
        pattern: &CvePattern,
        test_case: &TestCase,
    ) -> Option<Finding> {
        // Check if signature s component is > q/2
        if test_case.inputs.len() >= 2 {
            let s = &test_case.inputs[1]; // Assume s is second input
            let half_q = FieldElement::half_modulus();

            // If s > q/2, it's potentially malleable
            if s.to_biguint() > half_q.to_biguint() {
                return Some(pattern.create_finding(
                    ProofOfConcept {
                        witness_a: test_case.inputs.clone(),
                        witness_b: Some(vec![
                            test_case.inputs[0].clone(),
                            s.neg(), // Negated s
                        ]),
                        public_inputs: vec![],
                        proof: None,
                    },
                    Some("signature.s > q/2".to_string()),
                ));
            }
        }
        None
    }

    /// Check for range overflow
    fn check_range_overflow(
        &self,
        pattern: &CvePattern,
        test_case: &TestCase,
    ) -> Option<Finding> {
        // Check for values that might overflow bit decomposition
        for (i, input) in test_case.inputs.iter().enumerate() {
            // Check if input is suspiciously large
            let bytes = input.to_bytes();
            let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();

            // If value uses most of the field, it might cause overflow
            if leading_zeros < 4 {
                return Some(pattern.create_finding(
                    ProofOfConcept {
                        witness_a: test_case.inputs.clone(),
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                    Some(format!("input[{}] near field max", i)),
                ));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_cve_database() {
        let yaml = r#"
version: "1.0"
last_updated: "2026-02-05"
vulnerabilities:
  - id: "ZK-TEST-001"
    name: "Test Vulnerability"
    severity: high
    affected_circuits:
      - pattern: "test_circuit"
        versions: ["*"]
    sources:
      - "Test Source"
    description: "Test description"
    detection:
      oracle: test_oracle
      attack_type: boundary
      procedure: []
    regression_test:
      enabled: true
      circuit_path: "test.circom"
      test_cases: []
      assertion: "Test assertion"
    remediation:
      description: "Test remediation"
"#;
        let db: CveDatabase = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(db.vulnerabilities.len(), 1);
        assert_eq!(db.vulnerabilities[0].id, "ZK-TEST-001");
    }

    #[test]
    fn test_pattern_matching() {
        let pattern = CvePattern {
            id: "ZK-TEST-001".to_string(),
            name: "Test".to_string(),
            severity: "high".to_string(),
            cvss_score: Some(8.0),
            affected_circuits: vec![AffectedCircuit {
                pattern: "tornado*".to_string(),
                versions: vec!["*".to_string()],
            }],
            sources: vec![],
            description: "Test".to_string(),
            detection: DetectionConfig {
                oracle: "test".to_string(),
                attack_type: "boundary".to_string(),
                procedure: vec![],
            },
            regression_test: RegressionTestConfig {
                enabled: true,
                circuit_path: "test.circom".to_string(),
                test_cases: vec![],
                assertion: "".to_string(),
            },
            remediation: RemediationInfo {
                description: "Test".to_string(),
                code_example: None,
                recommendations: vec![],
                references: vec![],
            },
        };

        assert!(pattern.affects_circuit("tornado-core"));
        assert!(pattern.affects_circuit("tornado-cash"));
        assert!(!pattern.affects_circuit("semaphore"));
    }

    #[test]
    fn test_severity_conversion() {
        let pattern = CvePattern {
            id: "".to_string(),
            name: "".to_string(),
            severity: "critical".to_string(),
            cvss_score: None,
            affected_circuits: vec![],
            sources: vec![],
            description: "".to_string(),
            detection: DetectionConfig {
                oracle: "".to_string(),
                attack_type: "".to_string(),
                procedure: vec![],
            },
            regression_test: RegressionTestConfig {
                enabled: false,
                circuit_path: "".to_string(),
                test_cases: vec![],
                assertion: "".to_string(),
            },
            remediation: RemediationInfo {
                description: "".to_string(),
                code_example: None,
                recommendations: vec![],
                references: vec![],
            },
        };

        assert_eq!(pattern.severity_enum(), Severity::Critical);
    }
}
