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

use crate::executor::{ExecutorFactory, ExecutorFactoryOptions};
use crate::fuzzer::oracles::{
    CommitmentOracle, MerkleOracle, NullifierOracle, OracleConfig, RangeProofOracle, SemanticOracle,
};
use num_bigint::BigUint;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use zk_core::{AttackType, FieldElement, Finding, Framework, ProofOfConcept, Severity, TestCase};

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

    /// Load CVE database and enforce strict fixture semantics.
    ///
    /// Strict mode rejects ambiguous regression fixtures:
    /// - non-validity expected results
    /// - unsupported string literals in test inputs
    pub fn load_strict<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let db = Self::load(path)?;
        db.validate_regression_fixtures_strict()?;
        Ok(db)
    }

    /// Validate regression fixtures with strict, unambiguous semantics.
    pub fn validate_regression_fixtures_strict(&self) -> anyhow::Result<()> {
        let mut errors = Vec::new();

        for pattern in &self.vulnerabilities {
            if !pattern.regression_test.enabled {
                continue;
            }

            let expanded_circuit_path =
                expand_env_placeholders(&pattern.regression_test.circuit_path);
            if has_unresolved_env_placeholder(&expanded_circuit_path) {
                errors.push(format!(
                    "{} has unresolved env placeholder in regression_test.circuit_path '{}'. Set required environment variables.",
                    pattern.id, pattern.regression_test.circuit_path
                ));
            }

            for tc in &pattern.regression_test.test_cases {
                if tc.name.trim().is_empty() {
                    errors.push(format!(
                        "{}: regression test case has empty name",
                        pattern.id
                    ));
                }

                if !is_strict_expected_result(&tc.expected_result) {
                    errors.push(format!(
                        "{}:{} has ambiguous expected_result '{}'. Use explicit validity labels only.",
                        pattern.id, tc.name, tc.expected_result
                    ));
                }

                for (key, value) in &tc.inputs {
                    let key_name = match key {
                        serde_yaml::Value::String(s) if !s.trim().is_empty() => s.clone(),
                        serde_yaml::Value::String(_) => {
                            errors.push(format!("{}:{} has empty input key", pattern.id, tc.name));
                            "<empty-key>".to_string()
                        }
                        _ => {
                            errors.push(format!(
                                "{}:{} has non-string input key '{}'",
                                pattern.id,
                                tc.name,
                                match serde_yaml::to_string(key) {
                                    Ok(value) => value.trim().to_string(),
                                    Err(err) => format!("<unprintable:{}>", err),
                                }
                            ));
                            "<non-string-key>".to_string()
                        }
                    };
                    validate_strict_fixture_value(
                        value,
                        &format!("{}:{}:{}", pattern.id, tc.name, key_name),
                        &mut errors,
                    );
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(
                "Strict CVE fixture validation failed:\n{}",
                errors.join("\n")
            )
        }
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
        match self.interesting_values.get(category) {
            Some(values) => values.iter().collect(),
            None => Vec::new(),
        }
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
        self.affected_circuits
            .iter()
            .any(|ac| ac.matches_circuit(circuit_name))
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

impl AffectedCircuit {
    fn matches_circuit(&self, circuit_name: &str) -> bool {
        let pattern = self.pattern.trim();
        if pattern.is_empty() {
            return false;
        }

        if let Some(raw_regex) = parse_regex_pattern(pattern) {
            return matches_regex(raw_regex, circuit_name);
        }

        if pattern.contains('*') || pattern.contains('?') {
            let glob_regex = glob_like_to_regex(pattern);
            return matches_regex(&glob_regex, circuit_name);
        }

        let pattern_lc = pattern.to_ascii_lowercase();
        let circuit_lc = circuit_name.to_ascii_lowercase();
        if circuit_lc.contains(&pattern_lc) {
            return true;
        }

        // Resilient recovery for small naming/path differences such as
        // `tornado-core` vs `tornado_core` vs `tornado/core`.
        let normalized_pattern = normalize_circuit_token(pattern);
        let normalized_circuit = normalize_circuit_token(circuit_name);
        !normalized_pattern.is_empty() && normalized_circuit.contains(&normalized_pattern)
    }
}

fn parse_regex_pattern(pattern: &str) -> Option<&str> {
    let trimmed = pattern.trim();
    if let Some(regex) = trimmed.strip_prefix("regex:") {
        return Some(regex.trim());
    }
    if let Some(regex) = trimmed.strip_prefix("re:") {
        return Some(regex.trim());
    }
    if trimmed.len() >= 2 && trimmed.starts_with('/') && trimmed.ends_with('/') {
        return Some(&trimmed[1..trimmed.len() - 1]);
    }
    None
}

fn glob_like_to_regex(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() + 8);
    for ch in pattern.chars() {
        match ch {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

fn matches_regex(pattern: &str, value: &str) -> bool {
    match RegexBuilder::new(pattern).case_insensitive(true).build() {
        Ok(re) => re.is_match(value),
        Err(err) => {
            tracing::warn!(
                "Skipping invalid CVE affected_circuits regex '{}': {}",
                pattern,
                err
            );
            false
        }
    }
}

fn normalize_circuit_token(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
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
    pub inputs: serde_yaml::Mapping,
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
        let circuit_path = expand_env_placeholders(&pattern.regression_test.circuit_path);
        let test_cases = pattern
            .regression_test
            .test_cases
            .iter()
            .map(|tc| {
                let mut ordered_inputs = Vec::new();
                for (key, value) in &tc.inputs {
                    if let serde_yaml::Value::String(name) = key {
                        ordered_inputs.push((name.clone(), value.clone()));
                    }
                }

                let expected_valid = expected_result_to_validity(&tc.expected_result);

                GeneratedTestCase {
                    name: tc.name.clone(),
                    inputs: ordered_inputs,
                    expected_result: tc.expected_result.clone(),
                    expected_valid,
                }
            })
            .collect();

        Self {
            cve_id: pattern.id.clone(),
            cve_name: pattern.name.clone(),
            circuit_path,
            test_cases,
            assertion: pattern.regression_test.assertion.clone(),
        }
    }

    /// Run regression test against the configured real backend.
    pub fn run(&self) -> RegressionTestResult {
        let mut rng = StdRng::seed_from_u64(42);
        let mut test_results = Vec::new();
        let mut passed_all = true;

        if has_unresolved_env_placeholder(&self.circuit_path) {
            return RegressionTestResult {
                cve_id: self.cve_id.clone(),
                passed: false,
                test_results: self
                    .test_cases
                    .iter()
                    .map(|tc| TestCaseResult {
                        name: tc.name.clone(),
                        passed: false,
                        message: Some(format!(
                            "Unresolved env placeholder in circuit path '{}'. Set required environment variables.",
                            self.circuit_path
                        )),
                    })
                    .collect(),
            };
        }

        let path = Path::new(&self.circuit_path);
        if !path.exists() {
            return RegressionTestResult {
                cve_id: self.cve_id.clone(),
                passed: false,
                test_results: self
                    .test_cases
                    .iter()
                    .map(|tc| TestCaseResult {
                        name: tc.name.clone(),
                        passed: false,
                        message: Some(format!("Circuit path not found: {}", self.circuit_path)),
                    })
                    .collect(),
            };
        }

        let source = match std::fs::read_to_string(path) {
            Ok(source) => source,
            Err(e) => {
                return RegressionTestResult {
                    cve_id: self.cve_id.clone(),
                    passed: false,
                    test_results: self
                        .test_cases
                        .iter()
                        .map(|tc| TestCaseResult {
                            name: tc.name.clone(),
                            passed: false,
                            message: Some(format!("Failed to read circuit source: {}", e)),
                        })
                        .collect(),
                };
            }
        };
        let framework = match detect_framework(path) {
            Ok(framework) => framework,
            Err(e) => {
                return RegressionTestResult {
                    cve_id: self.cve_id.clone(),
                    passed: false,
                    test_results: self
                        .test_cases
                        .iter()
                        .map(|tc| TestCaseResult {
                            name: tc.name.clone(),
                            passed: false,
                            message: Some(format!("Framework detection failed: {}", e)),
                        })
                        .collect(),
                };
            }
        };
        let main_component = detect_main_component(&source, framework);

        let executor_options = ExecutorFactoryOptions {
            circom_skip_compile_if_artifacts: true,
            ..ExecutorFactoryOptions::default()
        };
        let executor = match ExecutorFactory::create_with_options(
            framework,
            &self.circuit_path,
            &main_component,
            &executor_options,
        ) {
            Ok(exec) => exec,
            Err(e) => {
                return RegressionTestResult {
                    cve_id: self.cve_id.clone(),
                    passed: false,
                    test_results: self
                        .test_cases
                        .iter()
                        .map(|tc| TestCaseResult {
                            name: tc.name.clone(),
                            passed: false,
                            message: Some(format!("Executor creation failed: {}", e)),
                        })
                        .collect(),
                };
            }
        };

        let input_specs = parse_inputs_from_source(&source, framework);
        let total_inputs = executor.num_private_inputs() + executor.num_public_inputs();
        let field_modulus = executor.field_modulus();

        for tc in &self.test_cases {
            let inputs = match build_inputs_for_test(
                tc,
                &input_specs,
                total_inputs,
                &field_modulus,
                &mut rng,
            ) {
                Ok(v) => v,
                Err(e) => {
                    passed_all = false;
                    test_results.push(TestCaseResult {
                        name: tc.name.clone(),
                        passed: false,
                        message: Some(e),
                    });
                    continue;
                }
            };

            let expectation = match expectation_for_result(&tc.expected_result) {
                Ok(expectation) => expectation,
                Err(e) => {
                    passed_all = false;
                    test_results.push(TestCaseResult {
                        name: tc.name.clone(),
                        passed: false,
                        message: Some(e),
                    });
                    continue;
                }
            };

            let result = executor.execute_sync(&inputs);
            let (passed, message) = match expectation {
                RegressionExpectation::ExecutionSucceeds => {
                    let passed = result.success;
                    let message = if passed {
                        None
                    } else {
                        Some(match result.error.as_deref() {
                            Some(err) => format!("Expected valid but execution failed: {}", err),
                            None => "Expected valid but execution failed".to_string(),
                        })
                    };
                    (passed, message)
                }
                RegressionExpectation::ExecutionFails => {
                    let passed = !result.success;
                    let message = if passed {
                        None
                    } else {
                        Some("Expected invalid but execution succeeded".to_string())
                    };
                    (passed, message)
                }
            };

            if !passed {
                passed_all = false;
            }

            test_results.push(TestCaseResult {
                name: tc.name.clone(),
                passed,
                message,
            });
        }

        RegressionTestResult {
            cve_id: self.cve_id.clone(),
            passed: passed_all,
            test_results,
        }
    }

    /// Best-effort preflight for executor/tooling readiness.
    ///
    /// Returns a human-readable reason when this regression target cannot be executed due to
    /// backend/tooling/artifact issues and should be skipped before running test cases.
    pub fn preflight_infrastructure_issue(&self) -> Option<String> {
        let path = Path::new(&self.circuit_path);
        if !path.exists() {
            return None;
        }

        let source = std::fs::read_to_string(path).ok()?;
        let framework = detect_framework(path).ok()?;
        let main_component = detect_main_component(&source, framework);

        let executor_options = ExecutorFactoryOptions {
            circom_skip_compile_if_artifacts: true,
            ..ExecutorFactoryOptions::default()
        };

        match ExecutorFactory::create_with_options(
            framework,
            &self.circuit_path,
            &main_component,
            &executor_options,
        ) {
            Ok(_) => None,
            Err(err) => Some(format!("Executor creation failed: {}", err)),
        }
    }
}

/// Generated test case
#[derive(Debug, Clone)]
pub struct GeneratedTestCase {
    pub name: String,
    pub inputs: Vec<(String, serde_yaml::Value)>,
    pub expected_result: String,
    pub expected_valid: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegressionExpectation {
    /// Expect circuit execution to succeed (valid witness/proof path)
    ExecutionSucceeds,
    /// Expect circuit execution to fail
    ExecutionFails,
}

/// Result of running a regression test
#[derive(Debug, Clone)]
pub struct RegressionTestResult {
    pub cve_id: String,
    pub passed: bool,
    pub test_results: Vec<TestCaseResult>,
}

impl RegressionTestResult {
    /// Returns true when all failing test-case messages indicate backend/tooling
    /// availability problems rather than circuit-level pass/fail behavior.
    pub fn is_infrastructure_failure(&self) -> bool {
        if self.passed || self.test_results.is_empty() {
            return false;
        }

        self.test_results.iter().all(|tc| {
            tc.message
                .as_deref()
                .map(is_infrastructure_error_message)
                .unwrap_or(false)
        })
    }
}

/// Result of a single test case
#[derive(Debug, Clone)]
pub struct TestCaseResult {
    pub name: String,
    pub passed: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone)]
struct InputSpec {
    name: String,
    length: Option<usize>,
    is_array: bool,
}

fn is_infrastructure_error_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("no circom constraints available")
        || lower.contains("backend required but not available")
        || lower.contains("snarkjs not found")
        || lower.contains("circom not found")
        || lower.contains("not found in path")
        || lower.contains("key setup failed")
        || lower.contains("failed to create executor")
        || lower.contains("executor creation failed")
}

fn detect_framework(path: &Path) -> anyhow::Result<Framework> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("circom") => Ok(Framework::Circom),
        Some("nr") => Ok(Framework::Noir),
        Some("cairo") => Ok(Framework::Cairo),
        Some("rs") => Ok(Framework::Halo2),
        Some("json") if looks_like_halo2_json(path) => Ok(Framework::Halo2),
        _ => anyhow::bail!(
            "Unsupported circuit file extension for backend detection: {}",
            path.display()
        ),
    }
}

fn looks_like_halo2_json(path: &Path) -> bool {
    let content = match std::fs::read_to_string(path) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let Some(obj) = parsed.as_object() else {
        return false;
    };

    let halo2_markers = [
        "k",
        "advice_columns",
        "fixed_columns",
        "instance_columns",
        "constraints",
        "lookups",
        "gates",
    ];
    halo2_markers.iter().any(|marker| obj.contains_key(*marker))
}

fn detect_main_component(source: &str, framework: Framework) -> String {
    match framework {
        Framework::Circom => {
            for line in source.lines() {
                if line.contains("component main") {
                    if let Some(start) = line.find('=') {
                        let rest = &line[start + 1..];
                        if let Some(end) = rest.find('(') {
                            return rest[..end].trim().to_string();
                        }
                    }
                }
            }
            for line in source.lines() {
                if line.trim().starts_with("template ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        return parts[1].trim_end_matches('(').to_string();
                    }
                }
            }
        }
        Framework::Noir => {
            for line in source.lines() {
                if line.contains("fn main") {
                    return "main".to_string();
                }
            }
        }
        _ => {}
    }
    "Main".to_string()
}

fn expected_result_to_validity(expected: &str) -> Option<bool> {
    let normalized = expected.trim().to_lowercase();

    let invalid_markers = [
        "invalid",
        "should_be_invalid",
        "should_fail",
        "reject",
        "rejected",
        "fail",
        "failure",
    ];
    let valid_markers = [
        "valid",
        "should_be_valid",
        "should_pass",
        "accept",
        "accepted",
        "success",
        "valid_proof",
    ];

    if invalid_markers.iter().any(|m| normalized.contains(m)) {
        return Some(false);
    }
    if valid_markers.iter().any(|m| normalized.contains(m)) {
        return Some(true);
    }

    None
}

fn expectation_for_result(expected: &str) -> Result<RegressionExpectation, String> {
    match expected_result_to_validity(expected) {
        Some(true) => Ok(RegressionExpectation::ExecutionSucceeds),
        Some(false) => Ok(RegressionExpectation::ExecutionFails),
        None => Err(format!(
            "Unsupported expected_result '{}'. Use explicit validity markers (valid/invalid, should_pass/should_fail, accepted/rejected).",
            expected
        )),
    }
}

fn is_strict_expected_result(expected: &str) -> bool {
    let normalized = expected.trim().to_lowercase();
    matches!(
        normalized.as_str(),
        "valid"
            | "valid_proof"
            | "should_be_valid"
            | "should_pass"
            | "accept"
            | "accepted"
            | "success"
            | "invalid"
            | "invalid_proof"
            | "should_be_invalid"
            | "should_fail"
            | "reject"
            | "rejected"
            | "fail"
            | "failure"
    )
}

fn validate_strict_fixture_value(
    value: &serde_yaml::Value,
    context: &str,
    errors: &mut Vec<String>,
) {
    match value {
        serde_yaml::Value::Null => {
            errors.push(format!(
                "{} contains null input value, which is ambiguous",
                context
            ));
        }
        serde_yaml::Value::Bool(_) | serde_yaml::Value::Number(_) => {}
        serde_yaml::Value::String(s) => {
            if !is_strict_fixture_string_literal(s) {
                errors.push(format!(
                    "{} has ambiguous string input '{}'. Use numeric/hex/placeholders only.",
                    context, s
                ));
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for (idx, item) in items.iter().enumerate() {
                validate_strict_fixture_value(item, &format!("{}[{}]", context, idx), errors);
            }
        }
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                let key = match serde_yaml::to_string(k) {
                    Ok(serialized) => serialized.trim().to_string(),
                    Err(err) => format!("<unprintable-key:{}>", err),
                };
                validate_strict_fixture_value(v, &format!("{}{{{}}}", context, key), errors);
            }
        }
        serde_yaml::Value::Tagged(tagged) => {
            validate_strict_fixture_value(&tagged.value, context, errors);
        }
    }
}

fn is_strict_fixture_string_literal(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "..." {
        return false;
    }
    if trimmed == "random_field_element" {
        return true;
    }
    if let Some(rest) = trimmed.strip_prefix("random_") {
        return !rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_digit());
    }
    if is_decimal_literal(trimmed) || is_hex_literal(trimmed) {
        return true;
    }
    is_field_placeholder_literal(trimmed)
}

fn is_decimal_literal(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some('+') | Some('-') => chars.next().is_some() && chars.all(|ch| ch.is_ascii_digit()),
        Some(first) if first.is_ascii_digit() => chars.all(|ch| ch.is_ascii_digit()),
        _ => false,
    }
}

fn is_hex_literal(value: &str) -> bool {
    let Some(hex_part) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    else {
        return false;
    };
    !hex_part.is_empty() && hex_part.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn is_field_placeholder_literal(value: &str) -> bool {
    let normalized = value.to_lowercase().replace(' ', "");
    matches!(
        normalized.as_str(),
        "zero" | "one" | "max" | "max_field" | "p" | "field_mod" | "(p-1)/2"
    ) || has_signed_offset(&normalized, "p")
        || has_signed_offset(&normalized, "max")
        || has_signed_offset(&normalized, "max_field")
        || has_signed_offset(&normalized, "field_mod")
}

fn has_signed_offset(value: &str, prefix: &str) -> bool {
    let Some(rest) = value.strip_prefix(prefix) else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    let mut chars = rest.chars();
    let Some(sign) = chars.next() else {
        return false;
    };
    (sign == '+' || sign == '-') && chars.next().is_some() && chars.all(|ch| ch.is_ascii_digit())
}

fn expand_env_placeholders(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    let mut out = String::new();

    while i < chars.len() {
        if chars[i] != '$' {
            out.push(chars[i]);
            i += 1;
            continue;
        }

        if i + 1 < chars.len() && chars[i + 1] == '{' {
            let mut j = i + 2;
            while j < chars.len() && chars[j] != '}' {
                j += 1;
            }
            if j >= chars.len() {
                out.push(chars[i]);
                i += 1;
                continue;
            }

            let inner: String = chars[i + 2..j].iter().collect();
            let placeholder = format!("${{{}}}", inner);
            let var_name = match inner.split_once(":-") {
                Some((name, _legacy_default)) => name,
                None => inner.as_str(),
            };
            if var_name.is_empty() {
                out.push_str(&placeholder);
                i = j + 1;
                continue;
            }
            match std::env::var(var_name) {
                Ok(value) => out.push_str(&value),
                Err(std::env::VarError::NotPresent) => out.push_str(&placeholder),
                Err(std::env::VarError::NotUnicode(_)) => out.push_str(&placeholder),
            }
            i = j + 1;
            continue;
        }

        let mut j = i + 1;
        if j < chars.len() && (chars[j].is_ascii_alphabetic() || chars[j] == '_') {
            while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                j += 1;
            }
            let var_name: String = chars[i + 1..j].iter().collect();
            let placeholder = format!("${}", var_name);
            match std::env::var(&var_name) {
                Ok(value) => out.push_str(&value),
                Err(std::env::VarError::NotPresent) => out.push_str(&placeholder),
                Err(std::env::VarError::NotUnicode(_)) => out.push_str(&placeholder),
            }
            i = j;
            continue;
        }

        out.push(chars[i]);
        i += 1;
    }

    out
}

fn has_unresolved_env_placeholder(input: &str) -> bool {
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] != '$' {
            i += 1;
            continue;
        }

        if i + 1 < chars.len() && chars[i + 1] == '{' {
            let mut j = i + 2;
            while j < chars.len() && chars[j] != '}' {
                j += 1;
            }
            return true;
        }

        if i + 1 < chars.len() && (chars[i + 1].is_ascii_alphabetic() || chars[i + 1] == '_') {
            return true;
        }

        i += 1;
    }
    false
}

fn parse_inputs_from_source(source: &str, framework: Framework) -> Vec<InputSpec> {
    let mut inputs = Vec::new();
    match framework {
        Framework::Circom => {
            for line in source.lines() {
                if let Some(spec) = parse_circom_input(line) {
                    inputs.push(spec);
                }
            }
        }
        Framework::Noir => {
            for line in source.lines() {
                if let Some(specs) = parse_noir_inputs(line) {
                    inputs.extend(specs);
                }
            }
        }
        _ => {}
    }
    inputs
}

fn parse_circom_input(line: &str) -> Option<InputSpec> {
    let line = line.trim();
    if line.starts_with("signal input") || line.starts_with("signal private input") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let name_part = parts.last()?;
            let name = name_part.trim_end_matches(';').trim_end_matches(']');

            let (name, length) = if let Some(bracket) = name.find('[') {
                let base_name = &name[..bracket];
                let len_str = &name[bracket + 1..];
                let len = match len_str.trim_end_matches(']').parse::<usize>() {
                    Ok(len) => Some(len),
                    Err(err) => {
                        tracing::debug!(
                            "Non-literal Circom array length '{}' in line '{}': {}",
                            len_str,
                            line,
                            err
                        );
                        None
                    }
                };
                (base_name.to_string(), len)
            } else {
                (name.to_string(), None)
            };

            return Some(InputSpec {
                name,
                length,
                is_array: name_part.contains('['),
            });
        }
    }
    None
}

fn parse_noir_inputs(line: &str) -> Option<Vec<InputSpec>> {
    let line = line.trim();
    if line.contains("fn main") || line.contains("fn ") {
        if let Some(start) = line.find('(') {
            if let Some(end) = line.find(')') {
                let params = &line[start + 1..end];
                let mut specs = Vec::new();
                for param in params.split(',') {
                    let param = param.trim();
                    if param.is_empty() {
                        continue;
                    }
                    let parts: Vec<&str> = param.split(':').collect();
                    if parts.len() == 2 {
                        specs.push(InputSpec {
                            name: parts[0].trim().to_string(),
                            length: None,
                            is_array: false,
                        });
                    }
                }
                if !specs.is_empty() {
                    return Some(specs);
                }
            }
        }
    }
    None
}

fn build_inputs_for_test(
    tc: &GeneratedTestCase,
    input_specs: &[InputSpec],
    total_inputs: usize,
    field_modulus: &[u8; 32],
    rng: &mut impl Rng,
) -> Result<Vec<FieldElement>, String> {
    if total_inputs == 0 {
        return Err("Executor reports zero inputs".to_string());
    }

    let mut key_map: HashMap<String, &serde_yaml::Value> = HashMap::new();
    let mut indexed_map: HashMap<String, std::collections::BTreeMap<usize, &serde_yaml::Value>> =
        HashMap::new();
    for (k, v) in &tc.inputs {
        let lower = k.to_lowercase();
        if let Some((base, idx)) = parse_indexed_name(&lower) {
            indexed_map.entry(base).or_default().insert(idx, v);
            continue;
        }
        key_map.insert(lower, v);
    }

    let mut inputs = Vec::new();

    if !input_specs.is_empty() {
        for spec in input_specs {
            let key = spec.name.to_lowercase();
            let synthesized = match indexed_map.get(&key) {
                Some(values) => Some(build_indexed_sequence(values)?),
                None => None,
            };
            let value = key_map.get(&key).copied().or(synthesized.as_ref());

            let inferred_len = spec.length.or_else(|| {
                if spec.is_array {
                    value.and_then(infer_length_from_value)
                } else {
                    None
                }
            });

            let elements = match value {
                Some(v) => parse_yaml_value(v, field_modulus, rng, inferred_len)?,
                None => {
                    let fill_len = inferred_len.unwrap_or(1);
                    tracing::debug!(
                        "CVE test '{}' missing input '{}'; zero-filling {} value(s)",
                        tc.name,
                        spec.name,
                        fill_len
                    );
                    vec![FieldElement::zero(); fill_len]
                }
            };

            if let Some(len) = inferred_len {
                if elements.len() < len {
                    return Err(format!(
                        "Input '{}' in test '{}' has too few elements: expected {}, got {}",
                        spec.name,
                        tc.name,
                        len,
                        elements.len()
                    ));
                } else if elements.len() > len {
                    return Err(format!(
                        "Input '{}' in test '{}' has too many elements: expected {}, got {}",
                        spec.name,
                        tc.name,
                        len,
                        elements.len()
                    ));
                }
            }

            inputs.extend(elements);
        }
    } else {
        for (_key, value) in &tc.inputs {
            let mut elements = parse_yaml_value(value, field_modulus, rng, None)?;
            inputs.append(&mut elements);
        }
    }

    if inputs.len() > total_inputs {
        let dropped = inputs.len() - total_inputs;
        tracing::debug!(
            "CVE test '{}' provided {} / {} inputs; truncating {} trailing inputs",
            tc.name,
            inputs.len(),
            total_inputs,
            dropped
        );
        inputs.truncate(total_inputs);
    } else if inputs.len() < total_inputs {
        let missing = total_inputs - inputs.len();
        tracing::debug!(
            "CVE test '{}' provided {} / {} inputs; zero-filling missing {} inputs",
            tc.name,
            inputs.len(),
            total_inputs,
            missing
        );
        inputs.extend(std::iter::repeat_with(FieldElement::zero).take(missing));
    }

    Ok(inputs)
}

fn parse_indexed_name(name: &str) -> Option<(String, usize)> {
    if let Some(start) = name.rfind('[') {
        if let Some(end) = name.rfind(']') {
            let base = name[..start].to_string();
            let idx = match name[start + 1..end].parse::<usize>() {
                Ok(idx) => idx,
                Err(err) => {
                    tracing::debug!("Invalid bracket index in '{}': {}", name, err);
                    return None;
                }
            };
            return Some((base, idx));
        }
    }
    if let Some(dot) = name.rfind('.') {
        let (base, idx_str) = name.split_at(dot);
        let idx = match idx_str.trim_start_matches('.').parse::<usize>() {
            Ok(idx) => idx,
            Err(err) => {
                tracing::debug!("Invalid dotted index in '{}': {}", name, err);
                return None;
            }
        };
        return Some((base.to_string(), idx));
    }
    None
}

fn build_indexed_sequence(
    values: &std::collections::BTreeMap<usize, &serde_yaml::Value>,
) -> Result<serde_yaml::Value, String> {
    if values.is_empty() {
        return Err("Indexed input map is empty".to_string());
    }

    let max = match values.keys().max().copied() {
        Some(value) => value,
        None => {
            return Err("Indexed input map is empty".to_string());
        }
    };
    let mut seq = Vec::with_capacity(max + 1);
    for idx in 0..=max {
        if let Some(value) = values.get(&idx) {
            seq.push((*value).clone());
        } else {
            return Err(format!(
                "Indexed input is missing index {} (indices must be contiguous from 0)",
                idx
            ));
        }
    }
    Ok(serde_yaml::Value::Sequence(seq))
}

fn infer_length_from_value(value: &serde_yaml::Value) -> Option<usize> {
    match value {
        serde_yaml::Value::Sequence(seq) => Some(seq.len()),
        serde_yaml::Value::String(s) => {
            let value = s.trim();
            if let Some(rest) = value.strip_prefix("random_") {
                if let Ok(count) = rest.parse::<usize>() {
                    return Some(count);
                }
            }
            None
        }
        _ => None,
    }
}

fn parse_yaml_value(
    value: &serde_yaml::Value,
    field_modulus: &[u8; 32],
    rng: &mut impl Rng,
    expected_len: Option<usize>,
) -> Result<Vec<FieldElement>, String> {
    match value {
        serde_yaml::Value::Number(n) => parse_yaml_number(n, field_modulus),
        serde_yaml::Value::Bool(b) => Ok(vec![if *b {
            FieldElement::one()
        } else {
            FieldElement::zero()
        }]),
        serde_yaml::Value::String(s) => parse_value_string(s, field_modulus, rng, expected_len),
        serde_yaml::Value::Sequence(seq) => {
            let mut out = Vec::new();
            for item in seq {
                let mut expanded = parse_yaml_value(item, field_modulus, rng, None)?;
                out.append(&mut expanded);
            }
            Ok(out)
        }
        _ => Err("Unsupported YAML value type for inputs".to_string()),
    }
}

fn parse_yaml_number(
    number: &serde_yaml::Number,
    field_modulus: &[u8; 32],
) -> Result<Vec<FieldElement>, String> {
    if let Some(u) = number.as_u64() {
        return Ok(vec![FieldElement::from_u64(u)]);
    }

    if let Some(i) = number.as_i64() {
        if i >= 0 {
            return Ok(vec![FieldElement::from_u64(i as u64)]);
        }

        let modulus = BigUint::from_bytes_be(field_modulus);
        if modulus == BigUint::from(0u8) {
            return Err(format!(
                "Cannot encode negative number {} without a non-zero field modulus",
                i
            ));
        }

        let abs = BigUint::from(i.unsigned_abs());
        let rem = abs % &modulus;
        let value = if rem == BigUint::from(0u8) {
            BigUint::from(0u8)
        } else {
            modulus - rem
        };
        return Ok(vec![FieldElement::from_bytes(&value.to_bytes_be())]);
    }

    Err(format!("Unsupported numeric input '{}'", number))
}

fn parse_value_string(
    raw: &str,
    field_modulus: &[u8; 32],
    rng: &mut impl Rng,
    _expected_len: Option<usize>,
) -> Result<Vec<FieldElement>, String> {
    let value = raw.trim();

    if value == "random_field_element" {
        return Ok(vec![FieldElement::random(rng)]);
    }
    if let Some(rest) = value.strip_prefix("random_") {
        if let Ok(count) = rest.parse::<usize>() {
            let mut out = Vec::with_capacity(count);
            for _ in 0..count {
                out.push(FieldElement::random(rng));
            }
            return Ok(out);
        }
    }
    let fe = parse_string_as_field_element(value, field_modulus)?;
    Ok(vec![fe])
}

fn parse_string_as_field_element(
    value: &str,
    field_modulus: &[u8; 32],
) -> Result<FieldElement, String> {
    if let Ok(bytes) = crate::config::parser::expand_value_placeholder(value, field_modulus) {
        return Ok(FieldElement::from_bytes(&bytes));
    }

    // Allow odd-nibble hex values such as "0x2" by left-padding one nibble.
    if let Some(hex_part) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        let normalized = hex_part.replace('_', "");
        if !normalized.is_empty() && normalized.chars().all(|c| c.is_ascii_hexdigit()) {
            let even = if normalized.len().is_multiple_of(2) {
                normalized
            } else {
                format!("0{}", normalized)
            };
            let decoded =
                hex::decode(&even).map_err(|e| format!("Invalid hex '{}': {}", value, e))?;
            return Ok(FieldElement::from_bytes(&decoded));
        }
    }

    Err(format!(
        "Unsupported string literal '{}'. Use numeric/hex values or supported placeholders.",
        value
    ))
}

/// CVE-aware oracle that checks for known vulnerability patterns
pub struct CveOracle {
    database: CveDatabase,
    active_patterns: Vec<String>,
    nullifier_oracle: Mutex<NullifierOracle>,
    merkle_oracle: Mutex<MerkleOracle>,
    range_oracle: Mutex<RangeProofOracle>,
    commitment_oracle: Mutex<CommitmentOracle>,
}

impl CveOracle {
    fn with_active_patterns(database: CveDatabase, active_patterns: Vec<String>) -> Self {
        let oracle_config = OracleConfig::default();
        Self {
            database,
            active_patterns,
            nullifier_oracle: Mutex::new(NullifierOracle::new(oracle_config.clone())),
            merkle_oracle: Mutex::new(MerkleOracle::new(oracle_config.clone())),
            range_oracle: Mutex::new(RangeProofOracle::new(oracle_config.clone())),
            commitment_oracle: Mutex::new(CommitmentOracle::new(oracle_config)),
        }
    }

    fn run_semantic_oracle<O: SemanticOracle>(
        oracle: &Mutex<O>,
        test_case: &TestCase,
        output: &[FieldElement],
    ) -> Option<Finding> {
        let mut guard = oracle
            .lock()
            .expect("semantic oracle state mutex poisoned; aborting CVE check");
        guard.check(test_case, output)
    }

    fn adapt_semantic_finding(&self, pattern: &CvePattern, finding: Finding) -> Finding {
        let mut cve_finding = pattern.create_finding(finding.poc, finding.location);
        let semantic_headline = finding
            .description
            .lines()
            .next()
            .map(str::trim)
            .filter(|line| !line.is_empty());
        if let Some(headline) = semantic_headline {
            cve_finding.description = format!(
                "{}\n\nSemantic trigger: {}",
                cve_finding.description, headline
            );
        }
        cve_finding
    }

    fn check_with_nullifier_oracle(
        &self,
        pattern: &CvePattern,
        test_case: &TestCase,
        output: &[FieldElement],
    ) -> Option<Finding> {
        Self::run_semantic_oracle(&self.nullifier_oracle, test_case, output)
            .map(|finding| self.adapt_semantic_finding(pattern, finding))
    }

    fn check_with_merkle_oracle(
        &self,
        pattern: &CvePattern,
        test_case: &TestCase,
        output: &[FieldElement],
    ) -> Option<Finding> {
        Self::run_semantic_oracle(&self.merkle_oracle, test_case, output)
            .map(|finding| self.adapt_semantic_finding(pattern, finding))
    }

    fn check_with_range_oracle(
        &self,
        pattern: &CvePattern,
        test_case: &TestCase,
        output: &[FieldElement],
    ) -> Option<Finding> {
        Self::run_semantic_oracle(&self.range_oracle, test_case, output)
            .map(|finding| self.adapt_semantic_finding(pattern, finding))
    }

    fn check_with_commitment_oracle(
        &self,
        pattern: &CvePattern,
        test_case: &TestCase,
        output: &[FieldElement],
    ) -> Option<Finding> {
        Self::run_semantic_oracle(&self.commitment_oracle, test_case, output)
            .map(|finding| self.adapt_semantic_finding(pattern, finding))
    }

    fn check_with_semantic_ensemble(
        &self,
        pattern: &CvePattern,
        test_case: &TestCase,
        output: &[FieldElement],
    ) -> Option<Finding> {
        self.check_with_nullifier_oracle(pattern, test_case, output)
            .or_else(|| self.check_with_merkle_oracle(pattern, test_case, output))
            .or_else(|| self.check_with_range_oracle(pattern, test_case, output))
            .or_else(|| self.check_with_commitment_oracle(pattern, test_case, output))
    }

    fn normalize_route_key(raw: &str) -> String {
        raw.trim().to_ascii_lowercase().replace(['-', ' '], "_")
    }

    fn route_pattern_key(
        &self,
        key: &str,
        pattern: &CvePattern,
        test_case: &TestCase,
        output: &[FieldElement],
    ) -> Option<Finding> {
        match key {
            "signature_malleability" => self.check_signature_malleability(pattern, test_case),
            "nullifier_collision"
            | "replay_protection"
            | "randomness_reuse"
            | "linkability_analysis"
            | "witness_collision"
            | "collision" => self.check_with_nullifier_oracle(pattern, test_case, output),
            "merkle_soundness"
            | "state_transition"
            | "ordering_dependency"
            | "batch_soundness"
            | "recursive_soundness"
            | "recursive_base_case"
            | "storage_soundness" => self.check_with_merkle_oracle(pattern, test_case, output),
            "range_overflow"
            | "arithmetic_boundary"
            | "opcode_boundary"
            | "opcode_bounds"
            | "accumulator_overflow"
            | "lookup_soundness"
            | "gate_activation"
            | "gas_accounting"
            | "gas_analysis"
            | "price_manipulation"
            | "boundary"
            | "arithmetic_overflow" => self.check_with_range_oracle(pattern, test_case, output),
            "vk_binding"
            | "fiat_shamir_binding"
            | "point_validation"
            | "cofactor_attack"
            | "oracle_manipulation"
            | "information_leakage"
            | "timing_analysis" => self.check_with_commitment_oracle(pattern, test_case, output),
            "underconstrained"
            | "soundness"
            | "assigned_not_constrained"
            | "constraint_inference"
            | "constraint_slice"
            | "spec_inference"
            | "metamorphic" => self.check_with_semantic_ensemble(pattern, test_case, output),
            _ => None,
        }
    }

    /// Create oracle with all patterns active
    pub fn new(database: CveDatabase) -> Self {
        let active_patterns = database
            .vulnerabilities
            .iter()
            .map(|p| p.id.clone())
            .collect();
        Self::with_active_patterns(database, active_patterns)
    }

    /// Create oracle for specific circuit
    pub fn for_circuit(database: CveDatabase, circuit_name: &str) -> Self {
        let active_patterns = database
            .patterns_for_circuit(circuit_name)
            .iter()
            .map(|p| p.id.clone())
            .collect();
        Self::with_active_patterns(database, active_patterns)
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

    /// Check single pattern using strict CVE-specific oracle routing.
    fn check_pattern(
        &self,
        pattern: &CvePattern,
        test_case: &TestCase,
        output: &[FieldElement],
    ) -> Option<Finding> {
        let oracle_key = Self::normalize_route_key(&pattern.detection.oracle);
        if let Some(finding) = self.route_pattern_key(&oracle_key, pattern, test_case, output) {
            return Some(finding);
        }

        let attack_key = Self::normalize_route_key(&pattern.detection.attack_type);
        if attack_key != oracle_key {
            if let Some(finding) = self.route_pattern_key(&attack_key, pattern, test_case, output) {
                return Some(finding);
            }
        }

        tracing::debug!(
            "No CVE oracle route for pattern {} (oracle='{}', attack_type='{}')",
            pattern.id,
            pattern.detection.oracle,
            pattern.detection.attack_type
        );
        None
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
}
