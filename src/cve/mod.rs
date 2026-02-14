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

use crate::executor::ExecutorFactory;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
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
            circuit_path: pattern.regression_test.circuit_path.clone(),
            test_cases,
            assertion: pattern.regression_test.assertion.clone(),
        }
    }

    /// Run regression test (placeholder for actual implementation)
    pub fn run(&self) -> RegressionTestResult {
        let mut rng = StdRng::seed_from_u64(42);
        let mut test_results = Vec::new();
        let mut passed_all = true;

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

        let source = std::fs::read_to_string(path).unwrap_or_default();
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

        let executor = match ExecutorFactory::create(framework, &self.circuit_path, &main_component)
        {
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

            let result = executor.execute_sync(&inputs);

            let (passed, message) = match tc.expected_valid {
                Some(expected) => {
                    let passed = result.success == expected;
                    let message = if passed {
                        None
                    } else {
                        Some(format!(
                            "Expected {} but execution {}",
                            if expected { "valid" } else { "invalid" },
                            if result.success {
                                "succeeded"
                            } else {
                                "failed"
                            }
                        ))
                    };
                    (passed, message)
                }
                None => {
                    if result.success {
                        (
                            true,
                            Some(format!(
                                "Expected result '{}' not evaluated; checked execution success only",
                                tc.expected_result
                            )),
                        )
                    } else {
                        (
                            false,
                            Some(format!(
                                "Execution failed; expected result '{}' is not evaluated",
                                tc.expected_result
                            )),
                        )
                    }
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
}

/// Generated test case
#[derive(Debug, Clone)]
pub struct GeneratedTestCase {
    pub name: String,
    pub inputs: Vec<(String, serde_yaml::Value)>,
    pub expected_result: String,
    pub expected_valid: Option<bool>,
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

#[derive(Debug, Clone)]
struct InputSpec {
    name: String,
    length: Option<usize>,
    is_array: bool,
}

fn detect_framework(path: &Path) -> anyhow::Result<Framework> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("circom") => Ok(Framework::Circom),
        Some("nr") => Ok(Framework::Noir),
        Some("cairo") => Ok(Framework::Cairo),
        Some("rs") => Ok(Framework::Halo2),
        _ => anyhow::bail!(
            "Unsupported circuit file extension for backend detection: {}",
            path.display()
        ),
    }
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
                let len = len_str.trim_end_matches(']').parse::<usize>().ok();
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
            if inputs.len() >= total_inputs {
                break;
            }

            let key = spec.name.to_lowercase();
            let synthesized = indexed_map.get(&key).map(build_indexed_sequence);
            let value = key_map.get(&key).copied().or(synthesized.as_ref());

            let inferred_len = spec.length.or_else(|| {
                if spec.is_array {
                    value.and_then(infer_length_from_value)
                } else {
                    None
                }
            });

            let mut elements = match value {
                Some(v) => parse_yaml_value(v, field_modulus, rng, inferred_len)?,
                None => vec![FieldElement::zero(); inferred_len.unwrap_or(1)],
            };

            if let Some(len) = inferred_len {
                if elements.len() < len {
                    elements.extend(std::iter::repeat_n(
                        FieldElement::zero(),
                        len - elements.len(),
                    ));
                } else if elements.len() > len {
                    elements.truncate(len);
                }
            }

            let remaining = total_inputs.saturating_sub(inputs.len());
            if elements.len() > remaining {
                elements.truncate(remaining);
            }

            inputs.extend(elements);
        }
    } else {
        for (_key, value) in &tc.inputs {
            if inputs.len() >= total_inputs {
                break;
            }
            let mut elements = parse_yaml_value(value, field_modulus, rng, None)?;
            let remaining = total_inputs.saturating_sub(inputs.len());
            if elements.len() > remaining {
                elements.truncate(remaining);
            }
            inputs.append(&mut elements);
        }
    }

    if inputs.len() < total_inputs {
        inputs.extend(std::iter::repeat_n(
            FieldElement::zero(),
            total_inputs - inputs.len(),
        ));
    } else if inputs.len() > total_inputs {
        inputs.truncate(total_inputs);
    }

    Ok(inputs)
}

fn parse_indexed_name(name: &str) -> Option<(String, usize)> {
    if let Some(start) = name.rfind('[') {
        if let Some(end) = name.rfind(']') {
            let base = name[..start].to_string();
            let idx = name[start + 1..end].parse::<usize>().ok()?;
            return Some((base, idx));
        }
    }
    if let Some(dot) = name.rfind('.') {
        let (base, idx_str) = name.split_at(dot);
        let idx = idx_str.trim_start_matches('.').parse::<usize>().ok()?;
        return Some((base.to_string(), idx));
    }
    None
}

fn build_indexed_sequence(
    values: &std::collections::BTreeMap<usize, &serde_yaml::Value>,
) -> serde_yaml::Value {
    let max = values.keys().max().copied().unwrap_or(0);
    let mut seq = Vec::with_capacity(max + 1);
    for idx in 0..=max {
        if let Some(value) = values.get(&idx) {
            seq.push((*value).clone());
        } else {
            seq.push(serde_yaml::Value::Number(serde_yaml::Number::from(0)));
        }
    }
    serde_yaml::Value::Sequence(seq)
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
        serde_yaml::Value::Number(n) => {
            let num = n.as_u64().unwrap_or(0);
            Ok(vec![FieldElement::from_u64(num)])
        }
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

fn parse_value_string(
    raw: &str,
    field_modulus: &[u8; 32],
    rng: &mut impl Rng,
    expected_len: Option<usize>,
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

    let bytes = crate::config::parser::expand_value_placeholder(value, field_modulus)
        .map_err(|e| e.to_string())?;
    let fe = FieldElement::from_bytes(&bytes);

    if let Some(len) = expected_len {
        if len > 1 {
            let mut out = Vec::with_capacity(len);
            out.push(fe.clone());
            out.extend(std::iter::repeat_n(FieldElement::zero(), len - 1));
            return Ok(out);
        }
    }

    Ok(vec![fe])
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
    fn check_range_overflow(&self, pattern: &CvePattern, test_case: &TestCase) -> Option<Finding> {
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
