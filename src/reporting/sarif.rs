//! SARIF (Static Analysis Results Interchange Format) Output
//!
//! Implements SARIF 2.1.0 compliant output for ZK circuit security findings.
//! SARIF enables IDE integration with VS Code, GitHub Code Scanning, and other tools.
//!
//! # Features
//!
//! - Full SARIF 2.1.0 schema compliance
//! - Rule definitions for all attack types
//! - Physical and logical locations for findings
//! - Code flows for complex vulnerability chains
//! - Related locations for context
//! - Remediation guidance
//! - Severity and confidence mappings
//!
//! # IDE Integration
//!
//! ## VS Code
//! Install the "SARIF Viewer" extension and open the generated .sarif file.
//!
//! ## GitHub Code Scanning
//! Upload the SARIF file using the GitHub API or Actions:
//! ```yaml
//! - uses: github/codeql-action/upload-sarif@v2
//!   with:
//!     sarif_file: reports/report.sarif
//! ```
//!
//! # Usage
//!
//! ```rust
//! use zk_fuzzer::config::{AttackType, Severity};
//! use zk_fuzzer::fuzzer::{Finding, ProofOfConcept};
//! use zk_fuzzer::reporting::sarif::SarifBuilder;
//!
//! # fn main() -> anyhow::Result<()> {
//! let findings = vec![Finding {
//!     attack_type: AttackType::Underconstrained,
//!     severity: Severity::High,
//!     description: "Example finding".to_string(),
//!     poc: ProofOfConcept::default(),
//!     location: None,
//! }];
//!
//! let report = SarifBuilder::new("zk-fuzzer", "0.1.0")
//!     .with_circuit_path("circuits/merkle.circom")
//!     .add_findings(&findings)
//!     .build();
//!
//! let temp = tempfile::NamedTempFile::new()?;
//! report.save_to_file(temp.path())?;
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::path::Path;
use zk_core::Finding;
use zk_core::{AttackType, Severity};

/// SARIF version constant
pub const SARIF_VERSION: &str = "2.1.0";

/// SARIF schema URL
pub const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

/// Complete SARIF report structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifReport {
    /// SARIF schema reference
    #[serde(rename = "$schema")]
    pub schema: String,

    /// SARIF version
    pub version: String,

    /// Analysis runs (typically one per tool execution)
    pub runs: Vec<SarifRun>,
}

/// A single analysis run
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRun {
    /// Tool information
    pub tool: SarifTool,

    /// Analysis results (findings)
    pub results: Vec<SarifResult>,

    /// Analyzed artifacts (files)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<SarifArtifact>,

    /// Invocation details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocations: Option<Vec<SarifInvocation>>,

    /// Taxonomy references (CWE, etc.)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub taxonomies: Vec<SarifTaxonomy>,

    /// Custom properties
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifPropertyBag>,
}

/// Tool that produced the analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifTool {
    /// Driver (the main tool)
    pub driver: SarifToolComponent,

    /// Extensions (plugins, additional rules)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<SarifToolComponent>,
}

/// Tool component (driver or extension)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifToolComponent {
    /// Tool name
    pub name: String,

    /// Tool version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Semantic version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_version: Option<String>,

    /// Information URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,

    /// Rules defined by this tool
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<SarifRule>,

    /// Supported taxonomies
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub supported_taxonomies: Vec<SarifToolComponentReference>,

    /// Short description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_description: Option<SarifMessage>,

    /// Full description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,
}

/// Reference to a tool component
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifToolComponentReference {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guid: Option<String>,
}

/// A rule (vulnerability type)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRule {
    /// Rule identifier
    pub id: String,

    /// Rule name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Short description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_description: Option<SarifMessage>,

    /// Full description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,

    /// Help text with remediation guidance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<SarifMessage>,

    /// Help URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,

    /// Default configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_configuration: Option<SarifRuleConfiguration>,

    /// Relationships to taxonomies (CWE, etc.)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<SarifRuleRelationship>,

    /// Custom properties
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifPropertyBag>,
}

/// Rule configuration (severity, enabled state)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRuleConfiguration {
    /// Default severity level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<SarifLevel>,

    /// Enabled by default
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Rank (0-100, higher = more important)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<f64>,
}

/// Rule relationship to taxonomy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRuleRelationship {
    /// Target taxonomy reference
    pub target: SarifReportingDescriptorReference,

    /// Relationship kinds
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<String>,
}

/// Reference to a reporting descriptor (rule or taxonomy item)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifReportingDescriptorReference {
    pub id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_component: Option<SarifToolComponentReference>,
}

/// SARIF result level (severity)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SarifLevel {
    None,
    Note,
    Warning,
    Error,
}

impl From<Severity> for SarifLevel {
    fn from(severity: Severity) -> Self {
        match severity {
            Severity::Critical | Severity::High => SarifLevel::Error,
            Severity::Medium => SarifLevel::Warning,
            Severity::Low | Severity::Info => SarifLevel::Note,
        }
    }
}

/// SARIF message with text and optional markdown
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifMessage {
    /// Plain text message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,

    /// Markdown message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,

    /// Message ID for localization
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl SarifMessage {
    /// Create a text message
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: Some(text.into()),
            markdown: None,
            id: None,
        }
    }

    /// Create a markdown message
    pub fn markdown(text: impl Into<String>, markdown: impl Into<String>) -> Self {
        Self {
            text: Some(text.into()),
            markdown: Some(markdown.into()),
            id: None,
        }
    }
}

/// A single result (finding)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    /// Rule ID that produced this result
    pub rule_id: String,

    /// Rule index in the rules array
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_index: Option<i32>,

    /// Result level (error, warning, note)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<SarifLevel>,

    /// Result kind (pass, fail, open, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    /// Result message
    pub message: SarifMessage,

    /// Locations where the issue was found
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<SarifLocation>,

    /// Related locations (context)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub related_locations: Vec<SarifLocation>,

    /// Code flows (for complex vulnerabilities)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub code_flows: Vec<SarifCodeFlow>,

    /// Fingerprints for deduplication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprints: Option<HashMap<String, String>>,

    /// Partial fingerprints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_fingerprints: Option<HashMap<String, String>>,

    /// Fix suggestions
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fixes: Vec<SarifFix>,

    /// Custom properties
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifPropertyBag>,
}

/// Location information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    /// Physical location (file, line, column)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_location: Option<SarifPhysicalLocation>,

    /// Logical location (function, class, namespace)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub logical_locations: Vec<SarifLogicalLocation>,

    /// Message describing this location
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<SarifMessage>,
}

/// Physical location in a file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    /// Artifact (file) location
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_location: Option<SarifArtifactLocation>,

    /// Region within the artifact
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,

    /// Context region (surrounding code)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_region: Option<SarifRegion>,
}

/// Artifact (file) location
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactLocation {
    /// URI of the artifact
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,

    /// URI base ID (for relative URIs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,

    /// Index in artifacts array
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<i32>,
}

/// Region within a file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRegion {
    /// Starting line (1-based)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<i32>,

    /// Starting column (1-based)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_column: Option<i32>,

    /// Ending line
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<i32>,

    /// Ending column
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<i32>,

    /// Character offset
    #[serde(skip_serializing_if = "Option::is_none")]
    pub char_offset: Option<i32>,

    /// Character length
    #[serde(skip_serializing_if = "Option::is_none")]
    pub char_length: Option<i32>,

    /// Snippet of code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<SarifArtifactContent>,
}

/// Artifact content (code snippet)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactContent {
    /// Text content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,

    /// Rendered content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rendered: Option<SarifRenderedContent>,
}

/// Rendered content
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRenderedContent {
    /// Text
    pub text: String,

    /// Markdown
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
}

/// Logical location (function, component)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLogicalLocation {
    /// Logical name (function, class, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Fully qualified name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fully_qualified_name: Option<String>,

    /// Decorated name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decorated_name: Option<String>,

    /// Kind (function, class, component, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// Code flow (sequence of locations)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifCodeFlow {
    /// Message describing the flow
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<SarifMessage>,

    /// Thread flows
    pub thread_flows: Vec<SarifThreadFlow>,
}

/// Thread flow (sequence of steps)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifThreadFlow {
    /// Thread ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<SarifMessage>,

    /// Flow locations
    pub locations: Vec<SarifThreadFlowLocation>,
}

/// Location in a thread flow
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifThreadFlowLocation {
    /// Location
    pub location: SarifLocation,

    /// Nesting level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nesting_level: Option<i32>,

    /// Step number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_order: Option<i32>,

    /// State at this point
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<HashMap<String, SarifMessage>>,
}

/// Fix suggestion
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifFix {
    /// Description of the fix
    pub description: SarifMessage,

    /// Artifact changes
    pub artifact_changes: Vec<SarifArtifactChange>,
}

/// Change to an artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactChange {
    /// Artifact location
    pub artifact_location: SarifArtifactLocation,

    /// Replacements
    pub replacements: Vec<SarifReplacement>,
}

/// Text replacement
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifReplacement {
    /// Region to delete
    pub deleted_region: SarifRegion,

    /// Inserted content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inserted_content: Option<SarifArtifactContent>,
}

/// Artifact (analyzed file)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifact {
    /// Artifact location
    pub location: SarifArtifactLocation,

    /// MIME type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,

    /// Length in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<i64>,

    /// Roles (analyzed, modified, etc.)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,

    /// Hashes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<HashMap<String, String>>,
}

/// Invocation details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifInvocation {
    /// Command line
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,

    /// Arguments
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<String>,

    /// Working directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<SarifArtifactLocation>,

    /// Start time (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time_utc: Option<String>,

    /// End time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time_utc: Option<String>,

    /// Execution successful
    pub execution_successful: bool,

    /// Exit code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

/// Taxonomy (CWE, OWASP, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifTaxonomy {
    /// Taxonomy name
    pub name: String,

    /// Version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Short description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_description: Option<SarifMessage>,

    /// Taxa (individual items)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub taxa: Vec<SarifTaxon>,

    /// GUID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guid: Option<String>,

    /// Information URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,
}

/// Taxon (single taxonomy item)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifTaxon {
    /// Taxon ID
    pub id: String,

    /// Name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Short description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_description: Option<SarifMessage>,
}

/// Property bag for custom properties
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SarifPropertyBag {
    #[serde(flatten)]
    pub properties: HashMap<String, serde_json::Value>,
}

impl SarifPropertyBag {
    /// Create a new property bag
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a property
    pub fn insert(&mut self, key: impl Into<String>, value: impl Serialize) {
        if let Ok(v) = serde_json::to_value(value) {
            self.properties.insert(key.into(), v);
        }
    }
}

/// Builder for creating SARIF reports
pub struct SarifBuilder {
    tool_name: String,
    tool_version: String,
    information_uri: Option<String>,
    circuit_path: Option<String>,
    findings: Vec<Finding>,
    artifacts: Vec<SarifArtifact>,
    invocation: Option<SarifInvocation>,
}

impl SarifBuilder {
    /// Create a new SARIF builder
    pub fn new(tool_name: impl Into<String>, tool_version: impl Into<String>) -> Self {
        Self {
            tool_name: tool_name.into(),
            tool_version: tool_version.into(),
            information_uri: None,
            circuit_path: None,
            findings: Vec::new(),
            artifacts: Vec::new(),
            invocation: None,
        }
    }

    /// Set the tool information URI
    pub fn with_information_uri(mut self, uri: impl Into<String>) -> Self {
        self.information_uri = Some(uri.into());
        self
    }

    /// Set the circuit path
    pub fn with_circuit_path(mut self, path: impl Into<String>) -> Self {
        self.circuit_path = Some(path.into());
        self
    }

    /// Add findings
    pub fn add_findings(mut self, findings: &[Finding]) -> Self {
        self.findings.extend(findings.iter().cloned());
        self
    }

    /// Add an artifact
    pub fn add_artifact(mut self, uri: impl Into<String>, mime_type: Option<&str>) -> Self {
        self.artifacts.push(SarifArtifact {
            location: SarifArtifactLocation {
                uri: Some(uri.into()),
                uri_base_id: Some("%SRCROOT%".to_string()),
                index: Some(self.artifacts.len() as i32),
            },
            mime_type: mime_type.map(String::from),
            length: None,
            roles: vec!["analysisTarget".to_string()],
            hashes: None,
        });
        self
    }

    /// Set invocation details
    pub fn with_invocation(mut self, invocation: SarifInvocation) -> Self {
        self.invocation = Some(invocation);
        self
    }

    /// Build the SARIF report
    pub fn build(self) -> SarifReport {
        let rules = generate_rules();
        let rule_map: HashMap<String, usize> = rules
            .iter()
            .enumerate()
            .map(|(i, r)| (r.id.clone(), i))
            .collect();

        let results: Vec<SarifResult> = self
            .findings
            .iter()
            .map(|f| finding_to_result(f, &rule_map, self.circuit_path.as_deref()))
            .collect();

        let mut artifacts = self.artifacts;
        if let Some(ref path) = self.circuit_path {
            if !artifacts
                .iter()
                .any(|a| a.location.uri.as_ref() == Some(path))
            {
                artifacts.push(SarifArtifact {
                    location: SarifArtifactLocation {
                        uri: Some(path.clone()),
                        uri_base_id: Some("%SRCROOT%".to_string()),
                        index: Some(artifacts.len() as i32),
                    },
                    mime_type: detect_mime_type(path),
                    length: None,
                    roles: vec!["analysisTarget".to_string()],
                    hashes: None,
                });
            }
        }

        SarifReport {
            schema: SARIF_SCHEMA.to_string(),
            version: SARIF_VERSION.to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifToolComponent {
                        name: self.tool_name,
                        version: Some(self.tool_version.clone()),
                        semantic_version: Some(self.tool_version),
                        information_uri: self.information_uri,
                        rules,
                        supported_taxonomies: vec![
                            SarifToolComponentReference {
                                name: "CWE".to_string(),
                                guid: Some("FFC64C90-42B6-44CE-8BEB-F6B7DAE649E5".to_string()),
                            },
                        ],
                        short_description: Some(SarifMessage::text(
                            "Zero-Knowledge Proof Security Testing Framework"
                        )),
                        full_description: Some(SarifMessage::text(
                            "ZK-Fuzzer detects vulnerabilities in zero-knowledge circuits through \
                             coverage-guided fuzzing, symbolic execution, and specialized attack patterns."
                        )),
                    },
                    extensions: Vec::new(),
                },
                results,
                artifacts,
                invocations: self.invocation.map(|i| vec![i]),
                taxonomies: vec![generate_cwe_taxonomy()],
                properties: None,
            }],
        }
    }
}

impl SarifReport {
    /// Save the report to a file
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Get total number of findings
    pub fn finding_count(&self) -> usize {
        self.runs.iter().map(|r| r.results.len()).sum()
    }

    /// Get findings by level
    pub fn findings_by_level(&self, level: SarifLevel) -> Vec<&SarifResult> {
        self.runs
            .iter()
            .flat_map(|r| r.results.iter())
            .filter(|r| r.level == Some(level))
            .collect()
    }
}

/// Generate all rule definitions
fn generate_rules() -> Vec<SarifRule> {
    vec![
        create_rule(
            AttackType::Underconstrained,
            "ZK001",
            "Underconstrained Circuit",
            "Circuit accepts multiple valid witnesses for the same public inputs",
            "Underconstrained circuits allow an attacker to forge proofs with different \
             private inputs that produce the same public output. This violates the \
             soundness property of the proof system.",
            "Review circuit constraints and ensure all private inputs are properly \
             constrained. Add assertions or range checks as needed.",
            (Some("CWE-697"), Severity::Critical),
        ),
        create_rule(
            AttackType::Soundness,
            "ZK002",
            "Soundness Violation",
            "Proof system accepts proofs for invalid statements",
            "A soundness violation allows forging proofs without knowledge of valid \
             witnesses. This completely breaks the security of the proof system.",
            "Check verifier implementation for bugs. Ensure all constraints are \
             properly enforced.",
            (Some("CWE-347"), Severity::Critical),
        ),
        create_rule(
            AttackType::ArithmeticOverflow,
            "ZK003",
            "Arithmetic Overflow/Underflow",
            "Field arithmetic may overflow or underflow at boundaries",
            "ZK circuits operate over finite fields where arithmetic wraps around. \
             Missing range checks can lead to unexpected behavior at boundaries.",
            "Add explicit range checks for all arithmetic operations. Test with \
             boundary values (0, 1, p-1, 2^n).",
            (Some("CWE-190"), Severity::High),
        ),
        create_rule(
            AttackType::Collision,
            "ZK004",
            "Hash Collision",
            "Circuit hash function vulnerable to collision attacks",
            "Hash collisions in ZK circuits can allow forging proofs or breaking \
             uniqueness guarantees (e.g., nullifier reuse).",
            "Use cryptographically secure ZK-friendly hash functions (Poseidon, MiMC) \
             with sufficient rounds. Ensure full output is used.",
            (Some("CWE-328"), Severity::Critical),
        ),
        create_rule(
            AttackType::Boundary,
            "ZK005",
            "Missing Boundary Check",
            "Input values not properly validated at boundaries",
            "Missing boundary checks allow invalid inputs that may cause unexpected \
             circuit behavior or bypass access controls.",
            "Add range checks for all inputs. Test with field boundaries and \
             application-specific limits.",
            (Some("CWE-20"), Severity::Medium),
        ),
        create_rule(
            AttackType::BitDecomposition,
            "ZK006",
            "Bit Decomposition Weakness",
            "Bit decomposition constraints may be incomplete",
            "Incorrect bit decomposition allows values outside expected ranges \
             to pass validation, bypassing range proofs.",
            "Ensure bit decomposition covers all necessary bits. Verify sum constraints.",
            (Some("CWE-682"), Severity::High),
        ),
        create_rule(
            AttackType::Malleability,
            "ZK007",
            "Proof Malleability",
            "Proofs can be modified without invalidating verification",
            "Malleable proofs allow attackers to create variations of valid proofs, \
             potentially bypassing replay protection or causing double-spending.",
            "Use non-malleable proof systems or add unique identifiers to proofs.",
            (Some("CWE-354"), Severity::High),
        ),
        create_rule(
            AttackType::InformationLeakage,
            "ZK008",
            "Information Leakage",
            "Private inputs may leak through public outputs",
            "Information leakage violates zero-knowledge property, potentially \
             revealing sensitive data through circuit outputs.",
            "Review output constraints. Ensure private data is properly masked \
             or hashed before output.",
            (Some("CWE-200"), Severity::High),
        ),
        create_rule(
            AttackType::TimingSideChannel,
            "ZK009",
            "Timing Side Channel",
            "Circuit execution time depends on private inputs",
            "Variable execution time can leak information about private inputs \
             through timing measurements.",
            "Ensure constant-time operations for security-critical computations.",
            (Some("CWE-208"), Severity::Medium),
        ),
        create_rule(
            AttackType::Differential,
            "ZK010",
            "Differential Behavior",
            "Circuit behaves differently across backends",
            "Inconsistent behavior between different ZK backends may indicate \
             implementation bugs or specification ambiguities.",
            "Test with multiple backends. Review specification compliance.",
            (Some("CWE-436"), Severity::Medium),
        ),
        create_rule(
            AttackType::VerificationFuzzing,
            "ZK011",
            "Verification Weakness",
            "Proof verification has edge case issues",
            "Verification weaknesses may allow invalid proofs to pass or cause \
             denial of service with malformed inputs.",
            "Fuzz test the verifier with malformed proofs. Add input validation.",
            (Some("CWE-20"), Severity::High),
        ),
        create_rule(
            AttackType::WitnessFuzzing,
            "ZK012",
            "Witness Generation Issue",
            "Witness generation is non-deterministic or fails on edge cases",
            "Non-deterministic witness generation can cause reproducibility issues \
             or denial of service.",
            "Ensure deterministic witness computation. Handle all edge cases.",
            (Some("CWE-330"), Severity::Medium),
        ),
        create_rule(
            AttackType::CircuitComposition,
            "ZK013",
            "Composition Vulnerability",
            "Multi-circuit composition has interface issues",
            "Composition vulnerabilities arise when circuits are combined without \
             proper input/output validation between components.",
            "Validate all inter-circuit data flows. Add boundary checks at interfaces.",
            (Some("CWE-501"), Severity::Medium),
        ),
        create_rule(
            AttackType::RecursiveProof,
            "ZK014",
            "Recursive Proof Issue",
            "Recursive proof verification has depth-related issues",
            "Recursive proof systems may have issues at extreme depths or with \
             malformed inner proofs.",
            "Test recursive verification at various depths. Add depth limits.",
            (Some("CWE-674"), Severity::High),
        ),
        create_rule(
            AttackType::ConstraintBypass,
            "ZK015",
            "Constraint Bypass",
            "Circuit constraints can be bypassed",
            "Missing or weak constraints allow unauthorized operations or state transitions.",
            "Audit all constraints. Add explicit checks for all security properties.",
            (Some("CWE-862"), Severity::Critical),
        ),
        create_rule(
            AttackType::WitnessLeakage,
            "ZK016",
            "Witness Leakage",
            "Witness values may be extractable from proofs",
            "Witness leakage allows recovery of private inputs from proof data.",
            "Use hiding commitments. Verify zero-knowledge property holds.",
            (Some("CWE-200"), Severity::High),
        ),
        create_rule(
            AttackType::ReplayAttack,
            "ZK017",
            "Replay Attack Vulnerability",
            "Proofs can be replayed in different contexts",
            "Replay attacks allow reusing valid proofs in unauthorized contexts.",
            "Add unique identifiers or domain separators to proof construction.",
            (Some("CWE-294"), Severity::High),
        ),
        create_rule(
            AttackType::TrustedSetup,
            "ZK018",
            "Trusted Setup Weakness",
            "Trusted setup parameters may be compromised",
            "Compromised trusted setup allows universal proof forgery.",
            "Use multi-party computation for setup. Consider transparent alternatives.",
            (Some("CWE-310"), Severity::Critical),
        ),
    ]
}

/// Create a single rule definition
fn create_rule(
    attack_type: AttackType,
    id: &str,
    name: &str,
    short_desc: &str,
    full_desc: &str,
    help: &str,
    metadata: (Option<&str>, Severity),
) -> SarifRule {
    let (cwe, severity) = metadata;
    let mut rule = SarifRule {
        id: id.to_string(),
        name: Some(name.to_string()),
        short_description: Some(SarifMessage::text(short_desc)),
        full_description: Some(SarifMessage::text(full_desc)),
        help: Some(SarifMessage::markdown(
            help,
            format!("## Remediation\n\n{}", help),
        )),
        help_uri: Some(format!(
            "https://github.com/example/zk-fuzzer/docs/rules/{}.md",
            id.to_lowercase()
        )),
        default_configuration: Some(SarifRuleConfiguration {
            level: Some(SarifLevel::from(severity)),
            enabled: Some(true),
            rank: Some(severity_to_rank(severity)),
        }),
        relationships: Vec::new(),
        properties: Some({
            let mut props = SarifPropertyBag::new();
            props.insert("attack_type", format!("{:?}", attack_type));
            props.insert("security_severity", severity_to_score(severity));
            props
        }),
    };

    // Add CWE relationship
    if let Some(cwe_id) = cwe {
        rule.relationships.push(SarifRuleRelationship {
            target: SarifReportingDescriptorReference {
                id: cwe_id.to_string(),
                index: None,
                tool_component: Some(SarifToolComponentReference {
                    name: "CWE".to_string(),
                    guid: Some("FFC64C90-42B6-44CE-8BEB-F6B7DAE649E5".to_string()),
                }),
            },
            kinds: vec!["superset".to_string()],
        });
    }

    rule
}

/// Convert finding to SARIF result
fn finding_to_result(
    finding: &Finding,
    rule_map: &HashMap<String, usize>,
    circuit_path: Option<&str>,
) -> SarifResult {
    let rule_id = attack_type_to_rule_id(&finding.attack_type);
    let rule_index = rule_map.get(&rule_id).copied().map(|i| i as i32);

    let mut locations = Vec::new();

    // Add location if available
    if let Some(ref loc) = finding.location {
        locations.push(parse_location(loc, circuit_path));
    } else if let Some(path) = circuit_path {
        // Default to circuit file
        locations.push(SarifLocation {
            physical_location: Some(SarifPhysicalLocation {
                artifact_location: Some(SarifArtifactLocation {
                    uri: Some(path.to_string()),
                    uri_base_id: Some("%SRCROOT%".to_string()),
                    index: None,
                }),
                region: None,
                context_region: None,
            }),
            logical_locations: Vec::new(),
            message: None,
        });
    }

    // Create fingerprint from description
    let mut fingerprints = HashMap::new();
    let fingerprint = sha2::Sha256::digest(finding.description.as_bytes());
    fingerprints.insert("primary".to_string(), hex::encode(&fingerprint[..8]));

    // Add PoC as properties
    let mut properties = SarifPropertyBag::new();
    if !finding.poc.witness_a.is_empty() {
        properties.insert(
            "witness_a",
            finding
                .poc
                .witness_a
                .iter()
                .map(|fe| fe.to_hex())
                .collect::<Vec<_>>(),
        );
    }
    if let Some(ref witness_b) = finding.poc.witness_b {
        properties.insert(
            "witness_b",
            witness_b.iter().map(|fe| fe.to_hex()).collect::<Vec<_>>(),
        );
    }

    SarifResult {
        rule_id,
        rule_index,
        level: Some(SarifLevel::from(finding.severity)),
        kind: Some("fail".to_string()),
        message: SarifMessage::text(&finding.description),
        locations,
        related_locations: Vec::new(),
        code_flows: Vec::new(),
        fingerprints: Some(fingerprints),
        partial_fingerprints: None,
        fixes: Vec::new(),
        properties: Some(properties),
    }
}

/// Parse location string to SARIF location
fn parse_location(loc: &str, default_path: Option<&str>) -> SarifLocation {
    // Try to parse "file:line" or "file:line:column" format
    let parts: Vec<&str> = loc.split(':').collect();

    let (file, line, column) = match parts.len() {
        1 => (parts[0], None, None),
        2 => (parts[0], parts[1].parse::<usize>().ok(), None),
        _ => (
            parts[0],
            parts[1].parse::<usize>().ok(),
            parts[2].parse::<usize>().ok(),
        ),
    };

    let uri = if file.contains('/') || file.contains('\\') || file.contains('.') {
        file.to_string()
    } else if let Some(path) = default_path {
        path.to_string()
    } else {
        file.to_string()
    };

    SarifLocation {
        physical_location: Some(SarifPhysicalLocation {
            artifact_location: Some(SarifArtifactLocation {
                uri: Some(uri),
                uri_base_id: Some("%SRCROOT%".to_string()),
                index: None,
            }),
            region: if line.is_some() {
                Some(SarifRegion {
                    start_line: line.map(|l: usize| l as i32),
                    start_column: column.map(|c: usize| c as i32),
                    end_line: None,
                    end_column: None,
                    char_offset: None,
                    char_length: None,
                    snippet: None,
                })
            } else {
                None
            },
            context_region: None,
        }),
        logical_locations: Vec::new(),
        message: None,
    }
}

/// Map attack type to rule ID
fn attack_type_to_rule_id(attack_type: &AttackType) -> String {
    match attack_type {
        AttackType::Underconstrained => "ZK001",
        AttackType::Soundness => "ZK002",
        AttackType::ArithmeticOverflow => "ZK003",
        AttackType::Collision => "ZK004",
        AttackType::Boundary => "ZK005",
        AttackType::BitDecomposition => "ZK006",
        AttackType::Malleability => "ZK007",
        AttackType::InformationLeakage => "ZK008",
        AttackType::TimingSideChannel => "ZK009",
        AttackType::Differential => "ZK010",
        AttackType::VerificationFuzzing => "ZK011",
        AttackType::WitnessFuzzing => "ZK012",
        AttackType::CircuitComposition => "ZK013",
        AttackType::RecursiveProof => "ZK014",
        AttackType::ConstraintBypass => "ZK015",
        AttackType::WitnessLeakage => "ZK016",
        AttackType::ReplayAttack => "ZK017",
        AttackType::TrustedSetup => "ZK018",
        AttackType::ConstraintInference => "ZK019",
        AttackType::Metamorphic => "ZK020",
        AttackType::ConstraintSlice => "ZK021",
        AttackType::SpecInference => "ZK022",
        AttackType::WitnessCollision => "ZK023",
        AttackType::Mev => "ZK024",
        AttackType::FrontRunning => "ZK025",
        AttackType::ZkEvm => "ZK026",
        AttackType::BatchVerification => "ZK027",
    }
    .to_string()
}

/// Convert severity to rank (0-100)
fn severity_to_rank(severity: Severity) -> f64 {
    match severity {
        Severity::Critical => 90.0,
        Severity::High => 75.0,
        Severity::Medium => 50.0,
        Severity::Low => 25.0,
        Severity::Info => 10.0,
    }
}

/// Convert severity to security score string
fn severity_to_score(severity: Severity) -> String {
    match severity {
        Severity::Critical => "9.8",
        Severity::High => "7.5",
        Severity::Medium => "5.0",
        Severity::Low => "3.0",
        Severity::Info => "1.0",
    }
    .to_string()
}

/// Detect MIME type from file extension
fn detect_mime_type(path: &str) -> Option<String> {
    let ext = path.rsplit('.').next()?;
    Some(
        match ext.to_lowercase().as_str() {
            "circom" => "text/x-circom",
            "nr" | "noir" => "text/x-noir",
            "rs" => "text/x-rust",
            "cairo" => "text/x-cairo",
            "json" => "application/json",
            "yaml" | "yml" => "text/yaml",
            "toml" => "text/x-toml",
            _ => "text/plain",
        }
        .to_string(),
    )
}

/// Generate CWE taxonomy
fn generate_cwe_taxonomy() -> SarifTaxonomy {
    SarifTaxonomy {
        name: "CWE".to_string(),
        version: Some("4.13".to_string()),
        guid: Some("FFC64C90-42B6-44CE-8BEB-F6B7DAE649E5".to_string()),
        information_uri: Some("https://cwe.mitre.org/".to_string()),
        short_description: Some(SarifMessage::text(
            "Common Weakness Enumeration - a community-developed list of software and hardware weakness types"
        )),
        taxa: vec![
            SarifTaxon {
                id: "CWE-20".to_string(),
                name: Some("Improper Input Validation".to_string()),
                short_description: Some(SarifMessage::text(
                    "The product does not validate or incorrectly validates input"
                )),
            },
            SarifTaxon {
                id: "CWE-190".to_string(),
                name: Some("Integer Overflow or Wraparound".to_string()),
                short_description: Some(SarifMessage::text(
                    "An integer overflow or wraparound occurs"
                )),
            },
            SarifTaxon {
                id: "CWE-200".to_string(),
                name: Some("Information Exposure".to_string()),
                short_description: Some(SarifMessage::text(
                    "Information is exposed to unauthorized actors"
                )),
            },
            SarifTaxon {
                id: "CWE-208".to_string(),
                name: Some("Observable Timing Discrepancy".to_string()),
                short_description: Some(SarifMessage::text(
                    "Timing differences in processing can be observed"
                )),
            },
            SarifTaxon {
                id: "CWE-294".to_string(),
                name: Some("Authentication Bypass by Capture-replay".to_string()),
                short_description: Some(SarifMessage::text(
                    "Authentication can be bypassed using captured data"
                )),
            },
            SarifTaxon {
                id: "CWE-310".to_string(),
                name: Some("Cryptographic Issues".to_string()),
                short_description: Some(SarifMessage::text(
                    "Weaknesses related to cryptographic operations"
                )),
            },
            SarifTaxon {
                id: "CWE-328".to_string(),
                name: Some("Reversible One-Way Hash".to_string()),
                short_description: Some(SarifMessage::text(
                    "Use of a weak hash function"
                )),
            },
            SarifTaxon {
                id: "CWE-330".to_string(),
                name: Some("Use of Insufficiently Random Values".to_string()),
                short_description: Some(SarifMessage::text(
                    "Random values are not sufficiently unpredictable"
                )),
            },
            SarifTaxon {
                id: "CWE-347".to_string(),
                name: Some("Improper Verification of Cryptographic Signature".to_string()),
                short_description: Some(SarifMessage::text(
                    "Signature verification is improper"
                )),
            },
            SarifTaxon {
                id: "CWE-354".to_string(),
                name: Some("Improper Validation of Integrity Check Value".to_string()),
                short_description: Some(SarifMessage::text(
                    "Integrity check values are not properly validated"
                )),
            },
            SarifTaxon {
                id: "CWE-436".to_string(),
                name: Some("Interpretation Conflict".to_string()),
                short_description: Some(SarifMessage::text(
                    "Different components interpret data differently"
                )),
            },
            SarifTaxon {
                id: "CWE-501".to_string(),
                name: Some("Trust Boundary Violation".to_string()),
                short_description: Some(SarifMessage::text(
                    "Trust boundaries are violated during data transfer"
                )),
            },
            SarifTaxon {
                id: "CWE-674".to_string(),
                name: Some("Uncontrolled Recursion".to_string()),
                short_description: Some(SarifMessage::text(
                    "Recursion depth is not properly controlled"
                )),
            },
            SarifTaxon {
                id: "CWE-682".to_string(),
                name: Some("Incorrect Calculation".to_string()),
                short_description: Some(SarifMessage::text(
                    "Calculations are performed incorrectly"
                )),
            },
            SarifTaxon {
                id: "CWE-697".to_string(),
                name: Some("Incorrect Comparison".to_string()),
                short_description: Some(SarifMessage::text(
                    "Comparisons are performed incorrectly"
                )),
            },
            SarifTaxon {
                id: "CWE-862".to_string(),
                name: Some("Missing Authorization".to_string()),
                short_description: Some(SarifMessage::text(
                    "Authorization checks are missing"
                )),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_core::ProofOfConcept;

    #[test]
    fn test_sarif_builder() {
        let findings = vec![Finding {
            attack_type: AttackType::Underconstrained,
            severity: Severity::Critical,
            description: "Test finding".to_string(),
            poc: ProofOfConcept::default(),
            location: Some("test.circom:42".to_string()),
        }];

        let report = SarifBuilder::new("zk-fuzzer", "0.1.0")
            .with_circuit_path("circuits/test.circom")
            .add_findings(&findings)
            .build();

        assert_eq!(report.version, SARIF_VERSION);
        assert_eq!(report.runs.len(), 1);
        assert_eq!(report.runs[0].results.len(), 1);
        assert_eq!(report.runs[0].results[0].rule_id, "ZK001");
    }

    #[test]
    fn test_severity_to_level() {
        assert_eq!(SarifLevel::from(Severity::Critical), SarifLevel::Error);
        assert_eq!(SarifLevel::from(Severity::High), SarifLevel::Error);
        assert_eq!(SarifLevel::from(Severity::Medium), SarifLevel::Warning);
        assert_eq!(SarifLevel::from(Severity::Low), SarifLevel::Note);
        assert_eq!(SarifLevel::from(Severity::Info), SarifLevel::Note);
    }

    #[test]
    fn test_parse_location() {
        let loc = parse_location("test.circom:42:10", None);
        let phys = loc.physical_location.unwrap();
        assert_eq!(
            phys.artifact_location.unwrap().uri,
            Some("test.circom".to_string())
        );
        let region = phys.region.unwrap();
        assert_eq!(region.start_line, Some(42));
        assert_eq!(region.start_column, Some(10));
    }

    #[test]
    fn test_attack_type_to_rule_id() {
        assert_eq!(
            attack_type_to_rule_id(&AttackType::Underconstrained),
            "ZK001"
        );
        assert_eq!(attack_type_to_rule_id(&AttackType::Collision), "ZK004");
        assert_eq!(attack_type_to_rule_id(&AttackType::Boundary), "ZK005");
    }

    #[test]
    fn test_generate_rules() {
        let rules = generate_rules();
        assert!(rules.len() >= 10);

        // All rules should have IDs starting with ZK
        assert!(rules.iter().all(|r| r.id.starts_with("ZK")));

        // All rules should have descriptions
        assert!(rules.iter().all(|r| r.short_description.is_some()));
    }

    #[test]
    fn test_sarif_serialization() {
        let report = SarifBuilder::new("test", "1.0.0").build();
        let json = report.to_json().unwrap();

        // Should contain required fields
        assert!(json.contains("$schema"));
        assert!(json.contains("version"));
        assert!(json.contains("runs"));
    }

    #[test]
    fn test_detect_mime_type() {
        assert_eq!(
            detect_mime_type("test.circom"),
            Some("text/x-circom".to_string())
        );
        assert_eq!(detect_mime_type("test.nr"), Some("text/x-noir".to_string()));
        assert_eq!(detect_mime_type("test.rs"), Some("text/x-rust".to_string()));
        assert_eq!(
            detect_mime_type("test.json"),
            Some("application/json".to_string())
        );
    }

    #[test]
    fn test_hamming_fingerprint() {
        let findings = vec![Finding {
            attack_type: AttackType::Collision,
            severity: Severity::High,
            description: "Test collision".to_string(),
            poc: ProofOfConcept::default(),
            location: None,
        }];

        let report = SarifBuilder::new("test", "1.0.0")
            .add_findings(&findings)
            .build();

        let result = &report.runs[0].results[0];
        assert!(result.fingerprints.is_some());
    }
}
