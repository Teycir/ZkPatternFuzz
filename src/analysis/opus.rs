//! Opus Project Analyzer
//!
//! Analyzes ZK projects and generates optimized YAML fuzzing configurations.
//! This module implements the "Opus" analysis workflow for adaptive fuzzing.
//!
//! # Workflow
//!
//! 1. Scan ZK project directory for circuit files
//! 2. Analyze each circuit for patterns, inputs, and vulnerabilities
//! 3. Generate optimized YAML configurations
//! 4. Feed configurations to the fuzzing engine
//!
//! # Example
//!
//! ```rust,ignore
//! use zk_fuzzer::analysis::opus::OpusAnalyzer;
//!
//! let analyzer = OpusAnalyzer::new();
//! let configs = analyzer.analyze_project("/path/to/zk/project")?;
//!
//! for config in configs {
//!     println!("Generated config for: {}", config.circuit_name);
//!     config.save("campaigns/")?;
//! }
//! ```

use crate::config::generator::{ConfigGenerator, DetectedPattern, PatternType};
use crate::config::v2::{FuzzConfigV2, Invariant, InvariantOracle, InvariantType, SchedulePhase};
use crate::config::{Attack, Campaign, FuzzConfig, Input, Parameters, ReportingConfig, Target};
use anyhow::Context;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use zk_core::{AttackType, Framework};

const DEFAULT_ZK0D_BASE: &str = "/media/elements/Repos/zk0d";

/// Result from analyzing a single circuit
#[derive(Debug, Clone)]
pub struct CircuitAnalysisResult {
    /// Path to the circuit file
    pub circuit_path: PathBuf,
    /// Detected framework
    pub framework: Framework,
    /// Main component/function name
    pub main_component: String,
    /// Detected patterns
    pub patterns: Vec<DetectedPattern>,
    /// Extracted inputs
    pub inputs: Vec<InputInfo>,
    /// Estimated complexity
    pub complexity: ComplexityEstimate,
    /// Suggested attack priorities
    pub attack_priorities: Vec<AttackPriority>,
    /// Zero-day vulnerability hints
    pub zero_day_hints: Vec<ZeroDayHint>,
}

/// Information about a circuit input
#[derive(Debug, Clone)]
pub struct InputInfo {
    /// Input name
    pub name: String,
    /// Input type
    pub input_type: String,
    /// Whether it's public
    pub is_public: bool,
    /// Inferred constraints
    pub constraints: Vec<String>,
    /// Array length (if applicable)
    pub length: Option<usize>,
}

/// Estimated complexity metrics
#[derive(Debug, Clone, Default)]
pub struct ComplexityEstimate {
    /// Estimated constraint count
    pub estimated_constraints: usize,
    /// Lines of code
    pub lines_of_code: usize,
    /// Number of template/function calls
    pub template_calls: usize,
    /// Nesting depth
    pub max_nesting: usize,
    /// Whether it uses recursion
    pub has_recursion: bool,
}

/// Attack type with priority and rationale
#[derive(Debug, Clone)]
pub struct AttackPriority {
    /// Attack type
    pub attack_type: AttackType,
    /// Priority (1 = highest)
    pub priority: u8,
    /// Why this attack is relevant
    pub rationale: String,
    /// Suggested iteration count
    pub suggested_iterations: usize,
}

/// Hints for potential zero-day vulnerabilities
#[derive(Debug, Clone)]
pub struct ZeroDayHint {
    /// Category of potential vulnerability
    pub category: ZeroDayCategory,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Description of the hint
    pub description: String,
    /// Location in source (line numbers)
    pub locations: Vec<usize>,
    /// Suggested mutation focus
    pub mutation_focus: Option<String>,
}

/// Categories of zero-day vulnerabilities
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ZeroDayCategory {
    /// Missing constraint on critical path
    MissingConstraint,
    /// Incorrect range check
    IncorrectRangeCheck,
    /// Non-deterministic witness generation
    NonDeterministicWitness,
    /// Hash function misuse
    HashMisuse,
    /// Signature malleability
    SignatureMalleability,
    /// Nullifier reuse possible
    NullifierReuse,
    /// Bit decomposition bypass
    BitDecompositionBypass,
    /// Arithmetic overflow in constraint
    ArithmeticOverflow,
    /// Information leak through timing
    TimingLeak,
    /// Custom vulnerability
    Custom(String),
}

/// Configuration for project analysis
#[derive(Debug, Clone)]
pub struct OpusConfig {
    /// Maximum files to analyze
    pub max_files: usize,
    /// Extensions to consider
    pub circuit_extensions: Vec<String>,
    /// Whether to analyze dependencies
    pub analyze_dependencies: bool,
    /// Minimum confidence for zero-day hints
    pub min_zero_day_confidence: f64,
    /// Output directory for generated configs
    pub output_dir: PathBuf,
}

impl Default for OpusConfig {
    fn default() -> Self {
        Self {
            max_files: 100,
            circuit_extensions: vec![
                "circom".to_string(),
                "nr".to_string(),
                "cairo".to_string(),
                "rs".to_string(),
            ],
            analyze_dependencies: true,
            min_zero_day_confidence: 0.3,
            output_dir: PathBuf::from("./campaigns/generated"),
        }
    }
}

/// Opus project analyzer
pub struct OpusAnalyzer {
    /// Configuration
    config: OpusConfig,
    /// Config generator for pattern detection
    generator: ConfigGenerator,
    /// Zero-day detectors
    zero_day_detectors: Vec<Box<dyn ZeroDayDetector>>,
}

impl Default for OpusAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl OpusAnalyzer {
    /// Create a new analyzer with default configuration
    pub fn new() -> Self {
        Self::with_config(OpusConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: OpusConfig) -> Self {
        let zero_day_detectors: Vec<Box<dyn ZeroDayDetector>> = vec![
            Box::new(MissingConstraintDetector),
            Box::new(RangeCheckDetector),
            Box::new(HashMisuseDetector),
            Box::new(SignatureMalleabilityDetector),
            Box::new(NullifierReuseDetector),
            Box::new(BitDecompositionDetector),
            Box::new(ArithmeticOverflowDetector),
        ];

        Self {
            config,
            generator: ConfigGenerator::new(),
            zero_day_detectors,
        }
    }

    /// Analyze a ZK project directory
    pub fn analyze_project(
        &self,
        project_path: impl AsRef<Path>,
    ) -> anyhow::Result<Vec<GeneratedConfig>> {
        let project_path = project_path.as_ref();
        tracing::info!("Analyzing ZK project: {}", project_path.display());

        // Find all circuit files
        let circuit_files = self.find_circuit_files(project_path)?;
        tracing::info!("Found {} circuit files", circuit_files.len());

        let mut configs = Vec::new();

        for circuit_path in circuit_files.iter().take(self.config.max_files) {
            match self.analyze_circuit(circuit_path) {
                Ok(analysis) => {
                    let config = self.generate_config(&analysis)?;
                    configs.push(config);
                }
                Err(e) => {
                    tracing::warn!("Failed to analyze {}: {}", circuit_path.display(), e);
                }
            }
        }

        Ok(configs)
    }

    /// Analyze a single circuit file
    pub fn analyze_circuit(
        &self,
        circuit_path: impl AsRef<Path>,
    ) -> anyhow::Result<CircuitAnalysisResult> {
        let circuit_path = circuit_path.as_ref();
        let source = std::fs::read_to_string(circuit_path)?;
        let framework = self.detect_framework(circuit_path)?;

        // Detect patterns
        let patterns = self.generator.detect_patterns(&source, framework);

        // Extract inputs
        let inputs = self.extract_inputs(&source, framework);

        // Estimate complexity
        let complexity = self.estimate_complexity(&source, framework);

        // Detect zero-day hints
        let zero_day_hints = self.detect_zero_day_hints(&source, framework, &patterns);

        // Calculate attack priorities
        let attack_priorities =
            self.calculate_attack_priorities(&patterns, &zero_day_hints, &complexity);

        // Detect main component
        let main_component = self.detect_main_component(&source, framework);

        Ok(CircuitAnalysisResult {
            circuit_path: circuit_path.to_path_buf(),
            framework,
            main_component,
            patterns,
            inputs,
            complexity,
            attack_priorities,
            zero_day_hints,
        })
    }

    /// Generate YAML configuration from analysis
    pub fn generate_config(
        &self,
        analysis: &CircuitAnalysisResult,
    ) -> anyhow::Result<GeneratedConfig> {
        let circuit_stem = analysis.circuit_path.file_stem().with_context(|| {
            format!(
                "Cannot derive circuit name from path without file stem: {}",
                analysis.circuit_path.display()
            )
        })?;
        let circuit_name = circuit_stem.to_str().with_context(|| {
            format!(
                "Circuit name is not valid UTF-8: {}",
                analysis.circuit_path.display()
            )
        })?;
        let circuit_name = circuit_name.to_string();

        // Build attacks from priorities
        let attacks = self.build_attacks(analysis);

        // Build inputs
        let inputs = self.build_inputs(analysis);

        // Build invariants from patterns and zero-day hints
        let invariants = self.build_invariants(analysis);

        // Build schedule based on attack priorities
        let schedule = self.build_schedule(analysis);

        // Build includes
        let includes = self.suggest_includes(&analysis.patterns);

        let config = FuzzConfigV2 {
            includes,
            profiles: HashMap::new(),
            active_profile: None,
            target_traits: self.build_target_traits(&analysis.patterns),
            invariants,
            schedule,
            chains: Vec::new(), // Mode 3: No auto-generated chains
            base: Some(FuzzConfig {
                campaign: Campaign {
                    name: format!("Opus-Generated: {}", circuit_name),
                    version: "2.0".to_string(),
                    target: Target {
                        framework: analysis.framework,
                        circuit_path: analysis.circuit_path.clone(),
                        main_component: analysis.main_component.clone(),
                    },
                    parameters: Parameters {
                        timeout_seconds: self.calculate_timeout(&analysis.complexity),
                        ..Default::default()
                    },
                },
                attacks,
                inputs,
                mutations: vec![],
                oracles: vec![],
                reporting: ReportingConfig {
                    output_dir: self.config.output_dir.join(&circuit_name),
                    ..Default::default()
                },
                chains: vec![],
            }),
        };

        Ok(GeneratedConfig {
            circuit_name,
            circuit_path: analysis.circuit_path.clone(),
            config,
            zero_day_hints: analysis.zero_day_hints.clone(),
            analysis_summary: self.generate_summary(analysis),
        })
    }

    /// Find all circuit files in project
    fn find_circuit_files(&self, project_path: &Path) -> anyhow::Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        fn visit_dir(
            dir: &Path,
            extensions: &[String],
            files: &mut Vec<PathBuf>,
            max_files: usize,
        ) -> std::io::Result<()> {
            if files.len() >= max_files {
                return Ok(());
            }

            if dir.is_dir() {
                for entry in std::fs::read_dir(dir)? {
                    let entry = entry?;
                    let path = entry.path();

                    // Skip node_modules, target, .git, etc.
                    if path.is_dir() {
                        let Some(name_os) = path.file_name() else {
                            continue;
                        };
                        let name = name_os.to_string_lossy();
                        if name.starts_with('.') || name == "node_modules" || name == "target" {
                            continue;
                        }
                        visit_dir(&path, extensions, files, max_files)?;
                    } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if extensions.iter().any(|e| e == ext) {
                            files.push(path);
                        }
                    }

                    if files.len() >= max_files {
                        break;
                    }
                }
            }
            Ok(())
        }

        visit_dir(
            project_path,
            &self.config.circuit_extensions,
            &mut files,
            self.config.max_files,
        )?;

        Ok(files)
    }

    /// Detect framework from file extension and content
    fn detect_framework(&self, path: &Path) -> anyhow::Result<Framework> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .with_context(|| format!("Circuit file has no UTF-8 extension: {}", path.display()))?;

        match ext {
            "circom" => Ok(Framework::Circom),
            "nr" => Ok(Framework::Noir),
            "cairo" => Ok(Framework::Cairo),
            "rs" => {
                // Check if it's Halo2
                let content = std::fs::read_to_string(path)?;
                if content.contains("halo2_proofs") || content.contains("halo2::") {
                    Ok(Framework::Halo2)
                } else {
                    anyhow::bail!(
                        "Rust circuit file is not recognized as Halo2: {}",
                        path.display()
                    )
                }
            }
            _ => anyhow::bail!(
                "Unsupported circuit file extension for backend detection: {}",
                path.display()
            ),
        }
    }

    /// Extract inputs from source
    fn extract_inputs(&self, source: &str, framework: Framework) -> Vec<InputInfo> {
        let mut inputs = Vec::new();

        match framework {
            Framework::Circom => {
                for (line_num, line) in source.lines().enumerate() {
                    let line = line.trim();

                    if line.starts_with("signal input") || line.starts_with("signal private input")
                    {
                        let is_public = !line.contains("private");
                        if let Some(info) = self.parse_circom_signal(line, is_public, line_num) {
                            inputs.push(info);
                        }
                    }
                }
            }
            Framework::Noir => {
                // Parse fn main parameters
                for line in source.lines() {
                    if line.contains("fn main") {
                        if let Some(start) = line.find('(') {
                            if let Some(end) = line.find(')') {
                                let params = &line[start + 1..end];
                                for param in params.split(',') {
                                    if let Some(info) = self.parse_noir_param(param.trim()) {
                                        inputs.push(info);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                // Generic input detection
                inputs.push(InputInfo {
                    name: "input".to_string(),
                    input_type: "field".to_string(),
                    is_public: false,
                    constraints: vec![],
                    length: None,
                });
            }
        }

        if inputs.is_empty() {
            inputs.push(InputInfo {
                name: "default_input".to_string(),
                input_type: "field".to_string(),
                is_public: false,
                constraints: vec![],
                length: None,
            });
        }

        inputs
    }

    fn parse_circom_signal(
        &self,
        line: &str,
        is_public: bool,
        _line_num: usize,
    ) -> Option<InputInfo> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let name_part = parts.last()?;
        let name = name_part.trim_end_matches(';');

        // Check for array
        let (name, length) = if let Some(bracket) = name.find('[') {
            let base_name = &name[..bracket];
            let len_str = name[bracket + 1..].trim_end_matches(']');
            let len: usize = match len_str.parse() {
                Ok(len) => len,
                Err(err) => {
                    tracing::debug!("Skipping non-literal input length '{}': {}", len_str, err);
                    return None;
                }
            };
            (base_name.to_string(), Some(len))
        } else {
            (name.to_string(), None)
        };

        Some(InputInfo {
            name,
            input_type: if length.is_some() {
                "array<field>".to_string()
            } else {
                "field".to_string()
            },
            is_public,
            constraints: vec![],
            length,
        })
    }

    fn parse_noir_param(&self, param: &str) -> Option<InputInfo> {
        if param.is_empty() {
            return None;
        }

        let parts: Vec<&str> = param.split(':').collect();
        if parts.len() < 2 {
            return None;
        }

        let name = parts[0].trim().to_string();
        let type_part = parts[1].trim();
        let is_public = type_part.contains("pub ");

        Some(InputInfo {
            name,
            input_type: "field".to_string(),
            is_public,
            constraints: vec![],
            length: None,
        })
    }

    /// Estimate circuit complexity
    fn estimate_complexity(&self, source: &str, framework: Framework) -> ComplexityEstimate {
        let lines_of_code = source
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with("//"))
            .count();

        let template_calls = match framework {
            Framework::Circom => {
                source.matches("component ").count()
                    + source.matches("<==").count()
                    + source.matches("===").count()
            }
            Framework::Noir => source.matches("fn ").count() + source.matches("assert").count(),
            _ => source.lines().count() / 10,
        };

        let max_nesting = self.calculate_max_nesting(source);
        let has_recursion = source.contains("recursive") || source.contains("@recursive");

        // Rough constraint estimation
        let estimated_constraints = match framework {
            Framework::Circom => template_calls * 5 + lines_of_code / 2,
            Framework::Noir => template_calls * 10 + lines_of_code,
            _ => lines_of_code * 2,
        };

        ComplexityEstimate {
            estimated_constraints,
            lines_of_code,
            template_calls,
            max_nesting,
            has_recursion,
        }
    }

    fn calculate_max_nesting(&self, source: &str) -> usize {
        let mut max_depth: usize = 0;
        let mut current_depth: usize = 0;

        for ch in source.chars() {
            match ch {
                '{' => {
                    current_depth += 1;
                    max_depth = max_depth.max(current_depth);
                }
                '}' => current_depth = current_depth.saturating_sub(1),
                _ => {}
            }
        }

        max_depth
    }

    /// Detect zero-day vulnerability hints
    fn detect_zero_day_hints(
        &self,
        source: &str,
        framework: Framework,
        patterns: &[DetectedPattern],
    ) -> Vec<ZeroDayHint> {
        let mut hints = Vec::new();

        for detector in &self.zero_day_detectors {
            hints.extend(detector.detect(source, framework, patterns));
        }

        // Filter by confidence threshold
        hints.retain(|h| h.confidence >= self.config.min_zero_day_confidence);

        // Sort by confidence (highest first)
        hints.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        hints
    }

    /// Calculate attack priorities based on analysis
    fn calculate_attack_priorities(
        &self,
        patterns: &[DetectedPattern],
        zero_day_hints: &[ZeroDayHint],
        complexity: &ComplexityEstimate,
    ) -> Vec<AttackPriority> {
        let mut priorities = Vec::new();

        // Always include underconstrained check (priority 1)
        priorities.push(AttackPriority {
            attack_type: AttackType::Underconstrained,
            priority: 1,
            rationale: "Core check for missing constraints".to_string(),
            suggested_iterations: (complexity.estimated_constraints * 10).max(2000),
        });

        // Add pattern-specific attacks
        for pattern in patterns {
            match &pattern.pattern_type {
                PatternType::MerkleTree => {
                    priorities.push(AttackPriority {
                        attack_type: AttackType::Collision,
                        priority: 2,
                        rationale: "Merkle tree detected - check for root collisions".to_string(),
                        suggested_iterations: 50000,
                    });
                }
                PatternType::HashFunction(_) => {
                    priorities.push(AttackPriority {
                        attack_type: AttackType::Collision,
                        priority: 2,
                        rationale: "Hash function detected - check for collisions".to_string(),
                        suggested_iterations: 100000,
                    });
                }
                PatternType::Signature => {
                    priorities.push(AttackPriority {
                        attack_type: AttackType::Soundness,
                        priority: 1,
                        rationale: "Signature scheme - check for forgery".to_string(),
                        suggested_iterations: 10000,
                    });
                }
                PatternType::RangeCheck | PatternType::BitDecomposition => {
                    priorities.push(AttackPriority {
                        attack_type: AttackType::ArithmeticOverflow,
                        priority: 2,
                        rationale: "Range check detected - test boundary conditions".to_string(),
                        suggested_iterations: 5000,
                    });
                }
                PatternType::Nullifier => {
                    priorities.push(AttackPriority {
                        attack_type: AttackType::Collision,
                        priority: 1,
                        rationale: "Nullifier pattern - check uniqueness".to_string(),
                        suggested_iterations: 50000,
                    });
                }
                _ => {}
            }
        }

        // Boost priority based on zero-day hints
        for hint in zero_day_hints {
            let boost_attack = match hint.category {
                ZeroDayCategory::MissingConstraint => Some(AttackType::Underconstrained),
                ZeroDayCategory::IncorrectRangeCheck => Some(AttackType::ArithmeticOverflow),
                ZeroDayCategory::SignatureMalleability => Some(AttackType::Soundness),
                ZeroDayCategory::NullifierReuse => Some(AttackType::Collision),
                _ => None,
            };

            if let Some(attack) = boost_attack {
                if let Some(p) = priorities.iter_mut().find(|p| p.attack_type == attack) {
                    p.priority = 1;
                    p.rationale = format!("{} (Zero-day hint: {})", p.rationale, hint.description);
                }
            }
        }

        // Add constraint inference for complex circuits
        if complexity.estimated_constraints > 1000 {
            priorities.push(AttackPriority {
                attack_type: AttackType::ConstraintInference,
                priority: 3,
                rationale: "Complex circuit - use constraint inference".to_string(),
                suggested_iterations: 10000,
            });
        }

        // Sort by priority
        priorities.sort_by_key(|p| p.priority);

        priorities
    }

    fn detect_main_component(&self, source: &str, framework: Framework) -> String {
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
                panic!(
                    "Circom source missing explicit `component main = ...`; implicit template selection removed"
                );
            }
            Framework::Noir => {
                if source.contains("fn main") {
                    return "main".to_string();
                }
                panic!("Noir source missing `fn main`; implicit defaults removed");
            }
            _ => {}
        }
        panic!("Unsupported framework for main component detection: {:?}", framework)
    }

    fn build_attacks(&self, analysis: &CircuitAnalysisResult) -> Vec<Attack> {
        analysis
            .attack_priorities
            .iter()
            .map(|p| {
                let mut config = serde_yaml::Mapping::new();
                config.insert(
                    serde_yaml::Value::String("samples".to_string()),
                    serde_yaml::Value::Number(p.suggested_iterations.into()),
                );

                Attack {
                    attack_type: p.attack_type.clone(),
                    description: p.rationale.clone(),
                    plugin: None,
                    config: serde_yaml::Value::Mapping(config),
                }
            })
            .collect()
    }

    fn build_inputs(&self, analysis: &CircuitAnalysisResult) -> Vec<Input> {
        analysis
            .inputs
            .iter()
            .map(|i| Input {
                name: i.name.clone(),
                input_type: i.input_type.clone(),
                fuzz_strategy: crate::config::FuzzStrategy::Random,
                constraints: i.constraints.clone(),
                interesting: vec!["0".to_string(), "1".to_string()],
                length: i.length,
            })
            .collect()
    }

    fn build_invariants(&self, analysis: &CircuitAnalysisResult) -> Vec<Invariant> {
        let mut invariants = Vec::new();

        // Add pattern-based invariants
        for pattern in &analysis.patterns {
            match &pattern.pattern_type {
                PatternType::MerkleTree => {
                    invariants.push(Invariant {
                        name: "merkle_path_binary".to_string(),
                        invariant_type: InvariantType::Constraint,
                        relation: "∀i: pathIndices[i] ∈ {0,1}".to_string(),
                        oracle: InvariantOracle::MustHold,
                        transform: None,
                        expected: None,
                        description: Some("Merkle path indices must be binary".to_string()),
                        severity: Some("critical".to_string()),
                    });
                }
                PatternType::Nullifier => {
                    invariants.push(Invariant {
                        name: "nullifier_uniqueness".to_string(),
                        invariant_type: InvariantType::Uniqueness,
                        relation: "unique(nullifier)".to_string(),
                        oracle: InvariantOracle::MustHold,
                        transform: None,
                        expected: None,
                        description: Some("Nullifier must be unique".to_string()),
                        severity: Some("critical".to_string()),
                    });
                }
                _ => {}
            }
        }

        // Add zero-day hint based invariants
        for hint in &analysis.zero_day_hints {
            if hint.confidence > 0.5 {
                invariants.push(Invariant {
                    name: format!("zero_day_{:?}", hint.category)
                        .to_lowercase()
                        .replace(' ', "_"),
                    invariant_type: InvariantType::Constraint,
                    relation: hint.description.clone(),
                    oracle: InvariantOracle::MustHold,
                    transform: None,
                    expected: None,
                    description: Some(format!("Potential zero-day: {}", hint.description)),
                    severity: Some("critical".to_string()),
                });
            }
        }

        invariants
    }

    fn build_schedule(&self, analysis: &CircuitAnalysisResult) -> Vec<SchedulePhase> {
        let mut phases = vec![];

        // Phase 1: Quick exploration
        phases.push(SchedulePhase {
            phase: "exploration".to_string(),
            duration_sec: 60,
            attacks: vec!["underconstrained".to_string(), "boundary".to_string()],
            max_iterations: None,
            early_terminate: Some(crate::config::v2::EarlyTerminateCondition {
                on_critical_findings: Some(3),
                on_coverage_percent: None,
                on_stale_seconds: None,
            }),
            carry_corpus: true,
            mutation_weights: HashMap::new(),
        });

        // Phase 2: Pattern-specific testing
        let pattern_attacks: Vec<String> = analysis
            .attack_priorities
            .iter()
            .filter(|p| p.priority <= 2)
            .map(|p| format!("{:?}", p.attack_type).to_lowercase())
            .collect();

        if !pattern_attacks.is_empty() {
            phases.push(SchedulePhase {
                phase: "pattern_specific".to_string(),
                duration_sec: 180,
                attacks: pattern_attacks,
                max_iterations: None,
                early_terminate: None,
                carry_corpus: true,
                mutation_weights: HashMap::new(),
            });
        }

        // Phase 3: Zero-day focused (adaptive)
        if !analysis.zero_day_hints.is_empty() {
            phases.push(SchedulePhase {
                phase: "zero_day_hunt".to_string(),
                duration_sec: 300,
                attacks: vec![
                    "constraint_inference".to_string(),
                    "spec_inference".to_string(),
                    "metamorphic".to_string(),
                ],
                max_iterations: None,
                early_terminate: Some(crate::config::v2::EarlyTerminateCondition {
                    on_critical_findings: Some(1),
                    on_coverage_percent: None,
                    on_stale_seconds: Some(120),
                }),
                carry_corpus: true,
                mutation_weights: HashMap::new(),
            });
        }

        // Phase 4: Deep testing
        phases.push(SchedulePhase {
            phase: "deep_testing".to_string(),
            duration_sec: 600,
            attacks: vec![
                "soundness".to_string(),
                "underconstrained".to_string(),
                "collision".to_string(),
            ],
            max_iterations: None,
            early_terminate: None,
            carry_corpus: true,
            mutation_weights: HashMap::new(),
        });

        phases
    }

    fn suggest_includes(&self, patterns: &[DetectedPattern]) -> Vec<String> {
        let mut includes = vec!["templates/traits/base.yaml".to_string()];

        for pattern in patterns {
            if let Some(ref trait_name) = pattern.suggested_trait {
                let include = format!("templates/traits/{}.yaml", trait_name);
                if !includes.contains(&include) {
                    includes.push(include);
                }
            }
        }

        includes
    }

    fn build_target_traits(&self, patterns: &[DetectedPattern]) -> crate::config::v2::TargetTraits {
        let mut traits = crate::config::v2::TargetTraits::default();

        for pattern in patterns {
            match &pattern.pattern_type {
                PatternType::MerkleTree => traits.uses_merkle = true,
                PatternType::Nullifier => traits.uses_nullifier = true,
                PatternType::Commitment => traits.uses_commitment = true,
                PatternType::Signature => traits.uses_signature = true,
                PatternType::HashFunction(name) => traits.hash_function = Some(name.clone()),
                PatternType::RangeCheck => traits.range_checks.push("detected".to_string()),
                _ => {}
            }
        }

        traits
    }

    fn calculate_timeout(&self, complexity: &ComplexityEstimate) -> u64 {
        // Base timeout + scaling based on complexity
        let base = 300;
        let constraint_factor = (complexity.estimated_constraints / 1000) as u64 * 60;
        let nesting_factor = complexity.max_nesting as u64 * 30;

        (base + constraint_factor + nesting_factor).min(3600)
    }

    fn generate_summary(&self, analysis: &CircuitAnalysisResult) -> String {
        let mut summary = String::new();

        summary.push_str(&format!("Circuit: {}\n", analysis.circuit_path.display()));
        summary.push_str(&format!("Framework: {:?}\n", analysis.framework));
        summary.push_str(&format!(
            "Estimated constraints: {}\n",
            analysis.complexity.estimated_constraints
        ));
        summary.push_str(&format!("Patterns detected: {}\n", analysis.patterns.len()));
        summary.push_str(&format!(
            "Zero-day hints: {}\n",
            analysis.zero_day_hints.len()
        ));

        if !analysis.zero_day_hints.is_empty() {
            summary.push_str("\nZero-day vulnerability hints:\n");
            for hint in &analysis.zero_day_hints {
                summary.push_str(&format!(
                    "  - [{:.0}%] {:?}: {}\n",
                    hint.confidence * 100.0,
                    hint.category,
                    hint.description
                ));
            }
        }

        summary
    }
}

/// Generated configuration with metadata
#[derive(Debug, Clone)]
pub struct GeneratedConfig {
    /// Circuit name
    pub circuit_name: String,
    /// Path to circuit
    pub circuit_path: PathBuf,
    /// Generated configuration
    pub config: FuzzConfigV2,
    /// Zero-day hints for this circuit
    pub zero_day_hints: Vec<ZeroDayHint>,
    /// Analysis summary
    pub analysis_summary: String,
}

impl GeneratedConfig {
    /// Save configuration to file
    pub fn save(&self, output_dir: impl AsRef<Path>) -> anyhow::Result<PathBuf> {
        self.save_with_rewrite(output_dir, None)
    }

    /// Save configuration with a custom root placeholder (e.g. ${TARGET_REPO})
    pub fn save_with_placeholder(
        &self,
        output_dir: impl AsRef<Path>,
        root: impl AsRef<Path>,
        placeholder: &str,
    ) -> anyhow::Result<PathBuf> {
        let placeholder = placeholder.trim();
        if placeholder.is_empty() {
            return self.save(output_dir);
        }
        self.save_with_rewrite(output_dir, Some((root.as_ref(), placeholder)))
    }

    fn save_with_rewrite(
        &self,
        output_dir: impl AsRef<Path>,
        rewrite: Option<(&Path, &str)>,
    ) -> anyhow::Result<PathBuf> {
        let output_dir = output_dir.as_ref();
        std::fs::create_dir_all(output_dir)?;

        let filename = format!("{}.yaml", self.circuit_name);
        let path = output_dir.join(&filename);

        let mut config = self.config.clone();
        let display_path = if let Some((root, placeholder)) = rewrite {
            let rewritten = rewrite_path_with_placeholder(&self.circuit_path, root, placeholder);
            if let Some(base) = &mut config.base {
                let rewritten_target = rewrite_path_with_placeholder(
                    &base.campaign.target.circuit_path,
                    root,
                    placeholder,
                );
                base.campaign.target.circuit_path = PathBuf::from(rewritten_target);
            }
            rewritten
        } else {
            let rewritten = rewrite_zk0d_path(&self.circuit_path);
            if let Some(base) = &mut config.base {
                let rewritten_target = rewrite_zk0d_path(&base.campaign.target.circuit_path);
                base.campaign.target.circuit_path = PathBuf::from(rewritten_target);
            }
            rewritten
        };

        // Serialize with header comment
        let header = format!(
            "# Auto-generated by Opus Analyzer\n\
             # Circuit: {}\n\
             # Zero-day hints: {}\n\
             # Generated: {}\n\n",
            display_path,
            self.zero_day_hints.len(),
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        );

        let yaml = serde_yaml::to_string(&config)?;
        std::fs::write(&path, format!("{}{}", header, yaml))?;

        Ok(path)
    }
}

fn rewrite_zk0d_path(path: &Path) -> String {
    let path_str = path.to_string_lossy();
    let env_root = match std::env::var("ZK0D_BASE") {
        Ok(v) => Some(v),
        Err(std::env::VarError::NotPresent) => None,
        Err(e) => panic!("Invalid ZK0D_BASE value: {}", e),
    };
    let root = match env_root.as_deref() {
        Some(v) => v,
        None => DEFAULT_ZK0D_BASE,
    };
    let root = root.trim_end_matches(std::path::MAIN_SEPARATOR);

    if let Some(raw_suffix) = path_str.strip_prefix(root) {
        let placeholder = "${ZK0D_BASE}".to_string();
        let suffix = raw_suffix.trim_start_matches(std::path::MAIN_SEPARATOR);
        if suffix.is_empty() {
            placeholder
        } else {
            format!("{}/{}", placeholder, suffix)
        }
    } else {
        path_str.to_string()
    }
}

fn rewrite_path_with_placeholder(path: &Path, root: &Path, placeholder: &str) -> String {
    let path_str = path.to_string_lossy();
    let root_string = root.to_string_lossy().to_string();
    let root_str = root_string.trim_end_matches(std::path::MAIN_SEPARATOR);

    if let Some(raw_suffix) = path_str.strip_prefix(root_str) {
        let suffix = raw_suffix.trim_start_matches(std::path::MAIN_SEPARATOR);
        if suffix.is_empty() {
            placeholder.to_string()
        } else {
            let prefix = placeholder.trim_end_matches('/');
            format!("{}/{}", prefix, suffix)
        }
    } else {
        path_str.to_string()
    }
}

// Zero-day detection traits

trait ZeroDayDetector: Send + Sync {
    fn detect(
        &self,
        source: &str,
        framework: Framework,
        patterns: &[DetectedPattern],
    ) -> Vec<ZeroDayHint>;
}

struct MissingConstraintDetector;

impl ZeroDayDetector for MissingConstraintDetector {
    fn detect(
        &self,
        source: &str,
        framework: Framework,
        _patterns: &[DetectedPattern],
    ) -> Vec<ZeroDayHint> {
        let mut hints = Vec::new();

        if framework == Framework::Circom {
            // Check for signals that are assigned but not constrained
            let signal_assignments: HashSet<&str> = source
                .lines()
                .filter_map(|l| {
                    if l.contains("<--") && !l.contains("<==") {
                        Some(l.trim())
                    } else {
                        None
                    }
                })
                .collect();

            if !signal_assignments.is_empty() {
                hints.push(ZeroDayHint {
                    category: ZeroDayCategory::MissingConstraint,
                    confidence: 0.7,
                    description: format!(
                        "Found {} signal assignments without constraints (<-- instead of <==)",
                        signal_assignments.len()
                    ),
                    locations: vec![],
                    mutation_focus: Some("assigned_but_unconstrained".to_string()),
                });
            }
        }

        hints
    }
}

struct RangeCheckDetector;

impl ZeroDayDetector for RangeCheckDetector {
    fn detect(
        &self,
        source: &str,
        _framework: Framework,
        _patterns: &[DetectedPattern],
    ) -> Vec<ZeroDayHint> {
        let mut hints = Vec::new();

        // Check for Num2Bits without proper range validation
        if source.contains("Num2Bits") && !source.contains("LessThan") && !source.contains("assert")
        {
            hints.push(ZeroDayHint {
                category: ZeroDayCategory::IncorrectRangeCheck,
                confidence: 0.5,
                description: "Num2Bits used without explicit range validation".to_string(),
                locations: vec![],
                mutation_focus: Some("bit_decomposition".to_string()),
            });
        }

        hints
    }
}

struct HashMisuseDetector;

impl ZeroDayDetector for HashMisuseDetector {
    fn detect(
        &self,
        source: &str,
        _framework: Framework,
        patterns: &[DetectedPattern],
    ) -> Vec<ZeroDayHint> {
        let mut hints = Vec::new();

        let has_hash = patterns
            .iter()
            .any(|p| matches!(p.pattern_type, PatternType::HashFunction(_)));

        if has_hash {
            // Check for potential domain separation issues
            if !source.contains("domain") && !source.contains("tag") && !source.contains("prefix") {
                hints.push(ZeroDayHint {
                    category: ZeroDayCategory::HashMisuse,
                    confidence: 0.4,
                    description: "Hash function without domain separation".to_string(),
                    locations: vec![],
                    mutation_focus: Some("hash_inputs".to_string()),
                });
            }
        }

        hints
    }
}

struct SignatureMalleabilityDetector;

impl ZeroDayDetector for SignatureMalleabilityDetector {
    fn detect(
        &self,
        source: &str,
        _framework: Framework,
        patterns: &[DetectedPattern],
    ) -> Vec<ZeroDayHint> {
        let mut hints = Vec::new();

        let has_signature = patterns
            .iter()
            .any(|p| p.pattern_type == PatternType::Signature);

        if has_signature {
            // Check for s-value normalization
            if !source.to_lowercase().contains("normalize") && !source.contains("s < order/2") {
                hints.push(ZeroDayHint {
                    category: ZeroDayCategory::SignatureMalleability,
                    confidence: 0.6,
                    description: "Signature without s-value normalization (potential malleability)"
                        .to_string(),
                    locations: vec![],
                    mutation_focus: Some("signature_s".to_string()),
                });
            }
        }

        hints
    }
}

struct NullifierReuseDetector;

impl ZeroDayDetector for NullifierReuseDetector {
    fn detect(
        &self,
        source: &str,
        _framework: Framework,
        patterns: &[DetectedPattern],
    ) -> Vec<ZeroDayHint> {
        let mut hints = Vec::new();

        let has_nullifier = patterns
            .iter()
            .any(|p| p.pattern_type == PatternType::Nullifier);

        if has_nullifier {
            // Check if nullifier includes external entropy
            if !source.contains("random")
                && !source.contains("nonce")
                && !source.contains("external")
            {
                hints.push(ZeroDayHint {
                    category: ZeroDayCategory::NullifierReuse,
                    confidence: 0.4,
                    description: "Nullifier may not include sufficient entropy".to_string(),
                    locations: vec![],
                    mutation_focus: Some("nullifier_inputs".to_string()),
                });
            }
        }

        hints
    }
}

struct BitDecompositionDetector;

impl ZeroDayDetector for BitDecompositionDetector {
    fn detect(
        &self,
        source: &str,
        _framework: Framework,
        _patterns: &[DetectedPattern],
    ) -> Vec<ZeroDayHint> {
        let mut hints = Vec::new();

        // Check for bit constraints
        if source.contains("Num2Bits") || source.contains("bits[") {
            // Verify binary constraints exist
            let has_binary_check = source.contains("* (1 - ")
                || source.contains("* (b - 1)")
                || source.contains("b * b === b");

            if !has_binary_check {
                hints.push(ZeroDayHint {
                    category: ZeroDayCategory::BitDecompositionBypass,
                    confidence: 0.6,
                    description: "Bit decomposition without explicit binary constraint".to_string(),
                    locations: vec![],
                    mutation_focus: Some("bit_values".to_string()),
                });
            }
        }

        hints
    }
}

struct ArithmeticOverflowDetector;

impl ZeroDayDetector for ArithmeticOverflowDetector {
    fn detect(
        &self,
        source: &str,
        _framework: Framework,
        _patterns: &[DetectedPattern],
    ) -> Vec<ZeroDayHint> {
        let mut hints = Vec::new();

        // Check for multiplication without range check
        let mul_count = source.matches(" * ").count();
        let range_check_count =
            source.matches("LessThan").count() + source.matches("range").count();

        if mul_count > 5 && range_check_count == 0 {
            hints.push(ZeroDayHint {
                category: ZeroDayCategory::ArithmeticOverflow,
                confidence: 0.4,
                description: format!(
                    "Multiple multiplications ({}) without range checks",
                    mul_count
                ),
                locations: vec![],
                mutation_focus: Some("large_values".to_string()),
            });
        }

        hints
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opus_analyzer_creation() {
        let analyzer = OpusAnalyzer::new();
        assert!(!analyzer.zero_day_detectors.is_empty());
    }

    #[test]
    fn test_circuit_analysis() {
        let source = r#"
            pragma circom 2.0.0;
            
            template MerkleProof(levels) {
                signal input leaf;
                signal input pathElements[levels];
                signal input pathIndices[levels];
                signal output root;
                
                component hasher = Poseidon(2);
            }
            
            component main = MerkleProof(20);
        "#;

        let analyzer = OpusAnalyzer::new();
        let temp = tempfile::NamedTempFile::with_suffix(".circom").unwrap();
        std::fs::write(temp.path(), source).unwrap();

        let result = analyzer.analyze_circuit(temp.path()).unwrap();

        assert_eq!(result.framework, Framework::Circom);
        assert!(!result.patterns.is_empty());
        assert!(!result.inputs.is_empty());
    }

    #[test]
    fn test_missing_constraint_detection() {
        let source = r#"
            signal out;
            out <-- in * 2;  // Assignment without constraint!
        "#;

        let detector = MissingConstraintDetector;
        let hints = detector.detect(source, Framework::Circom, &[]);

        assert!(!hints.is_empty());
        assert_eq!(hints[0].category, ZeroDayCategory::MissingConstraint);
    }
}
