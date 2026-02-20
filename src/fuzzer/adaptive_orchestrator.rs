//! Adaptive Fuzzing Orchestrator
//!
//! Implements the endgame workflow for catching hard-to-detect zero-day vulnerabilities:
//!
//! 1. Load a target ZK project into the Opus analysis tool
//! 2. Opus analyzes the project and generates YAML configuration files
//! 3. YAML files feed the adaptive fuzzing engine
//! 4. Near-miss detection guides mutation toward vulnerabilities
//! 5. Adaptive scheduler reallocates budget based on effectiveness
//!
//! # Example
//!
//! ```rust,ignore
//! use zk_fuzzer::fuzzer::adaptive_orchestrator::AdaptiveOrchestrator;
//!
//! let orchestrator = AdaptiveOrchestrator::new();
//! let results = orchestrator.run_adaptive_campaign("/path/to/zk/project").await?;
//! ```

use crate::analysis::opus::{
    GeneratedConfig, OpusAnalyzer, OpusConfig, ZeroDayCategory, ZeroDayHint,
};
use crate::config::suggester::YamlSuggester;
use crate::fuzzer::adaptive_attack_scheduler::{
    AdaptiveScheduler, AdaptiveSchedulerConfig, AttackResults, YamlSuggestion,
};
use crate::fuzzer::near_miss::{NearMissConfig, NearMissDetector, RangeConstraint};
use crate::fuzzer::FuzzingEngine;
use crate::reporting::FuzzReport;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zk_core::{AttackType, Finding, Severity};

/// Configuration for adaptive orchestrator
#[derive(Debug, Clone)]
pub struct AdaptiveOrchestratorConfig {
    /// Opus analyzer configuration
    pub opus_config: OpusConfig,
    /// Adaptive scheduler configuration
    pub scheduler_config: AdaptiveSchedulerConfig,
    /// Near-miss detector configuration
    pub near_miss_config: NearMissConfig,
    /// Number of parallel workers
    pub workers: usize,
    /// Maximum total campaign duration
    pub max_duration: Duration,
    /// Minimum iterations per circuit
    pub min_iterations_per_circuit: usize,
    /// Whether to save intermediate configs
    pub save_intermediate_configs: bool,
    /// Output directory for reports
    pub output_dir: PathBuf,
    /// Whether to use adaptive budget reallocation
    pub adaptive_budget: bool,
    /// Zero-day hunt mode (more aggressive)
    pub zero_day_hunt_mode: bool,
}

impl Default for AdaptiveOrchestratorConfig {
    fn default() -> Self {
        Self {
            opus_config: OpusConfig::default(),
            scheduler_config: AdaptiveSchedulerConfig::default(),
            near_miss_config: NearMissConfig::default(),
            workers: num_cpus::get().max(1),
            max_duration: Duration::from_secs(3600), // 1 hour
            min_iterations_per_circuit: 10000,
            save_intermediate_configs: true,
            output_dir: PathBuf::from("./reports/adaptive"),
            adaptive_budget: true,
            zero_day_hunt_mode: true,
        }
    }
}

/// Results from an adaptive fuzzing campaign
#[derive(Debug, Clone)]
pub struct AdaptiveCampaignResults {
    /// Total findings across all circuits
    pub total_findings: Vec<Finding>,
    /// Findings grouped by circuit
    pub findings_by_circuit: HashMap<String, Vec<Finding>>,
    /// Zero-day hints that were confirmed as bugs
    pub confirmed_zero_days: Vec<ConfirmedZeroDay>,
    /// Zero-day hints that were not triggered
    pub unconfirmed_hints: Vec<ZeroDayHint>,
    /// Reports per circuit
    pub circuit_reports: HashMap<String, FuzzReport>,
    /// YAML suggestions generated
    pub yaml_suggestions: Vec<YamlSuggestion>,
    /// Adaptive scheduler statistics
    pub scheduler_stats:
        HashMap<String, crate::fuzzer::adaptive_attack_scheduler::AdaptiveSchedulerStats>,
    /// Total campaign duration
    pub duration: Duration,
    /// Circuits analyzed
    pub circuits_analyzed: usize,
    /// Generated configs
    pub generated_configs: Vec<PathBuf>,
}

/// A confirmed zero-day vulnerability
#[derive(Debug, Clone)]
pub struct ConfirmedZeroDay {
    /// Original hint
    pub hint: ZeroDayHint,
    /// The finding that confirmed it
    pub finding: Finding,
    /// Circuit where it was found
    pub circuit: String,
    /// Time to discovery
    pub time_to_discovery: Duration,
}

/// Adaptive fuzzing orchestrator
pub struct AdaptiveOrchestrator {
    /// Configuration
    config: AdaptiveOrchestratorConfig,
    /// Opus analyzer
    opus: OpusAnalyzer,
    /// YAML suggester
    suggester: YamlSuggester,
    /// Campaign start time
    start_time: Option<Instant>,
}

impl Default for AdaptiveOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveOrchestrator {
    /// Create a new orchestrator with default configuration
    pub fn new() -> Self {
        Self::with_config(AdaptiveOrchestratorConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: AdaptiveOrchestratorConfig) -> Self {
        let opus = OpusAnalyzer::with_config(config.opus_config.clone());
        let suggester = YamlSuggester::new();

        Self {
            config,
            opus,
            suggester,
            start_time: None,
        }
    }

    /// Run an adaptive fuzzing campaign on a ZK project
    pub async fn run_adaptive_campaign(
        &mut self,
        project_path: impl AsRef<Path>,
    ) -> anyhow::Result<AdaptiveCampaignResults> {
        let project_path = project_path.as_ref();
        self.start_time = Some(Instant::now());

        tracing::info!(
            "Starting adaptive fuzzing campaign for: {}",
            project_path.display()
        );
        tracing::info!("Max duration: {:?}", self.config.max_duration);
        tracing::info!("Workers: {}", self.config.workers);
        tracing::info!("Zero-day hunt mode: {}", self.config.zero_day_hunt_mode);

        // Phase 1: Analyze project with Opus
        tracing::info!("Phase 1: Analyzing project with Opus...");
        let generated_configs = self.opus.analyze_project(project_path)?;
        tracing::info!("Generated {} configurations", generated_configs.len());

        // Save generated configs if configured
        let config_paths = if self.config.save_intermediate_configs {
            self.save_generated_configs(&generated_configs)?
        } else {
            vec![]
        };

        // Collect all zero-day hints for tracking
        let all_hints: Vec<(String, ZeroDayHint)> = generated_configs
            .iter()
            .flat_map(|c| {
                c.zero_day_hints
                    .iter()
                    .map(|h| (c.circuit_name.clone(), h.clone()))
            })
            .collect();

        tracing::info!("Total zero-day hints to investigate: {}", all_hints.len());

        // Phase 2: Run adaptive fuzzing on each circuit
        tracing::info!("Phase 2: Running adaptive fuzzing...");
        let mut results = AdaptiveCampaignResults {
            total_findings: Vec::new(),
            findings_by_circuit: HashMap::new(),
            confirmed_zero_days: Vec::new(),
            unconfirmed_hints: Vec::new(),
            circuit_reports: HashMap::new(),
            yaml_suggestions: Vec::new(),
            scheduler_stats: HashMap::new(),
            duration: Duration::from_secs(0),
            circuits_analyzed: 0,
            generated_configs: config_paths,
        };

        // Calculate budget per circuit
        let circuits_count = generated_configs.len();
        let budget_per_circuit = if circuits_count > 0 {
            self.config.max_duration / circuits_count as u32
        } else {
            self.config.max_duration
        };

        for gen_config in &generated_configs {
            if self.should_stop() {
                tracing::info!("Campaign timeout reached, stopping...");
                break;
            }

            tracing::info!("Fuzzing circuit: {}", gen_config.circuit_name);
            tracing::info!(
                "Zero-day hints for this circuit: {}",
                gen_config.zero_day_hints.len()
            );

            match self.fuzz_circuit(gen_config, budget_per_circuit).await {
                Ok((report, scheduler)) => {
                    // Track findings
                    results
                        .findings_by_circuit
                        .insert(gen_config.circuit_name.clone(), report.findings.clone());
                    results.total_findings.extend(report.findings.clone());

                    // Check for confirmed zero-days
                    let confirmed = self.check_confirmed_zero_days(
                        &gen_config.zero_day_hints,
                        &report.findings,
                        &gen_config.circuit_name,
                    );
                    results.confirmed_zero_days.extend(confirmed);

                    // Get YAML suggestions
                    let suggestions = self
                        .suggester
                        .generate_suggestions(&report, Some(&scheduler));
                    results.yaml_suggestions.extend(suggestions);

                    // Store stats
                    results
                        .scheduler_stats
                        .insert(gen_config.circuit_name.clone(), scheduler.stats());

                    results
                        .circuit_reports
                        .insert(gen_config.circuit_name.clone(), report);
                    results.circuits_analyzed += 1;
                }
                Err(e) => {
                    tracing::error!("Failed to fuzz {}: {}", gen_config.circuit_name, e);
                }
            }
        }

        // Determine unconfirmed hints while preserving one-to-one hint confirmations.
        let mut confirmed_hint_counts: HashMap<(String, String), usize> = HashMap::new();
        for confirmed in &results.confirmed_zero_days {
            let key = (
                confirmed.circuit.clone(),
                Self::hint_identity_key(&confirmed.hint),
            );
            *confirmed_hint_counts.entry(key).or_insert(0) += 1;
        }

        for (circuit, hint) in all_hints {
            let key = (circuit.clone(), Self::hint_identity_key(&hint));
            match confirmed_hint_counts.get_mut(&key) {
                Some(count) if *count > 0 => *count -= 1,
                _ => results.unconfirmed_hints.push(hint),
            }
        }

        results.duration = self.start_time.map(|s| s.elapsed()).unwrap_or_default();

        // Log summary
        self.log_summary(&results);

        Ok(results)
    }

    /// Run a single circuit fuzzing with adaptive scheduling
    async fn fuzz_circuit(
        &self,
        gen_config: &GeneratedConfig,
        budget: Duration,
    ) -> anyhow::Result<(FuzzReport, AdaptiveScheduler)> {
        // Convert v2 config to base config
        let base_config = gen_config
            .config
            .base
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Generated config has no base configuration"))?;

        // Initialize adaptive scheduler
        let mut scheduler = AdaptiveScheduler::with_config(self.config.scheduler_config.clone());

        // Get attack types from config
        let attack_types: Vec<AttackType> = base_config
            .attacks
            .iter()
            .map(|a| a.attack_type.clone())
            .collect();

        scheduler.initialize(&attack_types);

        // Initialize near-miss detector with zero-day hints
        let mut near_miss_detector =
            NearMissDetector::new().with_config(self.config.near_miss_config.clone());

        // Add range constraints from zero-day hints
        for (idx, hint) in gen_config.zero_day_hints.iter().enumerate() {
            if matches!(
                hint.category,
                ZeroDayCategory::IncorrectRangeCheck | ZeroDayCategory::ArithmeticOverflow
            ) {
                near_miss_detector = near_miss_detector.with_range_constraint(RangeConstraint {
                    wire_index: idx,
                    min_value: None,
                    max_value: None,
                    bit_length: Some(64), // Default to 64-bit check
                });
            }
        }

        // Run with adaptive scheduling
        let start = Instant::now();
        let mut accumulated_report: Option<FuzzReport> = None;
        let mut early_terminated = false;

        while start.elapsed() < budget {
            let remaining = budget.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }

            let phase_budget = remaining.min(Duration::from_secs(60));

            // Non-adaptive mode: run exactly one full attack sweep.
            if !self.config.adaptive_budget {
                let phase_config = Self::with_phase_timeout(base_config.clone(), phase_budget);
                let mut phase_engine = FuzzingEngine::new(phase_config, None, self.config.workers)?;
                let phase_report = phase_engine.run(None).await?;

                for attack in &base_config.attacks {
                    let findings: Vec<Finding> = phase_report
                        .findings
                        .iter()
                        .filter(|f| f.attack_type == attack.attack_type)
                        .cloned()
                        .collect();

                    let attack_results = AttackResults {
                        attack_type: attack.attack_type.clone(),
                        new_coverage: phase_report.statistics.coverage_percentage as usize,
                        findings,
                        near_misses: vec![], // Would be populated from near-miss detector
                        iterations: phase_report.statistics.total_executions as usize,
                        duration: Duration::from_secs(phase_report.duration_seconds),
                    };
                    scheduler.update_scores(&attack_results);
                }

                Self::merge_phase_report(&mut accumulated_report, phase_report);
                break;
            }

            let allocations = scheduler.allocate_budget(phase_budget);
            if allocations.is_empty() {
                break;
            }
            let phase_plan = Self::build_attack_phase_plan(&base_config.attacks, &allocations);
            if phase_plan.is_empty() {
                break;
            }

            let mut executed_any = false;
            for (attack, attack_budget) in phase_plan {
                let remaining_before_attack = budget.saturating_sub(start.elapsed());
                if remaining_before_attack.is_zero() {
                    break;
                }
                let effective_budget = attack_budget.min(remaining_before_attack);
                if effective_budget.is_zero() {
                    continue;
                }
                let phase_config = Self::with_phase_timeout(
                    Self::single_attack_config(base_config.clone(), attack.clone()),
                    effective_budget,
                );
                let mut phase_engine = FuzzingEngine::new(phase_config, None, self.config.workers)?;
                let phase_report = phase_engine.run(None).await?;
                executed_any = true;

                let findings: Vec<Finding> = phase_report
                    .findings
                    .iter()
                    .filter(|f| f.attack_type == attack.attack_type)
                    .cloned()
                    .collect();
                let attack_results = AttackResults {
                    attack_type: attack.attack_type,
                    new_coverage: phase_report.statistics.coverage_percentage as usize,
                    findings,
                    near_misses: vec![], // Would be populated from near-miss detector
                    iterations: phase_report.statistics.total_executions as usize,
                    duration: Duration::from_secs(phase_report.duration_seconds),
                };
                scheduler.update_scores(&attack_results);

                Self::merge_phase_report(&mut accumulated_report, phase_report);

                if let Some(ref report) = accumulated_report {
                    let critical_count = Self::critical_findings_count(report);
                    if critical_count >= 3 {
                        tracing::info!(
                            "Found {} critical findings, early terminating",
                            critical_count
                        );
                        early_terminated = true;
                        break;
                    }
                }
            }

            if early_terminated {
                break;
            }
            if !executed_any {
                break;
            }
        }

        let report = match accumulated_report {
            Some(value) => value,
            None => FuzzReport::new(
                gen_config.circuit_name.clone(),
                vec![],
                zk_core::CoverageMap::default(),
                base_config.reporting.clone(),
            ),
        };

        Ok((report, scheduler))
    }

    fn single_attack_config(
        mut base_config: crate::config::FuzzConfig,
        attack: crate::config::Attack,
    ) -> crate::config::FuzzConfig {
        base_config.attacks = vec![attack];
        base_config
    }

    fn with_phase_timeout(
        mut config: crate::config::FuzzConfig,
        timeout: Duration,
    ) -> crate::config::FuzzConfig {
        let timeout_secs = timeout.as_secs().max(1);
        config.campaign.parameters.additional.insert(
            "fuzzing_timeout_seconds".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(timeout_secs)),
        );
        config
    }

    fn build_attack_phase_plan(
        attacks: &[crate::config::Attack],
        allocations: &HashMap<AttackType, Duration>,
    ) -> Vec<(crate::config::Attack, Duration)> {
        let mut planned: Vec<(usize, crate::config::Attack, Duration)> = attacks
            .iter()
            .cloned()
            .enumerate()
            .filter_map(|(idx, attack)| {
                let allocated = allocations
                    .get(&attack.attack_type)
                    .copied()
                    .unwrap_or_default();
                if allocated.is_zero() {
                    None
                } else {
                    Some((idx, attack, allocated))
                }
            })
            .collect();

        // Prefer higher-budget attacks first while preserving source order for ties.
        planned.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
        planned
            .into_iter()
            .map(|(_, attack, budget)| (attack, budget))
            .collect()
    }

    fn merge_phase_report(accumulated_report: &mut Option<FuzzReport>, phase_report: FuzzReport) {
        match accumulated_report {
            Some(acc) => {
                acc.findings.extend(phase_report.findings);
                acc.duration_seconds += phase_report.duration_seconds;
                acc.statistics.total_executions += phase_report.statistics.total_executions;
                acc.statistics.coverage_percentage = acc
                    .statistics
                    .coverage_percentage
                    .max(phase_report.statistics.coverage_percentage);
            }
            None => {
                *accumulated_report = Some(phase_report);
            }
        }
    }

    fn critical_findings_count(report: &FuzzReport) -> usize {
        report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count()
    }

    /// Check if any zero-day hints were confirmed by findings
    fn check_confirmed_zero_days(
        &self,
        hints: &[ZeroDayHint],
        findings: &[Finding],
        circuit_name: &str,
    ) -> Vec<ConfirmedZeroDay> {
        let mut confirmed = Vec::new();
        let mut used_findings = HashSet::new();

        for hint in hints {
            let mut best_match: Option<(usize, usize)> = None;
            for (idx, finding) in findings.iter().enumerate() {
                if used_findings.contains(&idx) {
                    continue;
                }
                let score = Self::hint_finding_match_score(hint, finding);
                if score < 2 {
                    continue;
                }
                match best_match {
                    Some((_, best_score)) if score <= best_score => {}
                    _ => best_match = Some((idx, score)),
                }
            }

            if let Some((finding_idx, _score)) = best_match {
                used_findings.insert(finding_idx);
                let finding = findings[finding_idx].clone();
                confirmed.push(ConfirmedZeroDay {
                    hint: hint.clone(),
                    finding,
                    circuit: circuit_name.to_string(),
                    time_to_discovery: self.start_time.map(|s| s.elapsed()).unwrap_or_default(),
                });
            }
        }

        confirmed
    }

    fn hint_finding_match_score(hint: &ZeroDayHint, finding: &Finding) -> usize {
        if !Self::hint_category_matches_attack(&hint.category, &finding.attack_type) {
            return 0;
        }

        let hint_text = format!(
            "{} {}",
            hint.description,
            hint.mutation_focus.as_deref().unwrap_or_default()
        );
        let finding_text = format!(
            "{} {}",
            finding.description,
            finding.location.as_deref().unwrap_or_default()
        )
        .to_ascii_lowercase();

        let hint_tokens = Self::content_tokens(&hint_text);
        let finding_tokens = Self::content_tokens(&finding_text);
        let token_overlap = Self::fuzzy_overlap_count(&hint_tokens, &finding_tokens);
        let keyword_hits = Self::category_keywords(&hint.category)
            .iter()
            .filter(|kw| finding_text.contains(**kw))
            .count();
        let location_match = Self::hint_location_matches_finding(hint, &finding_text);

        let mut score = token_overlap.saturating_mul(2);
        score += keyword_hits.min(2);
        if location_match {
            score += 4;
        }
        score
    }

    fn hint_category_matches_attack(category: &ZeroDayCategory, attack_type: &AttackType) -> bool {
        matches!(
            (category, attack_type),
            (
                ZeroDayCategory::MissingConstraint,
                AttackType::Underconstrained
            ) | (
                ZeroDayCategory::IncorrectRangeCheck,
                AttackType::ArithmeticOverflow
            ) | (
                ZeroDayCategory::SignatureMalleability,
                AttackType::Soundness
            ) | (ZeroDayCategory::NullifierReuse, AttackType::Collision)
                | (ZeroDayCategory::HashMisuse, AttackType::Collision)
                | (
                    ZeroDayCategory::BitDecompositionBypass,
                    AttackType::ArithmeticOverflow
                )
                | (
                    ZeroDayCategory::ArithmeticOverflow,
                    AttackType::ArithmeticOverflow
                )
        )
    }

    fn category_keywords(category: &ZeroDayCategory) -> &'static [&'static str] {
        match category {
            ZeroDayCategory::MissingConstraint => {
                &["constraint", "underconstrain", "signal", "wire", "dof"]
            }
            ZeroDayCategory::IncorrectRangeCheck => {
                &["range", "bound", "num2bits", "overflow", "underflow"]
            }
            ZeroDayCategory::SignatureMalleability => {
                &["signature", "malleab", "forge", "proof", "verifier"]
            }
            ZeroDayCategory::NullifierReuse => &["nullif", "reuse", "collision", "uniq", "nonce"],
            ZeroDayCategory::HashMisuse => &["hash", "domain", "prefix", "tag", "collision"],
            ZeroDayCategory::BitDecompositionBypass => {
                &["bit", "decompos", "binary", "num2bits", "range"]
            }
            ZeroDayCategory::ArithmeticOverflow => {
                &["overflow", "underflow", "arithmetic", "range", "bound"]
            }
            _ => &[],
        }
    }

    fn hint_location_matches_finding(hint: &ZeroDayHint, finding_text: &str) -> bool {
        if hint.locations.is_empty() {
            return false;
        }
        let location_numbers = Self::extract_numbers(finding_text);
        hint.locations
            .iter()
            .any(|loc| location_numbers.contains(loc))
    }

    fn extract_numbers(text: &str) -> HashSet<usize> {
        let mut numbers = HashSet::new();
        let mut current = String::new();
        for ch in text.chars() {
            if ch.is_ascii_digit() {
                current.push(ch);
            } else if !current.is_empty() {
                if let Ok(value) = current.parse::<usize>() {
                    numbers.insert(value);
                }
                current.clear();
            }
        }
        if !current.is_empty() {
            if let Ok(value) = current.parse::<usize>() {
                numbers.insert(value);
            }
        }
        numbers
    }

    fn hint_identity_key(hint: &ZeroDayHint) -> String {
        let mut locations = hint.locations.clone();
        locations.sort_unstable();
        format!(
            "{:?}|{}|{}|{}",
            hint.category,
            hint.description.to_ascii_lowercase(),
            locations
                .iter()
                .map(|loc| loc.to_string())
                .collect::<Vec<_>>()
                .join(","),
            hint.mutation_focus
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
        )
    }

    fn content_tokens(text: &str) -> Vec<String> {
        text.split(|c: char| !c.is_ascii_alphanumeric())
            .filter_map(Self::normalize_token)
            .collect()
    }

    fn normalize_token(token: &str) -> Option<String> {
        if token.is_empty() {
            return None;
        }
        let mut value = token.to_ascii_lowercase();
        if value.len() < 4 || Self::is_common_stop_word(&value) {
            return None;
        }

        if value.ends_with("ies") && value.len() > 4 {
            value.truncate(value.len() - 3);
            value.push('y');
        } else {
            for suffix in ["ing", "ers", "er", "ed", "es", "s"] {
                if value.ends_with(suffix) && value.len() > suffix.len() + 2 {
                    value.truncate(value.len() - suffix.len());
                    break;
                }
            }
        }

        if value.len() < 4 || Self::is_common_stop_word(&value) {
            None
        } else {
            Some(value)
        }
    }

    fn is_common_stop_word(token: &str) -> bool {
        matches!(
            token,
            "about"
                | "after"
                | "before"
                | "could"
                | "found"
                | "from"
                | "have"
                | "into"
                | "likely"
                | "may"
                | "might"
                | "this"
                | "that"
                | "without"
                | "with"
        )
    }

    fn fuzzy_overlap_count(a_tokens: &[String], b_tokens: &[String]) -> usize {
        let mut matched = 0usize;
        let mut used_b = HashSet::new();

        for a in a_tokens {
            if let Some((idx, _)) = b_tokens
                .iter()
                .enumerate()
                .find(|(idx, b)| !used_b.contains(idx) && Self::tokens_roughly_match(a, b.as_str()))
            {
                used_b.insert(idx);
                matched += 1;
            }
        }

        matched
    }

    fn tokens_roughly_match(left: &str, right: &str) -> bool {
        if left == right || left.starts_with(right) || right.starts_with(left) {
            return true;
        }
        let prefix = left
            .chars()
            .zip(right.chars())
            .take_while(|(a, b)| a == b)
            .count();
        prefix >= 5
    }

    /// Save generated configs to disk
    fn save_generated_configs(&self, configs: &[GeneratedConfig]) -> anyhow::Result<Vec<PathBuf>> {
        let output_dir = self.config.output_dir.join("configs");
        std::fs::create_dir_all(&output_dir)?;

        let mut paths = Vec::new();

        for config in configs {
            let path = config.save(&output_dir)?;
            tracing::info!("Saved config: {}", path.display());
            paths.push(path);
        }

        Ok(paths)
    }

    /// Check if campaign should stop (timeout)
    fn should_stop(&self) -> bool {
        self.start_time
            .map(|s| s.elapsed() >= self.config.max_duration)
            .unwrap_or_default()
    }

    /// Log campaign summary
    fn log_summary(&self, results: &AdaptiveCampaignResults) {
        tracing::info!("=== Adaptive Campaign Summary ===");
        tracing::info!("Duration: {:?}", results.duration);
        tracing::info!("Circuits analyzed: {}", results.circuits_analyzed);
        tracing::info!("Total findings: {}", results.total_findings.len());
        tracing::info!("Confirmed zero-days: {}", results.confirmed_zero_days.len());
        tracing::info!("Unconfirmed hints: {}", results.unconfirmed_hints.len());
        tracing::info!("YAML suggestions: {}", results.yaml_suggestions.len());

        // Log critical findings
        let critical = results
            .total_findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = results
            .total_findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();

        tracing::info!("Critical findings: {}", critical);
        tracing::info!("High findings: {}", high);

        // Log confirmed zero-days
        if !results.confirmed_zero_days.is_empty() {
            tracing::info!("--- Confirmed Zero-Days ---");
            for zd in &results.confirmed_zero_days {
                tracing::info!(
                    "  [{:?}] in {}: {}",
                    zd.hint.category,
                    zd.circuit,
                    zd.hint.description
                );
            }
        }
    }
}

/// Builder for AdaptiveOrchestrator
pub struct AdaptiveOrchestratorBuilder {
    config: AdaptiveOrchestratorConfig,
}

impl Default for AdaptiveOrchestratorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveOrchestratorBuilder {
    pub fn new() -> Self {
        Self {
            config: AdaptiveOrchestratorConfig::default(),
        }
    }

    pub fn workers(mut self, workers: usize) -> Self {
        self.config.workers = workers;
        self
    }

    pub fn max_duration(mut self, duration: Duration) -> Self {
        self.config.max_duration = duration;
        self
    }

    pub fn output_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.config.output_dir = dir.into();
        self
    }

    pub fn zero_day_hunt_mode(mut self, enabled: bool) -> Self {
        self.config.zero_day_hunt_mode = enabled;
        self
    }

    pub fn adaptive_budget(mut self, enabled: bool) -> Self {
        self.config.adaptive_budget = enabled;
        self
    }

    pub fn opus_config(mut self, config: OpusConfig) -> Self {
        self.config.opus_config = config;
        self
    }

    pub fn build(self) -> AdaptiveOrchestrator {
        AdaptiveOrchestrator::with_config(self.config)
    }
}

/// Run an adaptive campaign from command line
pub async fn run_from_cli(
    project_path: &Path,
    workers: usize,
    max_duration_secs: u64,
    output_dir: &Path,
) -> anyhow::Result<AdaptiveCampaignResults> {
    let mut orchestrator = AdaptiveOrchestratorBuilder::new()
        .workers(workers)
        .max_duration(Duration::from_secs(max_duration_secs))
        .output_dir(output_dir)
        .zero_day_hunt_mode(true)
        .build();

    orchestrator.run_adaptive_campaign(project_path).await
}

#[cfg(test)]
#[path = "adaptive_orchestrator_tests.rs"]
mod tests;
