//! 0-Day Readiness Validation (Phase 4C)
//!
//! This module validates campaign configurations for professional 0-day discovery.
//! It checks that all necessary components are properly configured and warns about
//! potential misconfigurations that could lead to false findings or missed bugs.

use crate::config::FuzzConfig;
use std::fmt;

/// Readiness warning severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReadinessLevel {
    /// Campaign cannot produce valid 0-day findings
    Critical,
    /// Campaign may produce unreliable findings
    High,
    /// Campaign has suboptimal configuration
    Medium,
    /// Minor improvement suggestion
    Low,
    /// Informational note
    Info,
}

impl fmt::Display for ReadinessLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadinessLevel::Critical => write!(f, "CRITICAL"),
            ReadinessLevel::High => write!(f, "HIGH"),
            ReadinessLevel::Medium => write!(f, "MEDIUM"),
            ReadinessLevel::Low => write!(f, "LOW"),
            ReadinessLevel::Info => write!(f, "INFO"),
        }
    }
}

/// A readiness warning with context
#[derive(Debug, Clone)]
pub struct ReadinessWarning {
    pub level: ReadinessLevel,
    pub category: String,
    pub message: String,
    pub fix_hint: Option<String>,
}

impl ReadinessWarning {
    pub fn critical(category: &str, message: &str) -> Self {
        Self {
            level: ReadinessLevel::Critical,
            category: category.to_string(),
            message: message.to_string(),
            fix_hint: None,
        }
    }

    pub fn high(category: &str, message: &str) -> Self {
        Self {
            level: ReadinessLevel::High,
            category: category.to_string(),
            message: message.to_string(),
            fix_hint: None,
        }
    }

    pub fn medium(category: &str, message: &str) -> Self {
        Self {
            level: ReadinessLevel::Medium,
            category: category.to_string(),
            message: message.to_string(),
            fix_hint: None,
        }
    }

    pub fn low(category: &str, message: &str) -> Self {
        Self {
            level: ReadinessLevel::Low,
            category: category.to_string(),
            message: message.to_string(),
            fix_hint: None,
        }
    }

    pub fn info(category: &str, message: &str) -> Self {
        Self {
            level: ReadinessLevel::Info,
            category: category.to_string(),
            message: message.to_string(),
            fix_hint: None,
        }
    }

    pub fn with_fix(mut self, fix: &str) -> Self {
        self.fix_hint = Some(fix.to_string());
        self
    }
}

impl fmt::Display for ReadinessWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.level, self.category, self.message)?;
        if let Some(fix) = &self.fix_hint {
            write!(f, " (Fix: {})", fix)?;
        }
        Ok(())
    }
}

/// 0-Day readiness check result
#[derive(Debug, Clone)]
pub struct ReadinessReport {
    pub warnings: Vec<ReadinessWarning>,
    pub score: f64,
    pub ready_for_evidence: bool,
}

impl ReadinessReport {
    /// Compute the readiness score (0.0 - 10.0)
    pub fn compute_score(warnings: &[ReadinessWarning]) -> f64 {
        let mut score: f64 = 10.0;

        for warning in warnings {
            match warning.level {
                ReadinessLevel::Critical => score -= 3.0,
                ReadinessLevel::High => score -= 2.0,
                ReadinessLevel::Medium => score -= 1.0,
                ReadinessLevel::Low => score -= 0.5,
                ReadinessLevel::Info => score -= 0.1,
            }
        }

        if score < 0.0 {
            0.0
        } else {
            score
        }
    }

    /// Check if the config is ready for evidence mode
    pub fn is_evidence_ready(warnings: &[ReadinessWarning]) -> bool {
        !warnings.iter().any(|w| w.level == ReadinessLevel::Critical)
    }

    /// Format the report for display
    pub fn format(&self) -> String {
        let mut output = String::new();

        output.push_str("\n╔══════════════════════════════════════════════════════════════╗\n");
        output.push_str("║                   0-DAY READINESS REPORT                     ║\n");
        output.push_str("╠══════════════════════════════════════════════════════════════╣\n");
        output.push_str(&format!(
            "║  Score: {:.1}/10.0  {}                              ║\n",
            self.score,
            if self.ready_for_evidence {
                "✅"
            } else {
                "❌"
            }
        ));
        output.push_str("╚══════════════════════════════════════════════════════════════╝\n");

        if self.warnings.is_empty() {
            output.push_str("\n  ✅ No issues detected. Campaign is 0-day ready!\n");
        } else {
            let critical: Vec<_> = self
                .warnings
                .iter()
                .filter(|w| w.level == ReadinessLevel::Critical)
                .collect();
            let high: Vec<_> = self
                .warnings
                .iter()
                .filter(|w| w.level == ReadinessLevel::High)
                .collect();
            let medium: Vec<_> = self
                .warnings
                .iter()
                .filter(|w| w.level == ReadinessLevel::Medium)
                .collect();
            let low: Vec<_> = self
                .warnings
                .iter()
                .filter(|w| matches!(w.level, ReadinessLevel::Low | ReadinessLevel::Info))
                .collect();

            if !critical.is_empty() {
                output.push_str("\n  🚨 CRITICAL ISSUES (must fix):\n");
                for w in &critical {
                    output.push_str(&format!("     • {}: {}\n", w.category, w.message));
                    if let Some(fix) = &w.fix_hint {
                        output.push_str(&format!("       Fix: {}\n", fix));
                    }
                }
            }

            if !high.is_empty() {
                output.push_str("\n  ⚠️  HIGH PRIORITY:\n");
                for w in &high {
                    output.push_str(&format!("     • {}: {}\n", w.category, w.message));
                    if let Some(fix) = &w.fix_hint {
                        output.push_str(&format!("       Fix: {}\n", fix));
                    }
                }
            }

            if !medium.is_empty() {
                output.push_str("\n  📋 MEDIUM PRIORITY:\n");
                for w in &medium {
                    output.push_str(&format!("     • {}: {}\n", w.category, w.message));
                }
            }

            if !low.is_empty() {
                output.push_str("\n  💡 SUGGESTIONS:\n");
                for w in &low {
                    output.push_str(&format!("     • {}: {}\n", w.category, w.message));
                }
            }
        }

        output
    }
}

/// Check a campaign configuration for 0-day readiness
pub fn check_0day_readiness(config: &FuzzConfig) -> ReadinessReport {
    let mut warnings = Vec::new();

    // 1. Check strict_backend
    let additional = &config.campaign.parameters.additional;
    let evidence_mode = additional
        .get("evidence_mode")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let engagement_strict = additional
        .get("engagement_strict")
        .and_then(|v| v.as_bool())
        .unwrap_or(evidence_mode);
    let strict_backend = additional
        .get("strict_backend")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !strict_backend {
        warnings.push(
            ReadinessWarning::high(
                "Backend",
                "strict_backend is false - backend/tooling failures may be masked",
            )
            .with_fix("Set strict_backend: true in campaign.parameters.additional"),
        );
    }

    // 2. Check invariants
    let invariants = config.get_invariants();
    let has_chain_assertions = config
        .chains
        .iter()
        .any(|c| !c.assertions.is_empty());

    if invariants.is_empty() && !has_chain_assertions {
        warnings.push(
            ReadinessWarning::critical(
                "Invariants",
                "No invariants defined - cannot validate findings",
            )
            .with_fix("Add v2 invariants section with range/uniqueness/constraint invariants"),
        );
    } else {
        // Check invariant quality
        for inv in &invariants {
            if inv.relation.trim().is_empty() {
                warnings.push(ReadinessWarning::high(
                    "Invariants",
                    &format!("Invariant '{}' has empty relation", inv.name),
                ));
            }
        }
    }

    // If Mode 3 chains exist, they must have assertions; otherwise chain fuzzing cannot produce findings.
    if !config.chains.is_empty() && !has_chain_assertions {
        warnings.push(
            ReadinessWarning::critical(
                "Chains",
                "Chains are defined but no cross-step assertions are configured (Mode 3 would be silent)",
            )
            .with_fix("Add `assertions:` to each chain (or remove `chains:` and use v2 invariants)"),
        );
    }

    // 4. Check symbolic execution depth
    let symbolic_max_depth = additional
        .get("symbolic_max_depth")
        .and_then(|v| v.as_u64())
        .unwrap_or(200);

    if symbolic_max_depth < 50 {
        warnings.push(
            ReadinessWarning::medium(
                "Symbolic",
                &format!(
                    "symbolic_max_depth={} is too shallow for complex circuits",
                    symbolic_max_depth
                ),
            )
            .with_fix("Set symbolic_max_depth >= 100 for better coverage"),
        );
    }

    // 5. Check constraint-guided fuzzing
    let constraint_guided = additional
        .get("constraint_guided_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    if !constraint_guided {
        warnings.push(
            ReadinessWarning::medium(
                "Fuzzing",
                "constraint_guided_enabled is false - may miss constraint-specific bugs",
            )
            .with_fix("Set constraint_guided_enabled: true"),
        );
    }

    // 6. Check oracle validation
    let oracle_validation = additional
        .get("oracle_validation")
        .and_then(|v| v.as_bool())
        .unwrap_or(evidence_mode);

    if !oracle_validation {
        warnings.push(
            if engagement_strict {
                ReadinessWarning::critical(
                    "Oracles",
                    "oracle_validation is false - strict engagement requires validated findings",
                )
                .with_fix("Set oracle_validation: true")
            } else {
                ReadinessWarning::medium(
                    "Oracles",
                    "oracle_validation is false - findings may have higher false positive rate",
                )
                .with_fix("Set oracle_validation: true")
            },
        );
    }

    // 7. Check per-execution isolation
    let per_exec_isolation = additional.get_bool("per_exec_isolation").unwrap_or(false);
    let allow_no_isolation = additional
        .get_bool("evidence_allow_no_isolation")
        .unwrap_or(false);

    if !per_exec_isolation && !allow_no_isolation {
        warnings.push(
            ReadinessWarning::low(
                "Isolation",
                "per_exec_isolation is false - hangs may block the fuzzer",
            )
            .with_fix("Set per_exec_isolation: true for hang safety"),
        );
    }

    // 8. Check execution timeout
    let execution_timeout_ms = additional
        .get("execution_timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(30_000);

    if execution_timeout_ms < 1000 {
        warnings.push(ReadinessWarning::low(
            "Timeout",
            &format!(
                "execution_timeout_ms={} may be too short for complex circuits",
                execution_timeout_ms
            ),
        ));
    }

    // 9. Check attacks configuration (skip for chain-only campaigns)
    if !config.attacks.is_empty() {
        let has_soundness = config
            .attacks
            .iter()
            .any(|a| matches!(a.attack_type, crate::config::AttackType::Soundness));
        let has_underconstrained = config
            .attacks
            .iter()
            .any(|a| matches!(a.attack_type, crate::config::AttackType::Underconstrained));

        if engagement_strict {
            if !has_soundness {
                warnings.push(
                    ReadinessWarning::critical(
                        "Attacks",
                        "Missing required attack: soundness (strict engagement requires it)",
                    )
                    .with_fix("Add attack type: soundness"),
                );
            }
            if !has_underconstrained {
                warnings.push(
                    ReadinessWarning::critical(
                        "Attacks",
                        "Missing required attack: underconstrained (strict engagement requires it)",
                    )
                    .with_fix("Add attack type: underconstrained"),
                );
            }
        } else if !has_soundness && !has_underconstrained {
            warnings.push(
                ReadinessWarning::high(
                    "Attacks",
                    "No soundness or underconstrained attacks configured",
                )
                .with_fix("Add soundness and underconstrained attack types"),
            );
        }
    }

    // 10. Check forge attempts
    for attack in &config.attacks {
        if matches!(attack.attack_type, crate::config::AttackType::Soundness) {
            let forge_attempts = attack
                .config
                .get("forge_attempts")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            if forge_attempts == 0 {
                warnings.push(
                    if engagement_strict {
                        ReadinessWarning::critical("Attacks", "Soundness attack has 0 forge_attempts")
                            .with_fix("Set forge_attempts >= 1000")
                    } else {
                        ReadinessWarning::high("Attacks", "Soundness attack has 0 forge_attempts")
                            .with_fix("Set forge_attempts >= 1000")
                    },
                );
            } else if forge_attempts < 100 {
                warnings.push(
                    ReadinessWarning::medium(
                        "Attacks",
                        &format!(
                            "Soundness attack has only {} forge_attempts",
                            forge_attempts
                        ),
                    )
                    .with_fix("Set forge_attempts >= 1000 for thorough testing"),
                );
            }
        }
    }

    // 11. Check corpus size
    let corpus_max_size = additional
        .get("corpus_max_size")
        .and_then(|v| v.as_u64())
        .unwrap_or(100_000);

    if corpus_max_size < 10_000 {
        warnings.push(ReadinessWarning::low(
            "Corpus",
            &format!(
                "corpus_max_size={} may limit coverage exploration",
                corpus_max_size
            ),
        ));
    }

    // 12. Check circuit path exists
    if !config.campaign.target.circuit_path.exists() {
        warnings.push(ReadinessWarning::critical(
            "Target",
            &format!(
                "Circuit file not found: {:?}",
                config.campaign.target.circuit_path
            ),
        ));
    }

    // 13. Check fuzzing iterations (CRITICAL for 0-day discovery)
    //
    // Note: runs typically set `fuzzing_iterations` via the CLI, while some YAMLs set
    // `max_iterations` (profile-style). Report the effective key for clarity.
    let (iterations_key, max_iterations) = if !config.chains.is_empty() {
        let v = additional
            .get("chain_iterations")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000);
        ("chain_iterations", v)
    } else if let Some(v) = additional.get("max_iterations").and_then(|v| v.as_u64()) {
        ("max_iterations", v)
    } else if let Some(v) = additional.get("fuzzing_iterations").and_then(|v| v.as_u64()) {
        ("fuzzing_iterations", v)
    } else {
        ("fuzzing_iterations", 1000)
    };

    if max_iterations < 10_000 {
        warnings.push(
            ReadinessWarning::high(
                "Fuzzing",
                &format!(
                    "{}={} is too low for 0-day discovery",
                    iterations_key, max_iterations
                ),
            )
            .with_fix(&format!(
                "Set {} >= 100000 for production audits",
                iterations_key
            )),
        );
    } else if max_iterations < 100_000 {
        warnings.push(ReadinessWarning::medium(
            "Fuzzing",
            &format!("{}={} may miss deep bugs", iterations_key, max_iterations),
        ));
    }

    // 14. Check evidence mode consistency
    if evidence_mode && !oracle_validation {
        warnings.push(
            ReadinessWarning::high(
                "Evidence",
                "evidence_mode enabled but oracle_validation disabled",
            )
            .with_fix("Enable oracle_validation when using evidence_mode"),
        );
    }

    // 15. Check novel oracle attacks are enabled (skip for chain-only campaigns)
    if !config.attacks.is_empty() {
        let has_constraint_inference = config.attacks.iter().any(|a| {
            matches!(
                a.attack_type,
                crate::config::AttackType::ConstraintInference
            )
        });
        let has_metamorphic = config
            .attacks
            .iter()
            .any(|a| matches!(a.attack_type, crate::config::AttackType::Metamorphic));
        let has_constraint_slice = config
            .attacks
            .iter()
            .any(|a| matches!(a.attack_type, crate::config::AttackType::ConstraintSlice));
        let has_spec_inference = config
            .attacks
            .iter()
            .any(|a| matches!(a.attack_type, crate::config::AttackType::SpecInference));
        let has_witness_collision = config
            .attacks
            .iter()
            .any(|a| matches!(a.attack_type, crate::config::AttackType::WitnessCollision));

        if engagement_strict {
            let required = [
                (has_constraint_inference, "constraint_inference"),
                (has_metamorphic, "metamorphic"),
                (has_constraint_slice, "constraint_slice"),
                (has_spec_inference, "spec_inference"),
                (has_witness_collision, "witness_collision"),
            ];
            for (present, name) in required {
                if !present {
                    warnings.push(
                        ReadinessWarning::critical(
                            "Attacks",
                            &format!(
                                "Missing required novel attack: {} (strict engagement requires all pattern attacks)",
                                name
                            ),
                        )
                        .with_fix("Enable all novel oracle attacks in the campaign attacks list"),
                    );
                }
            }
        } else if !has_constraint_inference
            && !has_metamorphic
            && !has_constraint_slice
            && !has_spec_inference
            && !has_witness_collision
        {
            warnings.push(
                ReadinessWarning::medium(
                    "Attacks",
                    "No novel oracle attacks (constraint_inference, metamorphic, constraint_slice, spec_inference, witness_collision)",
                )
                .with_fix("Add novel oracle attacks for deeper bug discovery"),
            );
        }
    }

    // 16. Check timeout configuration
    let timeout_seconds = config.campaign.parameters.timeout_seconds;
    if timeout_seconds < 300 {
        warnings.push(
            ReadinessWarning::medium(
                "Timeout",
                &format!(
                    "Campaign timeout {}s may be too short for thorough testing",
                    timeout_seconds
                ),
            )
            .with_fix("Set timeout_seconds >= 3600 (1 hour) for production"),
        );
    }

    // 17. Check public input configuration for underconstrained attacks
    for attack in &config.attacks {
        if matches!(
            attack.attack_type,
            crate::config::AttackType::Underconstrained
        ) {
            let has_public_config = attack.config.get("public_input_names").is_some()
                || attack.config.get("public_input_positions").is_some()
                || attack.config.get("public_input_count").is_some();

            if !has_public_config {
                warnings.push(
                    if engagement_strict {
                        ReadinessWarning::critical(
                            "Attacks",
                            "Underconstrained attack missing public input configuration (strict engagement requires explicit public wiring)",
                        )
                        .with_fix(
                            "Add public_input_names or public_input_positions to underconstrained attack config",
                        )
                    } else {
                        ReadinessWarning::high(
                            "Attacks",
                            "Underconstrained attack missing public input configuration",
                        )
                        .with_fix(
                            "Add public_input_names or public_input_positions to underconstrained attack config",
                        )
                    },
                );
            }
        }
    }

    // 18. Check reporting configuration
    if config.reporting.formats.is_empty() {
        warnings.push(
            ReadinessWarning::low("Reporting", "No report formats configured")
                .with_fix("Add formats: ['json', 'markdown'] to reporting section"),
        );
    }

    // Compute final score and report
    let score = ReadinessReport::compute_score(&warnings);
    let ready_for_evidence = ReadinessReport::is_evidence_ready(&warnings);

    warnings.sort_by(|a, b| a.level.cmp(&b.level));

    ReadinessReport {
        warnings,
        score,
        ready_for_evidence,
    }
}

/// Quick check that returns only critical issues (for fail-fast validation)
pub fn check_critical_only(config: &FuzzConfig) -> Vec<ReadinessWarning> {
    check_0day_readiness(config)
        .warnings
        .into_iter()
        .filter(|w| w.level == ReadinessLevel::Critical)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_circuit_path_is_critical() {
        let config = FuzzConfig::default_v2();
        let report = check_0day_readiness(&config);

        assert!(!report.ready_for_evidence);
        assert!(report
            .warnings
            .iter()
            .any(|w| w.level == ReadinessLevel::Critical && w.category == "Target"));
    }

    #[test]
    fn test_low_iterations_warning() {
        let mut config = FuzzConfig::default_v2();
        config.campaign.parameters.additional.insert(
            "max_iterations".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(100)),
        );

        let report = check_0day_readiness(&config);
        assert!(report
            .warnings
            .iter()
            .any(|w| w.category == "Fuzzing" && w.message.contains("too low")));
    }

    #[test]
    fn test_evidence_mode_without_validation() {
        let mut config = FuzzConfig::default_v2();
        config
            .campaign
            .parameters
            .additional
            .insert("evidence_mode".to_string(), serde_yaml::Value::Bool(true));
        config.campaign.parameters.additional.insert(
            "oracle_validation".to_string(),
            serde_yaml::Value::Bool(false),
        );

        let report = check_0day_readiness(&config);
        assert!(report
            .warnings
            .iter()
            .any(|w| w.category == "Evidence" && w.level == ReadinessLevel::High));
    }
}
