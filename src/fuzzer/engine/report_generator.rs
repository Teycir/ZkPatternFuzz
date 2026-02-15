use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) fn generate_report(&self, findings: Vec<Finding>, duration: u64) -> FuzzReport {
        // Phase 6A: Apply cross-oracle correlation for confidence scoring
        let additional = &self.config.campaign.parameters.additional;
        let evidence_mode = match Self::additional_bool(additional, "evidence_mode") {
            Some(value) => value,
            None => false,
        };

        let processed_findings = if evidence_mode && !findings.is_empty() {
            // In evidence mode, filter to only HIGH+ confidence findings
            let correlator = OracleCorrelator::new();
            let correlated = correlator.correlate(&findings);

            tracing::info!(
                "Cross-oracle correlation: {} raw findings → {} correlation groups",
                findings.len(),
                correlated.len()
            );

            // Log confidence breakdown
            let mut critical_count = 0;
            let mut high_count = 0;
            let mut medium_count = 0;
            let mut low_count = 0;
            for cf in &correlated {
                match cf.confidence {
                    ConfidenceLevel::Critical => critical_count += 1,
                    ConfidenceLevel::High => high_count += 1,
                    ConfidenceLevel::Medium => medium_count += 1,
                    ConfidenceLevel::Low => low_count += 1,
                }
            }
            tracing::info!(
                "Confidence distribution: CRITICAL={}, HIGH={}, MEDIUM={}, LOW={}",
                critical_count,
                high_count,
                medium_count,
                low_count
            );

            // Filter to only MEDIUM+ confidence in evidence mode
            let min_confidence = Self::additional_string(additional, "min_evidence_confidence")
                .map(|s| match s.to_lowercase().as_str() {
                    "critical" => ConfidenceLevel::Critical,
                    "high" => ConfidenceLevel::High,
                    "low" => ConfidenceLevel::Low,
                    _ => ConfidenceLevel::Medium,
                })
                .map(|value| value);
            let min_confidence = match min_confidence {
                Some(value) => value,
                None => ConfidenceLevel::Medium,
            };

            let filtered: Vec<Finding> = correlated
                .into_iter()
                .filter(|cf| cf.confidence >= min_confidence)
                .map(|cf| cf.primary)
                .collect();

            if filtered.len() < findings.len() {
                tracing::info!(
                    "Evidence mode: filtered {} low-confidence findings (kept {})",
                    findings.len() - filtered.len(),
                    filtered.len()
                );
            }

            filtered
        } else {
            findings
        };

        let mut report = FuzzReport::new(
            self.config.campaign.name.clone(),
            processed_findings,
            zk_core::CoverageMap {
                constraint_hits: std::collections::HashMap::new(),
                edge_coverage: self.core.coverage().unique_constraints_hit() as u64,
                max_coverage: self.executor.num_constraints() as u64,
            },
            self.config.reporting.clone(),
        );
        report.duration_seconds = duration;
        report.statistics.total_executions = self.core.execution_count();
        report
    }

    /// Write evidence summary markdown file using format_bundle_markdown()
    pub(super) fn write_evidence_summary(
        &self,
        bundles: &[crate::reporting::EvidenceBundle],
        path: &std::path::Path,
    ) -> anyhow::Result<()> {
        use crate::reporting::evidence::format_bundle_markdown;
        use std::fs;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut md = String::new();
        md.push_str("# Evidence Summary\n\n");
        md.push_str(&format!("**Campaign:** {}\n", self.config.campaign.name));
        md.push_str(&format!(
            "**Generated:** {}\n\n",
            chrono::Utc::now().to_rfc3339()
        ));

        // Summary statistics
        let confirmed = bundles.iter().filter(|b| b.is_confirmed()).count();
        let failed = bundles
            .iter()
            .filter(|b| {
                matches!(
                    b.verification_result,
                    crate::reporting::VerificationResult::Failed(_)
                )
            })
            .count();
        let skipped = bundles
            .iter()
            .filter(|b| {
                matches!(
                    b.verification_result,
                    crate::reporting::VerificationResult::Skipped(_)
                )
            })
            .count();

        md.push_str("## Verification Summary\n\n");
        md.push_str("| Status | Count |\n");
        md.push_str("|--------|-------|\n");
        md.push_str(&format!("| ✅ CONFIRMED | {} |\n", confirmed));
        md.push_str(&format!("| ❌ NOT CONFIRMED | {} |\n", failed));
        md.push_str(&format!("| ⏭ SKIPPED | {} |\n", skipped));
        md.push_str(&format!("| **TOTAL** | {} |\n\n", bundles.len()));

        if confirmed > 0 {
            md.push_str("## ⚠️ CONFIRMED VULNERABILITIES\n\n");
            md.push_str("The following findings have been cryptographically verified. ");
            md.push_str("The circuit accepts witnesses that violate expected invariants.\n\n");
        }

        // Write each bundle using format_bundle_markdown
        for bundle in bundles {
            md.push_str(&format_bundle_markdown(bundle));
        }

        fs::write(path, md)?;
        Ok(())
    }

    /// Get current statistics
    pub fn stats(&self) -> FuzzingStats {
        self.core.stats()
    }

    pub(super) fn write_progress_snapshot(
        &self,
        mode_label: &str,
        stage: &str,
        phases_total: u64,
        phases_completed: u64,
        phase_progress: Option<f64>,
        details: serde_json::Value,
    ) {
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs());
        let now_epoch = match now_epoch {
            Ok(value) => value,
            Err(_) => 0,
        };

        let overall = if phases_total == 0 {
            0.0
        } else {
            let sub = match phase_progress {
                Some(value) => value,
                None => 0.0,
            }
            .clamp(0.0, 1.0);
            ((phases_completed as f64) + sub) / (phases_total as f64)
        }
        .clamp(0.0, 1.0);

        let steps_total = phases_total.max(1);
        let steps_done = phases_completed.min(steps_total);
        let step_current = (steps_done.saturating_add(1)).min(steps_total);

        let additional = &self.config.campaign.parameters.additional;
        let run_id = Self::additional_string(additional, "run_id");
        let command = match Self::additional_string(additional, "run_command") {
            Some(value) => value,
            None => {
                // Compatibility path for older binaries.
                if mode_label == "evidence" {
                    "evidence".to_string()
                } else {
                    "run".to_string()
                }
            }
        };

        let snapshot = serde_json::json!({
            "updated_unix_seconds": now_epoch,
            "run_id": run_id,
            "command": command,
            "mode_label": mode_label,
            "campaign_name": self.config.campaign.name,
            "output_dir": self.config.reporting.output_dir.display().to_string(),
            "stage": stage,
            "progress": {
                // "steps" is the clean signal: 1/n, 3/n, ..., n/n.
                "steps_total": steps_total,
                "steps_done": steps_done,
                "step_current": step_current,
                "step_fraction": format!("{}/{}", step_current, steps_total),
                "overall_fraction": overall,
                "overall_percent": (overall * 100.0),
                "phase_progress": phase_progress,
            },
            "details": details,
        });

        let path = self.config.reporting.output_dir.join("progress.json");
        if let Some(parent) = path.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                tracing::warn!(
                    "Failed to create progress snapshot directory '{}': {}",
                    parent.display(),
                    err
                );
                return;
            }
        }
        match serde_json::to_string_pretty(&snapshot) {
            Ok(data) => {
                if let Err(err) = std::fs::write(&path, data) {
                    tracing::warn!(
                        "Failed to write progress snapshot '{}': {}",
                        path.display(),
                        err
                    );
                }
            }
            Err(err) => {
                tracing::warn!("Failed to serialize progress snapshot: {}", err);
            }
        }
    }

    /// Update power scheduler with global statistics
    pub(super) fn update_power_scheduler_globals(&mut self) {
        self.core.update_power_scheduler_globals();
    }

    /// Number of unique constraints hit so far.
    pub fn coverage_edges(&self) -> u64 {
        self.core.coverage().unique_constraints_hit() as u64
    }

    /// Constraint IDs hit so far.
    pub fn coverage_constraint_ids(&self) -> Vec<usize> {
        self.core.coverage().constraint_ids()
    }

    /// Total constraints in the target circuit.
    pub fn max_coverage(&self) -> u64 {
        self.executor.num_constraints() as u64
    }

    /// Current corpus size.
    pub fn corpus_len(&self) -> usize {
        self.core.corpus().len()
    }

    /// Get complexity metrics for the circuit
    pub fn get_complexity_metrics(&self) -> crate::analysis::complexity::ComplexityMetrics {
        self.complexity_analyzer.analyze(&self.executor)
    }

    /// Run source code analysis to find vulnerability hints
    pub(super) fn run_source_analysis(&self, progress: Option<&ProgressReporter>) {
        use crate::targets::{cairo_analysis, circom_analysis, halo2_analysis, noir_analysis};

        // Try to read the circuit source file
        let source = match std::fs::read_to_string(&self.config.campaign.target.circuit_path) {
            Ok(s) => s,
            Err(_) => return, // Skip if source not readable
        };

        let hints: Vec<String> = match self.config.campaign.target.framework {
            Framework::Circom => circom_analysis::analyze_for_vulnerabilities(&source)
                .into_iter()
                .map(|h| {
                    format!(
                        "{:?}: {} at line {}",
                        h.hint_type,
                        h.description,
                        match h.line {
                            Some(value) => value,
                            None => 0,
                        }
                    )
                })
                .collect(),
            Framework::Noir => noir_analysis::analyze_for_vulnerabilities(&source)
                .into_iter()
                .map(|h| {
                    format!(
                        "{:?}: {} at line {}",
                        h.hint_type,
                        h.description,
                        match h.line {
                            Some(value) => value,
                            None => 0,
                        }
                    )
                })
                .collect(),
            Framework::Halo2 => halo2_analysis::analyze_circuit(&source)
                .into_iter()
                .map(|h| format!("[{}] {}: {}", h.severity, h.gate_type, h.description))
                .collect(),
            Framework::Cairo => cairo_analysis::analyze_for_vulnerabilities(&source)
                .into_iter()
                .map(|h| format!("{:?}: {}", h.issue_type, h.description))
                .collect(),
        };

        if !hints.is_empty() {
            tracing::info!("Source analysis found {} vulnerability hints", hints.len());
            for hint in &hints {
                tracing::warn!("Vulnerability hint: {}", hint);
                if let Some(p) = progress {
                    p.log_finding("INFO", hint);
                }
            }
        }
    }
}
