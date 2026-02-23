use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) fn finalize_run_report(
        &mut self,
        start_time: Instant,
        mode_label: &str,
        phases_total: u64,
    ) -> anyhow::Result<FuzzReport> {
        // Export corpus to output directory
        let corpus_dir = self.config.reporting.output_dir.join("corpus");
        match self.export_corpus(&corpus_dir) {
            Ok(count) => tracing::info!(
                "Exported {} interesting test cases to {:?}",
                count,
                corpus_dir
            ),
            Err(e) => tracing::warn!("Failed to export corpus: {}", e),
        }

        // Generate report
        let elapsed = start_time.elapsed();
        let mut findings = self.with_findings_read(Clone::clone)?;

        let additional = &self.config.campaign.parameters.additional;
        let evidence_mode = Self::additional_bool(additional, "evidence_mode").unwrap_or(false);
        let oracle_validation_enabled =
            Self::additional_bool(additional, "oracle_validation").unwrap_or(evidence_mode);
        let run_timed_out = self.wall_clock_timeout_reached();

        if oracle_validation_enabled {
            if run_timed_out {
                tracing::warn!(
                    "Skipping oracle validation: global wall-clock timeout already reached"
                );
            } else {
                let validation_config = self.oracle_validation_config();
                let skip_stateful = validation_config.skip_stateful_oracles;
                let mut validator = OracleValidator::with_config(validation_config);
                let mut validation_oracles = self.build_validation_oracles();
                let before = findings.len();
                findings = filter_validated_findings(
                    findings,
                    &mut validator,
                    &mut validation_oracles,
                    self.executor.as_ref(),
                    evidence_mode,
                );
                let after = findings.len();
                tracing::info!(
                    "Oracle validation complete: {} -> {} findings (skip_stateful={})",
                    before,
                    after,
                    skip_stateful
                );
            }
        }

        tracing::info!(
            "Fuzzing complete: {} findings in {:.2}s",
            findings.len(),
            elapsed.as_secs_f64()
        );
        tracing::warn!(
            "MILESTONE complete mode={} target={} findings={} duration_s={:.2}",
            mode_label,
            self.config.campaign.name,
            findings.len(),
            elapsed.as_secs_f64()
        );
        // Reporting/evidence generation can still take time; don't mark 100% until the end.
        self.write_progress_snapshot(
            mode_label,
            "reporting",
            phases_total,
            phases_total.saturating_sub(1),
            Some(0.0),
            serde_json::json!({
                "findings_total": findings.len(),
                "duration_seconds": elapsed.as_secs_f64(),
            }),
        );

        let mut report = self.generate_report(findings.clone(), elapsed.as_secs());

        let generate_evidence_bundles = Self::additional_bool(
            &self.config.campaign.parameters.additional,
            "generate_evidence_bundles",
        )
        .unwrap_or(true);

        // Phase 5B: Generate evidence bundles in evidence mode
        if evidence_mode && generate_evidence_bundles && !findings.is_empty() {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Skipping evidence bundle generation: global wall-clock timeout already reached"
                );
            } else {
                tracing::info!("Evidence mode: generating proof-level evidence bundles...");

                let evidence_dir = self.config.reporting.output_dir.join("evidence");
                let evidence_gen = crate::reporting::EvidenceGenerator::new(
                    self.config.clone(),
                    evidence_dir.clone(),
                );

                // Create backend identity from executor
                let backend_identity = crate::reporting::BackendIdentity::from_framework(
                    self.config.campaign.target.framework,
                );

                let bundles = evidence_gen.generate_all_bundles(&findings, backend_identity);

                // Count verification results
                let confirmed = bundles.iter().filter(|b| b.is_confirmed()).count();
                let skipped = bundles
                    .iter()
                    .filter(|b| {
                        matches!(
                            b.verification_result,
                            crate::reporting::VerificationResult::Skipped(_)
                        )
                    })
                    .count();
                let failed = bundles
                    .iter()
                    .filter(|b| {
                        matches!(
                            b.verification_result,
                            crate::reporting::VerificationResult::Failed(_)
                        )
                    })
                    .count();

                tracing::info!(
                "Evidence generation complete: {} confirmed, {} failed, {} skipped out of {} bundles",
                confirmed,
                failed,
                skipped,
                bundles.len()
            );

                // Write evidence summary to report
                if !bundles.is_empty() {
                    let evidence_summary_path = evidence_dir.join("EVIDENCE_SUMMARY.md");
                    if self
                        .write_evidence_summary(&bundles, &evidence_summary_path)
                        .is_ok()
                    {
                        tracing::info!("Evidence summary written to {:?}", evidence_summary_path);
                        // Update report statistics
                        report.statistics.unique_crashes = confirmed as u64;
                    }
                }
            }
        } else if evidence_mode && !generate_evidence_bundles {
            tracing::info!(
                "Evidence mode: skipping proof-level evidence bundle generation (generate_evidence_bundles=false)"
            );
        }

        self.write_progress_snapshot(
            mode_label,
            "completed",
            phases_total,
            phases_total,
            None,
            serde_json::json!({
                "findings_total": report.findings.len(),
            }),
        );

        Ok(report)
    }
}
