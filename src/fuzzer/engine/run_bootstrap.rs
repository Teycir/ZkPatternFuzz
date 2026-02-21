use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) fn run_bootstrap_phase(
        &mut self,
        progress: Option<&ProgressReporter>,
        mode_label: &str,
        phases_total: u64,
        evidence_mode: bool,
    ) -> anyhow::Result<()> {
        tracing::warn!(
            "MILESTONE start mode={} target={} circuit={} output_dir={}",
            mode_label,
            self.config.campaign.name,
            self.config.campaign.target.circuit_path.display(),
            self.config.reporting.output_dir.display()
        );
        self.write_progress_snapshot(
            mode_label,
            "start",
            phases_total,
            0,
            None,
            serde_json::json!({}),
        );

        tracing::info!("Starting fuzzing campaign: {}", self.config.campaign.name);
        tracing::info!(
            "Circuit: {} ({:?})",
            self.executor.name(),
            self.executor.framework()
        );
        tracing::info!("Workers: {}", self.workers);

        // Check for underconstrained circuit
        if self.executor.is_likely_underconstrained() {
            tracing::warn!(
                "Circuit appears underconstrained (DOF = {})",
                self.executor.circuit_info().degrees_of_freedom()
            );
        }

        // Run taint analysis before fuzzing
        if let Some(ref analyzer) = self.taint_analyzer {
            let taint_findings = analyzer.to_findings();
            if !taint_findings.is_empty() {
                tracing::info!(
                    "Taint analysis found {} potential issues",
                    taint_findings.len()
                );
                for finding in &taint_findings {
                    if let Some(p) = progress {
                        p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                    }
                }
                self.with_findings_write(|store| store.extend(taint_findings))?;
            }
        }

        // Run source code analysis for vulnerability hints
        self.run_source_analysis(progress);

        // Seed corpus with external inputs if provided
        if let Err(err) = self.seed_external_inputs_from_config() {
            tracing::warn!("Failed to load external seed inputs: {}", err);
        }

        // Phase 0: Load resume corpus if --resume was specified
        match self.maybe_load_resume_corpus() {
            Ok(count) if count > 0 => {
                tracing::info!("Resumed from {} previous test cases", count);
            }
            Err(err) => {
                tracing::warn!("Failed to load resume corpus: {}", err);
            }
            _ => {}
        }

        // Seed corpus
        self.seed_corpus()?;
        tracing::info!(
            "Seeded corpus with {} initial test cases",
            self.core.corpus().len()
        );
        tracing::warn!(
            "MILESTONE seeded_corpus target={} count={}",
            self.config.campaign.name,
            self.core.corpus().len()
        );
        self.write_progress_snapshot(
            mode_label,
            "seeded_corpus",
            phases_total,
            1,
            None,
            serde_json::json!({
                "corpus_len": self.core.corpus().len(),
            }),
        );

        // Regex selector hits are static CVE-pattern evidence. Record them as findings
        // with executable witness context so they survive evidence-mode validation.
        let pattern_findings = self.record_scan_pattern_findings(progress, evidence_mode)?;
        if pattern_findings > 0 {
            tracing::warn!(
                "MILESTONE pattern_findings target={} count={}",
                self.config.campaign.name,
                pattern_findings
            );
        }

        // Initialize simple progress tracker for non-interactive environments
        self.simple_tracker = Some(SimpleProgressTracker::new());

        // Update power scheduler with initial global stats
        self.update_power_scheduler_globals();

        Ok(())
    }
}
