use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    fn select_executable_witness_for_pattern_finding(
        &mut self,
        max_attempts: usize,
    ) -> Option<Vec<FieldElement>> {
        let attempts = max_attempts.max(1);

        for inputs in self.collect_corpus_inputs(attempts) {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping pattern witness selection early: wall-clock timeout reached"
                );
                return None;
            }
            let result = self.executor.execute_sync(&inputs);
            if result.success {
                return Some(inputs);
            }
        }

        for _ in 0..attempts {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping pattern witness probing early: wall-clock timeout reached"
                );
                return None;
            }
            let candidate = self.generate_test_case().inputs;
            let result = self.executor.execute_sync(&candidate);
            if result.success {
                return Some(candidate);
            }
        }

        None
    }

    pub(super) fn record_scan_pattern_findings(
        &mut self,
        progress: Option<&ProgressReporter>,
        evidence_mode: bool,
    ) -> anyhow::Result<usize> {
        let Some(summary_text) = self
            .config
            .campaign
            .parameters
            .additional
            .get_string("scan_pattern_summary_text")
        else {
            return Ok(0);
        };

        let pattern_lines: Vec<String> = summary_text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if pattern_lines.is_empty() {
            return Ok(0);
        }

        let Some(witness) = self.select_executable_witness_for_pattern_finding(64) else {
            tracing::warn!(
                "Pattern selectors matched ({}), but no executable witness was available \
                 to materialize evidence-grade findings.",
                pattern_lines.len()
            );
            return Ok(0);
        };

        let mut inserted = 0usize;
        self.with_findings_write(|store| {
            for line in &pattern_lines {
                let finding = Finding {
                    // Keep static CVE-pattern hits separate from dynamic attack families.
                    // This avoids false differential-oracle rejection in evidence mode.
                    attack_type: AttackType::ZkEvm,
                    severity: Severity::Info,
                    description: format!("Static pattern match: {}", line),
                    poc: ProofOfConcept {
                        witness_a: witness.clone(),
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: Some(
                        self.config
                            .campaign
                            .target
                            .circuit_path
                            .display()
                            .to_string(),
                    ),
                    class: None,
                };
                store.push(finding.clone());
                if let Some(p) = progress {
                    p.log_finding("INFO", &finding.description);
                }
                inserted += 1;
            }
        })?;

        if inserted > 0 {
            let mode = if evidence_mode { "evidence" } else { "run" };
            tracing::info!(
                "Recorded {} static regex-pattern findings in {} mode",
                inserted,
                mode
            );
        }
        Ok(inserted)
    }
}
