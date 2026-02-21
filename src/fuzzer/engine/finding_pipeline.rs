use super::prelude::*;
use super::FuzzingEngine;

fn apply_evidence_mode_policy(
    findings: &mut Vec<Finding>,
    evidence_mode: bool,
    attack_label: &str,
) {
    if evidence_mode {
        let before = findings.len();
        findings.retain(|f| {
            !FuzzingEngine::poc_is_empty(&f.poc) || FuzzingEngine::has_static_source_evidence(f)
        });
        let dropped = before.saturating_sub(findings.len());
        if dropped > 0 {
            tracing::info!(
                "Evidence mode: dropped {} heuristic findings from {}",
                dropped,
                attack_label
            );
        }
        return;
    }

    for finding in findings.iter_mut() {
        if FuzzingEngine::poc_is_empty(&finding.poc)
            && !FuzzingEngine::has_static_source_evidence(finding)
        {
            if !finding.description.starts_with("HINT:") {
                finding.description = format!("HINT: {}", finding.description);
            }
            if finding.severity > Severity::Info {
                finding.severity = Severity::Info;
            }
        }
    }
}

impl FuzzingEngine {
    pub(super) fn add_attack_findings(
        &self,
        attack: &dyn AttackTrait,
        samples: usize,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<usize> {
        let context = AttackContext::new(
            self.get_circuit_info(),
            samples,
            self.config.campaign.parameters.timeout_seconds,
        )
        .with_executor(self.executor.clone())
        .with_input_ranges(self.input_index_ranges());
        let mut findings = attack.run(&context);

        let evidence_mode =
            Self::additional_bool(&self.config.campaign.parameters.additional, "evidence_mode")
                .unwrap_or(false);
        apply_evidence_mode_policy(
            &mut findings,
            evidence_mode,
            &format!("{:?}", attack.attack_type()),
        );

        let count = findings.len();
        if count > 0 {
            self.with_findings_write(|store| {
                for finding in findings {
                    if let Some(p) = progress {
                        p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                    }
                    store.push(finding);
                }
            })?;
        }

        Ok(count)
    }

    pub(super) fn record_custom_findings(
        &self,
        mut findings: Vec<Finding>,
        attack_type: AttackType,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<usize> {
        let evidence_mode =
            Self::additional_bool(&self.config.campaign.parameters.additional, "evidence_mode")
                .unwrap_or(false);
        apply_evidence_mode_policy(&mut findings, evidence_mode, &format!("{:?}", attack_type));

        let count = findings.len();
        if count > 0 {
            self.with_findings_write(|store| {
                for finding in findings {
                    if let Some(p) = progress {
                        p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                    }
                    store.push(finding);
                }
            })?;
        }

        Ok(count)
    }

    pub(super) fn poc_is_empty(poc: &ProofOfConcept) -> bool {
        poc.witness_a.is_empty()
            && poc.witness_b.is_none()
            && poc.public_inputs.is_empty()
            && poc.proof.is_none()
    }

    pub(super) fn has_static_source_evidence(finding: &Finding) -> bool {
        matches!(
            finding.attack_type,
            AttackType::QuantumResistance | AttackType::CircomStaticLint
        ) && finding
            .location
            .as_ref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    }
}
