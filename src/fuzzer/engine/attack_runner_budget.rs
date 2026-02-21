use super::FuzzingEngine;

pub(super) fn deterministic_attack_cap(
    additional: &crate::config::AdditionalConfig,
    evidence_mode: bool,
    floor: usize,
    per_attack_cap_key: &str,
) -> Option<(usize, usize, usize)> {
    let deterministic =
        super::FuzzingEngine::additional_bool(additional, "evidence_deterministic_runtime")
            .unwrap_or(evidence_mode);
    if !deterministic {
        return None;
    }

    let iterations = super::FuzzingEngine::additional_u64(additional, "max_iterations")
        .or_else(|| super::FuzzingEngine::additional_u64(additional, "fuzzing_iterations"))
        .unwrap_or(1000)
        .max(1) as usize;
    let multiplier =
        super::FuzzingEngine::additional_usize(additional, "evidence_attack_budget_multiplier")
            .unwrap_or(4)
            .max(1);

    let auto_cap = iterations.saturating_mul(multiplier).max(floor);
    let global_cap =
        super::FuzzingEngine::additional_usize(additional, "evidence_attack_budget_cap")
            .unwrap_or(auto_cap)
            .max(floor);
    let cap = super::FuzzingEngine::additional_usize(additional, per_attack_cap_key)
        .unwrap_or(global_cap)
        .max(floor);

    Some((cap, iterations, multiplier))
}

pub(super) fn strict_attack_floor(
    additional: &crate::config::AdditionalConfig,
    configured: usize,
    minimum: usize,
    label: &str,
) -> usize {
    let evidence_mode =
        super::FuzzingEngine::additional_bool(additional, "evidence_mode").unwrap_or(false);
    let engagement_strict = super::FuzzingEngine::additional_bool(additional, "engagement_strict")
        .unwrap_or(evidence_mode);
    let deterministic_runtime =
        super::FuzzingEngine::additional_bool(additional, "evidence_deterministic_runtime")
            .unwrap_or(evidence_mode);

    if deterministic_runtime {
        return configured;
    }

    if !engagement_strict || configured >= minimum {
        return configured;
    }

    tracing::info!(
        "Strict mode floor applied: {} {} -> {}",
        label,
        configured,
        minimum
    );
    minimum
}

impl FuzzingEngine {
    pub(super) fn bounded_attack_units(
        &self,
        configured: usize,
        floor: usize,
        per_attack_cap_key: &str,
        label: &str,
    ) -> usize {
        let configured = configured.max(floor);
        let additional = &self.config.campaign.parameters.additional;
        let evidence_mode = Self::additional_bool(additional, "evidence_mode").unwrap_or(false);

        let Some((cap, iterations, multiplier)) =
            deterministic_attack_cap(additional, evidence_mode, floor, per_attack_cap_key)
        else {
            return configured;
        };

        let effective = configured.min(cap).max(floor);
        if effective < configured {
            tracing::warn!(
                "Deterministic attack budget applied: {} {} -> {} (cap={}, iterations={}, multiplier={}, key={})",
                label,
                configured,
                effective,
                cap,
                iterations,
                multiplier,
                per_attack_cap_key
            );
        }
        effective
    }
}
