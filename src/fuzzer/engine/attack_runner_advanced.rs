use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) async fn run_sidechannel_advanced_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{SidechannelAdvancedAttack, SidechannelAdvancedConfig};

        let section = config.get("sidechannel_advanced").unwrap_or(config);
        let mut advanced_config = SidechannelAdvancedConfig::default();

        if let Some(samples) = section
            .get("cache_timing")
            .and_then(|v| v.get("sample_size"))
            .and_then(|v| v.as_u64())
            .or_else(|| section.get("num_samples").and_then(|v| v.as_u64()))
        {
            advanced_config.timing_samples = self.bounded_attack_units(
                samples as usize,
                1,
                "sidechannel_advanced_timing_samples_cap",
                "sidechannel_advanced.timing_samples",
            );
        }

        if let Some(samples) = section
            .get("memory_patterns")
            .and_then(|v| v.get("sample_count"))
            .and_then(|v| v.as_u64())
            .or_else(|| section.get("num_tests").and_then(|v| v.as_u64()))
        {
            advanced_config.leakage_samples = self.bounded_attack_units(
                samples as usize,
                1,
                "sidechannel_advanced_leakage_samples_cap",
                "sidechannel_advanced.leakage_samples",
            );
        }

        if let Some(v) = section.get("detect_timing").and_then(|v| v.as_bool()) {
            advanced_config.detect_timing = v;
        }
        if let Some(v) = section.get("detect_leakage").and_then(|v| v.as_bool()) {
            advanced_config.detect_leakage = v;
        }
        if let Some(v) = section.get("timing_cv_threshold").and_then(|v| v.as_f64()) {
            advanced_config.timing_cv_threshold = v;
        }
        if let Some(v) = section
            .get("leakage_uniqueness_threshold")
            .and_then(|v| v.as_f64())
        {
            advanced_config.leakage_uniqueness_threshold = v;
        }
        if let Some(v) = section.get("seed").and_then(|v| v.as_u64()) {
            advanced_config.seed = Some(v);
        }

        let base_inputs = self
            .collect_corpus_inputs(1)
            .into_iter()
            .next()
            .unwrap_or_else(|| self.generate_test_case().inputs);

        let mut attack = SidechannelAdvancedAttack::new(advanced_config);
        let findings = attack.run(self.executor.as_ref(), &base_inputs)?;
        self.record_custom_findings(findings, AttackType::SidechannelAdvanced, progress)?;

        if let Some(p) = progress {
            p.inc();
        }
        Ok(())
    }

    pub(super) async fn run_privacy_advanced_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{PrivacyAdvancedAttack, PrivacyAdvancedConfig};

        let section = config.get("privacy_advanced").unwrap_or(config);
        let leakage_samples = section
            .get("metadata_leakage")
            .and_then(|v| v.get("sample_count"))
            .and_then(|v| v.as_u64())
            .or_else(|| section.get("sample_count").and_then(|v| v.as_u64()))
            .or_else(|| section.get("num_tests").and_then(|v| v.as_u64()));
        let timing_samples = section
            .get("metadata_leakage")
            .and_then(|v| v.get("sample_count"))
            .and_then(|v| v.as_u64())
            .or_else(|| section.get("timing_samples").and_then(|v| v.as_u64()));

        let mut privacy_config = PrivacyAdvancedConfig::default();
        let sample_count = leakage_samples
            .unwrap_or(privacy_config.sample_count as u64)
            .max(timing_samples.unwrap_or(0));
        privacy_config.sample_count = self.bounded_attack_units(
            sample_count as usize,
            1,
            "privacy_advanced_sample_count_cap",
            "privacy_advanced.sample_count",
        );
        if let Some(v) = section
            .get("entropy_threshold_bits")
            .and_then(|v| v.as_f64())
        {
            privacy_config.entropy_threshold_bits = v;
        }
        if let Some(v) = section.get("timing_cv_threshold").and_then(|v| v.as_f64()) {
            privacy_config.timing_cv_threshold = v;
        }
        if let Some(v) = section
            .get("detect_metadata_leakage")
            .and_then(|v| v.as_bool())
        {
            privacy_config.detect_metadata_leakage = v;
        }
        if let Some(v) = section
            .get("detect_timing_leakage")
            .and_then(|v| v.as_bool())
        {
            privacy_config.detect_timing_leakage = v;
        }
        if let Some(v) = section.get("seed").and_then(|v| v.as_u64()) {
            privacy_config.seed = Some(v);
        }

        let base_inputs = self
            .collect_corpus_inputs(1)
            .into_iter()
            .next()
            .unwrap_or_else(|| self.generate_test_case().inputs);
        let mut attack = PrivacyAdvancedAttack::new(privacy_config);
        let findings = attack.run(self.executor.as_ref(), &base_inputs)?;
        self.record_custom_findings(findings, AttackType::PrivacyAdvanced, progress)?;

        if let Some(p) = progress {
            p.inc();
        }
        Ok(())
    }

    pub(super) async fn run_defi_advanced_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{DefiAdvancedAttack, DefiAdvancedConfig};

        let section = config
            .get("defi_advanced")
            .or_else(|| config.get("defi"))
            .unwrap_or(config);

        let mev_section = section
            .get("mev_patterns")
            .or_else(|| section.get("mev"))
            .unwrap_or(section);
        let front_section = section
            .get("front_running_patterns")
            .or_else(|| section.get("front_running"))
            .unwrap_or(section);

        let mut defi_config = DefiAdvancedConfig::default();
        if let Some(v) = mev_section
            .get("ordering_permutations")
            .and_then(|v| v.as_u64())
        {
            defi_config.ordering_permutations = self.bounded_attack_units(
                v as usize,
                1,
                "defi_advanced_ordering_permutations_cap",
                "defi_advanced.ordering_permutations",
            );
        }
        if let Some(v) = mev_section.get("profit_threshold").and_then(|v| v.as_f64()) {
            defi_config.ordering_delta_threshold = v;
        }
        if let Some(v) = mev_section.get("detect_ordering").and_then(|v| v.as_bool()) {
            defi_config.detect_ordering = v;
        }

        if let Some(v) = front_section.get("leakage_tests").and_then(|v| v.as_u64()) {
            defi_config.leakage_samples = self.bounded_attack_units(
                v as usize,
                1,
                "defi_advanced_leakage_samples_cap",
                "defi_advanced.leakage_samples",
            );
        }
        if let Some(v) = front_section
            .get("entropy_threshold")
            .and_then(|v| v.as_f64())
        {
            defi_config.entropy_threshold_bits = v;
        }
        if let Some(v) = front_section
            .get("detect_leakage")
            .and_then(|v| v.as_bool())
        {
            defi_config.detect_front_running_signals = v;
        }
        if let Some(v) = section.get("seed").and_then(|v| v.as_u64()) {
            defi_config.seed = Some(v);
        }

        let base_inputs = self
            .collect_corpus_inputs(1)
            .into_iter()
            .next()
            .unwrap_or_else(|| self.generate_test_case().inputs);
        let mut attack = DefiAdvancedAttack::new(defi_config);
        let findings = attack.run(self.executor.as_ref(), &base_inputs)?;
        self.record_custom_findings(findings, AttackType::DefiAdvanced, progress)?;

        if let Some(p) = progress {
            p.inc();
        }

        Ok(())
    }
}
