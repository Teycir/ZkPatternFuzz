use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) async fn run_mev_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{MevAttack, MevConfig};

        let section = config
            .get("mev")
            .or_else(|| config.get("mev_patterns"))
            .or_else(|| config.get("defi"))
            .or_else(|| config.get("defi_advanced"))
            .unwrap_or(config);
        let mut mev_config = MevConfig::default();
        if let Some(v) = section
            .get("ordering_permutations")
            .and_then(|v| v.as_u64())
        {
            mev_config.ordering_permutations = v as usize;
        }
        if let Some(v) = section.get("sandwich_attempts").and_then(|v| v.as_u64()) {
            mev_config.sandwich_attempts = v as usize;
        }
        if let Some(v) = section.get("profit_threshold").and_then(|v| v.as_f64()) {
            mev_config.profit_threshold = v;
        }
        if let Some(v) = section.get("detect_ordering").and_then(|v| v.as_bool()) {
            mev_config.detect_ordering = v;
        }
        if let Some(v) = section.get("detect_sandwich").and_then(|v| v.as_bool()) {
            mev_config.detect_sandwich = v;
        }
        if let Some(v) = section.get("detect_leakage").and_then(|v| v.as_bool()) {
            mev_config.detect_leakage = v;
        }
        if let Some(v) = section.get("timeout_ms").and_then(|v| v.as_u64()) {
            mev_config.timeout_ms = v;
        }
        if let Some(v) = section.get("seed").and_then(|v| v.as_u64()) {
            mev_config.seed = Some(v);
        }

        let base_inputs = self
            .collect_corpus_inputs(1)
            .into_iter()
            .next()
            .unwrap_or_else(|| self.generate_test_case().inputs);

        let mut attack = MevAttack::new(mev_config);
        let mut findings = attack.run(self.executor.as_ref(), &base_inputs)?;
        for finding in &mut findings {
            finding.attack_type = AttackType::Mev;
        }
        self.record_custom_findings(findings, AttackType::Mev, progress)?;

        if let Some(p) = progress {
            p.inc();
        }
        Ok(())
    }

    pub(super) async fn run_front_running_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{FrontRunningAttack, FrontRunningConfig};

        let section = config
            .get("front_running")
            .or_else(|| config.get("front_running_patterns"))
            .or_else(|| config.get("defi"))
            .or_else(|| config.get("defi_advanced"))
            .unwrap_or(config);
        let mut front_config = FrontRunningConfig::default();
        if let Some(v) = section.get("leakage_tests").and_then(|v| v.as_u64()) {
            front_config.leakage_tests = v as usize;
        }
        if let Some(v) = section.get("commitment_tests").and_then(|v| v.as_u64()) {
            front_config.commitment_tests = v as usize;
        }
        if let Some(v) = section.get("detect_leakage").and_then(|v| v.as_bool()) {
            front_config.detect_leakage = v;
        }
        if let Some(v) = section
            .get("detect_commitment_bypass")
            .and_then(|v| v.as_bool())
        {
            front_config.detect_commitment_bypass = v;
        }
        if let Some(v) = section.get("detect_delay_attack").and_then(|v| v.as_bool()) {
            front_config.detect_delay_attack = v;
        }
        if let Some(v) = section.get("entropy_threshold").and_then(|v| v.as_f64()) {
            front_config.entropy_threshold = v;
        }
        if let Some(v) = section.get("seed").and_then(|v| v.as_u64()) {
            front_config.seed = Some(v);
        }

        let base_inputs = self
            .collect_corpus_inputs(1)
            .into_iter()
            .next()
            .unwrap_or_else(|| self.generate_test_case().inputs);

        let mut attack = FrontRunningAttack::new(front_config);
        let mut findings = attack.run(self.executor.as_ref(), &base_inputs)?;
        for finding in &mut findings {
            finding.attack_type = AttackType::FrontRunning;
        }
        self.record_custom_findings(findings, AttackType::FrontRunning, progress)?;

        if let Some(p) = progress {
            p.inc();
        }
        Ok(())
    }

    pub(super) async fn run_zkevm_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{ZkEvmAttack, ZkEvmConfig};

        let section = config
            .get("zkevm")
            .or_else(|| config.get("evm"))
            .unwrap_or(config);
        let mut zkevm_config = ZkEvmConfig::default();
        if let Some(v) = section
            .get("state_transition_tests")
            .and_then(|v| v.as_u64())
        {
            zkevm_config.state_transition_tests = v as usize;
        }
        if let Some(v) = section
            .get("opcode_boundary_tests")
            .and_then(|v| v.as_u64())
        {
            zkevm_config.opcode_boundary_tests = v as usize;
        }
        if let Some(v) = section
            .get("memory_expansion_tests")
            .and_then(|v| v.as_u64())
        {
            zkevm_config.memory_expansion_tests = v as usize;
        }
        if let Some(v) = section.get("storage_proof_tests").and_then(|v| v.as_u64()) {
            zkevm_config.storage_proof_tests = v as usize;
        }
        if let Some(v) = section
            .get("detect_state_transition")
            .and_then(|v| v.as_bool())
        {
            zkevm_config.detect_state_transition = v;
        }
        if let Some(v) = section
            .get("detect_opcode_boundary")
            .and_then(|v| v.as_bool())
        {
            zkevm_config.detect_opcode_boundary = v;
        }
        if let Some(v) = section
            .get("detect_memory_expansion")
            .and_then(|v| v.as_bool())
        {
            zkevm_config.detect_memory_expansion = v;
        }
        if let Some(v) = section
            .get("detect_storage_proof")
            .and_then(|v| v.as_bool())
        {
            zkevm_config.detect_storage_proof = v;
        }
        if let Some(v) = section.get("max_memory_offset").and_then(|v| v.as_u64()) {
            zkevm_config.max_memory_offset = v;
        }
        if let Some(v) = section.get("timeout_ms").and_then(|v| v.as_u64()) {
            zkevm_config.timeout_ms = v;
        }
        if let Some(v) = section.get("seed").and_then(|v| v.as_u64()) {
            zkevm_config.seed = Some(v);
        }
        if let Some(values) = section.get("target_opcodes").and_then(|v| v.as_sequence()) {
            let opcodes: Vec<String> = values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            if !opcodes.is_empty() {
                zkevm_config.target_opcodes = opcodes;
            }
        }

        let base_inputs = self
            .collect_corpus_inputs(1)
            .into_iter()
            .next()
            .unwrap_or_else(|| self.generate_test_case().inputs);

        let mut attack = ZkEvmAttack::new(zkevm_config);
        let mut findings = attack.run(self.executor.as_ref(), &base_inputs)?;
        for finding in &mut findings {
            finding.attack_type = AttackType::ZkEvm;
        }
        self.record_custom_findings(findings, AttackType::ZkEvm, progress)?;

        if let Some(p) = progress {
            p.inc();
        }
        Ok(())
    }

    pub(super) async fn run_batch_verification_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{
            AggregationMethod, BatchVerificationAttack, BatchVerificationConfig, InvalidPosition,
        };

        let section = config.get("batch_verification").unwrap_or(config);
        let mut batch_config = BatchVerificationConfig::default();
        if let Some(v) = section.get("batch_mixing_tests").and_then(|v| v.as_u64()) {
            batch_config.batch_mixing_tests = v as usize;
        }
        if let Some(v) = section
            .get("aggregation_forgery_tests")
            .and_then(|v| v.as_u64())
        {
            batch_config.aggregation_forgery_tests = v as usize;
        }
        if let Some(v) = section.get("cross_circuit_tests").and_then(|v| v.as_u64()) {
            batch_config.cross_circuit_tests = v as usize;
        }
        if let Some(v) = section
            .get("randomness_reuse_tests")
            .and_then(|v| v.as_u64())
        {
            batch_config.randomness_reuse_tests = v as usize;
        }
        if let Some(v) = section.get("detect_batch_mixing").and_then(|v| v.as_bool()) {
            batch_config.detect_batch_mixing = v;
        }
        if let Some(v) = section
            .get("detect_aggregation_forgery")
            .and_then(|v| v.as_bool())
        {
            batch_config.detect_aggregation_forgery = v;
        }
        if let Some(v) = section
            .get("detect_cross_circuit_batch")
            .and_then(|v| v.as_bool())
        {
            batch_config.detect_cross_circuit_batch = v;
        }
        if let Some(v) = section
            .get("detect_randomness_reuse")
            .and_then(|v| v.as_bool())
        {
            batch_config.detect_randomness_reuse = v;
        }
        if let Some(v) = section
            .get("correlation_threshold")
            .and_then(|v| v.as_f64())
        {
            batch_config.correlation_threshold = v;
        }
        if let Some(v) = section.get("timeout_ms").and_then(|v| v.as_u64()) {
            batch_config.timeout_ms = v;
        }
        if let Some(v) = section.get("seed").and_then(|v| v.as_u64()) {
            batch_config.seed = Some(v);
        }

        if let Some(values) = section.get("batch_sizes").and_then(|v| v.as_sequence()) {
            let parsed: Vec<usize> = values
                .iter()
                .filter_map(|v| v.as_u64().map(|n| n as usize))
                .filter(|v| *v > 0)
                .collect();
            if !parsed.is_empty() {
                batch_config.batch_sizes = parsed;
            }
        }

        if let Some(values) = section
            .get("aggregation_methods")
            .and_then(|v| v.as_sequence())
        {
            let mut parsed = Vec::new();
            for value in values {
                if let Some(raw) = value.as_str() {
                    match raw.trim().to_ascii_lowercase().as_str() {
                        "naive_batch" => parsed.push(AggregationMethod::NaiveBatch),
                        "snarkpack" => parsed.push(AggregationMethod::SnarkPack),
                        "groth16_aggregation" => parsed.push(AggregationMethod::Groth16Aggregation),
                        "plonk_aggregation" => parsed.push(AggregationMethod::PlonkAggregation),
                        "halo2_aggregation" => parsed.push(AggregationMethod::Halo2Aggregation),
                        _ => {}
                    }
                }
            }
            if !parsed.is_empty() {
                batch_config.aggregation_methods = parsed;
            }
        }

        if let Some(values) = section
            .get("invalid_positions")
            .and_then(|v| v.as_sequence())
        {
            let mut parsed = Vec::new();
            for value in values {
                if let Some(raw) = value.as_str() {
                    match raw.trim().to_ascii_lowercase().as_str() {
                        "first" => parsed.push(InvalidPosition::First),
                        "last" => parsed.push(InvalidPosition::Last),
                        "middle" => parsed.push(InvalidPosition::Middle),
                        "random" => parsed.push(InvalidPosition::Random),
                        _ => {}
                    }
                }
            }
            if !parsed.is_empty() {
                batch_config.invalid_positions = parsed;
            }
        }

        let sample_count = batch_config
            .batch_sizes
            .iter()
            .copied()
            .max()
            .unwrap_or(2)
            .max(2);
        let mut base_inputs = self.collect_corpus_inputs(sample_count);
        if base_inputs.is_empty() {
            base_inputs.push(self.generate_test_case().inputs);
        }

        let mut attack = BatchVerificationAttack::new(batch_config);
        let raw_findings = attack.run(self.executor.as_ref(), &base_inputs);
        let mut findings: Vec<Finding> = raw_findings
            .into_iter()
            .map(|finding| finding.to_finding())
            .collect();
        for finding in &mut findings {
            finding.attack_type = AttackType::BatchVerification;
        }
        self.record_custom_findings(findings, AttackType::BatchVerification, progress)?;

        if let Some(p) = progress {
            p.inc();
        }
        Ok(())
    }
}
