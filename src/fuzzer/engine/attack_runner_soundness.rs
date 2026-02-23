use super::attack_runner_budget::strict_attack_floor;
use super::attack_runner_option_ext::OptionValueExt;
use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) async fn run_soundness_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        let num_public = self.executor.num_public_inputs();
        if num_public == 0 {
            tracing::warn!(
                "Skipping soundness attack: circuit exposes 0 public inputs, so proof-forgery checks are inapplicable"
            );
            return Ok(());
        }

        let configured_forge_attempts: usize = config
            .get("forge_attempts")
            .and_then(|v| v.as_u64())
            .or_value(1000) as usize;
        let configured_forge_attempts = strict_attack_floor(
            &self.config.campaign.parameters.additional,
            configured_forge_attempts,
            1000,
            "soundness.forge_attempts",
        );
        let forge_attempts = self.bounded_attack_units(
            configured_forge_attempts,
            1,
            "soundness_forge_attempts_cap",
            "soundness.forge_attempts",
        );

        let mutation_rate: f64 = config
            .get("mutation_rate")
            .and_then(|v| v.as_f64())
            .or_value(0.1);

        tracing::info!("Attempting {} proof forgeries", forge_attempts);
        {
            use crate::oracles::SoundnessTester;
            let tester = SoundnessTester::new()
                .with_forge_attempts(forge_attempts)
                .with_mutation_rate(mutation_rate);
            self.add_attack_findings(&tester, forge_attempts, progress)?;
        }

        let corpus_witnesses = self.collect_corpus_inputs(forge_attempts.max(1));
        let corpus_seed_count = corpus_witnesses.len().min(forge_attempts);
        if corpus_seed_count > 0 {
            tracing::info!(
                "Soundness attack seeded {} witness(es) from corpus before random generation",
                corpus_seed_count
            );
        } else {
            tracing::warn!(
                "Soundness attack has no corpus witnesses; relying on random witness generation"
            );
        }

        let mut successful_proofs = 0usize;
        let mut proof_generation_failures = 0usize;
        let mut last_proof_error: Option<String> = None;

        for attempt in 0..forge_attempts {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping soundness attack at attempt {}/{}: wall-clock timeout reached",
                    attempt,
                    forge_attempts
                );
                break;
            }
            let valid_inputs = if attempt < corpus_witnesses.len() {
                corpus_witnesses[attempt].clone()
            } else {
                self.generate_test_case().inputs
            };

            let valid_proof = match self.executor.prove(&valid_inputs) {
                Ok(proof) => proof,
                Err(err) => {
                    proof_generation_failures += 1;
                    last_proof_error = Some(err.to_string());
                    tracing::debug!(
                        "Soundness attempt {}/{} skipped: witness failed proof generation: {}",
                        attempt + 1,
                        forge_attempts,
                        err
                    );
                    if let Some(p) = progress {
                        p.inc();
                    }
                    continue;
                }
            };
            successful_proofs += 1;

            let valid_public: Vec<FieldElement> =
                valid_inputs.iter().take(num_public).cloned().collect();

            // Mutate public inputs only
            let mutated_public: Vec<FieldElement> = {
                let rng = self.core.rng_mut();
                valid_public
                    .iter()
                    .map(|input| {
                        if rng.gen::<f64>() < mutation_rate {
                            mutate_field_element(input, rng)
                        } else {
                            input.clone()
                        }
                    })
                    .collect()
            };

            // Enforce at least one public-input mutation per attempt.
            let mutated_public = if mutated_public == valid_public {
                let mut forced = valid_public.clone();
                let idx = self.core.rng_mut().gen_range(0..forced.len());
                let mut bytes = forced[idx].0;
                bytes[31] ^= 0x01;
                forced[idx] = FieldElement(bytes);
                forced
            } else {
                mutated_public
            };

            // Try to verify with mutated inputs
            let verified = self.executor.verify(&valid_proof, &mutated_public)?;
            let oracle_findings = self.core.check_proof_forgery(
                &valid_inputs,
                &mutated_public,
                &valid_proof,
                verified,
            );

            if verified {
                // Always store the PoC finding with proof bytes so evidence
                // is preserved regardless of oracle findings.
                let finding = Finding {
                    attack_type: AttackType::Soundness,
                    severity: Severity::Critical,
                    description: "Proof verified with mutated inputs - soundness violation!"
                        .to_string(),
                    poc: super::ProofOfConcept {
                        witness_a: valid_inputs,
                        witness_b: None,
                        public_inputs: mutated_public,
                        proof: Some(valid_proof),
                    },
                    location: None,
                    class: None,
                };

                self.with_findings_write(|store| store.push(finding.clone()))?;

                if let Some(p) = progress {
                    p.log_finding("CRITICAL", &finding.description);
                    for of in &oracle_findings {
                        p.log_finding("CRITICAL", &of.description);
                    }
                }
            }

            if let Some(p) = progress {
                p.inc();
            }
        }

        if successful_proofs == 0 {
            let detail = last_proof_error.unwrap_or_else(|| "unknown error".to_string());
            tracing::warn!(
                "Skipping active soundness verification: no valid base proof was generated across {} attempts ({} failures). Last error: {}",
                forge_attempts,
                proof_generation_failures,
                detail
            );
            return Ok(());
        }

        if proof_generation_failures > 0 {
            tracing::warn!(
                "Soundness attack skipped {}/{} attempts due to proof generation failures",
                proof_generation_failures,
                forge_attempts
            );
        }

        self.run_proof_malleability_attack(config, AttackType::Soundness, progress)?;
        self.run_determinism_check(config, progress)?;
        self.run_setup_poisoning_attack(config, AttackType::Soundness, progress)?;

        Ok(())
    }

    pub(super) fn run_proof_malleability_attack(
        &self,
        config: &serde_yaml::Value,
        finding_attack_type: AttackType,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::ProofMalleabilityScanner;

        let section = config.get("proof_malleability");
        let enabled = section
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .or_value(false);
        if !enabled {
            return Ok(());
        }

        let proof_samples = section
            .and_then(|v| v.get("proof_samples"))
            .and_then(|v| v.as_u64())
            .or_value(10) as usize;
        let negative_control_random_mutations = section
            .and_then(|v| v.get("negative_control_random_mutations"))
            .and_then(|v| v.as_u64())
            .or_else(|| {
                section
                    .and_then(|v| v.get("random_mutations"))
                    .and_then(|v| v.as_u64())
            })
            .or_value(8) as usize;
        let algebraic_mutations = section
            .and_then(|v| v.get("algebraic_mutations"))
            .and_then(|v| v.as_bool())
            .or_else(|| {
                section
                    .and_then(|v| v.get("structured_mutations"))
                    .and_then(|v| v.as_bool())
            })
            .or_value(true);

        let witnesses = self.collect_corpus_inputs(proof_samples.max(1));
        if witnesses.is_empty() {
            anyhow::bail!(
                "Proof malleability scanner requires corpus witnesses, but none are available"
            );
        }

        let scanner = ProofMalleabilityScanner::new()
            .with_proof_samples(proof_samples)
            .with_negative_control_random_mutations(negative_control_random_mutations)
            .with_algebraic_mutations(algebraic_mutations);

        let findings = scanner.run(self.executor.as_ref(), &witnesses);
        self.record_custom_findings(findings, finding_attack_type, progress)?;
        Ok(())
    }

    pub(super) fn run_determinism_check(
        &self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::DeterminismOracle;

        let section = config.get("determinism");
        let enabled = section
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .or_value(false);
        if !enabled {
            return Ok(());
        }

        let repetitions = section
            .and_then(|v| v.get("repetitions"))
            .and_then(|v| v.as_u64())
            .or_value(5) as usize;
        let sample_count = section
            .and_then(|v| v.get("sample_count"))
            .and_then(|v| v.as_u64())
            .or_value(50) as usize;

        let witnesses = self.collect_corpus_inputs(sample_count.max(1));
        if witnesses.is_empty() {
            anyhow::bail!("Determinism oracle requires corpus witnesses, but none are available");
        }

        let oracle = DeterminismOracle::new()
            .with_repetitions(repetitions)
            .with_sample_count(sample_count);

        let findings = oracle.run(self.executor.as_ref(), &witnesses);
        self.record_custom_findings(findings, AttackType::Soundness, progress)?;
        Ok(())
    }

    pub(super) fn run_setup_poisoning_attack(
        &self,
        config: &serde_yaml::Value,
        finding_attack_type: AttackType,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{TrustedSetupAttack, TrustedSetupConfig};
        use std::path::PathBuf;

        let trusted_setup_config = TrustedSetupConfig::from_yaml(config);
        if !trusted_setup_config.enabled {
            return Ok(());
        }

        let attempts = trusted_setup_config.attempts.max(1);
        if attempts == 0 {
            anyhow::bail!("Trusted setup test requires attempts > 0");
        }

        let ptau_a = trusted_setup_config.ptau_file_a.as_deref();
        let ptau_b = trusted_setup_config.ptau_file_b.as_deref();

        let Some(ptau_a) = ptau_a else {
            anyhow::bail!("Trusted setup test missing required key: ptau_file_a");
        };
        let Some(ptau_b) = ptau_b else {
            anyhow::bail!("Trusted setup test missing required key: ptau_file_b");
        };
        if ptau_a == ptau_b {
            anyhow::bail!("Trusted setup test requires distinct ptau_file_a and ptau_file_b");
        }

        if !std::path::Path::new(ptau_a).exists() {
            anyhow::bail!("Trusted setup test ptau_file_a not found: {}", ptau_a);
        }
        if !std::path::Path::new(ptau_b).exists() {
            anyhow::bail!("Trusted setup test ptau_file_b not found: {}", ptau_b);
        }

        let circuit_path = self
            .config
            .campaign
            .target
            .circuit_path
            .to_str()
            .or_value("");
        if circuit_path.is_empty() {
            anyhow::bail!("Trusted setup test requires a valid UTF-8 circuit path");
        }

        let backend = self.config.campaign.target.framework;
        let main_component = &self.config.campaign.target.main_component;

        let mut options_a = self.executor_factory_options.clone();
        options_a.circom_ptau_path = Some(PathBuf::from(ptau_a));
        options_a.circom_auto_setup_keys = true;

        let mut options_b = self.executor_factory_options.clone();
        options_b.circom_ptau_path = Some(PathBuf::from(ptau_b));
        options_b.circom_auto_setup_keys = true;

        let executor_a = match ExecutorFactory::create_with_options(
            backend,
            circuit_path,
            main_component,
            &options_a,
        ) {
            Ok(exec) => exec,
            Err(e) => {
                anyhow::bail!("Trusted setup test failed to create executor A: {}", e);
            }
        };

        let executor_b = match ExecutorFactory::create_with_options(
            backend,
            circuit_path,
            main_component,
            &options_b,
        ) {
            Ok(exec) => exec,
            Err(e) => {
                anyhow::bail!("Trusted setup test failed to create executor B: {}", e);
            }
        };

        let witnesses = self.collect_corpus_inputs(attempts.max(1));
        if witnesses.is_empty() {
            anyhow::bail!("Trusted setup test requires corpus witnesses, but none are available");
        }

        let trusted_setup_attack = TrustedSetupAttack::new(trusted_setup_config);
        let mut findings =
            trusted_setup_attack.run(executor_a.as_ref(), executor_b.as_ref(), &witnesses);
        for finding in &mut findings {
            finding.attack_type = finding_attack_type.clone();
        }
        self.record_custom_findings(findings, finding_attack_type, progress)?;
        Ok(())
    }
}
