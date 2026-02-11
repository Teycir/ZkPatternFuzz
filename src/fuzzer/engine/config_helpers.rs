use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) fn normalize_oracle_name(name: &str) -> String {
        name.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(|c| c.to_lowercase())
            .collect()
    }

    pub(super) fn disabled_oracle_names(config: &FuzzConfig) -> std::collections::HashSet<String> {
        use std::collections::HashSet;

        let mut disabled = HashSet::new();
        let Some(value) = config.campaign.parameters.additional.get("disabled_oracles") else {
            return disabled;
        };

        match value {
            serde_yaml::Value::Sequence(items) => {
                for item in items {
                    if let Some(s) = item.as_str() {
                        disabled.insert(Self::normalize_oracle_name(s));
                    }
                }
            }
            serde_yaml::Value::String(s) => {
                for part in s.split(',') {
                    let trimmed = part.trim();
                    if !trimmed.is_empty() {
                        disabled.insert(Self::normalize_oracle_name(trimmed));
                    }
                }
            }
            _ => {}
        }

        disabled
    }

    /// Phase 0 Fix: Wire semantic and auxiliary oracles from configuration
    ///
    /// Instantiates nullifier/merkle/range/commitment oracles based on config.oracles,
    /// and recognizes common alias names used in campaigns.
    pub(super) fn add_semantic_oracles_from_config(
        config: &FuzzConfig,
        oracles: &mut Vec<Box<dyn BugOracle>>,
    ) {
        use crate::fuzzer::oracle::{ConstraintCountOracle, ProofForgeryOracle};
        use crate::fuzzer::oracles::{
            CommitmentOracle, MerkleOracle, NullifierOracle, RangeProofOracle,
        };
        use std::collections::HashSet;
        use zk_core::OracleConfig;
        use zk_fuzzer_core::oracle::SemanticOracleAdapter;

        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        enum OracleKind {
            Nullifier,
            Merkle,
            Commitment,
            Range,
            Underconstrained,
            ArithmeticOverflow,
            ConstraintCount,
            ProofForgery,
        }

        let classify = |name: &str| -> Option<OracleKind> {
            let normalized = Self::normalize_oracle_name(name);
            match normalized.as_str() {
                "nullifier"
                | "nullifieroracle"
                | "nullifiercollision"
                | "nullifiercollisionoracle"
                | "nullifierreuse"
                | "determinism" => Some(OracleKind::Nullifier),
                "merkle"
                | "merkleoracle"
                | "merkleproof"
                | "merklesoundness"
                | "merklesoundnessoracle" => Some(OracleKind::Merkle),
                "commitment" | "commitmentoracle" => Some(OracleKind::Commitment),
                "range"
                | "rangeoracle"
                | "rangeproof"
                | "rangeprooforacle"
                | "rangebypass"
                | "bitconstraintbypass" => Some(OracleKind::Range),
                "underconstrained" | "underconstrainedoracle" | "differentwitnesssameoutput" => {
                    Some(OracleKind::Underconstrained)
                }
                "arithmeticoverflow" | "arithmeticoverfloworacle" | "overflow" => {
                    Some(OracleKind::ArithmeticOverflow)
                }
                "constraintcountmismatch" | "constraintcountoracle" => {
                    Some(OracleKind::ConstraintCount)
                }
                "proofforgery" | "proofforgeryoracle" => Some(OracleKind::ProofForgery),
                _ => None,
            }
        };

        let oracle_config = OracleConfig::default();
        let disabled = Self::disabled_oracle_names(config);
        let mut registered: HashSet<String> =
            oracles.iter().map(|o| o.name().to_string()).collect();

        let mut add_oracle = |oracle: Box<dyn BugOracle>| {
            let name = oracle.name().to_string();
            if registered.insert(name) {
                oracles.push(oracle);
            }
        };

        let mut requested: Vec<String> = config.oracles.iter().map(|o| o.name.clone()).collect();
        if let Some(enabled_oracles) = config.campaign.parameters.additional.get("enabled_oracles")
        {
            if let Some(seq) = enabled_oracles.as_sequence() {
                for item in seq {
                    if let Some(name) = item.as_str() {
                        requested.push(name.to_string());
                    }
                }
            }
        }

        for oracle_name in requested {
            let kind = classify(&oracle_name);
            if disabled.contains(&Self::normalize_oracle_name(&oracle_name)) {
                continue;
            }

            match kind {
                Some(OracleKind::Nullifier) => add_oracle(Box::new(SemanticOracleAdapter::new(
                    Box::new(NullifierOracle::new(oracle_config.clone())),
                ))),
                Some(OracleKind::Merkle) => add_oracle(Box::new(SemanticOracleAdapter::new(
                    Box::new(MerkleOracle::new(oracle_config.clone())),
                ))),
                Some(OracleKind::Commitment) => add_oracle(Box::new(SemanticOracleAdapter::new(
                    Box::new(CommitmentOracle::new(oracle_config.clone())),
                ))),
                Some(OracleKind::Range) => add_oracle(Box::new(SemanticOracleAdapter::new(
                    Box::new(RangeProofOracle::new(oracle_config.clone())),
                ))),
                Some(OracleKind::ConstraintCount) => {
                    let expected = config.campaign.parameters.max_constraints as usize;
                    add_oracle(Box::new(ConstraintCountOracle::new(expected)));
                }
                Some(OracleKind::ProofForgery) => add_oracle(Box::new(ProofForgeryOracle::new())),
                Some(OracleKind::Underconstrained) | Some(OracleKind::ArithmeticOverflow) => {
                    // These oracles are enabled by default; treat as recognized aliases.
                }
                None => {
                    tracing::warn!("Unknown oracle type in config: {}", oracle_name);
                }
            }
        }
    }

    pub(super) fn parse_power_schedule(config: &FuzzConfig) -> PowerSchedule {
        // Check for power_schedule in campaign parameters
        if let Some(schedule_str) = config.campaign.parameters.additional.get("power_schedule") {
            if let Some(s) = schedule_str.as_str() {
                return s.parse().unwrap_or(PowerSchedule::Mmopt);
            }
        }
        // Default to MMOPT for balanced performance
        PowerSchedule::Mmopt
    }

    pub(super) fn parse_executor_factory_options(config: &FuzzConfig) -> ExecutorFactoryOptions {
        let additional = &config.campaign.parameters.additional;
        let mut options = ExecutorFactoryOptions::default();

        let base = Self::additional_path(additional, "build_dir_base")
            .or_else(|| Self::additional_path(additional, "build_dir"));
        options.build_dir_base = base;

        options.circom_build_dir = Self::additional_path(additional, "circom_build_dir");
        options.noir_build_dir = Self::additional_path(additional, "noir_build_dir");
        options.halo2_build_dir = Self::additional_path(additional, "halo2_build_dir");
        options.cairo_build_dir = Self::additional_path(additional, "cairo_build_dir");

        if let Some(strict_backend) = Self::additional_bool(additional, "strict_backend") {
            options.strict_backend = strict_backend;
        }
        if let Some(mark_fallback) = Self::additional_bool(additional, "mark_fallback") {
            options.mark_fallback = mark_fallback;
        }
        if let Some(auto_setup) = Self::additional_bool(additional, "circom_auto_setup_keys") {
            tracing::info!("Circom auto setup keys: {}", auto_setup);
            options.circom_auto_setup_keys = auto_setup;
        }
        if let Some(ptau_path) = Self::additional_path(additional, "circom_ptau_path") {
            options.circom_ptau_path = Some(ptau_path);
        }
        if let Some(snarkjs_path) = Self::additional_path(additional, "circom_snarkjs_path") {
            options.circom_snarkjs_path = Some(snarkjs_path);
        }
        if let Some(skip_compile) =
            Self::additional_bool(additional, "circom_skip_compile_if_artifacts")
        {
            options.circom_skip_compile_if_artifacts = skip_compile;
        }

        if let Some(value) = additional.get("include_paths") {
            let mut paths = Vec::new();
            match value {
                serde_yaml::Value::Sequence(items) => {
                    for item in items {
                        if let Some(s) = item.as_str() {
                            let trimmed = s.trim();
                            if !trimmed.is_empty() {
                                paths.push(std::path::PathBuf::from(trimmed));
                            }
                        }
                    }
                }
                serde_yaml::Value::String(s) => {
                    for part in s.split(',') {
                        let trimmed = part.trim();
                        if !trimmed.is_empty() {
                            paths.push(std::path::PathBuf::from(trimmed));
                        }
                    }
                }
                _ => {}
            }
            if !paths.is_empty() {
                options.circom_include_paths = paths;
            }
        }

        options
    }

    pub(super) fn oracle_validation_config(&self) -> OracleValidationConfig {
        let additional = &self.config.campaign.parameters.additional;
        let mut config = OracleValidationConfig::default();

        if let Some(ratio) =
            Self::additional_f64(additional, "oracle_validation_min_agreement_ratio")
        {
            config.min_agreement_ratio = ratio.clamp(0.0, 1.0);
        }
        if let Some(require_ground_truth) =
            Self::additional_bool(additional, "oracle_validation_require_ground_truth")
        {
            config.require_ground_truth = require_ground_truth;
        }
        if let Some(count) =
            Self::additional_usize(additional, "oracle_validation_mutation_test_count")
        {
            config.mutation_test_count = count.max(1);
        }
        if let Some(rate) =
            Self::additional_f64(additional, "oracle_validation_min_mutation_detection_rate")
        {
            config.min_mutation_detection_rate = rate.clamp(0.0, 1.0);
        }
        if let Some(skip_stateful) =
            Self::additional_bool(additional, "oracle_validation_skip_stateful")
        {
            config.skip_stateful_oracles = skip_stateful;
        }
        if let Some(allow_cross) =
            Self::additional_bool(additional, "oracle_validation_allow_cross_attack")
        {
            config.allow_cross_attack_type = allow_cross;
        }
        if let Some(weight) =
            Self::additional_f64(additional, "oracle_validation_cross_attack_weight")
        {
            config.cross_attack_weight = weight.clamp(0.0, 1.0);
        }
        if let Some(reset_stateful) =
            Self::additional_bool(additional, "oracle_validation_reset_stateful")
        {
            config.reset_stateful_oracles = reset_stateful;
        }

        config
    }

    pub(super) fn build_validation_oracles(&self) -> Vec<Box<dyn BugOracle>> {
        let mut oracles: Vec<Box<dyn BugOracle>> = vec![
            Box::new(
                UnderconstrainedOracle::new()
                    .with_public_input_count(self.executor.num_public_inputs()),
            ),
            Box::new(ArithmeticOverflowOracle::new_with_modulus(
                self.executor.field_modulus(),
            )),
        ];

        // Reuse semantic oracle configuration for validation
        Self::add_semantic_oracles_from_config(&self.config, &mut oracles);
        let disabled = Self::disabled_oracle_names(&self.config);
        if !disabled.is_empty() {
            oracles.retain(|o| !disabled.contains(&Self::normalize_oracle_name(o.name())));
        }

        oracles
    }

    pub(super) fn load_attack_plugins(config: &FuzzConfig, registry: &mut AttackRegistry) {
        let additional = &config.campaign.parameters.additional;
        let Some(value) = additional.get("attack_plugin_dirs") else {
            return;
        };

        let mut paths = Vec::new();
        match value {
            serde_yaml::Value::Sequence(items) => {
                for item in items {
                    if let Some(s) = item.as_str() {
                        paths.push(std::path::PathBuf::from(s));
                    }
                }
            }
            serde_yaml::Value::String(s) => {
                for part in s.split(',') {
                    let trimmed = part.trim();
                    if !trimmed.is_empty() {
                        paths.push(std::path::PathBuf::from(trimmed));
                    }
                }
            }
            _ => {}
        }

        if paths.is_empty() {
            return;
        }

        let loader = DynamicLibraryLoader::new(paths);
        if let Err(err) = registry.load_from_loader(&loader) {
            tracing::warn!("Attack plugin loading failed: {}", err);
        }
    }

    pub(super) fn constraint_guided_config(&self) -> Option<EnhancedSymbolicConfig> {
        let additional = &self.config.campaign.parameters.additional;

        if let Some(enabled) = Self::additional_bool(additional, "constraint_guided_enabled") {
            if !enabled {
                return None;
            }
        }

        let mut config = EnhancedSymbolicConfig {
            max_depth: 200,
            solver_timeout_ms: 3000,
            solutions_per_path: 4,
            pruning_strategy: PruningStrategy::DepthBounded,
            simplify_constraints: true,
            incremental_solving: false,
            random_seed: self.seed,
            ..Default::default()
        };

        if let Some(max_depth) = Self::additional_usize(additional, "constraint_guided_max_depth") {
            config.max_depth = max_depth.max(1);
        }
        if let Some(max_paths) = Self::additional_usize(additional, "constraint_guided_max_paths") {
            config.max_paths = max_paths.max(1);
        }
        if let Some(timeout) =
            Self::additional_u32(additional, "constraint_guided_solver_timeout_ms")
        {
            config.solver_timeout_ms = timeout;
        }
        if let Some(solutions) =
            Self::additional_usize(additional, "constraint_guided_solutions_per_path")
        {
            config.solutions_per_path = solutions.max(1);
        }
        if let Some(loop_bound) = Self::additional_usize(additional, "constraint_guided_loop_bound")
        {
            config.loop_bound = loop_bound.max(1);
        }
        if let Some(simplify) =
            Self::additional_bool(additional, "constraint_guided_simplify_constraints")
        {
            config.simplify_constraints = simplify;
        }
        if let Some(incremental) =
            Self::additional_bool(additional, "constraint_guided_incremental_solving")
        {
            config.incremental_solving = incremental;
        }
        if let Some(strategy) =
            Self::additional_string(additional, "constraint_guided_pruning_strategy")
                .or_else(|| Self::additional_string(additional, "constraint_guided_pruning"))
        {
            config.pruning_strategy = Self::parse_pruning_strategy(&strategy);
        }

        Some(config)
    }

    pub(super) fn parse_pruning_strategy(value: &str) -> PruningStrategy {
        let normalized = value.trim().to_lowercase();
        match normalized.as_str() {
            "none" | "off" => PruningStrategy::None,
            "depth" | "depth_bounded" | "depthbounded" => PruningStrategy::DepthBounded,
            "constraint" | "constraint_bounded" | "constraintbounded" => {
                PruningStrategy::ConstraintBounded
            }
            "coverage" | "coverage_guided" | "coverageguided" => PruningStrategy::CoverageGuided,
            "random" | "random_sampling" | "randomsampling" => PruningStrategy::RandomSampling,
            "loop" | "loop_bounded" | "loopbounded" => PruningStrategy::LoopBounded,
            "similarity" | "similarity_based" | "similaritybased" => {
                PruningStrategy::SimilarityBased
            }
            "subsumption" | "subsumption_based" | "subsumptionbased" => {
                PruningStrategy::SubsumptionBased
            }
            _ => {
                tracing::warn!(
                    "Unknown pruning strategy '{}', defaulting to DepthBounded",
                    value
                );
                PruningStrategy::DepthBounded
            }
        }
    }

    pub(super) fn additional_bool(additional: &AdditionalConfig, key: &str) -> Option<bool> {
        additional.get_bool(key)
    }

    pub(super) fn additional_usize(additional: &AdditionalConfig, key: &str) -> Option<usize> {
        additional.get_usize(key)
    }

    pub(super) fn additional_u32(additional: &AdditionalConfig, key: &str) -> Option<u32> {
        additional.get_u32(key)
    }

    pub(super) fn additional_f64(additional: &AdditionalConfig, key: &str) -> Option<f64> {
        additional.get_f64(key)
    }

    /// Phase 0 Fix: Helper to extract u64 from additional config
    pub(super) fn additional_u64(additional: &AdditionalConfig, key: &str) -> Option<u64> {
        additional.get_u64(key)
    }

    pub(super) fn additional_string(additional: &AdditionalConfig, key: &str) -> Option<String> {
        additional.get_string(key)
    }

    pub(super) fn additional_path(additional: &AdditionalConfig, key: &str) -> Option<PathBuf> {
        additional.get_path(key)
    }

    pub(super) fn resolve_attack_plugin(attack: &Attack) -> (Option<String>, bool) {
        if let Some(name) = attack.plugin.as_ref() {
            return (Some(name.clone()), true);
        }

        if let Some(value) = attack.config.get("plugin") {
            if let Some(name) = value.as_str() {
                return (Some(name.to_string()), true);
            }
        }

        (None, false)
    }

    pub(super) fn attack_samples(config: &serde_yaml::Value) -> usize {
        config
            .get("samples")
            .or_else(|| config.get("witness_pairs"))
            .or_else(|| config.get("forge_attempts"))
            .or_else(|| config.get("tests"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize
    }

}
