use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    fn split_bracket_index(name: &str) -> Option<(&str, usize)> {
        let open = name.rfind('[')?;
        let close = name.rfind(']')?;
        if close <= open {
            return None;
        }
        let idx = name[open + 1..close].parse::<usize>().ok()?;
        Some((&name[..open], idx))
    }

    fn split_underscore_index(name: &str) -> Option<(&str, usize)> {
        let (base, idx_str) = name.rsplit_once('_')?;
        if !idx_str.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let idx = idx_str.parse::<usize>().ok()?;
        Some((base, idx))
    }

    fn normalize_input_name_key(name: &str) -> String {
        name.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(|c| c.to_lowercase())
            .collect()
    }

    fn input_name_aliases(name: &str) -> std::collections::HashSet<String> {
        let mut aliases = std::collections::HashSet::new();
        let clean = name.strip_prefix("main.").unwrap_or(name);

        aliases.insert(Self::normalize_input_name_key(clean));

        if let Some((base, idx)) = Self::split_bracket_index(clean) {
            aliases.insert(Self::normalize_input_name_key(base));
            aliases.insert(Self::normalize_input_name_key(&format!(
                "{}[{}]",
                base, idx
            )));
            aliases.insert(Self::normalize_input_name_key(&format!("{}_{}", base, idx)));
        }

        if let Some((base, idx)) = Self::split_underscore_index(clean) {
            aliases.insert(Self::normalize_input_name_key(base));
            aliases.insert(Self::normalize_input_name_key(&format!(
                "{}[{}]",
                base, idx
            )));
            aliases.insert(Self::normalize_input_name_key(&format!("{}_{}", base, idx)));
        }

        aliases
    }

    fn canonical_input_label(raw: &str, fallback_idx: usize) -> String {
        let trimmed = raw.trim();
        let label = trimmed.strip_prefix("main.").unwrap_or(trimmed).trim();
        if label.is_empty() {
            format!("input_{}", fallback_idx)
        } else {
            label.to_string()
        }
    }

    fn infer_ordered_input_labels(
        executor: &dyn CircuitExecutor,
        expected: usize,
    ) -> anyhow::Result<Vec<String>> {
        let inspector = executor.constraint_inspector().ok_or_else(|| {
            anyhow::anyhow!(
                "Cannot reconcile inputs strictly: constraint inspector is unavailable \
                 for framework {:?}",
                executor.framework()
            )
        })?;

        let mut indices = inspector.public_input_indices();
        indices.extend(inspector.private_input_indices());

        let mut seen_indices = std::collections::HashSet::new();
        indices.retain(|idx| seen_indices.insert(*idx));

        if indices.len() != expected {
            anyhow::bail!(
                "Cannot reconcile inputs strictly: inspector exposed {} input indices, \
                 executor reports {} total inputs",
                indices.len(),
                expected
            );
        }

        let wire_labels = inspector.wire_labels();
        let mut seen_labels = std::collections::HashSet::new();
        let mut labels = Vec::with_capacity(expected);
        for (position, idx) in indices.into_iter().enumerate() {
            let candidate = wire_labels.get(&idx).ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot reconcile inputs strictly: missing wire label for input index {} \
                     (position {})",
                    idx,
                    position
                )
            })?;
            let candidate = Self::canonical_input_label(candidate, position);
            if !seen_labels.insert(candidate.clone()) {
                anyhow::bail!(
                    "Cannot reconcile inputs strictly: duplicate input label '{}'",
                    candidate
                );
            }
            labels.push(candidate);
        }

        Ok(labels)
    }

    pub(super) fn reconcile_inputs_with_executor(
        config: &mut FuzzConfig,
        executor: &dyn CircuitExecutor,
    ) -> anyhow::Result<()> {
        let expected = executor
            .num_public_inputs()
            .saturating_add(executor.num_private_inputs());
        if expected == 0 {
            config.campaign.parameters.additional.insert(
                "inputs_reconciled".to_string(),
                serde_yaml::Value::Bool(false),
            );
            return Ok(());
        }

        // Fast path: if count already matches, keep the existing YAML-defined labels.
        if config.inputs.len() == expected {
            config.campaign.parameters.additional.insert(
                "inputs_reconciled".to_string(),
                serde_yaml::Value::Bool(false),
            );
            return Ok(());
        }

        let inferred_labels = Self::infer_ordered_input_labels(executor, expected)?;

        let is_already_aligned = config.inputs.len() == expected
            && config
                .inputs
                .iter()
                .zip(inferred_labels.iter())
                .all(|(spec, inferred)| {
                    Self::normalize_input_name_key(&spec.name)
                        == Self::normalize_input_name_key(inferred)
                });
        if is_already_aligned {
            config.campaign.parameters.additional.insert(
                "inputs_reconciled".to_string(),
                serde_yaml::Value::Bool(false),
            );
            return Ok(());
        }

        let mut existing_by_alias = std::collections::HashMap::new();
        for spec in &config.inputs {
            for alias in Self::input_name_aliases(&spec.name) {
                existing_by_alias
                    .entry(alias)
                    .or_insert_with(|| spec.clone());
            }
        }

        let mut rebuilt = Vec::with_capacity(expected);
        for label in inferred_labels {
            let mut chosen = None;
            for alias in Self::input_name_aliases(&label) {
                if let Some(spec) = existing_by_alias.get(&alias) {
                    chosen = Some(spec.clone());
                    break;
                }
            }

            let mut spec = chosen.unwrap_or_else(|| Input {
                name: label.clone(),
                input_type: "field".to_string(),
                fuzz_strategy: FuzzStrategy::Random,
                constraints: Vec::new(),
                interesting: Vec::new(),
                length: None,
            });

            spec.name = label;
            if spec.input_type.trim().is_empty() {
                spec.input_type = "field".to_string();
            }
            rebuilt.push(spec);
        }

        tracing::warn!(
            "Input schema mismatch detected for target '{}': config has {}, executor expects {}. \
             Reconciled inputs to target-derived ordering for this run.",
            config.campaign.target.circuit_path.display(),
            config.inputs.len(),
            expected
        );
        config.inputs = rebuilt;
        config.campaign.parameters.additional.insert(
            "inputs_reconciled".to_string(),
            serde_yaml::Value::Bool(true),
        );
        Ok(())
    }

    pub(super) fn normalize_oracle_name(name: &str) -> String {
        name.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(|c| c.to_lowercase())
            .collect()
    }

    pub(super) fn disabled_oracle_names(config: &FuzzConfig) -> std::collections::HashSet<String> {
        use std::collections::HashSet;

        let mut disabled = HashSet::new();
        let Some(value) = config
            .campaign
            .parameters
            .additional
            .get("disabled_oracles")
        else {
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
        field_modulus: [u8; 32],
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
                Some(OracleKind::Range) => {
                    add_oracle(Box::new(SemanticOracleAdapter::new(Box::new(
                        RangeProofOracle::new_with_modulus(oracle_config.clone(), field_modulus),
                    ))))
                }
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
                return match s.parse() {
                    Ok(schedule) => schedule,
                    Err(err) => {
                        panic!("Invalid power_schedule '{}': {:?}", s, err);
                    }
                };
            }
        }
        // Default to MMOPT for balanced performance
        PowerSchedule::Mmopt
    }

    pub(super) fn parse_executor_factory_options(
        config: &FuzzConfig,
    ) -> anyhow::Result<ExecutorFactoryOptions> {
        let additional = &config.campaign.parameters.additional;
        let mut options = ExecutorFactoryOptions::default();

        let base = Self::additional_path(additional, "build_dir_base")
            .or_else(|| Self::additional_path(additional, "build_dir"));
        options.build_dir_base = base;

        options.circom_build_dir = Self::additional_path(additional, "circom_build_dir");
        options.noir_build_dir = Self::additional_path(additional, "noir_build_dir");
        options.halo2_build_dir = Self::additional_path(additional, "halo2_build_dir");
        options.cairo_build_dir = Self::additional_path(additional, "cairo_build_dir");

        // Runtime hardening: enforce strict backend availability checks.
        if let Some(strict_backend) = Self::additional_bool(additional, "strict_backend") {
            if !strict_backend {
                tracing::warn!("Ignoring strict_backend=false; strict backend mode is enforced");
            }
        }
        options.strict_backend = true;
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
        if let Some(skip_check) = Self::additional_bool(additional, "circom_skip_constraint_check")
        {
            if skip_check {
                tracing::error!(
                    "Invalid config: circom_skip_constraint_check=true is not allowed because it removes constraint-level coverage"
                );
                anyhow::bail!(
                    "Invalid config: circom_skip_constraint_check=true is disallowed. \
                     Mode 2/3 require real constraint coverage. Set circom_skip_constraint_check: false."
                );
            }
            options.circom_skip_constraint_check = false;
        }
        if let Some(sanity_check) = Self::additional_bool(additional, "circom_witness_sanity_check")
        {
            options.circom_witness_sanity_check = sanity_check;
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

        Ok(options)
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
        Self::add_semantic_oracles_from_config(
            &self.config,
            self.executor.field_modulus(),
            &mut oracles,
        );
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

    pub(super) fn constraint_guided_config(
        &self,
    ) -> anyhow::Result<Option<EnhancedSymbolicConfig>> {
        let additional = &self.config.campaign.parameters.additional;

        if let Some(enabled) = Self::additional_bool(additional, "constraint_guided_enabled") {
            if !enabled {
                return Ok(None);
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
            config.pruning_strategy = Self::parse_pruning_strategy(&strategy)?;
        }

        Ok(Some(config))
    }

    pub(super) fn parse_pruning_strategy(value: &str) -> anyhow::Result<PruningStrategy> {
        let normalized = value.trim().to_lowercase();
        match normalized.as_str() {
            "none" | "off" => Ok(PruningStrategy::None),
            "depth" | "depth_bounded" | "depthbounded" => Ok(PruningStrategy::DepthBounded),
            "constraint" | "constraint_bounded" | "constraintbounded" => {
                Ok(PruningStrategy::ConstraintBounded)
            }
            "coverage" | "coverage_guided" | "coverageguided" => {
                Ok(PruningStrategy::CoverageGuided)
            }
            "random" | "random_sampling" | "randomsampling" => Ok(PruningStrategy::RandomSampling),
            "loop" | "loop_bounded" | "loopbounded" => Ok(PruningStrategy::LoopBounded),
            "similarity" | "similarity_based" | "similaritybased" => {
                Ok(PruningStrategy::SimilarityBased)
            }
            "subsumption" | "subsumption_based" | "subsumptionbased" => {
                Ok(PruningStrategy::SubsumptionBased)
            }
            _ => {
                tracing::error!(
                    "Invalid pruning strategy '{}'; refusing to apply fallback",
                    value
                );
                anyhow::bail!(
                    "Invalid constraint-guided pruning strategy '{}'. \
                     Allowed values: none/off, depth, constraint, coverage, random, loop, similarity, subsumption.",
                    value
                );
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
        let samples = config
            .get("samples")
            .or_else(|| config.get("witness_pairs"))
            .or_else(|| config.get("forge_attempts"))
            .or_else(|| config.get("tests"))
            .and_then(|v| v.as_u64());
        match samples {
            Some(value) => value as usize,
            None => 0,
        }
    }
}
