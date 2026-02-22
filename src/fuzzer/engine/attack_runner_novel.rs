use super::attack_runner_budget::strict_attack_floor;
use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) async fn run_constraint_inference_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::config::v2::InvariantType;
        use crate::oracles::constraint_inference::{ConstraintInferenceEngine, InferenceContext};

        let confidence_threshold = config
            .get("confidence_threshold")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.7);

        let confirm_violations = config
            .get("confirm_violations")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        tracing::info!(
            "Running constraint inference attack (confidence >= {:.0}%)",
            confidence_threshold * 100.0
        );

        let engine = ConstraintInferenceEngine::new()
            .with_confidence_threshold(confidence_threshold)
            .with_generate_violations(true);

        let num_inputs = self.executor.num_public_inputs() + self.executor.num_private_inputs();
        let num_wires = num_inputs.saturating_add(100);
        let mut output_wires = std::collections::HashSet::new();

        tracing::debug!("Analyzing constraints for inference...");
        let mut implied = if let Some(inspector) = self.executor.constraint_inspector() {
            let mut context = InferenceContext::from_inspector(inspector, num_wires);
            self.merge_config_input_labels(inspector, &mut context.wire_labels);
            self.merge_output_labels(inspector, &mut context.wire_labels);
            output_wires.extend(inspector.output_indices());

            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                engine.analyze_with_context(&context)
            })) {
                Ok(result) => {
                    tracing::info!("Found {} implied constraints", result.len());
                    result
                }
                Err(e) => {
                    tracing::error!("FATAL: Constraint analysis panicked: {:?}", e);
                    anyhow::bail!("Constraint analysis panicked during execution");
                }
            }
        } else {
            tracing::error!("FATAL: No constraint inspector available for constraint inference");
            anyhow::bail!("Constraint inspector not available");
        };

        if confirm_violations && !implied.is_empty() {
            tracing::info!("Confirming {} inferred violations...", implied.len());
            let base_inputs = self.generate_test_case().inputs;
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                engine.confirm_violations(
                    self.executor.as_ref(),
                    &base_inputs,
                    &mut implied,
                    &output_wires,
                );
            })) {
                Ok(_) => {
                    tracing::info!("✓ Violation confirmation completed successfully");
                }
                Err(e) => {
                    tracing::error!("FATAL: Violation confirmation panicked: {:?}", e);
                    anyhow::bail!("Violation confirmation panicked during execution");
                }
            }
        }

        // Filter to only confirmed violations (eliminate false positives)
        use crate::oracles::constraint_inference::ViolationConfirmation;
        let before_filter = implied.len();
        implied.retain(|c| c.confirmation == ViolationConfirmation::Confirmed);
        tracing::info!(
            "Filtered {} -> {} violations (keeping only Confirmed, rejecting false positives)",
            before_filter,
            implied.len()
        );

        tracing::debug!("Converting implied constraints to findings...");
        let findings = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine.to_findings(&implied)
        })) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("FATAL: Finding conversion panicked: {:?}", e);
                anyhow::bail!("Finding conversion panicked during execution");
            }
        };

        if !findings.is_empty() {
            let kept =
                self.record_custom_findings(findings, AttackType::ConstraintInference, progress)?;
            tracing::info!("Generated {} findings from constraint inference", kept);
        }

        // Enforce v2 invariants (constraint/range/uniqueness) by attempting violations.
        tracing::debug!("Enforcing v2 invariants...");
        let invariants: Vec<_> = self
            .config
            .get_invariants()
            .into_iter()
            .filter(|inv| inv.invariant_type != InvariantType::Metamorphic)
            .collect();

        let invariant_findings =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.enforce_invariants(&invariants)
            })) {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!("FATAL: Invariant enforcement panicked: {:?}", e);
                    anyhow::bail!("Invariant enforcement panicked during execution");
                }
            };

        if !invariant_findings.is_empty() {
            let kept = self.record_custom_findings(
                invariant_findings,
                AttackType::ConstraintInference,
                progress,
            )?;
            tracing::info!("Generated {} findings from invariant enforcement", kept);
        }

        self.run_constraint_inference_witness_extension(config, &invariants, progress)?;

        tracing::info!("Constraint inference attack completed");
        if let Some(p) = progress {
            p.inc();
        }

        Ok(())
    }

    fn run_constraint_inference_witness_extension(
        &mut self,
        config: &serde_yaml::Value,
        invariants: &[crate::config::v2::Invariant],
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::analysis::{
            ConstraintSubsetStrategy, EnhancedSymbolicConfig, EnhancedSymbolicExecutor,
            ExecutionMode, WitnessExtensionConfig,
        };
        use crate::config::v2::parse_invariant_relation;

        let section = config.get("witness_extension");
        let enabled = section
            .and_then(|value| value.get("enabled"))
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        if !enabled {
            return Ok(());
        }

        let Some(inspector) = self.executor.constraint_inspector() else {
            tracing::warn!(
                "Skipping witness-extension phase: constraint inspector unavailable for target"
            );
            return Ok(());
        };

        let equations = inspector.get_constraints();
        if equations.is_empty() {
            tracing::warn!("Skipping witness-extension phase: no constraints available");
            return Ok(());
        }

        let public_wire_indices = inspector.public_input_indices();
        let mut ordered_wire_indices = inspector.public_input_indices();
        ordered_wire_indices.extend(inspector.private_input_indices());
        if ordered_wire_indices.is_empty() {
            ordered_wire_indices = (0..self.config.inputs.len()).collect();
        }

        let mut wire_labels = inspector.wire_labels();
        self.merge_config_input_labels(inspector, &mut wire_labels);
        self.merge_output_labels(inspector, &mut wire_labels);

        let symbolic_constraints = equations
            .iter()
            .map(|equation| Self::equation_to_symbolic_constraint(equation, &wire_labels))
            .collect::<Vec<_>>();
        if symbolic_constraints.is_empty() {
            tracing::warn!("Skipping witness-extension phase: failed symbolic conversion");
            return Ok(());
        }

        let subset_strategy = match section
            .and_then(|value| value.get("subset_strategy"))
            .and_then(|value| value.as_str())
            .unwrap_or("single")
            .to_ascii_lowercase()
            .as_str()
        {
            "single" | "remove_single" | "remove_single_constraint" => {
                ConstraintSubsetStrategy::RemoveSingleConstraint
            }
            "cluster" | "dependency_cluster" | "remove_dependency_cluster" => {
                ConstraintSubsetStrategy::RemoveDependencyCluster
            }
            "type" | "by_type" | "remove_by_type" => ConstraintSubsetStrategy::RemoveByType,
            _ => ConstraintSubsetStrategy::RemoveSingleConstraint,
        };
        let max_removed_constraints = section
            .and_then(|value| value.get("max_removed_constraints"))
            .and_then(|value| value.as_u64())
            .unwrap_or(3) as usize;
        let max_subsets = section
            .and_then(|value| value.get("max_subsets"))
            .and_then(|value| value.as_u64())
            .unwrap_or(64) as usize;
        let require_invariant_violation = section
            .and_then(|value| value.get("require_invariant_violation"))
            .and_then(|value| value.as_bool())
            .unwrap_or(true);
        let max_analysis_time_ms = section
            .and_then(|value| value.get("max_analysis_time_ms"))
            .and_then(|value| value.as_u64())
            .unwrap_or(60_000);
        let solver_timeout_ms = section
            .and_then(|value| value.get("solver_timeout_ms"))
            .and_then(|value| value.as_u64())
            .unwrap_or(5_000)
            .min(u32::MAX as u64) as u32;

        let semantic_invariants = invariants
            .iter()
            .filter_map(|invariant| {
                let ast = parse_invariant_relation(&invariant.relation).ok()?;
                Self::invariant_ast_to_symbolic_constraint(&ast)
            })
            .collect::<Vec<_>>();

        if semantic_invariants.is_empty() {
            tracing::warn!(
                "Witness-extension semantic integration: no parseable invariants were available"
            );
            if require_invariant_violation {
                return Ok(());
            }
        }

        let base_witness_attempts = section
            .and_then(|value| value.get("base_witness_attempts"))
            .and_then(|value| value.as_u64())
            .unwrap_or(32) as usize;
        let mut base_witness = None;

        for witness in self.collect_corpus_inputs(base_witness_attempts.saturating_mul(2).max(8)) {
            if self.executor.execute_sync(&witness).success {
                base_witness = Some(witness);
                break;
            }
        }
        if base_witness.is_none() {
            for _ in 0..base_witness_attempts {
                if self.wall_clock_timeout_reached() {
                    break;
                }
                let candidate = self.generate_test_case().inputs;
                if self.executor.execute_sync(&candidate).success {
                    base_witness = Some(candidate);
                    break;
                }
            }
        }
        let Some(base_witness) = base_witness else {
            tracing::warn!("Skipping witness-extension phase: no valid base witness available");
            return Ok(());
        };

        if ordered_wire_indices.is_empty() {
            ordered_wire_indices = (0..base_witness.len()).collect();
        }

        let mut assignments = std::collections::HashMap::new();
        for (input_idx, value) in base_witness.iter().enumerate() {
            let wire_idx = ordered_wire_indices
                .get(input_idx)
                .copied()
                .unwrap_or(input_idx);
            assignments.insert(format!("w_{}", wire_idx), value.clone());
            if let Some(label) = wire_labels.get(&wire_idx) {
                assignments.insert(Self::sanitize_symbol_name(label), value.clone());
            }
        }

        let mut fixed_symbols = std::collections::HashSet::new();
        for wire_idx in public_wire_indices {
            fixed_symbols.insert(format!("w_{}", wire_idx));
            if let Some(label) = wire_labels.get(&wire_idx) {
                fixed_symbols.insert(Self::sanitize_symbol_name(label));
            }
        }

        let mut symbolic = EnhancedSymbolicExecutor::with_config(
            self.config.inputs.len().max(1),
            EnhancedSymbolicConfig {
                max_paths: max_subsets.max(1),
                max_depth: symbolic_constraints.len().min(1024).max(1),
                solver_timeout_ms,
                random_seed: self.seed,
                pruning_strategy: crate::analysis::PruningStrategy::DepthBounded,
                simplify_constraints: true,
                incremental_solving: true,
                solutions_per_path: 1,
                loop_bound: 1,
                execution_mode: ExecutionMode::WitnessExtension,
                witness_extension: WitnessExtensionConfig {
                    enabled: true,
                    subset_strategy,
                    max_removed_constraints: max_removed_constraints.max(1),
                    max_subsets: max_subsets.max(1),
                    require_invariant_violation,
                    max_analysis_time_ms,
                },
            },
        );

        let results = symbolic.run_witness_extension(
            &symbolic_constraints,
            &assignments,
            &fixed_symbols,
            &semantic_invariants,
        );

        if results.is_empty() {
            tracing::info!("Witness-extension phase completed with no violating candidates");
            return Ok(());
        }

        let findings = results
            .iter()
            .map(|result| {
                let severity = if result.removed_indices.len() <= 3
                    && !result.violated_invariants.is_empty()
                {
                    Severity::Critical
                } else {
                    Severity::High
                };

                let witness_b = Self::assignment_map_to_inputs(
                    &result.assignments,
                    &base_witness,
                    &ordered_wire_indices,
                    &wire_labels,
                );

                Finding {
                    attack_type: AttackType::ConstraintInference,
                    severity,
                    description: format!(
                        "Witness-extension candidate found by removing constraints {:?}: {} removed constraints checked, {} violated semantic invariants.",
                        result.removed_indices,
                        result.removed_constraints_total,
                        result.violated_invariants.len()
                    ),
                    poc: ProofOfConcept {
                        witness_a: base_witness.clone(),
                        witness_b: Some(witness_b),
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: Some("witness_extension".to_string()),
                }
            })
            .collect::<Vec<_>>();

        let kept =
            self.record_custom_findings(findings, AttackType::ConstraintInference, progress)?;
        tracing::info!(
            "Witness-extension semantic integration produced {} findings",
            kept
        );
        Ok(())
    }

    fn equation_to_symbolic_constraint(
        equation: &zk_core::ConstraintEquation,
        wire_labels: &std::collections::HashMap<usize, String>,
    ) -> crate::analysis::SymbolicConstraint {
        use crate::analysis::{SymbolicConstraint, SymbolicValue};

        fn lc_to_value(
            terms: &[(usize, FieldElement)],
            labels: &std::collections::HashMap<usize, String>,
        ) -> SymbolicValue {
            let mut iter = terms.iter();
            let Some((first_idx, first_coeff)) = iter.next() else {
                return SymbolicValue::concrete(FieldElement::zero());
            };

            let first_term =
                FuzzingEngine::symbolic_term_from_coeff(*first_idx, first_coeff.clone(), labels);
            iter.fold(first_term, |acc, (idx, coeff)| {
                let term = FuzzingEngine::symbolic_term_from_coeff(*idx, coeff.clone(), labels);
                SymbolicValue::Add(Box::new(acc), Box::new(term))
            })
        }

        SymbolicConstraint::R1CS {
            a: lc_to_value(&equation.a_terms, wire_labels),
            b: lc_to_value(&equation.b_terms, wire_labels),
            c: lc_to_value(&equation.c_terms, wire_labels),
        }
    }

    fn symbolic_term_from_coeff(
        wire_idx: usize,
        coeff: FieldElement,
        wire_labels: &std::collections::HashMap<usize, String>,
    ) -> crate::analysis::SymbolicValue {
        use crate::analysis::SymbolicValue;
        let symbol = wire_labels
            .get(&wire_idx)
            .map(|value| Self::sanitize_symbol_name(value))
            .unwrap_or_else(|| format!("w_{}", wire_idx));

        let value = SymbolicValue::symbol(&symbol);
        if coeff.is_one() {
            value
        } else {
            SymbolicValue::Mul(Box::new(SymbolicValue::concrete(coeff)), Box::new(value))
        }
    }

    fn sanitize_symbol_name(raw: &str) -> String {
        let mut out = String::new();
        for ch in raw.chars() {
            if ch.is_ascii_alphanumeric() {
                out.push(ch.to_ascii_lowercase());
            } else {
                out.push('_');
            }
        }
        let out = out.trim_matches('_').to_string();
        if out.is_empty() {
            "symbol".to_string()
        } else {
            out
        }
    }

    fn invariant_ast_to_symbolic_constraint(
        ast: &crate::config::v2::InvariantAST,
    ) -> Option<crate::analysis::SymbolicConstraint> {
        use crate::analysis::{SymbolicConstraint, SymbolicValue};
        use crate::config::v2::InvariantAST;

        match ast {
            InvariantAST::Equals(left, right) => Some(SymbolicConstraint::Eq(
                Self::invariant_ast_to_symbolic_value(left),
                Self::invariant_ast_to_symbolic_value(right),
            )),
            InvariantAST::NotEquals(left, right) => Some(SymbolicConstraint::Neq(
                Self::invariant_ast_to_symbolic_value(left),
                Self::invariant_ast_to_symbolic_value(right),
            )),
            InvariantAST::LessThan(left, right) => Some(SymbolicConstraint::Lt(
                Self::invariant_ast_to_symbolic_value(left),
                Self::invariant_ast_to_symbolic_value(right),
            )),
            InvariantAST::LessThanOrEqual(left, right) => Some(SymbolicConstraint::Lte(
                Self::invariant_ast_to_symbolic_value(left),
                Self::invariant_ast_to_symbolic_value(right),
            )),
            InvariantAST::GreaterThan(left, right) => Some(SymbolicConstraint::Lt(
                Self::invariant_ast_to_symbolic_value(right),
                Self::invariant_ast_to_symbolic_value(left),
            )),
            InvariantAST::GreaterThanOrEqual(left, right) => Some(SymbolicConstraint::Lte(
                Self::invariant_ast_to_symbolic_value(right),
                Self::invariant_ast_to_symbolic_value(left),
            )),
            InvariantAST::Range {
                lower,
                value,
                upper,
                inclusive_lower,
                inclusive_upper,
            } => {
                let lower_check = if *inclusive_lower {
                    SymbolicConstraint::Lte(
                        Self::invariant_ast_to_symbolic_value(lower),
                        Self::invariant_ast_to_symbolic_value(value),
                    )
                } else {
                    SymbolicConstraint::Lt(
                        Self::invariant_ast_to_symbolic_value(lower),
                        Self::invariant_ast_to_symbolic_value(value),
                    )
                };
                let upper_check = if *inclusive_upper {
                    SymbolicConstraint::Lte(
                        Self::invariant_ast_to_symbolic_value(value),
                        Self::invariant_ast_to_symbolic_value(upper),
                    )
                } else {
                    SymbolicConstraint::Lt(
                        Self::invariant_ast_to_symbolic_value(value),
                        Self::invariant_ast_to_symbolic_value(upper),
                    )
                };
                Some(SymbolicConstraint::And(
                    Box::new(lower_check),
                    Box::new(upper_check),
                ))
            }
            InvariantAST::InSet(_, _) | InvariantAST::ForAll { .. } => None,
            InvariantAST::Identifier(_)
            | InvariantAST::ArrayAccess(_, _)
            | InvariantAST::Call(_, _)
            | InvariantAST::Literal(_)
            | InvariantAST::Power(_, _)
            | InvariantAST::Set(_)
            | InvariantAST::Raw(_) => Some(SymbolicConstraint::Eq(
                Self::invariant_ast_to_symbolic_value(ast),
                SymbolicValue::concrete(FieldElement::one()),
            )),
        }
    }

    fn invariant_ast_to_symbolic_value(
        ast: &crate::config::v2::InvariantAST,
    ) -> crate::analysis::SymbolicValue {
        use crate::analysis::SymbolicValue;
        use crate::config::v2::InvariantAST;

        match ast {
            InvariantAST::Identifier(name) => {
                SymbolicValue::symbol(&Self::sanitize_symbol_name(name))
            }
            InvariantAST::ArrayAccess(name, index) => {
                SymbolicValue::symbol(&Self::sanitize_symbol_name(&format!("{}_{}", name, index)))
            }
            InvariantAST::Call(name, args) => {
                let joined = args.join("_");
                SymbolicValue::symbol(&Self::sanitize_symbol_name(&format!("{}_{}", name, joined)))
            }
            InvariantAST::Literal(value) => {
                if let Ok(parsed) = value.parse::<u64>() {
                    SymbolicValue::concrete(FieldElement::from_u64(parsed))
                } else if let Ok(parsed) = FieldElement::from_hex(value) {
                    SymbolicValue::concrete(parsed)
                } else {
                    SymbolicValue::symbol(&Self::sanitize_symbol_name(value))
                }
            }
            InvariantAST::Power(base, exp) => {
                if let (Ok(base_u), Ok(exp_u)) = (base.parse::<u64>(), exp.parse::<u32>()) {
                    if exp_u <= 63 {
                        if let Some(pow) = base_u.checked_pow(exp_u) {
                            return SymbolicValue::concrete(FieldElement::from_u64(pow));
                        }
                    }
                }
                SymbolicValue::symbol(&Self::sanitize_symbol_name(&format!(
                    "pow_{}_{}",
                    base, exp
                )))
            }
            InvariantAST::Raw(raw) => SymbolicValue::symbol(&Self::sanitize_symbol_name(raw)),
            _ => SymbolicValue::symbol("unsupported_term"),
        }
    }

    fn assignment_map_to_inputs(
        assignments: &std::collections::HashMap<String, FieldElement>,
        baseline_inputs: &[FieldElement],
        wire_indices: &[usize],
        wire_labels: &std::collections::HashMap<usize, String>,
    ) -> Vec<FieldElement> {
        let mut out = baseline_inputs.to_vec();
        for (input_idx, value) in out.iter_mut().enumerate() {
            let wire_idx = wire_indices.get(input_idx).copied().unwrap_or(input_idx);
            let fallback = format!("w_{}", wire_idx);
            if let Some(candidate) = assignments.get(&fallback) {
                *value = candidate.clone();
                continue;
            }
            if let Some(label) = wire_labels.get(&wire_idx) {
                let alias = Self::sanitize_symbol_name(label);
                if let Some(candidate) = assignments.get(&alias) {
                    *value = candidate.clone();
                }
            }
        }
        out
    }

    pub(super) async fn run_metamorphic_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::metamorphic::MetamorphicOracle;

        let configured_num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;
        let num_tests = self.bounded_attack_units(
            configured_num_tests,
            1,
            "metamorphic_num_tests_cap",
            "metamorphic.num_tests",
        );

        tracing::info!(
            "Running metamorphic testing with {} base witnesses",
            num_tests
        );

        let mut oracle = MetamorphicOracle::new().with_circuit_aware_relations();
        let invariant_relations = self.build_metamorphic_relations();
        for relation in invariant_relations {
            oracle = oracle.with_relation(relation);
        }

        // Generate base witnesses and test metamorphic relations
        for _ in 0..num_tests {
            if self.wall_clock_timeout_reached() {
                tracing::warn!("Stopping metamorphic attack early: wall-clock timeout reached");
                break;
            }
            let base_witness = self.generate_test_case();
            let results = oracle
                .test_all(self.executor.as_ref(), &base_witness.inputs)
                .await;

            let findings = oracle.to_findings(&results);
            if !findings.is_empty() {
                self.with_findings_write(|store| store.extend(findings.iter().cloned()))?;
                if let Some(p) = progress {
                    for finding in &findings {
                        p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                    }
                }
            }

            if let Some(p) = progress {
                p.inc();
            }
        }

        Ok(())
    }

    pub(super) async fn run_constraint_slice_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::constraint_slice::{ConstraintSliceOracle, OutputMapping};

        let configured_samples_per_cone = config
            .get("samples_per_cone")
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;
        let configured_samples_per_cone = strict_attack_floor(
            &self.config.campaign.parameters.additional,
            configured_samples_per_cone,
            32,
            "constraint_slice.samples_per_cone",
        );
        let samples_per_cone = self.bounded_attack_units(
            configured_samples_per_cone,
            1,
            "constraint_slice_samples_per_cone_cap",
            "constraint_slice.samples_per_cone",
        );

        let configured_base_witness_attempts = config
            .get("base_witness_attempts")
            .and_then(|v| v.as_u64())
            .unwrap_or(16) as usize;
        let configured_base_witness_attempts = strict_attack_floor(
            &self.config.campaign.parameters.additional,
            configured_base_witness_attempts,
            32,
            "constraint_slice.base_witness_attempts",
        );
        let base_witness_attempts = self.bounded_attack_units(
            configured_base_witness_attempts,
            1,
            "constraint_slice_base_witness_attempts_cap",
            "constraint_slice.base_witness_attempts",
        );

        tracing::info!(
            "Running constraint slice analysis ({} samples/cone)",
            samples_per_cone
        );

        let oracle = ConstraintSliceOracle::new().with_samples(samples_per_cone);

        // Generate a base witness that successfully executes.
        // Start with fresh generation, then fall back to corpus-derived witnesses.
        let mut base_witness_inputs: Option<Vec<FieldElement>> = None;
        let attempts = base_witness_attempts.max(1);
        for _ in 0..attempts {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping constraint-slice base witness search early: wall-clock timeout reached"
                );
                break;
            }
            let candidate = self.generate_test_case();
            let result = self.executor.execute_sync(&candidate.inputs);
            if result.success {
                base_witness_inputs = Some(candidate.inputs);
                break;
            }
        }

        if base_witness_inputs.is_none() {
            let corpus_probe_count = attempts.saturating_mul(4).max(16);
            for witness in self.collect_corpus_inputs(corpus_probe_count) {
                if self.wall_clock_timeout_reached() {
                    tracing::warn!(
                        "Stopping constraint-slice corpus witness fallback early: wall-clock timeout reached"
                    );
                    break;
                }
                let result = self.executor.execute_sync(&witness);
                if result.success {
                    tracing::info!(
                        "Constraint-slice base witness recovered via corpus fallback (probe_count={})",
                        corpus_probe_count
                    );
                    base_witness_inputs = Some(witness);
                    break;
                }
            }
        }

        let Some(base_witness_inputs) = base_witness_inputs else {
            tracing::warn!(
                "Skipping constraint slice attack: failed to find a valid base witness after {} generated attempts plus corpus fallback",
                attempts,
            );
            return Ok(());
        };

        // Determine output wire indices (prefer inspector-provided outputs)
        let outputs: Vec<OutputMapping> = if let Some(inspector) =
            self.executor.constraint_inspector()
        {
            let output_wires = inspector.output_indices();
            if !output_wires.is_empty() {
                output_wires
                    .into_iter()
                    .enumerate()
                    .map(|(output_index, output_wire)| OutputMapping {
                        output_index,
                        output_wire,
                    })
                    .collect()
            } else {
                let num_inputs =
                    self.executor.num_public_inputs() + self.executor.num_private_inputs();
                vec![OutputMapping {
                    output_index: 0,
                    output_wire: num_inputs,
                }]
            }
        } else {
            let num_inputs = self.executor.num_public_inputs() + self.executor.num_private_inputs();
            vec![OutputMapping {
                output_index: 0,
                output_wire: num_inputs,
            }]
        };

        let findings = oracle
            .run(self.executor.as_ref(), &base_witness_inputs, &outputs)
            .await;

        let _kept = self.record_custom_findings(findings, AttackType::ConstraintSlice, progress)?;

        if let Some(p) = progress {
            p.inc();
        }

        Ok(())
    }

    fn spec_inference_boundary_values() -> Vec<FieldElement> {
        vec![
            FieldElement::zero(),
            FieldElement::one(),
            FieldElement::from_u64(2),
            FieldElement::half_modulus(),
            FieldElement::max_value(),
        ]
    }

    fn append_spec_inference_boundary_witnesses(
        witnesses: &mut Vec<Vec<FieldElement>>,
        target_count: usize,
        template: &[FieldElement],
        boundary_values: &[FieldElement],
    ) -> usize {
        use std::collections::HashSet;
        fn push_unique_candidate(
            witnesses: &mut Vec<Vec<FieldElement>>,
            seen: &mut HashSet<Vec<FieldElement>>,
            candidate: Vec<FieldElement>,
            target_count: usize,
        ) -> bool {
            if witnesses.len() >= target_count {
                return false;
            }
            if seen.insert(candidate.clone()) {
                witnesses.push(candidate);
                return true;
            }
            false
        }

        if target_count == 0 || template.is_empty() || boundary_values.is_empty() {
            return 0;
        }

        let mut seen: HashSet<Vec<FieldElement>> = witnesses.iter().cloned().collect();
        let mut added = 0usize;

        let width = template.len();
        let max_value = FieldElement::max_value();

        if push_unique_candidate(
            witnesses,
            &mut seen,
            vec![FieldElement::zero(); width],
            target_count,
        ) {
            added += 1;
        }
        if push_unique_candidate(
            witnesses,
            &mut seen,
            vec![FieldElement::one(); width],
            target_count,
        ) {
            added += 1;
        }
        if push_unique_candidate(
            witnesses,
            &mut seen,
            vec![max_value.clone(); width],
            target_count,
        ) {
            added += 1;
        }

        let mut alternating = Vec::with_capacity(width);
        for idx in 0..width {
            if idx % 2 == 0 {
                alternating.push(FieldElement::zero());
            } else {
                alternating.push(max_value.clone());
            }
        }
        if push_unique_candidate(witnesses, &mut seen, alternating, target_count) {
            added += 1;
        }

        let single_width = width.min(16);
        for idx in 0..single_width {
            if witnesses.len() >= target_count {
                break;
            }
            for value in boundary_values {
                let mut witness = template.to_vec();
                witness[idx] = value.clone();
                if push_unique_candidate(witnesses, &mut seen, witness, target_count) {
                    added += 1;
                }
            }
        }

        let pair_width = width.min(8);
        let mut pair_values = vec![FieldElement::zero(), FieldElement::one()];
        if !pair_values.contains(&max_value) {
            pair_values.push(max_value.clone());
        }

        for i in 0..pair_width {
            if witnesses.len() >= target_count {
                break;
            }
            for j in (i + 1)..pair_width {
                if witnesses.len() >= target_count {
                    break;
                }
                for left in &pair_values {
                    if witnesses.len() >= target_count {
                        break;
                    }
                    for right in &pair_values {
                        let mut witness = template.to_vec();
                        witness[i] = left.clone();
                        witness[j] = right.clone();
                        if push_unique_candidate(witnesses, &mut seen, witness, target_count) {
                            added += 1;
                        }
                    }
                }
            }
        }

        added
    }

    pub(super) async fn run_spec_inference_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
        phase_context: Option<(u64, u64, u64, u64)>,
    ) -> anyhow::Result<()> {
        use crate::oracles::spec_inference::SpecInferenceOracle;

        let configured_sample_count = config
            .get("sample_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(500) as usize;
        let configured_sample_count = strict_attack_floor(
            &self.config.campaign.parameters.additional,
            configured_sample_count,
            1000,
            "spec_inference.sample_count",
        );
        let sample_count = self.bounded_attack_units(
            configured_sample_count,
            1,
            "spec_inference_sample_count_cap",
            "spec_inference.sample_count",
        );
        let configured_auto_invariant_cap = config
            .get("auto_invariant_cap")
            .and_then(|v| v.as_u64())
            .unwrap_or(64) as usize;
        let auto_invariant_cap = self.bounded_attack_units(
            configured_auto_invariant_cap,
            1,
            "spec_inference_auto_invariant_cap",
            "spec_inference.auto_invariant_cap",
        );
        let evidence_mode =
            Self::additional_bool(&self.config.campaign.parameters.additional, "evidence_mode")
                .unwrap_or_default();

        // Depth contract: SpecInference must run full depth in Mode 2.
        // Do not accept YAML knobs that would cap work or reduce attempt depth.
        if evidence_mode
            && (config.get("max_specs").is_some()
                || config.get("max_wall_clock_secs").is_some()
                || config.get("violation_attempts").is_some())
        {
            anyhow::bail!(
                "SpecInference depth-limiting knobs are not allowed in evidence mode: \
                 remove 'max_specs', 'max_wall_clock_secs', and 'violation_attempts' from the campaign YAML"
            );
        }

        tracing::info!("Running spec inference attack ({} samples)", sample_count);

        let oracle = SpecInferenceOracle::new()
            .with_sample_count(sample_count)
            .with_confidence_threshold(0.9)
            .with_wire_labels(self.input_labels());

        let boundary_seed_enabled = config
            .get("boundary_seeding")
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        // Generate initial witnesses
        let mut initial_witnesses = Vec::with_capacity(sample_count.max(1));
        let mut boundary_seeded = 0usize;
        if boundary_seed_enabled {
            let template = self.generate_test_case().inputs;
            let boundary_values = Self::spec_inference_boundary_values();
            boundary_seeded = Self::append_spec_inference_boundary_witnesses(
                &mut initial_witnesses,
                sample_count.max(1),
                &template,
                &boundary_values,
            );
        }

        let mut random_seeded = 0usize;
        while initial_witnesses.len() < sample_count.max(1) {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping spec-inference witness seeding early: wall-clock timeout reached"
                );
                break;
            }
            initial_witnesses.push(self.generate_test_case().inputs);
            random_seeded = random_seeded.saturating_add(1);
        }
        tracing::info!(
            "Spec inference witness seeding mix: boundary_guided={} random={} total={}",
            boundary_seeded,
            random_seeded,
            initial_witnesses.len()
        );

        let mode_label = if evidence_mode { "evidence" } else { "run" };

        let run_result = if let Some((phases_total, phases_completed, attack_idx, attacks_total)) =
            phase_context
        {
            let mut last_snapshot = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(60))
                .unwrap_or_else(std::time::Instant::now);
            oracle
                .run_with_progress_and_specs(
                    self.executor.as_ref(),
                    &initial_witnesses,
                    |spec_idx, specs_total| {
                        let now = std::time::Instant::now();
                        let is_last = spec_idx.saturating_add(1) >= specs_total;
                        let should_emit = spec_idx == 0
                            || is_last
                            || now.duration_since(last_snapshot)
                                >= std::time::Duration::from_secs(15);
                        if !should_emit {
                            return;
                        }
                        last_snapshot = now;

                        let denom = specs_total.max(1) as f64;
                        let phase_progress =
                            ((spec_idx.saturating_add(1) as f64) / denom).clamp(0.0, 1.0);
                        self.write_progress_snapshot(
                            mode_label,
                            "attack_progress",
                            phases_total,
                            phases_completed,
                            Some(phase_progress),
                            serde_json::json!({
                                "attack_idx": attack_idx,
                                "attacks_total": attacks_total,
                                "attack_type": "SpecInference",
                                "specs_total": specs_total,
                                "specs_tested": spec_idx.saturating_add(1),
                            }),
                        );
                    },
                )
                .await
        } else {
            oracle
                .run_with_progress_and_specs(
                    self.executor.as_ref(),
                    &initial_witnesses,
                    |_spec_idx, _specs_total| {},
                )
                .await
        };
        let findings = run_result.findings;

        let auto_invariants =
            self.spec_inference_specs_to_invariants(&run_result.inferred_specs, auto_invariant_cap);
        let registered_auto_invariants = self.register_spec_inference_invariants(auto_invariants);
        if registered_auto_invariants > 0 {
            tracing::info!(
                "Spec inference integrated {} auto-generated invariants (inferred_specs={}, accepted_samples={})",
                registered_auto_invariants,
                run_result.inferred_specs.len(),
                run_result.samples_collected
            );
        } else {
            tracing::debug!(
                "Spec inference produced no new auto-generated invariants (inferred_specs={}, cap={})",
                run_result.inferred_specs.len(),
                auto_invariant_cap
            );
        }

        if !findings.is_empty() {
            self.with_findings_write(|store| store.extend(findings.iter().cloned()))?;
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        if let Some(p) = progress {
            p.inc();
        }

        Ok(())
    }

    fn register_spec_inference_invariants(
        &mut self,
        invariants: Vec<crate::config::v2::Invariant>,
    ) -> usize {
        if invariants.is_empty() {
            return 0;
        }

        if let Some(checker) = self.invariant_checker.as_mut() {
            checker.register_runtime_invariants(invariants)
        } else {
            let accepted = invariants.len();
            self.invariant_checker = Some(InvariantChecker::new(invariants, &self.config.inputs));
            accepted
        }
    }

    fn spec_inference_specs_to_invariants(
        &self,
        specs: &[crate::oracles::spec_inference::InferredSpec],
        cap: usize,
    ) -> Vec<crate::config::v2::Invariant> {
        let mut invariants = Vec::new();
        for (idx, spec) in specs.iter().enumerate() {
            if invariants.len() >= cap {
                break;
            }
            if let Some(invariant) = self.spec_inference_spec_to_invariant(spec, idx) {
                invariants.push(invariant);
            }
        }
        invariants
    }

    fn spec_inference_spec_to_invariant(
        &self,
        spec: &crate::oracles::spec_inference::InferredSpec,
        idx: usize,
    ) -> Option<crate::config::v2::Invariant> {
        use crate::config::v2::{Invariant, InvariantOracle, InvariantType};
        use crate::oracles::spec_inference::InferredSpec::{
            BitwiseConstraint, ConstantValue, Equality, Inequality, LinearRelation, NonZero,
            RangeCheck,
        };

        let severity = if spec.confidence() >= 0.99 {
            "critical"
        } else if spec.confidence() >= 0.95 {
            "high"
        } else {
            "medium"
        }
        .to_string();

        let description = format!(
            "Auto-generated from spec inference ({:.1}% confidence): {}",
            spec.confidence() * 100.0,
            spec.description()
        );

        let (name, invariant_type, relation) = match spec {
            RangeCheck {
                input_index,
                observed_min,
                observed_max,
                ..
            } => {
                let input_name = self.spec_input_name(*input_index)?;
                (
                    format!(
                        "auto_spec_range_{}_{}",
                        idx,
                        self.sanitize_spec_fragment(input_name)
                    ),
                    InvariantType::Range,
                    format!("{} <= {} <= {}", observed_min, input_name, observed_max),
                )
            }
            BitwiseConstraint {
                input_index,
                bit_length,
                ..
            } => {
                let input_name = self.spec_input_name(*input_index)?;
                (
                    format!(
                        "auto_spec_bitwise_{}_{}",
                        idx,
                        self.sanitize_spec_fragment(input_name)
                    ),
                    InvariantType::Range,
                    format!("0 <= {} < 2^{}", input_name, bit_length),
                )
            }
            NonZero { wire_index, .. } => {
                let input_name = self.spec_input_name(*wire_index)?;
                (
                    format!(
                        "auto_spec_nonzero_{}_{}",
                        idx,
                        self.sanitize_spec_fragment(input_name)
                    ),
                    InvariantType::Constraint,
                    format!("{} != 0", input_name),
                )
            }
            ConstantValue {
                wire_index, value, ..
            } => {
                let input_name = self.spec_input_name(*wire_index)?;
                (
                    format!(
                        "auto_spec_constant_{}_{}",
                        idx,
                        self.sanitize_spec_fragment(input_name)
                    ),
                    InvariantType::Constraint,
                    format!("{} == {}", input_name, value.to_decimal_string()),
                )
            }
            Equality { wire_a, wire_b, .. } => {
                let lhs = self.spec_input_name(*wire_a)?;
                let rhs = self.spec_input_name(*wire_b)?;
                (
                    format!(
                        "auto_spec_equal_{}_{}_{}",
                        idx,
                        self.sanitize_spec_fragment(lhs),
                        self.sanitize_spec_fragment(rhs)
                    ),
                    InvariantType::Constraint,
                    format!("{} == {}", lhs, rhs),
                )
            }
            Inequality { wire_a, wire_b, .. } => {
                let lhs = self.spec_input_name(*wire_a)?;
                let rhs = self.spec_input_name(*wire_b)?;
                (
                    format!(
                        "auto_spec_neq_{}_{}_{}",
                        idx,
                        self.sanitize_spec_fragment(lhs),
                        self.sanitize_spec_fragment(rhs)
                    ),
                    InvariantType::Constraint,
                    format!("{} != {}", lhs, rhs),
                )
            }
            LinearRelation { .. } => {
                tracing::debug!(
                    "Skipping linear relation inferred spec for auto-invariant conversion: {}",
                    spec.description()
                );
                return None;
            }
        };

        Some(Invariant {
            name,
            invariant_type,
            relation,
            oracle: InvariantOracle::MustHold,
            transform: None,
            expected: None,
            description: Some(description),
            severity: Some(severity),
        })
    }

    fn spec_input_name(&self, wire_index: usize) -> Option<&str> {
        self.config
            .inputs
            .get(wire_index)
            .map(|input| input.name.as_str())
    }

    fn sanitize_spec_fragment(&self, raw: &str) -> String {
        let mut out = String::new();
        for ch in raw.chars() {
            if ch.is_ascii_alphanumeric() {
                out.push(ch.to_ascii_lowercase());
            } else {
                out.push('_');
            }
        }
        let out = out.trim_matches('_').to_string();
        if out.is_empty() {
            "wire".to_string()
        } else {
            out
        }
    }

    pub(super) async fn run_witness_collision_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::witness_collision::WitnessCollisionDetector;

        let configured_samples = config
            .get("samples")
            .and_then(|v| v.as_u64())
            .unwrap_or(10000) as usize;
        let configured_samples = strict_attack_floor(
            &self.config.campaign.parameters.additional,
            configured_samples,
            2000,
            "witness_collision.samples",
        );
        let samples = self.bounded_attack_units(
            configured_samples,
            1,
            "witness_collision_samples_cap",
            "witness_collision.samples",
        );

        let scope_public_inputs = config
            .get("scope_public_inputs")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        tracing::info!("Running witness collision detection ({} samples)", samples);

        let mut detector = WitnessCollisionDetector::new()
            .with_samples(samples)
            .with_public_input_scope(scope_public_inputs);

        if scope_public_inputs {
            let public_input_indices = if let Some(inspector) = self.executor.constraint_inspector()
            {
                let public_wires: std::collections::HashSet<_> =
                    inspector.public_input_indices().into_iter().collect();
                let mut wire_indices = inspector.public_input_indices();
                wire_indices.extend(inspector.private_input_indices());
                if wire_indices.is_empty() {
                    wire_indices = (0..self.config.inputs.len()).collect();
                }
                wire_indices
                    .into_iter()
                    .enumerate()
                    .filter_map(|(input_idx, wire_idx)| {
                        if public_wires.contains(&wire_idx) {
                            Some(input_idx)
                        } else {
                            None
                        }
                    })
                    .collect()
            } else {
                (0..self
                    .executor
                    .num_public_inputs()
                    .min(self.config.inputs.len()))
                    .collect()
            };
            detector = detector.with_public_input_indices(public_input_indices);
        }

        // Generate witnesses
        let mut witnesses = Vec::with_capacity(samples);
        for _ in 0..samples {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping witness-collision sample generation early: wall-clock timeout reached"
                );
                break;
            }
            witnesses.push(self.generate_test_case().inputs);
        }

        let collisions = detector.run(self.executor.as_ref(), &witnesses).await;
        let findings = detector.to_findings(&collisions);

        if !findings.is_empty() {
            self.with_findings_write(|store| store.extend(findings.iter().cloned()))?;
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        if let Some(p) = progress {
            p.inc();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_inference_boundary_witnesses_add_edge_cases_and_pairs() {
        let template = vec![
            FieldElement::from_u64(9),
            FieldElement::from_u64(7),
            FieldElement::from_u64(5),
        ];
        let mut witnesses = Vec::new();
        let boundary_values = FuzzingEngine::spec_inference_boundary_values();
        let added = FuzzingEngine::append_spec_inference_boundary_witnesses(
            &mut witnesses,
            128,
            &template,
            &boundary_values,
        );
        assert!(added > 0);
        assert!(witnesses
            .iter()
            .any(|witness| witness.iter().all(FieldElement::is_zero)));
        assert!(witnesses
            .iter()
            .any(|witness| witness[0] == FieldElement::max_value() && witness[1].is_zero()));
    }

    #[test]
    fn spec_inference_boundary_witnesses_respect_target_limit() {
        let template = vec![FieldElement::from_u64(3), FieldElement::from_u64(4)];
        let mut witnesses = Vec::new();
        let boundary_values = FuzzingEngine::spec_inference_boundary_values();
        let added = FuzzingEngine::append_spec_inference_boundary_witnesses(
            &mut witnesses,
            2,
            &template,
            &boundary_values,
        );
        assert!(added <= 2);
        assert_eq!(witnesses.len(), 2);
    }

    #[test]
    fn spec_inference_boundary_witnesses_skip_empty_templates() {
        let mut witnesses = Vec::new();
        let boundary_values = FuzzingEngine::spec_inference_boundary_values();
        let added = FuzzingEngine::append_spec_inference_boundary_witnesses(
            &mut witnesses,
            16,
            &[],
            &boundary_values,
        );
        assert_eq!(added, 0);
        assert!(witnesses.is_empty());
    }
}
