use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) fn record_invariant_violation(
        &self,
        violation: &crate::fuzzer::invariant_checker::Violation,
        test_case: &TestCase,
    ) {
        use zk_core::{Finding, ProofOfConcept};

        let severity = match violation.severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Medium,
        };

        let finding = Finding {
            attack_type: AttackType::ConstraintInference,
            severity,
            description: format!(
                "Invariant '{}' violated: {}\nRelation: {}\nEvidence: {}",
                violation.invariant_name,
                if violation.circuit_accepted {
                    "Circuit ACCEPTED violating witness"
                } else {
                    "Violation detected"
                },
                violation.relation,
                violation.evidence
            ),
            poc: ProofOfConcept {
                witness_a: test_case.inputs.clone(),
                witness_b: None,
                public_inputs: vec![],
                proof: None,
            },
            location: Some(format!("Invariant: {}", violation.invariant_name)),
        };

        if let Ok(mut findings) = self.core.findings().write() {
            findings.push(finding);
        }
    }

    pub(super) fn severity_from_invariant(
        &self,
        invariant: &crate::config::v2::Invariant,
    ) -> Severity {
        match invariant.severity.as_deref().map(|s| s.to_lowercase()) {
            Some(ref s) if s == "critical" => Severity::Critical,
            Some(ref s) if s == "high" => Severity::High,
            Some(ref s) if s == "medium" => Severity::Medium,
            Some(ref s) if s == "low" => Severity::Low,
            Some(ref s) if s == "info" => Severity::Info,
            _ => match invariant.invariant_type {
                crate::config::v2::InvariantType::Range => Severity::High,
                crate::config::v2::InvariantType::Uniqueness => Severity::Critical,
                crate::config::v2::InvariantType::Metamorphic => Severity::High,
                _ => Severity::Medium,
            },
        }
    }

    pub(super) fn enforce_invariants(
        &self,
        invariants: &[crate::config::v2::Invariant],
    ) -> Vec<Finding> {
        use crate::config::v2::{InvariantOracle, InvariantType};

        use crate::config::v2::parse_invariant_relation;

        let input_ranges = self.input_index_ranges();
        let mut findings = Vec::new();

        for invariant in invariants {
            if matches!(invariant.invariant_type, InvariantType::Metamorphic) {
                tracing::debug!(
                    "Skipping metamorphic invariant '{}' in direct enforcement pass",
                    invariant.name
                );
                continue;
            }
            if matches!(
                invariant.oracle,
                InvariantOracle::Custom | InvariantOracle::Differential | InvariantOracle::Symbolic
            ) {
                tracing::debug!(
                    "Skipping {:?} oracle invariant '{}' in direct enforcement pass",
                    invariant.oracle,
                    invariant.name
                );
                continue;
            }

            let ast = parse_invariant_relation(&invariant.relation).ok();
            let target_indices = if let Some(ast) = ast.as_ref() {
                self.extract_target_indices_from_ast(ast, &input_ranges)
            } else {
                self.extract_target_indices_from_relation(&invariant.relation, &input_ranges)
            };
            if target_indices.is_empty() {
                continue;
            }

            let violation_value = match self.invariant_violation_value(invariant, ast.as_ref()) {
                Some(value) => value,
                None => continue,
            };

            let mut witness = vec![FieldElement::zero(); self.config.inputs.len().max(1)];
            for idx in target_indices {
                if idx < witness.len() {
                    witness[idx] = violation_value.clone();
                }
            }

            let result = self.executor.execute_sync(&witness);
            if result.success {
                let severity = self.severity_from_invariant(invariant);
                let description = format!(
                    "Invariant '{}' violated but circuit accepted input.\nRelation: {}",
                    invariant.name, invariant.relation
                );
                findings.push(Finding {
                    attack_type: AttackType::ConstraintInference,
                    severity,
                    description,
                    poc: ProofOfConcept {
                        witness_a: witness,
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: None,
                });
            }
        }

        findings
    }

    pub(super) fn input_index_map(&self) -> std::collections::HashMap<String, usize> {
        self.config
            .inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| (input.name.to_lowercase(), idx))
            .collect()
    }

    pub(super) fn input_index_ranges(&self) -> std::collections::HashMap<String, (usize, usize)> {
        let mut map = std::collections::HashMap::new();
        let mut offset = 0usize;
        for input in &self.config.inputs {
            let len = if input.input_type.starts_with("array") {
                input.length.unwrap_or(1)
            } else {
                1
            };
            map.insert(input.name.to_lowercase(), (offset, len));
            offset = offset.saturating_add(len);
        }
        map
    }

    pub(super) fn input_labels(&self) -> std::collections::HashMap<usize, String> {
        self.config
            .inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| (idx, input.name.clone()))
            .collect()
    }

    pub(super) fn merge_config_input_labels(
        &self,
        inspector: &dyn ConstraintInspector,
        labels: &mut std::collections::HashMap<usize, String>,
    ) {
        let mut wire_indices = inspector.public_input_indices();
        wire_indices.extend(inspector.private_input_indices());

        if wire_indices.is_empty() {
            wire_indices = (0..self.config.inputs.len()).collect();
        }

        for (input_idx, input) in self.config.inputs.iter().enumerate() {
            if let Some(&wire_idx) = wire_indices.get(input_idx) {
                labels.entry(wire_idx).or_insert_with(|| input.name.clone());
            }
        }
    }

    pub(super) fn merge_output_labels(
        &self,
        inspector: &dyn ConstraintInspector,
        labels: &mut std::collections::HashMap<usize, String>,
    ) {
        for (idx, wire_idx) in inspector.output_indices().iter().enumerate() {
            labels
                .entry(*wire_idx)
                .or_insert_with(|| format!("output_{}", idx));
        }
    }

    pub(super) fn extract_target_indices_from_relation(
        &self,
        relation: &str,
        input_ranges: &std::collections::HashMap<String, (usize, usize)>,
    ) -> Vec<usize> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        for ch in relation.chars() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                current.push(ch);
            } else if !current.is_empty() {
                tokens.push(current.clone());
                current.clear();
            }
        }
        if !current.is_empty() {
            tokens.push(current);
        }

        let mut indices = Vec::new();
        for token in tokens {
            let key = Self::normalize_input_name(&token).to_lowercase();
            if let Some((start, len)) = input_ranges.get(&key) {
                for idx in *start..start.saturating_add(*len) {
                    indices.push(idx);
                }
            }
        }
        indices.sort_unstable();
        indices.dedup();
        indices
    }

    pub(super) fn invariant_violation_value(
        &self,
        invariant: &crate::config::v2::Invariant,
        ast: Option<&crate::config::v2::InvariantAST>,
    ) -> Option<FieldElement> {
        if let Some(ast) = ast {
            if let Some(value) = self.violation_from_ast(ast, invariant) {
                return Some(value);
            }
        }

        let relation = invariant.relation.to_lowercase();

        if relation.contains("∈ {0,1}") || relation.contains("binary") {
            return Some(FieldElement::from_u64(2));
        }

        let bit_length = self.extract_bit_length(&relation);

        if matches!(
            invariant.invariant_type,
            crate::config::v2::InvariantType::Range
        ) || relation.contains('<')
        {
            if let Some(bits) = bit_length {
                if bits <= 63 {
                    return Some(FieldElement::from_u64(1u64 << bits));
                }
            }
            return Some(FieldElement::max_value());
        }

        None
    }

    pub(super) fn extract_target_indices_from_ast(
        &self,
        ast: &crate::config::v2::InvariantAST,
        input_ranges: &std::collections::HashMap<String, (usize, usize)>,
    ) -> Vec<usize> {
        let mut names = Vec::new();
        self.collect_identifiers(ast, &mut names);
        let mut indices = Vec::new();
        for name in names {
            let key = Self::normalize_input_name(&name).to_lowercase();
            if let Some((start, len)) = input_ranges.get(&key) {
                for idx in *start..start.saturating_add(*len) {
                    indices.push(idx);
                }
            }
        }
        indices.sort_unstable();
        indices.dedup();
        indices
    }

    pub(super) fn collect_identifiers(
        &self,
        ast: &crate::config::v2::InvariantAST,
        out: &mut Vec<String>,
    ) {
        use crate::config::v2::InvariantAST;

        match ast {
            InvariantAST::Identifier(name) => out.push(name.clone()),
            InvariantAST::ArrayAccess(name, _) => out.push(name.clone()),
            InvariantAST::Call(_, args) => {
                for arg in args {
                    out.push(arg.clone());
                }
            }
            InvariantAST::Equals(a, b)
            | InvariantAST::NotEquals(a, b)
            | InvariantAST::LessThan(a, b)
            | InvariantAST::LessThanOrEqual(a, b)
            | InvariantAST::GreaterThan(a, b)
            | InvariantAST::GreaterThanOrEqual(a, b)
            | InvariantAST::InSet(a, b) => {
                self.collect_identifiers(a, out);
                self.collect_identifiers(b, out);
            }
            InvariantAST::Range {
                lower,
                value,
                upper,
                ..
            } => {
                self.collect_identifiers(lower, out);
                self.collect_identifiers(value, out);
                self.collect_identifiers(upper, out);
            }
            InvariantAST::ForAll { expr, .. } => self.collect_identifiers(expr, out),
            InvariantAST::Set(values) => {
                for value in values {
                    self.collect_identifiers(value, out);
                }
            }
            _ => {}
        }
    }

    pub(super) fn extract_bit_length(&self, relation: &str) -> Option<u32> {
        if let Some(pos) = relation.find("2^") {
            let suffix = &relation[pos + 2..];
            let digits: String = suffix.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !digits.is_empty() {
                if let Ok(value) = digits.parse::<u32>() {
                    return Some(value);
                }
            } else if suffix.starts_with("bit_length") {
                if let Some(value) = self
                    .config
                    .campaign
                    .parameters
                    .additional
                    .get("bit_length")
                    .and_then(|v| v.as_u64())
                {
                    return Some(value as u32);
                }
            }
        }

        let traits = self.config.get_target_traits();
        for entry in traits.range_checks {
            let entry = entry.to_lowercase();
            if let Some(bits) = entry.strip_prefix("bitlen:") {
                if let Ok(value) = bits.parse::<u32>() {
                    return Some(value);
                }
            }
            if entry == "u64" {
                return Some(64);
            }
            if entry == "u32" {
                return Some(32);
            }
            if entry == "u8" {
                return Some(8);
            }
        }

        None
    }

    pub(super) fn normalize_input_name(raw: &str) -> String {
        raw.trim()
            .split('[')
            .next()
            .unwrap_or(raw)
            .trim()
            .to_string()
    }

    pub(super) fn violation_from_ast(
        &self,
        ast: &crate::config::v2::InvariantAST,
        invariant: &crate::config::v2::Invariant,
    ) -> Option<FieldElement> {
        use crate::config::v2::InvariantAST;

        match ast {
            InvariantAST::ForAll { expr, .. } => self.violation_from_ast(expr, invariant),
            InvariantAST::InSet(_, set) => self.violation_from_in_set(set),
            InvariantAST::Range {
                lower,
                upper,
                inclusive_lower,
                inclusive_upper,
                ..
            } => self.violation_from_range(lower, upper, *inclusive_lower, *inclusive_upper),
            InvariantAST::LessThan(_, rhs) => self.violation_from_comparison(rhs, false, false),
            InvariantAST::LessThanOrEqual(_, rhs) => {
                self.violation_from_comparison(rhs, false, true)
            }
            InvariantAST::GreaterThan(_, rhs) => self.violation_from_comparison(rhs, true, false),
            InvariantAST::GreaterThanOrEqual(_, rhs) => {
                self.violation_from_comparison(rhs, true, true)
            }
            InvariantAST::Equals(_, rhs) => self.violation_from_not_equal(rhs),
            InvariantAST::NotEquals(_, rhs) => self.violation_from_equal(rhs),
            _ => None,
        }
    }

    pub(super) fn violation_from_in_set(
        &self,
        set: &crate::config::v2::InvariantAST,
    ) -> Option<FieldElement> {
        use crate::config::v2::InvariantAST;

        if let InvariantAST::Set(values) = set {
            let mut has_zero = false;
            let mut has_one = false;
            for value in values {
                if let Some(num) = self.eval_expr_to_u64(value) {
                    if num == 0 {
                        has_zero = true;
                    } else if num == 1 {
                        has_one = true;
                    }
                }
            }
            if has_zero && has_one {
                return Some(FieldElement::from_u64(2));
            }
        }

        None
    }

    pub(super) fn violation_from_range(
        &self,
        lower: &crate::config::v2::InvariantAST,
        upper: &crate::config::v2::InvariantAST,
        inclusive_lower: bool,
        inclusive_upper: bool,
    ) -> Option<FieldElement> {
        if let Some(upper_val) = self.eval_expr_to_u64(upper) {
            if inclusive_upper {
                return Some(FieldElement::from_u64(upper_val.saturating_add(1)));
            }
            return Some(FieldElement::from_u64(upper_val));
        }

        if let Some(lower_val) = self.eval_expr_to_u64(lower) {
            let val = if inclusive_lower {
                lower_val.saturating_sub(1)
            } else {
                lower_val
            };
            return Some(FieldElement::from_u64(val));
        }

        Some(FieldElement::max_value())
    }

    pub(super) fn violation_from_comparison(
        &self,
        rhs: &crate::config::v2::InvariantAST,
        is_greater: bool,
        inclusive: bool,
    ) -> Option<FieldElement> {
        if let Some(bound) = self.eval_expr_to_u64(rhs) {
            if is_greater {
                let value = if inclusive {
                    bound.saturating_sub(1)
                } else {
                    bound
                };
                return Some(FieldElement::from_u64(value));
            }
            let value = if inclusive {
                bound.saturating_add(1)
            } else {
                bound
            };
            return Some(FieldElement::from_u64(value));
        }
        Some(FieldElement::max_value())
    }

    pub(super) fn violation_from_not_equal(
        &self,
        rhs: &crate::config::v2::InvariantAST,
    ) -> Option<FieldElement> {
        let base = self.eval_expr_to_u64(rhs);
        match base {
            Some(value) => Some(FieldElement::from_u64(value.saturating_add(1))),
            None => Some(FieldElement::max_value()),
        }
    }

    pub(super) fn violation_from_equal(
        &self,
        rhs: &crate::config::v2::InvariantAST,
    ) -> Option<FieldElement> {
        if let Some(value) = self.eval_expr_to_u64(rhs) {
            return Some(FieldElement::from_u64(value));
        }
        None
    }

    pub(super) fn eval_expr_to_u64(&self, expr: &crate::config::v2::InvariantAST) -> Option<u64> {
        use crate::config::v2::InvariantAST;

        match expr {
            InvariantAST::Literal(value) => self.parse_u64_literal(value),
            InvariantAST::Power(base, exp) => {
                if base.trim() != "2" {
                    return None;
                }
                if let Some(bits) = self.parse_u64_literal(exp) {
                    if bits <= 63 {
                        return Some(1u64 << bits);
                    }
                }
                None
            }
            InvariantAST::Identifier(name) if name.trim().eq_ignore_ascii_case("bit_length") => {
                self.config
                    .campaign
                    .parameters
                    .additional
                    .get("bit_length")
                    .and_then(|v| v.as_u64())
            }
            _ => None,
        }
    }

    pub(super) fn parse_u64_literal(&self, raw: &str) -> Option<u64> {
        let trimmed = raw.trim().to_lowercase();
        if trimmed.starts_with("0x") {
            return u64::from_str_radix(trimmed.trim_start_matches("0x"), 16).ok();
        }
        if let Some(expr) = trimmed.strip_prefix("2^") {
            let expr = expr.trim();
            if let Some(exp) = expr
                .strip_suffix("-1")
                .or_else(|| expr.strip_suffix(" - 1"))
            {
                if let Ok(bits) = exp.trim().parse::<u32>() {
                    if bits <= 63 {
                        return Some((1u64 << bits).saturating_sub(1));
                    }
                }
                return None;
            }
            if let Ok(bits) = expr.trim().parse::<u32>() {
                if bits <= 63 {
                    return Some(1u64 << bits);
                }
            }
        }
        trimmed.parse::<u64>().ok()
    }
}
