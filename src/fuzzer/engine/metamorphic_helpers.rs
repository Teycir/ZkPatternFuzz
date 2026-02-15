use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) fn build_metamorphic_relations(
        &self,
    ) -> Vec<crate::attacks::metamorphic::MetamorphicRelation> {
        use crate::attacks::metamorphic::MetamorphicRelation;
        use crate::config::v2::InvariantType;

        let invariants = self.config.get_invariants();
        let mut relations = Vec::new();

        let input_map = self.input_index_map();
        for invariant in invariants {
            if invariant.invariant_type != InvariantType::Metamorphic {
                continue;
            }

            let transform = match invariant.transform.as_deref() {
                Some(raw) => self.parse_transform(raw, &input_map),
                None => None,
            };

            let Some(transform) = transform else {
                continue;
            };

            let expected = self.parse_expected_behavior(invariant.expected.as_deref());
            let severity = self.severity_from_invariant(&invariant);

            let mut relation = MetamorphicRelation::new(&invariant.name, transform, expected)
                .with_severity(severity);
            if let Some(desc) = invariant.description.as_deref() {
                relation = relation.with_description(desc);
            }

            relations.push(relation);
        }

        relations.extend(self.auto_metamorphic_relations());

        relations
    }

    pub(super) fn auto_metamorphic_relations(
        &self,
    ) -> Vec<crate::attacks::metamorphic::MetamorphicRelation> {
        use crate::attacks::metamorphic::{ExpectedBehavior, MetamorphicRelation, Transform};
        let traits = self.config.get_target_traits();
        if Self::traits_are_empty(&traits) {
            return Vec::new();
        }

        let mut relations = Vec::new();

        if traits.uses_merkle {
            if let Some(idx) = self.find_input_index_by_patterns(&[
                "pathindices",
                "path_indices",
                "pathindex",
                "path_index",
            ]) {
                let mut assignments = std::collections::HashMap::new();
                assignments.insert(idx, FieldElement::from_u64(2));
                relations.push(
                    MetamorphicRelation::new(
                        "auto_merkle_path_index_binary",
                        Transform::SetInputs { assignments },
                        ExpectedBehavior::ShouldReject,
                    )
                    .with_severity(Severity::Critical)
                    .with_description("Merkle path indices should be binary (0/1)"),
                );
            }

            if let Some(idx) = self.find_input_index_by_patterns(&["leaf"]) {
                relations.push(
                    MetamorphicRelation::new(
                        "auto_merkle_leaf_flip",
                        Transform::BitFlipInput {
                            index: idx,
                            bit_position: 0,
                        },
                        ExpectedBehavior::OutputChanged,
                    )
                    .with_severity(Severity::High)
                    .with_description("Flipping the Merkle leaf should change the root/output"),
                );
            }

            if let Some(idx) = self.find_input_index_by_patterns(&["root"]) {
                relations.push(
                    MetamorphicRelation::new(
                        "auto_merkle_root_flip",
                        Transform::BitFlipInput {
                            index: idx,
                            bit_position: 0,
                        },
                        ExpectedBehavior::OutputChanged,
                    )
                    .with_severity(Severity::High)
                    .with_description("Changing the root input should change output/verification"),
                );
            }
        }

        if traits.uses_nullifier {
            if let Some(idx) = self.find_input_index_by_patterns(&["nullifier"]) {
                relations.push(
                    MetamorphicRelation::new(
                        "auto_nullifier_variation",
                        Transform::AddToInputs {
                            indices: vec![idx],
                            value: FieldElement::one(),
                        },
                        ExpectedBehavior::OutputChanged,
                    )
                    .with_severity(Severity::High)
                    .with_description("Nullifier changes should affect outputs"),
                );
            }
        }

        if traits.uses_commitment {
            if let Some(idx) = self.find_input_index_by_patterns(&["commitment", "commit"]) {
                relations.push(
                    MetamorphicRelation::new(
                        "auto_commitment_flip",
                        Transform::BitFlipInput {
                            index: idx,
                            bit_position: 0,
                        },
                        ExpectedBehavior::OutputChanged,
                    )
                    .with_severity(Severity::High)
                    .with_description("Commitment mutation should affect outputs"),
                );
            }
        }

        if traits.uses_signature {
            if let Some(idx) = self.find_signature_input_index() {
                relations.push(
                    MetamorphicRelation::new(
                        "auto_signature_flip",
                        Transform::BitFlipInput {
                            index: idx,
                            bit_position: 0,
                        },
                        ExpectedBehavior::OutputChanged,
                    )
                    .with_severity(Severity::High)
                    .with_description("Mutating the signature should change verification outcome"),
                );
            }
        }

        if !traits.range_checks.is_empty() {
            if let Some(idx) = self
                .find_input_index_by_patterns(&["amount", "value", "balance", "quantity", "qty"])
            {
                let mut assignments = std::collections::HashMap::new();
                assignments.insert(idx, FieldElement::max_value());
                relations.push(
                    MetamorphicRelation::new(
                        "auto_range_overflow",
                        Transform::SetInputs { assignments },
                        ExpectedBehavior::ShouldReject,
                    )
                    .with_severity(Severity::High)
                    .with_description("Range-checked inputs should reject overflow values"),
                );
            }
        }

        relations
    }

    pub(super) fn traits_are_empty(traits: &crate::config::v2::TargetTraits) -> bool {
        !traits.uses_merkle
            && !traits.uses_nullifier
            && !traits.uses_commitment
            && !traits.uses_signature
            && traits.range_checks.is_empty()
            && traits.hash_function.is_none()
            && traits.curve.is_none()
            && traits.custom.is_empty()
    }

    pub(super) fn find_input_index_by_patterns(&self, patterns: &[&str]) -> Option<usize> {
        let patterns: Vec<String> = patterns.iter().map(|p| p.to_lowercase()).collect();
        for (idx, input) in self.config.inputs.iter().enumerate() {
            let name = input.name.to_lowercase();
            if patterns.iter().any(|p| name.contains(p)) {
                return Some(idx);
            }
        }
        None
    }

    pub(super) fn find_signature_input_index(&self) -> Option<usize> {
        for (idx, input) in self.config.inputs.iter().enumerate() {
            let name = input.name.to_lowercase();
            if name.contains("signature")
                || name.starts_with("sig")
                || name.contains("_sig")
                || name.contains("sig_")
            {
                return Some(idx);
            }
        }
        None
    }

    pub(super) fn parse_transform(
        &self,
        transform: &str,
        input_map: &std::collections::HashMap<String, usize>,
    ) -> Option<crate::attacks::metamorphic::Transform> {
        use crate::attacks::metamorphic::Transform;

        let raw = transform.trim();
        if raw.eq_ignore_ascii_case("swap_sibling_order") {
            let candidate = ["pathindices", "path_indices", "pathindex", "indices"];
            for name in candidate {
                if let Some(idx) = input_map.get(name) {
                    return Some(Transform::BitFlipInput {
                        index: *idx,
                        bit_position: 0,
                    });
                }
            }
        }

        let (name, args) = Self::parse_call(raw)?;

        match name.as_str() {
            "scale_input" => {
                let (input_name, factor) = Self::parse_two_args(&args)?;
                let (input_name, _) = Self::parse_transform_target(&input_name);
                let idx = input_map.get(&Self::normalize_input_name(&input_name).to_lowercase())?;
                let factor = Self::parse_field_element(&factor)?;
                Some(Transform::ScaleInputs {
                    indices: vec![*idx],
                    factor,
                })
            }
            "add_input" => {
                let (input_name, value) = Self::parse_two_args(&args)?;
                let (input_name, _) = Self::parse_transform_target(&input_name);
                let idx = input_map.get(&Self::normalize_input_name(&input_name).to_lowercase())?;
                let value = Self::parse_field_element(&value)?;
                Some(Transform::AddToInputs {
                    indices: vec![*idx],
                    value,
                })
            }
            "negate_input" => {
                let input_name = args.first()?;
                let (input_name, _) = Self::parse_transform_target(input_name);
                let idx = input_map.get(&Self::normalize_input_name(&input_name).to_lowercase())?;
                Some(Transform::NegateInputs {
                    indices: vec![*idx],
                })
            }
            "swap_inputs" => {
                let (left, right) = Self::parse_two_args(&args)?;
                let (left, _) = Self::parse_transform_target(&left);
                let (right, _) = Self::parse_transform_target(&right);
                let a = input_map.get(&Self::normalize_input_name(&left).to_lowercase())?;
                let b = input_map.get(&Self::normalize_input_name(&right).to_lowercase())?;
                Some(Transform::SwapInputs {
                    index_a: *a,
                    index_b: *b,
                })
            }
            "bit_flip" => {
                let (input_name, bit) = Self::parse_two_args(&args)?;
                let (input_name, _) = Self::parse_transform_target(&input_name);
                let idx = input_map.get(&Self::normalize_input_name(&input_name).to_lowercase())?;
                let bit_position = match bit.parse::<usize>() {
                    Ok(bit_position) => bit_position,
                    Err(err) => {
                        tracing::debug!("Invalid bit_flip position '{}': {}", bit, err);
                        return None;
                    }
                };
                Some(Transform::BitFlipInput {
                    index: *idx,
                    bit_position,
                })
            }
            "double_input" => {
                let input_name = args.first()?;
                let (input_name, _) = Self::parse_transform_target(input_name);
                let idx = input_map.get(&Self::normalize_input_name(&input_name).to_lowercase())?;
                Some(Transform::DoubleInput { index: *idx })
            }
            "set_input" => {
                let (input_name, value) = if args.len() == 1 {
                    if let Some((left, right)) = args[0].split_once('=') {
                        (left.trim().to_string(), right.trim().to_string())
                    } else {
                        Self::parse_two_args(&args)?
                    }
                } else {
                    Self::parse_two_args(&args)?
                };
                let (input_name, _) = Self::parse_transform_target(&input_name);
                let idx = input_map.get(&Self::normalize_input_name(&input_name).to_lowercase())?;
                let value = Self::parse_field_element(&value)?;
                let mut assignments = std::collections::HashMap::new();
                assignments.insert(*idx, value);
                Some(Transform::SetInputs { assignments })
            }
            _ => None,
        }
    }

    pub(super) fn parse_expected_behavior(
        &self,
        expected: Option<&str>,
    ) -> crate::attacks::metamorphic::ExpectedBehavior {
        use crate::attacks::metamorphic::ExpectedBehavior;

        let Some(raw) = expected else {
            return ExpectedBehavior::OutputChanged;
        };
        let lower = raw.trim().to_lowercase();

        if lower.contains("output_unchanged") || lower.contains("unchanged") {
            return ExpectedBehavior::OutputUnchanged;
        }
        if lower.contains("output_changes")
            || lower.contains("output_changed")
            || lower.contains("changes")
        {
            return ExpectedBehavior::OutputChanged;
        }
        if let Some(arg) = lower
            .strip_prefix("output_scaled(")
            .and_then(|s| s.strip_suffix(')'))
        {
            if let Some(factor) = Self::parse_field_element(arg) {
                return ExpectedBehavior::OutputScaled(factor);
            }
        }
        if lower.contains("reject") {
            return ExpectedBehavior::ShouldReject;
        }
        if lower.contains("accept") {
            return ExpectedBehavior::ShouldAccept;
        }

        ExpectedBehavior::Custom(raw.to_string())
    }

    pub(super) fn parse_call(raw: &str) -> Option<(String, Vec<String>)> {
        let open = raw.find('(')?;
        let close = raw.rfind(')')?;
        if close <= open {
            return None;
        }
        let name = raw[..open].trim().to_lowercase();
        let args = raw[open + 1..close]
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Some((name, args))
    }

    pub(super) fn parse_two_args(args: &[String]) -> Option<(String, String)> {
        if args.len() < 2 {
            return None;
        }
        Some((args[0].clone(), args[1].clone()))
    }

    pub(super) fn parse_transform_target(raw: &str) -> (String, Option<usize>) {
        let trimmed = raw.trim();
        if let Some(start) = trimmed.find('[') {
            if trimmed.ends_with(']') {
                let base = trimmed[..start].trim();
                let index = trimmed[start + 1..trimmed.len() - 1].trim();
                let parsed = match index.parse::<usize>() {
                    Ok(value) => Some(value),
                    Err(err) => {
                        tracing::debug!("Invalid transform target index '{}': {}", index, err);
                        None
                    }
                };
                return (base.to_string(), parsed);
            }
        }
        (trimmed.to_string(), None)
    }

    pub(super) fn parse_field_element(raw: &str) -> Option<FieldElement> {
        let trimmed = raw.trim();
        let lower = trimmed.to_lowercase();

        if lower == "p-1" || lower == "max" || lower == "max_field" {
            return Some(FieldElement::max_value());
        }
        if lower == "(p-1)/2" {
            return Some(FieldElement::half_modulus());
        }

        if lower.starts_with("0x") {
            return match FieldElement::from_hex(trimmed) {
                Ok(value) => Some(value),
                Err(err) => {
                    tracing::debug!("Invalid hex metamorphic field literal '{}': {}", trimmed, err);
                    None
                }
            };
        }

        if let Some(exp) = lower.strip_prefix("2^") {
            let exp = exp.trim();
            if let Some(exp) = exp.strip_suffix("-1").or_else(|| exp.strip_suffix(" - 1")) {
                if let Ok(bits) = exp.trim().parse::<u32>() {
                    if bits <= 63 {
                        return Some(FieldElement::from_u64((1u64 << bits).saturating_sub(1)));
                    }
                }
                return Some(FieldElement::max_value());
            }

            if let Ok(bits) = exp.parse::<u32>() {
                if bits <= 63 {
                    return Some(FieldElement::from_u64(1u64 << bits));
                }
            }
            return Some(FieldElement::max_value());
        }

        match trimmed.parse::<u64>() {
            Ok(value) => Some(FieldElement::from_u64(value)),
            Err(err) => {
                tracing::debug!("Invalid decimal metamorphic field literal '{}': {}", trimmed, err);
                None
            }
        }
    }
}
