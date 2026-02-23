use std::collections::BTreeSet;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zk_postroadmap_core::{PostRoadmapError, PostRoadmapResult};

const REQUIRED_MARKERS: &[&str] = &[
    "must", "shall", "should", "require", "requires", "only", "always", "ensure", "ensures",
];
const FORBIDDEN_MARKERS: &[&str] = &[
    "must not",
    "mustn't",
    "should not",
    "shouldn't",
    "never",
    "cannot",
    "can't",
    "forbid",
    "forbidden",
    "reject",
];
const SECURITY_MARKERS: &[&str] = &[
    "proof",
    "witness",
    "input",
    "public",
    "private",
    "verify",
    "nullifier",
    "merkle",
    "signature",
    "overflow",
    "underflow",
    "range",
    "constraint",
    "admin",
    "owner",
    "auth",
    "permission",
    "withdraw",
    "mint",
    "replay",
    "leak",
];
const HIGH_RISK_TERMS: &[&str] = &[
    "bypass",
    "unauthorized",
    "forge",
    "forgery",
    "replay",
    "mint",
    "withdraw",
    "overflow",
    "underflow",
    "leak",
    "escalation",
];
const WEAK_IMPL_TERMS: &[&str] = &[
    "todo",
    "fixme",
    "hack",
    "temporary",
    "debug",
    "unchecked",
    "skip",
    "disable verification",
];
const SECURITY_CRITICAL_MARKERS: &[&str] = &[
    "must never",
    "always",
    "only if",
    "only",
    "reject",
    "verify",
    "auth",
    "permission",
    "private",
    "nullifier",
    "replay",
];

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SemanticIntent {
    pub source: String,
    pub invariants: Vec<String>,
    pub required_behaviors: Vec<String>,
    pub forbidden_behaviors: Vec<String>,
    pub security_properties: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ExploitabilityAssessment {
    pub exploitable: bool,
    pub rationale: String,
    pub confidence: u8,
}

#[async_trait]
pub trait SemanticIntentAdapter: Send + Sync {
    fn provider_name(&self) -> &'static str;
    async fn extract_intent(&self, source_text: &str) -> PostRoadmapResult<SemanticIntent>;
    async fn classify_exploitability(
        &self,
        intent: &SemanticIntent,
        violation_summary: &str,
    ) -> PostRoadmapResult<ExploitabilityAssessment>;
}

#[derive(Debug, Default)]
pub struct HeuristicSemanticIntentAdapter;

#[derive(Debug, Clone)]
pub struct ModelGuidedSemanticIntentAdapter {
    model_name: String,
    system_prompt: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExternalUserSemanticIntentAdapter {
    actor_label: String,
    intent_payload: Option<String>,
    exploitability_payload: Option<String>,
}

impl Default for ModelGuidedSemanticIntentAdapter {
    fn default() -> Self {
        Self::new("mistral")
    }
}

impl ModelGuidedSemanticIntentAdapter {
    pub fn new(model_name: impl Into<String>) -> Self {
        Self {
            model_name: model_name.into(),
            system_prompt: None,
        }
    }

    pub fn with_system_prompt(mut self, system_prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(system_prompt.into());
        self
    }
}

impl ExternalUserSemanticIntentAdapter {
    pub fn new(actor_label: impl Into<String>) -> Self {
        Self {
            actor_label: actor_label.into(),
            intent_payload: None,
            exploitability_payload: None,
        }
    }

    pub fn with_intent_payload(mut self, payload: impl Into<String>) -> Self {
        self.intent_payload = Some(payload.into());
        self
    }

    pub fn with_exploitability_payload(mut self, payload: impl Into<String>) -> Self {
        self.exploitability_payload = Some(payload.into());
        self
    }
}

#[async_trait]
impl SemanticIntentAdapter for HeuristicSemanticIntentAdapter {
    fn provider_name(&self) -> &'static str {
        "heuristic-semantic-v1"
    }

    async fn extract_intent(&self, source_text: &str) -> PostRoadmapResult<SemanticIntent> {
        let mut required_behaviors = BTreeSet::new();
        let mut forbidden_behaviors = BTreeSet::new();
        let mut security_properties = BTreeSet::new();

        for statement in statement_candidates(source_text) {
            let statement_lc = statement.to_ascii_lowercase();
            let has_required = contains_any(&statement_lc, REQUIRED_MARKERS);
            let has_forbidden = contains_any(&statement_lc, FORBIDDEN_MARKERS);
            let has_security = contains_any(&statement_lc, SECURITY_MARKERS);

            if !(has_required || has_forbidden || has_security) {
                continue;
            }

            if has_required {
                required_behaviors.insert(statement.clone());
            }
            if has_forbidden {
                forbidden_behaviors.insert(statement.clone());
            }
            if has_security {
                security_properties.insert(statement);
            }
        }

        let mut invariants = BTreeSet::new();
        invariants.extend(required_behaviors.iter().cloned());
        invariants.extend(forbidden_behaviors.iter().cloned());
        invariants.extend(security_properties.iter().cloned());

        Ok(SemanticIntent {
            source: self.provider_name().to_string(),
            invariants: invariants.into_iter().collect(),
            required_behaviors: required_behaviors.into_iter().collect(),
            forbidden_behaviors: forbidden_behaviors.into_iter().collect(),
            security_properties: security_properties.into_iter().collect(),
        })
    }

    async fn classify_exploitability(
        &self,
        intent: &SemanticIntent,
        violation_summary: &str,
    ) -> PostRoadmapResult<ExploitabilityAssessment> {
        let violation_lc = violation_summary.to_ascii_lowercase();
        let has_high_risk_term = contains_any(&violation_lc, HIGH_RISK_TERMS);
        let has_weak_impl_term = contains_any(&violation_lc, WEAK_IMPL_TERMS);

        let mut confidence: i32 = 20;
        confidence += (intent.security_properties.len().min(5) as i32) * 8;
        confidence += (intent.forbidden_behaviors.len().min(3) as i32) * 7;
        confidence += (intent.required_behaviors.len().min(3) as i32) * 4;
        if has_high_risk_term {
            confidence += 35;
        }
        if has_weak_impl_term {
            confidence += 20;
        }
        if violation_lc.contains("potential") {
            confidence -= 5;
        }

        let confidence = confidence.clamp(0, 100) as u8;
        let exploitable =
            confidence >= 65 && (has_high_risk_term || !intent.forbidden_behaviors.is_empty());

        let rationale = if exploitable {
            format!(
                "Exploitability likely: confidence={}, high_risk={}, weak_impl={}",
                confidence, has_high_risk_term, has_weak_impl_term
            )
        } else {
            format!(
                "Exploitability uncertain: confidence={}, high_risk={}, weak_impl={}",
                confidence, has_high_risk_term, has_weak_impl_term
            )
        };

        Ok(ExploitabilityAssessment {
            exploitable,
            rationale,
            confidence,
        })
    }
}

#[async_trait]
impl SemanticIntentAdapter for ModelGuidedSemanticIntentAdapter {
    fn provider_name(&self) -> &'static str {
        "model-guided-semantic-v1"
    }

    async fn extract_intent(&self, source_text: &str) -> PostRoadmapResult<SemanticIntent> {
        let heuristic = HeuristicSemanticIntentAdapter;
        let mut base = heuristic.extract_intent(source_text).await?;
        let statements = statement_candidates(source_text);

        let mut formal_invariants = BTreeSet::new();
        let mut security_critical_properties = BTreeSet::new();
        for statement in &statements {
            if let Some(formal) = synthesize_formal_invariant(statement) {
                formal_invariants.insert(formal);
            }
            if is_security_critical(statement) {
                security_critical_properties.insert(format!(
                    "security_critical:{}",
                    normalize_statement(statement)
                ));
            }
        }

        if let Some(system_prompt) = &self.system_prompt {
            let prompt_lc = system_prompt.to_ascii_lowercase();
            if prompt_lc.contains("strict") || prompt_lc.contains("formal") {
                for statement in &statements {
                    if contains_any(&statement.to_ascii_lowercase(), REQUIRED_MARKERS) {
                        formal_invariants.insert(format!(
                            "formal.strict_requirement:{}",
                            normalize_statement(statement)
                        ));
                    }
                }
            }
        }

        let mut invariants = BTreeSet::new();
        invariants.extend(base.invariants.drain(..));
        invariants.extend(formal_invariants.iter().cloned());
        invariants.extend(security_critical_properties.iter().cloned());

        let mut security_properties = BTreeSet::new();
        security_properties.extend(base.security_properties.drain(..));
        security_properties.extend(security_critical_properties.into_iter());

        base.source = format!("{}:{}", self.provider_name(), self.model_name);
        base.invariants = invariants.into_iter().collect();
        base.security_properties = security_properties.into_iter().collect();
        Ok(base)
    }

    async fn classify_exploitability(
        &self,
        intent: &SemanticIntent,
        violation_summary: &str,
    ) -> PostRoadmapResult<ExploitabilityAssessment> {
        let heuristic = HeuristicSemanticIntentAdapter;
        let mut assessment = heuristic
            .classify_exploitability(intent, violation_summary)
            .await?;

        let formal_count = intent
            .invariants
            .iter()
            .filter(|invariant| {
                invariant.starts_with("formal.") || invariant.starts_with("invariant.")
            })
            .count();
        let security_critical_count = intent
            .security_properties
            .iter()
            .filter(|property| property.starts_with("security_critical:"))
            .count();

        let mut adjusted_confidence = assessment.confidence as i32;
        adjusted_confidence += (formal_count.min(5) as i32) * 3;
        adjusted_confidence += (security_critical_count.min(5) as i32) * 4;
        if violation_summary.to_ascii_lowercase().contains("bypass") {
            adjusted_confidence += 5;
        }

        assessment.confidence = adjusted_confidence.clamp(0, 100) as u8;
        assessment.exploitable = assessment.exploitable || assessment.confidence >= 70;
        assessment.rationale = format!(
            "{}; model_guided_adjustment=formal:{} security_critical:{} model:{}",
            assessment.rationale, formal_count, security_critical_count, self.model_name
        );
        Ok(assessment)
    }
}

#[async_trait]
impl SemanticIntentAdapter for ExternalUserSemanticIntentAdapter {
    fn provider_name(&self) -> &'static str {
        "external-user-semantic-v1"
    }

    async fn extract_intent(&self, source_text: &str) -> PostRoadmapResult<SemanticIntent> {
        let _ = source_text;
        if let Some(payload) = self.intent_payload.as_ref().map(|value| value.trim()) {
            let mut parsed = parse_external_intent_payload(payload).ok_or_else(|| {
                PostRoadmapError::Adapter(
                    "external semantic intent payload is present but not parseable".to_string(),
                )
            })?;
            if parsed.source.trim().is_empty() {
                parsed.source = format!("{}:{}", self.provider_name(), self.actor_label);
            }
            return Ok(parsed);
        }

        Err(PostRoadmapError::Adapter(format!(
            "external semantic intent is required for `{}`; missing `intent_payload` for actor `{}`",
            self.provider_name(),
            self.actor_label
        )))
    }

    async fn classify_exploitability(
        &self,
        intent: &SemanticIntent,
        violation_summary: &str,
    ) -> PostRoadmapResult<ExploitabilityAssessment> {
        if let Some(payload) = self
            .exploitability_payload
            .as_ref()
            .map(|value| value.trim())
        {
            let mut parsed = parse_external_assessment_payload(payload).ok_or_else(|| {
                PostRoadmapError::Adapter(
                    "external exploitability payload is present but not parseable".to_string(),
                )
            })?;
            if parsed.rationale.trim().is_empty() {
                parsed.rationale = format!(
                    "External AI assessment provided by `{}` with confidence {}",
                    self.actor_label, parsed.confidence
                );
            }
            parsed.rationale = format!(
                "{}; source={}:{}",
                parsed.rationale,
                self.provider_name(),
                self.actor_label
            );
            return Ok(parsed);
        }

        let _ = (intent, violation_summary);
        Err(PostRoadmapError::Adapter(format!(
            "external exploitability assessment is required for `{}`; missing `exploitability_payload` for actor `{}`",
            self.provider_name(),
            self.actor_label
        )))
    }
}

fn parse_external_intent_payload(payload: &str) -> Option<SemanticIntent> {
    let value = parse_json_object_payload(payload)?;
    let root = value.get("semantic_intent").unwrap_or(&value);
    let object = root.as_object()?;

    let source = get_string_field(object, &["source", "provider"]).unwrap_or_default();
    let mut intent = SemanticIntent {
        source,
        invariants: collect_string_list(object, &["invariants", "formal_invariants", "rules"]),
        required_behaviors: collect_string_list(
            object,
            &["required_behaviors", "required", "requirements", "must"],
        ),
        forbidden_behaviors: collect_string_list(
            object,
            &["forbidden_behaviors", "forbidden", "must_not", "never"],
        ),
        security_properties: collect_string_list(
            object,
            &["security_properties", "security_critical", "security"],
        ),
    };

    if intent.invariants.is_empty()
        && intent.required_behaviors.is_empty()
        && intent.forbidden_behaviors.is_empty()
        && intent.security_properties.is_empty()
    {
        if let Some(text) = get_string_field(object, &["summary", "text", "analysis"]) {
            let statements = statement_candidates(&text);
            for statement in statements {
                let statement_lc = statement.to_ascii_lowercase();
                if contains_any(&statement_lc, REQUIRED_MARKERS) {
                    intent.required_behaviors.push(statement.clone());
                }
                if contains_any(&statement_lc, FORBIDDEN_MARKERS) {
                    intent.forbidden_behaviors.push(statement.clone());
                }
                if contains_any(&statement_lc, SECURITY_MARKERS) {
                    intent.security_properties.push(statement.clone());
                }
                if let Some(formal) = synthesize_formal_invariant(&statement) {
                    intent.invariants.push(formal);
                }
            }
        }
    }

    deduplicate_semantic_intent(&mut intent);
    Some(intent)
}

fn parse_external_assessment_payload(payload: &str) -> Option<ExploitabilityAssessment> {
    let value = parse_json_object_payload(payload)?;
    let root = value.get("exploitability").unwrap_or(&value);
    let object = root.as_object()?;

    let exploitable = object
        .get("exploitable")
        .or_else(|| object.get("is_exploitable"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let rationale =
        get_string_field(object, &["rationale", "reason", "explanation"]).unwrap_or_default();
    let confidence = object
        .get("confidence")
        .or_else(|| object.get("confidence_score"))
        .and_then(Value::as_u64)
        .map(|value| value.min(100) as u8)
        .unwrap_or(50);

    Some(ExploitabilityAssessment {
        exploitable,
        rationale,
        confidence,
    })
}

fn parse_json_object_payload(payload: &str) -> Option<Value> {
    if let Ok(value) = serde_json::from_str::<Value>(payload) {
        return Some(value);
    }

    let fenced = extract_fenced_json(payload)?;
    serde_json::from_str::<Value>(&fenced).ok()
}

fn extract_fenced_json(payload: &str) -> Option<String> {
    let start = payload.find("```")?;
    let rest = &payload[start + 3..];
    let body_start = rest.find('\n').map(|index| index + 1).unwrap_or(0);
    let body = &rest[body_start..];
    let end = body.find("```")?;
    Some(body[..end].trim().to_string())
}

fn collect_string_list(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Vec<String> {
    let mut values = BTreeSet::new();
    for key in keys {
        let Some(value) = object.get(*key) else {
            continue;
        };
        match value {
            Value::String(text) => {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    values.insert(trimmed.to_string());
                }
            }
            Value::Array(items) => {
                for item in items {
                    if let Some(text) = item.as_str() {
                        let trimmed = text.trim();
                        if !trimmed.is_empty() {
                            values.insert(trimmed.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    values.into_iter().collect()
}

fn get_string_field(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn deduplicate_semantic_intent(intent: &mut SemanticIntent) {
    fn dedup(values: &mut Vec<String>) {
        let mut unique = BTreeSet::new();
        for value in values.drain(..) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                unique.insert(trimmed.to_string());
            }
        }
        values.extend(unique);
    }

    dedup(&mut intent.invariants);
    dedup(&mut intent.required_behaviors);
    dedup(&mut intent.forbidden_behaviors);
    dedup(&mut intent.security_properties);
}

fn synthesize_formal_invariant(statement: &str) -> Option<String> {
    let statement_lc = statement.to_ascii_lowercase();
    let normalized = normalize_statement(statement);
    if normalized.is_empty() {
        return None;
    }

    if contains_any(&statement_lc, FORBIDDEN_MARKERS) {
        return Some(format!("invariant.forbidden:{normalized}"));
    }
    if statement_lc.contains("only if") {
        return Some(format!("invariant.precondition:{normalized}"));
    }
    if statement_lc.contains("only")
        && (statement_lc.contains("can") || statement_lc.contains("may"))
    {
        return Some(format!("invariant.authorization:{normalized}"));
    }
    if contains_any(&statement_lc, REQUIRED_MARKERS) {
        return Some(format!("invariant.requirement:{normalized}"));
    }
    if contains_any(&statement_lc, SECURITY_MARKERS) {
        return Some(format!("invariant.security:{normalized}"));
    }
    None
}

fn is_security_critical(statement: &str) -> bool {
    let statement_lc = statement.to_ascii_lowercase();
    contains_any(&statement_lc, SECURITY_CRITICAL_MARKERS)
        && contains_any(&statement_lc, SECURITY_MARKERS)
}

fn normalize_statement(statement: &str) -> String {
    let mut out = String::with_capacity(statement.len());
    let mut last_was_underscore = false;
    for ch in statement.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_underscore = false;
        } else if !last_was_underscore {
            out.push('_');
            last_was_underscore = true;
        }
    }
    out.trim_matches('_').to_string()
}

fn statement_candidates(source_text: &str) -> Vec<String> {
    let mut statements = BTreeSet::new();

    for line in source_text.lines() {
        let normalized = line
            .trim()
            .trim_start_matches(['/', '#', '*', '-', ' '])
            .trim();
        if normalized.is_empty() {
            continue;
        }

        for segment in normalized.split(['.', ';']) {
            let candidate = segment.trim();
            if candidate.len() < 12 {
                continue;
            }
            let collapsed = candidate.split_whitespace().collect::<Vec<_>>().join(" ");
            if collapsed.len() >= 12 {
                statements.insert(collapsed);
            }
        }
    }

    statements.into_iter().collect()
}

fn contains_any(haystack_lc: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack_lc.contains(needle))
}
