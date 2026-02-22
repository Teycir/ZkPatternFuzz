use std::collections::BTreeSet;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use zk_postroadmap_core::PostRoadmapResult;

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
