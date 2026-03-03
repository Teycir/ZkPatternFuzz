use crate::scan_selector_context::build_selector_source;
use anyhow::Context;
use regex::RegexBuilder;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

fn yaml_key(name: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(name.to_string())
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ScanRegexPatternKind {
    #[default]
    Regex,
}

fn default_scan_regex_pattern_weight() -> f64 {
    1.0
}

#[derive(Debug, Clone, Deserialize)]
struct ScanRegexPatternSpec {
    id: String,
    pattern: String,
    #[serde(default)]
    kind: ScanRegexPatternKind,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default = "default_scan_regex_pattern_weight")]
    weight: f64,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct ScanRegexSelectorPolicySpec {
    k_of_n: Option<usize>,
    min_score: Option<f64>,
    groups: Vec<ScanRegexSelectorGroupPolicySpec>,
}

fn default_selector_synonym_flexible_separators() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct ScanRegexSelectorNormalizationSpec {
    synonym_flexible_separators: bool,
}

impl Default for ScanRegexSelectorNormalizationSpec {
    fn default() -> Self {
        Self {
            synonym_flexible_separators: default_selector_synonym_flexible_separators(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct ScanRegexSelectorGroupPolicySpec {
    #[serde(alias = "group")]
    name: String,
    k_of_n: Option<usize>,
    min_score: Option<f64>,
}

#[derive(Debug, Clone)]
pub(crate) struct ScanRegexSelectorConfig {
    patterns: Vec<ScanRegexPatternSpec>,
    policy: ScanRegexSelectorPolicySpec,
}

#[derive(Debug, Clone)]
pub(crate) struct ScanRegexPatternMatch {
    pub(crate) id: String,
    pub(crate) lines: Vec<usize>,
    pub(crate) occurrences: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct ScanRegexPatternGroupMatch {
    pub(crate) name: String,
    pub(crate) total_patterns: usize,
    pub(crate) matched_patterns: usize,
    pub(crate) matched_score: f64,
    pub(crate) required_k_of_n: usize,
    pub(crate) required_min_score: f64,
    pub(crate) passed: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ScanRegexPatternSummary {
    pub(crate) total_patterns: usize,
    pub(crate) matched_patterns: usize,
    pub(crate) total_occurrences: usize,
    pub(crate) matched_score: f64,
    pub(crate) required_k_of_n: usize,
    pub(crate) required_min_score: f64,
    pub(crate) selector_passed: bool,
    pub(crate) matched_ids: Vec<String>,
    pub(crate) matches: Vec<ScanRegexPatternMatch>,
    pub(crate) group_matches: Vec<ScanRegexPatternGroupMatch>,
}

pub(crate) fn validate_scan_regex_pattern_safety(pattern: &str) -> anyhow::Result<()> {
    const MAX_PATTERN_LENGTH: usize = 1000;
    const MAX_ALTERNATIONS: usize = 50;
    const MAX_GROUPS: usize = 20;

    if pattern.len() > MAX_PATTERN_LENGTH {
        anyhow::bail!(
            "Regex pattern too long ({} chars). Maximum allowed: {}",
            pattern.len(),
            MAX_PATTERN_LENGTH
        );
    }

    let alternation_count = pattern.matches('|').count();
    if alternation_count > MAX_ALTERNATIONS {
        anyhow::bail!(
            "Regex pattern has too many alternations ({}). Maximum allowed: {}",
            alternation_count,
            MAX_ALTERNATIONS
        );
    }

    // Escape-aware scan for group count and nested quantifiers such as (a+)+.
    let bytes = pattern.as_bytes();
    let mut i = 0usize;
    let mut group_count = 0usize;
    let mut paren_stack: Vec<bool> = Vec::new(); // bool = has quantifier inside this group

    while i < bytes.len() {
        let ch = bytes[i];

        if ch == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }

        if ch == b'(' {
            group_count += 1;
            if group_count > MAX_GROUPS {
                anyhow::bail!(
                    "Regex pattern has too many groups ({}). Maximum allowed: {}",
                    group_count,
                    MAX_GROUPS
                );
            }
            paren_stack.push(false);
            i += 1;
            continue;
        }

        if ch == b')' {
            if let Some(has_quant_inside) = paren_stack.pop() {
                if i + 1 < bytes.len() {
                    let next = bytes[i + 1];
                    let has_outer_quant = next == b'*' || next == b'+' || next == b'{';
                    if has_outer_quant && has_quant_inside {
                        anyhow::bail!(
                            "Potentially dangerous nested quantifier detected in regex pattern: {}",
                            pattern
                        );
                    }
                }
                if has_quant_inside && !paren_stack.is_empty() {
                    if let Some(parent) = paren_stack.last_mut() {
                        *parent = true;
                    }
                }
            }
            i += 1;
            continue;
        }

        let is_quantifier = ch == b'*' || ch == b'+' || ch == b'{';
        if is_quantifier && !paren_stack.is_empty() {
            if let Some(last) = paren_stack.last_mut() {
                *last = true;
            }
        }

        i += 1;
    }

    Ok(())
}

fn normalize_synonym_term_to_regex(
    term: &str,
    normalization: &ScanRegexSelectorNormalizationSpec,
) -> String {
    if !normalization.synonym_flexible_separators {
        return regex::escape(term.trim());
    }

    let mut tokens: Vec<String> = Vec::new();
    for raw_chunk in term
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        let mut current = String::new();
        let mut prev: Option<char> = None;
        for ch in raw_chunk.chars() {
            let boundary = match prev {
                Some(prev_ch) => {
                    (prev_ch.is_ascii_lowercase() && ch.is_ascii_uppercase())
                        || (prev_ch.is_ascii_alphabetic() && ch.is_ascii_digit())
                        || (prev_ch.is_ascii_digit() && ch.is_ascii_alphabetic())
                }
                None => false,
            };
            if boundary && !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            current.push(ch);
            prev = Some(ch);
        }
        if !current.is_empty() {
            tokens.push(current);
        }
    }
    let tokens: Vec<String> = tokens
        .into_iter()
        .map(|token| regex::escape(&token))
        .collect();
    if tokens.len() >= 2 {
        return tokens.join(r"(?:[\s_\-./]*)");
    }

    regex::escape(term.trim())
}

fn validate_scan_regex_synonym_bundles(
    pattern_path: &str,
    bundles: &BTreeMap<String, Vec<String>>,
) -> anyhow::Result<()> {
    for (bundle_name, variants) in bundles {
        let bundle_name = bundle_name.trim();
        if bundle_name.is_empty() {
            anyhow::bail!(
                "Invalid `selector_synonyms` in '{}': bundle names must be non-empty",
                pattern_path
            );
        }
        if variants.is_empty() {
            anyhow::bail!(
                "Invalid `selector_synonyms.{}` in '{}': bundle must contain at least one synonym",
                bundle_name,
                pattern_path
            );
        }
        for (idx, variant) in variants.iter().enumerate() {
            if variant.trim().is_empty() {
                anyhow::bail!(
                    "Invalid `selector_synonyms.{}[{}]` in '{}': synonym values must be non-empty",
                    bundle_name,
                    idx,
                    pattern_path
                );
            }
        }
    }

    Ok(())
}

fn build_scan_regex_synonym_regexes(
    pattern_path: &str,
    bundles: &BTreeMap<String, Vec<String>>,
    normalization: &ScanRegexSelectorNormalizationSpec,
) -> anyhow::Result<BTreeMap<String, String>> {
    let mut regexes: BTreeMap<String, String> = BTreeMap::new();
    for (bundle_name, variants) in bundles {
        let mut bundle_variants: Vec<String> = Vec::with_capacity(variants.len());
        for variant in variants {
            bundle_variants.push(normalize_synonym_term_to_regex(variant, normalization));
        }
        if bundle_variants.is_empty() {
            anyhow::bail!(
                "Invalid `selector_synonyms.{}` in '{}': bundle must contain at least one synonym",
                bundle_name,
                pattern_path
            );
        }
        regexes.insert(
            bundle_name.trim().to_string(),
            format!("(?:{})", bundle_variants.join("|")),
        );
    }

    Ok(regexes)
}

fn expand_scan_regex_synonym_placeholders(
    pattern_path: &str,
    pattern_id: &str,
    raw_pattern: &str,
    synonym_regexes: &BTreeMap<String, String>,
) -> anyhow::Result<String> {
    if !raw_pattern.contains("{{") {
        return Ok(raw_pattern.to_string());
    }

    let mut expanded = String::new();
    let mut cursor = 0usize;
    while let Some(start_rel) = raw_pattern[cursor..].find("{{") {
        let start = cursor + start_rel;
        expanded.push_str(&raw_pattern[cursor..start]);

        let tail = &raw_pattern[start + 2..];
        let Some(end_rel) = tail.find("}}") else {
            anyhow::bail!(
                "Invalid synonym placeholder in pattern '{}' from '{}': missing closing '}}'",
                pattern_id,
                pattern_path
            );
        };

        let bundle_name = tail[..end_rel].trim();
        if bundle_name.is_empty() {
            anyhow::bail!(
                "Invalid synonym placeholder in pattern '{}' from '{}': empty bundle name",
                pattern_id,
                pattern_path
            );
        }
        let Some(bundle_regex) = synonym_regexes.get(bundle_name) else {
            anyhow::bail!(
                "Unknown synonym bundle '{}' referenced by pattern '{}' in '{}'",
                bundle_name,
                pattern_id,
                pattern_path
            );
        };
        expanded.push_str(bundle_regex);
        cursor = start + 2 + end_rel + 2;
    }
    expanded.push_str(&raw_pattern[cursor..]);

    Ok(expanded)
}

fn validate_scan_regex_selector_config(
    pattern_path: &str,
    patterns: &[ScanRegexPatternSpec],
    policy: &ScanRegexSelectorPolicySpec,
) -> anyhow::Result<()> {
    if patterns.is_empty() {
        return Ok(());
    }

    let global_k = policy.k_of_n.unwrap_or(1);
    if global_k == 0 {
        anyhow::bail!(
            "Invalid `selector_policy.k_of_n` in '{}': value must be >= 1",
            pattern_path
        );
    }
    if global_k > patterns.len() {
        anyhow::bail!(
            "Invalid `selector_policy.k_of_n` in '{}': value {} exceeds total patterns {}",
            pattern_path,
            global_k,
            patterns.len()
        );
    }

    if let Some(min_score) = policy.min_score {
        if !min_score.is_finite() || min_score < 0.0 {
            anyhow::bail!(
                "Invalid `selector_policy.min_score` in '{}': expected a non-negative finite number",
                pattern_path
            );
        }
    }

    let mut patterns_by_group: BTreeMap<String, usize> = BTreeMap::new();
    for pattern in patterns {
        if let Some(group) = pattern.group.as_ref() {
            *patterns_by_group.entry(group.clone()).or_insert(0usize) += 1;
        }
    }

    let mut seen_groups = BTreeSet::new();
    for (idx, group_rule) in policy.groups.iter().enumerate() {
        let group_name = group_rule.name.trim();
        if group_name.is_empty() {
            anyhow::bail!(
                "Invalid `selector_policy.groups[{}]` in '{}': `name` must be non-empty",
                idx,
                pattern_path
            );
        }
        if !seen_groups.insert(group_name.to_string()) {
            anyhow::bail!(
                "Invalid `selector_policy.groups[{}]` in '{}': duplicate group '{}'",
                idx,
                pattern_path,
                group_name
            );
        }

        let Some(total_patterns) = patterns_by_group.get(group_name).copied() else {
            anyhow::bail!(
                "Invalid `selector_policy.groups[{}]` in '{}': group '{}' has no matching patterns",
                idx,
                pattern_path,
                group_name
            );
        };

        let group_k = group_rule.k_of_n.unwrap_or(1);
        if group_k == 0 {
            anyhow::bail!(
                "Invalid `selector_policy.groups[{}].k_of_n` in '{}': value must be >= 1",
                idx,
                pattern_path
            );
        }
        if group_k > total_patterns {
            anyhow::bail!(
                "Invalid `selector_policy.groups[{}].k_of_n` in '{}': value {} exceeds group pattern count {} for '{}'",
                idx,
                pattern_path,
                group_k,
                total_patterns,
                group_name
            );
        }

        if let Some(min_score) = group_rule.min_score {
            if !min_score.is_finite() || min_score < 0.0 {
                anyhow::bail!(
                    "Invalid `selector_policy.groups[{}].min_score` in '{}': expected a non-negative finite number",
                    idx,
                    pattern_path
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn load_scan_regex_selector_config(
    pattern_path: &str,
) -> anyhow::Result<Option<ScanRegexSelectorConfig>> {
    let raw = fs::read_to_string(pattern_path)
        .with_context(|| format!("Failed to read pattern YAML '{}'", pattern_path))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed to parse pattern YAML '{}'", pattern_path))?;
    let root = doc
        .as_mapping()
        .context("Pattern YAML root must be a mapping")?;

    let Some(patterns_value) = root.get(yaml_key("patterns")) else {
        return Ok(None);
    };

    let sequence = patterns_value
        .as_sequence()
        .context("'patterns' must be a YAML sequence when present")?;

    let normalization = match root.get(yaml_key("selector_normalization")) {
        Some(value) => serde_yaml::from_value(value.clone()).with_context(|| {
            format!(
                "Invalid `selector_normalization` in '{}': expected key `synonym_flexible_separators`",
                pattern_path
            )
        })?,
        None => ScanRegexSelectorNormalizationSpec::default(),
    };

    let synonyms: BTreeMap<String, Vec<String>> = match root
        .get(yaml_key("selector_synonyms"))
        .or_else(|| root.get(yaml_key("synonym_bundles")))
    {
        Some(value) => serde_yaml::from_value(value.clone()).with_context(|| {
            format!(
                "Invalid `selector_synonyms` in '{}': expected mapping of bundle -> list of strings",
                pattern_path
            )
        })?,
        None => BTreeMap::new(),
    };
    validate_scan_regex_synonym_bundles(pattern_path, &synonyms)?;
    let synonym_regexes =
        build_scan_regex_synonym_regexes(pattern_path, &synonyms, &normalization)?;

    let mut patterns: Vec<ScanRegexPatternSpec> = Vec::with_capacity(sequence.len());
    for (idx, item) in sequence.iter().enumerate() {
        let mut pattern: ScanRegexPatternSpec =
            serde_yaml::from_value(item.clone()).with_context(|| {
                format!(
                    "Invalid `patterns[{}]` entry in '{}': expected keys {{id, kind, pattern, message, group, weight}}",
                    idx, pattern_path
                )
            })?;

        pattern.id = pattern.id.trim().to_string();
        if pattern.id.is_empty() {
            anyhow::bail!(
                "Invalid `patterns[{}]` in '{}': `id` must be non-empty",
                idx,
                pattern_path
            );
        }
        pattern.pattern = pattern.pattern.trim().to_string();
        if pattern.pattern.is_empty() {
            anyhow::bail!(
                "Invalid `patterns[{}]` in '{}': `pattern` must be non-empty",
                idx,
                pattern_path
            );
        }
        if pattern.kind != ScanRegexPatternKind::Regex {
            anyhow::bail!(
                "Invalid `patterns[{}]` in '{}': only `kind: regex` is supported",
                idx,
                pattern_path
            );
        }

        if !pattern.weight.is_finite() || pattern.weight <= 0.0 {
            anyhow::bail!(
                "Invalid `patterns[{}]` in '{}': `weight` must be a positive finite number",
                idx,
                pattern_path
            );
        }

        pattern.group = pattern
            .group
            .map(|group| group.trim().to_string())
            .filter(|group| !group.is_empty());

        pattern.pattern = expand_scan_regex_synonym_placeholders(
            pattern_path,
            &pattern.id,
            &pattern.pattern,
            &synonym_regexes,
        )?;

        validate_scan_regex_pattern_safety(&pattern.pattern)
            .with_context(|| format!("Unsafe regex for pattern '{}'", pattern.id))?;
        RegexBuilder::new(&pattern.pattern)
            .case_insensitive(true)
            .size_limit(2 * 1024 * 1024)
            .dfa_size_limit(2 * 1024 * 1024)
            .build()
            .with_context(|| {
                format!("Invalid regex in `patterns[{}]` (id='{}')", idx, pattern.id)
            })?;

        patterns.push(pattern);
    }

    let policy = match root.get(yaml_key("selector_policy")) {
        Some(value) => serde_yaml::from_value(value.clone()).with_context(|| {
            format!(
                "Invalid `selector_policy` in '{}': expected keys {{k_of_n, min_score, groups}}",
                pattern_path
            )
        })?,
        None => ScanRegexSelectorPolicySpec::default(),
    };

    validate_scan_regex_selector_config(pattern_path, &patterns, &policy)?;

    Ok(Some(ScanRegexSelectorConfig { patterns, policy }))
}

pub(crate) fn evaluate_loaded_scan_regex_patterns(
    selector_config: &ScanRegexSelectorConfig,
    target_circuit: &Path,
) -> anyhow::Result<ScanRegexPatternSummary> {
    let patterns = &selector_config.patterns;
    if patterns.is_empty() {
        return Ok(ScanRegexPatternSummary::default());
    }

    let source = build_selector_source(target_circuit)?;
    let source = strip_selector_metadata_lines(&source);

    let mut line_starts = vec![0usize];
    for (idx, ch) in source.char_indices() {
        if ch == '\n' {
            line_starts.push(idx + 1);
        }
    }

    tracing::debug!("PATTERN FILTER START");
    let mut summary = ScanRegexPatternSummary {
        total_patterns: patterns.len(),
        required_k_of_n: selector_config.policy.k_of_n.unwrap_or(1),
        required_min_score: selector_config.policy.min_score.unwrap_or(0.0),
        ..Default::default()
    };
    let mut matched_pattern_ids: BTreeSet<String> = BTreeSet::new();
    for (idx, pattern) in patterns.iter().enumerate() {
        tracing::debug!(
            "pattern filter {}/{} {}",
            idx + 1,
            patterns.len(),
            pattern.id
        );

        let regex = RegexBuilder::new(&pattern.pattern)
            .case_insensitive(true)
            .size_limit(2 * 1024 * 1024)
            .dfa_size_limit(2 * 1024 * 1024)
            .build()
            .with_context(|| {
                format!(
                    "Invalid regex in pattern '{}' while scanning target '{}'",
                    pattern.id,
                    target_circuit.display()
                )
            })?;

        if regex.is_match(&source) {
            let mut lines: Vec<usize> = Vec::new();
            let mut occurrences = 0usize;
            for m in regex.find_iter(&source) {
                occurrences += 1;
                let line = match line_starts.binary_search(&m.start()) {
                    Ok(pos) => pos + 1,
                    Err(pos) => pos,
                };
                if lines.last().copied() != Some(line) {
                    lines.push(line);
                }
            }
            summary.matched_patterns += 1;
            summary.total_occurrences += occurrences;
            summary.matched_score += pattern.weight;
            summary.matched_ids.push(pattern.id.clone());
            matched_pattern_ids.insert(pattern.id.clone());
            summary.matches.push(ScanRegexPatternMatch {
                id: pattern.id.clone(),
                lines: lines.clone(),
                occurrences,
            });
            if let Some(message) = pattern
                .message
                .as_ref()
                .map(|m| m.trim())
                .filter(|m| !m.is_empty())
            {
                tracing::debug!(
                    "pattern hit {}: {} (matches: {}, weight: {:.2}, lines: {:?})",
                    pattern.id,
                    message,
                    occurrences,
                    pattern.weight,
                    lines
                );
            } else {
                tracing::debug!(
                    "pattern hit {} (matches: {}, weight: {:.2}, lines: {:?})",
                    pattern.id,
                    occurrences,
                    pattern.weight,
                    lines
                );
            }
        }
    }

    let mut grouped_stats: BTreeMap<String, (usize, usize, f64)> = BTreeMap::new();
    for pattern in patterns {
        let Some(group_name) = pattern.group.as_ref() else {
            continue;
        };
        let entry = grouped_stats
            .entry(group_name.clone())
            .or_insert((0usize, 0usize, 0.0f64));
        entry.0 += 1;
        if matched_pattern_ids.contains(&pattern.id) {
            entry.1 += 1;
            entry.2 += pattern.weight;
        }
    }

    for group_rule in &selector_config.policy.groups {
        let group_name = group_rule.name.trim();
        if group_name.is_empty() {
            continue;
        }
        let (total_patterns, matched_patterns, matched_score) = grouped_stats
            .get(group_name)
            .copied()
            .unwrap_or((0usize, 0usize, 0.0f64));
        let required_k_of_n = group_rule.k_of_n.unwrap_or(1);
        let required_min_score = group_rule.min_score.unwrap_or(0.0);
        let passed = matched_patterns >= required_k_of_n
            && matched_score + f64::EPSILON >= required_min_score;
        summary.group_matches.push(ScanRegexPatternGroupMatch {
            name: group_name.to_string(),
            total_patterns,
            matched_patterns,
            matched_score,
            required_k_of_n,
            required_min_score,
            passed,
        });
    }

    let global_k_pass = summary.matched_patterns >= summary.required_k_of_n;
    let global_score_pass = summary.matched_score + f64::EPSILON >= summary.required_min_score;
    let groups_pass = summary.group_matches.iter().all(|group| group.passed);
    summary.selector_passed = global_k_pass && global_score_pass && groups_pass;

    tracing::debug!("PATTERN FILTER END");
    let match_ratio = if summary.total_patterns == 0 {
        0.0
    } else {
        (summary.matched_patterns as f64 / summary.total_patterns as f64) * 100.0
    };
    tracing::debug!(
        "pattern summary: matched {}/{} ({:.1}%), total regex hits: {}",
        summary.matched_patterns,
        summary.total_patterns,
        match_ratio,
        summary.total_occurrences
    );
    tracing::debug!(
        "pattern gate: k_of_n {}/{} (required {}), score {:.2}/{:.2} => {}",
        summary.matched_patterns,
        summary.total_patterns,
        summary.required_k_of_n,
        summary.matched_score,
        summary.required_min_score,
        if global_k_pass && global_score_pass {
            "PASS"
        } else {
            "FAIL"
        }
    );
    for group in &summary.group_matches {
        tracing::debug!(
            "pattern group {}: k_of_n {}/{} (required {}), score {:.2}/{:.2} => {}",
            group.name,
            group.matched_patterns,
            group.total_patterns,
            group.required_k_of_n,
            group.matched_score,
            group.required_min_score,
            if group.passed { "PASS" } else { "FAIL" }
        );
    }
    for hit in &summary.matches {
        let frequency = if summary.total_occurrences == 0 {
            0.0
        } else {
            (hit.occurrences as f64 / summary.total_occurrences as f64) * 100.0
        };
        tracing::debug!(
            "pattern frequency {}: {} hits ({:.1}%)",
            hit.id,
            hit.occurrences,
            frequency
        );
    }
    tracing::debug!(
        "pattern selector verdict: {}",
        if summary.selector_passed {
            "PASS"
        } else {
            "FAIL"
        }
    );

    Ok(summary)
}

fn strip_selector_metadata_lines(source: &str) -> String {
    source
        .lines()
        .filter(|line| {
            !line.starts_with("__selector_target_path__: ")
                && !line.starts_with("__selector_target_file__: ")
                && !line.starts_with("__selector_context_file__: ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn selector_failure_detail(summary: &ScanRegexPatternSummary) -> String {
    let mut reasons: Vec<String> = Vec::new();
    if summary.matched_patterns < summary.required_k_of_n {
        reasons.push(format!(
            "k_of_n not met (matched {} of {}, required >= {})",
            summary.matched_patterns, summary.total_patterns, summary.required_k_of_n
        ));
    }
    if summary.matched_score + f64::EPSILON < summary.required_min_score {
        reasons.push(format!(
            "score threshold not met (matched {:.2}, required >= {:.2})",
            summary.matched_score, summary.required_min_score
        ));
    }
    for group in &summary.group_matches {
        if !group.passed {
            reasons.push(format!(
                "group '{}' unmet (k_of_n {}/{}, required >= {}; score {:.2}, required >= {:.2})",
                group.name,
                group.matched_patterns,
                group.total_patterns,
                group.required_k_of_n,
                group.matched_score,
                group.required_min_score
            ));
        }
    }
    if reasons.is_empty() {
        "selector policy thresholds not satisfied".to_string()
    } else {
        reasons.join("; ")
    }
}

pub(crate) fn evaluate_scan_selectors_or_bail(
    pattern_path: &str,
    selector_config: Option<&ScanRegexSelectorConfig>,
    target_circuit: &Path,
) -> anyhow::Result<Option<ScanRegexPatternSummary>> {
    let Some(selector_config) = selector_config else {
        return Ok(None);
    };

    let summary = evaluate_loaded_scan_regex_patterns(selector_config, target_circuit)?;
    if !summary.selector_passed {
        let detail = selector_failure_detail(&summary);
        anyhow::bail!(
            "Pattern '{}' selectors did not match target circuit '{}': {}. \
             Refine `patterns`/`selector_policy` or choose a matching pattern YAML.",
            pattern_path,
            target_circuit.display(),
            detail
        );
    }
    tracing::info!(
        "Pattern selectors matched {}/{} (score {:.2}, required {:.2}): [{}]",
        summary.matched_patterns,
        summary.total_patterns,
        summary.matched_score,
        summary.required_min_score,
        summary.matched_ids.join(", ")
    );
    Ok(Some(summary))
}
