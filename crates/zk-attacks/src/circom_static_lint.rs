//! Circom-specific static lint checks.
//!
//! This module provides a fast first-pass static analysis for common Circom
//! anti-patterns that correlate with missing constraints.

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use zk_core::{AttackType, Finding, ProofOfConcept, Severity};

/// Supported Circom static checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticCheck {
    /// Signal declared but only appears at declaration site.
    UnusedSignal,
    /// Output not constrained with `<==`.
    UnconstrainedOutput,
    /// Division where denominator appears to be signal/identifier.
    DivisionBySignal,
    /// `<--` assignment without a matching constraint.
    MissingConstraint,
    /// Signal assignment inside conditional branches (possible path-dependent constraints).
    BranchDependentConstraint,
}

impl StaticCheck {
    fn from_config_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "unused_signal" | "unusedsignal" => Some(Self::UnusedSignal),
            "unconstrained_output" | "unconstrainedoutput" => Some(Self::UnconstrainedOutput),
            "division_by_signal" | "divisionbysignal" => Some(Self::DivisionBySignal),
            "missing_constraint" | "missingconstraint" => Some(Self::MissingConstraint),
            "branch_dependent_constraint"
            | "branchdependentconstraint"
            | "conditional_assignment"
            | "conditionalassignment" => Some(Self::BranchDependentConstraint),
            _ => None,
        }
    }
}

/// Configuration for Circom static linting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircomStaticLintConfig {
    /// Enabled checks.
    pub enabled_checks: Vec<StaticCheck>,
    /// Maximum emitted findings per check.
    pub max_findings_per_check: usize,
    /// Whether matching should be case-sensitive.
    pub case_sensitive: bool,
}

impl Default for CircomStaticLintConfig {
    fn default() -> Self {
        Self {
            enabled_checks: vec![
                StaticCheck::UnusedSignal,
                StaticCheck::UnconstrainedOutput,
                StaticCheck::DivisionBySignal,
                StaticCheck::MissingConstraint,
                StaticCheck::BranchDependentConstraint,
            ],
            max_findings_per_check: 20,
            case_sensitive: false,
        }
    }
}

#[derive(Debug, Clone)]
struct SignalDecl {
    name: String,
    line: usize,
    is_output: bool,
}

/// Circom static linter.
pub struct CircomStaticLint {
    config: CircomStaticLintConfig,
}

impl CircomStaticLint {
    /// Create a new static linter.
    pub fn new(config: CircomStaticLintConfig) -> Self {
        Self { config }
    }

    /// Parse static-check list from strings.
    pub fn parse_checks(values: &[String]) -> Vec<StaticCheck> {
        values
            .iter()
            .filter_map(|name| StaticCheck::from_config_name(name))
            .collect()
    }

    /// Scan source file and return findings.
    pub fn scan_file(&self, source_path: &Path) -> anyhow::Result<Vec<Finding>> {
        let source = std::fs::read_to_string(source_path)?;
        Ok(self.scan_source(&source, Some(source_path.display().to_string())))
    }

    /// Scan source text and return findings.
    pub fn scan_source(&self, source: &str, location_prefix: Option<String>) -> Vec<Finding> {
        let source_no_comments = strip_comments(source);
        let decls = parse_signal_declarations(&source_no_comments, self.config.case_sensitive);

        let mut findings = Vec::new();
        let max_per_check = self.config.max_findings_per_check.max(1);

        if self
            .config
            .enabled_checks
            .contains(&StaticCheck::UnusedSignal)
        {
            let mut count = 0usize;
            for decl in &decls {
                if count >= max_per_check {
                    break;
                }
                let refs =
                    word_occurrences(&source_no_comments, &decl.name, self.config.case_sensitive);
                if refs <= 1 {
                    findings.push(make_finding(
                        Severity::Low,
                        format!("Declared signal appears unused: {}", decl.name),
                        with_line(&location_prefix, decl.line),
                    ));
                    count += 1;
                }
            }
        }

        if self
            .config
            .enabled_checks
            .contains(&StaticCheck::UnconstrainedOutput)
        {
            let mut count = 0usize;
            for decl in decls.iter().filter(|decl| decl.is_output) {
                if count >= max_per_check {
                    break;
                }
                let has_constrained_assign = has_assignment(
                    &source_no_comments,
                    &decl.name,
                    "<==",
                    self.config.case_sensitive,
                );
                if has_constrained_assign {
                    continue;
                }

                let has_unconstrained_assign = has_assignment(
                    &source_no_comments,
                    &decl.name,
                    "<--",
                    self.config.case_sensitive,
                );
                let severity = if has_unconstrained_assign {
                    Severity::High
                } else {
                    Severity::Medium
                };

                findings.push(make_finding(
                    severity,
                    format!("Output signal '{}' is not constrained with <==", decl.name),
                    with_line(&location_prefix, decl.line),
                ));
                count += 1;
            }
        }

        if self
            .config
            .enabled_checks
            .contains(&StaticCheck::DivisionBySignal)
        {
            let mut count = 0usize;
            for (line_no, line) in source_no_comments.lines().enumerate() {
                if count >= max_per_check {
                    break;
                }
                if !line.contains('/') {
                    continue;
                }
                if has_division_by_identifier(line) {
                    findings.push(make_finding(
                        Severity::High,
                        "Potential division-by-signal pattern detected".to_string(),
                        with_line(&location_prefix, line_no + 1),
                    ));
                    count += 1;
                }
            }
        }

        if self
            .config
            .enabled_checks
            .contains(&StaticCheck::MissingConstraint)
        {
            let mut count = 0usize;
            let assign_re = compile_regex(
                r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]+\])?\s*<--",
                self.config.case_sensitive,
            );
            if let Some(assign_re) = assign_re {
                for captures in assign_re.captures_iter(&source_no_comments) {
                    if count >= max_per_check {
                        break;
                    }
                    let Some(lhs) = captures.get(1).map(|m| m.as_str()) else {
                        continue;
                    };
                    let has_related_constraint = has_related_constraint(
                        &source_no_comments,
                        lhs,
                        self.config.case_sensitive,
                    );
                    if has_related_constraint {
                        continue;
                    }
                    let line = captures
                        .get(0)
                        .map(|m| byte_offset_to_line(&source_no_comments, m.start()))
                        .unwrap_or(1);
                    findings.push(make_finding(
                        Severity::Critical,
                        format!(
                            "`<--` assignment to '{}' has no matching `===` / `<==` constraint",
                            lhs
                        ),
                        with_line(&location_prefix, line),
                    ));
                    count += 1;
                }
            }
        }

        if self
            .config
            .enabled_checks
            .contains(&StaticCheck::BranchDependentConstraint)
        {
            let mut count = 0usize;
            let mut seen = HashSet::new();
            for assignment in
                collect_conditional_assignments(&source_no_comments, self.config.case_sensitive)
            {
                if count >= max_per_check {
                    break;
                }
                if !condition_appears_dynamic(&assignment.condition) {
                    continue;
                }
                // Avoid duplicate findings for the same signal within one conditional block.
                if !seen.insert((assignment.if_line, assignment.signal.clone())) {
                    continue;
                }

                let severity = if assignment.operator == "<--" {
                    Severity::Critical
                } else {
                    Severity::High
                };
                findings.push(make_finding(
                    severity,
                    format!(
                        "Signal '{}' is assigned with '{}' inside conditional at line {}; ensure both branches are fully constrained",
                        assignment.signal, assignment.operator, assignment.if_line
                    ),
                    with_line(&location_prefix, assignment.line),
                ));
                count += 1;
            }
        }

        findings
    }
}

fn make_finding(severity: Severity, description: String, location: Option<String>) -> Finding {
    Finding {
        attack_type: AttackType::CircomStaticLint,
        severity,
        description,
        poc: ProofOfConcept {
            witness_a: Vec::new(),
            witness_b: None,
            public_inputs: Vec::new(),
            proof: None,
        },
        location,
    }
}

fn with_line(location_prefix: &Option<String>, line: usize) -> Option<String> {
    location_prefix
        .as_ref()
        .map(|prefix| format!("{}:{}", prefix, line))
}

fn strip_comments(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut in_line_comment = false;
    let mut in_block_comment = false;

    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                result.push('\n');
            } else if ch == '\r' {
                // Keep CRLF layout stable when present.
                result.push('\r');
            } else {
                result.push(' ');
            }
            continue;
        }

        if in_block_comment {
            if ch == '*' && chars.peek().copied() == Some('/') {
                let _ = chars.next();
                in_block_comment = false;
                result.push(' ');
                result.push(' ');
            } else if ch == '\n' {
                result.push('\n');
            } else if ch == '\r' {
                result.push('\r');
            } else {
                result.push(' ');
            }
            continue;
        }

        if ch == '/' {
            match chars.peek().copied() {
                Some('/') => {
                    let _ = chars.next();
                    in_line_comment = true;
                    result.push(' ');
                    result.push(' ');
                    continue;
                }
                Some('*') => {
                    let _ = chars.next();
                    in_block_comment = true;
                    result.push(' ');
                    result.push(' ');
                    continue;
                }
                _ => {}
            }
        }

        result.push(ch);
    }

    result
}

fn compile_regex(pattern: &str, case_sensitive: bool) -> Option<Regex> {
    RegexBuilder::new(pattern)
        .case_insensitive(!case_sensitive)
        .build()
        .ok()
}

fn parse_signal_declarations(source: &str, case_sensitive: bool) -> Vec<SignalDecl> {
    let Some(decl_re) = compile_regex(
        r"(?m)^\s*signal\s+(?:(input|output)\s+)?([A-Za-z_][A-Za-z0-9_]*)",
        case_sensitive,
    ) else {
        return Vec::new();
    };

    decl_re
        .captures_iter(source)
        .filter_map(|captures| {
            let name = captures.get(2)?.as_str().to_string();
            let class = captures.get(1).map(|m| m.as_str()).unwrap_or_default();
            let line = captures
                .get(0)
                .map(|m| byte_offset_to_line(source, m.start()))
                .unwrap_or(1);
            Some(SignalDecl {
                name,
                line,
                is_output: class.eq_ignore_ascii_case("output"),
            })
        })
        .collect()
}

fn byte_offset_to_line(source: &str, offset: usize) -> usize {
    source[..offset].lines().count() + 1
}

fn word_occurrences(source: &str, word: &str, case_sensitive: bool) -> usize {
    let escaped = regex::escape(word);
    let pattern = format!(r"\b{}\b", escaped);
    let Some(regex) = compile_regex(&pattern, case_sensitive) else {
        return 0;
    };
    regex.find_iter(source).count()
}

fn has_assignment(source: &str, name: &str, operator: &str, case_sensitive: bool) -> bool {
    let escaped_name = regex::escape(name);
    let escaped_op = regex::escape(operator);
    let pattern = format!(
        r"(?m)\b{}\b\s*{}|{}\s*\b{}\b",
        escaped_name, escaped_op, escaped_op, escaped_name
    );
    compile_regex(&pattern, case_sensitive)
        .map(|re| re.is_match(source))
        .unwrap_or(false)
}

fn has_related_constraint(source: &str, name: &str, case_sensitive: bool) -> bool {
    let escaped_name = regex::escape(name);
    let pattern = format!(
        r"(?m)\b{}\b\s*===|===\s*\b{}\b|\b{}\b\s*<==",
        escaped_name, escaped_name, escaped_name
    );
    compile_regex(&pattern, case_sensitive)
        .map(|re| re.is_match(source))
        .unwrap_or(false)
}

fn has_division_by_identifier(line: &str) -> bool {
    let mut parts = line.split('/').skip(1);
    for rhs in parts.by_ref() {
        let rhs = rhs.trim_start();
        let token: String = rhs
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .collect();
        if token.is_empty() {
            continue;
        }
        if token.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        return true;
    }
    false
}

#[derive(Debug, Clone)]
struct ConditionalAssignment {
    signal: String,
    operator: String,
    condition: String,
    line: usize,
    if_line: usize,
}

fn collect_conditional_assignments(
    source: &str,
    case_sensitive: bool,
) -> Vec<ConditionalAssignment> {
    let Some(if_re) = compile_regex(r"^\s*if\s*\(([^)]*)\)\s*\{", case_sensitive) else {
        return Vec::new();
    };
    let Some(assign_re) = compile_regex(
        r"^\s*([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]+\])?\s*(<--|<==)",
        case_sensitive,
    ) else {
        return Vec::new();
    };

    let lines: Vec<&str> = source.lines().collect();
    let mut findings = Vec::new();
    let mut idx = 0usize;

    while idx < lines.len() {
        let line = lines[idx];
        let Some(if_caps) = if_re.captures(line) else {
            idx += 1;
            continue;
        };

        let condition = if_caps
            .get(1)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        let if_line = idx + 1;
        let mut depth = brace_delta(line);
        idx += 1;

        while idx < lines.len() && depth > 0 {
            let current = lines[idx];
            if let Some(assign_caps) = assign_re.captures(current) {
                let signal = assign_caps
                    .get(1)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                let operator = assign_caps
                    .get(2)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                if !signal.is_empty() && !operator.is_empty() {
                    findings.push(ConditionalAssignment {
                        signal,
                        operator,
                        condition: condition.clone(),
                        line: idx + 1,
                        if_line,
                    });
                }
            }
            depth += brace_delta(current);
            idx += 1;
        }
    }

    findings
}

fn brace_delta(line: &str) -> i32 {
    let open = line.chars().filter(|ch| *ch == '{').count() as i32;
    let close = line.chars().filter(|ch| *ch == '}').count() as i32;
    open - close
}

fn condition_appears_dynamic(condition: &str) -> bool {
    let Some(identifier_re) = Regex::new(r"[A-Za-z_][A-Za-z0-9_]*").ok() else {
        return false;
    };
    let mut has_identifier = false;
    for ident in identifier_re.find_iter(condition).map(|m| m.as_str()) {
        let lower = ident.to_ascii_lowercase();
        if matches!(lower.as_str(), "if" | "true" | "false") {
            continue;
        }
        has_identifier = true;
        break;
    }
    has_identifier
}

#[cfg(test)]
#[path = "circom_static_lint_tests.rs"]
mod tests;
