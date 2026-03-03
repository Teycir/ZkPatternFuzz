use anyhow::Context;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const DEFAULT_SEARCH_ROOTS: &[&str] = &["src", "crates"];
pub const DEFAULT_BASELINE: &str = "config/prod_test_separation_baseline.json";
pub const EXCLUDED_DIR_NAMES: &[&str] = &["target", "tests", "benches", "examples"];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Violation {
    pub path: String,
    pub line: usize,
    pub kind: String,
    pub code: String,
}

impl Violation {
    pub fn signature(&self) -> (String, String, String) {
        (
            self.path.clone(),
            self.kind.clone(),
            self.code.trim().to_string(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineViolationEntry {
    pub path: String,
    pub kind: String,
    pub code: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFile {
    pub format_version: u32,
    pub description: String,
    pub violations: Vec<BaselineViolationEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProdTestSeparationReport {
    pub repo_root: String,
    pub search_roots: Vec<String>,
    pub baseline_path: String,
    pub strict: bool,
    pub violation_count: usize,
    pub legacy_violation_count: usize,
    pub new_violation_count: usize,
    pub baseline_signature_count: usize,
    pub violations: Vec<Violation>,
    pub new_violations: Vec<Violation>,
    pub pass: bool,
}

pub fn is_test_like_filename(name: &str) -> bool {
    name == "tests.rs" || name.ends_with("_tests.rs") || name.starts_with("test_")
}

pub fn is_excluded_path(path: &Path) -> bool {
    path.components().any(|part| {
        let component = part.as_os_str().to_string_lossy();
        EXCLUDED_DIR_NAMES
            .iter()
            .any(|excluded| component == *excluded)
    })
}

fn path_attr_target(raw_attr: &str) -> Option<String> {
    let pattern = Regex::new(r#"^\s*#\[\s*path\s*=\s*"([^"]+)"\s*\]"#).ok()?;
    pattern
        .captures(raw_attr.trim())
        .and_then(|capture| capture.get(1).map(|m| m.as_str().to_string()))
}

fn is_test_path(path_str: &str) -> bool {
    let norm = path_str.replace('\\', "/");
    let name = norm.rsplit('/').next().unwrap_or_default();
    if is_test_like_filename(name) {
        return true;
    }
    format!("/{norm}/").contains("/tests/")
}

fn is_test_attribute_line(raw_attr: &str) -> bool {
    let compact = raw_attr.split_whitespace().collect::<String>();
    let test_attr = match Regex::new(r#"^#!?\[(?:[A-Za-z_][A-Za-z0-9_]*::)*test(?:[(\]]|$)"#) {
        Ok(pattern) => pattern,
        Err(_) => return false,
    };
    let contains_test_token = |text: &str| -> bool {
        let mut token_start: Option<usize> = None;
        for (idx, ch) in text.char_indices() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                if token_start.is_none() {
                    token_start = Some(idx);
                }
                continue;
            }
            if let Some(start) = token_start.take() {
                if &text[start..idx] == "test" {
                    return true;
                }
            }
        }
        if let Some(start) = token_start {
            return &text[start..] == "test";
        }
        false
    };
    if test_attr.is_match(&compact) {
        return true;
    }
    if compact.starts_with("#[cfg(") || compact.starts_with("#![cfg(") {
        return contains_test_token(&compact);
    }
    if compact.starts_with("#[cfg_attr(") || compact.starts_with("#![cfg_attr(") {
        return contains_test_token(&compact);
    }
    false
}

fn to_relative_slash_path(repo_root: &Path, rust_file: &Path) -> anyhow::Result<String> {
    let rel = rust_file.strip_prefix(repo_root).with_context(|| {
        format!(
            "Failed to make '{}' relative to '{}'",
            rust_file.display(),
            repo_root.display()
        )
    })?;
    Ok(rel.to_string_lossy().replace('\\', "/"))
}

pub fn collect_violations(
    repo_root: &Path,
    search_roots: &[String],
) -> anyhow::Result<Vec<Violation>> {
    let mod_decl_pattern = Regex::new(r#"^\s*mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;"#)
        .with_context(|| "Failed compiling production/test-separation module-declaration regex")?;
    let use_test_symbol_pattern =
        Regex::new(r#"\b(?:pub(?:\([^)]*\))?\s+)?use\s+[^;]*(?:\btests\b|_tests\b)"#)
            .with_context(|| "Failed compiling production/test-separation symbol regex")?;

    let mut violations = Vec::new();

    for root_name in search_roots {
        let root = repo_root.join(root_name);
        if !root.exists() {
            continue;
        }
        let walker = walkdir::WalkDir::new(&root).into_iter();
        for entry in walker {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let path = entry.path();
            if !entry.file_type().is_file()
                || path.extension().and_then(|v| v.to_str()) != Some("rs")
            {
                continue;
            }

            let rel_buf: PathBuf = path.strip_prefix(repo_root).unwrap_or(path).to_path_buf();
            if is_excluded_path(&rel_buf) {
                continue;
            }
            let rel = to_relative_slash_path(repo_root, path)?;

            if let Some(file_name) = path.file_name().and_then(|v| v.to_str()) {
                if is_test_like_filename(file_name) {
                    violations.push(Violation {
                        path: rel.clone(),
                        line: 1,
                        kind: "test_file_in_production_tree".to_string(),
                        code: file_name.to_string(),
                    });
                }
            }

            let text = std::fs::read_to_string(path)
                .or_else(|_| {
                    std::fs::read(path).map(|bytes| String::from_utf8_lossy(&bytes).to_string())
                })
                .with_context(|| format!("Failed to read source file '{}'", path.display()))?;

            let mut pending_attrs: Vec<String> = Vec::new();
            for (idx, raw_line) in text.lines().enumerate() {
                let line_no = idx + 1;
                let stripped = raw_line.trim();

                if is_test_attribute_line(stripped) {
                    violations.push(Violation {
                        path: rel.clone(),
                        line: line_no,
                        kind: "test_attribute_in_production".to_string(),
                        code: raw_line.trim_end().to_string(),
                    });
                }

                if use_test_symbol_pattern.is_match(raw_line) {
                    violations.push(Violation {
                        path: rel.clone(),
                        line: line_no,
                        kind: "test_symbol_import_or_reexport".to_string(),
                        code: raw_line.trim_end().to_string(),
                    });
                }

                if stripped.starts_with("#[") {
                    pending_attrs.push(stripped.to_string());
                    continue;
                }
                if stripped.is_empty() {
                    pending_attrs.clear();
                    continue;
                }
                if stripped.starts_with("//") {
                    continue;
                }

                let has_test_path_attr = pending_attrs
                    .iter()
                    .filter_map(|attr| path_attr_target(attr))
                    .any(|target| is_test_path(&target));
                if has_test_path_attr {
                    violations.push(Violation {
                        path: rel.clone(),
                        line: line_no,
                        kind: "test_path_attr_in_production".to_string(),
                        code: raw_line.trim_end().to_string(),
                    });
                }

                if let Some(capture) = mod_decl_pattern.captures(raw_line) {
                    if let Some(module_name) = capture.get(1).map(|m| m.as_str()) {
                        if module_name == "tests" || module_name.ends_with("_tests") {
                            violations.push(Violation {
                                path: rel.clone(),
                                line: line_no,
                                kind: "test_module_decl_in_production".to_string(),
                                code: raw_line.trim_end().to_string(),
                            });
                        }
                    }
                }
                pending_attrs.clear();
            }
        }
    }

    violations.sort_by(|a, b| {
        (&a.path, a.line, &a.kind, &a.code).cmp(&(&b.path, b.line, &b.kind, &b.code))
    });
    Ok(violations)
}

pub fn load_baseline(path: &Path) -> anyhow::Result<BTreeMap<(String, String, String), usize>> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read baseline '{}'", path.display()))?;
    let baseline: BaselineFile = serde_json::from_str(&raw)
        .with_context(|| format!("Failed to parse baseline '{}'", path.display()))?;

    let mut signatures = BTreeMap::new();
    for entry in baseline.violations {
        let path = entry.path.trim().to_string();
        let kind = entry.kind.trim().to_string();
        let code = entry.code.trim().to_string();
        let count = entry.count;
        if !path.is_empty() && !kind.is_empty() && !code.is_empty() && count > 0 {
            signatures.insert((path, kind, code), count);
        }
    }
    Ok(signatures)
}

pub fn write_baseline(path: &Path, violations: &[Violation]) -> anyhow::Result<()> {
    let mut counts: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for violation in violations {
        let signature = violation.signature();
        *counts.entry(signature).or_insert(0) += 1;
    }
    let entries: Vec<BaselineViolationEntry> = counts
        .into_iter()
        .map(|((path, kind, code), count)| BaselineViolationEntry {
            path,
            kind,
            code,
            count,
        })
        .collect();
    let payload = BaselineFile {
        format_version: 1,
        description: "Known legacy prod/test separation violations; CI fails on any new entries."
            .to_string(),
        violations: entries,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed creating baseline parent directory '{}'",
                parent.display()
            )
        })?;
    }
    let json = serde_json::to_string_pretty(&payload)?;
    std::fs::write(path, format!("{json}\n"))
        .with_context(|| format!("Failed writing baseline '{}'", path.display()))?;
    Ok(())
}

pub fn filter_new_violations(
    violations: &[Violation],
    baseline_counts: &BTreeMap<(String, String, String), usize>,
) -> Vec<Violation> {
    let mut seen_counts: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    let mut new_violations = Vec::new();
    for violation in violations {
        let signature = violation.signature();
        let seen = seen_counts.get(&signature).copied().unwrap_or(0) + 1;
        seen_counts.insert(signature.clone(), seen);
        if seen > baseline_counts.get(&signature).copied().unwrap_or(0) {
            new_violations.push(violation.clone());
        }
    }
    new_violations
}

pub fn unique_signatures(violations: &[Violation]) -> BTreeSet<(String, String, String)> {
    violations.iter().map(Violation::signature).collect()
}
