use anyhow::Context;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;

pub const DEFAULT_BLOCKED_ROOT_FILES: &[&str] = &["new_file.txt"];

pub fn parse_blocklist_file(path: &Path) -> anyhow::Result<BTreeSet<String>> {
    let mut blocked = BTreeSet::new();
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read blocklist '{}'", path.display()))?;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        blocked.insert(line.to_string());
    }
    Ok(blocked)
}

pub fn blocked_root_files<'a>(
    repo_root: &Path,
    blocked_names: impl IntoIterator<Item = &'a str>,
) -> Vec<String> {
    let mut matches = Vec::new();
    let unique: BTreeSet<&str> = blocked_names.into_iter().collect();
    for name in unique {
        if repo_root.join(name).exists() {
            matches.push(name.to_string());
        }
    }
    matches
}

#[derive(Debug, Clone, Serialize)]
pub struct RepoHygieneReport {
    pub repo_root: String,
    pub blocked_root_files: Vec<String>,
    pub matches: Vec<String>,
    pub pass: bool,
}

pub fn build_report(
    repo_root: &Path,
    default_blocked: &[&str],
    extra_blocked: &BTreeSet<String>,
) -> RepoHygieneReport {
    let mut blocked: BTreeSet<String> = default_blocked.iter().map(|s| (*s).to_string()).collect();
    blocked.extend(extra_blocked.iter().cloned());

    let blocked_for_scan: Vec<&str> = blocked.iter().map(String::as_str).collect();
    let matches = blocked_root_files(repo_root, blocked_for_scan);

    RepoHygieneReport {
        repo_root: repo_root.display().to_string(),
        blocked_root_files: blocked.into_iter().collect(),
        pass: matches.is_empty(),
        matches,
    }
}
