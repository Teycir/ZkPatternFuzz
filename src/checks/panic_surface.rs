use anyhow::Context;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const DEFAULT_SEARCH_ROOTS: &[&str] = &["src", "crates"];
pub const EXCLUDED_DIR_NAMES: &[&str] = &["target", "tests", "benches", "examples"];
const UNWRAP_CALL_MARKER: &str = concat!(".un", "wrap(");
const EXPECT_CALL_MARKER: &str = concat!(".ex", "pect(");

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PanicMatch {
    pub path: String,
    pub line: usize,
    pub code: String,
}

impl PanicMatch {
    pub fn key(&self) -> String {
        format!("{}|{}", self.path, self.code.trim())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PanicSurfaceReport {
    pub matches: usize,
    pub allowlist: usize,
    pub unknown: usize,
    pub stale: usize,
    pub unknown_entries: Vec<String>,
    pub stale_entries: Vec<String>,
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

pub fn is_excluded_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or_default();
    if name == "tests.rs" || name.ends_with("_tests.rs") || name.starts_with("test_") {
        return true;
    }
    path.components().any(|part| {
        let component = part.as_os_str().to_string_lossy();
        EXCLUDED_DIR_NAMES
            .iter()
            .any(|excluded| component == *excluded)
    })
}

pub fn collect_panic_matches(
    repo_root: &Path,
    search_roots: &[String],
) -> anyhow::Result<Vec<PanicMatch>> {
    let mut matches = Vec::new();

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

            let rel_path_buf: PathBuf = path.strip_prefix(repo_root).unwrap_or(path).to_path_buf();
            if is_excluded_path(&rel_path_buf) {
                continue;
            }

            let text = std::fs::read_to_string(path)
                .or_else(|_| {
                    std::fs::read(path).map(|bytes| String::from_utf8_lossy(&bytes).to_string())
                })
                .with_context(|| format!("Failed to read source file '{}'", path.display()))?;
            let rel = to_relative_slash_path(repo_root, path)?;

            for (idx, line) in text.lines().enumerate() {
                let stripped = line.trim();
                if stripped.is_empty() || stripped.starts_with("//") {
                    continue;
                }
                if !line.contains(UNWRAP_CALL_MARKER) && !line.contains(EXPECT_CALL_MARKER) {
                    continue;
                }
                matches.push(PanicMatch {
                    path: rel.clone(),
                    line: idx + 1,
                    code: line.trim_end().to_string(),
                });
            }
        }
    }

    matches.sort_by(|a, b| (&a.path, a.line, &a.code).cmp(&(&b.path, b.line, &b.code)));
    Ok(matches)
}

pub fn load_allowlist(path: &Path) -> anyhow::Result<BTreeSet<String>> {
    if !path.exists() {
        return Ok(BTreeSet::new());
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read allowlist '{}'", path.display()))?;
    let mut keys = BTreeSet::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        keys.insert(line.to_string());
    }
    Ok(keys)
}

pub fn write_allowlist(path: &Path, keys: &BTreeSet<String>) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed creating allowlist parent directory '{}'",
                parent.display()
            )
        })?;
    }
    let content = if keys.is_empty() {
        String::new()
    } else {
        format!(
            "{}\n",
            keys.iter().cloned().collect::<Vec<String>>().join("\n")
        )
    };
    std::fs::write(path, content)
        .with_context(|| format!("Failed writing allowlist '{}'", path.display()))?;
    Ok(())
}

pub fn build_report(
    current_keys: &BTreeSet<String>,
    allowed: &BTreeSet<String>,
) -> PanicSurfaceReport {
    let unknown_entries: Vec<String> = current_keys.difference(allowed).cloned().collect();
    let stale_entries: Vec<String> = allowed.difference(current_keys).cloned().collect();
    PanicSurfaceReport {
        matches: current_keys.len(),
        allowlist: allowed.len(),
        unknown: unknown_entries.len(),
        stale: stale_entries.len(),
        unknown_entries,
        stale_entries,
    }
}
