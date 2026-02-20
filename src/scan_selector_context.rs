use anyhow::Context;
use std::fs;
use std::path::{Path, PathBuf};

const SELECTOR_MAX_CONTEXT_BYTES: usize = 512 * 1024;
const SELECTOR_MAX_CONTEXT_FILES: usize = 64;
const SELECTOR_MAX_FILE_BYTES: usize = 64 * 1024;

struct SelectorContextSystem {
    manifest_names: &'static [&'static str],
    source_roots: &'static [&'static str],
    allowed_extensions: &'static [&'static str],
}

const SELECTOR_CONTEXT_SYSTEMS: &[SelectorContextSystem] = &[
    SelectorContextSystem {
        manifest_names: &["Cargo.toml"],
        source_roots: &["src"],
        allowed_extensions: &["rs", "toml", "json"],
    },
    SelectorContextSystem {
        manifest_names: &["Nargo.toml"],
        source_roots: &["src"],
        allowed_extensions: &["nr", "toml", "json"],
    },
];

pub(crate) fn build_selector_source(target_circuit: &Path) -> anyhow::Result<String> {
    let source = fs::read_to_string(target_circuit).with_context(|| {
        format!(
            "Failed to read target circuit '{}' for regex pattern evaluation",
            target_circuit.display()
        )
    })?;

    let mut builder = SelectorSourceBuilder::new(target_circuit, source);
    for system in SELECTOR_CONTEXT_SYSTEMS {
        if system.supports(target_circuit) {
            system.append_context(target_circuit, &mut builder);
        }
    }
    Ok(builder.finish())
}

impl SelectorContextSystem {
    fn supports(&self, target: &Path) -> bool {
        let Some(name) = target.file_name().and_then(|name| name.to_str()) else {
            return false;
        };
        self.manifest_names.contains(&name)
    }

    fn append_context(&self, target: &Path, builder: &mut SelectorSourceBuilder) {
        let Some(project_root) = target.parent() else {
            return;
        };
        for root in self.source_roots {
            let source_dir = project_root.join(root);
            if !source_dir.is_dir() {
                continue;
            }
            self.walk_source_dir(&source_dir, builder);
        }
    }

    fn walk_source_dir(&self, root: &Path, builder: &mut SelectorSourceBuilder) {
        if builder.exhausted() {
            return;
        }
        let Ok(entries) = fs::read_dir(root) else {
            return;
        };

        let mut paths: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .collect();
        paths.sort();

        for path in paths {
            if builder.exhausted() {
                break;
            }
            if path.is_dir() {
                self.walk_source_dir(&path, builder);
                continue;
            }
            if !self.is_allowed_text_file(&path) {
                continue;
            }
            let Some(snippet) = read_selector_snippet(&path) else {
                continue;
            };
            builder.append_context_file(&path, &snippet);
        }
    }

    fn is_allowed_text_file(&self, path: &Path) -> bool {
        let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
            return false;
        };
        self.allowed_extensions.contains(&ext)
    }
}

struct SelectorSourceBuilder {
    out: String,
    bytes_used: usize,
    files_used: usize,
}

impl SelectorSourceBuilder {
    fn new(target: &Path, base_source: String) -> Self {
        let mut out = String::new();
        out.push_str("__selector_target_path__: ");
        out.push_str(&target.to_string_lossy());
        out.push('\n');
        out.push_str("__selector_target_file__: ");
        out.push_str(
            target
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("<unknown>"),
        );
        out.push('\n');
        out.push_str(&base_source);
        out.push('\n');

        Self {
            bytes_used: out.len(),
            out,
            files_used: 0,
        }
    }

    fn exhausted(&self) -> bool {
        self.bytes_used >= SELECTOR_MAX_CONTEXT_BYTES
            || self.files_used >= SELECTOR_MAX_CONTEXT_FILES
    }

    fn append_context_file(&mut self, path: &Path, snippet: &str) {
        if self.exhausted() {
            return;
        }
        self.files_used += 1;
        self.out.push('\n');
        self.out.push_str("__selector_context_file__: ");
        self.out.push_str(&path.to_string_lossy());
        self.out.push('\n');
        self.write_snippet_with_budget(snippet);
    }

    fn write_snippet_with_budget(&mut self, snippet: &str) {
        if self.bytes_used >= SELECTOR_MAX_CONTEXT_BYTES {
            return;
        }
        let remaining = SELECTOR_MAX_CONTEXT_BYTES - self.bytes_used;
        if snippet.len() <= remaining {
            self.out.push_str(snippet);
            self.bytes_used += snippet.len();
            return;
        }

        let mut cut = remaining;
        while cut > 0 && !snippet.is_char_boundary(cut) {
            cut -= 1;
        }
        self.out.push_str(&snippet[..cut]);
        self.bytes_used += cut;
    }

    fn finish(self) -> String {
        self.out
    }
}

fn read_selector_snippet(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    if content.len() <= SELECTOR_MAX_FILE_BYTES {
        return Some(content);
    }

    let mut snippet = content;
    let mut cut = SELECTOR_MAX_FILE_BYTES;
    while cut > 0 && !snippet.is_char_boundary(cut) {
        cut -= 1;
    }
    snippet.truncate(cut);
    Some(snippet)
}
