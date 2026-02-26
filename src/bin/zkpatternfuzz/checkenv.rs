use anyhow::{bail, Context};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

fn parse_env_line(line: &str, line_no: usize) -> anyhow::Result<Option<(String, String)>> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }

    let candidate = if let Some(rest) = trimmed.strip_prefix("export ") {
        rest.trim_start()
    } else {
        trimmed
    };

    let Some((raw_key, raw_value)) = candidate.split_once('=') else {
        bail!("Invalid .env entry at line {}: expected KEY=VALUE", line_no);
    };

    let key = raw_key.trim();
    if key.is_empty() {
        bail!("Invalid .env entry at line {}: empty key", line_no);
    }
    if !key
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        bail!(
            "Invalid .env key '{}' at line {}: use only [A-Za-z0-9_]",
            key,
            line_no
        );
    }

    let mut value = raw_value.trim().to_string();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        let quoted = (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'');
        if quoted {
            value = value[1..value.len() - 1].to_string();
        }
    }

    Ok(Some((key.to_string(), value)))
}

fn dotenv_overlay_store() -> &'static Mutex<BTreeMap<String, String>> {
    static STORE: OnceLock<Mutex<BTreeMap<String, String>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn load_dotenv(path: &Path) -> anyhow::Result<BTreeMap<String, String>> {
    if !path.exists() {
        bail!(
            "Missing env file '{}'. Create it with required runtime keys before running zkpatternfuzz.",
            path.display()
        );
    }

    let mut parsed = BTreeMap::new();
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read env file '{}'", path.display()))?;
    for (idx, line) in content.lines().enumerate() {
        let line_no = idx + 1;
        if let Some((key, value)) = parse_env_line(line, line_no)? {
            parsed.insert(key, value);
        }
    }
    Ok(parsed)
}

fn env_value_with_overlay(
    key: &str,
    overlay: &BTreeMap<String, String>,
) -> Result<String, std::env::VarError> {
    match std::env::var(key) {
        Ok(value) => Ok(value),
        Err(std::env::VarError::NotPresent) => overlay
            .get(key)
            .cloned()
            .ok_or(std::env::VarError::NotPresent),
        Err(err) => Err(err),
    }
}

fn ensure_required_env(
    required_keys: &[&str],
    source_path: &Path,
    overlay: &BTreeMap<String, String>,
) -> anyhow::Result<()> {
    let mut missing = Vec::new();
    for key in required_keys {
        match env_value_with_overlay(key, overlay) {
            Ok(value) if !value.trim().is_empty() => {}
            _ => missing.push((*key).to_string()),
        }
    }

    if !missing.is_empty() {
        bail!(
            "Missing required env keys in '{}': {}",
            source_path.display(),
            missing.join(", ")
        );
    }
    Ok(())
}

pub struct CheckEnv;

impl CheckEnv {
    pub fn new(path: &Path, required_keys: &[&str]) -> anyhow::Result<Self> {
        let parsed = load_dotenv(path)?;
        ensure_required_env(required_keys, path, &parsed)?;

        let mut overlay = dotenv_overlay_store()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        overlay.clear();
        for (key, value) in parsed {
            if std::env::var_os(&key).is_none() {
                overlay.insert(key, value);
            }
        }

        Ok(Self)
    }
}

pub fn var(name: &str) -> Result<String, std::env::VarError> {
    let overlay = dotenv_overlay_store()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    env_value_with_overlay(name, &overlay)
}

pub fn is_set(name: &str) -> bool {
    var(name).is_ok()
}
