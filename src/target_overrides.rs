use anyhow::Context;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_TARGET_OVERRIDES_INDEX_PATH: &str = "targets/zk0d_matrix_external_manual.yaml";

#[derive(Debug, Deserialize, Default, Clone)]
pub struct TargetRunOverrides {
    #[serde(default)]
    pub batch_jobs: Option<usize>,
    #[serde(default)]
    pub workers: Option<usize>,
    #[serde(default)]
    pub iterations: Option<u64>,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub env: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone)]
pub struct ResolvedTargetRunOverrides {
    pub target_name: String,
    pub target_circuit: PathBuf,
    pub overrides_path: PathBuf,
    pub overrides: TargetRunOverrides,
}

fn yaml_key(name: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(name.to_string())
}

fn expand_env_placeholders(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    let mut out = String::new();

    while i < chars.len() {
        if chars[i] != '$' {
            out.push(chars[i]);
            i += 1;
            continue;
        }

        if i + 1 < chars.len() && chars[i + 1] == '{' {
            let mut j = i + 2;
            while j < chars.len() && chars[j] != '}' {
                j += 1;
            }
            if j >= chars.len() {
                out.push(chars[i]);
                i += 1;
                continue;
            }

            let inner: String = chars[i + 2..j].iter().collect();
            let placeholder = format!("${{{}}}", inner);
            if let Some((var, _default_ignored)) = inner.split_once(":-") {
                match std::env::var(var) {
                    Ok(value) => out.push_str(&value),
                    Err(std::env::VarError::NotPresent)
                    | Err(std::env::VarError::NotUnicode(_)) => out.push_str(&placeholder),
                }
            } else {
                match std::env::var(&inner) {
                    Ok(value) => out.push_str(&value),
                    Err(std::env::VarError::NotPresent)
                    | Err(std::env::VarError::NotUnicode(_)) => out.push_str(&placeholder),
                }
            }
            i = j + 1;
            continue;
        }

        let mut j = i + 1;
        if j < chars.len() && (chars[j].is_ascii_alphabetic() || chars[j] == '_') {
            while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                j += 1;
            }
            let var: String = chars[i + 1..j].iter().collect();
            let placeholder = format!("${}", var);
            match std::env::var(&var) {
                Ok(value) => out.push_str(&value),
                Err(std::env::VarError::NotPresent) | Err(std::env::VarError::NotUnicode(_)) => {
                    out.push_str(&placeholder)
                }
            }
            i = j;
            continue;
        }

        out.push(chars[i]);
        i += 1;
    }

    out
}

fn normalize_match_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn paths_match(lhs: &Path, rhs: &Path) -> bool {
    let lhs_norm = normalize_match_path(lhs);
    let rhs_norm = normalize_match_path(rhs);
    if lhs_norm == rhs_norm {
        return true;
    }

    let lhs_abs = if lhs.is_absolute() {
        lhs.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(lhs)
    };
    let rhs_abs = if rhs.is_absolute() {
        rhs.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(rhs)
    };
    if lhs_abs == rhs_abs {
        return true;
    }

    lhs_norm.ends_with(rhs) || rhs_norm.ends_with(lhs)
}

pub fn load_target_run_overrides(path: &Path) -> anyhow::Result<TargetRunOverrides> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed reading target run overrides '{}'", path.display()))?;
    let mut parsed: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed parsing target run overrides '{}'", path.display()))?;

    if let Some(map) = parsed.as_mapping_mut() {
        if let Some(inner) = map.get(yaml_key("run_overrides")) {
            parsed = inner.clone();
        } else if let Some(inner) = map.get(yaml_key("run")) {
            parsed = inner.clone();
        } else if let Some(inner) = map.get(yaml_key("config")) {
            parsed = inner.clone();
        }
    }

    serde_yaml::from_value(parsed).with_context(|| {
        format!(
            "Failed decoding run overrides from '{}'; expected keys like batch_jobs/workers/iterations/timeout/env",
            path.display()
        )
    })
}

pub fn resolve_target_run_overrides(
    index_path: &Path,
    target_circuit: &Path,
    framework: &str,
) -> anyhow::Result<Option<ResolvedTargetRunOverrides>> {
    let raw = fs::read_to_string(index_path).with_context(|| {
        format!(
            "Failed reading target overrides index '{}'",
            index_path.display()
        )
    })?;
    let parsed: serde_yaml::Value = serde_yaml::from_str(&raw).with_context(|| {
        format!(
            "Failed parsing target overrides index '{}'",
            index_path.display()
        )
    })?;
    let targets = parsed
        .as_mapping()
        .and_then(|map| map.get(yaml_key("targets")))
        .and_then(|value| value.as_sequence())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Target overrides index '{}' is missing a top-level 'targets' array",
                index_path.display()
            )
        })?;

    let index_parent = index_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let mut matched: Option<ResolvedTargetRunOverrides> = None;

    for entry in targets {
        let Some(map) = entry.as_mapping() else {
            continue;
        };
        let target_name = map
            .get(yaml_key("name"))
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let target_circuit_raw = map
            .get(yaml_key("target_circuit"))
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let framework_raw = map
            .get(yaml_key("framework"))
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let run_overrides_file_raw = map
            .get(yaml_key("run_overrides_file"))
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim()
            .to_string();

        if run_overrides_file_raw.is_empty() || target_circuit_raw.is_empty() {
            continue;
        }
        if !framework_raw.is_empty() && !framework_raw.eq_ignore_ascii_case(framework) {
            continue;
        }

        let matrix_target = PathBuf::from(expand_env_placeholders(&target_circuit_raw));
        if !paths_match(&matrix_target, target_circuit) {
            continue;
        }

        let run_overrides_file = PathBuf::from(expand_env_placeholders(&run_overrides_file_raw));
        let overrides_path = if run_overrides_file.is_absolute() {
            run_overrides_file
        } else {
            index_parent.join(run_overrides_file)
        };
        let overrides = load_target_run_overrides(&overrides_path)?;
        let target_name = if target_name.is_empty() {
            matrix_target.display().to_string()
        } else {
            target_name
        };
        let resolved = ResolvedTargetRunOverrides {
            target_name,
            target_circuit: matrix_target,
            overrides_path,
            overrides,
        };

        if let Some(existing) = &matched {
            anyhow::bail!(
                "Multiple target overrides matched '{}': '{}' and '{}'. Narrow your matrix entries.",
                target_circuit.display(),
                existing.target_name,
                resolved.target_name
            );
        }
        matched = Some(resolved);
    }

    Ok(matched)
}

fn env_override_value_to_string(value: &serde_yaml::Value) -> anyhow::Result<Option<String>> {
    let rendered = match value {
        serde_yaml::Value::Null => return Ok(None),
        serde_yaml::Value::Bool(v) => {
            if *v {
                "1".to_string()
            } else {
                "0".to_string()
            }
        }
        serde_yaml::Value::Number(v) => v.to_string(),
        serde_yaml::Value::String(v) => v.clone(),
        other => anyhow::bail!(
            "Unsupported target override env value type: {:?}. Use scalar string/number/bool.",
            other
        ),
    };
    Ok(Some(rendered))
}

pub fn collect_target_override_env(
    overrides: &TargetRunOverrides,
) -> anyhow::Result<BTreeMap<String, String>> {
    let mut env_overrides = BTreeMap::new();
    for (key, value) in &overrides.env {
        if key.trim().is_empty() {
            anyhow::bail!("Invalid target override env key: empty string");
        }
        if let Some(rendered) = env_override_value_to_string(value)? {
            env_overrides.insert(key.clone(), rendered);
        }
    }
    Ok(env_overrides)
}
