use crate::cli::ScanFamily;
use anyhow::Context;
use std::fs;
use zk_fuzzer::Framework;

fn yaml_key(name: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(name.to_string())
}

pub fn parse_framework_arg(value: &str) -> anyhow::Result<Framework> {
    match value.trim().to_ascii_lowercase().as_str() {
        "circom" => Ok(Framework::Circom),
        "noir" => Ok(Framework::Noir),
        "halo2" => Ok(Framework::Halo2),
        "cairo" => Ok(Framework::Cairo),
        other => anyhow::bail!(
            "Unsupported --framework '{}'. Expected one of: circom, noir, halo2, cairo",
            other
        ),
    }
}

pub fn detect_pattern_has_chains(path: &str) -> anyhow::Result<bool> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read pattern YAML '{}'", path))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed to parse pattern YAML '{}'", path))?;
    let root = doc
        .as_mapping()
        .context("Pattern YAML root must be a mapping")?;
    let chains_key = yaml_key("chains");
    let chains = match root.get(&chains_key) {
        Some(v) => v,
        None => return Ok(false),
    };
    let seq = chains
        .as_sequence()
        .context("'chains' must be a YAML sequence when present")?;
    Ok(!seq.is_empty())
}

pub fn validate_scan_pattern_complexity(path: &str, family: ScanFamily) -> anyhow::Result<()> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read pattern YAML '{}'", path))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed to parse pattern YAML '{}'", path))?;
    let root = doc
        .as_mapping()
        .context("Pattern YAML root must be a mapping")?;

    match family {
        ScanFamily::Mono => {}
        ScanFamily::Multi => {
            let chains = root
                .get(yaml_key("chains"))
                .and_then(|v| v.as_sequence())
                .context("Mode 3 (multi deep) requires non-empty `chains` in pattern YAML")?;
            if chains.is_empty() {
                anyhow::bail!("Mode 3 (multi deep) requires non-empty `chains` in pattern YAML");
            }

            let mut has_multistage_chain = false;
            let mut has_multi_circuit_chain = false;
            for chain in chains {
                let Some(chain_map) = chain.as_mapping() else {
                    anyhow::bail!("Each `chains` entry must be a mapping");
                };
                let steps_len = chain_map
                    .get(yaml_key("steps"))
                    .and_then(|v| v.as_sequence())
                    .map(|s| s.len())
                    .unwrap_or(0);
                if steps_len >= 2 {
                    has_multistage_chain = true;
                }

                let mut distinct_refs = std::collections::BTreeSet::new();
                if let Some(steps) = chain_map
                    .get(yaml_key("steps"))
                    .and_then(|v| v.as_sequence())
                {
                    for step in steps {
                        if let Some(step_map) = step.as_mapping() {
                            if let Some(circuit_ref) = step_map
                                .get(yaml_key("circuit_ref"))
                                .and_then(|v| v.as_str())
                            {
                                distinct_refs.insert(circuit_ref.to_string());
                            }
                        }
                    }
                }
                if distinct_refs.len() >= 2 {
                    has_multi_circuit_chain = true;
                }

                if has_multistage_chain && has_multi_circuit_chain {
                    break;
                }
            }
            if !has_multistage_chain {
                anyhow::bail!(
                    "Mode 3 (multi deep) requires multi-stage chains (at least one chain with 2+ steps)"
                );
            }
            if !has_multi_circuit_chain {
                anyhow::bail!(
                    "Mode 3 (multi deep) requires at least two distinct circuit refs in a chain. Mono-circuit targets cannot run multi."
                );
            }
        }
        ScanFamily::Auto => {}
    }

    Ok(())
}
