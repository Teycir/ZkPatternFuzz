use crate::cli::ScanFamily;
use crate::scan_selector::{
    evaluate_scan_selectors_or_bail, load_scan_regex_selector_config, ScanRegexPatternSummary,
};
use anyhow::Context;
use std::collections::BTreeSet;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use zk_fuzzer::Framework;

fn yaml_key(name: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(name.to_string())
}

#[derive(Debug, Clone)]
pub struct ScanTarget {
    pub framework: Framework,
    pub circuit_path: PathBuf,
    pub main_component: String,
}

#[derive(Debug, Clone)]
pub struct PreparedScanDispatch {
    pub family: ScanFamily,
    pub materialized_campaign_path: PathBuf,
}

pub fn build_scan_target(
    framework: &str,
    target_circuit: &str,
    main_component: &str,
) -> anyhow::Result<ScanTarget> {
    Ok(ScanTarget {
        framework: parse_framework_arg(framework)?,
        circuit_path: PathBuf::from(target_circuit),
        main_component: main_component.to_string(),
    })
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

pub fn resolve_scan_family(
    pattern_path: &str,
    family_hint: ScanFamily,
    regex_mode: bool,
) -> anyhow::Result<ScanFamily> {
    let has_chains = detect_pattern_has_chains(pattern_path)?;
    let family = if regex_mode {
        if has_chains {
            tracing::info!(
                "Regex-focused scan: forcing mono execution and ignoring `chains` in '{}'",
                pattern_path
            );
        }
        ScanFamily::Mono
    } else {
        match family_hint {
            ScanFamily::Auto => {
                if has_chains {
                    ScanFamily::Multi
                } else {
                    ScanFamily::Mono
                }
            }
            ScanFamily::Mono => {
                if has_chains {
                    anyhow::bail!(
                        "Scan family set to mono but pattern '{}' contains non-empty `chains`.",
                        pattern_path
                    );
                }
                ScanFamily::Mono
            }
            ScanFamily::Multi => {
                if !has_chains {
                    anyhow::bail!(
                        "Scan family set to multi but pattern '{}' has no `chains`.",
                        pattern_path
                    );
                }
                ScanFamily::Multi
            }
        }
    };

    if !regex_mode {
        validate_scan_pattern_complexity(pattern_path, family)?;
    } else {
        tracing::info!(
            "Regex selectors active: skipping multi-chain complexity checks for '{}'",
            pattern_path
        );
    }

    Ok(family)
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

pub fn validate_pattern_only_yaml(path: &str, mode_name: &str) -> anyhow::Result<()> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read {} pattern YAML '{}'", mode_name, path))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed to parse {} pattern YAML '{}'", mode_name, path))?;
    let root = doc
        .as_mapping()
        .context("Pattern YAML root must be a mapping")?;

    let allowed: BTreeSet<&'static str> = BTreeSet::from([
        "includes",
        "profiles",
        "active_profile",
        "patterns",
        "selector_policy",
        "selector_synonyms",
        "synonym_bundles",
        "selector_normalization",
        "target_traits",
        "invariants",
        "schedule",
        "attacks",
        "inputs",
        "mutations",
        "oracles",
        "chains",
    ]);

    let mut unexpected = Vec::new();
    for key in root.keys() {
        let key = key
            .as_str()
            .context("Pattern YAML contains a non-string top-level key")?;
        if !allowed.contains(key) {
            unexpected.push(key.to_string());
        }
    }
    if !unexpected.is_empty() {
        unexpected.sort();
        anyhow::bail!(
            "{} YAML must be pattern-only. Unsupported top-level keys: [{}]. Allowed keys: [{}].",
            mode_name,
            unexpected.join(", "),
            allowed.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    Ok(())
}

pub fn materialize_scan_pattern_campaign(
    pattern_path: &str,
    family: ScanFamily,
    target: &ScanTarget,
    output_suffix: Option<&str>,
    scan_regex_summary: Option<&ScanRegexPatternSummary>,
) -> anyhow::Result<PathBuf> {
    let raw = fs::read_to_string(pattern_path)
        .with_context(|| format!("Failed to read pattern YAML '{}'", pattern_path))?;
    let mut doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed to parse pattern YAML '{}'", pattern_path))?;
    let root = doc
        .as_mapping_mut()
        .context("Pattern YAML root must be a mapping")?;

    // Regex selector metadata is scan-time only. Remove it from the materialized
    // campaign so the runtime parser only sees executable fuzzing configuration.
    root.remove(yaml_key("patterns"));
    root.remove(yaml_key("selector_policy"));
    root.remove(yaml_key("selector_synonyms"));
    root.remove(yaml_key("synonym_bundles"));
    root.remove(yaml_key("selector_normalization"));

    // Keep includes valid after writing a materialized temp campaign.
    if let Some(includes) = root.get_mut(yaml_key("includes")) {
        let seq = includes
            .as_sequence_mut()
            .context("'includes' must be a YAML sequence")?;
        let pattern_dir = Path::new(pattern_path)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        for item in seq.iter_mut() {
            let include = match item.as_str() {
                Some(v) => v,
                None => continue,
            };
            if include.starts_with("${") {
                continue;
            }
            let include_path = Path::new(include);
            if include_path.is_absolute() {
                continue;
            }
            let rewritten = pattern_dir.join(include_path);
            *item = serde_yaml::Value::String(rewritten.to_string_lossy().to_string());
        }
    }

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    pattern_path.hash(&mut hasher);
    target.framework.hash(&mut hasher);
    target.circuit_path.to_string_lossy().hash(&mut hasher);
    target.main_component.hash(&mut hasher);
    family.hash(&mut hasher);
    let digest = hasher.finish();

    let stem = Path::new(pattern_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(crate::sanitize_slug)
        .unwrap_or_else(|| "pattern".to_string());
    let mut campaign = serde_yaml::Mapping::new();
    campaign.insert(
        yaml_key("name"),
        serde_yaml::Value::String(format!("scan_{}", stem)),
    );
    campaign.insert(
        yaml_key("version"),
        serde_yaml::Value::String("2.0".to_string()),
    );

    let mut campaign_target = serde_yaml::Mapping::new();
    campaign_target.insert(
        yaml_key("framework"),
        serde_yaml::to_value(target.framework).context("Failed to serialize framework")?,
    );
    campaign_target.insert(
        yaml_key("circuit_path"),
        serde_yaml::Value::String(target.circuit_path.to_string_lossy().to_string()),
    );
    campaign_target.insert(
        yaml_key("main_component"),
        serde_yaml::Value::String(target.main_component.clone()),
    );
    campaign.insert(
        yaml_key("target"),
        serde_yaml::Value::Mapping(campaign_target),
    );

    let mut parameters = serde_yaml::Mapping::new();
    parameters.insert(
        yaml_key("field"),
        serde_yaml::Value::String("bn254".to_string()),
    );
    parameters.insert(
        yaml_key("max_constraints"),
        serde_yaml::Value::Number(serde_yaml::Number::from(120000u64)),
    );
    parameters.insert(
        yaml_key("timeout_seconds"),
        serde_yaml::Value::Number(serde_yaml::Number::from(600u64)),
    );
    if matches!(target.framework, Framework::Circom) {
        // Scan stability hardening: ensure backend preflight validates not just tool presence
        // but also proving/verification key setup readiness for Circom targets.
        parameters.insert(
            yaml_key("circom_auto_setup_keys"),
            serde_yaml::Value::Bool(true),
        );
        parameters.insert(
            yaml_key("circom_require_setup_keys"),
            serde_yaml::Value::Bool(true),
        );
    }
    if let Some(raw_suffix) = output_suffix.map(str::trim).filter(|s| !s.is_empty()) {
        parameters.insert(
            yaml_key("scan_output_suffix"),
            serde_yaml::Value::String(crate::sanitize_slug(raw_suffix)),
        );
    }
    if let Some(summary) = scan_regex_summary {
        let mut lines: Vec<String> = Vec::new();
        for hit in &summary.matches {
            if hit.lines.is_empty() {
                lines.push(format!(
                    "pattern {} found ({} matches)",
                    hit.id, hit.occurrences
                ));
            } else {
                lines.push(format!(
                    "pattern {} found ({} matches) in lines {:?}",
                    hit.id, hit.occurrences, hit.lines
                ));
            }
        }
        if !lines.is_empty() {
            parameters.insert(
                yaml_key("scan_pattern_summary_text"),
                serde_yaml::Value::String(lines.join("\n")),
            );
            // Regex selector scans intentionally preserve static findings as scan evidence.
            // Without this, strict evidence-mode filtering can hide valid selector hits.
            parameters.insert(
                yaml_key("min_evidence_confidence"),
                serde_yaml::Value::String("low".to_string()),
            );
        }
    }
    campaign.insert(
        yaml_key("parameters"),
        serde_yaml::Value::Mapping(parameters),
    );

    root.insert(yaml_key("campaign"), serde_yaml::Value::Mapping(campaign));

    let out = std::env::temp_dir()
        .join("zkfuzz_scan")
        .join(format!("{}__{:016x}.yaml", stem, digest));
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create temp scan materialization directory '{}'",
                parent.display()
            )
        })?;
    }
    let yaml = serde_yaml::to_string(&doc)?;
    fs::write(&out, yaml).with_context(|| {
        format!(
            "Failed to write materialized scan campaign '{}'",
            out.display()
        )
    })?;
    Ok(out)
}

pub fn prepare_scan_dispatch(
    pattern_path: &str,
    family_hint: ScanFamily,
    target_circuit: &str,
    main_component: &str,
    framework: &str,
    output_suffix: Option<&str>,
) -> anyhow::Result<PreparedScanDispatch> {
    validate_pattern_only_yaml(pattern_path, "Scan")?;
    let regex_selector_config = load_scan_regex_selector_config(pattern_path)?;
    let regex_mode = regex_selector_config.is_some();

    let family = resolve_scan_family(pattern_path, family_hint, regex_mode)?;
    let target = build_scan_target(framework, target_circuit, main_component)?;
    let scan_regex_summary = evaluate_scan_selectors_or_bail(
        pattern_path,
        regex_selector_config.as_ref(),
        &target.circuit_path,
    )?;

    let materialized = materialize_scan_pattern_campaign(
        pattern_path,
        family,
        &target,
        output_suffix,
        scan_regex_summary.as_ref(),
    )?;

    tracing::info!(
        "Scan dispatch: pattern='{}' family={:?} materialized='{}'",
        pattern_path,
        family,
        materialized.display()
    );

    Ok(PreparedScanDispatch {
        family,
        materialized_campaign_path: materialized,
    })
}
