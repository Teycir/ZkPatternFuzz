use anyhow::Context;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use super::{
    validate_template_compatibility, Args, CollectionEntry, CollectionIndex, DedupeResult, Family,
    RegistryEntry, RegistryFile, TemplateIndex, TemplateInfo,
};

pub(super) fn template_family_from_name(name: &str) -> anyhow::Result<Family> {
    if name.ends_with(".yaml") || name.ends_with(".yml") {
        return Ok(Family::Auto);
    }
    anyhow::bail!(
        "Invalid template filename '{}': expected .yaml or .yml extension",
        name
    )
}

pub(super) fn validate_template_name(name: &str) -> anyhow::Result<()> {
    let _family = template_family_from_name(name)?;
    let prefix = name.trim_end_matches(".yaml").trim_end_matches(".yml");

    if prefix.is_empty() {
        anyhow::bail!(
            "Invalid template filename '{}': missing attack identifier before extension",
            name
        );
    }

    if !prefix
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        anyhow::bail!(
            "Invalid template filename '{}': use only letters, digits, and underscores before suffix",
            name
        );
    }

    if !prefix.contains('_') {
        anyhow::bail!(
            "Invalid template filename '{}': expected pattern '<attacktype>_<attack>.yaml'",
            name
        );
    }

    Ok(())
}

pub(super) fn split_csv(input: Option<&str>) -> Vec<String> {
    let Some(input) = input else {
        return Vec::new();
    };

    input
        .split(',')
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .map(|part| part.to_string())
        .collect()
}

fn yaml_key(name: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(name.to_string())
}

pub(super) fn validate_pattern_only_yaml(path: &Path) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read pattern YAML '{}': {}", path.display(), e))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("Failed to parse pattern YAML '{}': {}", path.display(), e))?;
    let root = doc.as_mapping().ok_or_else(|| {
        anyhow::anyhow!("Pattern YAML '{}' root must be a mapping", path.display())
    })?;

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
        let Some(key) = key.as_str() else {
            anyhow::bail!(
                "Pattern YAML '{}' contains a non-string top-level key",
                path.display()
            );
        };
        if !allowed.contains(key) {
            unexpected.push(key.to_string());
        }
    }

    if !unexpected.is_empty() {
        unexpected.sort();
        anyhow::bail!(
            "Pattern YAML '{}' must be pattern-only. Unsupported top-level keys: [{}]",
            path.display(),
            unexpected.join(", ")
        );
    }

    Ok(())
}

fn collection_base_path(
    registry_path: &Path,
    collection: &CollectionEntry,
    registries: &BTreeMap<String, RegistryEntry>,
) -> anyhow::Result<PathBuf> {
    let registry = registries
        .get(&collection.registry)
        .ok_or_else(|| anyhow::anyhow!("Unknown registry '{}'", collection.registry))?;

    let base = match &registry.path {
        Some(path) => {
            let from_cwd = PathBuf::from(path);
            if from_cwd.is_absolute() || from_cwd.exists() {
                from_cwd
            } else {
                // Recovery for catalogs that keep paths relative to the catalog file.
                registry_path.join(from_cwd)
            }
        }
        None => {
            let source = registry.url.as_deref().unwrap_or("<no-path-no-url>");
            anyhow::bail!(
                "Registry '{}' has no local `path` (source: '{}'). Remote registries are not executable by zkpatternfuzz.",
                collection.registry,
                source
            );
        }
    };

    let base = match &collection.path {
        Some(path) => base.join(path),
        None => base,
    };

    Ok(base)
}

pub(super) fn build_template_index(
    registry_file: &RegistryFile,
    registry_path: &Path,
) -> anyhow::Result<(TemplateIndex, CollectionIndex)> {
    let mut templates: TemplateIndex = BTreeMap::new();
    let mut by_collection: CollectionIndex = BTreeMap::new();

    for (collection_name, collection) in &registry_file.collections {
        if collection.templates.is_empty() {
            continue;
        }

        let base = collection_base_path(registry_path, collection, &registry_file.registries)
            .with_context(|| {
                format!(
                    "Invalid collection '{}' (registry='{}')",
                    collection_name, collection.registry
                )
            })?;

        let mut names = Vec::with_capacity(collection.templates.len());
        for template in &collection.templates {
            validate_template_name(template)?;
            let family = template_family_from_name(template)?;
            let path = base.join(template);

            if let Some(prev) = templates.get(template) {
                if prev.path != path {
                    anyhow::bail!(
                        "Template '{}' resolves to multiple paths: '{}' and '{}'",
                        template,
                        prev.path.display(),
                        path.display()
                    );
                }
            } else {
                templates.insert(
                    template.clone(),
                    TemplateInfo {
                        file_name: template.clone(),
                        path,
                        family,
                    },
                );
            }

            names.push(template.clone());
        }
        by_collection.insert(collection_name.clone(), names);
    }

    Ok((templates, by_collection))
}

pub(super) fn print_catalog(
    registry_file: &RegistryFile,
    template_index: &TemplateIndex,
    by_collection: &CollectionIndex,
) {
    let version = match &registry_file.version {
        serde_yaml::Value::Null => "unknown".to_string(),
        serde_yaml::Value::Bool(v) => v.to_string(),
        serde_yaml::Value::Number(v) => v.to_string(),
        serde_yaml::Value::String(v) => v.clone(),
        _ => "<non-scalar>".to_string(),
    };
    println!("Catalog version: {}", version);
    println!("Registries ({}):", registry_file.registries.len());
    for (name, registry) in &registry_file.registries {
        let location = registry
            .path
            .as_deref()
            .or(registry.url.as_deref())
            .unwrap_or("<unconfigured>");
        println!("  - {} -> {}", name, location);
        if let Some(desc) = &registry.description {
            println!("      {}", desc);
        }
        if let Some(maintainer) = &registry.maintainer {
            println!("      maintainer: {}", maintainer);
        }
    }

    println!("\nCollections ({}):", registry_file.collections.len());
    for (name, collection) in &registry_file.collections {
        let count = by_collection.get(name).map(|v| v.len()).unwrap_or(0);
        println!("  - {} ({} templates)", name, count);
        if let Some(desc) = &collection.description {
            println!("      {}", desc);
        }
    }

    println!("\nAliases ({}):", registry_file.aliases.len());
    for (name, values) in &registry_file.aliases {
        println!("  - {} -> {}", name, values.join(", "));
    }

    println!("\nTemplates ({}):", template_index.len());
    for (name, info) in template_index {
        println!(
            "  - {} [{}] {}",
            name,
            info.family.as_str(),
            info.path.display()
        );
    }
}

fn append_selector_value(
    requested_templates: &mut Vec<String>,
    by_collection: &CollectionIndex,
    template_index: &TemplateIndex,
    value: &str,
    source_label: &str,
) -> anyhow::Result<()> {
    if let Some(collection_templates) = by_collection.get(value) {
        requested_templates.extend(collection_templates.iter().cloned());
        return Ok(());
    }
    if template_index.contains_key(value) {
        requested_templates.push(value.to_string());
        return Ok(());
    }
    anyhow::bail!(
        "{} contains unknown item '{}'. It must reference a collection or template filename.",
        source_label,
        value
    );
}

pub(super) fn resolve_selection(
    args: &Args,
    registry_file: &RegistryFile,
    template_index: &TemplateIndex,
    by_collection: &CollectionIndex,
) -> anyhow::Result<Vec<TemplateInfo>> {
    let selected_collections = split_csv(args.collection.as_deref());
    let selected_aliases = split_csv(args.alias.as_deref());
    let selected_templates = split_csv(args.template.as_deref());

    let mut requested_templates: Vec<String> = Vec::new();

    if selected_collections.is_empty()
        && selected_aliases.is_empty()
        && selected_templates.is_empty()
    {
        for template_name in template_index.keys() {
            requested_templates.push(template_name.clone());
        }
    }

    for collection in &selected_collections {
        append_selector_value(
            &mut requested_templates,
            by_collection,
            template_index,
            collection,
            "Collection selection",
        )?;
    }

    for alias in &selected_aliases {
        let Some(values) = registry_file.aliases.get(alias) else {
            anyhow::bail!("Unknown alias '{}'", alias);
        };
        for value in values {
            let source = format!("Alias '{}'", alias);
            append_selector_value(
                &mut requested_templates,
                by_collection,
                template_index,
                value,
                &source,
            )?;
        }
    }

    for template in &selected_templates {
        if !template_index.contains_key(template) {
            anyhow::bail!(
                "Unknown template '{}'. Use --list-catalog to inspect available template filenames.",
                template
            );
        }
        requested_templates.push(template.clone());
    }

    let mut dedup = BTreeSet::new();
    let mut ordered = Vec::new();
    for template in requested_templates {
        if dedup.insert(template.clone()) {
            let info = template_index.get(&template).ok_or_else(|| {
                anyhow::anyhow!("Template '{}' vanished during selection", template)
            })?;
            ordered.push(info.clone());
        }
    }

    if ordered.is_empty() {
        anyhow::bail!(
            "Selection resolved to zero templates. Use --list-catalog to inspect available entries."
        );
    }

    Ok(ordered)
}

pub(super) fn resolve_explicit_pattern_selection(
    raw_paths: &[String],
    family_override: Family,
) -> anyhow::Result<Vec<TemplateInfo>> {
    let mut dedup = BTreeSet::new();
    let mut selected = Vec::new();
    for raw in raw_paths {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let path = PathBuf::from(trimmed);
        let canonical = path.to_string_lossy().to_string();
        if !dedup.insert(canonical.clone()) {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or(trimmed)
            .to_string();
        validate_template_name(&file_name)?;
        let family = validate_template_compatibility(
            &TemplateInfo {
                file_name: file_name.clone(),
                path: path.clone(),
                family: template_family_from_name(&file_name)?,
            },
            family_override,
        )?;
        selected.push(TemplateInfo {
            file_name,
            path,
            family,
        });
    }

    if selected.is_empty() {
        anyhow::bail!("pattern_yaml resolved to zero usable pattern paths");
    }

    Ok(selected)
}

fn should_skip_pattern_discovery_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "target"
            | "artifacts"
            | "node_modules"
            | "vendor"
            | "ZkFuzz"
            | "reports"
            | "build"
    )
}

pub(super) fn discover_all_pattern_templates(
    repo_root: &Path,
) -> anyhow::Result<Vec<TemplateInfo>> {
    let mut stack = vec![repo_root.to_path_buf()];
    let mut discovered = Vec::<TemplateInfo>::new();
    let mut dedup = BTreeSet::<String>::new();

    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries {
            let Ok(entry) = entry else {
                continue;
            };
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if should_skip_pattern_discovery_dir(name) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let Some(ext) = path.extension().and_then(|v| v.to_str()) else {
                continue;
            };
            if ext != "yaml" && ext != "yml" {
                continue;
            }

            let canonical = path.display().to_string();
            if !dedup.insert(canonical) {
                continue;
            }

            let Some(file_name) = path.file_name().and_then(|v| v.to_str()) else {
                continue;
            };
            if validate_template_name(file_name).is_err() {
                continue;
            }
            if validate_pattern_only_yaml(&path).is_err() {
                continue;
            }

            let family = template_family_from_name(file_name)?;
            discovered.push(TemplateInfo {
                file_name: file_name.to_string(),
                path,
                family,
            });
        }
    }

    discovered.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(discovered)
}

fn pattern_regex_signature(path: &Path) -> anyhow::Result<Option<Vec<String>>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read pattern YAML '{}'", path.display()))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed to parse pattern YAML '{}'", path.display()))?;
    let Some(root) = doc.as_mapping() else {
        return Ok(None);
    };
    let patterns_key = yaml_key("patterns");
    let Some(patterns) = root.get(&patterns_key) else {
        return Ok(None);
    };
    let Some(items) = patterns.as_sequence() else {
        return Ok(None);
    };
    let mut selectors = Vec::<String>::new();
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        let pattern_key = yaml_key("pattern");
        let kind_key = yaml_key("kind");
        let Some(pattern) = map.get(&pattern_key).and_then(|v| v.as_str()) else {
            continue;
        };
        let kind = map
            .get(&kind_key)
            .and_then(|v| v.as_str())
            .unwrap_or("regex")
            .trim()
            .to_ascii_lowercase();
        selectors.push(format!("{}::{}", kind, pattern.trim()));
    }
    if selectors.is_empty() {
        return Ok(None);
    }
    selectors.sort();
    selectors.dedup();
    Ok(Some(selectors))
}

fn pattern_specificity_score(path: &Path) -> i64 {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(_) => return 0,
    };
    let doc: serde_yaml::Value = match serde_yaml::from_str(&raw) {
        Ok(doc) => doc,
        Err(_) => return 0,
    };
    let Some(root) = doc.as_mapping() else {
        return 0;
    };
    let mut score = 0i64;
    if root.contains_key(yaml_key("profiles")) {
        score += 4;
    }
    if root.contains_key(yaml_key("active_profile")) {
        score += 4;
    }
    if root.contains_key(yaml_key("selector_policy")) {
        score += 1;
    }
    if root.contains_key(yaml_key("selector_synonyms")) {
        score += 1;
    }
    if root.contains_key(yaml_key("selector_normalization")) {
        score += 1;
    }
    score + (raw.len() as i64 / 1024)
}

pub(super) fn dedupe_patterns_by_signature(
    selected: Vec<TemplateInfo>,
) -> anyhow::Result<DedupeResult> {
    let mut kept = Vec::<TemplateInfo>::new();
    let mut dropped = Vec::<(TemplateInfo, TemplateInfo)>::new();
    let mut signature_to_index = BTreeMap::<String, usize>::new();

    for template in selected {
        let signature = pattern_regex_signature(&template.path)?;
        let Some(signature) = signature else {
            kept.push(template);
            continue;
        };
        let key = signature.join("\n");
        if let Some(existing_idx) = signature_to_index.get(&key).copied() {
            let existing = kept[existing_idx].clone();
            let existing_score = pattern_specificity_score(&existing.path);
            let incoming_score = pattern_specificity_score(&template.path);
            let incoming_better = incoming_score > existing_score
                || (incoming_score == existing_score && template.path < existing.path);
            if incoming_better {
                kept[existing_idx] = template.clone();
                dropped.push((existing, template.clone()));
            } else {
                dropped.push((template.clone(), existing));
            }
            continue;
        }
        signature_to_index.insert(key, kept.len());
        kept.push(template);
    }

    Ok((kept, dropped))
}
