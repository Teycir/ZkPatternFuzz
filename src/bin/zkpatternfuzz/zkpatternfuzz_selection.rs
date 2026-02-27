use anyhow::Context;
use std::collections::BTreeSet;
use std::path::PathBuf;

use super::{
    build_template_index, dedupe_patterns_by_signature, default_registry_for_profile,
    discover_all_pattern_templates, expand_env_placeholders, has_unresolved_env_placeholder,
    print_catalog, resolve_explicit_pattern_selection, resolve_selection, scan_output_suffix,
    split_csv, validate_template_compatibility, Args, Family, RegistryFile, TemplateInfo,
};

pub(super) enum SelectionResolution {
    ListedCatalog,
    Selected(ResolvedBatchSelection),
}

pub(super) struct ResolvedBatchSelection {
    pub(super) target_circuit: String,
    pub(super) target_circuit_path: PathBuf,
    pub(super) selected_with_family: Vec<(TemplateInfo, Family)>,
    pub(super) expected_suffixes: BTreeSet<String>,
}

pub(super) fn parse_family(value: &str) -> anyhow::Result<Family> {
    match value {
        "auto" => Ok(Family::Auto),
        "mono" => Ok(Family::Mono),
        "multi" => Ok(Family::Multi),
        other => anyhow::bail!(
            "Unsupported family '{}'. Expected one of: auto, mono, multi",
            other
        ),
    }
}

pub(super) fn ensure_positive_cli_values(args: &Args) -> anyhow::Result<()> {
    if args.jobs == 0 {
        anyhow::bail!("--jobs must be >= 1");
    }
    if args.workers == 0 {
        anyhow::bail!("--workers must be >= 1");
    }
    if args.iterations == 0 {
        anyhow::bail!("--iterations must be >= 1");
    }
    if args.timeout == 0 {
        anyhow::bail!("--timeout must be >= 1");
    }
    Ok(())
}

pub(super) fn resolve_batch_selection(
    args: &mut Args,
    family_override: Family,
) -> anyhow::Result<SelectionResolution> {
    let explicit_patterns = split_csv(args.pattern_yaml.as_deref());
    let using_explicit_patterns = !explicit_patterns.is_empty();
    let has_registry_selectors =
        args.collection.is_some() || args.alias.is_some() || args.template.is_some();

    let selected = if using_explicit_patterns {
        if args.list_catalog {
            anyhow::bail!("--list-catalog cannot be combined with --pattern-yaml");
        }
        resolve_explicit_pattern_selection(&explicit_patterns, family_override)?
    } else if !has_registry_selectors {
        if args.list_catalog {
            anyhow::bail!(
                "--list-catalog requires registry mode; omit --list-catalog for auto-discovery mode"
            );
        }
        let repo_root = std::env::current_dir().context("Failed to resolve current directory")?;
        let discovered = discover_all_pattern_templates(&repo_root)?;
        if discovered.is_empty() {
            anyhow::bail!(
                "Auto-discovery found zero pattern-compatible YAML files under '{}'. Use --pattern-yaml or registry selectors.",
                repo_root.display()
            );
        }
        discovered
    } else {
        let registry_path_raw = args
            .registry
            .clone()
            .unwrap_or_else(|| default_registry_for_profile(args.config_profile).to_string());
        let registry_path = PathBuf::from(&registry_path_raw);
        let registry_dir = registry_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        let raw = std::fs::read_to_string(&registry_path).with_context(|| {
            format!("Failed to read registry YAML '{}'", registry_path.display())
        })?;
        let registry_file: RegistryFile = serde_yaml::from_str(&raw).with_context(|| {
            format!(
                "Failed to parse registry YAML '{}'",
                registry_path.display()
            )
        })?;
        let (template_index, by_collection) = build_template_index(&registry_file, &registry_dir)?;

        if args.list_catalog {
            print_catalog(&registry_file, &template_index, &by_collection);
            return Ok(SelectionResolution::ListedCatalog);
        }

        args.registry = Some(registry_path_raw);
        resolve_selection(args, &registry_file, &template_index, &by_collection)?
    };

    let target_circuit_raw = args.target_circuit.as_deref().ok_or_else(|| {
        anyhow::anyhow!("Missing required --target-circuit (unless --list-catalog is used)")
    })?;
    let target_circuit = expand_env_placeholders(target_circuit_raw).with_context(|| {
        format!(
            "Failed to resolve environment placeholders in target_circuit '{}'",
            target_circuit_raw
        )
    })?;
    if has_unresolved_env_placeholder(&target_circuit) {
        anyhow::bail!(
            "Unresolved env placeholder in target_circuit '{}'. Set required environment variables.",
            target_circuit_raw
        );
    }

    let target_circuit_path = PathBuf::from(&target_circuit);
    if !target_circuit_path.exists() {
        anyhow::bail!(
            "target_circuit not found '{}' (resolved from '{}')",
            target_circuit,
            target_circuit_raw
        );
    }

    let (selected, signature_dupes) = dedupe_patterns_by_signature(selected)?;
    if !signature_dupes.is_empty() {
        eprintln!(
            "Skipped {} full-overlap duplicate patterns (same normalized selector set):",
            signature_dupes.len()
        );
        for (dup, kept) in signature_dupes.iter().take(20) {
            eprintln!("  - {} -> kept {}", dup.path.display(), kept.path.display());
        }
    }

    let mut selected_with_family: Vec<(TemplateInfo, Family)> = Vec::with_capacity(selected.len());
    for template in selected {
        let chosen_family = validate_template_compatibility(&template, family_override)?;
        selected_with_family.push((template, chosen_family));
    }
    let expected_suffixes: BTreeSet<String> = selected_with_family
        .iter()
        .map(|(template, family)| scan_output_suffix(template, *family))
        .collect();

    Ok(SelectionResolution::Selected(ResolvedBatchSelection {
        target_circuit,
        target_circuit_path,
        selected_with_family,
        expected_suffixes,
    }))
}
