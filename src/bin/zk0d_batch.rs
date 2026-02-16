use anyhow::Context;
use clap::Parser;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser, Debug)]
#[command(name = "zk0d_batch")]
#[command(about = "Batch runner for YAML attack-pattern catalogs")]
struct Args {
    /// Path to fuzzer registry YAML
    #[arg(long, default_value = "targets/fuzzer_registry.yaml")]
    registry: String,

    /// List available collections/aliases/templates and exit
    #[arg(long, default_value_t = false)]
    list_catalog: bool,

    /// Comma-separated collection names to run
    #[arg(long)]
    collection: Option<String>,

    /// Comma-separated alias names to run
    #[arg(long)]
    alias: Option<String>,

    /// Comma-separated template filenames to run
    #[arg(long)]
    template: Option<String>,

    /// Target circuit path used for all selected templates
    #[arg(long)]
    target_circuit: Option<String>,

    /// Main component used for all selected templates
    #[arg(long, default_value = "main")]
    main_component: String,

    /// Framework used for all selected templates
    #[arg(long, default_value = "circom")]
    framework: String,

    /// Family override passed to `zk-fuzzer scan`
    #[arg(long, default_value = "auto")]
    family: String,

    /// Target topology: mono targets reject multi templates
    #[arg(long, default_value = "mono")]
    target_topology: String,

    /// Build release binary if missing
    #[arg(long, default_value_t = true)]
    build: bool,

    /// Skip YAML validation pass
    #[arg(long, default_value_t = false)]
    skip_validate: bool,

    /// Dry run (print commands only)
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Worker count per run
    #[arg(long, default_value_t = 8)]
    workers: usize,

    /// RNG seed per run
    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Iterations per run
    #[arg(long, default_value_t = 50_000)]
    iterations: u64,

    /// Timeout per run (seconds)
    #[arg(long, default_value_t = 1_800)]
    timeout: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Auto,
    Mono,
    Multi,
}

impl Family {
    fn as_str(self) -> &'static str {
        match self {
            Family::Auto => "auto",
            Family::Mono => "mono",
            Family::Multi => "multi",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Topology {
    Mono,
    Multi,
}

#[derive(Debug, Deserialize, Default)]
struct RegistryFile {
    version: serde_yaml::Value,
    #[serde(default)]
    registries: BTreeMap<String, RegistryEntry>,
    #[serde(default)]
    collections: BTreeMap<String, CollectionEntry>,
    #[serde(default)]
    aliases: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
struct RegistryEntry {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    maintainer: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct CollectionEntry {
    registry: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    templates: Vec<String>,
}

#[derive(Debug, Clone)]
struct TemplateInfo {
    file_name: String,
    path: PathBuf,
    family: Family,
}

type TemplateIndex = BTreeMap<String, TemplateInfo>;
type CollectionIndex = BTreeMap<String, Vec<String>>;

#[derive(Clone, Copy)]
struct ScanRunConfig<'a> {
    bin_path: &'a Path,
    target_circuit: &'a str,
    framework: &'a str,
    main_component: &'a str,
    workers: usize,
    seed: u64,
    iterations: u64,
    timeout: u64,
    dry_run: bool,
}

fn parse_family(value: &str) -> anyhow::Result<Family> {
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

fn parse_topology(value: &str) -> anyhow::Result<Topology> {
    match value {
        "mono" => Ok(Topology::Mono),
        "multi" => Ok(Topology::Multi),
        other => anyhow::bail!(
            "Unsupported target_topology '{}'. Expected one of: mono, multi",
            other
        ),
    }
}

fn template_family_from_name(name: &str) -> anyhow::Result<Family> {
    if name.ends_with("_mono.yaml") {
        return Ok(Family::Mono);
    }
    if name.ends_with("_multi.yaml") {
        return Ok(Family::Multi);
    }

    anyhow::bail!(
        "Invalid template filename '{}': expected suffix '_mono.yaml' or '_multi.yaml'",
        name
    )
}

fn validate_template_name(name: &str) -> anyhow::Result<()> {
    let family = template_family_from_name(name)?;
    let prefix = match family {
        Family::Mono => name.trim_end_matches("_mono.yaml"),
        Family::Multi => name.trim_end_matches("_multi.yaml"),
        Family::Auto => unreachable!("template family comes from filename suffix"),
    };

    if prefix.is_empty() {
        anyhow::bail!(
            "Invalid template filename '{}': missing attack identifier before family suffix",
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
            "Invalid template filename '{}': expected pattern '<attacktype>_<attack>_mono|multi.yaml'",
            name
        );
    }

    Ok(())
}

fn split_csv(input: Option<&str>) -> Vec<String> {
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
                    Err(std::env::VarError::NotPresent) => out.push_str(&placeholder),
                    Err(e) => panic!("Invalid environment variable {}: {}", var, e),
                }
            } else {
                match std::env::var(&inner) {
                    Ok(value) => out.push_str(&value),
                    Err(std::env::VarError::NotPresent) => out.push_str(&placeholder),
                    Err(e) => panic!("Invalid environment variable {}: {}", inner, e),
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
                Err(std::env::VarError::NotPresent) => out.push_str(&placeholder),
                Err(e) => panic!("Invalid environment variable {}: {}", var, e),
            }
            i = j;
            continue;
        }

        out.push(chars[i]);
        i += 1;
    }

    out
}

fn has_unresolved_env_placeholder(input: &str) -> bool {
    input.contains("${") || input.contains('$')
}

fn validate_pattern_only_yaml(path: &Path) -> anyhow::Result<()> {
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
                // Fallback for catalogs that keep paths relative to the catalog file.
                registry_path.join(from_cwd)
            }
        }
        None => {
            let source = registry.url.as_deref().unwrap_or("<no-path-no-url>");
            anyhow::bail!(
                "Registry '{}' has no local `path` (source: '{}'). Remote registries are not executable by zk0d_batch.",
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

fn build_template_index(
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

fn print_catalog(
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

fn resolve_selection(
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
        if registry_file.aliases.contains_key("always") {
            let values = registry_file
                .aliases
                .get("always")
                .expect("checked contains_key");
            for value in values {
                append_selector_value(
                    &mut requested_templates,
                    by_collection,
                    template_index,
                    value,
                    "Default alias 'always'",
                )?;
            }
        } else {
            for name in registry_file.collections.keys() {
                append_selector_value(
                    &mut requested_templates,
                    by_collection,
                    template_index,
                    name,
                    "Collection selection",
                )?;
            }
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

fn run_scan(
    run_cfg: ScanRunConfig<'_>,
    template: &TemplateInfo,
    family: Family,
    validate_only: bool,
) -> anyhow::Result<bool> {
    let family_str = family.as_str();
    let mut cmd = Command::new(run_cfg.bin_path);
    cmd.arg("scan")
        .arg(&template.path)
        .arg("--family")
        .arg(family_str)
        .arg("--target-circuit")
        .arg(run_cfg.target_circuit)
        .arg("--main-component")
        .arg(run_cfg.main_component)
        .arg("--framework")
        .arg(run_cfg.framework)
        .arg("--workers")
        .arg(run_cfg.workers.to_string())
        .arg("--seed")
        .arg(run_cfg.seed.to_string())
        .arg("--iterations")
        .arg(run_cfg.iterations.to_string())
        .arg("--timeout")
        .arg(run_cfg.timeout.to_string())
        .arg("--simple-progress");

    if validate_only {
        cmd.arg("--dry-run");
    }

    if run_cfg.dry_run {
        println!(
            "[DRY RUN] {} scan {} --family {} --target-circuit {} --main-component {} --framework {} --workers {} --seed {} --iterations {} --timeout {} --simple-progress{}",
            run_cfg.bin_path.display(),
            template.path.display(),
            family_str,
            run_cfg.target_circuit,
            run_cfg.main_component,
            run_cfg.framework,
            run_cfg.workers,
            run_cfg.seed,
            run_cfg.iterations,
            run_cfg.timeout,
            if validate_only { " --dry-run" } else { "" }
        );
        return Ok(true);
    }

    let status = cmd.status()?;
    Ok(status.success())
}

fn effective_family(template_family: Family, family_override: Family) -> Family {
    match family_override {
        Family::Auto => template_family,
        Family::Mono => Family::Mono,
        Family::Multi => Family::Multi,
    }
}

fn validate_template_compatibility(
    template: &TemplateInfo,
    family_override: Family,
    target_topology: Topology,
) -> anyhow::Result<Family> {
    let effective = effective_family(template.family, family_override);

    if target_topology == Topology::Mono && effective == Family::Multi {
        anyhow::bail!(
            "Template '{}' resolved to multi but target_topology is mono. Multi templates require multi-circuit targets.",
            template.file_name
        );
    }

    Ok(effective)
}

fn run_template(
    run_cfg: ScanRunConfig<'_>,
    template: &TemplateInfo,
    family: Family,
    skip_validate: bool,
) -> anyhow::Result<bool> {
    if !template.path.exists() {
        eprintln!(
            "Template '{}' failed: file not found '{}'",
            template.file_name,
            template.path.display()
        );
        return Ok(false);
    }

    if let Err(err) = validate_pattern_only_yaml(&template.path) {
        eprintln!(
            "Template '{}' failed: invalid pattern YAML '{}': {}",
            template.file_name,
            template.path.display(),
            err
        );
        return Ok(false);
    }

    if !skip_validate && !run_scan(run_cfg, template, family, true)? {
        eprintln!("Template '{}' failed validation", template.file_name);
        return Ok(false);
    }

    if !run_scan(run_cfg, template, family, false)? {
        eprintln!("Template '{}' failed", template.file_name);
        return Ok(false);
    }

    Ok(true)
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let family_override = parse_family(&args.family)?;
    let target_topology = parse_topology(&args.target_topology)?;

    let registry_path = PathBuf::from(&args.registry);
    let registry_dir = registry_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    let raw = std::fs::read_to_string(&registry_path)
        .with_context(|| format!("Failed to read registry YAML '{}'", registry_path.display()))?;
    let registry_file: RegistryFile = serde_yaml::from_str(&raw).with_context(|| {
        format!(
            "Failed to parse registry YAML '{}'",
            registry_path.display()
        )
    })?;

    let (template_index, by_collection) = build_template_index(&registry_file, &registry_dir)?;

    if args.list_catalog {
        print_catalog(&registry_file, &template_index, &by_collection);
        return Ok(());
    }

    let target_circuit_raw = args.target_circuit.as_deref().ok_or_else(|| {
        anyhow::anyhow!("Missing required --target-circuit (unless --list-catalog is used)")
    })?;
    let target_circuit = expand_env_placeholders(target_circuit_raw);
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

    let selected = resolve_selection(&args, &registry_file, &template_index, &by_collection)?;

    let mut selected_with_family: Vec<(TemplateInfo, Family)> = Vec::with_capacity(selected.len());
    for template in selected {
        let chosen_family =
            validate_template_compatibility(&template, family_override, target_topology)?;
        selected_with_family.push((template, chosen_family));
    }

    let bin_path = PathBuf::from("target/release/zk-fuzzer");
    if args.build && !bin_path.exists() {
        let status = Command::new("cargo")
            .args(["build", "--release", "--bin", "zk-fuzzer"])
            .status()?;
        if !status.success() {
            anyhow::bail!("cargo build --release --bin zk-fuzzer failed");
        }
    }

    let mut failures = 0usize;
    let mut executed = 0usize;
    let run_cfg = ScanRunConfig {
        bin_path: &bin_path,
        target_circuit: &target_circuit,
        framework: &args.framework,
        main_component: &args.main_component,
        workers: args.workers,
        seed: args.seed,
        iterations: args.iterations,
        timeout: args.timeout,
        dry_run: args.dry_run,
    };

    for (template, family) in selected_with_family {
        executed += 1;
        let ok = run_template(run_cfg, &template, family, args.skip_validate)?;
        if !ok {
            failures += 1;
        }
    }

    println!(
        "Batch complete. Templates executed: {}, failures: {}",
        executed, failures
    );

    if failures > 0 {
        std::process::exit(1);
    }

    Ok(())
}
