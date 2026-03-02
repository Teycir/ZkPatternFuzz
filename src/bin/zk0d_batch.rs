use anyhow::Context;
use chrono::Utc;
use clap::{Parser, ValueEnum};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

const SCAN_RUN_ROOT_ENV: &str = "ZKF_SCAN_RUN_ROOT";
const SCAN_OUTPUT_ROOT_ENV: &str = "ZKF_SCAN_OUTPUT_ROOT";
const RUN_SIGNAL_DIR_ENV: &str = "ZKF_RUN_SIGNAL_DIR";
const BUILD_CACHE_DIR_ENV: &str = "ZKF_BUILD_CACHE_DIR";
const SHARED_BUILD_CACHE_DIR_ENV: &str = "ZKF_SHARED_BUILD_CACHE_DIR";
const HALO2_EXTERNAL_TIMEOUT_ENV: &str = "ZK_FUZZER_HALO2_EXTERNAL_TIMEOUT_SECS";
const HALO2_MIN_EXTERNAL_TIMEOUT_ENV: &str = "ZK_FUZZER_HALO2_MIN_EXTERNAL_TIMEOUT_SECS";
const HALO2_USE_HOST_CARGO_HOME_ENV: &str = "ZK_FUZZER_HALO2_USE_HOST_CARGO_HOME";
const HALO2_CARGO_TOOLCHAIN_CANDIDATES_ENV: &str = "ZK_FUZZER_HALO2_CARGO_TOOLCHAIN_CANDIDATES";
const HALO2_TOOLCHAIN_CASCADE_LIMIT_ENV: &str = "ZK_FUZZER_HALO2_TOOLCHAIN_CASCADE_LIMIT";
const CAIRO_EXTERNAL_TIMEOUT_ENV: &str = "ZK_FUZZER_CAIRO_EXTERNAL_TIMEOUT_SECS";
const SCARB_DOWNLOAD_TIMEOUT_ENV: &str = "ZK_FUZZER_SCARB_DOWNLOAD_TIMEOUT_SECS";
const HIGH_CONFIDENCE_MIN_ORACLES_ENV: &str = "ZKF_HIGH_CONFIDENCE_MIN_ORACLES";
const DEFAULT_HIGH_CONFIDENCE_MIN_ORACLES: usize = 2;
const DEFAULT_REGISTRY_PATH: &str = "targets/fuzzer_registry.yaml";
const DEV_REGISTRY_PATH: &str = "targets/fuzzer_registry.dev.yaml";
const PROD_REGISTRY_PATH: &str = "targets/fuzzer_registry.prod.yaml";

#[derive(Parser, Debug)]
#[command(name = "zk0d_batch")]
#[command(about = "Batch runner for YAML attack-pattern catalogs")]
struct Args {
    /// Path to fuzzer registry YAML
    #[arg(long)]
    registry: Option<String>,

    /// Config profile for default registry path selection
    #[arg(long, value_enum)]
    config_profile: Option<ConfigProfile>,

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

    /// Build release binary if missing
    #[arg(long, default_value_t = true)]
    build: bool,

    /// Skip YAML validation pass
    #[arg(long, default_value_t = false)]
    skip_validate: bool,

    /// Dry run (print commands only)
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Maximum number of templates to execute in parallel
    #[arg(long, default_value_t = num_cpus::get())]
    jobs: usize,

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

    /// Root directory for scan output artifacts (overrides ZKF_SCAN_OUTPUT_ROOT)
    #[arg(long)]
    output_root: Option<String>,

    /// Emit per-template reason codes as TSV to stdout (for external harness ingestion)
    #[arg(long, default_value_t = false)]
    emit_reason_tsv: bool,

    /// Disable batch-level progress lines (enabled by default)
    #[arg(long, default_value_t = false)]
    no_batch_progress: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ConfigProfile {
    Dev,
    Prod,
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

fn default_registry_for_profile(profile: Option<ConfigProfile>) -> &'static str {
    match profile {
        Some(ConfigProfile::Dev) => DEV_REGISTRY_PATH,
        Some(ConfigProfile::Prod) => PROD_REGISTRY_PATH,
        None => DEFAULT_REGISTRY_PATH,
    }
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
    scan_run_root: Option<&'a str>,
    scan_output_root: &'a Path,
    dry_run: bool,
    artifacts_root: &'a Path,
}

#[derive(Debug, Clone)]
struct TemplateOutcomeReason {
    template_file: String,
    suffix: String,
    status: Option<String>,
    stage: Option<String>,
    reason_code: String,
    high_confidence_detected: bool,
}

struct ScanRunResult {
    success: bool,
    stdout: String,
    stderr: String,
}

struct BatchProgress {
    total: usize,
    started_at: Instant,
    completed: AtomicUsize,
    failed: AtomicUsize,
}

impl BatchProgress {
    fn new(total: usize) -> Self {
        Self {
            total,
            started_at: Instant::now(),
            completed: AtomicUsize::new(0),
            failed: AtomicUsize::new(0),
        }
    }

    fn record(&self, template_file: &str, success: bool) -> String {
        let completed = self.completed.fetch_add(1, Ordering::Relaxed) + 1;
        if !success {
            self.failed.fetch_add(1, Ordering::Relaxed);
        }

        let failed = self.failed.load(Ordering::Relaxed);
        let succeeded = completed.saturating_sub(failed);
        let elapsed_secs = self.started_at.elapsed().as_secs_f64();

        format_batch_progress_line(
            completed,
            self.total,
            succeeded,
            failed,
            elapsed_secs,
            template_file,
            success,
        )
    }
}

fn format_batch_progress_line(
    completed: usize,
    total: usize,
    succeeded: usize,
    failed: usize,
    elapsed_secs: f64,
    template_file: &str,
    success: bool,
) -> String {
    let percent = if total == 0 {
        100.0
    } else {
        (completed as f64 * 100.0) / total as f64
    };
    let elapsed = elapsed_secs.max(0.001);
    let rate = completed as f64 / elapsed;
    let remaining = total.saturating_sub(completed);
    let eta_secs = if rate > 0.0 {
        remaining as f64 / rate
    } else {
        0.0
    };
    let result = if success { "ok" } else { "fail" };

    format!(
        "[BATCH PROGRESS] {}/{} ({:.1}%) ok={} fail={} elapsed={:.1}s rate={:.2}/s eta={:.1}s last={} result={}",
        completed,
        total,
        percent,
        succeeded,
        failed,
        elapsed,
        rate,
        eta_secs,
        template_file,
        result
    )
}

fn report_has_high_confidence_finding(report_path: &Path) -> bool {
    report_has_high_confidence_finding_with_min_oracles(
        report_path,
        high_confidence_min_oracles_from_env(),
    )
}

fn high_confidence_min_oracles_from_env() -> usize {
    std::env::var(HIGH_CONFIDENCE_MIN_ORACLES_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_HIGH_CONFIDENCE_MIN_ORACLES)
}

fn parse_correlation_confidence(description: &str) -> Option<String> {
    let marker = "correlation:";
    let description_lc = description.to_ascii_lowercase();
    let start = description_lc.find(marker)?;
    let tail = description_lc.get(start + marker.len()..)?.trim_start();
    let token = tail
        .split_whitespace()
        .next()?
        .trim_matches(|ch: char| ch == '(' || ch == ')' || ch == ',' || ch == ';' || ch == '.');
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

fn parse_correlation_oracle_count(description: &str) -> Option<usize> {
    let marker = "oracles=";
    let start = description.find(marker)?;
    let tail = description.get(start + marker.len()..)?;
    let digits: String = tail.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<usize>().ok()
}

fn report_has_high_confidence_finding_with_min_oracles(
    report_path: &Path,
    min_oracles: usize,
) -> bool {
    let raw = match fs::read_to_string(report_path) {
        Ok(raw) => raw,
        Err(_) => return false,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    let Some(findings) = parsed.get("findings").and_then(|v| v.as_array()) else {
        return false;
    };
    findings.iter().any(|finding| {
        let description = finding
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let Some(confidence) = parse_correlation_confidence(description) else {
            return false;
        };
        if confidence == "critical" {
            return true;
        }
        if confidence != "high" {
            return false;
        }
        match parse_correlation_oracle_count(description) {
            Some(oracles) => oracles >= min_oracles,
            None => true,
        }
    })
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

fn template_family_from_name(name: &str) -> anyhow::Result<Family> {
    if name.ends_with(".yaml") || name.ends_with(".yml") {
        return Ok(Family::Auto);
    }
    anyhow::bail!(
        "Invalid template filename '{}': expected .yaml or .yml extension",
        name
    )
}

fn validate_template_name(name: &str) -> anyhow::Result<()> {
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
        "patterns",
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
        if let Some(values) = registry_file.aliases.get("always") {
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
    output_suffix: &str,
) -> anyhow::Result<ScanRunResult> {
    let family_str = family.as_str();
    let run_signal_dir = run_cfg.scan_output_root.join("run_signals");
    let build_cache_dir = resolve_build_cache_dir(run_cfg.scan_output_root);
    let mut cmd = Command::new(run_cfg.bin_path);
    cmd.env(SCAN_OUTPUT_ROOT_ENV, run_cfg.scan_output_root)
        .env(RUN_SIGNAL_DIR_ENV, &run_signal_dir)
        .env(BUILD_CACHE_DIR_ENV, &build_cache_dir);
    if std::env::var_os(HALO2_EXTERNAL_TIMEOUT_ENV).is_none() {
        cmd.env(
            HALO2_EXTERNAL_TIMEOUT_ENV,
            halo2_effective_external_timeout_secs(run_cfg.framework, run_cfg.timeout).to_string(),
        );
    }
    if std::env::var_os(CAIRO_EXTERNAL_TIMEOUT_ENV).is_none() {
        cmd.env(CAIRO_EXTERNAL_TIMEOUT_ENV, run_cfg.timeout.to_string());
    }
    if std::env::var_os(SCARB_DOWNLOAD_TIMEOUT_ENV).is_none() {
        cmd.env(SCARB_DOWNLOAD_TIMEOUT_ENV, run_cfg.timeout.to_string());
    }
    if let Some(run_root) = run_cfg.scan_run_root {
        cmd.env(SCAN_RUN_ROOT_ENV, run_root);
    }
    if is_external_target(run_cfg.target_circuit) && run_cfg.framework.eq_ignore_ascii_case("halo2")
    {
        let auto_candidates = auto_halo2_toolchain_candidates();

        // External targets often live outside the writable workspace; keep Halo2 Cargo state
        // local and avoid broad toolchain cascades that trigger rustup network fetches.
        if std::env::var_os(HALO2_USE_HOST_CARGO_HOME_ENV).is_none() {
            cmd.env(HALO2_USE_HOST_CARGO_HOME_ENV, "0");
        }
        if std::env::var_os(HALO2_CARGO_TOOLCHAIN_CANDIDATES_ENV).is_none()
            && !auto_candidates.is_empty()
        {
            cmd.env(
                HALO2_CARGO_TOOLCHAIN_CANDIDATES_ENV,
                auto_candidates.join(","),
            );
        }
        if std::env::var_os(HALO2_TOOLCHAIN_CASCADE_LIMIT_ENV).is_none() {
            let cascade_limit = auto_candidates.len().clamp(1, 8);
            cmd.env(HALO2_TOOLCHAIN_CASCADE_LIMIT_ENV, cascade_limit.to_string());
        }
    }
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

    // Validation dry-runs should not materialize scan output roots.
    if !validate_only {
        cmd.arg("--output-suffix").arg(output_suffix);
    }

    if validate_only {
        cmd.arg("--dry-run");
    }

    if run_cfg.dry_run {
        let suffix_arg = if !validate_only {
            format!(" --output-suffix {}", output_suffix)
        } else {
            String::new()
        };
        println!(
            "[DRY RUN] {}={} {}={} {}={} {} scan {} --family {} --target-circuit {} --main-component {} --framework {} --workers {} --seed {} --iterations {} --timeout {} --simple-progress{}{}",
            SCAN_OUTPUT_ROOT_ENV,
            run_cfg.scan_output_root.display(),
            RUN_SIGNAL_DIR_ENV,
            run_signal_dir.display(),
            BUILD_CACHE_DIR_ENV,
            build_cache_dir.display(),
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
            suffix_arg,
            if validate_only { " --dry-run" } else { "" }
        );
        return Ok(ScanRunResult {
            success: true,
            stdout: String::new(),
            stderr: String::new(),
        });
    }

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !stdout.is_empty() {
        print!("{}", stdout);
    }
    if !stderr.is_empty() {
        eprint!("{}", stderr);
    }

    Ok(ScanRunResult {
        success: output.status.success(),
        stdout,
        stderr,
    })
}

fn resolve_build_cache_dir(scan_output_root: &Path) -> PathBuf {
    for env_name in [BUILD_CACHE_DIR_ENV, SHARED_BUILD_CACHE_DIR_ENV] {
        if let Ok(raw) = std::env::var(env_name) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed);
            }
        }
    }
    scan_output_root.join("_build_cache")
}

fn halo2_effective_external_timeout_secs(framework: &str, requested_timeout: u64) -> u64 {
    if !framework.eq_ignore_ascii_case("halo2") {
        return requested_timeout;
    }

    let floor = std::env::var(HALO2_MIN_EXTERNAL_TIMEOUT_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(180);

    requested_timeout.max(floor)
}

fn push_unique_nonempty(values: &mut Vec<String>, candidate: impl Into<String>) {
    let candidate = candidate.into();
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return;
    }
    if values.iter().any(|existing| existing == trimmed) {
        return;
    }
    values.push(trimmed.to_string());
}

fn parse_rustup_toolchain_names(raw: &str) -> Vec<String> {
    let mut parsed = Vec::new();
    for line in raw.lines() {
        let first = line.split_whitespace().next().unwrap_or_default().trim();
        if first.is_empty() || first.starts_with("info:") || first.starts_with("error:") {
            continue;
        }
        push_unique_nonempty(&mut parsed, first.trim_end_matches(','));
    }
    parsed
}

fn rustup_stdout(args: &[&str]) -> Option<String> {
    let output = Command::new("rustup").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

fn auto_halo2_toolchain_candidates() -> Vec<String> {
    let mut candidates = Vec::<String>::new();

    if let Some(active) = rustup_stdout(&["show", "active-toolchain"]) {
        if let Some(toolchain) = active.split_whitespace().next() {
            push_unique_nonempty(&mut candidates, toolchain);
        }
    }

    let installed = rustup_stdout(&["toolchain", "list"])
        .map(|raw| parse_rustup_toolchain_names(&raw))
        .unwrap_or_default();
    let installed_set = installed.iter().cloned().collect::<BTreeSet<String>>();

    for preferred in [
        "nightly-x86_64-unknown-linux-gnu",
        "nightly",
        "stable-x86_64-unknown-linux-gnu",
        "stable",
    ] {
        if installed_set.contains(preferred) {
            push_unique_nonempty(&mut candidates, preferred);
        }
    }

    for name in &installed {
        if name.starts_with("nightly-") {
            push_unique_nonempty(&mut candidates, name);
        }
    }
    for name in &installed {
        if name.starts_with("stable-") {
            push_unique_nonempty(&mut candidates, name);
        }
    }
    for name in &installed {
        push_unique_nonempty(&mut candidates, name);
    }

    const MAX_AUTO_TOOLCHAINS: usize = 6;
    if candidates.len() > MAX_AUTO_TOOLCHAINS {
        candidates.truncate(MAX_AUTO_TOOLCHAINS);
    }
    candidates
}

fn is_external_target(target_circuit: &str) -> bool {
    let target_path = Path::new(target_circuit);
    if !target_path.is_absolute() {
        return false;
    }

    let Ok(workspace_root) = std::env::current_dir() else {
        return false;
    };
    !target_path.starts_with(&workspace_root)
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
) -> anyhow::Result<Family> {
    let effective = effective_family(template.family, family_override);
    Ok(effective)
}

fn run_template(
    run_cfg: ScanRunConfig<'_>,
    template: &TemplateInfo,
    family: Family,
    skip_validate: bool,
    output_suffix: &str,
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

    if !skip_validate {
        let validate = run_scan(run_cfg, template, family, true, output_suffix)?;
        if !validate.success {
            if is_selector_mismatch_validation(&validate.stdout, &validate.stderr)
                && write_selector_mismatch_outcome(
                    run_cfg.artifacts_root,
                    run_cfg.scan_run_root,
                    output_suffix,
                )
                .is_ok()
            {
                eprintln!(
                    "Template '{}' selector mismatch recorded as synthetic preflight outcome",
                    template.file_name
                );
                return Ok(true);
            }
            eprintln!("Template '{}' failed validation", template.file_name);
            return Ok(false);
        }
    }

    if !run_scan(run_cfg, template, family, false, output_suffix)?.success {
        eprintln!("Template '{}' failed", template.file_name);
        return Ok(false);
    }

    Ok(true)
}

fn scan_output_suffix(template: &TemplateInfo, family: Family) -> String {
    let stem = template
        .file_name
        .strip_suffix(".yaml")
        .unwrap_or(template.file_name.as_str());
    let mut normalized = String::with_capacity(stem.len() + 8);
    for ch in stem.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            normalized.push(ch);
        } else {
            normalized.push('_');
        }
    }
    if normalized.is_empty() {
        normalized = "pattern".to_string();
    }
    format!("{}__{}", family.as_str(), normalized)
}

fn resolve_scan_output_root(override_root: Option<&str>) -> anyhow::Result<PathBuf> {
    if let Some(raw) = override_root {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            anyhow::bail!("--output-root cannot be empty");
        }
        return Ok(PathBuf::from(trimmed));
    }

    let raw = std::env::var(SCAN_OUTPUT_ROOT_ENV).with_context(|| {
        format!(
            "{} is required when --output-root is not provided",
            SCAN_OUTPUT_ROOT_ENV
        )
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!(
            "{} is set but empty; provide a writable output root",
            SCAN_OUTPUT_ROOT_ENV
        );
    }
    Ok(PathBuf::from(trimmed))
}

fn reserve_batch_scan_run_root(artifacts_root: &Path) -> anyhow::Result<String> {
    std::fs::create_dir_all(artifacts_root).with_context(|| {
        format!(
            "Failed to create scan artifacts root '{}'",
            artifacts_root.display()
        )
    })?;

    // Keep run-root naming stable while avoiding collisions for concurrent batch invocations.
    for _ in 0..120 {
        let ts = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let candidate = format!("scan_run{}", ts);
        let reservation = artifacts_root.join(&candidate);
        match std::fs::create_dir(&reservation) {
            Ok(_) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                std::thread::sleep(std::time::Duration::from_millis(1100));
                continue;
            }
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "Failed to reserve batch scan run root '{}' under '{}': {}",
                    candidate,
                    artifacts_root.display(),
                    err
                ));
            }
        }
    }

    anyhow::bail!(
        "Failed to allocate unique batch scan run root after repeated collisions under '{}'",
        artifacts_root.display()
    )
}

fn list_scan_run_roots(artifacts_root: &Path) -> anyhow::Result<BTreeSet<String>> {
    if !artifacts_root.exists() {
        return Ok(BTreeSet::new());
    }

    let mut roots = BTreeSet::new();
    for entry in fs::read_dir(artifacts_root).with_context(|| {
        format!(
            "Failed to read artifacts root '{}'",
            artifacts_root.display()
        )
    })? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("scan_run") {
            continue;
        }
        if entry.file_type()?.is_dir() {
            roots.insert(name.to_string());
        }
    }

    Ok(roots)
}

fn collect_observed_suffixes_for_roots(
    artifacts_root: &Path,
    run_roots: &BTreeSet<String>,
) -> anyhow::Result<BTreeSet<String>> {
    let mut observed = BTreeSet::new();
    for run_root in run_roots {
        let run_root_path = artifacts_root.join(run_root);
        if !run_root_path.exists() {
            continue;
        }
        for entry in fs::read_dir(&run_root_path).with_context(|| {
            format!(
                "Failed to read run artifact root '{}'",
                run_root_path.display()
            )
        })? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            observed.insert(name.to_string());
        }
    }
    Ok(observed)
}

fn classify_run_reason_code(doc: &serde_json::Value) -> &'static str {
    let Some(obj) = doc.as_object() else {
        return "invalid_run_outcome_json";
    };
    let status = obj
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let stage = obj
        .get("stage")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let error_lc = obj
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let reason_lc = obj
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let panic_message_lc = obj
        .get("panic")
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let is_dependency_resolution_failure = |message: &str| -> bool {
        message.contains("failed to load source for dependency")
            || message.contains("failed to get `")
            || message.contains("failed to update")
            || message.contains("unable to update")
            || message.contains("could not clone")
            || message.contains("failed to clone")
            || message.contains("failed to fetch into")
            || message.contains("couldn't find remote ref")
            || message.contains("network failure seems to have happened")
            || message.contains("spurious network error")
            || message.contains("index-pack failed")
            || message.contains("failed to download")
            || message.contains("checksum failed")
    };
    let is_input_contract_mismatch = |message: &str| -> bool {
        message.contains("not all inputs have been set")
            || message.contains("input map is missing")
            || message.contains("missing required circom signals")
    };
    let is_circom_compilation_failure = |message: &str| -> bool {
        message.contains("circom compilation failed")
            || message.contains("failed to run circom compiler")
            || (message.contains("out of bounds exception") && message.contains(".circom"))
    };
    let is_backend_toolchain_mismatch = |message: &str| -> bool {
        let cascade_exhausted = message.contains("toolchain cascade exhausted")
            || message.contains("scarb build failed for all configured candidates")
            || message.contains("no working scarb candidate found");
        let scarb_compile_mismatch = message.contains("scarb build failed")
            && message.contains("could not compile `")
            && (message.contains("error[e")
                || message.contains("identifier not found")
                || message.contains("type annotations needed")
                || message.contains("unsupported"));
        let rust_toolchain_mismatch = message.contains("requires rustc")
            || message.contains("the package requires")
            || message.contains("is not supported by this compiler")
            || message.contains("cargo-features");
        cascade_exhausted || scarb_compile_mismatch || rust_toolchain_mismatch
    };

    if status == "completed_with_critical_findings" {
        return "critical_findings_detected";
    }
    if status == "completed" {
        return "completed";
    }
    if status == "failed_engagement_contract" {
        return "engagement_contract_failed";
    }
    if status == "stale_interrupted" {
        return "stale_interrupted";
    }
    if status == "panic" {
        if panic_message_lc.contains("missing required 'command' in run document") {
            return "artifact_mirror_panic_missing_command";
        }
        return "panic";
    }
    if status == "running" {
        return "running";
    }
    if error_lc.contains("permission denied") {
        return "filesystem_permission_denied";
    }
    if stage == "preflight_backend"
        && (error_lc.contains("backend required but not available")
            || error_lc.contains("not found in path")
            || error_lc.contains("snarkjs not found")
            || error_lc.contains("circom not found")
            || error_lc.contains("install circom"))
    {
        return "backend_tooling_missing";
    }
    if stage == "preflight_backend" && is_dependency_resolution_failure(&error_lc) {
        return "backend_dependency_resolution_failed";
    }
    if stage == "preflight_backend" && is_backend_toolchain_mismatch(&error_lc) {
        return "backend_toolchain_mismatch";
    }
    if is_circom_compilation_failure(&error_lc) {
        return "circom_compilation_failed";
    }
    if error_lc.contains("key generation failed")
        || error_lc.contains("key setup failed")
        || error_lc.contains("proving key")
    {
        return "key_generation_failed";
    }
    if error_lc.contains("wall-clock timeout") || reason_lc.contains("wall-clock timeout") {
        return "wall_clock_timeout";
    }
    if stage == "acquire_output_lock" {
        return "output_dir_locked";
    }
    if is_input_contract_mismatch(&error_lc) {
        return "backend_input_contract_mismatch";
    }
    if stage == "preflight_backend" {
        return "backend_preflight_failed";
    }
    if stage == "preflight_selector" {
        return "selector_mismatch";
    }
    if stage == "preflight_invariants" {
        return "missing_invariants";
    }
    if stage == "preflight_readiness" {
        return "readiness_failed";
    }
    if stage == "parse_chains" && reason_lc.contains("requires chains") {
        return "missing_chains_definition";
    }
    if status == "failed" {
        return "runtime_error";
    }

    "unknown"
}

fn collect_template_outcome_reasons(
    artifacts_root: &Path,
    run_root: Option<&str>,
    selected_with_family: &[(TemplateInfo, Family)],
) -> Vec<TemplateOutcomeReason> {
    let Some(run_root) = run_root else {
        return Vec::new();
    };

    selected_with_family
        .iter()
        .map(|(template, family)| {
            let suffix = scan_output_suffix(template, *family);
            let run_outcome_path = artifacts_root
                .join(run_root)
                .join(&suffix)
                .join("run_outcome.json");

            if !run_outcome_path.exists() {
                return TemplateOutcomeReason {
                    template_file: template.file_name.clone(),
                    suffix,
                    status: None,
                    stage: None,
                    reason_code: "run_outcome_missing".to_string(),
                    high_confidence_detected: false,
                };
            }

            let raw = match fs::read_to_string(&run_outcome_path) {
                Ok(raw) => raw,
                Err(_) => {
                    return TemplateOutcomeReason {
                        template_file: template.file_name.clone(),
                        suffix,
                        status: None,
                        stage: None,
                        reason_code: "run_outcome_unreadable".to_string(),
                        high_confidence_detected: false,
                    };
                }
            };

            let parsed: serde_json::Value = match serde_json::from_str(&raw) {
                Ok(parsed) => parsed,
                Err(_) => {
                    return TemplateOutcomeReason {
                        template_file: template.file_name.clone(),
                        suffix,
                        status: None,
                        stage: None,
                        reason_code: "run_outcome_invalid_json".to_string(),
                        high_confidence_detected: false,
                    };
                }
            };

            let status = parsed
                .get("status")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let stage = parsed
                .get("stage")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let report_path = artifacts_root
                .join(run_root)
                .join(&suffix)
                .join("report.json");

            TemplateOutcomeReason {
                template_file: template.file_name.clone(),
                suffix,
                status,
                stage,
                reason_code: parsed
                    .get("reason_code")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| classify_run_reason_code(&parsed).to_string()),
                high_confidence_detected: report_has_high_confidence_finding(&report_path),
            }
        })
        .collect()
}

fn print_reason_summary(reasons: &[TemplateOutcomeReason]) {
    if reasons.is_empty() {
        return;
    }

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for reason in reasons {
        *counts.entry(reason.reason_code.clone()).or_insert(0) += 1;
    }

    let summary_line = counts
        .iter()
        .map(|(code, count)| format!("{}={}", code, count))
        .collect::<Vec<_>>()
        .join(", ");

    println!("Reason code summary: {}", summary_line);

    for reason in reasons {
        if reason.reason_code == "completed" || reason.reason_code == "critical_findings_detected" {
            continue;
        }
        println!(
            "  - {} [{}]: reason_code={} status={} stage={}",
            reason.template_file,
            reason.suffix,
            reason.reason_code,
            reason.status.as_deref().unwrap_or("unknown"),
            reason.stage.as_deref().unwrap_or("unknown"),
        );
    }
}

fn print_reason_tsv(reasons: &[TemplateOutcomeReason]) {
    if reasons.is_empty() {
        return;
    }

    println!("REASON_TSV_START");
    println!("template\tsuffix\treason_code\tstatus\tstage\thigh_confidence_detected");
    for reason in reasons {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            reason.template_file,
            reason.suffix,
            reason.reason_code,
            reason.status.as_deref().unwrap_or("unknown"),
            reason.stage.as_deref().unwrap_or("unknown"),
            if reason.high_confidence_detected {
                "1"
            } else {
                "0"
            },
        );
    }
    println!("REASON_TSV_END");
}

fn is_selector_mismatch_validation(stdout: &str, stderr: &str) -> bool {
    let combined = format!("{}\n{}", stdout, stderr).to_ascii_lowercase();
    combined.contains("selectors did not match target circuit")
}

fn write_selector_mismatch_outcome(
    artifacts_root: &Path,
    run_root: Option<&str>,
    output_suffix: &str,
) -> anyhow::Result<()> {
    let Some(run_root) = run_root else {
        anyhow::bail!("scan_run_root is unavailable for selector mismatch outcome");
    };

    let template_dir = artifacts_root.join(run_root).join(output_suffix);
    fs::create_dir_all(&template_dir).with_context(|| {
        format!(
            "Failed creating selector-mismatch artifact dir '{}'",
            template_dir.display()
        )
    })?;

    let run_outcome_path = template_dir.join("run_outcome.json");
    let payload = serde_json::json!({
        "status": "failed",
        "stage": "preflight_selector",
        "reason": "selector_mismatch",
        "error": "Pattern selectors did not match target circuit",
    });
    let serialized = serde_json::to_string_pretty(&payload)?;
    fs::write(&run_outcome_path, serialized).with_context(|| {
        format!(
            "Failed writing selector-mismatch run outcome '{}'",
            run_outcome_path.display()
        )
    })?;

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let family_override = parse_family(&args.family)?;

    let registry_path_raw = args
        .registry
        .clone()
        .unwrap_or_else(|| default_registry_for_profile(args.config_profile).to_string());
    let registry_path = PathBuf::from(&registry_path_raw);
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
        let chosen_family = validate_template_compatibility(&template, family_override)?;
        selected_with_family.push((template, chosen_family));
    }
    let expected_suffixes: BTreeSet<String> = selected_with_family
        .iter()
        .map(|(template, family)| scan_output_suffix(template, *family))
        .collect();
    let expected_count = expected_suffixes.len();
    let batch_started_at = Instant::now();

    println!("Gate 1/3 (expected templates): {}", expected_count);

    let bin_path = PathBuf::from("target/release/zk-fuzzer");
    if args.build {
        let status = Command::new("cargo")
            .args(["build", "--release", "--bin", "zk-fuzzer"])
            .status()?;
        if !status.success() {
            anyhow::bail!("cargo build --release --bin zk-fuzzer failed");
        }
    } else if !bin_path.exists() {
        anyhow::bail!(
            "zk-fuzzer binary not found at '{}' and --build=false",
            bin_path.display()
        );
    }

    let scan_output_root = resolve_scan_output_root(args.output_root.as_deref())?;
    let artifacts_root = scan_output_root.join(".scan_run_artifacts");

    let run_cfg_base = ScanRunConfig {
        bin_path: &bin_path,
        target_circuit: &target_circuit,
        framework: &args.framework,
        main_component: &args.main_component,
        workers: args.workers,
        seed: args.seed,
        iterations: args.iterations,
        timeout: args.timeout,
        scan_run_root: None,
        scan_output_root: &scan_output_root,
        dry_run: args.dry_run,
        artifacts_root: &artifacts_root,
    };

    let baseline_roots = if args.dry_run {
        BTreeSet::new()
    } else {
        list_scan_run_roots(&artifacts_root)?
    };
    // One batch command -> one collision-safe scan_run root.
    let batch_run_root = if args.dry_run {
        None
    } else {
        Some(reserve_batch_scan_run_root(&artifacts_root)?)
    };
    let run_cfg = ScanRunConfig {
        scan_run_root: batch_run_root.as_deref(),
        ..run_cfg_base
    };

    use rayon::prelude::*;

    let jobs = args.jobs.max(1);
    println!(
        "Running {} templates in parallel (jobs={})",
        selected_with_family.len(),
        jobs
    );
    println!(
        "Batch progress indicator: {}",
        if args.no_batch_progress {
            "disabled"
        } else {
            "enabled"
        }
    );
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build()
        .map_err(|err| anyhow::anyhow!("Failed to build rayon thread pool: {}", err))?;
    let progress = if args.no_batch_progress {
        None
    } else {
        Some(Arc::new(BatchProgress::new(selected_with_family.len())))
    };

    let outcomes = pool.install(|| {
        selected_with_family
            .par_iter()
            .map(|(template, family)| {
                let suffix = scan_output_suffix(template, *family);
                let ok = match run_template(
                    run_cfg,
                    template,
                    *family,
                    args.skip_validate,
                    suffix.as_str(),
                ) {
                    Ok(ok) => ok,
                    Err(err) => {
                        eprintln!("Template '{}' failed: {}", template.file_name, err);
                        false
                    }
                };
                if let Some(progress) = progress.as_ref() {
                    println!("{}", progress.record(&template.file_name, ok));
                }
                ok
            })
            .collect::<Vec<_>>()
    });

    let executed = outcomes.len();
    let failures = outcomes.iter().filter(|ok| !**ok).count();
    let duration_secs = batch_started_at.elapsed().as_secs_f64().max(0.001);
    let avg_rate = executed as f64 / duration_secs;

    println!(
        "Batch complete. Templates executed: {}, failures: {}, duration: {:.1}s, avg_rate: {:.2}/s",
        executed, failures, duration_secs, avg_rate
    );
    let gate2_ok = executed == expected_count && failures == 0;
    println!(
        "Gate 2/3 (completion line): {}",
        if gate2_ok {
            format!("PASS (executed={}, failures=0)", executed)
        } else {
            format!(
                "FAIL (expected={}, executed={}, failures={})",
                expected_count, executed, failures
            )
        }
    );

    let gate3_ok = if args.dry_run {
        println!("Gate 3/3 (artifact reconciliation): SKIP (dry run)");
        true
    } else {
        let after_roots = list_scan_run_roots(&artifacts_root)?;
        let new_roots: BTreeSet<String> =
            after_roots.difference(&baseline_roots).cloned().collect();
        let observed_suffixes = collect_observed_suffixes_for_roots(&artifacts_root, &new_roots)?;
        let missing: Vec<String> = expected_suffixes
            .difference(&observed_suffixes)
            .cloned()
            .collect();
        if missing.is_empty() {
            println!(
                "Gate 3/3 (artifact reconciliation): PASS (new run roots={}, observed={})",
                new_roots.len(),
                observed_suffixes.len()
            );
            true
        } else {
            eprintln!(
                "Gate 3/3 (artifact reconciliation): FAIL (missing={})",
                missing.len()
            );
            eprintln!("Missing suffixes: {}", missing.join(", "));
            false
        }
    };

    if !args.dry_run {
        let reasons = collect_template_outcome_reasons(
            &artifacts_root,
            batch_run_root.as_deref(),
            &selected_with_family,
        );
        print_reason_summary(&reasons);
        if args.emit_reason_tsv {
            print_reason_tsv(&reasons);
        }
    }

    if !gate2_ok || !gate3_ok {
        std::process::exit(1);
    }

    Ok(())
}
