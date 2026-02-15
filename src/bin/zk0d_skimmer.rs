use clap::Parser;
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zk_fuzzer::analysis::opus::{GeneratedConfig, OpusAnalyzer, OpusConfig, ZeroDayCategory};
use zk_fuzzer::targets::circom_analysis;

const DEFAULT_ZK0D_BASE: &str = "/media/elements/Repos/zk0d";

#[derive(Parser, Debug)]
#[command(name = "zk0d_skimmer")]
#[command(about = "Skim zk0d repository for promising circuits (hints only)")]
struct Args {
    /// Root path to zk0d
    #[arg(long)]
    root: Option<String>,

    /// Override placeholder for root path in generated outputs (e.g. ${TARGET_REPO})
    #[arg(long)]
    root_placeholder: Option<String>,

    /// Maximum circuit files to analyze
    #[arg(long, default_value_t = 200)]
    max_files: usize,

    /// Minimum hint confidence
    #[arg(long, default_value_t = 0.3)]
    min_confidence: f64,

    /// Comma-separated circuit extensions to scan (default: circom,nr,cairo)
    #[arg(long, default_value = "circom,nr,cairo")]
    extensions: String,

    /// Save generated YAML configs (skimmer only)
    #[arg(long, default_value_t = true)]
    save_configs: bool,

    /// Directory for generated YAML configs
    #[arg(long, default_value = "campaigns/zk0d/skimmer")]
    config_dir: String,

    /// Output directory for summary
    #[arg(long, default_value = "reports/zk0d/skimmer")]
    output_dir: String,

    /// Number of top candidates to display
    #[arg(long, default_value_t = 10)]
    top: usize,
}

#[derive(Debug, Serialize)]
struct SkimEntry {
    circuit_name: String,
    circuit_path: String,
    hint_score: f64,
    hint_count: usize,
    high_confidence: usize,
    hints: Vec<HintSummary>,
}

#[derive(Debug, Serialize, Clone)]
struct HintSummary {
    category: String,
    confidence: f64,
    description: String,
}

#[derive(Debug, Serialize)]
struct CandidateInvariant {
    name: String,
    category: String,
    confidence: f64,
    relation: String,
    inputs: Vec<String>,
    rationale: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct CandidateEntry {
    circuit_name: String,
    circuit_path: String,
    hint_score: f64,
    hints: Vec<HintSummary>,
    candidate_invariants: Vec<CandidateInvariant>,
}

#[derive(Debug, Serialize)]
struct CandidateInvariantsFile {
    version: u32,
    generated: String,
    root: String,
    note: String,
    candidates: Vec<CandidateEntry>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let env_root = match std::env::var("ZK0D_BASE") {
        Ok(v) => Some(v),
        Err(_) => None,
    };
    let root_value = args
        .root
        .or(env_root);
    let root_value = match root_value {
        Some(value) => value,
        None => {
            anyhow::bail!(
                "Missing zk0d root: pass --root or set ZK0D_BASE (example: {})",
                DEFAULT_ZK0D_BASE
            );
        }
    };
    let root = PathBuf::from(&root_value);

    if !root.exists() {
        anyhow::bail!("Root path does not exist: {}", root.display());
    }
    ensure_single_repo(&root)?;

    let extensions: Vec<String> = args
        .extensions
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let config = OpusConfig {
        max_files: args.max_files,
        min_zero_day_confidence: args.min_confidence,
        circuit_extensions: extensions,
        ..Default::default()
    };

    let analyzer = OpusAnalyzer::with_config(config);
    let generated = analyzer.analyze_project(&root)?;

    if generated.is_empty() {
        println!("No circuits analyzed (empty result).");
        return Ok(());
    }

    let mut entries: Vec<SkimEntry> = generated.iter().map(entry_from_generated).collect();

    entries.sort_by(|a, b| b.hint_score.total_cmp(&a.hint_score));

    let output_dir = Path::new(&args.output_dir);
    std::fs::create_dir_all(output_dir)?;

    let summary_path = output_dir.join("skimmer_summary.md");
    let json_path = output_dir.join("skimmer_summary.json");
    let candidate_path = output_dir.join("candidate_invariants.yaml");
    let root_placeholder = root_placeholder(&root, args.root_placeholder.as_deref());

    write_summary_markdown(
        &summary_path,
        &entries,
        args.top,
        &root,
        root_placeholder.as_deref(),
    )?;
    let json = serde_json::to_string_pretty(&entries)?;
    std::fs::write(&json_path, json)?;
    write_candidate_invariants(
        &candidate_path,
        &generated,
        &entries,
        args.top,
        &root,
        root_placeholder.as_deref(),
    )?;

    if args.save_configs {
        let config_dir = Path::new(&args.config_dir);
        std::fs::create_dir_all(config_dir)?;
        for gen in &generated {
            if let Some(placeholder) = root_placeholder.as_deref() {
                gen.save_with_placeholder(config_dir, &root, placeholder)?;
            } else {
                gen.save(config_dir)?;
            }
        }
    }

    println!(
        "Skimmer complete. Summary: {} (top {} shown). Candidates: {}",
        summary_path.display(),
        args.top,
        candidate_path.display()
    );

    Ok(())
}

fn ensure_single_repo(root: &Path) -> anyhow::Result<()> {
    let git_marker = root.join(".git");
    if !git_marker.exists() {
        anyhow::bail!(
            "Skimmer expects a single repo root (missing .git): {}",
            root.display()
        );
    }
    Ok(())
}

fn entry_from_generated(g: &GeneratedConfig) -> SkimEntry {
    let mut hint_score = 0.0;
    let mut high_confidence = 0usize;
    for h in &g.zero_day_hints {
        hint_score += h.confidence;
        if h.confidence >= 0.6 {
            high_confidence += 1;
        }
    }

    let hints = g
        .zero_day_hints
        .iter()
        .map(|h| HintSummary {
            category: format!("{:?}", h.category),
            confidence: h.confidence,
            description: h.description.clone(),
        })
        .collect();

    SkimEntry {
        circuit_name: g.circuit_name.clone(),
        circuit_path: g.circuit_path.display().to_string(),
        hint_score,
        hint_count: g.zero_day_hints.len(),
        high_confidence,
        hints,
    }
}

fn write_summary_markdown(
    path: &Path,
    entries: &[SkimEntry],
    top: usize,
    root: &Path,
    root_placeholder: Option<&str>,
) -> anyhow::Result<()> {
    let mut out = String::new();
    out.push_str("# zk0d Skimmer Summary (Hints Only)\n\n");
    out.push_str("**WARNING:** This is a hint-only scan. No findings are confirmed.\n\n");
    let root_display = root_placeholder
        .map(str::to_string);
    let root_display = match root_display {
        Some(value) => value,
        None => root.display().to_string(),
    };
    out.push_str(&format!("Root: `{}`\n\n", root_display));

    let display = entries.iter().take(top);
    for (i, entry) in display.enumerate() {
        out.push_str(&format!(
            "## {}. {} (score {:.2})\n",
            i + 1,
            entry.circuit_name,
            entry.hint_score
        ));
        let display_path =
            rewrite_path_with_placeholder(&entry.circuit_path, root, root_placeholder);
        out.push_str(&format!("Path: `{}`\n\n", display_path));
        if entry.hints.is_empty() {
            out.push_str("- No hints\n\n");
            continue;
        }
        out.push_str("Hints:\n");
        for h in &entry.hints {
            out.push_str(&format!(
                "- [{:.0}%] {:?}: {}\n",
                h.confidence * 100.0,
                h.category,
                h.description
            ));
        }
        out.push('\n');
    }

    std::fs::write(path, out)?;
    Ok(())
}

fn write_candidate_invariants(
    path: &Path,
    generated: &[GeneratedConfig],
    entries: &[SkimEntry],
    top: usize,
    root: &Path,
    root_placeholder: Option<&str>,
) -> anyhow::Result<()> {
    let mut by_path: HashMap<String, &GeneratedConfig> = HashMap::new();
    for gen in generated {
        by_path.insert(gen.circuit_path.display().to_string(), gen);
    }

    let mut candidates = Vec::new();
    for entry in entries.iter().take(top) {
        let Some(gen) = by_path.get(&entry.circuit_path) else {
            continue;
        };
        let input_names = extract_circom_inputs(&gen.circuit_path);
        let candidate_invariants =
            candidate_invariants_from_hints(&gen.zero_day_hints, &input_names);
        let display_path =
            rewrite_path_with_placeholder(&entry.circuit_path, root, root_placeholder);

        candidates.push(CandidateEntry {
            circuit_name: entry.circuit_name.clone(),
            circuit_path: display_path,
            hint_score: entry.hint_score,
            hints: entry.hints.clone(),
            candidate_invariants,
        });
    }

    let root_display = root_placeholder
        .map(str::to_string);
    let root_display = match root_display {
        Some(value) => value,
        None => root.display().to_string(),
    };

    let doc = CandidateInvariantsFile {
        version: 1,
        generated: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        root: root_display,
        note: "Auto-generated from skimmer hints. Manual review required to fill exact inputs and finalize invariants.".to_string(),
        candidates,
    };

    let header = "# Auto-generated candidate invariants (manual review required)\n\
# Fill in exact inputs and refine relations before evidence runs.\n\n";
    let yaml = serde_yaml::to_string(&doc)?;
    std::fs::write(path, format!("{}{}", header, yaml))?;
    Ok(())
}

fn extract_circom_inputs(path: &Path) -> Vec<String> {
    let ext = match path.extension().and_then(|s| s.to_str()) {
        Some(value) => value,
        None => return Vec::new(),
    };
    if ext != "circom" {
        return Vec::new();
    }
    let Ok(source) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let signals = circom_analysis::extract_signals(&source);
    let mut inputs: Vec<String> = signals
        .into_iter()
        .filter(|s| matches!(s.direction, circom_analysis::SignalDirection::Input))
        .map(|s| s.name)
        .collect();
    inputs.sort();
    inputs.dedup();
    inputs
}

fn candidate_invariants_from_hints(
    hints: &[zk_fuzzer::analysis::opus::ZeroDayHint],
    inputs: &[String],
) -> Vec<CandidateInvariant> {
    let mut out = Vec::new();
    for (idx, hint) in hints.iter().enumerate() {
        let affected = inputs_for_category(&hint.category, inputs, 4);
        if affected.is_empty() {
            tracing::warn!(
                "Skipping hint {} ({:?}): no matching circuit inputs found",
                idx.saturating_add(1),
                hint.category
            );
            continue;
        }
        let primary = affected[0].clone();
        let relation = relation_for_category(&hint.category, &primary);
        let name =
            format!("{:?}_candidate_{}", hint.category, idx.saturating_add(1)).to_lowercase();
        out.push(CandidateInvariant {
            name,
            category: format!("{:?}", hint.category),
            confidence: hint.confidence,
            relation,
            inputs: affected,
            rationale: hint.description.clone(),
            status: "manual_review_required".to_string(),
        });
    }
    out
}

fn inputs_for_category(category: &ZeroDayCategory, inputs: &[String], limit: usize) -> Vec<String> {
    let keywords: &[&str] = match category {
        ZeroDayCategory::SignatureMalleability => &["sig", "signature", "r8", "s"],
        ZeroDayCategory::BitDecompositionBypass => &["path", "index", "indices", "bit", "flag"],
        ZeroDayCategory::IncorrectRangeCheck | ZeroDayCategory::ArithmeticOverflow => &[
            "amount",
            "value",
            "nonce",
            "balance",
            "fee",
            "refund",
            "timestamp",
            "index",
            "slot",
            "count",
            "size",
        ],
        ZeroDayCategory::HashMisuse => &["hash", "root", "commit", "merkle"],
        ZeroDayCategory::NullifierReuse => &["nullifier"],
        _ => &[],
    };

    let mut matches = Vec::new();
    if !keywords.is_empty() {
        for input in inputs {
            let lower = input.to_lowercase();
            if keywords.iter().any(|k| lower.contains(k)) {
                matches.push(input.clone());
                if matches.len() >= limit {
                    break;
                }
            }
        }
    }

    if matches.is_empty() {
        inputs
            .iter()
            .take(limit.min(inputs.len()))
            .cloned()
            .collect()
    } else {
        matches
    }
}

fn relation_for_category(category: &ZeroDayCategory, primary: &str) -> String {
    match category {
        ZeroDayCategory::SignatureMalleability => format!("{} < subgroup_order", primary),
        ZeroDayCategory::BitDecompositionBypass => format!("{} in {{0,1}}", primary),
        ZeroDayCategory::IncorrectRangeCheck | ZeroDayCategory::ArithmeticOverflow => {
            format!("0 <= {} < 2^64", primary)
        }
        ZeroDayCategory::HashMisuse => format!("domain_sep({})", primary),
        ZeroDayCategory::NullifierReuse => format!("unique({})", primary),
        ZeroDayCategory::MissingConstraint => format!("constraint_missing({})", primary),
        ZeroDayCategory::NonDeterministicWitness => "deterministic_witness(inputs)".to_string(),
        ZeroDayCategory::TimingLeak => "timing_constant(inputs)".to_string(),
        ZeroDayCategory::Custom(name) => format!("custom_invariant({})", name),
    }
}

fn root_placeholder(root: &Path, override_placeholder: Option<&str>) -> Option<String> {
    if let Some(override_placeholder) = override_placeholder {
        let trimmed = override_placeholder.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    let root_str = root.to_string_lossy();
    let env_root = match std::env::var("ZK0D_BASE") {
        Ok(v) => Some(v),
        Err(_) => None,
    };
    if root_str == DEFAULT_ZK0D_BASE || env_root.as_deref() == Some(root_str.as_ref()) {
        Some("${ZK0D_BASE}".to_string())
    } else {
        None
    }
}

fn rewrite_path_with_placeholder(path: &str, root: &Path, placeholder: Option<&str>) -> String {
    let Some(placeholder) = placeholder else {
        return path.to_string();
    };
    let root_str = root.to_string_lossy();
    let root_str = root_str.trim_end_matches(std::path::MAIN_SEPARATOR);
    if let Some(raw_suffix) = path.strip_prefix(root_str) {
        let suffix = raw_suffix.trim_start_matches(std::path::MAIN_SEPARATOR);
        if suffix.is_empty() {
            placeholder.to_string()
        } else {
            format!("{}/{}", placeholder.trim_end_matches('/'), suffix)
        }
    } else {
        path.to_string()
    }
}
