use clap::Parser;
use serde::Serialize;
use std::path::{Path, PathBuf};
use zk_fuzzer::analysis::opus::{GeneratedConfig, OpusAnalyzer, OpusConfig};

#[derive(Parser, Debug)]
#[command(name = "zk0d_skimmer")]
#[command(about = "Skim zk0d repository for promising circuits (hints only)")]
struct Args {
    /// Root path to zk0d
    #[arg(long, default_value = "/media/elements/Repos/zk0d")]
    root: String,

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

#[derive(Debug, Serialize)]
struct HintSummary {
    category: String,
    confidence: f64,
    description: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let root = PathBuf::from(&args.root);

    if !root.exists() {
        anyhow::bail!("Root path does not exist: {}", root.display());
    }

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

    let mut entries: Vec<SkimEntry> = generated
        .iter()
        .map(entry_from_generated)
        .collect();

    entries.sort_by(|a, b| b.hint_score.partial_cmp(&a.hint_score).unwrap());

    let output_dir = Path::new(&args.output_dir);
    std::fs::create_dir_all(output_dir)?;

    let summary_path = output_dir.join("skimmer_summary.md");
    let json_path = output_dir.join("skimmer_summary.json");

    write_summary_markdown(&summary_path, &entries, args.top, &args.root)?;
    let json = serde_json::to_string_pretty(&entries)?;
    std::fs::write(&json_path, json)?;

    if args.save_configs {
        let config_dir = Path::new(&args.config_dir);
        std::fs::create_dir_all(config_dir)?;
        for gen in &generated {
            let _ = gen.save(config_dir)?;
        }
    }

    println!(
        "Skimmer complete. Summary: {} (top {} shown)",
        summary_path.display(),
        args.top
    );

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
    root: &str,
) -> anyhow::Result<()> {
    let mut out = String::new();
    out.push_str("# zk0d Skimmer Summary (Hints Only)\n\n");
    out.push_str("**WARNING:** This is a hint-only scan. No findings are confirmed.\n\n");
    out.push_str(&format!("Root: `{}`\n\n", root));

    let display = entries.iter().take(top);
    for (i, entry) in display.enumerate() {
        out.push_str(&format!(
            "## {}. {} (score {:.2})\n",
            i + 1,
            entry.circuit_name,
            entry.hint_score
        ));
        out.push_str(&format!("Path: `{}`\n\n", entry.circuit_path));
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
        out.push_str("\n");
    }

    std::fs::write(path, out)?;
    Ok(())
}
