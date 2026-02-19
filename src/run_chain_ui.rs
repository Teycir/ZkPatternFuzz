use colored::*;
use zk_fuzzer::chain_fuzzer::metrics::DepthMetricsSummary;
use zk_fuzzer::chain_fuzzer::ChainFinding;
use zk_fuzzer::chain_fuzzer::ChainSpec;

use crate::truncate_str;

pub(crate) fn print_chain_mode_banner(
    campaign_name: &str,
    chain_count: usize,
    timeout_seconds: u64,
    resume: bool,
) {
    println!();
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".bright_magenta()
    );
    println!(
        "{}",
        "║         ZK-FUZZER v0.1.0 — MODE 3: CHAIN FUZZING          ║".bright_magenta()
    );
    println!(
        "{}",
        "║               Multi-Step Deep Bug Discovery               ║".bright_magenta()
    );
    println!(
        "{}",
        "╠═══════════════════════════════════════════════════════════╣".bright_magenta()
    );
    println!(
        "{}  Campaign: {:<45} {}",
        "║".bright_magenta(),
        truncate_str(campaign_name, 45).white(),
        "║".bright_magenta()
    );
    println!(
        "{}  Chains:   {:<45} {}",
        "║".bright_magenta(),
        format!("{} defined", chain_count).cyan(),
        "║".bright_magenta()
    );
    println!(
        "{}  Budget:   {:<45} {}",
        "║".bright_magenta(),
        format!("{}s total", timeout_seconds).yellow(),
        "║".bright_magenta()
    );
    println!(
        "{}  Resume:   {:<45} {}",
        "║".bright_magenta(),
        if resume { "yes".green() } else { "no".white() },
        "║".bright_magenta()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝".bright_magenta()
    );
    println!();
}

pub(crate) fn print_chains_to_fuzz(chains: &[ChainSpec]) {
    println!("{}", "CHAINS TO FUZZ:".bright_yellow().bold());
    for chain in chains {
        println!(
            "  {} {} ({} steps, {} assertions)",
            "→".bright_cyan(),
            chain.name.white(),
            chain.steps.len(),
            chain.assertions.len()
        );
    }
    println!();
}

pub(crate) struct ChainResultsUiContext<'a> {
    pub summary: &'a DepthMetricsSummary,
    pub final_total_entries: usize,
    pub baseline_total_entries: usize,
    pub final_unique_coverage_bits: usize,
    pub baseline_unique_coverage_bits: usize,
    pub final_max_depth: usize,
    pub chain_findings: &'a [ChainFinding],
    pub run_valid: bool,
    pub quality_failures: &'a [String],
    pub config_path: &'a str,
    pub seed: Option<u64>,
}

pub(crate) fn print_chain_results(ctx: &ChainResultsUiContext<'_>) {
    println!();
    println!("{}", "═".repeat(60).bright_magenta());
    println!("{}", "  CHAIN FUZZING RESULTS".bright_white().bold());
    println!("{}", "═".repeat(60).bright_magenta());

    println!("\n{}", "DEPTH METRICS".bright_yellow().bold());
    println!("  Total Chain Findings:  {}", ctx.summary.total_findings);
    println!("  Mean L_min (D):        {:.2}", ctx.summary.d_mean);
    println!("  P(L_min >= 2):         {:.1}%", ctx.summary.p_deep * 100.0);
    println!();
    println!("{}", "CORPUS / EXPLORATION METRICS".bright_yellow().bold());
    println!(
        "  Corpus entries:            {} (Δ {})",
        ctx.final_total_entries,
        ctx.final_total_entries
            .saturating_sub(ctx.baseline_total_entries)
    );
    println!(
        "  Unique coverage bits:      {} (Δ {})",
        ctx.final_unique_coverage_bits,
        ctx.final_unique_coverage_bits
            .saturating_sub(ctx.baseline_unique_coverage_bits)
    );
    println!("  Max depth reached:         {}", ctx.final_max_depth);

    if !ctx.summary.depth_distribution.is_empty() {
        println!("\n{}", "DEPTH DISTRIBUTION".bright_yellow().bold());
        let mut depths: Vec<_> = ctx.summary.depth_distribution.iter().collect();
        depths.sort_by_key(|(k, _)| *k);
        for (depth, count) in depths {
            let bar = "█".repeat((*count).min(30));
            println!("  L_min={}: {} ({})", depth, bar.bright_cyan(), count);
        }
    }

    if !ctx.chain_findings.is_empty() {
        println!("\n{}", "CHAIN FINDINGS".bright_yellow().bold());
        for (i, finding) in ctx.chain_findings.iter().enumerate() {
            let severity_str = match finding.finding.severity.to_uppercase().as_str() {
                "CRITICAL" => format!("[{}]", finding.finding.severity)
                    .bright_red()
                    .bold(),
                "HIGH" => format!("[{}]", finding.finding.severity).red(),
                "MEDIUM" => format!("[{}]", finding.finding.severity).yellow(),
                "LOW" => format!("[{}]", finding.finding.severity).bright_yellow(),
                _ => format!("[{}]", finding.finding.severity).white(),
            };

            println!(
                "\n  {}. {} Chain: {} (L_min: {})",
                i + 1,
                severity_str,
                finding.spec_name.cyan(),
                finding.l_min.to_string().bright_green()
            );
            println!("     {}", finding.finding.description);

            if let Some(ref assertion) = finding.violated_assertion {
                println!("     Violated: {}", assertion.bright_red());
            }

            println!("     {}", "Reproduction:".bright_yellow());
            println!(
                "       cargo run --release -- chains {} --seed {}",
                ctx.config_path,
                ctx.seed.unwrap_or(42)
            );
        }
    } else if ctx.run_valid {
        println!(
            "\n{}",
            "  ✓ No chain vulnerabilities found!".bright_green().bold()
        );
    } else {
        println!(
            "\n{}",
            "  ✗ Run invalid: exploration too narrow to treat as 'clean'"
                .bright_red()
                .bold()
        );
        for failure in ctx.quality_failures {
            println!("     - {}", failure);
        }
    }

    println!("\n{}", "═".repeat(60).bright_magenta());
}
