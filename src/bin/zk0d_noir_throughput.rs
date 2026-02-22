use anyhow::{Context, Result};
use clap::Parser;
use std::cmp::Ordering;
use std::path::PathBuf;
use std::time::Instant;
use zk_fuzzer::executor::{CircuitExecutor, NoirExecutor};
use zk_fuzzer::fuzzer::FieldElement;
use zk_fuzzer::targets::NoirTarget;

#[derive(Parser, Debug)]
#[command(
    name = "zk0d_noir_throughput",
    about = "Measure repeated-run Noir executor throughput and cache warmup impact"
)]
struct Cli {
    /// Path to a Noir project
    #[arg(long, default_value = "tests/noir_projects/multiplier")]
    project: String,
    /// Number of execute_sync runs (must be >= 2 for warm/cold comparison)
    #[arg(long, default_value_t = 20)]
    runs: usize,
    /// Required cold/warm median speedup ratio threshold
    #[arg(long, default_value_t = 1.05)]
    min_improvement_ratio: f64,
    /// Optional path for JSON output
    #[arg(long)]
    json_out: Option<String>,
}

fn median(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[mid - 1] + values[mid]) / 2
    } else {
        values[mid]
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.runs < 2 {
        anyhow::bail!("--runs must be >= 2 to compare cold vs warm executions");
    }

    NoirTarget::check_nargo_available()
        .context("Noir tooling unavailable; install nargo before throughput measurement")?;

    let project_path = PathBuf::from(&cli.project);
    let executor = NoirExecutor::new(
        project_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("project path contains non-UTF8 bytes"))?,
    )
    .with_context(|| format!("Failed to initialize NoirExecutor at '{}'", cli.project))?;

    let inputs = vec![FieldElement::from_u64(3), FieldElement::from_u64(5)];
    let mut samples_us = Vec::with_capacity(cli.runs);
    for _ in 0..cli.runs {
        let start = Instant::now();
        let result = executor.execute_sync(&inputs);
        let elapsed = start.elapsed().as_micros() as u64;
        if !result.success {
            let err = result
                .error
                .unwrap_or_else(|| "unknown noir execution failure".to_string());
            anyhow::bail!("Noir execution failed during throughput run: {err}");
        }
        samples_us.push(elapsed);
    }

    let first_us = samples_us[0];
    let mut warm_samples = samples_us[1..].to_vec();
    let warm_median_us = median(&mut warm_samples);
    let warm_mean_us = warm_samples.iter().sum::<u64>() as f64 / warm_samples.len() as f64;

    let improvement_ratio = if warm_median_us == 0 {
        match first_us.cmp(&0) {
            Ordering::Equal => 1.0,
            _ => f64::INFINITY,
        }
    } else {
        first_us as f64 / warm_median_us as f64
    };
    let passes = improvement_ratio >= cli.min_improvement_ratio;

    let payload = serde_json::json!({
        "generated_utc": chrono::Utc::now().to_rfc3339(),
        "project": cli.project,
        "runs": cli.runs,
        "samples_us": samples_us,
        "cold_first_us": first_us,
        "warm_median_us": warm_median_us,
        "warm_mean_us": warm_mean_us,
        "improvement_ratio": improvement_ratio,
        "min_improvement_ratio": cli.min_improvement_ratio,
        "passes": passes
    });

    println!(
        "Noir throughput: cold_first_us={} warm_median_us={} ratio={:.3} (threshold {:.3}) passes={}",
        first_us, warm_median_us, improvement_ratio, cli.min_improvement_ratio, passes
    );

    if let Some(path) = &cli.json_out {
        let out = PathBuf::from(path);
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create parent directory for '{}'", out.display())
            })?;
        }
        std::fs::write(&out, serde_json::to_string_pretty(&payload)?)
            .with_context(|| format!("Failed to write '{}'", out.display()))?;
        println!("Report: {}", out.display());
    }

    if !passes {
        anyhow::bail!(
            "Noir throughput improvement ratio {:.3} below threshold {:.3}",
            improvement_ratio,
            cli.min_improvement_ratio
        );
    }

    Ok(())
}
