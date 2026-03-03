use clap::{Parser, Subcommand};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(name = "zkf_checks")]
#[command(about = "Integrated Rust repository checks (panic surface, hygiene, prod/test separation)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Check production panic-surface calls against an allowlist
    PanicSurface {
        #[arg(long, default_value = ".")]
        repo_root: String,
        #[arg(long, default_value = "config/panic_surface_allowlist.txt")]
        allowlist: String,
        #[arg(long, default_value = "src,crates")]
        search_roots: String,
        #[arg(long, default_value_t = false)]
        write_allowlist: bool,
        #[arg(long, default_value_t = false)]
        fail_on_stale: bool,
    },
    /// Check repository root for blocked placeholder files
    RepoHygiene {
        #[arg(long, default_value = ".")]
        repo_root: String,
        #[arg(long)]
        blocklist: Option<String>,
        #[arg(long)]
        json_out: Option<String>,
    },
    /// Check production Rust tree for prod/test separation violations
    ProdTestSeparation {
        #[arg(long, default_value = ".")]
        repo_root: String,
        #[arg(long, default_value = "src,crates")]
        search_roots: String,
        #[arg(long, default_value = "config/prod_test_separation_baseline.json")]
        baseline: String,
        #[arg(long, default_value_t = false)]
        write_baseline: bool,
        #[arg(long, default_value_t = false)]
        strict: bool,
        #[arg(long)]
        json_out: Option<String>,
    },
}

fn parse_roots(csv: &str) -> Vec<String> {
    csv.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn absolute_from_root(repo_root: &Path, input: &str) -> PathBuf {
    let path = PathBuf::from(input);
    if path.is_absolute() {
        path
    } else {
        repo_root.join(path)
    }
}

fn cmd_panic_surface(
    repo_root: &Path,
    allowlist: &Path,
    search_roots: &[String],
    write_allowlist: bool,
    fail_on_stale: bool,
) -> anyhow::Result<i32> {
    let matches = zk_fuzzer::checks::panic_surface::collect_panic_matches(repo_root, search_roots)?;
    let current_keys: BTreeSet<String> = matches.iter().map(|m| m.key()).collect();

    if write_allowlist {
        zk_fuzzer::checks::panic_surface::write_allowlist(allowlist, &current_keys)?;
        println!(
            "panic-surface allowlist written: {} (entries={})",
            allowlist.display(),
            current_keys.len()
        );
        return Ok(0);
    }

    let allowed = zk_fuzzer::checks::panic_surface::load_allowlist(allowlist)?;
    let report = zk_fuzzer::checks::panic_surface::build_report(&current_keys, &allowed);

    println!(
        "panic-surface check: matches={} allowlist={} unknown={} stale={}",
        report.matches, report.allowlist, report.unknown, report.stale
    );

    if !report.unknown_entries.is_empty() {
        println!("\nNew panic-surface entries not in allowlist:");
        for entry in &report.unknown_entries {
            println!("  {}", entry);
        }
        println!("\nUpdate allowlist intentionally via:");
        println!("  cargo run --bin zkf_checks -- panic-surface --write-allowlist");
        return Ok(1);
    }

    if fail_on_stale && !report.stale_entries.is_empty() {
        println!("\nStale allowlist entries (no longer present):");
        for entry in &report.stale_entries {
            println!("  {}", entry);
        }
        return Ok(1);
    }

    Ok(0)
}

fn cmd_repo_hygiene(
    repo_root: &Path,
    blocklist: Option<&Path>,
    json_out: Option<&Path>,
) -> anyhow::Result<i32> {
    let mut extra_blocked = BTreeSet::new();
    if let Some(path) = blocklist {
        extra_blocked = zk_fuzzer::checks::repo_hygiene::parse_blocklist_file(path)?;
    }

    let report = zk_fuzzer::checks::repo_hygiene::build_report(
        repo_root,
        zk_fuzzer::checks::repo_hygiene::DEFAULT_BLOCKED_ROOT_FILES,
        &extra_blocked,
    );

    if let Some(out_path) = json_out {
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(out_path, format!("{json}\n"))?;
    }

    if !report.matches.is_empty() {
        println!("Repo hygiene check failed: blocked root files detected.");
        for name in &report.matches {
            println!("  - {}", name);
        }
        return Ok(1);
    }
    println!("Repo hygiene check passed: no blocked root placeholder files found.");
    Ok(0)
}

fn cmd_prod_test_separation(
    repo_root: &Path,
    search_roots: &[String],
    baseline: &Path,
    write_baseline: bool,
    strict: bool,
    json_out: Option<&Path>,
) -> anyhow::Result<i32> {
    let violations =
        zk_fuzzer::checks::prod_test_separation::collect_violations(repo_root, search_roots)?;

    if write_baseline {
        zk_fuzzer::checks::prod_test_separation::write_baseline(baseline, &violations)?;
        let unique = zk_fuzzer::checks::prod_test_separation::unique_signatures(&violations);
        println!(
            "Wrote prod/test separation baseline: {} ({} signatures, {} total violations)",
            baseline.display(),
            unique.len(),
            violations.len()
        );
        return Ok(0);
    }

    let baseline_counts = if strict {
        Default::default()
    } else {
        zk_fuzzer::checks::prod_test_separation::load_baseline(baseline)?
    };
    let new_violations = if strict {
        violations.clone()
    } else {
        zk_fuzzer::checks::prod_test_separation::filter_new_violations(&violations, &baseline_counts)
    };

    let report = zk_fuzzer::checks::prod_test_separation::ProdTestSeparationReport {
        repo_root: repo_root.display().to_string(),
        search_roots: search_roots.to_vec(),
        baseline_path: baseline.display().to_string(),
        strict,
        violation_count: violations.len(),
        legacy_violation_count: violations.len().saturating_sub(new_violations.len()),
        new_violation_count: new_violations.len(),
        baseline_signature_count: baseline_counts.len(),
        violations: violations.clone(),
        new_violations: new_violations.clone(),
        pass: new_violations.is_empty(),
    };

    if let Some(out_path) = json_out {
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(out_path, format!("{json}\n"))?;
    }

    if violations.is_empty() {
        println!("Production/test separation check passed: no violations found.");
        return Ok(0);
    }

    if strict {
        println!("Production/test separation check failed (strict mode):");
        for violation in &violations {
            println!(
                "  - {}:{}: {}: {}",
                violation.path,
                violation.line,
                violation.kind,
                violation.code.trim()
            );
        }
        return Ok(1);
    }

    if !baseline.exists() {
        println!("Production/test separation check failed: baseline not found and violations exist.");
        println!(
            "Generate baseline with: cargo run --bin zkf_checks -- prod-test-separation --write-baseline"
        );
        return Ok(1);
    }

    if new_violations.is_empty() {
        println!(
            "Production/test separation check passed: no new violations (legacy baseline signatures matched: {}).",
            baseline_counts.len()
        );
        return Ok(0);
    }

    println!("Production/test separation check failed: new violations detected.");
    for violation in &new_violations {
        println!(
            "  - {}:{}: {}: {}",
            violation.path,
            violation.line,
            violation.kind,
            violation.code.trim()
        );
    }
    Ok(1)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::PanicSurface {
            repo_root,
            allowlist,
            search_roots,
            write_allowlist,
            fail_on_stale,
        } => {
            let root = PathBuf::from(repo_root).canonicalize().unwrap_or_else(|_| PathBuf::from("."));
            let allowlist_path = absolute_from_root(&root, &allowlist);
            let roots = parse_roots(&search_roots);
            cmd_panic_surface(&root, &allowlist_path, &roots, write_allowlist, fail_on_stale)?
        }
        Commands::RepoHygiene {
            repo_root,
            blocklist,
            json_out,
        } => {
            let root = PathBuf::from(repo_root).canonicalize().unwrap_or_else(|_| PathBuf::from("."));
            let blocklist_path = blocklist
                .as_deref()
                .map(|value| absolute_from_root(&root, value));
            let json_out_path = json_out
                .as_deref()
                .map(|value| absolute_from_root(&root, value));
            cmd_repo_hygiene(&root, blocklist_path.as_deref(), json_out_path.as_deref())?
        }
        Commands::ProdTestSeparation {
            repo_root,
            search_roots,
            baseline,
            write_baseline,
            strict,
            json_out,
        } => {
            let root = PathBuf::from(repo_root).canonicalize().unwrap_or_else(|_| PathBuf::from("."));
            let roots = parse_roots(&search_roots);
            let baseline_path = absolute_from_root(&root, &baseline);
            let json_out_path = json_out
                .as_deref()
                .map(|value| absolute_from_root(&root, value));
            cmd_prod_test_separation(
                &root,
                &roots,
                &baseline_path,
                write_baseline,
                strict,
                json_out_path.as_deref(),
            )?
        }
    };

    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
