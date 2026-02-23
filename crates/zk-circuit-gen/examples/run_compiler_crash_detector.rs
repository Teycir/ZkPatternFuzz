use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zk_circuit_gen::{
    evaluate_known_compiler_bug_regressions, run_compiler_crash_detection,
    CompilerBugRegressionReport, CompilerCrashDetectionReport, CompilerProbeCase,
    KnownCompilerBugExpectation,
};

#[derive(Debug, Clone, Deserialize)]
struct ProbeInput {
    cases: Vec<CompilerProbeCase>,
    #[serde(default)]
    expectations: Vec<KnownCompilerBugExpectation>,
}

#[derive(Debug, Clone, Serialize)]
struct DetectorOutput {
    crash_report: CompilerCrashDetectionReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    regression_report: Option<CompilerBugRegressionReport>,
}

#[derive(Debug, Clone)]
struct CliArgs {
    probe_json: PathBuf,
    output_dir: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let payload = fs::read_to_string(&args.probe_json)?;
    let probe: ProbeInput = serde_json::from_str(&payload)?;

    fs::create_dir_all(&args.output_dir)?;
    let repro_dir = args.output_dir.join("repros");
    let crash_report = run_compiler_crash_detection(&probe.cases, &repro_dir)?;
    let regression_report = if probe.expectations.is_empty() {
        None
    } else {
        Some(evaluate_known_compiler_bug_regressions(
            &crash_report,
            &probe.expectations,
        ))
    };

    let output = DetectorOutput {
        crash_report,
        regression_report,
    };
    let output_path = args.output_dir.join("latest_report.json");
    fs::write(&output_path, serde_json::to_string_pretty(&output)? + "\n")?;

    println!(
        "compiler crash detector complete: cases={} failures={} bug_reports={} report={}",
        output.crash_report.total_cases,
        output.crash_report.failed + output.crash_report.timed_out,
        output.crash_report.bug_reports.len(),
        output_path.display()
    );
    Ok(())
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut probe_json = None;
    let mut output_dir = PathBuf::from("artifacts/circuit_gen/crash_detection_latest");

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--probe-json" => {
                probe_json = Some(PathBuf::from(next_value(&mut args, "--probe-json")?))
            }
            "--output-dir" => output_dir = PathBuf::from(next_value(&mut args, "--output-dir")?),
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }

    Ok(CliArgs {
        probe_json: probe_json.ok_or("--probe-json is required")?,
        output_dir,
    })
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn print_help() {
    println!(
        "\
run_compiler_crash_detector

Run timeout/crash/ICE/user-error classification and bug-report generation.

Usage:
  cargo run -q -p zk-circuit-gen --example run_compiler_crash_detector -- [options]

Options:
  --probe-json <path>     Required probe case JSON
  --output-dir <path>     Output directory (default: artifacts/circuit_gen/crash_detection_latest)
"
    );
}
