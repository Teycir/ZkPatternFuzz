use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use zk_postroadmap_core::{TrackInput, TrackRunner};
use zk_track_semantic::SemanticTrackRunner;

const DEFAULT_OUTPUT_DIR: &str = "artifacts/semantic_campaign";
const DEFAULT_RUN_ID: &str = "semantic-exit-sample";
const DEFAULT_CAMPAIGN_ID: &str = "semantic-exit-campaign";
const DEFAULT_SEMANTIC_ROOTS: &str = "tests,docs,targets/zkbugs/dataset/halo2";
const DEFAULT_ADAPTER: &str = "heuristic_augmented";
const DEFAULT_GUIDANCE_LABEL: &str = "mistral";
const DEFAULT_SYSTEM_PROMPT: &str =
    "strict formal extraction for semantic security intent from docs/comments";
const DEFAULT_EXECUTION_EVIDENCE_JSON: &str = r#"{
  "cases": [
    {
      "id": "semantic-case-1",
      "accepted": true,
      "violates_intent": true,
      "summary": "non-admin withdrawal accepted after bypassing authorization checks"
    },
    {
      "id": "semantic-case-2",
      "accepted": true,
      "violates_intent": true,
      "summary": "forged proof accepted despite verifier requirement to reject invalid proofs"
    },
    {
      "id": "semantic-case-3",
      "accepted": true,
      "violates_intent": true,
      "summary": "replay proof accepted without nullifier uniqueness enforcement"
    }
  ]
}"#;

#[derive(Debug, Clone)]
struct CliArgs {
    output_dir: PathBuf,
    run_id: String,
    campaign_id: String,
    semantic_roots: String,
    adapter: String,
    guidance_label: String,
    system_prompt: String,
    execution_evidence_json: String,
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut output_dir = PathBuf::from(DEFAULT_OUTPUT_DIR);
    let mut run_id = DEFAULT_RUN_ID.to_string();
    let mut campaign_id = DEFAULT_CAMPAIGN_ID.to_string();
    let mut semantic_roots = DEFAULT_SEMANTIC_ROOTS.to_string();
    let mut adapter = DEFAULT_ADAPTER.to_string();
    let mut guidance_label = DEFAULT_GUIDANCE_LABEL.to_string();
    let mut system_prompt = DEFAULT_SYSTEM_PROMPT.to_string();
    let mut execution_evidence_json = DEFAULT_EXECUTION_EVIDENCE_JSON.to_string();

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output-dir" => {
                output_dir = PathBuf::from(next_value(&mut args, "--output-dir")?);
            }
            "--run-id" => {
                run_id = next_value(&mut args, "--run-id")?;
            }
            "--campaign-id" => {
                campaign_id = next_value(&mut args, "--campaign-id")?;
            }
            "--semantic-roots" => {
                semantic_roots = next_value(&mut args, "--semantic-roots")?;
            }
            "--adapter" => {
                adapter = next_value(&mut args, "--adapter")?;
            }
            "--guidance-label" | "--model-name" => {
                guidance_label = next_value(&mut args, "--guidance-label/--model-name")?;
            }
            "--system-prompt" => {
                system_prompt = next_value(&mut args, "--system-prompt")?;
            }
            "--execution-evidence-json" => {
                execution_evidence_json = next_value(&mut args, "--execution-evidence-json")?;
            }
            "--execution-evidence-path" => {
                let path = PathBuf::from(next_value(&mut args, "--execution-evidence-path")?);
                execution_evidence_json = fs::read_to_string(&path).map_err(|error| {
                    format!(
                        "failed to read execution evidence payload `{}`: {error}",
                        path.display()
                    )
                })?;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            unknown => {
                return Err(format!("unknown argument: {unknown}").into());
            }
        }
    }

    Ok(CliArgs {
        output_dir,
        run_id,
        campaign_id,
        semantic_roots,
        adapter,
        guidance_label,
        system_prompt,
        execution_evidence_json,
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
semantic_exit_campaign

Runs the semantic track against real repo docs/circuits and emits semantic artifacts.

Usage:
  cargo run -p zk-track-semantic --example semantic_exit_campaign -- [options]

Options:
  --output-dir <path>               Output root (default: {DEFAULT_OUTPUT_DIR})
  --run-id <id>                     Run ID (default: {DEFAULT_RUN_ID})
  --campaign-id <id>                Campaign ID (default: {DEFAULT_CAMPAIGN_ID})
  --semantic-roots <csv>            Comma-separated scan roots (default: {DEFAULT_SEMANTIC_ROOTS})
  --adapter <name>                  semantic adapter mode (default: {DEFAULT_ADAPTER})
  --guidance-label <name>           heuristic guidance label (legacy alias: --model-name)
  --system-prompt <text>            system prompt metadata
  --execution-evidence-json <json>  inline execution evidence payload
  --execution-evidence-path <path>  execution evidence payload file
"
    );
}

fn find_report_path(paths: &[PathBuf], file_name: &str) -> Option<PathBuf> {
    paths
        .iter()
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name == file_name)
                .unwrap_or(false)
        })
        .cloned()
}

fn parse_report_counts(report_path: &Path) -> Result<(usize, usize), Box<dyn Error>> {
    let report_text = fs::read_to_string(report_path)?;
    let report_json: serde_json::Value = serde_json::from_str(&report_text)?;
    let intents = report_json["extracted_intent_sources"]
        .as_u64()
        .unwrap_or(0) as usize;
    let violations = report_json["findings_count"].as_u64().unwrap_or(0) as usize;
    Ok((intents, violations))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let output_dir = args.output_dir.canonicalize().unwrap_or(args.output_dir);
    fs::create_dir_all(&output_dir)?;

    let metadata = BTreeMap::from([
        ("semantic_roots".to_string(), args.semantic_roots.clone()),
        ("semantic_adapter".to_string(), args.adapter.clone()),
        (
            "semantic_guidance_label".to_string(),
            args.guidance_label.clone(),
        ),
        (
            "semantic_system_prompt".to_string(),
            args.system_prompt.clone(),
        ),
        (
            "semantic_execution_evidence_json".to_string(),
            args.execution_evidence_json.clone(),
        ),
    ]);
    let input = TrackInput {
        campaign_id: args.campaign_id.clone(),
        run_id: args.run_id.clone(),
        seed: Some(42),
        corpus_dir: output_dir.join("corpus"),
        evidence_dir: output_dir.join("evidence"),
        output_dir: output_dir.clone(),
        metadata,
    };

    let runner = SemanticTrackRunner::new();
    runner.prepare(&input).await?;
    let execution = runner.run(&input).await?;
    runner.validate(&execution).await?;
    let emitted_paths = runner.emit(&execution).await?;

    let report_path = find_report_path(&emitted_paths, "semantic_track_report.json")
        .ok_or("semantic_track_report.json missing from emitted paths")?;
    let (intent_sources, findings_count) = parse_report_counts(&report_path)?;

    println!(
        "semantic campaign complete: run_id={} output_dir={} intents={} findings={} report={}",
        args.run_id,
        output_dir.display(),
        intent_sources,
        findings_count,
        report_path.display(),
    );
    Ok(())
}
