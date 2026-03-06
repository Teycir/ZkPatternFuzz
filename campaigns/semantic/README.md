# Semantic Campaigns

This directory is the checked-in entrypoint for the semantic-analysis lane. Unlike the YAML attack catalogs under `campaigns/benchmark/` and `campaigns/cve/`, these runs are powered by `zk-track-semantic` and emit semantic-intent, exploitability, and actionable-report artifacts rather than scan-template findings.

## Current Supported Campaign

- wrapper: `scripts/run_semantic_exit_sample.sh`
- runner: `cargo run -p zk-track-semantic --example semantic_exit_campaign -- ...`
- checked-in execution evidence: `campaigns/semantic/semantic_exit_sample.execution_evidence.json`
- output root: `artifacts/semantic_campaign/post_roadmap/semantic/semantic-exit-sample/`
- aggregate report: `artifacts/semantic_exit/latest_report.json`

## Why This Exists

This is the bridge between the repo's semantic track and the rest of the operator workflow:

- the campaign payload is versioned
- the wrapper command is reproducible
- the emitted reports can be reviewed, labeled, and enforced

That makes the semantic lane a real executable workflow in the repository, not just a crate example.
