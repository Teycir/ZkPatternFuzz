# Campaign Output Standardization

This document defines the standardized `run_outcome` envelope emitted by campaign runs.

## Goal

Make each campaign artifact analysis-ready with:

- stable machine fields (`reason_code`, `status_family`, `terminal`)
- discovery qualification (`discovery_state`, `proof_status`, `analysis_priority`)
- explicit next action for proof/root-cause workflow

## Canonical Fields

All emitted run artifacts (`run_outcome.json`, engagement `events.jsonl`, mode `events.jsonl`,
`summary.json`, `latest.json`) carry:

- `artifact_schema.name`: `zkfuzz.run_outcome`
- `artifact_schema.version`: `1.0.0`
- `reason_code`: normalized run classification
- `status_family`: `running | completed | failed | unknown`
- `terminal`: `true | false`
- `discovery_qualification`:
  - `discovery_state`
  - `proof_status`
  - `analysis_priority`
  - `findings_total`
  - `critical_findings`
  - `next_step`
  - `analysis_inputs` (`run_outcome_json`, `report_json`, `chain_report_json`, `evidence_summary_json`)

## Discovery Qualification States

- `candidate_vulnerability`
  - Meaning: findings observed (or critical status)
  - Proof status: `pending_proof`
  - Next step: deterministic replay + exploit/non-exploit proof
- `no_vulnerability_observed`
  - Meaning: run completed without findings
  - Proof status: `pending_proof` (absence of findings is not proof)
  - Next step: bounded non-exploitability campaign with assumptions/limits
- `run_failed`
  - Meaning: run failed before valid conclusion
  - Proof status: `not_ready`
  - Next step: root-cause failure and rerun
- `engagement_contract_failed`
  - Meaning: strict contract/readiness failed
  - Proof status: `not_ready`
  - Next step: fix contract readiness and rerun strict mode
- `stale_interrupted`
  - Meaning: interrupted before terminal artifact completion
  - Proof status: `not_ready`
  - Next step: diagnose interruption cause (OOM/SIGKILL/external stop) and rerun
- `in_progress`
  - Meaning: run is active
  - Proof status: `not_ready`

## Summary Totals

`summary.json` now includes `totals`:

- `modes_total`
- `running`
- `completed`
- `failed`
- `unknown`
- `pending_proof`
- `candidate_vulnerabilities`
- `critical_modes`

This enables quick external-target state snapshots without custom parsing.
