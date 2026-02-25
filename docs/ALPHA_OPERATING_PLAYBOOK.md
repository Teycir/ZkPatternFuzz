# Alpha Operating Playbook

This playbook turns scan output into proof-bearing security results.

## Why The Tool Feels Low-Signal

Most runs stop at discovery artifacts (`findings`, reason codes, `pending_proof`) and never close the proof branch.
Without deterministic replay or bounded non-exploit evidence, output stays triage-only.

## Alpha Definition

For this repo, "alpha" means:
- high-value targets prioritized,
- candidates quickly converted into replay/falsification attempts,
- each target ends as `exploitable` or `not exploitable within bounds` (not just `pending_proof`).

## Required Adjustments

1. Optimize for proof-closure, not finding-count.
2. Keep discovery runs bounded and deterministic (fixed seed/timeouts).
3. Run a proof branch immediately after each completed target.
4. Record one-command replay for every conclusion.
5. Track blockers by reason code (`backend_toolchain_mismatch`, `selector_mismatch`, etc.).
6. Freeze toolchain paths from local installs before every campaign.

## Operator Workflow

### 1) Freeze environment

```bash
source build/toolchains/installed_tools.env
```

### 2) Run narrow discovery directly (JSON config + YAML pattern)

```bash
cargo run --release --bin zkpatternfuzz -- \
  --config-json targets/external/target_run_overrides/ext015_orion_svm_classifier_test.json \
  --pattern-yaml campaigns/cve/patterns/cveX34_cairo_multiplier_assert_readiness_probe.yaml \
  --target-circuit /media/elements/Repos/zkml/orion/tests/ml/svm_classifier_test.cairo \
  --framework cairo \
  --main-component main \
  --output-root artifacts/external_targets/manual \
  --report-json artifacts/external_targets/manual/latest_findings.json
```

### 3) Convert each completed target into proof artifacts

Create scaffold:

```bash
scripts/scaffold_proof_bundle.sh \
  --target EXT-015 \
  --root artifacts/external_targets/ext_batch_013/reports \
  --mode non_exploit
```

Then fill:
- `replay_command.txt` with exact deterministic command,
- `exploit_notes.md` **or** `no_exploit_proof.md`,
- `impact.md`,
- replay log file referenced by notes.

## Minimal Proof KPIs

- `proof_closure_rate = closed_targets / completed_targets`
- `pending_proof_backlog = targets still lacking exploit/non-exploit pack`
- `tooling_blocker_rate = backend/toolchain blocker targets / total targets`

Use these KPIs to decide if the run produced alpha.
