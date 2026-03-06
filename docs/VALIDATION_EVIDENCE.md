# Validation Evidence

This document publishes one concrete validation case from the archived evidence store so readers can inspect a real end-to-end proof path instead of only benchmark totals.

## Case Study: EXT-003 `test_vuln_iszero.circom`

### Target Freeze

- Target ID: `EXT-003`
- Frozen clean-checkout commit: `072bf1fbbd1c9ecad58d4f6d2204c3b96e7fec17`
- Entrypoint: `tests/sample/test_vuln_iszero.circom`
- Component: `VulnerableIsZero`
- Canonical proof-status index: `artifacts/external_targets/ext_batch_001/reports/evidence/PROOF_STATUS.md`

### Proof Goal

Show that the `IsZero`-style circuit is exploitable, not merely suspicious, by replaying two witnesses on the same non-zero input:

- honest witness: produces the intended output `0`
- malicious witness: still satisfies all constraints but produces `1`

### Deterministic Replay

Canonical clean-checkout replay command:

```bash
python3 artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/replay_ext003_iszero_exploit.py \
  --repo /tmp/ext003_clean_20260224_231039 \
  --entrypoint tests/sample/test_vuln_iszero.circom \
  --component VulnerableIsZero \
  --input 5 \
  --expected-sha 072bf1fbbd1c9ecad58d4f6d2204c3b96e7fec17
```

Replay artifacts:

- command file: `artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/replay_command.txt`
- exploit notes: `artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/exploit_notes.md`
- replay log: `artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/replay_ext003_iszero_exploit.log`
- impact summary: `artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/impact.md`

### Witness Payload

Input:

- `in = 5`

Honest witness:

- `inv = 8755297148735710088898562298102910035419345760166413737479281674630323398247`
- `out = 0`

Malicious witness:

- `inv = 0`
- `out = 1`

### Expected Vs Observed

- Expected behavior: for `in != 0`, `isZero(in)` must evaluate to `0`
- Observed behavior: both witnesses satisfy the circuit constraints, but the malicious witness returns `1`

The clean-checkout replay log records the proof outcome explicitly:

```text
Both witnesses satisfy constraints; malicious witness violates intended behavior.
```

### Picus Cross-Check

The repository also contains a Picus verification follow-up for the same target family:

- log: `artifacts/external_targets/ext_batch_001/logs/step4_verify_ext003_after_picus_classification_fix_escalated.log`
- observed result: `UNKNOWN`
- interpretation: Picus did not disprove the bug, but it also did not provide a formal `UNSAFE` counterexample in the recorded run

This means the exploitability claim rests on the deterministic replay artifact, not on a formal Picus proof.

### Outcome

- classification: `exploitable`
- evidence status: deterministic replay succeeded on a clean checkout
- proof-status record: `artifacts/external_targets/ext_batch_001/reports/evidence/PROOF_STATUS.md`

### Why This Matters

This is the standard of evidence the repository should keep publishing:

- frozen target identity
- one-command replay
- explicit witness payload
- expected versus observed mismatch
- formal cross-check result when available
- final exploitability conclusion
