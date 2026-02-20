# Roadmap Target Tests Follow-Up (v2)

Generated (UTC): 2026-02-20T01:28:14Z

## Scope
- Focused rerun subset: targets that showed at least one 'completed' or 'critical_findings_detected' in first pass
- Runner: scripts/run_breadth_step.sh
- Output root: artifacts/roadmap_step_tests_followup_v2
- Settings: workers=2, iterations=250, timeout=12

## Selected Steps
002 003 004 006 007 008 009 010 011 012 013 018 019 020 023 025 028 030 031 033 034 038 039 043 044 045 046 047 053 055 056 057 058 059 060 062 063 

## Counts
- Observation files: 37
- Summary TSV files: 37
- Status distribution:
```text
     37 FAIL
```
- Aggregate reason codes:
  - completed=72
  - critical_findings_detected=21
  - run_outcome_missing=906

## Per-Step Outcomes
| Step | Target | Exit | Reasons |
|---|---|---:|---|
| 002 | cat8_libs_snarkjs_test_plonk_circuit_circuit | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 003 | cat8_libs_snarkjs_test_groth16_circuit | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 004 | cat8_libs_snarkjs_test_fflonk_circuit | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 006 | cat8_libs_snarkjs_test_circuit2_circuit | 1 | completed=1, run_outcome_missing=26 |
| 007 | cat8_libs_snarkjs_test_circuit_circuit | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 008 | cat5_frameworks_snarkjs_test_plonk_circuit_circuit | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 009 | cat5_frameworks_snarkjs_test_groth16_circuit | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 010 | cat5_frameworks_snarkjs_test_fflonk_circuit | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 011 | cat5_frameworks_snarkjs_test_circuit2_circuit | 1 | completed=1, run_outcome_missing=26 |
| 012 | cat5_frameworks_snarkjs_test_circuit_circuit | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 013 | cat3_privacy_circuits_test_circuits_utils_utils_verifyExpirationTime | 1 | critical_findings_detected=2, run_outcome_missing=25 |
| 018 | cat3_privacy_circuits_test_circuits_utils_utils_verifyClaimSignature | 1 | critical_findings_detected=2, run_outcome_missing=25 |
| 019 | cat3_privacy_circuits_test_circuits_utils_utils_isUpdatable | 1 | completed=1, run_outcome_missing=26 |
| 020 | cat3_privacy_circuits_test_circuits_utils_utils_isExpirable | 1 | completed=1, run_outcome_missing=26 |
| 023 | cat3_privacy_circuits_test_circuits_utils_utils_getSubjectLocation | 1 | completed=1, run_outcome_missing=26 |
| 025 | cat3_privacy_circuits_test_circuits_utils_utils_getClaimSubjectOtherIden | 1 | completed=3, run_outcome_missing=24 |
| 028 | cat3_privacy_circuits_test_circuits_utils_utils_getClaimExpiration | 1 | completed=1, run_outcome_missing=26 |
| 030 | cat3_privacy_circuits_test_circuits_utils_utils_checkIdenStateMatchesRoots | 1 | critical_findings_detected=2, run_outcome_missing=25 |
| 031 | cat3_privacy_circuits_test_circuits_eq | 1 | critical_findings_detected=2, run_outcome_missing=25 |
| 033 | cat3_privacy_circuits_test_circuits_eddsaposeidon | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 034 | cat3_privacy_circuits_test_circuits_utils_claimUtils_getClaimMerklizeRoot | 1 | completed=2, run_outcome_missing=25 |
| 038 | cat3_privacy_circuits_test_circuits_authV3Test | 1 | completed=2, run_outcome_missing=25 |
| 039 | cat3_privacy_circuits_test_circuits_stateTransitionTest | 1 | completed=1, run_outcome_missing=26 |
| 043 | cat3_privacy_circuits_circuits_stateTransitionV3 | 1 | completed=1, run_outcome_missing=26 |
| 044 | cat3_privacy_circuits_test_circuits_poseidon16 | 1 | completed=2, run_outcome_missing=25 |
| 045 | cat3_privacy_circuits_test_circuits_poseidon14 | 1 | completed=2, run_outcome_missing=25 |
| 046 | cat3_privacy_circuits_test_circuits_poseidon | 1 | critical_findings_detected=2, run_outcome_missing=25 |
| 047 | cat3_privacy_circuits_test_circuits_lessthan | 1 | critical_findings_detected=2, run_outcome_missing=25 |
| 053 | cat3_privacy_circuits_circuits_credentialAtomicQueryV3Universal | 1 | completed=6, run_outcome_missing=21 |
| 055 | cat3_privacy_circuits_circuits_credentialAtomicQueryV3OnChain | 1 | completed=7, run_outcome_missing=20 |
| 056 | cat3_privacy_circuits_circuits_credentialAtomicQueryV3OnChain_16_16_64_16_32 | 1 | completed=7, run_outcome_missing=20 |
| 057 | cat3_privacy_circuits_circuits_credentialAtomicQueryV3 | 1 | completed=5, run_outcome_missing=22 |
| 058 | cat3_privacy_circuits_circuits_credentialAtomicQueryV3_16_16_64 | 1 | completed=5, run_outcome_missing=22 |
| 059 | cat3_privacy_circuits_circuits_authV3 | 1 | completed=5, run_outcome_missing=22 |
| 060 | cat3_privacy_circuits_circuits_authV3_8_32 | 1 | completed=5, run_outcome_missing=22 |
| 062 | cat3_privacy_email_wallet_packages_circuits_src_claim | 1 | completed=6, run_outcome_missing=21 |
| 063 | cat3_privacy_email_wallet_packages_circuits_src_announcement | 1 | completed=7, run_outcome_missing=20 |
