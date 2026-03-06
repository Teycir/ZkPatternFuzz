# ZkPatternFuzz Documentation Index

This index focuses on the maintained operator-facing docs. Some top-level files such as `ARCHITECTURE.md` and `ROADMAP.md` contain dated snapshots; use them as historical context, not as the primary command reference.

## Start Here

1. [README.md](../README.md)
   Top-level project overview, current binaries, and tested quick-start commands.

2. [TUTORIAL.md](TUTORIAL.md)
   Current walkthrough for `zk-fuzzer`, `zkpatternfuzz`, and writable local output setup.

3. [STANDARDIZED_RUN_PROFILES.md](STANDARDIZED_RUN_PROFILES.md)
   Source of truth for routine `smoke`, `standard`, and `deep` wrapper runs.

## Daily Operations

4. [TARGETS.md](TARGETS.md)
   Current target execution model, direct batch-run environment requirements, and catalog examples.

5. [TROUBLESHOOTING_PLAYBOOK.md](TROUBLESHOOTING_PLAYBOOK.md)
   Fast triage for missing env vars, unwritable output roots, selector mismatches, keygen failures, and release-gate issues.

6. [BACKEND_SETUP.md](BACKEND_SETUP.md)
   Backend verification guide for the toolchain that is already installed on the host.

7. [TOOLS_AVAILABLE_ON_HOST.md](TOOLS_AVAILABLE_ON_HOST.md)
   Verified local tool inventory as of 2026-03-05.

## Release And Validation

8. [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)
   Current release gate checklist using `zk0d_benchmark` and `release_candidate_gate.sh`.

9. [scan_modes.md](scan_modes.md)
   How pattern selection, selectors, and mono-vs-multi scan dispatch work today.

10. [scan_metrics.md](scan_metrics.md)
    Definitions for scan-mode metrics and maturity comparisons.

## Backend-Specific Guides

11. [NOIR_BACKEND_TROUBLESHOOTING.md](NOIR_BACKEND_TROUBLESHOOTING.md)
    Current Noir readiness checks and single-target repro flow.

12. [CAIRO_INTEGRATION_TUTORIAL.md](CAIRO_INTEGRATION_TUTORIAL.md)
    Current Cairo readiness workflow and local target examples.

13. [HALO2_REAL_EXECUTION_MIGRATION.md](HALO2_REAL_EXECUTION_MIGRATION.md)
    Current Halo2 migration and readiness workflow.

## Reference

14. [CIRCUIT_GEN.md](CIRCUIT_GEN.md)
    Operator-facing overview of the circuit generator, adversarial corpus flow, and compiler-testing lane.

15. [ATTACK_DSL_SPEC.md](ATTACK_DSL_SPEC.md)
    Normative attack configuration schema.

16. [PATTERN_LIBRARY.md](PATTERN_LIBRARY.md)
    Pattern authoring background and examples.

17. [INVARIANT_SPEC_SCHEMA.md](INVARIANT_SPEC_SCHEMA.md)
    Invariant spec format used by scans and formal bridges.

18. [SEMANTIC_ANALYSIS_OPERATOR_GUIDE.md](SEMANTIC_ANALYSIS_OPERATOR_GUIDE.md)
    Reproducible semantic-analysis runbook.

19. [../campaigns/semantic/README.md](../campaigns/semantic/README.md)
    Checked-in semantic campaign entrypoint with the wrapper and execution-evidence payload.

20. [PLUGIN_API.md](PLUGIN_API.md)
    Minimal external plugin contract with the required symbol and campaign wiring.

21. [PLUGIN_SYSTEM_GUIDE.md](PLUGIN_SYSTEM_GUIDE.md)
    Plugin loading and safety model.

22. [SECURITY_THREAT_MODEL.md](SECURITY_THREAT_MODEL.md)
    Security boundaries and assumptions.

23. [../CVErefs/README.md](../CVErefs/README.md)
    Operator-facing index of the curated CVE-style regression catalog and fixture mapping.

24. [VALIDATION_EVIDENCE.md](VALIDATION_EVIDENCE.md)
    Published real-target evidence case study with deterministic replay and Picus follow-up.

25. [GROUND_TRUTH_REPORT.md](GROUND_TRUTH_REPORT.md)
    Published benchmarked ground-truth recall, precision, and false-positive figures.

## Historical Context

- [ARCHITECTURE.md](../ARCHITECTURE.md)
  Structural overview with some dated component snapshots.

- [ROADMAP.md](../ROADMAP.md)
  Dated progress log and validation history.

- [CHANGELOG.md](../CHANGELOG.md)
  Release-oriented change history.
