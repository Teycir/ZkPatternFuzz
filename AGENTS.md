# AI Session Entry Rule (Read First)

All AI agents must read `docs/AI_PENTEST_RULES.md` and `docs/scan_modes.md`
**before** starting any pentesting session or producing findings. This is a
hard requirement.

## Output Stability Rule (Hard Requirement)

- Do **not** change output folder paths.
- Do **not** change output file names, JSON/Markdown schema, or on-disk report format.
- Do **not** override output roots (for example `reporting.output_dir`, `ZKF_RUN_SIGNAL_DIR`, or equivalent runtime output locations).
- Any output path or format change requires explicit user approval in the current session.
