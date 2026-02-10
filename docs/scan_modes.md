# Scan Modes

This document defines the three scanning modes used in this repo. Read this before starting a new session so the chosen mode, scope, and expected outputs are explicit. For measurement and comparisons, also read `docs/scan_metrics.md`.

**Global Constraints**
- Targets are read-only and must come from `/media/elements/Repos/zk0d`.
- No mocks or synthetic targets unless explicitly approved.

**Mode 1: Fast Skimmer**

Purpose: rapid surface coverage to identify obvious issues and prioritize where to go deeper.

Inputs
- Minimal YAML config.
- Broad oracles, low iteration counts.

Outputs
- Short list of high-signal findings or suspicious areas.
- Quick stats: coverage hints, failure types, oracles firing.

Use When
- First pass on a new target.
- You need to triage or compare multiple targets quickly.

Limits
- Low depth; misses multi-step logic bugs and chained invariants.

**Mode 2: YAML Deeper Searcher**

Purpose: deeper, configurable fuzzing with targeted oracles and richer witness exploration.

Inputs
- Target-specific YAML with explicit signals, constraints, and invariants.
- Increased iterations and sampling.

Outputs
- Evidence runs with repro inputs and oracle traces.
- Candidate PoCs for manual validation.

Use When
- Fast Skimmer finds promising areas.
- You need better signal-to-noise and more confidence in findings.

Limits
- Still mostly single-stage; may miss bugs that require chained events.

**Mode 3: YAML Deepest Searcher (Multi-Step)**

Purpose: find logic-based 0day class bugs that are not obvious to shallow fuzzing, using multi-step event chains.

Core Idea
- A first phase performs a code read to identify precise fuzz points and invariants.
- A second phase generates modular YAML to drive chained events and multi-step state transitions.

Inputs
- Modular YAML with explicit event chains, state transitions, and cross-invariant checks.
- Oracles tuned for semantic violations and protocol-level invariants.

Outputs
- High-confidence PoCs with minimal repro YAML and clear impact notes.
- Evidence that links inputs, state transitions, and violated invariants.

Use When
- The goal is logic-based 0day discovery.
- The target has complex state or multi-step workflows.

Limits
- Highest cost; requires careful setup and validation.

**Switching Guidance**
- Start with Fast Skimmer to find candidate surfaces.
- Escalate to YAML Deeper Searcher for targeted evidence.
- Use YAML Deepest Searcher when multi-step logic or protocol-level invariants are likely.

**Skimmer-First Rule**
- Always run a **short Fast Skimmer** before Mode 2 or Mode 3 to validate wiring, inputs, and basic constraints.
- Goal: catch misconfigurations early and avoid wasted deep runs.
- Suggested budget: 5–10 minutes per target, low iterations, broad oracles.
- Exception: skip only if the user explicitly requests it in writing.
