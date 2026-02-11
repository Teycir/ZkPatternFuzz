# ZkPatternFuzz: Best Use Cases

Date: 2026-02-11

## Ideal Targets

- Circom, Noir, Halo2, or Cairo circuits with deterministic builds and accessible artifacts.
- Protocols using Merkle trees, nullifiers, commitments, range checks, or signatures where semantic oracles add signal.
- Projects that can supply real backend tooling (no mock fallback) for evidence-quality claims.

## Recommended Workflows

- Fast Skimmer to triage large repos and identify high-signal candidates quickly.
- Evidence mode for confirmed findings with strict backend verification and reproducible witnesses.
- Chain fuzzing (Mode 3) for multi-step protocols or stateful workflows such as deposit-withdraw, mint-burn, or recursive proofs.

## High-Value Use Cases

- Underconstrained circuit detection where multiple witnesses can satisfy identical public inputs.
- Soundness testing against proof forgery attempts with real backend verification.
- Differential testing across Circom/Noir/Halo2 implementations to catch backend-specific divergence.
- Regression testing after circuit changes, compiler upgrades, or constraint refactors.
- Pre-release or bug-bounty prep where evidence bundles are required for disclosure.

## When It’s Less Effective

- Targets without working backend toolchains or with non-deterministic build outputs.
- Workflows that require formal proofs only, with no executable circuit artifacts.
- Extremely large circuits where compilation dominates and a skimmer-first approach is not used.

## Inputs That Improve Signal

- Explicit public input names or indices to avoid misclassification of private/public wires.
- Known-good PTAU, ZKey, or verifier keys for Circom proof generation.
- Targeted invariants for protocol semantics rather than purely syntactic checks.
