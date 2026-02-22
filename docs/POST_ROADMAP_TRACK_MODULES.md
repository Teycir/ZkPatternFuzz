# Post-Roadmap Track Modules

This document records the deferred-track module boundaries and toggle surface.

## Crate Boundaries

- `crates/zk-postroadmap-core`
  - shared contracts (`TrackInput`, `TrackFinding`, `ReplayArtifact`, `TrackExecution`, `Scorecard`)
  - shared error taxonomy (`PostRoadmapError`)
  - shared runner interface (`TrackRunner`)
- `crates/zk-track-boundary`
  - boundary-only protocol adapter interfaces (`VerifierAdapter`, `SerializationAdapter`, `BoundaryProtocolAdapter`)
- `crates/zk-track-compiler`
  - compiler backend strategy interface (`CompilerBackendAdapter`)
- `crates/zk-track-semantic`
  - semantic provider strategy interface (`SemanticIntentAdapter`)
- `crates/zk-track-crypto`
  - crypto-track runner shell (field/curve/pairing work lands here)

## Independent Module Versioning

Each deferred-track crate publishes its own module version constant:

- `zk_postroadmap_core::POST_ROADMAP_CORE_VERSION`
- `zk_track_boundary::TRACK_MODULE_VERSION`
- `zk_track_compiler::TRACK_MODULE_VERSION`
- `zk_track_semantic::TRACK_MODULE_VERSION`
- `zk_track_crypto::TRACK_MODULE_VERSION`

Values come from each crate's own `Cargo.toml` package version.

## Track Toggle Config

`PostRoadmapRunnerConfig` controls which track runners execute:

```rust
use zk_fuzzer::{PostRoadmapRunner, PostRoadmapRunnerConfig};
use zk_postroadmap_core::TrackKind;

let runner = PostRoadmapRunner::with_config(
    zk_fuzzer::default_post_roadmap_tracks(),
    PostRoadmapRunnerConfig::only([TrackKind::Boundary, TrackKind::Compiler]),
);
```

Disabled tracks are skipped, and enabled tracks continue independently even if one track fails.

## Workflow Activation, Cadence, and Gates

`PostRoadmapWorkflowRunner` wraps the track runner with explicit activation and promotion checks.

- Activation: `PostRoadmapWorkflowConfig.activated` defaults to `false`.
- Weekly cadence default: `generate -> boundary -> semantic -> crypto -> regress`.
- Integrated pipeline default: `generate -> attack -> interpret -> validate -> regress`.
- Promotion gates enforce:
  - deterministic replay metric threshold
  - false-positive budget
  - explicit coverage counts
  - mandatory `regression_test` metadata for high/critical findings

## Foundation Sprint State

`build_foundation_sprint_state` produces a shared foundation manifest:

- `SharedStoreLayout`:
  - `corpus/post_roadmap/shared`
  - `evidence/post_roadmap/shared`
  - `output/post_roadmap/replay`
  - `output/post_roadmap/dashboard`
- `ReplayHarnessState`:
  - replay artifact count
  - minimization queue count (reproducible findings)
- `DashboardSnapshot`:
  - run/finding/failure totals
  - finding counts per track
  - high/critical findings missing regression-test metadata

## Shared Data Flow Manifest

`build_shared_data_flow` extracts handoff artifacts for the deferred workflow:

- compiler-generated circuits for boundary testing
- boundary/compiler findings promoted into semantic candidate queue
- crypto validation notes for noise filtering
- semantic generator priorities for next-cycle generation
