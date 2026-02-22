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
