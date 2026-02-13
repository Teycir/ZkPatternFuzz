//! Mode 3: Multi-Step Chain Fuzzer Module
//!
//! This module implements real multi-step event-chain fuzzing for deep bug discovery.
//! Chain fuzzing executes sequences of circuit operations to find vulnerabilities
//! that only manifest through specific sequences of state transitions.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Chain Fuzzer Module                      │
//! ├─────────────────────────────────────────────────────────────┤
//! │  types.rs      - ChainSpec, StepSpec, ChainTrace, etc.      │
//! │  runner.rs     - ChainRunner (executes chain specs)         │
//! │  invariants.rs - CrossStepInvariantChecker                  │
//! │  mutator.rs    - ChainMutator (mutates chain inputs)        │
//! │  shrinker.rs   - ChainShrinker (minimizes to L_min)         │
//! │  metrics.rs    - Depth metrics (D, P_deep)                  │
//! │  scheduler.rs  - ChainScheduler (budget allocation)         │
//! │  corpus.rs     - ChainCorpus (persistence)                  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # YAML Configuration
//!
//! Chains are defined in campaign YAML under the `chains:` key:
//!
//! ```yaml
//! chains:
//!   - name: "deposit_then_withdraw"
//!     steps:
//!       - circuit_ref: "deposit"
//!         input_wiring: fresh
//!       - circuit_ref: "withdraw"
//!         input_wiring:
//!           from_prior_output:
//!             step: 0
//!             mapping:
//!               - [0, 2]   # deposit.out[0] → withdraw.in[2]
//!     assertions:
//!       - name: "nullifier_uniqueness"
//!         relation: "unique(step[*].out[0])"
//!         severity: "critical"
//! ```
//!
//! # Key Metrics
//!
//! - **L_min**: Minimum chain length to reproduce a finding
//! - **D**: Mean L_min across confirmed findings
//! - **P_deep**: Probability that a finding requires L_min >= 2

pub mod corpus;
pub mod invariants;
pub mod metrics;
pub mod mutator;
pub mod runner;
pub mod scheduler;
pub mod shrinker;
pub mod types;

// Re-exports
pub use corpus::{ChainCorpus, ChainCorpusEntry};
pub use invariants::{CrossStepInvariantChecker, CrossStepViolation};
pub use metrics::DepthMetrics;
pub use mutator::ChainMutator;
pub use runner::ChainRunner;
pub use scheduler::ChainScheduler;
pub use shrinker::ChainShrinker;
pub use types::{
    ChainFinding, ChainRunResult, ChainSpec, ChainTrace, CrossStepAssertion, InputWiring, StepSpec,
    StepTrace,
};
