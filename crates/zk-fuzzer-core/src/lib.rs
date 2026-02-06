//! Core fuzzing utilities for ZK circuits.

pub mod constants;
pub mod mutators;
pub mod power_schedule;
pub mod corpus;
pub mod coverage;
pub mod structure_aware;
pub mod oracle;
pub mod stats;
pub mod engine;

pub use stats::FuzzingStats;
