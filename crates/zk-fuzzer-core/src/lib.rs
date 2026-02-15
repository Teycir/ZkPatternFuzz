//! Core fuzzing utilities for ZK circuits.

pub mod constants;
pub mod corpus;
pub mod coverage;
pub mod engine;
pub mod mutators;
pub mod oracle;
pub mod power_schedule;
pub mod stats;
pub mod structure_aware;

pub use stats::FuzzingStats;
