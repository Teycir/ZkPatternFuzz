//! ZK-Fuzzer: Zero-Knowledge Proof Security Testing Framework
//!
//! This library provides a comprehensive fuzzing and security testing
//! framework for ZK circuits across multiple backends (Circom, Noir, Halo2, Cairo).

pub mod attacks;
pub mod config;
pub mod fuzzer;
pub mod reporting;
pub mod targets;

pub use config::FuzzConfig;
pub use fuzzer::ZkFuzzer;
pub use reporting::FuzzReport;
