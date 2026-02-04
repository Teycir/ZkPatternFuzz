//! Boundary Value Testing for ZK Circuits
//!
//! Implements systematic boundary value analysis to test circuit behavior at:
//! - Field element boundaries (0, 1, p-1, p, etc.)
//! - Bit boundaries (2^n - 1, 2^n, 2^n + 1)
//! - Application-specific boundaries (range proofs, age verification, etc.)
//! - Type transition boundaries
//!
//! The boundary attack is implemented directly in the fuzzer engine
//! (see `FuzzingEngine::run_boundary_attack()`).
