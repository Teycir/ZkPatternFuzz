//! Correctness Tests (Milestone 0.0)
//!
//! Tests to verify correctness of fuzzer components and prevent
//! false positives/negatives identified in the dual code review.
//!
//! Run with: `cargo test correctness --release`

pub mod oracle_independence_tests;
pub mod evidence_confidence_tests;
pub mod metamorphic_tests;
pub mod concurrency_tests;
