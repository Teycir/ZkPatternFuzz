//! Soundness attack detection
//!
//! Soundness attacks attempt to create valid proofs for false statements.
//! A sound proof system should never accept a proof for an invalid statement.
//!
//! The soundness attack is implemented directly in the fuzzer engine
//! (see `FuzzingEngine::run_soundness_attack()`).
