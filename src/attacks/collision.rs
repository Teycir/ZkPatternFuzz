//! Collision Detection for ZK Circuits
//!
//! Detects hash and nullifier collisions in ZK circuits using:
//! - Birthday paradox attacks (O(2^(n/2)) for n-bit outputs)
//! - Near-collision detection (Hamming distance analysis)
//! - Output distribution analysis
//!
//! The collision attack is implemented directly in the fuzzer engine
//! (see `FuzzingEngine::run_collision_attack()`).
