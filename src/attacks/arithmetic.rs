//! Arithmetic Overflow/Underflow Detection
//!
//! Tests field arithmetic edge cases for vulnerabilities including:
//! - Overflow/underflow at field boundaries
//! - Division by zero handling
//! - Incorrect modular reduction
//!
//! The arithmetic attack is implemented directly in the fuzzer engine
//! (see `FuzzingEngine::run_arithmetic_attack()`).
