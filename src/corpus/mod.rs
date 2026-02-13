//! Re-exported corpus management from zk-fuzzer-core.
//!
//! ## Lock-Free Corpus (Phase 4.4)
//!
//! The [`lockfree`] module provides lock-free data structures for
//! high-performance concurrent corpus management.

pub mod deduplication;
pub mod lockfree; // Phase 4.4: Lock-free corpus data structures
pub mod minimizer;
pub mod storage;

pub use zk_fuzzer_core::corpus::*;

// Phase 4.4: Lock-free corpus exports
pub use lockfree::{
    create_shared_corpus, AtomicCoverageBitmap, LockFreeCorpus, LockFreeTestQueue,
    SharedLockFreeCorpus,
};
