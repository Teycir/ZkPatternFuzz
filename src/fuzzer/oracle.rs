//! Re-exported bug oracles from zk-fuzzer-core.

pub use zk_fuzzer_core::oracle::{
    ArithmeticOverflowOracle, BugOracle, ConstraintCountOracle, OracleStatistics,
    ProofForgeryOracle, SemanticOracleAdapter, UnderconstrainedOracle,
};
