//! Re-exported constraint inference attack helpers from zk-attacks.

pub use zk_attacks::constraint_inference::{
    ConstraintCategory,
    ImpliedConstraint,
    ViolationConfirmation,
    InferenceRule,
    InferenceContext,
    BitDecompositionInference,
    MerklePathInference,
    NullifierUniquenessInference,
    RangeEnforcementInference,
    ConstraintInferenceEngine,
    ConstraintInferenceStats,
};
