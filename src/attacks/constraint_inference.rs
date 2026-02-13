//! Re-exported constraint inference attack helpers from zk-attacks.

pub use zk_attacks::constraint_inference::{
    BitDecompositionInference, ConstraintCategory, ConstraintInferenceEngine,
    ConstraintInferenceStats, ImpliedConstraint, InferenceContext, InferenceRule,
    MerklePathInference, NullifierUniquenessInference, RangeEnforcementInference,
    ViolationConfirmation,
};
