//! Re-exported attack modules from zk-attacks.
//!
//! ## Novel Oracles (Phase 4)
//!
//! - [`constraint_inference`]: Detect missing constraints via pattern analysis
//! - [`metamorphic`]: Transform-based testing for logic bugs
//! - [`constraint_slice`]: Dependency cone mutation and leak detection
//! - [`spec_inference`]: Auto-learn and violate circuit properties
//! - [`witness_collision`]: Enhanced collision detection with equivalence classes
//!
//! ## DeFi/MEV Attacks (Phase 3)
//!
//! - [`mev`]: MEV extraction detection (ordering, sandwich, arbitrage)
//! - [`front_running`]: Front-running vulnerability detection
//!
//! ## zkEVM-Specific Attacks (Phase 3: Milestone 3.2)
//!
//! - [`zkevm`]: zkEVM state transition, opcode boundary, memory expansion,
//!   and storage proof attacks for L2 rollup security testing
//! - [`zkevm_differential`]: Differential testing with reference EVM (Phase 5)
//!
//! ## Batch Verification Attacks (Phase 3: Milestone 3.3)
//!
//! - [`batch_verification`]: Batch mixing, aggregation forgery, cross-circuit
//!   batch analysis, and randomness reuse detection for batch verifiers
//!
//! ## Recursive SNARK Attacks (Phase 3: Milestone 3.4)
//!
//! - [`recursive`]: Base case bypass, accumulator overflow, VK substitution,
//!   and folding attacks for recursive proof systems (Nova, Supernova, Halo2)

pub mod arithmetic;
pub mod batch_verification; // Phase 3: Batch verification bypass attacks
pub mod boundary;
pub mod canonicalization;
pub mod collision;
pub mod constraint_inference;
pub mod constraint_slice;
pub mod cross_backend;
pub mod determinism;
pub mod front_running; // Phase 3: Front-running attacks
pub mod frozen_wire;
pub mod metamorphic;
pub mod mev; // Phase 3: MEV attacks
pub mod nullifier_replay;
pub mod proof_malleability;
pub mod recursive; // Phase 3: Recursive SNARK attacks
pub mod setup_poisoning;
pub mod soundness;
pub mod spec_inference;
pub mod underconstrained;
pub mod verification;
pub mod witness;
pub mod witness_collision;
pub mod zkevm; // Phase 3: zkEVM-specific attacks
pub mod zkevm_differential; // Phase 5: zkEVM differential testing with reference EVM

pub use arithmetic::ArithmeticTester;
pub use batch_verification::{
    AggregationMethod, BatchProof, BatchProofOfConcept, BatchVerificationAnalyzer,
    BatchVerificationAttack, BatchVerificationConfig, BatchVerificationFinding,
    BatchVerificationResult, BatchVerificationStats, BatchVulnerabilityType, InvalidPosition,
    ProofBatch,
};
pub use boundary::{
    common_ranges, BoundaryCategory, BoundaryTestResult, BoundaryTestSummary, BoundaryTester,
    BoundaryVulnerability, RangeSpec,
};
pub use canonicalization::CanonicalizationChecker;
pub use collision::{CollisionAnalysis, CollisionDetector, CollisionPair, HashType};
pub use constraint_inference::{
    BitDecompositionInference, ConstraintCategory, ConstraintInferenceEngine,
    ConstraintInferenceStats, ImpliedConstraint, InferenceContext, InferenceRule,
    MerklePathInference, NullifierUniquenessInference, RangeEnforcementInference,
    ViolationConfirmation,
};
pub use constraint_slice::{
    ConstraintCone, ConstraintId, ConstraintSliceOracle, ConstraintSliceStats, ConstraintSlicer,
    LeakingConstraint, OutputMapping,
};
pub use cross_backend::CrossBackendDifferential;
pub use determinism::DeterminismOracle;
pub use front_running::{
    FrontRunningAttack, FrontRunningConfig, FrontRunningResult, FrontRunningVulnerability,
    StateLeakageAnalyzer,
};
pub use frozen_wire::FrozenWireDetector;
pub use metamorphic::{
    CircuitType, ExpectedBehavior, MetamorphicOracle, MetamorphicRelation, MetamorphicStats,
    MetamorphicTestResult, Transform,
};
pub use mev::{
    ArbitrageDetector, MevAttack, MevConfig, MevTestResult, MevVulnerabilityType,
    PriceImpactAnalyzer,
};
pub use nullifier_replay::{NullifierHeuristic, NullifierReplayScanner};
pub use proof_malleability::{MalleabilityResult, ProofMalleabilityScanner, ProofMutation};
pub use recursive::{
    AccumulatorState, Halo2AccumulationAnalyzer, NovaAnalyzer, RecursiveAttack,
    RecursiveAttackConfig, RecursiveStep, RecursiveSystem, RecursiveVulnerabilityType,
    SupernovaAnalyzer,
};
pub use setup_poisoning::SetupPoisoningDetector;
pub use soundness::SoundnessTester;
pub use spec_inference::{ExecutionSample, InferredSpec, SpecInferenceOracle, SpecInferenceStats};
pub use underconstrained::UnderconstrainedDetector;
pub use verification::VerificationFuzzer;
pub use witness::WitnessFuzzer;
pub use witness_collision::{
    CollisionAnalysis as WitnessCollisionAnalysis, EquivalenceClass, EquivalencePredicate,
    WitnessCollision, WitnessCollisionDetector, WitnessCollisionStats,
};
pub use zkevm::{
    EvmOpcode, ZkEvmAttack, ZkEvmCallDetector, ZkEvmConfig, ZkEvmPriceAnalyzer, ZkEvmTestResult,
    ZkEvmVulnerabilityType, EVM_OPCODES,
};
pub use zkevm_differential::{
    precompiles, AccountState, DifferentialFinding, DifferentialStats, EvmLog, EvmState,
    ExecutionTrace, MismatchType, MockReferenceEvm, PrecompileTestGenerator, ReferenceEvm,
    StateDifference, TestTransaction, ZkEvmDifferentialConfig, ZkEvmDifferentialTester,
};

pub use zk_attacks::{
    Attack, AttackContext, AttackMetadata, AttackPlugin, AttackPluginLoader, AttackRegistry,
    CircuitInfo, DynamicLibraryLoader, NoopPluginLoader,
};
