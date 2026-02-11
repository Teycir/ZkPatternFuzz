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
pub mod batch_verification;  // Phase 3: Batch verification bypass attacks
pub mod boundary;
pub mod collision;
pub mod constraint_inference;
pub mod constraint_slice;
pub mod canonicalization;
pub mod cross_backend;
pub mod determinism;
pub mod front_running;  // Phase 3: Front-running attacks
pub mod frozen_wire;
pub mod metamorphic;
pub mod mev;  // Phase 3: MEV attacks
pub mod nullifier_replay;
pub mod proof_malleability;
pub mod recursive;  // Phase 3: Recursive SNARK attacks
pub mod setup_poisoning;
pub mod soundness;
pub mod spec_inference;
pub mod underconstrained;
pub mod verification;
pub mod witness;
pub mod witness_collision;
pub mod zkevm;  // Phase 3: zkEVM-specific attacks
pub mod zkevm_differential;  // Phase 5: zkEVM differential testing with reference EVM

pub use arithmetic::ArithmeticTester;
pub use batch_verification::{
    BatchVerificationConfig,
    BatchVulnerabilityType,
    AggregationMethod,
    InvalidPosition,
    BatchProof,
    ProofBatch,
    BatchVerificationResult,
    BatchProofOfConcept,
    BatchVerificationFinding,
    BatchVerificationAttack,
    BatchVerificationAnalyzer,
    BatchVerificationStats,
};
pub use boundary::{
    common_ranges,
    BoundaryCategory,
    BoundaryTestResult,
    BoundaryTestSummary,
    BoundaryTester,
    BoundaryVulnerability,
    RangeSpec,
};
pub use collision::{
    CollisionAnalysis,
    CollisionDetector,
    CollisionPair,
    HashType,
};
pub use constraint_inference::{
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
pub use constraint_slice::{
    ConstraintId,
    ConstraintCone,
    ConstraintSlicer,
    OutputMapping,
    LeakingConstraint,
    ConstraintSliceOracle,
    ConstraintSliceStats,
};
pub use canonicalization::CanonicalizationChecker;
pub use cross_backend::CrossBackendDifferential;
pub use determinism::DeterminismOracle;
pub use front_running::{
    FrontRunningConfig,
    FrontRunningVulnerability,
    FrontRunningResult,
    FrontRunningAttack,
    StateLeakageAnalyzer,
};
pub use frozen_wire::FrozenWireDetector;
pub use metamorphic::{
    CircuitType,
    ExpectedBehavior,
    Transform,
    MetamorphicRelation,
    MetamorphicOracle,
    MetamorphicTestResult,
    MetamorphicStats,
};
pub use mev::{
    MevConfig,
    MevTestResult,
    MevVulnerabilityType,
    MevAttack,
    PriceImpactAnalyzer,
    ArbitrageDetector,
};
pub use nullifier_replay::{
    NullifierHeuristic,
    NullifierReplayScanner,
};
pub use proof_malleability::{
    ProofMutation,
    MalleabilityResult,
    ProofMalleabilityScanner,
};
pub use recursive::{
    RecursiveAttackConfig,
    RecursiveSystem,
    RecursiveVulnerabilityType,
    RecursiveStep,
    AccumulatorState,
    RecursiveAttack,
    NovaAnalyzer,
    SupernovaAnalyzer,
    Halo2AccumulationAnalyzer,
};
pub use setup_poisoning::SetupPoisoningDetector;
pub use soundness::SoundnessTester;
pub use spec_inference::{
    InferredSpec,
    ExecutionSample,
    SpecInferenceOracle,
    SpecInferenceStats,
};
pub use underconstrained::UnderconstrainedDetector;
pub use verification::VerificationFuzzer;
pub use witness::WitnessFuzzer;
pub use witness_collision::{
    WitnessCollision,
    EquivalenceClass,
    EquivalencePredicate,
    WitnessCollisionDetector,
    CollisionAnalysis as WitnessCollisionAnalysis,
    WitnessCollisionStats,
};
pub use zkevm::{
    ZkEvmConfig,
    ZkEvmVulnerabilityType,
    ZkEvmTestResult,
    EvmOpcode,
    EVM_OPCODES,
    ZkEvmAttack,
    ZkEvmPriceAnalyzer,
    ZkEvmCallDetector,
};
pub use zkevm_differential::{
    ZkEvmDifferentialConfig,
    AccountState,
    ExecutionTrace,
    EvmLog,
    TestTransaction,
    ReferenceEvm,
    EvmState,
    MockReferenceEvm,
    ZkEvmDifferentialTester,
    DifferentialStats,
    DifferentialFinding,
    MismatchType,
    StateDifference,
    precompiles,
    PrecompileTestGenerator,
};

pub use zk_attacks::{
    Attack, AttackContext, AttackMetadata, AttackPlugin, AttackPluginLoader, AttackRegistry,
    CircuitInfo, DynamicLibraryLoader, NoopPluginLoader,
};
