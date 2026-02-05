use crate::{AttackType, CircuitInfo, FieldElement, Finding, TestCase};

/// Trait for attack implementations
pub trait Attack: Send + Sync {
    /// Run the attack and return any findings
    fn run(&self, context: &AttackContext) -> Vec<Finding>;

    /// Get the attack type
    fn attack_type(&self) -> AttackType;

    /// Get attack description
    fn description(&self) -> &str;
}

/// Context provided to attacks
pub struct AttackContext {
    pub circuit_info: CircuitInfo,
    pub samples: usize,
    pub timeout_seconds: u64,
}

impl AttackContext {
    /// Create a new attack context
    pub fn new(circuit_info: CircuitInfo, samples: usize, timeout_seconds: u64) -> Self {
        Self {
            circuit_info,
            samples,
            timeout_seconds,
        }
    }

    /// Get the circuit name
    pub fn circuit_name(&self) -> &str {
        &self.circuit_info.name
    }

    /// Check if we should continue based on timeout
    pub fn should_continue(&self, elapsed_secs: u64) -> bool {
        elapsed_secs < self.timeout_seconds
    }
}

/// Trait for semantic bug detection oracles
pub trait SemanticOracle: Send + Sync {
    /// Check if the given execution reveals a vulnerability
    fn check(&mut self, test_case: &TestCase, output: &[FieldElement]) -> Option<Finding>;

    /// Get the oracle name
    fn name(&self) -> &str;

    /// Get the attack type this oracle detects
    fn attack_type(&self) -> AttackType;

    /// Reset oracle state (e.g., for new fuzzing campaign)
    fn reset(&mut self);

    /// Get oracle statistics
    fn stats(&self) -> OracleStats {
        OracleStats::default()
    }
}

/// Statistics for oracle operation
#[derive(Debug, Clone, Default)]
pub struct OracleStats {
    /// Number of checks performed
    pub checks: u64,
    /// Number of unique observations tracked
    pub observations: u64,
    /// Number of findings generated
    pub findings: u64,
    /// Memory usage estimate in bytes
    pub memory_bytes: usize,
}

/// Configuration for semantic oracles
#[derive(Debug, Clone)]
pub struct OracleConfig {
    /// Maximum observations to track before eviction
    pub max_observations: usize,
    /// Enable entropy analysis for predictability detection
    pub check_entropy: bool,
    /// Minimum entropy threshold (0.0 - 1.0)
    pub min_entropy_threshold: f64,
    /// Enable non-determinism detection
    pub check_determinism: bool,
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            max_observations: 100_000,
            check_entropy: true,
            min_entropy_threshold: 0.5,
            check_determinism: true,
        }
    }
}
