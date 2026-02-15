//! zkEVM Differential Testing with Reference EVM (Phase 5: Milestone 5.2)
//!
//! Implements differential testing between zkEVM circuits and a reference EVM
//! implementation to detect semantic mismatches and vulnerabilities.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    ZkEvmDifferentialTester                               │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────────┐          ┌─────────────────────┐              │
//! │  │   zkEVM Circuit     │          │   Reference EVM     │              │
//! │  │   (Polygon/Scroll/  │◄────────►│   (revm/geth)       │              │
//! │  │    zkSync)          │          │                     │              │
//! │  └──────────┬──────────┘          └──────────┬──────────┘              │
//! │             │                                │                          │
//! │             ▼                                ▼                          │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                    State Comparator                              │   │
//! │  │  • Account balances  • Storage slots  • Code hashes              │   │
//! │  │  • Nonces            • Gas used       • Return data              │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # References
//!
//! - revm: https://github.com/bluealloy/revm
//! - Polygon zkEVM: https://github.com/0xPolygonHermez/zkevm-circuits
//! - Scroll zkEVM: https://github.com/scroll-tech/zkevm-circuits

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use zk_core::{AttackType, Finding, Severity};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for zkEVM differential testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkEvmDifferentialConfig {
    /// Number of differential tests to run
    pub num_tests: usize,
    /// Enable state root comparison
    pub compare_state_root: bool,
    /// Enable storage slot comparison
    pub compare_storage: bool,
    /// Enable gas usage comparison
    pub compare_gas: bool,
    /// Enable return data comparison
    pub compare_return_data: bool,
    /// Gas tolerance for comparison (percentage)
    pub gas_tolerance_percent: f64,
    /// Timeout per test in milliseconds
    pub timeout_ms: u64,
    /// Random seed for reproducibility
    pub seed: Option<u64>,
    /// Opcodes to focus on (empty = all)
    pub target_opcodes: Vec<u8>,
    /// Precompile addresses to test
    pub target_precompiles: Vec<[u8; 20]>,
}

impl Default for ZkEvmDifferentialConfig {
    fn default() -> Self {
        Self {
            num_tests: 1000,
            compare_state_root: true,
            compare_storage: true,
            compare_gas: true,
            compare_return_data: true,
            gas_tolerance_percent: 1.0, // 1% tolerance for gas
            timeout_ms: 30_000,
            seed: None,
            target_opcodes: vec![],
            target_precompiles: vec![],
        }
    }
}

// ============================================================================
// EVM State Types
// ============================================================================

/// EVM account state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AccountState {
    /// Account balance
    pub balance: [u8; 32],
    /// Account nonce
    pub nonce: u64,
    /// Code hash
    pub code_hash: [u8; 32],
    /// Storage root
    pub storage_root: [u8; 32],
}

/// EVM execution trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    /// Gas used
    pub gas_used: u64,
    /// Return data
    pub return_data: Vec<u8>,
    /// Success status
    pub success: bool,
    /// Revert reason (if any)
    pub revert_reason: Option<String>,
    /// Storage changes
    pub storage_changes: HashMap<[u8; 20], HashMap<[u8; 32], [u8; 32]>>,
    /// Account state changes
    pub account_changes: HashMap<[u8; 20], AccountState>,
    /// Logs emitted
    pub logs: Vec<EvmLog>,
    /// State root after execution
    pub state_root: [u8; 32],
}

/// EVM log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// Transaction for differential testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestTransaction {
    /// Sender address
    pub from: [u8; 20],
    /// Recipient address (None for contract creation)
    pub to: Option<[u8; 20]>,
    /// Value in wei
    pub value: [u8; 32],
    /// Input data (calldata or init code)
    pub data: Vec<u8>,
    /// Gas limit
    pub gas_limit: u64,
    /// Gas price
    pub gas_price: [u8; 32],
    /// Nonce
    pub nonce: u64,
}

// ============================================================================
// Reference EVM Interface
// ============================================================================

/// Trait for reference EVM implementations
pub trait ReferenceEvm: Send + Sync {
    /// Execute a transaction and return the trace
    fn execute(&self, tx: &TestTransaction, state: &EvmState) -> anyhow::Result<ExecutionTrace>;

    /// Get the EVM implementation name
    fn name(&self) -> &str;

    /// Check if the EVM is available
    fn is_available(&self) -> bool;
}

/// EVM state for testing
#[derive(Debug, Clone, Default)]
pub struct EvmState {
    /// Account states
    pub accounts: HashMap<[u8; 20], AccountState>,
    /// Account code
    pub code: HashMap<[u8; 20], Vec<u8>>,
    /// Storage
    pub storage: HashMap<[u8; 20], HashMap<[u8; 32], [u8; 32]>>,
    /// Block number
    pub block_number: u64,
    /// Block timestamp
    pub timestamp: u64,
    /// Chain ID
    pub chain_id: u64,
}

// ============================================================================
// Local Reference EVM (for testing)
// ============================================================================

/// Local EVM simulator for testing when revm is not available.
pub struct LocalReferenceEvm {
    /// Simulated execution results
    results: HashMap<Vec<u8>, ExecutionTrace>,
}

impl LocalReferenceEvm {
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
        }
    }

    /// Add a simulated result for testing
    pub fn add_result(&mut self, data: Vec<u8>, trace: ExecutionTrace) {
        self.results.insert(data, trace);
    }
}

impl Default for LocalReferenceEvm {
    fn default() -> Self {
        Self::new()
    }
}

impl ReferenceEvm for LocalReferenceEvm {
    fn execute(&self, tx: &TestTransaction, _state: &EvmState) -> anyhow::Result<ExecutionTrace> {
        if let Some(trace) = self.results.get(&tx.data) {
            Ok(trace.clone())
        } else {
            // Default successful execution
            Ok(ExecutionTrace {
                gas_used: 21000,
                return_data: vec![],
                success: true,
                revert_reason: None,
                storage_changes: HashMap::new(),
                account_changes: HashMap::new(),
                logs: vec![],
                state_root: [0u8; 32],
            })
        }
    }

    fn name(&self) -> &str {
        "local_reference_evm"
    }

    fn is_available(&self) -> bool {
        true
    }
}

// ============================================================================
// Differential Tester
// ============================================================================

/// Differential tester for zkEVM circuits
pub struct ZkEvmDifferentialTester {
    config: ZkEvmDifferentialConfig,
    reference_evm: Box<dyn ReferenceEvm>,
    findings: Vec<DifferentialFinding>,
    stats: DifferentialStats,
}

/// Statistics from differential testing
#[derive(Debug, Clone, Default)]
pub struct DifferentialStats {
    /// Total tests run
    pub total_tests: usize,
    /// Tests that passed (both EVMs agree)
    pub passed: usize,
    /// Tests with state mismatches
    pub state_mismatches: usize,
    /// Tests with gas mismatches
    pub gas_mismatches: usize,
    /// Tests with return data mismatches
    pub return_data_mismatches: usize,
    /// Tests with execution outcome mismatches
    pub outcome_mismatches: usize,
    /// Opcodes with most mismatches
    pub opcode_mismatch_counts: HashMap<u8, usize>,
}

/// Finding from differential testing
#[derive(Debug, Clone)]
pub struct DifferentialFinding {
    /// Type of mismatch
    pub mismatch_type: MismatchType,
    /// Test transaction that triggered the mismatch
    pub transaction: TestTransaction,
    /// zkEVM result
    pub zkevm_result: ExecutionTrace,
    /// Reference EVM result
    pub reference_result: ExecutionTrace,
    /// Specific differences found
    pub differences: Vec<StateDifference>,
    /// Severity of the mismatch
    pub severity: Severity,
}

/// Type of mismatch between zkEVM and reference EVM
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MismatchType {
    /// Execution success/failure disagrees
    OutcomeMismatch,
    /// State root differs
    StateRootMismatch,
    /// Storage values differ
    StorageMismatch,
    /// Gas used differs significantly
    GasMismatch,
    /// Return data differs
    ReturnDataMismatch,
    /// Logs differ
    LogsMismatch,
    /// Account state differs
    AccountMismatch,
}

impl MismatchType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MismatchType::OutcomeMismatch => "outcome_mismatch",
            MismatchType::StateRootMismatch => "state_root_mismatch",
            MismatchType::StorageMismatch => "storage_mismatch",
            MismatchType::GasMismatch => "gas_mismatch",
            MismatchType::ReturnDataMismatch => "return_data_mismatch",
            MismatchType::LogsMismatch => "logs_mismatch",
            MismatchType::AccountMismatch => "account_mismatch",
        }
    }
}

/// Specific state difference
#[derive(Debug, Clone)]
pub struct StateDifference {
    /// Description of the difference
    pub description: String,
    /// zkEVM value (hex encoded)
    pub zkevm_value: String,
    /// Reference EVM value (hex encoded)
    pub reference_value: String,
    /// Location (address, slot, etc.)
    pub location: Option<String>,
}

impl ZkEvmDifferentialTester {
    /// Create a new differential tester with local reference EVM.
    pub fn new(config: ZkEvmDifferentialConfig) -> Self {
        Self {
            config,
            reference_evm: Box::new(LocalReferenceEvm::new()),
            findings: vec![],
            stats: DifferentialStats::default(),
        }
    }

    /// Create with a custom reference EVM
    pub fn with_reference_evm(
        config: ZkEvmDifferentialConfig,
        reference_evm: Box<dyn ReferenceEvm>,
    ) -> Self {
        Self {
            config,
            reference_evm,
            findings: vec![],
            stats: DifferentialStats::default(),
        }
    }

    /// Run differential test with a transaction
    pub fn test_transaction(
        &mut self,
        tx: &TestTransaction,
        zkevm_result: &ExecutionTrace,
        state: &EvmState,
    ) -> anyhow::Result<Option<DifferentialFinding>> {
        self.stats.total_tests += 1;

        // Execute on reference EVM
        let reference_result = self.reference_evm.execute(tx, state)?;

        // Compare results
        let differences = self.compare_traces(zkevm_result, &reference_result);

        if differences.is_empty() {
            self.stats.passed += 1;
            return Ok(None);
        }

        // Determine mismatch type and severity
        let mismatch_type = self.classify_mismatch(&differences);
        let severity = self.classify_severity(&mismatch_type, &differences);

        // Update stats
        match mismatch_type {
            MismatchType::OutcomeMismatch => self.stats.outcome_mismatches += 1,
            MismatchType::StateRootMismatch => self.stats.state_mismatches += 1,
            MismatchType::StorageMismatch => self.stats.state_mismatches += 1,
            MismatchType::GasMismatch => self.stats.gas_mismatches += 1,
            MismatchType::ReturnDataMismatch => self.stats.return_data_mismatches += 1,
            MismatchType::LogsMismatch => self.stats.state_mismatches += 1,
            MismatchType::AccountMismatch => self.stats.state_mismatches += 1,
        }

        let finding = DifferentialFinding {
            mismatch_type,
            transaction: tx.clone(),
            zkevm_result: zkevm_result.clone(),
            reference_result,
            differences,
            severity,
        };

        self.findings.push(finding.clone());
        Ok(Some(finding))
    }

    /// Compare two execution traces
    fn compare_traces(
        &self,
        zkevm: &ExecutionTrace,
        reference: &ExecutionTrace,
    ) -> Vec<StateDifference> {
        let mut differences = vec![];

        // Compare execution outcome
        if zkevm.success != reference.success {
            differences.push(StateDifference {
                description: "Execution outcome differs".to_string(),
                zkevm_value: zkevm.success.to_string(),
                reference_value: reference.success.to_string(),
                location: None,
            });
        }

        // Compare state root
        if self.config.compare_state_root && zkevm.state_root != reference.state_root {
            differences.push(StateDifference {
                description: "State root differs".to_string(),
                zkevm_value: hex::encode(zkevm.state_root),
                reference_value: hex::encode(reference.state_root),
                location: None,
            });
        }

        // Compare gas used
        if self.config.compare_gas {
            let gas_diff = (zkevm.gas_used as f64 - reference.gas_used as f64).abs();
            let tolerance = reference.gas_used as f64 * self.config.gas_tolerance_percent / 100.0;

            if gas_diff > tolerance {
                differences.push(StateDifference {
                    description: format!(
                        "Gas usage differs by {} (tolerance: {})",
                        gas_diff, tolerance
                    ),
                    zkevm_value: zkevm.gas_used.to_string(),
                    reference_value: reference.gas_used.to_string(),
                    location: None,
                });
            }
        }

        // Compare return data
        if self.config.compare_return_data && zkevm.return_data != reference.return_data {
            differences.push(StateDifference {
                description: "Return data differs".to_string(),
                zkevm_value: hex::encode(&zkevm.return_data),
                reference_value: hex::encode(&reference.return_data),
                location: None,
            });
        }

        // Compare storage changes
        if self.config.compare_storage {
            let storage_diffs =
                self.compare_storage_changes(&zkevm.storage_changes, &reference.storage_changes);
            differences.extend(storage_diffs);
        }

        // Compare logs
        let log_diffs = self.compare_logs(&zkevm.logs, &reference.logs);
        differences.extend(log_diffs);

        differences
    }

    /// Compare storage changes
    fn compare_storage_changes(
        &self,
        zkevm: &HashMap<[u8; 20], HashMap<[u8; 32], [u8; 32]>>,
        reference: &HashMap<[u8; 20], HashMap<[u8; 32], [u8; 32]>>,
    ) -> Vec<StateDifference> {
        let mut differences = vec![];

        // Get all addresses
        let all_addresses: HashSet<_> = zkevm.keys().chain(reference.keys()).collect();

        for addr in all_addresses {
            let zkevm_slots = zkevm.get(addr);
            let ref_slots = reference.get(addr);

            match (zkevm_slots, ref_slots) {
                (Some(z), Some(r)) => {
                    // Compare all slots
                    let all_slots: HashSet<_> = z.keys().chain(r.keys()).collect();
                    for slot in all_slots {
                        let z_val = z.get(slot);
                        let r_val = r.get(slot);
                        if z_val != r_val {
                            let zkevm_value = match z_val.map(hex::encode) {
                                Some(value) => value,
                                None => String::new(),
                            };
                            let reference_value = match r_val.map(hex::encode) {
                                Some(value) => value,
                                None => String::new(),
                            };
                            differences.push(StateDifference {
                                description: "Storage slot value differs".to_string(),
                                zkevm_value,
                                reference_value,
                                location: Some(format!(
                                    "{}:{}",
                                    hex::encode(addr),
                                    hex::encode(slot)
                                )),
                            });
                        }
                    }
                }
                (Some(z), None) => {
                    for (slot, val) in z {
                        differences.push(StateDifference {
                            description: "Storage slot exists only in zkEVM".to_string(),
                            zkevm_value: hex::encode(val),
                            reference_value: String::new(),
                            location: Some(format!("{}:{}", hex::encode(addr), hex::encode(slot))),
                        });
                    }
                }
                (None, Some(r)) => {
                    for (slot, val) in r {
                        differences.push(StateDifference {
                            description: "Storage slot exists only in reference".to_string(),
                            zkevm_value: String::new(),
                            reference_value: hex::encode(val),
                            location: Some(format!("{}:{}", hex::encode(addr), hex::encode(slot))),
                        });
                    }
                }
                (None, None) => {}
            }
        }

        differences
    }

    /// Compare logs
    fn compare_logs(&self, zkevm: &[EvmLog], reference: &[EvmLog]) -> Vec<StateDifference> {
        let mut differences = vec![];

        if zkevm.len() != reference.len() {
            differences.push(StateDifference {
                description: "Number of logs differs".to_string(),
                zkevm_value: zkevm.len().to_string(),
                reference_value: reference.len().to_string(),
                location: None,
            });
            return differences;
        }

        for (i, (z, r)) in zkevm.iter().zip(reference.iter()).enumerate() {
            if z.address != r.address {
                differences.push(StateDifference {
                    description: format!("Log {} address differs", i),
                    zkevm_value: hex::encode(z.address),
                    reference_value: hex::encode(r.address),
                    location: Some(format!("log_{}", i)),
                });
            }
            if z.topics != r.topics {
                differences.push(StateDifference {
                    description: format!("Log {} topics differ", i),
                    zkevm_value: z
                        .topics
                        .iter()
                        .map(hex::encode)
                        .collect::<Vec<_>>()
                        .join(","),
                    reference_value: r
                        .topics
                        .iter()
                        .map(hex::encode)
                        .collect::<Vec<_>>()
                        .join(","),
                    location: Some(format!("log_{}", i)),
                });
            }
            if z.data != r.data {
                differences.push(StateDifference {
                    description: format!("Log {} data differs", i),
                    zkevm_value: hex::encode(&z.data),
                    reference_value: hex::encode(&r.data),
                    location: Some(format!("log_{}", i)),
                });
            }
        }

        differences
    }

    /// Classify the type of mismatch
    fn classify_mismatch(&self, differences: &[StateDifference]) -> MismatchType {
        // Priority order for classification
        for diff in differences {
            if diff.description.contains("Execution outcome") {
                return MismatchType::OutcomeMismatch;
            }
        }
        for diff in differences {
            if diff.description.contains("State root") {
                return MismatchType::StateRootMismatch;
            }
        }
        for diff in differences {
            if diff.description.contains("Storage") {
                return MismatchType::StorageMismatch;
            }
        }
        for diff in differences {
            if diff.description.contains("Return data") {
                return MismatchType::ReturnDataMismatch;
            }
        }
        for diff in differences {
            if diff.description.contains("Gas") {
                return MismatchType::GasMismatch;
            }
        }
        for diff in differences {
            if diff.description.contains("Log") {
                return MismatchType::LogsMismatch;
            }
        }

        MismatchType::AccountMismatch
    }

    /// Classify severity based on mismatch type
    fn classify_severity(
        &self,
        mismatch_type: &MismatchType,
        _differences: &[StateDifference],
    ) -> Severity {
        match mismatch_type {
            MismatchType::OutcomeMismatch => Severity::Critical,
            MismatchType::StateRootMismatch => Severity::Critical,
            MismatchType::StorageMismatch => Severity::High,
            MismatchType::ReturnDataMismatch => Severity::High,
            MismatchType::LogsMismatch => Severity::Medium,
            MismatchType::AccountMismatch => Severity::Medium,
            MismatchType::GasMismatch => Severity::Low,
        }
    }

    /// Get all findings
    pub fn findings(&self) -> &[DifferentialFinding] {
        &self.findings
    }

    /// Get statistics
    pub fn stats(&self) -> &DifferentialStats {
        &self.stats
    }

    /// Reset the tester
    pub fn reset(&mut self) {
        self.findings.clear();
        self.stats = DifferentialStats::default();
    }
}

impl DifferentialFinding {
    /// Convert to a generic Finding
    pub fn to_finding(&self) -> Finding {
        Finding {
            attack_type: AttackType::Underconstrained,
            description: format!(
                "zkEVM differential testing found {}: {}",
                self.mismatch_type.as_str(),
                match self.differences.first().map(|d| d.description.as_str()) {
                    Some(value) => value,
                    None => "unknown difference",
                }
            ),
            severity: self.severity,
            poc: zk_core::ProofOfConcept {
                witness_a: vec![],
                witness_b: None,
                public_inputs: Vec::new(),
                proof: None,
            },
            location: Some(format!(
                "tx_from={}, mismatch={}",
                hex::encode(self.transaction.from),
                self.mismatch_type.as_str()
            )),
        }
    }
}

// ============================================================================
// Precompile Testing
// ============================================================================

/// Standard precompile addresses
pub mod precompiles {
    /// ECRECOVER (0x01)
    pub const ECRECOVER: [u8; 20] = {
        let mut addr = [0u8; 20];
        addr[19] = 0x01;
        addr
    };

    /// SHA256 (0x02)
    pub const SHA256: [u8; 20] = {
        let mut addr = [0u8; 20];
        addr[19] = 0x02;
        addr
    };

    /// RIPEMD160 (0x03)
    pub const RIPEMD160: [u8; 20] = {
        let mut addr = [0u8; 20];
        addr[19] = 0x03;
        addr
    };

    /// IDENTITY (0x04)
    pub const IDENTITY: [u8; 20] = {
        let mut addr = [0u8; 20];
        addr[19] = 0x04;
        addr
    };

    /// MODEXP (0x05)
    pub const MODEXP: [u8; 20] = {
        let mut addr = [0u8; 20];
        addr[19] = 0x05;
        addr
    };

    /// ECADD (0x06)
    pub const ECADD: [u8; 20] = {
        let mut addr = [0u8; 20];
        addr[19] = 0x06;
        addr
    };

    /// ECMUL (0x07)
    pub const ECMUL: [u8; 20] = {
        let mut addr = [0u8; 20];
        addr[19] = 0x07;
        addr
    };

    /// ECPAIRING (0x08)
    pub const ECPAIRING: [u8; 20] = {
        let mut addr = [0u8; 20];
        addr[19] = 0x08;
        addr
    };

    /// BLAKE2F (0x09)
    pub const BLAKE2F: [u8; 20] = {
        let mut addr = [0u8; 20];
        addr[19] = 0x09;
        addr
    };
}

/// Generator for precompile edge case tests
pub struct PrecompileTestGenerator;

impl PrecompileTestGenerator {
    pub fn new(_seed: u64) -> Self {
        Self
    }

    /// Generate edge case tests for ECRECOVER
    pub fn ecrecover_edge_cases(&self) -> Vec<TestTransaction> {
        let mut tests = vec![];

        // Test with invalid signature (v = 0)
        tests.push(self.make_precompile_call(precompiles::ECRECOVER, vec![0u8; 128]));

        // Test with max r value
        let mut max_r = vec![0u8; 128];
        max_r[32..64].fill(0xff);
        tests.push(self.make_precompile_call(precompiles::ECRECOVER, max_r));

        // Test with max s value
        let mut max_s = vec![0u8; 128];
        max_s[64..96].fill(0xff);
        tests.push(self.make_precompile_call(precompiles::ECRECOVER, max_s));

        tests
    }

    /// Generate edge case tests for MODEXP
    pub fn modexp_edge_cases(&self) -> Vec<TestTransaction> {
        let mut tests = vec![];

        // Zero exponent
        let zero_exp = vec![
            0, 0, 0, 0, 0, 0, 0, 32, // base length
            0, 0, 0, 0, 0, 0, 0, 0, // exp length (0)
            0, 0, 0, 0, 0, 0, 0, 32, // mod length
        ];
        tests.push(self.make_precompile_call(precompiles::MODEXP, zero_exp));

        // Very large base length
        let large_base = vec![
            0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, // base length (huge)
            0, 0, 0, 0, 0, 0, 0, 1, // exp length
            0, 0, 0, 0, 0, 0, 0, 32, // mod length
        ];
        tests.push(self.make_precompile_call(precompiles::MODEXP, large_base));

        tests
    }

    /// Generate edge case tests for ECPAIRING
    pub fn ecpairing_edge_cases(&self) -> Vec<TestTransaction> {
        let mut tests = vec![];

        // Empty input
        tests.push(self.make_precompile_call(precompiles::ECPAIRING, vec![]));

        // Invalid point (not on curve)
        let invalid_point = vec![1u8; 192];
        tests.push(self.make_precompile_call(precompiles::ECPAIRING, invalid_point));

        // Point at infinity
        let infinity = vec![0u8; 192];
        tests.push(self.make_precompile_call(precompiles::ECPAIRING, infinity));

        tests
    }

    fn make_precompile_call(&self, to: [u8; 20], data: Vec<u8>) -> TestTransaction {
        TestTransaction {
            from: [0u8; 20],
            to: Some(to),
            value: [0u8; 32],
            data,
            gas_limit: 1_000_000,
            gas_price: [0u8; 32],
            nonce: 0,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_differential_tester_creation() {
        let config = ZkEvmDifferentialConfig::default();
        let tester = ZkEvmDifferentialTester::new(config);
        assert_eq!(tester.stats().total_tests, 0);
    }

    #[test]
    fn test_mismatch_type_classification() {
        let config = ZkEvmDifferentialConfig::default();
        let tester = ZkEvmDifferentialTester::new(config);

        let outcome_diff = vec![StateDifference {
            description: "Execution outcome differs".to_string(),
            zkevm_value: "true".to_string(),
            reference_value: "false".to_string(),
            location: None,
        }];
        assert_eq!(
            tester.classify_mismatch(&outcome_diff),
            MismatchType::OutcomeMismatch
        );

        let storage_diff = vec![StateDifference {
            description: "Storage slot value differs".to_string(),
            zkevm_value: "0x01".to_string(),
            reference_value: "0x02".to_string(),
            location: Some("addr:slot".to_string()),
        }];
        assert_eq!(
            tester.classify_mismatch(&storage_diff),
            MismatchType::StorageMismatch
        );
    }

    #[test]
    fn test_precompile_addresses() {
        assert_eq!(precompiles::ECRECOVER[19], 0x01);
        assert_eq!(precompiles::SHA256[19], 0x02);
        assert_eq!(precompiles::ECPAIRING[19], 0x08);
    }

    #[test]
    fn test_precompile_generator() {
        let generator = PrecompileTestGenerator::new(42);
        let ecrecover_tests = generator.ecrecover_edge_cases();
        assert!(!ecrecover_tests.is_empty());
        assert_eq!(ecrecover_tests[0].to, Some(precompiles::ECRECOVER));
    }

    #[test]
    fn test_severity_classification() {
        let config = ZkEvmDifferentialConfig::default();
        let tester = ZkEvmDifferentialTester::new(config);

        assert_eq!(
            tester.classify_severity(&MismatchType::OutcomeMismatch, &[]),
            Severity::Critical
        );
        assert_eq!(
            tester.classify_severity(&MismatchType::StorageMismatch, &[]),
            Severity::High
        );
        assert_eq!(
            tester.classify_severity(&MismatchType::GasMismatch, &[]),
            Severity::Low
        );
    }
}
