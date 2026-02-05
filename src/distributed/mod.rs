//! Distributed Fuzzing with Corpus Sharing
//!
//! Enables distributed fuzzing across multiple machines with:
//! - Network-based corpus synchronization
//! - Work distribution and load balancing
//! - Centralized coverage tracking
//! - Fault-tolerant node management

pub mod network;
pub mod corpus_sync;
pub mod coordinator;

pub use network::{NetworkConfig, NodeRole, FuzzerNode};
pub use corpus_sync::{CorpusSyncManager, SyncStrategy};
pub use coordinator::{DistributedCoordinator, WorkUnit, NodeStatus};

use crate::corpus::CorpusEntry;
use crate::fuzzer::{Finding, FieldElement, TestCase};
use std::time::Duration;

/// Unique identifier for a fuzzer node
pub type NodeId = String;

/// Unique identifier for a work unit
pub type WorkUnitId = u64;

/// Message types for distributed communication
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum DistributedMessage {
    /// Node registration with coordinator
    Register {
        node_id: NodeId,
        role: NodeRole,
        capabilities: NodeCapabilities,
    },
    /// Heartbeat to indicate node is alive
    Heartbeat {
        node_id: NodeId,
        stats: NodeStats,
    },
    /// Request work from coordinator
    RequestWork {
        node_id: NodeId,
    },
    /// Work assignment from coordinator
    AssignWork {
        work_unit: WorkUnit,
    },
    /// Report work completion
    WorkComplete {
        node_id: NodeId,
        work_unit_id: WorkUnitId,
        results: WorkResults,
    },
    /// Share interesting corpus entries
    ShareCorpus {
        entries: Vec<SerializableCorpusEntry>,
    },
    /// Report a finding
    ReportFinding {
        node_id: NodeId,
        finding: Finding,
    },
    /// Coverage update
    CoverageUpdate {
        node_id: NodeId,
        coverage_bitmap: Vec<u8>,
    },
    /// Shutdown signal
    Shutdown,
}

/// Node capabilities for work distribution
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeCapabilities {
    /// Number of worker threads
    pub worker_count: usize,
    /// Available memory in bytes
    pub memory_bytes: u64,
    /// Supported frameworks
    pub frameworks: Vec<String>,
    /// Has GPU acceleration
    pub has_gpu: bool,
}

impl Default for NodeCapabilities {
    fn default() -> Self {
        Self {
            worker_count: std::thread::available_parallelism()
                .map(|count| count.get())
                .unwrap_or(1),
            memory_bytes: 8 * 1024 * 1024 * 1024, // 8GB default
            frameworks: vec!["mock".to_string()],
            has_gpu: false,
        }
    }
}

/// Statistics from a node
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NodeStats {
    /// Total executions performed
    pub executions: u64,
    /// Executions per second
    pub exec_per_second: f64,
    /// Unique coverage found
    pub coverage_count: usize,
    /// Findings discovered
    pub findings_count: usize,
    /// Corpus size
    pub corpus_size: usize,
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Memory usage in bytes
    pub memory_usage: u64,
}

/// Results from a work unit
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkResults {
    /// Executions performed
    pub executions: u64,
    /// New coverage discovered
    pub new_coverage: bool,
    /// Interesting test cases found
    pub interesting_cases: Vec<SerializableCorpusEntry>,
    /// Findings discovered
    pub findings: Vec<Finding>,
    /// Coverage delta (serialized bitmap)
    pub coverage_delta: Vec<u8>,
}

/// Serializable corpus entry for network transfer
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SerializableCorpusEntry {
    /// Input field elements (hex encoded)
    pub inputs: Vec<String>,
    /// Coverage hash
    pub coverage_hash: u64,
    /// Whether it discovered new coverage
    pub discovered_new_coverage: bool,
    /// Energy level
    pub energy: usize,
}

impl From<&CorpusEntry> for SerializableCorpusEntry {
    fn from(entry: &CorpusEntry) -> Self {
        Self {
            inputs: entry.test_case.inputs.iter().map(|fe| fe.to_hex()).collect(),
            coverage_hash: entry.coverage_hash,
            discovered_new_coverage: entry.discovered_new_coverage,
            energy: entry.energy,
        }
    }
}

impl SerializableCorpusEntry {
    pub fn to_corpus_entry(&self) -> Option<CorpusEntry> {
        let inputs: Result<Vec<FieldElement>, _> = self
            .inputs
            .iter()
            .map(|hex| FieldElement::from_hex(hex))
            .collect();

        inputs.ok().map(|inputs| {
            let test_case = TestCase {
                inputs,
                expected_output: None,
                metadata: Default::default(),
            };
            let mut entry = CorpusEntry::new(test_case, self.coverage_hash);
            entry.energy = self.energy;
            if self.discovered_new_coverage {
                entry = entry.with_new_coverage();
            }
            entry
        })
    }
}

/// Configuration for distributed fuzzing
#[derive(Debug, Clone)]
pub struct DistributedConfig {
    /// Coordinator address
    pub coordinator_addr: String,
    /// Port for communication
    pub port: u16,
    /// Heartbeat interval
    pub heartbeat_interval: Duration,
    /// Corpus sync interval
    pub sync_interval: Duration,
    /// Maximum nodes
    pub max_nodes: usize,
    /// Work unit size (number of test cases)
    pub work_unit_size: usize,
    /// Enable compression for network transfer
    pub compression: bool,
    /// Node timeout before considered dead
    pub node_timeout: Duration,
}

impl Default for DistributedConfig {
    fn default() -> Self {
        Self {
            coordinator_addr: "127.0.0.1".to_string(),
            port: 9527,
            heartbeat_interval: Duration::from_secs(5),
            sync_interval: Duration::from_secs(30),
            max_nodes: 100,
            work_unit_size: 1000,
            compression: true,
            node_timeout: Duration::from_secs(60),
        }
    }
}

/// Statistics for the distributed fuzzing cluster
#[derive(Debug, Clone, Default)]
pub struct ClusterStats {
    /// Total nodes in cluster
    pub total_nodes: usize,
    /// Active nodes
    pub active_nodes: usize,
    /// Total executions across cluster
    pub total_executions: u64,
    /// Combined executions per second
    pub combined_exec_per_second: f64,
    /// Global coverage percentage
    pub global_coverage: f64,
    /// Total findings across cluster
    pub total_findings: usize,
    /// Global corpus size
    pub global_corpus_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_capabilities_default() {
        let caps = NodeCapabilities::default();
        assert!(caps.worker_count > 0);
        assert!(caps.memory_bytes > 0);
    }

    #[test]
    fn test_serializable_corpus_entry() {
        let entry = SerializableCorpusEntry {
            inputs: vec!["0x01".to_string(), "0x02".to_string()],
            coverage_hash: 12345,
            discovered_new_coverage: true,
            energy: 50,
        };

        let corpus_entry = entry.to_corpus_entry();
        assert!(corpus_entry.is_some());
    }
}
