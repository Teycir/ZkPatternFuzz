//! Distributed Fuzzing Coordinator
//!
//! Manages work distribution, load balancing, and result aggregation.

use super::{
    ClusterStats, DistributedConfig, DistributedMessage, NodeCapabilities, NodeId, NodeStats,
    SerializableCorpusEntry, WorkResults, WorkUnitId,
};
use super::corpus_sync::GlobalCorpusManager;
use crate::config::FuzzConfig;
use crate::fuzzer::Finding;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Status of a worker node
#[derive(Debug, Clone)]
pub enum NodeStatus {
    /// Node is idle and ready for work
    Idle,
    /// Node is working on a task
    Working { work_unit_id: WorkUnitId },
    /// Node is syncing corpus
    Syncing,
    /// Node is disconnected
    Disconnected,
    /// Node has failed
    Failed { reason: String },
}

/// A unit of work to be distributed
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkUnit {
    /// Unique identifier
    pub id: WorkUnitId,
    /// Attack type to run
    pub attack_type: String,
    /// Number of iterations
    pub iterations: usize,
    /// Seed test cases to use
    pub seeds: Vec<SerializableCorpusEntry>,
    /// Configuration overrides
    pub config: serde_yaml::Value,
    /// Priority (higher = more important)
    pub priority: i32,
    /// Creation timestamp (for timeout)
    pub created_at: u64,
}

impl WorkUnit {
    pub fn new(id: WorkUnitId, attack_type: &str, iterations: usize) -> Self {
        Self {
            id,
            attack_type: attack_type.to_string(),
            iterations,
            seeds: Vec::new(),
            config: serde_yaml::Value::Null,
            priority: 0,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    pub fn with_seeds(mut self, seeds: Vec<SerializableCorpusEntry>) -> Self {
        self.seeds = seeds;
        self
    }

    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }
}

/// Information about a connected worker
#[derive(Debug, Clone)]
struct WorkerInfo {
    status: NodeStatus,
    last_heartbeat: Instant,
    stats: NodeStats,
    work_history: Vec<WorkUnitId>,
}

/// Distributed fuzzing coordinator
pub struct DistributedCoordinator {
    /// Configuration
    config: DistributedConfig,
    /// Fuzzing campaign configuration
    fuzz_config: Option<FuzzConfig>,
    /// Connected workers
    workers: Arc<RwLock<HashMap<NodeId, WorkerInfo>>>,
    /// Work queue
    work_queue: Arc<RwLock<VecDeque<WorkUnit>>>,
    /// Completed work units
    completed_work: Arc<RwLock<Vec<(WorkUnitId, WorkResults)>>>,
    /// Active work assignments
    active_work: Arc<RwLock<HashMap<WorkUnitId, NodeId>>>,
    /// Global corpus manager
    corpus_manager: Arc<RwLock<GlobalCorpusManager>>,
    /// All findings
    findings: Arc<RwLock<Vec<Finding>>>,
    /// Global coverage bitmap
    global_coverage: Arc<RwLock<Vec<u8>>>,
    /// Next work unit ID
    next_work_id: Arc<RwLock<WorkUnitId>>,
    /// Statistics
    stats: Arc<RwLock<ClusterStats>>,
    /// Start time
    start_time: Instant,
}

impl DistributedCoordinator {
    pub fn new(config: DistributedConfig) -> Self {
        Self {
            config,
            fuzz_config: None,
            workers: Arc::new(RwLock::new(HashMap::new())),
            work_queue: Arc::new(RwLock::new(VecDeque::new())),
            completed_work: Arc::new(RwLock::new(Vec::new())),
            active_work: Arc::new(RwLock::new(HashMap::new())),
            corpus_manager: Arc::new(RwLock::new(GlobalCorpusManager::new())),
            findings: Arc::new(RwLock::new(Vec::new())),
            global_coverage: Arc::new(RwLock::new(Vec::new())),
            next_work_id: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(ClusterStats::default())),
            start_time: Instant::now(),
        }
    }

    pub fn with_fuzz_config(mut self, config: FuzzConfig) -> Self {
        self.fuzz_config = Some(config);
        self
    }

    /// Handle a message from a worker
    pub fn handle_message(&self, message: DistributedMessage) -> Option<DistributedMessage> {
        match message {
            DistributedMessage::Register {
                node_id,
                role: _,
                capabilities,
            } => {
                self.register_worker(node_id.clone(), capabilities);
                Some(DistributedMessage::Heartbeat {
                    node_id: "coordinator".to_string(),
                    stats: NodeStats::default(),
                })
            }

            DistributedMessage::Heartbeat { node_id, stats } => {
                self.update_worker_stats(&node_id, stats);
                None
            }

            DistributedMessage::RequestWork { node_id } => {
                self.assign_work(&node_id).map(|wu| DistributedMessage::AssignWork { work_unit: wu })
            }

            DistributedMessage::WorkComplete {
                node_id,
                work_unit_id,
                results,
            } => {
                self.handle_work_completion(&node_id, work_unit_id, results);
                None
            }

            DistributedMessage::ShareCorpus { entries } => {
                // Infer node_id from context or require it
                self.handle_corpus_share("unknown", entries);
                None
            }

            DistributedMessage::ReportFinding { node_id: _, finding } => {
                self.findings.write().unwrap().push(finding);
                None
            }

            DistributedMessage::CoverageUpdate {
                node_id,
                coverage_bitmap,
            } => {
                self.merge_coverage(&node_id, &coverage_bitmap);
                None
            }

            _ => None,
        }
    }

    /// Register a new worker
    fn register_worker(&self, node_id: NodeId, _capabilities: NodeCapabilities) {
        let worker = WorkerInfo {
            status: NodeStatus::Idle,
            last_heartbeat: Instant::now(),
            stats: NodeStats::default(),
            work_history: Vec::new(),
        };

        self.workers.write().unwrap().insert(node_id, worker);
        self.update_cluster_stats();

        tracing::info!("Worker registered, total workers: {}", self.workers.read().unwrap().len());
    }

    /// Update worker statistics
    fn update_worker_stats(&self, node_id: &str, stats: NodeStats) {
        if let Some(worker) = self.workers.write().unwrap().get_mut(node_id) {
            worker.last_heartbeat = Instant::now();
            worker.stats = stats;
        }
        self.update_cluster_stats();
    }

    /// Assign work to a worker
    fn assign_work(&self, node_id: &str) -> Option<WorkUnit> {
        // Check if worker exists and is idle
        {
            let workers = self.workers.read().unwrap();
            let worker = workers.get(node_id)?;
            if !matches!(worker.status, NodeStatus::Idle) {
                return None;
            }
        }

        // Get next work unit from queue
        let work_unit = self.work_queue.write().unwrap().pop_front()?;

        // Mark worker as working
        if let Some(worker) = self.workers.write().unwrap().get_mut(node_id) {
            worker.status = NodeStatus::Working {
                work_unit_id: work_unit.id,
            };
        }

        // Track active work
        self.active_work
            .write()
            .unwrap()
            .insert(work_unit.id, node_id.to_string());

        tracing::debug!("Assigned work unit {} to {}", work_unit.id, node_id);

        Some(work_unit)
    }

    /// Handle work completion from a worker
    fn handle_work_completion(&self, node_id: &str, work_unit_id: WorkUnitId, results: WorkResults) {
        // Update worker status
        if let Some(worker) = self.workers.write().unwrap().get_mut(node_id) {
            worker.status = NodeStatus::Idle;
            worker.work_history.push(work_unit_id);
        }

        // Remove from active work
        self.active_work.write().unwrap().remove(&work_unit_id);

        // Process results
        self.process_work_results(node_id, work_unit_id, &results);

        // Store completion
        self.completed_work
            .write()
            .unwrap()
            .push((work_unit_id, results));

        self.update_cluster_stats();
    }

    /// Process results from a work unit
    fn process_work_results(&self, node_id: &str, _work_unit_id: WorkUnitId, results: &WorkResults) {
        // Add findings
        for finding in &results.findings {
            self.findings.write().unwrap().push(finding.clone());
        }

        // Add corpus entries
        if !results.interesting_cases.is_empty() {
            self.handle_corpus_share(node_id, results.interesting_cases.clone());
        }

        // Merge coverage
        if !results.coverage_delta.is_empty() {
            self.merge_coverage(node_id, &results.coverage_delta);
        }
    }

    /// Handle corpus sharing from a worker
    fn handle_corpus_share(&self, node_id: &str, entries: Vec<SerializableCorpusEntry>) {
        let corpus_entries: Vec<_> = entries
            .iter()
            .filter_map(|e| e.to_corpus_entry())
            .collect();

        self.corpus_manager
            .write()
            .unwrap()
            .add_from_node(node_id, corpus_entries);
    }

    /// Merge coverage from a worker
    fn merge_coverage(&self, _node_id: &str, bitmap: &[u8]) {
        let mut global = self.global_coverage.write().unwrap();

        // Resize if needed
        if global.len() < bitmap.len() {
            global.resize(bitmap.len(), 0);
        }

        // OR the bitmaps together
        for (i, &byte) in bitmap.iter().enumerate() {
            if i < global.len() {
                global[i] |= byte;
            }
        }
    }

    /// Add work to the queue
    pub fn add_work(&self, work_unit: WorkUnit) {
        self.work_queue.write().unwrap().push_back(work_unit);
    }

    /// Generate work units from campaign configuration
    pub fn generate_work_from_config(&self) -> Vec<WorkUnit> {
        let Some(ref config) = self.fuzz_config else {
            return Vec::new();
        };

        let mut work_units = Vec::new();
        let mut next_id = *self.next_work_id.read().unwrap();

        for attack in &config.attacks {
            // Split attack into multiple work units based on iterations
            let iterations = attack
                .config
                .get("iterations")
                .and_then(|v| v.as_u64())
                .unwrap_or(1000) as usize;

            let unit_size = self.config.work_unit_size;
            let num_units = (iterations + unit_size - 1) / unit_size;

            for i in 0..num_units {
                let unit_iterations = if i == num_units - 1 {
                    iterations - (i * unit_size)
                } else {
                    unit_size
                };

                let work_unit = WorkUnit::new(
                    next_id,
                    &format!("{:?}", attack.attack_type),
                    unit_iterations,
                )
                .with_priority(i as i32);

                work_units.push(work_unit);
                next_id += 1;
            }
        }

        *self.next_work_id.write().unwrap() = next_id;

        // Add to queue
        for unit in &work_units {
            self.add_work(unit.clone());
        }

        work_units
    }

    /// Update cluster statistics
    fn update_cluster_stats(&self) {
        let workers = self.workers.read().unwrap();
        let mut stats = ClusterStats::default();

        stats.total_nodes = workers.len();
        stats.active_nodes = workers
            .values()
            .filter(|w| !matches!(w.status, NodeStatus::Disconnected | NodeStatus::Failed { .. }))
            .count();

        for worker in workers.values() {
            stats.total_executions += worker.stats.executions;
            stats.combined_exec_per_second += worker.stats.exec_per_second;
        }

        stats.total_findings = self.findings.read().unwrap().len();
        stats.global_corpus_size = self.corpus_manager.read().unwrap().stats().unique_entries;

        // Calculate global coverage
        let coverage = self.global_coverage.read().unwrap();
        if !coverage.is_empty() {
            let total_bits = coverage.len() * 8;
            let set_bits: usize = coverage.iter().map(|b| b.count_ones() as usize).sum();
            stats.global_coverage = (set_bits as f64 / total_bits as f64) * 100.0;
        }

        *self.stats.write().unwrap() = stats;
    }

    /// Check for and handle timed-out workers
    pub fn check_timeouts(&self) {
        let timeout = self.config.node_timeout;
        let mut workers = self.workers.write().unwrap();
        let mut timed_out = Vec::new();

        for (node_id, worker) in workers.iter_mut() {
            if worker.last_heartbeat.elapsed() > timeout {
                worker.status = NodeStatus::Disconnected;
                timed_out.push(node_id.clone());
            }
        }

        drop(workers);

        // Reassign work from timed-out workers
        for node_id in timed_out {
            self.reassign_work_from_node(&node_id);
        }
    }

    /// Reassign work from a failed node
    fn reassign_work_from_node(&self, node_id: &str) {
        let mut active = self.active_work.write().unwrap();
        let to_reassign: Vec<WorkUnitId> = active
            .iter()
            .filter(|(_, assigned)| *assigned == node_id)
            .map(|(id, _)| *id)
            .collect();

        for work_id in to_reassign {
            active.remove(&work_id);
            // TODO: Re-queue the work unit (need to store work units somewhere)
            tracing::warn!("Work unit {} from {} needs reassignment", work_id, node_id);
        }
    }

    /// Get cluster statistics
    pub fn stats(&self) -> ClusterStats {
        self.stats.read().unwrap().clone()
    }

    /// Get all findings
    pub fn findings(&self) -> Vec<Finding> {
        self.findings.read().unwrap().clone()
    }

    /// Get global corpus
    pub fn global_corpus(&self) -> Vec<SerializableCorpusEntry> {
        self.corpus_manager
            .read()
            .unwrap()
            .global_corpus()
            .iter()
            .map(SerializableCorpusEntry::from)
            .collect()
    }

    /// Get number of connected workers
    pub fn worker_count(&self) -> usize {
        self.workers.read().unwrap().len()
    }

    /// Get pending work count
    pub fn pending_work_count(&self) -> usize {
        self.work_queue.read().unwrap().len()
    }

    /// Get runtime duration
    pub fn runtime(&self) -> Duration {
        self.start_time.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coordinator_creation() {
        let config = DistributedConfig::default();
        let coordinator = DistributedCoordinator::new(config);
        assert_eq!(coordinator.worker_count(), 0);
    }

    #[test]
    fn test_work_unit_creation() {
        let work = WorkUnit::new(1, "underconstrained", 1000);
        assert_eq!(work.id, 1);
        assert_eq!(work.iterations, 1000);
    }

    #[test]
    fn test_worker_registration() {
        let config = DistributedConfig::default();
        let coordinator = DistributedCoordinator::new(config);

        let msg = DistributedMessage::Register {
            node_id: "test-worker".to_string(),
            role: super::super::network::NodeRole::Worker,
            capabilities: NodeCapabilities::default(),
        };

        coordinator.handle_message(msg);
        assert_eq!(coordinator.worker_count(), 1);
    }
}
