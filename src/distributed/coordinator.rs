//! Distributed Fuzzing Coordinator
//!
//! Manages work distribution, load balancing, and result aggregation.

use super::corpus_sync::GlobalCorpusManager;
use super::{
    ClusterStats, DistributedConfig, DistributedMessage, NodeCapabilities, NodeId, NodeStats,
    SerializableCorpusEntry, WorkResults, WorkUnitId,
};
use crate::config::FuzzConfig;
use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};
use zk_core::Finding;

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
    fn read_lock<'a, T>(&self, lock: &'a RwLock<T>, name: &str) -> Result<RwLockReadGuard<'a, T>> {
        lock.read()
            .map_err(|e| anyhow::anyhow!("{} lock poisoned (read): {}", name, e))
    }

    fn write_lock<'a, T>(
        &self,
        lock: &'a RwLock<T>,
        name: &str,
    ) -> Result<RwLockWriteGuard<'a, T>> {
        lock.write()
            .map_err(|e| anyhow::anyhow!("{} lock poisoned (write): {}", name, e))
    }

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
    pub fn handle_message(
        &self,
        message: DistributedMessage,
    ) -> Result<Option<DistributedMessage>> {
        match message {
            DistributedMessage::Register {
                node_id,
                role: _,
                capabilities,
            } => {
                self.register_worker(node_id.clone(), capabilities)?;
                Ok(Some(DistributedMessage::Heartbeat {
                    node_id: "coordinator".to_string(),
                    stats: NodeStats::default(),
                }))
            }

            DistributedMessage::Heartbeat { node_id, stats } => {
                self.update_worker_stats(&node_id, stats)?;
                Ok(None)
            }

            DistributedMessage::RequestWork { node_id } => Ok(self
                .assign_work(&node_id)?
                .map(|wu| DistributedMessage::AssignWork { work_unit: wu })),

            DistributedMessage::WorkComplete {
                node_id,
                work_unit_id,
                results,
            } => {
                self.handle_work_completion(&node_id, work_unit_id, results)?;
                Ok(None)
            }

            DistributedMessage::ShareCorpus { entries } => {
                // Infer node_id from context or require it
                self.handle_corpus_share("unknown", entries)?;
                Ok(None)
            }

            DistributedMessage::ReportFinding {
                node_id: _,
                finding,
            } => {
                self.write_lock(&self.findings, "findings")?.push(finding);
                Ok(None)
            }

            DistributedMessage::CoverageUpdate {
                node_id,
                coverage_bitmap,
            } => {
                self.merge_coverage(&node_id, &coverage_bitmap)?;
                Ok(None)
            }

            _ => Ok(None),
        }
    }

    /// Register a new worker
    fn register_worker(&self, node_id: NodeId, _capabilities: NodeCapabilities) -> Result<()> {
        let worker = WorkerInfo {
            status: NodeStatus::Idle,
            last_heartbeat: Instant::now(),
            stats: NodeStats::default(),
            work_history: Vec::new(),
        };

        self.write_lock(&self.workers, "workers")?
            .insert(node_id, worker);
        self.update_cluster_stats()?;

        tracing::info!(
            "Worker registered, total workers: {}",
            self.read_lock(&self.workers, "workers")?.len()
        );
        Ok(())
    }

    /// Update worker statistics
    fn update_worker_stats(&self, node_id: &str, stats: NodeStats) -> Result<()> {
        if let Some(worker) = self.write_lock(&self.workers, "workers")?.get_mut(node_id) {
            worker.last_heartbeat = Instant::now();
            worker.stats = stats;
        }
        self.update_cluster_stats()?;
        Ok(())
    }

    /// Assign work to a worker
    fn assign_work(&self, node_id: &str) -> Result<Option<WorkUnit>> {
        // Check if worker exists and is idle
        {
            let workers = self.read_lock(&self.workers, "workers")?;
            let Some(worker) = workers.get(node_id) else {
                return Ok(None);
            };
            if !matches!(worker.status, NodeStatus::Idle) {
                return Ok(None);
            }
        }

        // Get next work unit from queue
        let Some(work_unit) = self.write_lock(&self.work_queue, "work_queue")?.pop_front() else {
            return Ok(None);
        };

        // Mark worker as working
        if let Some(worker) = self.write_lock(&self.workers, "workers")?.get_mut(node_id) {
            worker.status = NodeStatus::Working {
                work_unit_id: work_unit.id,
            };
        }

        // Track active work
        self.write_lock(&self.active_work, "active_work")?
            .insert(work_unit.id, node_id.to_string());

        tracing::debug!("Assigned work unit {} to {}", work_unit.id, node_id);

        Ok(Some(work_unit))
    }

    /// Handle work completion from a worker
    fn handle_work_completion(
        &self,
        node_id: &str,
        work_unit_id: WorkUnitId,
        results: WorkResults,
    ) -> Result<()> {
        // Update worker status
        if let Some(worker) = self.write_lock(&self.workers, "workers")?.get_mut(node_id) {
            worker.status = NodeStatus::Idle;
            worker.work_history.push(work_unit_id);
        }

        // Remove from active work
        self.write_lock(&self.active_work, "active_work")?
            .remove(&work_unit_id);

        // Process results
        self.process_work_results(node_id, work_unit_id, &results)?;

        // Store completion
        self.write_lock(&self.completed_work, "completed_work")?
            .push((work_unit_id, results));

        self.update_cluster_stats()?;
        Ok(())
    }

    /// Process results from a work unit
    fn process_work_results(
        &self,
        node_id: &str,
        _work_unit_id: WorkUnitId,
        results: &WorkResults,
    ) -> Result<()> {
        // Add findings
        if !results.findings.is_empty() {
            self.write_lock(&self.findings, "findings")?
                .extend(results.findings.clone());
        }

        // Add corpus entries
        if !results.interesting_cases.is_empty() {
            self.handle_corpus_share(node_id, results.interesting_cases.clone())?;
        }

        // Merge coverage
        if !results.coverage_delta.is_empty() {
            self.merge_coverage(node_id, &results.coverage_delta)?;
        }
        Ok(())
    }

    /// Handle corpus sharing from a worker
    fn handle_corpus_share(
        &self,
        node_id: &str,
        entries: Vec<SerializableCorpusEntry>,
    ) -> Result<()> {
        let corpus_entries: Vec<_> = entries.iter().filter_map(|e| e.to_corpus_entry()).collect();

        self.write_lock(&self.corpus_manager, "corpus_manager")?
            .add_from_node(node_id, corpus_entries);
        Ok(())
    }

    /// Merge coverage from a worker
    fn merge_coverage(&self, _node_id: &str, bitmap: &[u8]) -> Result<()> {
        let mut global = self.write_lock(&self.global_coverage, "global_coverage")?;

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
        Ok(())
    }

    /// Add work to the queue
    pub fn add_work(&self, work_unit: WorkUnit) -> Result<()> {
        self.write_lock(&self.work_queue, "work_queue")?
            .push_back(work_unit);
        Ok(())
    }

    /// Generate work units from campaign configuration
    pub fn generate_work_from_config(&self) -> Result<Vec<WorkUnit>> {
        let Some(ref config) = self.fuzz_config else {
            return Ok(Vec::new());
        };

        let mut work_units = Vec::new();
        let mut next_id = *self.read_lock(&self.next_work_id, "next_work_id")?;

        for attack in &config.attacks {
            // Split attack into multiple work units based on iterations
            let iterations = attack.config.get("iterations").and_then(|v| v.as_u64());
            let iterations = match iterations {
                Some(value) => value as usize,
                None => {
                    anyhow::bail!(
                        "Attack {:?} is missing required numeric 'iterations' in distributed mode",
                        attack.attack_type
                    );
                }
            };

            let unit_size = self.config.work_unit_size;
            let num_units = iterations.div_ceil(unit_size);

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

        *self.write_lock(&self.next_work_id, "next_work_id")? = next_id;

        // Add to queue
        for unit in &work_units {
            self.add_work(unit.clone())?;
        }

        Ok(work_units)
    }

    /// Update cluster statistics
    fn update_cluster_stats(&self) -> Result<()> {
        let workers = self.read_lock(&self.workers, "workers")?;

        let total_nodes = workers.len();
        let active_nodes = workers
            .values()
            .filter(|w| {
                !matches!(
                    w.status,
                    NodeStatus::Disconnected | NodeStatus::Failed { .. }
                )
            })
            .count();

        let mut total_executions = 0;
        let mut combined_exec_per_second = 0.0;
        for worker in workers.values() {
            total_executions += worker.stats.executions;
            combined_exec_per_second += worker.stats.exec_per_second;
        }

        let total_findings = self.read_lock(&self.findings, "findings")?.len();
        let global_corpus_size = self
            .read_lock(&self.corpus_manager, "corpus_manager")?
            .stats()
            .unique_entries;

        // Calculate global coverage
        let coverage = self.read_lock(&self.global_coverage, "global_coverage")?;
        let global_coverage = if !coverage.is_empty() {
            let total_bits = coverage.len() * 8;
            let set_bits: usize = coverage.iter().map(|b| b.count_ones() as usize).sum();
            (set_bits as f64 / total_bits as f64) * 100.0
        } else {
            0.0
        };

        *self.write_lock(&self.stats, "stats")? = ClusterStats {
            total_nodes,
            active_nodes,
            total_executions,
            combined_exec_per_second,
            total_findings,
            global_corpus_size,
            global_coverage,
            ..Default::default()
        };
        Ok(())
    }

    /// Check for and handle timed-out workers
    pub fn check_timeouts(&self) -> Result<()> {
        let timeout = self.config.node_timeout;
        let mut workers = self.write_lock(&self.workers, "workers")?;
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
            self.reassign_work_from_node(&node_id)?;
        }
        Ok(())
    }

    /// Reassign work from a failed / timed-out node.
    ///
    /// Any work units that were assigned to `node_id` are removed from the
    /// active-work map and pushed back onto the front of the work queue with
    /// elevated priority so they are picked up next.
    fn reassign_work_from_node(&self, node_id: &str) -> Result<()> {
        let mut active = self.write_lock(&self.active_work, "active_work")?;
        let to_reassign: Vec<WorkUnitId> = active
            .iter()
            .filter(|(_, assigned)| *assigned == node_id)
            .map(|(id, _)| *id)
            .collect();

        if to_reassign.is_empty() {
            return Ok(());
        }

        // Collect the completed set so we don't re-queue already-finished work.
        let completed: HashSet<WorkUnitId> = self
            .read_lock(&self.completed_work, "completed_work")?
            .iter()
            .map(|(id, _)| *id)
            .collect();

        let mut queue = self.write_lock(&self.work_queue, "work_queue")?;

        for work_id in &to_reassign {
            active.remove(work_id);

            if completed.contains(work_id) {
                tracing::debug!(
                    "Work unit {} from {} already completed, skipping requeue",
                    work_id,
                    node_id
                );
                continue;
            }

            // Re-create a minimal work unit and push to front of queue.
            let requeued = WorkUnit::new(*work_id, "requeued", 0).with_priority(i32::MAX); // highest priority
            queue.push_front(requeued);

            tracing::warn!(
                "Re-queued work unit {} (was assigned to disconnected node {})",
                work_id,
                node_id
            );
        }

        // Update stats
        let mut stats = self.write_lock(&self.stats, "stats")?;
        stats.requeued_work_units += to_reassign.len();
        Ok(())
    }

    /// Get cluster statistics
    pub fn stats(&self) -> Result<ClusterStats> {
        Ok(self.read_lock(&self.stats, "stats")?.clone())
    }

    /// Get all findings
    pub fn findings(&self) -> Result<Vec<Finding>> {
        Ok(self.read_lock(&self.findings, "findings")?.clone())
    }

    /// Get global corpus
    pub fn global_corpus(&self) -> Result<Vec<SerializableCorpusEntry>> {
        Ok(self
            .read_lock(&self.corpus_manager, "corpus_manager")?
            .global_corpus()
            .iter()
            .map(SerializableCorpusEntry::from)
            .collect())
    }

    /// Get number of connected workers
    pub fn worker_count(&self) -> Result<usize> {
        Ok(self.read_lock(&self.workers, "workers")?.len())
    }

    /// Get pending work count
    pub fn pending_work_count(&self) -> Result<usize> {
        Ok(self.read_lock(&self.work_queue, "work_queue")?.len())
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
        assert_eq!(coordinator.worker_count().expect("worker count failed"), 0);
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

        coordinator
            .handle_message(msg)
            .expect("message handling failed");
        assert_eq!(coordinator.worker_count().expect("worker count failed"), 1);
    }
}
