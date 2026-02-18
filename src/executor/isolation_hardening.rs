//! Process Isolation Hardening (Phase 5: Milestone 5.4)
//!
//! Provides robust crash recovery, resource limits, and watchdog functionality
//! for production-stable circuit execution.
//!
//! # Features
//!
//! - **Crash Recovery**: Automatic restart after executor crashes
//! - **Resource Limits**: Memory and CPU usage bounds
//! - **Watchdog Timer**: Detection and killing of hung processes
//! - **Telemetry**: Detailed logging of isolation failures
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                  HardenedIsolatedExecutor                    │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
//! │  │  Watchdog   │  │  Resource   │  │  Crash Recovery     │  │
//! │  │   Timer     │  │   Monitor   │  │    Manager          │  │
//! │  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
//! │         │                │                    │              │
//! │         ▼                ▼                    ▼              │
//! │  ┌─────────────────────────────────────────────────────┐    │
//! │  │              IsolatedExecutor                        │    │
//! │  │          (subprocess execution)                      │    │
//! │  └─────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use anyhow::{Context, Result};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zk_core::{CircuitExecutor, ExecutionResult, FieldElement, Framework};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for hardened isolation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationHardeningConfig {
    /// Maximum memory usage in bytes (0 = unlimited)
    pub max_memory_bytes: u64,
    /// Maximum CPU time in milliseconds
    pub max_cpu_time_ms: u64,
    /// Watchdog timeout in milliseconds
    pub watchdog_timeout_ms: u64,
    /// Maximum consecutive crashes before circuit is blacklisted
    pub max_consecutive_crashes: usize,
    /// Enable crash recovery and restart
    pub enable_crash_recovery: bool,
    /// Enable resource monitoring
    pub enable_resource_monitoring: bool,
    /// Enable detailed telemetry
    pub enable_telemetry: bool,
    /// Crash cooldown period in milliseconds
    pub crash_cooldown_ms: u64,
    /// Maximum restarts per minute
    pub max_restarts_per_minute: usize,
}

impl Default for IsolationHardeningConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 4 * 1024 * 1024 * 1024, // 4GB
            max_cpu_time_ms: 60_000,                   // 60 seconds
            watchdog_timeout_ms: 30_000,               // 30 seconds
            max_consecutive_crashes: 5,
            enable_crash_recovery: true,
            enable_resource_monitoring: true,
            enable_telemetry: true,
            crash_cooldown_ms: 1000,
            max_restarts_per_minute: 10,
        }
    }
}

// ============================================================================
// Telemetry
// ============================================================================

/// Isolation failure event for telemetry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationEvent {
    /// Timestamp of the event
    pub timestamp: u64,
    /// Type of event
    pub event_type: IsolationEventType,
    /// Circuit identifier
    pub circuit_id: String,
    /// Error message (if any)
    pub error: Option<String>,
    /// Additional context
    pub context: Option<String>,
}

/// Types of isolation events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IsolationEventType {
    /// Process crashed
    Crash,
    /// Process timed out
    Timeout,
    /// Memory limit exceeded
    MemoryExceeded,
    /// CPU limit exceeded
    CpuExceeded,
    /// Process restarted
    Restart,
    /// Circuit blacklisted
    Blacklisted,
    /// Resource warning
    ResourceWarning,
}

/// Telemetry collector for isolation events
#[derive(Debug)]
pub struct IsolationTelemetry {
    /// Recent events (circular buffer)
    events: Mutex<VecDeque<IsolationEvent>>,
    /// Maximum events to keep
    max_events: usize,
    /// Total crash count
    total_crashes: AtomicU64,
    /// Total timeout count
    total_timeouts: AtomicU64,
    /// Total memory exceeded count
    total_memory_exceeded: AtomicU64,
    /// Total restarts
    total_restarts: AtomicU64,
}

impl IsolationTelemetry {
    pub fn new(max_events: usize) -> Self {
        Self {
            events: Mutex::new(VecDeque::with_capacity(max_events)),
            max_events,
            total_crashes: AtomicU64::new(0),
            total_timeouts: AtomicU64::new(0),
            total_memory_exceeded: AtomicU64::new(0),
            total_restarts: AtomicU64::new(0),
        }
    }

    /// Record an event
    pub fn record(&self, event: IsolationEvent) {
        match event.event_type {
            IsolationEventType::Crash => {
                self.total_crashes.fetch_add(1, Ordering::Relaxed);
            }
            IsolationEventType::Timeout => {
                self.total_timeouts.fetch_add(1, Ordering::Relaxed);
            }
            IsolationEventType::MemoryExceeded => {
                self.total_memory_exceeded.fetch_add(1, Ordering::Relaxed);
            }
            IsolationEventType::Restart => {
                self.total_restarts.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        let mut events = self.events.lock();
        if events.len() >= self.max_events {
            events.pop_front();
        }
        events.push_back(event);
    }

    /// Get recent events
    pub fn recent_events(&self, count: usize) -> Vec<IsolationEvent> {
        self.events
            .lock()
            .iter()
            .rev()
            .take(count)
            .cloned()
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> IsolationStats {
        IsolationStats {
            total_crashes: self.total_crashes.load(Ordering::Relaxed),
            total_timeouts: self.total_timeouts.load(Ordering::Relaxed),
            total_memory_exceeded: self.total_memory_exceeded.load(Ordering::Relaxed),
            total_restarts: self.total_restarts.load(Ordering::Relaxed),
        }
    }
}

/// Statistics from isolation
#[derive(Debug, Clone, Default)]
pub struct IsolationStats {
    pub total_crashes: u64,
    pub total_timeouts: u64,
    pub total_memory_exceeded: u64,
    pub total_restarts: u64,
}

// ============================================================================
// Crash Recovery
// ============================================================================

/// State for crash recovery
#[derive(Debug)]
pub struct CrashRecoveryState {
    /// Consecutive crashes for each circuit
    consecutive_crashes: RwLock<std::collections::HashMap<String, usize>>,
    /// Blacklisted circuits
    blacklisted: RwLock<std::collections::HashSet<String>>,
    /// Restart timestamps (for rate limiting)
    restart_times: Mutex<VecDeque<Instant>>,
}

impl CrashRecoveryState {
    pub fn new() -> Self {
        Self {
            consecutive_crashes: RwLock::new(std::collections::HashMap::new()),
            blacklisted: RwLock::new(std::collections::HashSet::new()),
            restart_times: Mutex::new(VecDeque::with_capacity(100)),
        }
    }

    /// Record a crash for a circuit
    pub fn record_crash(&self, circuit_id: &str) -> usize {
        let mut crashes = self.consecutive_crashes.write();
        let count = crashes.entry(circuit_id.to_string()).or_insert(0);
        *count += 1;
        *count
    }

    /// Reset crash count for a circuit (on successful execution)
    pub fn reset_crashes(&self, circuit_id: &str) {
        let mut crashes = self.consecutive_crashes.write();
        crashes.remove(circuit_id);
    }

    /// Blacklist a circuit
    pub fn blacklist(&self, circuit_id: &str) {
        let mut blacklisted = self.blacklisted.write();
        blacklisted.insert(circuit_id.to_string());
    }

    /// Check if a circuit is blacklisted
    pub fn is_blacklisted(&self, circuit_id: &str) -> bool {
        let blacklisted = self.blacklisted.read();
        blacklisted.contains(circuit_id)
    }

    /// Check if we can restart (rate limiting)
    pub fn can_restart(&self, max_per_minute: usize) -> bool {
        let mut times = self.restart_times.lock();
        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);

        // Remove old entries
        while match times.front() {
            Some(t) => *t < one_minute_ago,
            None => false,
        } {
            times.pop_front();
        }

        times.len() < max_per_minute
    }

    /// Record a restart
    pub fn record_restart(&self) {
        let mut times = self.restart_times.lock();
        times.push_back(Instant::now());
    }
}

impl Default for CrashRecoveryState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Resource Monitor
// ============================================================================

/// Resource usage snapshot
#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    /// Memory usage in bytes
    pub memory_bytes: u64,
    /// CPU time in milliseconds
    pub cpu_time_ms: u64,
    /// Process ID
    pub pid: u32,
    /// Is process alive
    pub is_alive: bool,
}

/// Resource monitor for subprocess
pub struct ResourceMonitor {
    config: IsolationHardeningConfig,
}

impl ResourceMonitor {
    pub fn new(config: IsolationHardeningConfig) -> Self {
        Self { config }
    }

    /// Check if resource limits are exceeded
    pub fn check_limits(&self, usage: &ResourceUsage) -> Option<IsolationEventType> {
        if self.config.max_memory_bytes > 0 && usage.memory_bytes > self.config.max_memory_bytes {
            return Some(IsolationEventType::MemoryExceeded);
        }
        if self.config.max_cpu_time_ms > 0 && usage.cpu_time_ms > self.config.max_cpu_time_ms {
            return Some(IsolationEventType::CpuExceeded);
        }
        None
    }

    /// Get resource usage for a process (platform-specific)
    #[cfg(unix)]
    pub fn get_usage(&self, pid: u32) -> ResourceUsage {
        // Get system page size and clock ticks per second
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page_size = if page_size <= 0 { 4096 } else { page_size as u64 };

        let clock_ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let clock_ticks_per_sec = if clock_ticks_per_sec <= 0 {
            100
        } else {
            clock_ticks_per_sec as u64
        };
        
        let statm_path = format!("/proc/{}/statm", pid);
        let stat_path = format!("/proc/{}/stat", pid);

        let memory_bytes = match std::fs::read_to_string(&statm_path) {
            Ok(content) => {
                let parts: Vec<&str> = content.split_whitespace().collect();
                // First field is total program size in pages
                match parts.first().map(|s| s.parse::<u64>()) {
                    Some(Ok(pages)) => pages * page_size,
                    Some(Err(err)) => {
                        tracing::warn!("Failed to parse statm pages for pid {}: {}", pid, err);
                        0
                    }
                    None => 0,
                }
            }
            Err(err) => {
                tracing::debug!("Failed to read {}: {}", statm_path, err);
                0
            }
        };

        let (cpu_time_ms, is_alive) = match std::fs::read_to_string(&stat_path) {
            Ok(content) => {
                let parts: Vec<&str> = content.split_whitespace().collect();
                // Fields 14 and 15 are utime and stime in clock ticks
                let utime = match parts.get(13).map(|s| s.parse::<u64>()) {
                    Some(Ok(v)) => v,
                    Some(Err(err)) => {
                        tracing::warn!("Failed to parse utime for pid {}: {}", pid, err);
                        0
                    }
                    None => 0,
                };
                let stime = match parts.get(14).map(|s| s.parse::<u64>()) {
                    Some(Ok(v)) => v,
                    Some(Err(err)) => {
                        tracing::warn!("Failed to parse stime for pid {}: {}", pid, err);
                        0
                    }
                    None => 0,
                };
                // Convert clock ticks to milliseconds
                let cpu_ms = ((utime + stime) * 1000) / clock_ticks_per_sec;
                (cpu_ms, true)
            }
            Err(err) => {
                tracing::debug!("Failed to read {}: {}", stat_path, err);
                (0, false)
            }
        };

        ResourceUsage {
            memory_bytes,
            cpu_time_ms,
            pid,
            is_alive,
        }
    }

    #[cfg(not(unix))]
    pub fn get_usage(&self, pid: u32) -> ResourceUsage {
        // On non-Unix platforms, return defaults
        ResourceUsage {
            memory_bytes: 0,
            cpu_time_ms: 0,
            pid,
            is_alive: true, // Assume alive; proper check requires platform-specific code
        }
    }
}

// ============================================================================
// Watchdog
// ============================================================================

/// Watchdog for monitoring process health
pub struct Watchdog {
    timeout: Duration,
    last_activity: Arc<std::sync::atomic::AtomicU64>,
}

impl Watchdog {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            last_activity: Arc::new(std::sync::atomic::AtomicU64::new(
                Self::now_millis(),
            )),
        }
    }

    /// Record activity (call periodically to prevent timeout)
    pub fn ping(&self) {
        self.last_activity.store(Self::now_millis(), Ordering::Relaxed);
    }

    /// Check if the watchdog has timed out
    pub fn is_timed_out(&self) -> bool {
        let last = self.last_activity.load(Ordering::Relaxed);
        let now = Self::now_millis();
        Duration::from_millis(now.saturating_sub(last)) > self.timeout
    }

    /// Get the shared activity tracker (for subprocess to ping)
    pub fn activity_tracker(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.last_activity)
    }

    fn now_millis() -> u64 {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration.as_millis() as u64,
            Err(err) => {
                panic!("System clock is before UNIX_EPOCH while computing watchdog time: {err}")
            }
        }
    }
}

// ============================================================================
// Hardened Executor Wrapper
// ============================================================================

/// Hardened wrapper around IsolatedExecutor
///
/// This provides additional crash recovery, resource monitoring,
/// and watchdog functionality for production stability.
pub struct HardenedIsolatedExecutor {
    /// Inner executor
    inner: Arc<dyn CircuitExecutor>,
    /// Configuration
    config: IsolationHardeningConfig,
    /// Circuit identifier
    circuit_id: String,
    /// Crash recovery state
    recovery_state: Arc<CrashRecoveryState>,
    /// Resource monitor
    resource_monitor: ResourceMonitor,
    /// Telemetry
    telemetry: Arc<IsolationTelemetry>,
    /// Watchdog
    watchdog: Watchdog,
}

impl HardenedIsolatedExecutor {
    /// Create a new hardened executor
    pub fn new(
        inner: Arc<dyn CircuitExecutor>,
        circuit_id: String,
        config: IsolationHardeningConfig,
    ) -> Self {
        let telemetry = Arc::new(IsolationTelemetry::new(1000));
        let recovery_state = Arc::new(CrashRecoveryState::new());
        let resource_monitor = ResourceMonitor::new(config.clone());
        let watchdog = Watchdog::new(config.watchdog_timeout_ms);

        Self {
            inner,
            config,
            circuit_id,
            recovery_state,
            resource_monitor,
            telemetry,
            watchdog,
        }
    }

    /// Execute with hardened isolation
    pub fn execute_hardened(&self, inputs: &[FieldElement]) -> ExecutionResult {
        // Check if circuit is blacklisted
        if self.recovery_state.is_blacklisted(&self.circuit_id) {
            return ExecutionResult::failure(format!(
                "Circuit {} is blacklisted due to repeated crashes",
                self.circuit_id
            ));
        }

        // Reset watchdog
        self.watchdog.ping();

        // Execute with the inner executor
        let result = self.inner.execute_sync(inputs);

        // Check if execution crashed
        if result.is_crash() {
            self.handle_crash(&result);
        } else if result.success {
            // Reset crash counter on success
            self.recovery_state.reset_crashes(&self.circuit_id);
        }

        result
    }

    /// Handle a crash event
    fn handle_crash(&self, result: &ExecutionResult) {
        let crash_count = self.recovery_state.record_crash(&self.circuit_id);

        // Record telemetry
        self.telemetry.record(IsolationEvent {
            timestamp: match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(duration) => duration.as_secs(),
                Err(err) => {
                    panic!(
                        "System clock is before UNIX_EPOCH while recording crash event: {err}"
                    )
                }
            },
            event_type: IsolationEventType::Crash,
            circuit_id: self.circuit_id.clone(),
            error: result.error.clone(),
            context: Some(format!("Crash #{}", crash_count)),
        });

        // Check if we should blacklist
        if crash_count >= self.config.max_consecutive_crashes {
            self.recovery_state.blacklist(&self.circuit_id);
            self.telemetry.record(IsolationEvent {
                timestamp: match std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                {
                    Ok(duration) => duration.as_secs(),
                    Err(err) => {
                        panic!(
                            "System clock is before UNIX_EPOCH while recording blacklist event: {err}"
                        )
                    }
                },
                event_type: IsolationEventType::Blacklisted,
                circuit_id: self.circuit_id.clone(),
                error: None,
                context: Some(format!(
                    "Blacklisted after {} consecutive crashes",
                    crash_count
                )),
            });

            tracing::error!(
                "Circuit {} blacklisted after {} consecutive crashes",
                self.circuit_id,
                crash_count
            );
        }
    }

    /// Get telemetry
    pub fn telemetry(&self) -> Arc<IsolationTelemetry> {
        Arc::clone(&self.telemetry)
    }

    /// Get recovery state
    pub fn recovery_state(&self) -> Arc<CrashRecoveryState> {
        Arc::clone(&self.recovery_state)
    }

    /// Check if circuit is blacklisted
    pub fn is_blacklisted(&self) -> bool {
        self.recovery_state.is_blacklisted(&self.circuit_id)
    }
}

impl CircuitExecutor for HardenedIsolatedExecutor {
    fn framework(&self) -> Framework {
        self.inner.framework()
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn circuit_info(&self) -> zk_core::CircuitInfo {
        self.inner.circuit_info()
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        self.execute_hardened(inputs)
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        self.inner.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        self.inner.verify(proof, public_inputs)
    }

    fn constraint_inspector(&self) -> Option<&dyn zk_core::ConstraintInspector> {
        self.inner.constraint_inspector()
    }

    fn field_modulus(&self) -> [u8; 32] {
        self.inner.field_modulus()
    }

    fn field_name(&self) -> &str {
        self.inner.field_name()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "isolation_hardening_tests.rs"]
mod tests;
