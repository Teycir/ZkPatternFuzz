//! Network Layer for Distributed Fuzzing
//!
//! Provides TCP-based communication between fuzzer nodes.

use super::{
    DistributedMessage, NodeCapabilities, NodeId, NodeStats, SerializableCorpusEntry, WorkResults,
    WorkUnitId,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Role of a fuzzer node
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NodeRole {
    /// Coordinator node - manages work distribution
    Coordinator,
    /// Worker node - executes fuzzing work
    Worker,
    /// Hybrid node - both coordinator and worker
    Hybrid,
}

/// Configuration for network communication
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Bind address for server
    pub bind_addr: String,
    /// Port number
    pub port: u16,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Read timeout
    pub read_timeout: Duration,
    /// Write timeout
    pub write_timeout: Duration,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Request TLS transport. Currently unsupported; `start()` rejects `true`.
    pub enable_tls: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1".to_string(), // Secure default: localhost only
            port: 9527,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            max_message_size: 100 * 1024 * 1024, // 100MB
            enable_tls: false,
        }
    }
}

/// A fuzzer node that can participate in distributed fuzzing
pub struct FuzzerNode {
    /// Node identifier
    node_id: NodeId,
    /// Node role
    role: NodeRole,
    /// Network configuration
    config: NetworkConfig,
    /// Node capabilities
    capabilities: NodeCapabilities,
    /// Connection to coordinator (for workers)
    coordinator_connection: Option<TcpStream>,
    /// Connected workers (for coordinator)
    workers: Arc<RwLock<HashMap<NodeId, WorkerConnection>>>,
    /// Running flag
    running: Arc<RwLock<bool>>,
    /// Message handler callback
    message_handler: Option<Box<dyn Fn(DistributedMessage) + Send + Sync>>,
}

/// Connection info for a worker
struct WorkerConnection {
    node_id: NodeId,
    stream: TcpStream,
    capabilities: NodeCapabilities,
    last_heartbeat: std::time::Instant,
    current_work: Option<WorkUnitId>,
}

impl FuzzerNode {
    /// Create a new fuzzer node
    pub fn new(node_id: &str, role: NodeRole) -> Self {
        Self {
            node_id: node_id.to_string(),
            role,
            config: NetworkConfig::default(),
            capabilities: NodeCapabilities::default(),
            coordinator_connection: None,
            workers: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(false)),
            message_handler: None,
        }
    }

    pub fn with_config(mut self, config: NetworkConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_capabilities(mut self, capabilities: NodeCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Set message handler
    pub fn on_message<F>(mut self, handler: F) -> Self
    where
        F: Fn(DistributedMessage) + Send + Sync + 'static,
    {
        self.message_handler = Some(Box::new(handler));
        self
    }

    /// Start the node
    pub fn start(&mut self) -> anyhow::Result<()> {
        if self.config.enable_tls {
            anyhow::bail!("Distributed TLS transport is not implemented; set enable_tls=false");
        }

        *self.running.write() = true;

        match self.role {
            NodeRole::Coordinator => self.start_coordinator(),
            NodeRole::Worker => self.start_worker(),
            NodeRole::Hybrid => {
                self.start_coordinator()?;
                self.start_worker()
            }
        }
    }

    /// Start as coordinator
    fn start_coordinator(&self) -> anyhow::Result<()> {
        let addr = format!("{}:{}", self.config.bind_addr, self.config.port);
        let listener = TcpListener::bind(&addr)?;
        listener.set_nonblocking(true)?;

        tracing::info!("Coordinator listening on {}", addr);

        let workers = Arc::clone(&self.workers);
        let running = Arc::clone(&self.running);
        let read_timeout = self.config.read_timeout;
        let max_message_size = self.config.max_message_size;

        thread::spawn(move || {
            while *running.read() {
                match listener.accept() {
                    Ok((stream, addr)) => {
                        tracing::info!("New worker connection from {}", addr);
                        if let Err(err) = stream.set_read_timeout(Some(read_timeout)) {
                            tracing::warn!(
                                "Failed to set read timeout for worker {}: {}",
                                addr,
                                err
                            );
                        }

                        // Handle registration in separate thread
                        let workers = Arc::clone(&workers);
                        let max_message_size = max_message_size;
                        thread::spawn(move || {
                            Self::handle_worker_connection(stream, workers, max_message_size);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        tracing::error!("Accept error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Handle a worker connection
    fn handle_worker_connection(
        mut stream: TcpStream,
        workers: Arc<RwLock<HashMap<NodeId, WorkerConnection>>>,
        max_message_size: usize,
    ) {
        // Read registration message
        if let Some(DistributedMessage::Register {
            node_id,
            role: _,
            capabilities,
        }) = Self::read_message(&mut stream, max_message_size)
        {
            tracing::info!(
                "Worker {} registered with {} threads",
                node_id,
                capabilities.worker_count
            );

            let connection = WorkerConnection {
                node_id: node_id.clone(),
                stream,
                capabilities,
                last_heartbeat: std::time::Instant::now(),
                current_work: None,
            };

            let idle = connection.current_work.is_none();
            let worker_threads = connection.capabilities.worker_count;
            let heartbeat_age_ms = connection.last_heartbeat.elapsed().as_millis();
            if let Err(err) = connection.stream.peer_addr() {
                tracing::warn!(
                    "Failed to read peer address for worker '{}': {}",
                    connection.node_id,
                    err
                );
            }
            tracing::debug!(
                "Worker {} registered: threads={}, idle={}, heartbeat_age_ms={}",
                connection.node_id,
                worker_threads,
                idle,
                heartbeat_age_ms
            );

            workers.write().insert(node_id, connection);
        }
    }

    /// Start as worker
    fn start_worker(&mut self) -> anyhow::Result<()> {
        let addr = format!("{}:{}", self.config.bind_addr, self.config.port);

        let stream = TcpStream::connect_timeout(&addr.parse()?, self.config.connect_timeout)?;

        stream.set_read_timeout(Some(self.config.read_timeout))?;
        stream.set_write_timeout(Some(self.config.write_timeout))?;

        // Send registration
        let register_msg = DistributedMessage::Register {
            node_id: self.node_id.clone(),
            role: self.role,
            capabilities: self.capabilities.clone(),
        };

        Self::send_message(&stream, &register_msg)?;

        self.coordinator_connection = Some(stream);
        tracing::info!("Connected to coordinator at {}", addr);

        Ok(())
    }

    /// Send a message over a stream
    fn send_message(stream: &TcpStream, message: &DistributedMessage) -> anyhow::Result<()> {
        let data = serde_json::to_vec(message)?;
        let len = data.len() as u32;

        let mut stream = stream;
        stream.write_all(&len.to_le_bytes())?;
        stream.write_all(&data)?;
        stream.flush()?;

        Ok(())
    }

    /// Read a message from a stream
    fn read_message(stream: &mut TcpStream, max_message_size: usize) -> Option<DistributedMessage> {
        let mut len_buf = [0u8; 4];
        if let Err(err) = stream.read_exact(&mut len_buf) {
            tracing::debug!("Failed reading message length: {}", err);
            return None;
        }
        let len = u32::from_le_bytes(len_buf) as usize;

        // Enforce max_message_size before allocation
        if len > max_message_size {
            tracing::warn!("Rejecting oversized message: {} bytes", len);
            return None;
        }

        let mut data = vec![0u8; len];
        if let Err(err) = stream.read_exact(&mut data) {
            tracing::warn!("Failed reading message payload ({} bytes): {}", len, err);
            return None;
        }

        match serde_json::from_slice(&data) {
            Ok(msg) => Some(msg),
            Err(err) => {
                tracing::warn!("Failed deserializing distributed message: {}", err);
                None
            }
        }
    }

    /// Send heartbeat (for workers)
    pub fn send_heartbeat(&self, stats: NodeStats) -> anyhow::Result<()> {
        if let Some(ref stream) = self.coordinator_connection {
            let msg = DistributedMessage::Heartbeat {
                node_id: self.node_id.clone(),
                stats,
            };
            Self::send_message(stream, &msg)?;
        }
        Ok(())
    }

    /// Request work (for workers)
    pub fn request_work(&self) -> anyhow::Result<()> {
        if let Some(ref stream) = self.coordinator_connection {
            let msg = DistributedMessage::RequestWork {
                node_id: self.node_id.clone(),
            };
            Self::send_message(stream, &msg)?;
        }
        Ok(())
    }

    /// Report work completion (for workers)
    pub fn report_work_complete(
        &self,
        work_unit_id: WorkUnitId,
        results: WorkResults,
    ) -> anyhow::Result<()> {
        if let Some(ref stream) = self.coordinator_connection {
            let msg = DistributedMessage::WorkComplete {
                node_id: self.node_id.clone(),
                work_unit_id,
                results,
            };
            Self::send_message(stream, &msg)?;
        }
        Ok(())
    }

    /// Share corpus entries
    pub fn share_corpus(&self, entries: Vec<SerializableCorpusEntry>) -> anyhow::Result<()> {
        if let Some(ref stream) = self.coordinator_connection {
            let msg = DistributedMessage::ShareCorpus { entries };
            Self::send_message(stream, &msg)?;
        }
        Ok(())
    }

    /// Get number of connected workers (for coordinator)
    pub fn worker_count(&self) -> usize {
        self.workers.read().len()
    }

    /// Stop the node
    pub fn stop(&mut self) {
        *self.running.write() = false;
        self.coordinator_connection = None;
    }

    /// Get node ID
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Get node role
    pub fn role(&self) -> NodeRole {
        self.role
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzer_node_creation() {
        let node = FuzzerNode::new("test-node", NodeRole::Worker);
        assert_eq!(node.node_id(), "test-node");
        assert_eq!(node.role(), NodeRole::Worker);
    }

    #[test]
    fn test_network_config_default() {
        let config = NetworkConfig::default();
        assert_eq!(config.port, 9527);
        assert!(config.max_message_size > 0);
    }
}
