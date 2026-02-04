//! Custom error types for ZK-Fuzzer
//!
//! Provides actionable error messages with context for debugging.

use thiserror::Error;

/// Main error type for ZK-Fuzzer operations
#[derive(Error, Debug)]
pub enum ZkFuzzerError {
    /// Configuration errors
    #[error("Configuration error: {message}")]
    Config {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Circuit compilation errors
    #[error("Circuit compilation failed for {circuit_path}: {message}")]
    CircuitCompilation {
        circuit_path: String,
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Circuit execution errors
    #[error("Circuit execution failed: {message}")]
    CircuitExecution {
        message: String,
        inputs_hash: Option<String>,
    },

    /// Proof generation errors
    #[error("Proof generation failed: {message}")]
    ProofGeneration { message: String },

    /// Proof verification errors
    #[error("Proof verification failed: {message}")]
    ProofVerification { message: String },

    /// Backend not supported
    #[error("Backend '{backend}' is not supported. Supported: circom, noir, halo2, cairo")]
    UnsupportedBackend { backend: String },

    /// File I/O errors
    #[error("File operation failed for {path}: {message}")]
    FileOperation {
        path: String,
        message: String,
        #[source]
        source: Option<std::io::Error>,
    },

    /// Corpus errors
    #[error("Corpus error: {message}")]
    Corpus { message: String },

    /// Timeout errors
    #[error("Operation timed out after {timeout_seconds}s: {operation}")]
    Timeout {
        operation: String,
        timeout_seconds: u64,
    },

    /// Invalid input
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    /// Internal errors
    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl ZkFuzzerError {
    /// Create a configuration error
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
            source: None,
        }
    }

    /// Create a configuration error with source
    pub fn config_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Config {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a circuit compilation error
    pub fn compilation(circuit_path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::CircuitCompilation {
            circuit_path: circuit_path.into(),
            message: message.into(),
            source: None,
        }
    }

    /// Create a circuit execution error
    pub fn execution(message: impl Into<String>) -> Self {
        Self::CircuitExecution {
            message: message.into(),
            inputs_hash: None,
        }
    }

    /// Create an unsupported backend error
    pub fn unsupported_backend(backend: impl Into<String>) -> Self {
        Self::UnsupportedBackend {
            backend: backend.into(),
        }
    }

    /// Create a file operation error
    pub fn file_operation(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::FileOperation {
            path: path.into(),
            message: message.into(),
            source: None,
        }
    }

    /// Create a timeout error
    pub fn timeout(operation: impl Into<String>, timeout_seconds: u64) -> Self {
        Self::Timeout {
            operation: operation.into(),
            timeout_seconds,
        }
    }

    /// Create an invalid input error
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::InvalidInput {
            message: message.into(),
        }
    }

    /// Create an internal error
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Get a user-friendly suggestion for fixing the error
    pub fn suggestion(&self) -> Option<String> {
        match self {
            Self::Config { message, .. } => {
                if message.contains("not found") {
                    Some("Check that the file path is correct and the file exists.".to_string())
                } else if message.contains("parse") || message.contains("YAML") {
                    Some("Validate your YAML syntax. Run 'zk-fuzzer validate <path>' for detailed error info.".to_string())
                } else {
                    None
                }
            }
            Self::CircuitCompilation { .. } => {
                Some("Ensure the circuit file is valid and all dependencies are installed.".to_string())
            }
            Self::UnsupportedBackend { backend } => {
                Some(format!(
                    "Use one of the supported backends: circom, noir, halo2, cairo. Got: {}",
                    backend
                ))
            }
            Self::Timeout { operation, timeout_seconds } => {
                Some(format!(
                    "Consider increasing the timeout or reducing the complexity. Current: {}s for {}",
                    timeout_seconds, operation
                ))
            }
            Self::InvalidInput { message } => {
                if message.contains("hex") {
                    Some("Hex values should be prefixed with '0x' (e.g., 0xdead).".to_string())
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Result type alias for ZK-Fuzzer operations
pub type Result<T> = std::result::Result<T, ZkFuzzerError>;

/// Extension trait for adding context to errors
pub trait ErrorContext<T> {
    /// Add context to an error
    fn context(self, message: impl Into<String>) -> Result<T>;
}

impl<T, E: std::error::Error + Send + Sync + 'static> ErrorContext<T>
    for std::result::Result<T, E>
{
    fn context(self, message: impl Into<String>) -> Result<T> {
        self.map_err(|e| ZkFuzzerError::Config {
            message: message.into(),
            source: Some(Box::new(e)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ZkFuzzerError::config("Invalid YAML syntax");
        assert!(err.to_string().contains("Configuration error"));
        assert!(err.to_string().contains("Invalid YAML syntax"));
    }

    #[test]
    fn test_error_suggestion() {
        let err = ZkFuzzerError::config("File not found");
        assert!(err.suggestion().is_some());
        assert!(err.suggestion().unwrap().contains("file path"));
    }

    #[test]
    fn test_unsupported_backend() {
        let err = ZkFuzzerError::unsupported_backend("unknown");
        assert!(err.to_string().contains("unknown"));
        assert!(err.suggestion().unwrap().contains("circom"));
    }
}
