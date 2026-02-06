//! Backend registry for creating circuit executors.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use zk_core::{CircuitExecutor, CircuitInfo, ExecutionCoverage, ExecutionResult, FieldElement, Framework};

use crate::TargetCircuit;

#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub circuit_path: String,
    pub main_component: String,
    pub build_dir: Option<PathBuf>,
}

impl BackendConfig {
    pub fn new(circuit_path: &str, main_component: &str) -> Self {
        Self {
            circuit_path: circuit_path.to_string(),
            main_component: main_component.to_string(),
            build_dir: None,
        }
    }

    pub fn with_build_dir(mut self, build_dir: PathBuf) -> Self {
        self.build_dir = Some(build_dir);
        self
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BackendError {
    pub framework: Framework,
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Backend not registered: {:?}", self.framework)
    }
}

impl std::error::Error for BackendError {}

#[async_trait]
pub trait BackendProvider: Send + Sync {
    fn framework(&self) -> Framework;

    fn create_executor(&self, config: &BackendConfig) -> anyhow::Result<Arc<dyn CircuitExecutor>>;
}

pub struct BackendRegistry {
    providers: HashMap<Framework, Box<dyn BackendProvider>>,
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            providers: HashMap::new(),
        };

        #[cfg(feature = "mock")]
        registry.register(Box::new(MockBackendProvider));
        #[cfg(feature = "circom")]
        registry.register(Box::new(CircomBackendProvider));
        #[cfg(feature = "noir")]
        registry.register(Box::new(NoirBackendProvider));
        #[cfg(feature = "halo2")]
        registry.register(Box::new(Halo2BackendProvider));
        #[cfg(feature = "cairo")]
        registry.register(Box::new(CairoBackendProvider));

        registry
    }

    pub fn register(&mut self, provider: Box<dyn BackendProvider>) {
        self.providers.insert(provider.framework(), provider);
    }

    pub fn create_executor(
        &self,
        framework: Framework,
        config: &BackendConfig,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        let provider = self
            .providers
            .get(&framework)
            .ok_or_else(|| anyhow::anyhow!(BackendError { framework }))?;
        provider.create_executor(config)
    }
}

struct TargetExecutor<T: TargetCircuit> {
    target: T,
}

impl<T: TargetCircuit> TargetExecutor<T> {
    fn new(target: T) -> Self {
        Self { target }
    }
}

#[async_trait]
impl<T: TargetCircuit + Send + Sync> CircuitExecutor for TargetExecutor<T> {
    fn framework(&self) -> Framework {
        self.target.framework()
    }

    fn name(&self) -> &str {
        self.target.name()
    }

    fn circuit_info(&self) -> CircuitInfo {
        CircuitInfo {
            name: self.target.name().to_string(),
            num_constraints: self.target.num_constraints(),
            num_private_inputs: self.target.num_private_inputs(),
            num_public_inputs: self.target.num_public_inputs(),
            num_outputs: 1,
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        let start = std::time::Instant::now();
        match self.target.execute(inputs) {
            Ok(outputs) => ExecutionResult::success(outputs.clone(), ExecutionCoverage::with_output_hash(&outputs))
                .with_time(start.elapsed().as_micros() as u64),
            Err(e) => ExecutionResult::failure(e.to_string()),
        }
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        self.target.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        self.target.verify(proof, public_inputs)
    }
}

#[cfg(feature = "mock")]
struct MockBackendProvider;

#[cfg(feature = "mock")]
#[async_trait]
impl BackendProvider for MockBackendProvider {
    fn framework(&self) -> Framework {
        Framework::Mock
    }

    fn create_executor(&self, config: &BackendConfig) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        let circuit = crate::mock::MockCircuit::new(&config.main_component, 10, 2);
        Ok(Arc::new(TargetExecutor::new(circuit)))
    }
}

#[cfg(feature = "circom")]
struct CircomBackendProvider;

#[cfg(feature = "circom")]
#[async_trait]
impl BackendProvider for CircomBackendProvider {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn create_executor(&self, config: &BackendConfig) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        let mut target = crate::circom::CircomTarget::new(
            &config.circuit_path,
            &config.main_component,
        )?;

        if let Some(dir) = &config.build_dir {
            target = target.with_build_dir(dir.clone());
        }

        target.compile()?;
        Ok(Arc::new(TargetExecutor::new(target)))
    }
}

#[cfg(feature = "noir")]
struct NoirBackendProvider;

#[cfg(feature = "noir")]
#[async_trait]
impl BackendProvider for NoirBackendProvider {
    fn framework(&self) -> Framework {
        Framework::Noir
    }

    fn create_executor(&self, config: &BackendConfig) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        let mut target = crate::noir::NoirTarget::new(&config.circuit_path)?;
        if let Some(dir) = &config.build_dir {
            target = target.with_build_dir(dir.clone());
        }
        target.compile()?;
        Ok(Arc::new(TargetExecutor::new(target)))
    }
}

#[cfg(feature = "halo2")]
struct Halo2BackendProvider;

#[cfg(feature = "halo2")]
#[async_trait]
impl BackendProvider for Halo2BackendProvider {
    fn framework(&self) -> Framework {
        Framework::Halo2
    }

    fn create_executor(&self, config: &BackendConfig) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        let mut target = crate::halo2::Halo2Target::new(&config.circuit_path)?;
        if let Some(dir) = &config.build_dir {
            target = target.with_build_dir(dir.clone());
        }
        target.setup()?;
        Ok(Arc::new(TargetExecutor::new(target)))
    }
}

#[cfg(feature = "cairo")]
struct CairoBackendProvider;

#[cfg(feature = "cairo")]
#[async_trait]
impl BackendProvider for CairoBackendProvider {
    fn framework(&self) -> Framework {
        Framework::Cairo
    }

    fn create_executor(&self, config: &BackendConfig) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        let mut target = crate::cairo::CairoTarget::new(&config.circuit_path)?;
        if let Some(dir) = &config.build_dir {
            target = target.with_build_dir(dir.clone());
        }
        target.compile()?;
        Ok(Arc::new(TargetExecutor::new(target)))
    }
}
