//! Attack registry and plugin scaffolding.

use crate::{
    arithmetic::ArithmeticTester,
    boundary::BoundaryTester,
    collision::CollisionDetector,
    soundness::SoundnessTester,
    underconstrained::UnderconstrainedDetector,
    verification::VerificationFuzzer,
    witness::WitnessFuzzer,
};
use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use zk_core::Attack;

/// Metadata describing an attack plugin.
#[derive(Debug, Clone)]
pub struct AttackMetadata {
    pub name: String,
    pub description: String,
    pub version: String,
}

impl AttackMetadata {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            version: version.into(),
        }
    }
}

/// Trait for pluggable attacks.
pub trait AttackPlugin: Attack {
    fn metadata(&self) -> AttackMetadata;
}

/// Loader interface for external attack plugins.
pub trait AttackPluginLoader: Send + Sync {
    fn load(&self) -> Result<Vec<Box<dyn AttackPlugin>>>;
}

/// No-op loader (returns no plugins).
pub struct NoopPluginLoader;

impl AttackPluginLoader for NoopPluginLoader {
    fn load(&self) -> Result<Vec<Box<dyn AttackPlugin>>> {
        Ok(Vec::new())
    }
}

/// Dynamic loader placeholder (useful for wiring, not implemented here).
pub struct DynamicLibraryLoader {
    paths: Vec<PathBuf>,
}

impl DynamicLibraryLoader {
    pub fn new(paths: Vec<PathBuf>) -> Self {
        Self { paths }
    }

    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }
}

impl AttackPluginLoader for DynamicLibraryLoader {
    fn load(&self) -> Result<Vec<Box<dyn AttackPlugin>>> {
        anyhow::bail!("dynamic plugin loading is not enabled in this build");
    }
}

/// Registry for attack plugins.
#[derive(Default)]
pub struct AttackRegistry {
    attacks: HashMap<String, Box<dyn AttackPlugin>>,
}

impl AttackRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            attacks: HashMap::new(),
        };
        registry.register_default_attacks();
        registry
    }

    pub fn empty() -> Self {
        Self {
            attacks: HashMap::new(),
        }
    }

    pub fn register(&mut self, attack: Box<dyn AttackPlugin>) -> Option<Box<dyn AttackPlugin>> {
        let metadata = attack.metadata();
        self.attacks.insert(metadata.name, attack)
    }

    pub fn load_from_loader(&mut self, loader: &dyn AttackPluginLoader) -> Result<usize> {
        let plugins = loader.load()?;
        let count = plugins.len();
        for plugin in plugins {
            self.register(plugin);
        }
        Ok(count)
    }

    pub fn get(&self, name: &str) -> Option<&dyn AttackPlugin> {
        self.attacks.get(name).map(|a| a.as_ref())
    }

    pub fn remove(&mut self, name: &str) -> Option<Box<dyn AttackPlugin>> {
        self.attacks.remove(name)
    }

    pub fn list(&self) -> Vec<AttackMetadata> {
        self.attacks.values().map(|a| a.metadata()).collect()
    }

    pub fn len(&self) -> usize {
        self.attacks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.attacks.is_empty()
    }

    fn register_default_attacks(&mut self) {
        self.register(Box::new(UnderconstrainedDetector::default()));
        self.register(Box::new(SoundnessTester::default()));
        self.register(Box::new(ArithmeticTester::default()));
        self.register(Box::new(BoundaryTester::default()));
        self.register(Box::new(CollisionDetector::default()));
        self.register(Box::new(VerificationFuzzer::default()));
        self.register(Box::new(WitnessFuzzer::default()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_defaults() {
        let registry = AttackRegistry::new();
        assert!(!registry.is_empty());
        assert!(registry.get("underconstrained").is_some());
    }
}
