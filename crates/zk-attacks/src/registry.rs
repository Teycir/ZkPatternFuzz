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
#[cfg(feature = "plugin-loader")]
use std::path::Path;
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

/// Result of loading plugins from an external source.
pub struct LoadedPlugins {
    plugins: Vec<Box<dyn AttackPlugin>>,
    #[cfg(feature = "plugin-loader")]
    libraries: Vec<libloading::Library>,
}

impl LoadedPlugins {
    pub fn empty() -> Self {
        Self {
            plugins: Vec::new(),
            #[cfg(feature = "plugin-loader")]
            libraries: Vec::new(),
        }
    }

    pub fn new(plugins: Vec<Box<dyn AttackPlugin>>) -> Self {
        Self {
            plugins,
            #[cfg(feature = "plugin-loader")]
            libraries: Vec::new(),
        }
    }

    #[cfg(feature = "plugin-loader")]
    pub fn with_libraries(
        plugins: Vec<Box<dyn AttackPlugin>>,
        libraries: Vec<libloading::Library>,
    ) -> Self {
        Self { plugins, libraries }
    }
}

/// Loader interface for external attack plugins.
pub trait AttackPluginLoader: Send + Sync {
    fn load(&self) -> Result<LoadedPlugins>;
}

/// No-op loader (returns no plugins).
pub struct NoopPluginLoader;

impl AttackPluginLoader for NoopPluginLoader {
    fn load(&self) -> Result<LoadedPlugins> {
        Ok(LoadedPlugins::empty())
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

#[cfg(not(feature = "plugin-loader"))]
impl AttackPluginLoader for DynamicLibraryLoader {
    fn load(&self) -> Result<LoadedPlugins> {
        anyhow::bail!(
            "dynamic plugin loading is not enabled in this build (feature: plugin-loader)"
        );
    }
}

#[cfg(feature = "plugin-loader")]
impl DynamicLibraryLoader {
    fn collect_library_paths(&self) -> Result<Vec<PathBuf>> {
        let mut libs = Vec::new();

        for path in &self.paths {
            if path.is_dir() {
                for entry in std::fs::read_dir(path)? {
                    let entry = entry?;
                    let file_path = entry.path();
                    if is_dynamic_library(&file_path) {
                        libs.push(file_path);
                    }
                }
            } else if is_dynamic_library(path) {
                libs.push(path.clone());
            }
        }

        Ok(libs)
    }
}

#[cfg(feature = "plugin-loader")]
fn is_dynamic_library(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
        return false;
    };
    let ext = ext.to_ascii_lowercase();
    if cfg!(target_os = "windows") {
        ext == "dll"
    } else if cfg!(target_os = "macos") {
        ext == "dylib"
    } else {
        ext == "so"
    }
}

#[cfg(feature = "plugin-loader")]
impl AttackPluginLoader for DynamicLibraryLoader {
    fn load(&self) -> Result<LoadedPlugins> {
        use libloading::{Library, Symbol};

        type PluginCreate = unsafe extern "Rust" fn() -> Vec<Box<dyn AttackPlugin>>;

        let mut libraries = Vec::new();
        let mut plugins = Vec::new();

        let paths = self.collect_library_paths()?;
        if paths.is_empty() {
            return Ok(LoadedPlugins::empty());
        }

        for path in paths {
            let lib = unsafe { Library::new(&path) }
                .map_err(|e| anyhow::anyhow!("Failed to load {:?}: {}", path, e))?;
            let symbol: Symbol<PluginCreate> = unsafe { lib.get(b"zk_attacks_plugins") }
                .map_err(|e| anyhow::anyhow!("Missing zk_attacks_plugins in {:?}: {}", path, e))?;

            let mut new_plugins = unsafe { symbol() };
            plugins.append(&mut new_plugins);
            libraries.push(lib);
        }

        Ok(LoadedPlugins::with_libraries(plugins, libraries))
    }
}

/// Registry for attack plugins.
#[derive(Default)]
pub struct AttackRegistry {
    attacks: HashMap<String, Box<dyn AttackPlugin>>,
    #[cfg(feature = "plugin-loader")]
    libraries: Vec<libloading::Library>,
}

impl AttackRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            attacks: HashMap::new(),
            #[cfg(feature = "plugin-loader")]
            libraries: Vec::new(),
        };
        registry.register_default_attacks();
        registry
    }

    pub fn empty() -> Self {
        Self {
            attacks: HashMap::new(),
            #[cfg(feature = "plugin-loader")]
            libraries: Vec::new(),
        }
    }

    pub fn register(&mut self, attack: Box<dyn AttackPlugin>) -> Option<Box<dyn AttackPlugin>> {
        let metadata = attack.metadata();
        self.attacks.insert(metadata.name, attack)
    }

    pub fn load_from_loader(&mut self, loader: &dyn AttackPluginLoader) -> Result<usize> {
        let loaded = loader.load()?;
        let count = loaded.plugins.len();
        for plugin in loaded.plugins {
            self.register(plugin);
        }
        #[cfg(feature = "plugin-loader")]
        {
            self.libraries.extend(loaded.libraries);
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
