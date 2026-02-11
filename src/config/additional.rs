use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

/// Additional campaign parameters.
///
/// This is a typed wrapper around the legacy key/value map. It keeps backward
/// compatibility via `Deref` while offering typed accessors for migration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdditionalConfig {
    #[serde(flatten)]
    extra: HashMap<String, serde_yaml::Value>,
}

impl AdditionalConfig {
    pub fn extra(&self) -> &HashMap<String, serde_yaml::Value> {
        &self.extra
    }

    pub fn extra_mut(&mut self) -> &mut HashMap<String, serde_yaml::Value> {
        &mut self.extra
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.extra.get(key)? {
            serde_yaml::Value::Bool(v) => Some(*v),
            serde_yaml::Value::Number(n) => n.as_i64().map(|v| v != 0),
            serde_yaml::Value::String(s) => match s.to_lowercase().as_str() {
                "true" | "yes" | "1" => Some(true),
                "false" | "no" | "0" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn get_usize(&self, key: &str) -> Option<usize> {
        match self.extra.get(key)? {
            serde_yaml::Value::Number(n) => n.as_u64().map(|v| v as usize),
            serde_yaml::Value::String(s) => s.parse::<usize>().ok(),
            _ => None,
        }
    }

    pub fn get_u32(&self, key: &str) -> Option<u32> {
        match self.extra.get(key)? {
            serde_yaml::Value::Number(n) => n.as_u64().map(|v| v.min(u32::MAX as u64) as u32),
            _ => None,
        }
    }

    pub fn get_u64(&self, key: &str) -> Option<u64> {
        match self.extra.get(key)? {
            serde_yaml::Value::Number(n) => n.as_u64(),
            serde_yaml::Value::String(s) => s.parse::<u64>().ok(),
            _ => None,
        }
    }

    pub fn get_f64(&self, key: &str) -> Option<f64> {
        match self.extra.get(key)? {
            serde_yaml::Value::Number(n) => n.as_f64(),
            serde_yaml::Value::String(s) => s.parse::<f64>().ok(),
            _ => None,
        }
    }

    pub fn get_string(&self, key: &str) -> Option<String> {
        match self.extra.get(key)? {
            serde_yaml::Value::String(s) => Some(s.clone()),
            serde_yaml::Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    }

    pub fn get_path(&self, key: &str) -> Option<PathBuf> {
        self.get_string(key).map(PathBuf::from)
    }
}

impl Deref for AdditionalConfig {
    type Target = HashMap<String, serde_yaml::Value>;

    fn deref(&self) -> &Self::Target {
        &self.extra
    }
}

impl DerefMut for AdditionalConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.extra
    }
}
