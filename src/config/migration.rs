use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationChange {
    pub path: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct MigrationReport {
    pub changed: bool,
    pub rewritten_keys: Vec<MigrationChange>,
    pub deprecated_constructs: Vec<MigrationChange>,
}

impl MigrationReport {
    fn add_rewrite(&mut self, path: impl Into<String>, detail: impl Into<String>) {
        self.changed = true;
        self.rewritten_keys.push(MigrationChange {
            path: path.into(),
            detail: detail.into(),
        });
    }

    fn add_deprecated(&mut self, path: impl Into<String>, detail: impl Into<String>) {
        self.deprecated_constructs.push(MigrationChange {
            path: path.into(),
            detail: detail.into(),
        });
    }
}

fn key(name: &str) -> Value {
    Value::String(name.to_string())
}

fn nested_mapping_mut<'a>(root: &'a mut Value, keys: &[&str]) -> Option<&'a mut Mapping> {
    let mut current = root;
    for name in keys {
        let map = current.as_mapping_mut()?;
        current = map.get_mut(&key(name))?;
    }
    current.as_mapping_mut()
}

fn migrate_legacy_additional(root: &mut Value, report: &mut MigrationReport) {
    let Some(parameters) = nested_mapping_mut(root, &["campaign", "parameters"]) else {
        return;
    };

    let additional_key = key("additional");
    let Some(legacy_value) = parameters.remove(&additional_key) else {
        return;
    };

    let Value::Mapping(legacy_map) = legacy_value else {
        parameters.insert(additional_key, legacy_value);
        report.add_deprecated(
            "campaign.parameters.additional",
            "expected mapping but found non-mapping value; left unchanged",
        );
        return;
    };

    for (legacy_key, legacy_value) in legacy_map {
        let Value::String(legacy_name) = legacy_key else {
            report.add_deprecated(
                "campaign.parameters.additional",
                "ignored non-string nested key while hoisting",
            );
            continue;
        };

        let destination_key = key(&legacy_name);
        if parameters.contains_key(&destination_key) {
            report.add_deprecated(
                format!("campaign.parameters.additional.{}", legacy_name),
                "top-level key already exists; kept top-level value",
            );
            continue;
        }

        parameters.insert(destination_key, legacy_value);
        report.add_rewrite(
            format!("campaign.parameters.additional.{}", legacy_name),
            format!("hoisted to campaign.parameters.{}", legacy_name),
        );
    }
}

fn migrate_attack_plugin_fields(root: &mut Value, report: &mut MigrationReport) {
    let Some(root_map) = root.as_mapping_mut() else {
        return;
    };
    let Some(attacks_value) = root_map.get_mut(&key("attacks")) else {
        return;
    };
    let Some(attacks) = attacks_value.as_sequence_mut() else {
        report.add_deprecated("attacks", "expected sequence; left unchanged");
        return;
    };

    for (idx, attack) in attacks.iter_mut().enumerate() {
        let Some(attack_map) = attack.as_mapping_mut() else {
            report.add_deprecated(
                format!("attacks[{}]", idx),
                "expected mapping attack entry; left unchanged",
            );
            continue;
        };

        let plugin_key = key("plugin");
        if attack_map.contains_key(&plugin_key) {
            continue;
        }

        let config_key = key("config");
        let plugin_candidate = attack_map
            .get_mut(&config_key)
            .and_then(Value::as_mapping_mut)
            .and_then(|config| config.remove(&plugin_key));

        let Some(plugin_value) = plugin_candidate else {
            continue;
        };

        if let Some(plugin_name) = plugin_value.as_str() {
            attack_map.insert(plugin_key, Value::String(plugin_name.to_string()));
            report.add_rewrite(
                format!("attacks[{}].config.plugin", idx),
                format!("moved plugin '{}' to attacks[{}].plugin", plugin_name, idx),
            );
            continue;
        }

        if let Some(config_map) = attack_map.get_mut(&config_key).and_then(Value::as_mapping_mut) {
            config_map.insert(plugin_key, plugin_value);
        }
        report.add_deprecated(
            format!("attacks[{}].config.plugin", idx),
            "plugin value is not a string; left under config.plugin",
        );
    }
}

fn migrate_attack_plugin_dirs(root: &mut Value, report: &mut MigrationReport) {
    let Some(parameters) = nested_mapping_mut(root, &["campaign", "parameters"]) else {
        return;
    };
    let Some(plugin_dirs_value) = parameters.get_mut(&key("attack_plugin_dirs")) else {
        return;
    };

    let Value::String(raw_dirs) = plugin_dirs_value else {
        return;
    };

    let normalized: Vec<String> = raw_dirs
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect();

    if normalized.is_empty() {
        report.add_deprecated(
            "campaign.parameters.attack_plugin_dirs",
            "string value was empty after trimming; left unchanged",
        );
        return;
    }

    if normalized.len() == 1 && raw_dirs.trim() == normalized[0] {
        return;
    }

    *plugin_dirs_value = Value::Sequence(normalized.into_iter().map(Value::String).collect());
    report.add_rewrite(
        "campaign.parameters.attack_plugin_dirs",
        "normalized comma-separated string into sequence",
    );
}

pub fn migrate_config_value(mut root: Value) -> (Value, MigrationReport) {
    let mut report = MigrationReport::default();
    migrate_legacy_additional(&mut root, &mut report);
    migrate_attack_plugin_fields(&mut root, &mut report);
    migrate_attack_plugin_dirs(&mut root, &mut report);
    (root, report)
}

#[cfg(test)]
#[path = "tests/migration_tests.rs"]
mod tests;
