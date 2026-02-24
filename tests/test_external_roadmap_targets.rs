use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

#[derive(Debug, Deserialize)]
struct ExternalInventory {
    targets: Vec<InventoryTarget>,
}

#[derive(Debug, Deserialize)]
struct InventoryTarget {
    target_id: String,
    repo_path: String,
    framework: String,
    entrypoint: String,
}

#[derive(Debug, Deserialize)]
struct ExternalMatrix {
    targets: Vec<MatrixTarget>,
}

#[derive(Debug, Deserialize)]
struct MatrixTarget {
    name: String,
    target_circuit: String,
    framework: String,
    alias: Option<String>,
    enabled: bool,
}

fn ext_id_from_matrix_name(name: &str) -> Option<String> {
    let prefix = name.split('_').next()?.to_ascii_lowercase();
    if prefix.len() == 6
        && prefix.starts_with("ext")
        && prefix[3..].chars().all(|c| c.is_ascii_digit())
    {
        return Some(format!("EXT-{}", &prefix[3..]));
    }
    None
}

#[test]
fn external_roadmap_matrix_matches_inventory_targets() {
    let inventory_raw = fs::read_to_string("targets/external_repo_inventory_2026-02-23.json")
        .expect("read inventory json");
    let matrix_raw = fs::read_to_string("targets/zk0d_matrix_external_manual.yaml")
        .expect("read external matrix yaml");

    let inventory: ExternalInventory =
        serde_json::from_str(&inventory_raw).expect("parse inventory json");
    let matrix: ExternalMatrix = serde_yaml::from_str(&matrix_raw).expect("parse matrix yaml");

    // Roadmap-defined external audit track should include all 12 EXT targets.
    assert!(
        inventory.targets.len() >= 12,
        "inventory should include the full roadmap external target set (>=12), got {}",
        inventory.targets.len()
    );

    let mut matrix_by_ext_id: BTreeMap<String, &MatrixTarget> = BTreeMap::new();
    for matrix_target in &matrix.targets {
        let ext_id = ext_id_from_matrix_name(&matrix_target.name).unwrap_or_else(|| {
            panic!(
                "matrix target '{}' missing extNNN prefix",
                matrix_target.name
            )
        });
        assert!(
            matrix_target.enabled,
            "matrix target '{}' must be enabled for manual roadmap audits",
            matrix_target.name
        );
        assert_eq!(
            matrix_target.alias.as_deref(),
            Some("external_manual"),
            "matrix target '{}' must use alias=external_manual",
            matrix_target.name
        );
        let prev = matrix_by_ext_id.insert(ext_id.clone(), matrix_target);
        assert!(
            prev.is_none(),
            "duplicate matrix target id '{}' detected",
            ext_id
        );
    }

    let inventory_ids: BTreeSet<String> = inventory
        .targets
        .iter()
        .map(|target| target.target_id.clone())
        .collect();
    let matrix_ids: BTreeSet<String> = matrix_by_ext_id.keys().cloned().collect();
    assert_eq!(
        matrix_ids, inventory_ids,
        "matrix ext-id set must match inventory ext-id set"
    );

    for inv in &inventory.targets {
        let matrix_target = matrix_by_ext_id
            .get(&inv.target_id)
            .unwrap_or_else(|| panic!("missing matrix target for {}", inv.target_id));
        assert_eq!(
            matrix_target.framework, inv.framework,
            "framework mismatch for {}",
            inv.target_id
        );
        let expected_target_circuit =
            format!("{}/{}", inv.repo_path.trim_end_matches('/'), inv.entrypoint);
        assert_eq!(
            matrix_target.target_circuit, expected_target_circuit,
            "target_circuit mismatch for {}",
            inv.target_id
        );
    }
}
