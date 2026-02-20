use super::*;
use crate::config::v2::{Invariant, InvariantOracle, InvariantType};
use crate::config::{FuzzConfig, ReportingConfig};
use crate::reporting::{FuzzReport, FuzzStatistics};
use chrono::Utc;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{}_{}", prefix, unique));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn sample_invariant(name: &str, relation: &str) -> Invariant {
    Invariant {
        name: name.to_string(),
        invariant_type: InvariantType::Constraint,
        relation: relation.to_string(),
        oracle: InvariantOracle::MustHold,
        transform: None,
        expected: None,
        description: None,
        severity: Some("high".to_string()),
    }
}

#[test]
fn test_import_formal_invariants_from_file() {
    let temp_dir = unique_temp_dir("zkf_formal_import");
    let invariants_path = temp_dir.join("formal_invariants.yaml");
    let config_path = temp_dir.join("campaign.yaml");

    let yaml = r#"
invariants:
  - name: "formal_range"
    invariant_type: "range"
    relation: "x < 2^64"
    oracle: "must_hold"
    severity: "critical"
"#;
    std::fs::write(&invariants_path, yaml).unwrap();
    std::fs::write(&config_path, "campaign: {}\n").unwrap();

    let mut config = FuzzConfig::default_v2();
    config.campaign.parameters.additional.insert(
        "formal_invariants_file".to_string(),
        serde_yaml::Value::String(invariants_path.display().to_string()),
    );

    let imported =
        import_formal_invariants_from_file(&mut config, config_path.to_str().unwrap()).unwrap();
    assert_eq!(imported, 1);
    assert_eq!(config.get_invariants().len(), 1);
    assert!(config
        .oracles
        .iter()
        .any(|oracle| oracle.name.starts_with("formal_invariant::")));

    std::fs::remove_dir_all(temp_dir).ok();
}

#[test]
fn test_export_formal_bridge_artifacts() {
    let temp_dir = unique_temp_dir("zkf_formal_export");
    let report = FuzzReport {
        campaign_name: "bridge-test".to_string(),
        timestamp: Utc::now(),
        duration_seconds: 1,
        findings: Vec::new(),
        statistics: FuzzStatistics::default(),
        config: ReportingConfig::default(),
    };
    let invariants = vec![sample_invariant("range_check", "x < 2^64")];

    let artifacts = export_formal_bridge_artifacts(
        &temp_dir,
        "bridge-test",
        &report,
        &invariants,
        &FormalBridgeOptions::default(),
    )
    .unwrap();

    assert!(artifacts.findings_export_path.exists());
    assert!(artifacts.imported_oracles_path.exists());
    assert!(artifacts.proof_module_path.exists());
    assert!(artifacts.workflow_path.exists());
    assert!(artifacts.obligations_count >= 1);

    std::fs::remove_dir_all(temp_dir).ok();
}
