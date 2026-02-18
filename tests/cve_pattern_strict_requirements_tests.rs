use std::fs;
use std::path::PathBuf;

fn cve_pattern_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("campaigns")
        .join("cve")
        .join("patterns")
}

#[test]
fn cve_pattern_campaigns_include_strict_required_attacks() {
    let required = [
        "soundness",
        "underconstrained",
        "constraint_inference",
        "metamorphic",
        "constraint_slice",
        "spec_inference",
        "witness_collision",
    ];

    let mut pattern_files: Vec<PathBuf> = fs::read_dir(cve_pattern_dir())
        .expect("failed to read campaigns/cve/patterns")
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            (path.extension().and_then(|ext| ext.to_str()) == Some("yaml")).then_some(path)
        })
        .collect();
    pattern_files.sort();
    assert!(
        !pattern_files.is_empty(),
        "expected at least one CVE pattern campaign in campaigns/cve/patterns"
    );

    for pattern_file in pattern_files {
        let source = fs::read_to_string(&pattern_file).unwrap_or_else(|err| {
            panic!(
                "failed to read CVE pattern '{}': {:#}",
                pattern_file.display(),
                err
            )
        });
        let yaml: serde_yaml::Value = serde_yaml::from_str(&source).unwrap_or_else(|err| {
            panic!(
                "failed to parse CVE pattern '{}': {:#}",
                pattern_file.display(),
                err
            )
        });
        let present = yaml["attacks"]
            .as_sequence()
            .expect("pattern yaml should include an 'attacks' sequence")
            .iter()
            .filter_map(|attack| attack["type"].as_str().map(str::to_string))
            .collect::<Vec<_>>();

        for required_attack in &required {
            assert!(
                present.iter().any(|attack| attack == required_attack),
                "CVE pattern '{}' missing required strict attack '{}'; present {:?}",
                pattern_file.display(),
                required_attack,
                present
            );
        }
    }
}
