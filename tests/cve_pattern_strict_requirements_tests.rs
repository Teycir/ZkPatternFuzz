use std::fs;
use std::path::PathBuf;

fn cve_pattern_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("campaigns")
        .join("cve")
        .join("patterns")
}

fn load_pattern_yaml(path: &PathBuf) -> serde_yaml::Value {
    let source = fs::read_to_string(path).unwrap_or_else(|err| {
        panic!("failed to read CVE pattern '{}': {:#}", path.display(), err)
    });
    serde_yaml::from_str(&source)
        .unwrap_or_else(|err| panic!("failed to parse CVE pattern '{}': {:#}", path.display(), err))
}

fn collect_pattern_files() -> Vec<PathBuf> {
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
    pattern_files
}

fn find_attack<'a>(yaml: &'a serde_yaml::Value, attack_type: &str) -> &'a serde_yaml::Value {
    yaml["attacks"]
        .as_sequence()
        .expect("pattern yaml should include an 'attacks' sequence")
        .iter()
        .find(|attack| attack["type"].as_str() == Some(attack_type))
        .unwrap_or_else(|| panic!("attack '{}' missing from pattern", attack_type))
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

    for pattern_file in collect_pattern_files() {
        let yaml = load_pattern_yaml(&pattern_file);
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

#[test]
fn cve_pattern_campaigns_meet_minimum_attack_budgets() {
    for pattern_file in collect_pattern_files() {
        let yaml = load_pattern_yaml(&pattern_file);

        let soundness = find_attack(&yaml, "soundness");
        let forge_attempts = soundness["config"]["forge_attempts"]
            .as_u64()
            .unwrap_or_else(|| panic!("{}: missing soundness.config.forge_attempts", pattern_file.display()));
        assert!(
            forge_attempts >= 1000,
            "{}: forge_attempts={} is below minimum 1000",
            pattern_file.display(),
            forge_attempts
        );

        let constraint_slice = find_attack(&yaml, "constraint_slice");
        let samples_per_cone = constraint_slice["config"]["samples_per_cone"]
            .as_u64()
            .unwrap_or_else(|| {
                panic!(
                    "{}: missing constraint_slice.config.samples_per_cone",
                    pattern_file.display()
                )
            });
        let base_witness_attempts = constraint_slice["config"]["base_witness_attempts"]
            .as_u64()
            .unwrap_or_else(|| {
                panic!(
                    "{}: missing constraint_slice.config.base_witness_attempts",
                    pattern_file.display()
                )
            });
        assert!(
            samples_per_cone >= 32,
            "{}: samples_per_cone={} is below minimum 32",
            pattern_file.display(),
            samples_per_cone
        );
        assert!(
            base_witness_attempts >= 32,
            "{}: base_witness_attempts={} is below minimum 32",
            pattern_file.display(),
            base_witness_attempts
        );

        let spec = find_attack(&yaml, "spec_inference");
        let spec_samples = spec["config"]["sample_count"]
            .as_u64()
            .unwrap_or_else(|| panic!("{}: missing spec_inference.config.sample_count", pattern_file.display()));
        assert!(
            spec_samples >= 1000,
            "{}: spec_inference sample_count={} is below minimum 1000",
            pattern_file.display(),
            spec_samples
        );

        let metamorphic = find_attack(&yaml, "metamorphic");
        let metamorphic_tests = metamorphic["config"]["num_tests"]
            .as_u64()
            .unwrap_or_else(|| panic!("{}: missing metamorphic.config.num_tests", pattern_file.display()));
        assert!(
            metamorphic_tests >= 256,
            "{}: metamorphic num_tests={} is below minimum 256",
            pattern_file.display(),
            metamorphic_tests
        );
    }
}
