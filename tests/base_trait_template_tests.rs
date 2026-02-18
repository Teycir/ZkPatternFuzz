use std::path::PathBuf;

fn base_template_path() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("templates")
        .join("traits")
        .join("base.yaml")
        .to_string_lossy()
        .to_string()
}

fn load_base_template() -> serde_yaml::Value {
    let path = base_template_path();
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read base template '{}': {:#}", path, err));
    serde_yaml::from_str(&source)
        .unwrap_or_else(|err| panic!("failed to parse base template '{}': {:#}", path, err))
}

fn find_attack<'a>(template: &'a serde_yaml::Value, attack_type: &str) -> &'a serde_yaml::Value {
    template["attacks"]
        .as_sequence()
        .expect("base template should include an attacks sequence")
        .iter()
        .find(|attack| attack["type"].as_str() == Some(attack_type))
        .unwrap_or_else(|| panic!("attack '{}' should exist in base template", attack_type))
}

#[test]
fn base_template_novel_attack_budgets_meet_strict_minima() {
    let template = load_base_template();

    let metamorphic_tests = find_attack(&template, "metamorphic")["config"]["num_tests"]
        .as_u64()
        .expect("metamorphic.config.num_tests should be numeric");
    assert!(
        metamorphic_tests >= 256,
        "metamorphic num_tests should be >= 256, got {}",
        metamorphic_tests
    );

    let slice = find_attack(&template, "constraint_slice");
    let samples_per_cone = slice["config"]["samples_per_cone"]
        .as_u64()
        .expect("constraint_slice.config.samples_per_cone should be numeric");
    let base_witness_attempts = slice["config"]["base_witness_attempts"]
        .as_u64()
        .expect("constraint_slice.config.base_witness_attempts should be numeric");
    assert!(
        samples_per_cone >= 32,
        "constraint_slice samples_per_cone should be >= 32, got {}",
        samples_per_cone
    );
    assert!(
        base_witness_attempts >= 32,
        "constraint_slice base_witness_attempts should be >= 32, got {}",
        base_witness_attempts
    );

    let spec_samples = find_attack(&template, "spec_inference")["config"]["sample_count"]
        .as_u64()
        .expect("spec_inference.config.sample_count should be numeric");
    assert!(
        spec_samples >= 1000,
        "spec_inference sample_count should be >= 1000, got {}",
        spec_samples
    );
}
