use serde::Deserialize;
use serde_yaml::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct BenchmarkSuitesFile {
    suites: BTreeMap<String, BenchmarkSuite>,
}

#[derive(Debug, Deserialize)]
struct BenchmarkSuite {
    targets: Vec<BenchmarkTarget>,
}

#[derive(Debug, Deserialize)]
struct BenchmarkTarget {
    name: String,
    alias: Option<String>,
    template: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BenchmarkRegistryFile {
    collections: BTreeMap<String, BenchmarkCollection>,
}

#[derive(Debug, Deserialize)]
struct BenchmarkCollection {
    templates: Vec<String>,
}

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn load_yaml_file<T: for<'de> Deserialize<'de>>(relative: &str) -> T {
    let path = repo_path(relative);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read '{}': {:#}", path.display(), err));
    serde_yaml::from_str(&source)
        .unwrap_or_else(|err| panic!("failed to parse '{}': {:#}", path.display(), err))
}

fn find_target<'a>(suite_file: &'a BenchmarkSuitesFile, target_name: &str) -> &'a BenchmarkTarget {
    suite_file
        .suites
        .values()
        .flat_map(|suite| suite.targets.iter())
        .find(|target| target.name == target_name)
        .unwrap_or_else(|| panic!("target '{}' should exist in suite file", target_name))
}

#[test]
fn merkle_target_uses_dedicated_template_in_default_and_dev_suites() {
    for relative in ["targets/benchmark_suites.yaml", "targets/benchmark_suites.dev.yaml"] {
        let suites: BenchmarkSuitesFile = load_yaml_file(relative);
        let merkle = find_target(&suites, "merkle_unconstrained");
        assert_eq!(
            merkle.template.as_deref(),
            Some("merkle_path_binarity_probe.yaml"),
            "merkle target should use dedicated template in {}",
            relative
        );
        assert!(
            merkle.alias.is_none(),
            "merkle target should not also carry generic alias in {}",
            relative
        );
    }
}

#[test]
fn merkle_target_uses_dedicated_template_in_prod_suite() {
    let suites: BenchmarkSuitesFile = load_yaml_file("targets/benchmark_suites.prod.yaml");
    let merkle = find_target(&suites, "merkle_unconstrained");
    assert_eq!(
        merkle.template.as_deref(),
        Some("merkle_path_binarity_probe_prod.yaml")
    );
    assert!(merkle.alias.is_none());
}

#[test]
fn merkle_template_is_registered_without_widening_generic_aliases() {
    for relative in ["targets/benchmark_registry.yaml", "targets/benchmark_registry.dev.yaml"] {
        let registry: BenchmarkRegistryFile = load_yaml_file(relative);
        let generic = registry
            .collections
            .get("benchmark_generic")
            .expect("benchmark_generic collection should exist");
        assert_eq!(generic.templates, vec!["underconstrained_strict_probe.yaml"]);

        let merkle = registry
            .collections
            .get("benchmark_merkle_specific")
            .expect("benchmark_merkle_specific collection should exist");
        assert_eq!(merkle.templates, vec!["merkle_path_binarity_probe.yaml"]);
    }

    let prod_registry: BenchmarkRegistryFile = load_yaml_file("targets/benchmark_registry.prod.yaml");
    let generic_prod = prod_registry
        .collections
        .get("benchmark_prod")
        .expect("benchmark_prod collection should exist");
    assert_eq!(
        generic_prod.templates,
        vec!["underconstrained_strict_probe_prod.yaml"]
    );

    let merkle_prod = prod_registry
        .collections
        .get("benchmark_merkle_specific_prod")
        .expect("benchmark_merkle_specific_prod collection should exist");
    assert_eq!(
        merkle_prod.templates,
        vec!["merkle_path_binarity_probe_prod.yaml"]
    );
}

#[test]
fn merkle_templates_bind_path_indices_as_arrays() {
    for relative in [
        "campaigns/benchmark/patterns/merkle_path_binarity_probe.yaml",
        "campaigns/benchmark/patterns/merkle_path_binarity_probe_prod.yaml",
    ] {
        let template: Value = load_yaml_file(relative);
        assert_eq!(
            template["invariants"][0]["relation"].as_str(),
            Some("forall i in path_indices: path_indices[i] in {0,1}")
        );
        assert_eq!(template["inputs"][3]["name"].as_str(), Some("path_indices"));
        assert_eq!(template["inputs"][3]["type"].as_str(), Some("array<field>"));
        assert_eq!(template["inputs"][3]["length"].as_u64(), Some(3));
    }
}
