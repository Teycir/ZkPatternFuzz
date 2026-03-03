use tempfile::tempdir;
use zk_fuzzer::checks::prod_test_separation::{
    collect_violations, filter_new_violations, is_test_like_filename, load_baseline, write_baseline,
};

#[test]
fn test_like_filenames_are_detected() {
    assert!(is_test_like_filename("tests.rs"));
    assert!(is_test_like_filename("foo_tests.rs"));
    assert!(is_test_like_filename("test_helper.rs"));
    assert!(!is_test_like_filename("module.rs"));
}

#[test]
fn detects_test_file_and_symbol_reexport() {
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::create_dir_all(root.join("src")).expect("mkdir src");
    std::fs::write(
        root.join("src/mod.rs"),
        "pub(super) use super::attack_runner_tests::helper;\n",
    )
    .expect("write mod");
    std::fs::write(
        root.join("src/attack_runner_tests.rs"),
        "pub fn helper() {}\n",
    )
    .expect("write tests module");

    let violations = collect_violations(root, &["src".to_string()]).expect("collect violations");
    let kinds: std::collections::BTreeSet<&str> =
        violations.iter().map(|v| v.kind.as_str()).collect();
    assert!(kinds.contains("test_symbol_import_or_reexport"));
    assert!(kinds.contains("test_file_in_production_tree"));
}

#[test]
fn detects_cfg_test_and_test_path_attr_and_module() {
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::create_dir_all(root.join("src")).expect("mkdir src");
    std::fs::write(
        root.join("src/mod.rs"),
        "#[cfg(test)]\n#[path = \"mod_tests.rs\"]\nmod tests;\npub fn f() {}\n",
    )
    .expect("write mod");

    let violations = collect_violations(root, &["src".to_string()]).expect("collect violations");
    let kinds: std::collections::BTreeSet<&str> =
        violations.iter().map(|v| v.kind.as_str()).collect();
    assert!(kinds.contains("test_attribute_in_production"));
    assert!(kinds.contains("test_path_attr_in_production"));
    assert!(kinds.contains("test_module_decl_in_production"));
}

#[test]
fn baseline_flow_detects_new_violations() {
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::create_dir_all(root.join("src")).expect("mkdir src");
    std::fs::create_dir_all(root.join("config")).expect("mkdir config");
    let baseline_path = root.join("config/prod_test_separation_baseline.json");

    std::fs::write(
        root.join("src/legacy.rs"),
        "#[cfg(test)]\npub fn legacy_only() {}\n",
    )
    .expect("write legacy");
    let initial = collect_violations(root, &["src".to_string()]).expect("collect initial");
    write_baseline(&baseline_path, &initial).expect("write baseline");

    let baseline_counts = load_baseline(&baseline_path).expect("load baseline");
    let new_from_initial = filter_new_violations(&initial, &baseline_counts);
    assert!(new_from_initial.is_empty());

    std::fs::write(
        root.join("src/new_bad.rs"),
        "#[cfg(test)]\npub fn new_bad() {}\n",
    )
    .expect("write new bad");
    let with_new = collect_violations(root, &["src".to_string()]).expect("collect with new");
    let new_violations = filter_new_violations(&with_new, &baseline_counts);
    assert!(!new_violations.is_empty());
}
