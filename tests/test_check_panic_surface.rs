use std::collections::BTreeSet;
use std::path::Path;
use tempfile::tempdir;
use zk_fuzzer::checks::panic_surface::{
    collect_panic_matches, is_excluded_path, load_allowlist, write_allowlist,
};

#[test]
fn excluded_path_filters_tests() {
    assert!(is_excluded_path(Path::new("src/foo/tests.rs")));
    assert!(is_excluded_path(Path::new("src/foo/bar_tests.rs")));
    assert!(is_excluded_path(Path::new("src/foo/test_utils.rs")));
    assert!(is_excluded_path(Path::new("src/tests/mod.rs")));
    assert!(!is_excluded_path(Path::new("src/foo/mod.rs")));
}

#[test]
fn collect_matches_ignores_comments_and_tests() {
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::create_dir_all(root.join("src")).expect("mkdir src");
    std::fs::write(
        root.join("src/main.rs"),
        r#"
fn run() {
    let _x = maybe().unwrap();
    // let _ignored = maybe().expect("comment only");
}
"#,
    )
    .expect("write main");
    std::fs::write(
        root.join("src/tests.rs"),
        "fn t() { let _ = maybe().unwrap(); }\n",
    )
    .expect("write tests.rs");
    std::fs::create_dir_all(root.join("crates/foo/src")).expect("mkdir crate src");
    std::fs::write(
        root.join("crates/foo/src/lib.rs"),
        r#"fn f() { let _ = maybe().expect("boom"); }"#,
    )
    .expect("write lib");

    let roots = vec!["src".to_string(), "crates".to_string()];
    let matches = collect_panic_matches(root, &roots).expect("collect panic matches");
    let keys: Vec<String> = matches.iter().map(|m| m.key()).collect();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().any(|k| k.contains("src/main.rs")));
    assert!(keys.iter().any(|k| k.contains("crates/foo/src/lib.rs")));
    assert!(!keys.iter().any(|k| k.contains("src/tests.rs")));
}

#[test]
fn allowlist_roundtrip() {
    let tmp = tempdir().expect("tempdir");
    let allowlist = tmp.path().join("allow.txt");
    let keys = BTreeSet::from([
        "src/main.rs|let _x = maybe().unwrap();".to_string(),
        r#"crates/foo/src/lib.rs|let _ = maybe().expect("boom");"#.to_string(),
    ]);
    write_allowlist(&allowlist, &keys).expect("write allowlist");
    let loaded = load_allowlist(&allowlist).expect("load allowlist");
    assert_eq!(loaded, keys);
}
