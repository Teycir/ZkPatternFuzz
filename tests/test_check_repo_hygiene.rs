use std::path::Path;
use tempfile::tempdir;
use zk_fuzzer::checks::repo_hygiene::{
    blocked_root_files, build_report, parse_blocklist_file, DEFAULT_BLOCKED_ROOT_FILES,
};

#[test]
fn detects_default_blocked_root_file() {
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::write(root.join("new_file.txt"), "").expect("write blocked placeholder");
    let matches = blocked_root_files(root, DEFAULT_BLOCKED_ROOT_FILES.iter().copied());
    assert_eq!(matches, vec!["new_file.txt".to_string()]);
}

#[test]
fn parse_blocklist_ignores_comments() {
    let tmp = tempdir().expect("tempdir");
    let blocklist = tmp.path().join("blocklist.txt");
    std::fs::write(
        &blocklist,
        "# comment\n\ncustom_placeholder.txt\n  extra.log  \n",
    )
    .expect("write blocklist");
    let blocked = parse_blocklist_file(&blocklist).expect("parse blocklist");
    assert!(blocked.contains("custom_placeholder.txt"));
    assert!(blocked.contains("extra.log"));
    assert_eq!(blocked.len(), 2);
}

#[test]
fn report_passes_when_no_matches() {
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::write(root.join("README.md"), "ok\n").expect("write readme");
    let report = build_report(root, DEFAULT_BLOCKED_ROOT_FILES, &Default::default());
    assert!(report.pass);
    assert!(report.matches.is_empty());
    assert_eq!(report.repo_root, Path::new(root).display().to_string());
}
