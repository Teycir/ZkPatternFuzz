#[test]
fn engine_dispatch_has_no_not_yet_implemented_fallback() {
    let source = format!(
        "{}\n{}\n{}",
        include_str!("../src/fuzzer/engine/mod.rs"),
        include_str!("../src/fuzzer/engine/run_lifecycle.rs"),
        include_str!("../src/fuzzer/engine/run_dispatch.rs")
    );
    assert!(
        !source.contains("not yet implemented"),
        "engine dispatch should not rely on generic 'not yet implemented' fallback"
    );
    assert!(
        source.contains("AttackType::BitDecomposition =>"),
        "BitDecomposition should be routed explicitly in engine dispatch"
    );
}
