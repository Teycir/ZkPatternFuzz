#[allow(dead_code, unused_imports, clippy::all)]
mod zk0d_batch_impl {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bin/zk0d_batch.rs"
    ));

    #[test]
    fn parse_rustup_toolchain_names_extracts_first_token_and_filters_noise() {
        let raw = "\
nightly-x86_64-unknown-linux-gnu (default)\n\
stable-x86_64-unknown-linux-gnu\n\
info: syncing channel updates\n\
error: network unavailable\n";
        let parsed = parse_rustup_toolchain_names(raw);
        assert_eq!(
            parsed,
            vec![
                "nightly-x86_64-unknown-linux-gnu".to_string(),
                "stable-x86_64-unknown-linux-gnu".to_string()
            ]
        );
    }

    #[test]
    fn push_unique_nonempty_dedupes_and_ignores_empty_values() {
        let mut values = Vec::new();
        push_unique_nonempty(&mut values, "");
        push_unique_nonempty(&mut values, "nightly");
        push_unique_nonempty(&mut values, "nightly");
        push_unique_nonempty(&mut values, " stable ");
        assert_eq!(values, vec!["nightly".to_string(), "stable".to_string()]);
    }
}
